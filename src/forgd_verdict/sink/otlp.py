"""The only sink type built: OTLP/HTTP JSON to a collector the customer runs.

Deliberately not a Splunk HEC or CloudWatch exporter. Emitting OTLP to the
customer's own OpenTelemetry Collector and letting it fan out is one
integration instead of N, no vendor SDK to track, and it matches the
deployment model -- they run this in their own cloud, next to a collector
that already speaks HEC, CloudWatch and Datadog well.

If a direct exporter is ever wanted it is a new `Sink` and nothing else
changes: the events arriving at `send` are already redacted, filtered and
annotated.
"""

from __future__ import annotations

import http.client
import json
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..plugins import PluginAllow, build_plugin, find_entry, refuse_shadowing
from .base import RedactedEvent, Sink, SinkConfig, SinkUnavailable, safe_endpoint
from .transport import Connect, HttpTransport

# The OTLP/HTTP default. `OTEL_EXPORTER_OTLP_ENDPOINT` is a BASE url and the
# exporter appends the signal path -- the same rule Anthropic's exporter
# follows on the way in.
PATH_LOGS = "/v1/logs"


def _any_value(v: Any) -> dict[str, Any]:
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    return {"stringValue": str(v)}


def _kv(d: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"key": k, "value": _any_value(v)} for k, v in d.items()]


class OtlpSink:
    """OTLP/HTTP with a JSON body.

    JSON rather than protobuf so the payload is readable in a capture and
    the package takes no new dependency. Every OTLP receiver accepts it.
    """

    type = "otlp"

    def __init__(self, config: SinkConfig, *, connect: Connect | None = None) -> None:
        if not config.endpoint:
            raise SinkUnavailable(
                f"sink {config.name!r} has no endpoint. A sink that cannot "
                "reach anywhere is a queue that fills and drops, which looks "
                "exactly like a working sink with a quiet week."
            )
        self.config = config
        # Appended to the PATH, not to the whole string.
        # `endpoint.rstrip("/") + PATH_LOGS` put the signal path after any
        # query string -- `...?tenant=abc/v1/logs` -- so a sink
        # configured with one posted to a URL that does not exist.
        parts = urlsplit(config.endpoint)
        self._url = urlunsplit((
            parts.scheme, parts.netloc,
            parts.path.rstrip("/") + PATH_LOGS,
            parts.query, parts.fragment,
        ))
        try:
            self._http = HttpTransport(self._url, config.timeout_s, connect=connect)
        except ValueError as exc:
            raise SinkUnavailable(
                f"sink {config.name!r} endpoint {safe_endpoint(config.endpoint)!r} "
                "is not an http or https URL with a host") from exc
        self.sent = 0
        self.failed = 0

    # Conservative against the smallest thing downstream is likely to be.
    # The core chunks on these rather than every exporter re-chunking.
    @property
    def max_batch_bytes(self) -> int:
        return 1_000_000

    @property
    def max_batch_events(self) -> int:
        return 1_000

    @property
    def requires_ordering(self) -> bool:
        # OTLP does not care. CloudWatch would return True here, and the
        # core -- not the exporter -- is what would honour it.
        return False

    def _body(self, events: Sequence[RedactedEvent]) -> bytes:
        """One resourceLogs entry PER DISTINCT RESOURCE.

        A batch routinely mixes records: chunking is by size and count,
        not by sender. One entry built from `events[0].resource` for the
        whole batch would do three things.

        Silent loss -- every non-first resource is discarded, so the pod,
        tenant and org of every later record are not on the wire.

        Cross-org MISATTRIBUTION -- a record whose sender said
        `organization.id: org-B` is serialised under org-A's resource. A
        SIEM routing or partitioning on resource attributes would file it
        against the wrong org.

        Order dependence -- reversing the two inputs flips which org
        survives, so the same batch produces different output depending
        on arrival order.
        """
        groups: dict[str, list[RedactedEvent]] = {}
        order: list[str] = []
        for e in events:
            key = json.dumps(e.resource, sort_keys=True, separators=(",", ":"))
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(e)
        return json.dumps(
            {"resourceLogs": [self._resource_logs(groups[k]) for k in order]},
            separators=(",", ":"),
        ).encode("utf-8")

    def _resource_logs(self, events: Sequence[RedactedEvent]) -> dict[str, Any]:
        scopes = []
        for e in events:
            attrs = dict(e.attributes)
            attrs["forgd.surface"] = e.surface
            attrs["forgd.org"] = e.org
            # What was censored and why, never what it was. A SIEM can
            # alert on "this event was redacted" without being handed the
            # thing that caused it.
            for det, n in e.redactions.items():
                attrs[f"forgd.redacted.{det}"] = n
            if e.redactions:
                attrs["forgd.redacted"] = True
            scopes.append({
                "timeUnixNano": "0",
                "observedTimeUnixNano": "0",
                "severityText": "INFO",
                "body": {"stringValue": e.name},
                "attributes": _kv(attrs),
            })
        return {
            "resource": {"attributes": _kv(
                {**(events[0].resource if events else {}),
                 "service.name": "forgd-verdict"}
            )},
            "scopeLogs": [{"logRecords": scopes}],
        }

    def send(self, events: Sequence[RedactedEvent]) -> int:
        if not events:
            return 0
        headers = {"content-type": "application/json"}
        if self.config.token:
            headers["authorization"] = f"Bearer {self.config.token}"
        try:
            status = self._http.post(self._body(events), headers)
        except (OSError, http.client.HTTPException) as exc:
            self.failed += len(events)
            raise SinkSendFailed(
                f"{safe_endpoint(self._url)} unreachable: {type(exc).__name__}") from exc
        if status >= 300:
            self.failed += len(events)
            raise SinkSendFailed(f"{safe_endpoint(self._url)} returned {status}", status=status)
        self.sent += len(events)
        return len(events)

    def describe(self) -> dict[str, Any]:
        return {
            "type": self.type, "name": self.config.name,
            "endpoint": safe_endpoint(self._url),
            "sent": self.sent, "failed": self.failed,
            "authenticated": bool(self.config.token),
        }

    def end_flush(self) -> None:
        self._http.close()

    def close(self) -> None:
        self._http.close()


class SinkSendFailed(RuntimeError):
    """One batch did not land. The pipeline retries then drops.

    Never raised out of the ingest path: a downstream outage must not
    become a non-200 to Anthropic, because sustained export failures trip
    the circuit breaker.

    The message names the endpoint and a status or exception type, never
    an upstream response or an underlying exception's text. `status` is
    the HTTP status when there was one.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


BUILTIN_SINK_TYPES = ("otlp", "azure-monitor")


def build_sink(config: SinkConfig, *, plugins: Sequence[PluginAllow] = (),
               profile: str | None = None, **kw) -> Sink:
    """The sink for `config.type`: a built-in, or a listed `sinks` plugin."""
    refuse_shadowing(plugins, "sinks", BUILTIN_SINK_TYPES)
    if config.options and config.type in BUILTIN_SINK_TYPES:
        raise SinkUnavailable(f"sink {config.name!r} is a built-in type and takes no `options`")
    if config.type == "otlp":
        return OtlpSink(config, **kw)
    if config.type == "azure-monitor":
        # Imported here, not at module scope: it reaches for azure-identity
        # on first send, and a deployment with no Azure sink should not
        # need the extra installed to import this module.
        from .azmonitor import AzureMonitorSink

        return AzureMonitorSink(config, **kw)
    entry = find_entry(plugins, "sinks", config.type)
    if entry is not None:
        return build_plugin(entry, profile, set(BUILTIN_SINK_TYPES), Sink, config, **kw)
    raise SinkUnavailable(
        f"sink {config.name!r} has type {config.type!r}; built types are "
        "'otlp' and 'azure-monitor'. Splunk HEC, CloudWatch, Datadog and "
        "Cribl each need a new Sink implementation registered in "
        "build_sink; nothing else changes."
    )
