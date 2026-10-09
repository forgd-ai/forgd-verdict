"""Adapter 5 -> Azure Monitor Logs, via the Logs Ingestion API.

The second sink, and the one that proves the first was not hardwired.
`OtlpSink` speaks OTLP/HTTP to anything that accepts it; this speaks a
Microsoft REST API with Entra bearer tokens into a custom table. Nothing
in `core`, `redact` or `RedactedEvent` changed to make it work -- the
projection out of the neutral intermediate is this file and nothing else.

## Why the Logs Ingestion API and not OTLP

Azure Monitor does not take an OTLP export into a Log Analytics
workspace. The supported route for arbitrary structured records is the
Logs Ingestion API: a POST of a JSON array to a Data Collection Rule,
which transforms it and lands it in a custom table.

    POST {endpoint}/dataCollectionRules/{dcr}/streams/{stream}
         ?api-version=2023-01-01

`endpoint` is the DCR's own `logsIngestion` endpoint. A DCR created with
`kind: Direct` generates one, so no separate Data Collection Endpoint
resource is needed. Configure the whole URI as the sink's `endpoint` --
it carries the DCR immutable id and the stream name already, and adding
two more config fields to restate them would be two more things to get
inconsistent.

## Why the token is not in policy.yaml

Every other sink credential is a static bearer in the cluster Secret.
This one cannot be: Azure access tokens expire in about an hour, so a
value pasted into a Secret works until it does not. The sink asks
`azure_auth.credential()` -- the same chain the findings store uses -- and
caches the token until shortly before it expires.

That also means the deployment holds no Azure Monitor credential at all.
The pod's managed identity needs **Monitoring Metrics Publisher** on the
DCR, and that grant is the whole configuration.

## What the table receives

One row per event, already redacted. `Body` is the event text with the
matched spans replaced and the prose around them intact -- the point of
the exercise: a SIEM that can read the conversation without holding the
secret that was in it. `Redactions` says what was censored and how many
times, by detector, with no offsets and no values, so an analyst can
alert on "this was censored and why" without being told what.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.parse
from collections.abc import Sequence
from typing import Any

from .base import RedactedEvent, SinkConfig, SinkUnavailable, safe_endpoint
from .otlp import SinkSendFailed
from .transport import Connect, HttpTransport

API_VERSION = "2023-01-01"

# The documented limit is 1 MB per call, uncompressed. Chunked below it
# rather than at it: `RedactedEvent.byte_size` is an approximation, and a
# rejected batch costs a retry while a slightly small one costs nothing.
MAX_BATCH_BYTES = 900_000

# No documented per-call event cap, only the 1 MB. This is a ceiling so a
# burst cannot build one enormous request that then fails whole.
MAX_BATCH_EVENTS = 1000

# Refresh this far before expiry. A token that expires mid-flight fails
# the whole batch, and the queue is bounded -- so the margin is generous.
_RENEW_MARGIN_S = 300.0


class AzureMonitorSink:
    """Sink implementation. Redaction already happened; see `redact.py`."""

    type = "azure-monitor"

    def __init__(self, config: SinkConfig, connect: Connect | None = None, token_provider=None):
        self.config = config
        self.sent = 0
        self.failed = 0
        self._token: str = ""
        self._expires_at: float = 0.0

        endpoint = (config.endpoint or "").strip()
        if not endpoint:
            raise SinkUnavailable(
                f"sink {config.name!r} has type 'azure-monitor' and no "
                "endpoint. Give it the DCR logs-ingestion URI, including "
                "the rule id and the stream: "
                "https://<dcr>.<region>.ingest.monitor.azure.com"
                "/dataCollectionRules/dcr-<id>/streams/Custom-<table>"
            )
        parsed = urllib.parse.urlparse(endpoint)
        if parsed.scheme != "https":
            # Not pedantry. The body is redacted but it is still
            # transcript text, and a token goes with it.
            raise SinkUnavailable(
                f"sink {config.name!r} endpoint must be https, got "
                f"{parsed.scheme or 'no scheme'!r}"
            )
        if "/dataCollectionRules/" not in parsed.path or "/streams/" not in parsed.path:
            # Without the rule and the stream, every send answers 404. The
            # portal shows the host on its own and it looks complete.
            raise SinkUnavailable(
                f"sink {config.name!r} endpoint {safe_endpoint(endpoint)!r} is missing the "
                "rule or the stream. The host alone is not an ingestion "
                "URI: it must contain /dataCollectionRules/<id>/streams/<name>"
            )
        if config.token:
            raise SinkUnavailable(
                f"sink {config.name!r} sets a token, which this sink cannot "
                "use. Azure access tokens expire hourly, so a static value "
                "works until it silently does not. Grant the deployment's "
                "managed identity 'Monitoring Metrics Publisher' on the DCR "
                "and remove the token."
            )
        self._url = f"{endpoint}?api-version={API_VERSION}"
        self._http = HttpTransport(self._url, config.timeout_s, connect=connect)
        self._token_provider = token_provider or _entra_token

    # -- tokens -----------------------------------------------------------

    def _bearer(self) -> str:
        if self._token and time.time() < self._expires_at:
            return self._token
        token, expires_on = self._token_provider()
        self._token = token
        self._expires_at = expires_on - _RENEW_MARGIN_S
        return self._token

    # -- the projection ---------------------------------------------------

    def _rows(self, events: Sequence[RedactedEvent]) -> list[dict[str, Any]]:
        """One JSON object per event, in the shape the DCR stream declares.

        `TimeGenerated` is the column Azure Monitor requires; everything
        else is ours and is declared in the custom table. Dicts go as
        dynamic columns rather than being flattened -- a flattened
        attribute bag turns every new attribute name into a schema
        change, and the DCR would start dropping columns it was never
        told about.
        """
        rows = []
        for e in events:
            rows.append({
                "TimeGenerated": e.observed_at,
                "Kind": e.kind,
                "EventName": e.name,
                "Surface": e.surface,
                "Organization": e.org,
                "Attributes": e.attributes,
                "Resource": e.resource,
                # Detector -> count. No offsets, no values: this is what
                # lets a SIEM alert on "censored, and why" without being
                # handed the thing that was censored.
                "Redactions": e.redactions,
                "RedactionTotal": sum(e.redactions.values()),
            })
        return rows

    def send(self, events: Sequence[RedactedEvent]) -> int:
        if not events:
            return 0
        body = json.dumps(self._rows(events)).encode("utf-8")
        try:
            headers = {"content-type": "application/json",
                       "authorization": f"Bearer {self._bearer()}"}
        except Exception as exc:  # noqa: BLE001 - any credential failure
            # A token failure is a send failure, not a crash: the pipeline
            # retries and the queue drops with a counter. Raised as the
            # same type a transport failure raises so one caller handles
            # both.
            self.failed += len(events)
            raise SinkSendFailed(
                f"could not acquire an Azure token: {type(exc).__name__}") from exc
        try:
            status = self._http.post(body, headers)
        except (OSError, http.client.HTTPException) as exc:
            self.failed += len(events)
            raise SinkSendFailed(
                f"{safe_endpoint(self._url)} unreachable: {type(exc).__name__}") from exc
        if status >= 300:
            self.failed += len(events)
            # 403 here is almost always the missing role assignment, and
            # the generic message sends people to check the endpoint.
            hint = ""
            if status == 403:
                hint = (" -- the identity likely lacks 'Monitoring Metrics "
                        "Publisher' on the data collection rule")
            raise SinkSendFailed(f"{safe_endpoint(self._url)} returned {status}{hint}",
                                 status=status)
        self.sent += len(events)
        return len(events)

    def describe(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "name": self.config.name,
            "endpoint": safe_endpoint(self._url),
            "sent": self.sent,
            "failed": self.failed,
            # No token to report. The identity is the credential and it is
            # not held here.
            "authenticated": "managed-identity",
        }

    def end_flush(self) -> None:
        self._http.close()

    def close(self) -> None:
        self._http.close()

    @property
    def max_batch_bytes(self) -> int:
        return MAX_BATCH_BYTES

    @property
    def max_batch_events(self) -> int:
        return MAX_BATCH_EVENTS

    @property
    def requires_ordering(self) -> bool:
        # Every row carries its own TimeGenerated and the table is queried
        # by that, so arrival order is not meaningful here.
        return False


def _entra_token() -> tuple[str, float]:
    """(token, unix expiry). Separate so a test needs no Azure."""
    from ..azure_auth import SCOPE_MONITOR, credential

    cred, _ = credential()
    tok = cred.get_token(SCOPE_MONITOR)
    return tok.token, float(tok.expires_on)
