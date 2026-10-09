"""The sink protocol, the neutral event it carries, and its configuration."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol

from ..models import shown_url


class SinkUnavailable(RuntimeError):
    """A sink cannot be built or cannot start.

    Raised at construction, never per-batch. A misconfigured sink must stop
    the process rather than degrade: see the fail-closed rule in `redact`.
    """


@dataclass
class RedactedEvent:
    """One event on its way out, after redaction.

    THE NEUTRAL INTERMEDIATE, and the thing that decides whether OTLP is
    hardwired. If the core handed a sink OTLP protobuf, a Splunk HEC
    exporter would have to un-OTLP it and OTLP would be the wire format in
    disguise.

    The shape is OTel's DATA MODEL -- resource, attributes, timestamp,
    name/body -- which is a different thing from OTLP the wire protocol. It
    is a superset of what HEC (`event`, `fields`, `time`, `sourcetype`),
    CloudWatch (`logGroup`, `logStream`, `timestamp`, `message`) and Datadog
    need, so every planned exporter is a projection out of this rather than
    a translation through someone else's envelope.

    `redactions` is what was removed, by detector. It carries no offsets and
    no values -- it is what lets a SIEM alert on "this event was censored
    and why" without being told what was censored.
    """

    kind: str
    name: str
    observed_at: str
    surface: str
    org: str
    attributes: dict[str, Any] = field(default_factory=dict)
    resource: dict[str, Any] = field(default_factory=dict)
    redactions: dict[str, int] = field(default_factory=dict)

    def byte_size(self) -> int:
        """Rough encoded size, for chunking against a sink's limit.

        Deliberately cheap and deliberately an overestimate: the core
        chunks on this, and a sink that rejects an oversized batch costs a
        retry while a sink that receives a slightly small one costs
        nothing.
        """
        n = len(self.kind) + len(self.name) + len(self.observed_at)
        n += len(self.surface) + len(self.org)
        for d in (self.attributes, self.resource):
            for k, v in d.items():
                n += len(k) + len(str(v)) + 4
        return n + 64


@dataclass
class SinkConfig:
    """One destination.

    A LIST of these, and each carries a `type`. "Splunk for security, blob
    for retention" is two entries in the list.
    """

    name: str
    type: str = "otlp"
    endpoint: str = ""
    # Bearer/HEC token/API key. Never in policy.yaml: `$ENV_VAR` here and
    # the value in the cluster Secret, like every other credential.
    token: str = ""
    # Detector ids whose matches are replaced on the way out.
    #
    # ABSENT MEANS REDACT EVERYTHING. Were it to mean redact nothing, a
    # sink configured with an endpoint and no `redact` would forward every
    # matched secret verbatim while looking configured.
    #
    # Opting out is supported, because a customer may legitimately want
    # their own raw telemetry in their own SIEM. It has to be written
    # down: `redact: [none]`.
    redact: list[str] = field(default_factory=list)
    # Event names dropped entirely. Splunk licenses per GB ingested, so
    # dropping event types nobody queries is a line item, not tidiness.
    drop_events: list[str] = field(default_factory=list)
    # Stamped onto every event on the way out.
    metadata: dict[str, str] = field(default_factory=dict)
    # Bounded. A downstream outage must never reach Anthropic, so the queue
    # drops with a counter rather than blocking the ingest path.
    max_queue: int = 10_000
    # `otel.orgs[].label` values this sink forwards for: the records filed
    # under any org id those entries name (`id`, or each of `ids`). Empty
    # means every org the collector serves, which is what a sink did before
    # this field existed.
    orgs: list[str] = field(default_factory=list)
    timeout_s: float = 10.0
    # A sink plugin's own settings, read-only all the way down. Built-in
    # types refuse a non-empty one.
    options: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))


def safe_endpoint(url: str) -> str:
    """An endpoint with anything credential-shaped removed.

    A URL can carry a credential two ways and both escaped: userinfo, and
    a query parameter. `describe()` returned the full URL, `stats()`
    carried it, `/stats` serves that to metrics-token holders, and a send
    failure put it in an exception the pipeline logs.

    The separate `token` field was always clean -- redacted in the policy
    and reported as a boolean. This makes the endpoint match it.
    """
    return shown_url(url)


class Sink(Protocol):
    """How a batch travels. Never what is in it.

    Modelled on `Store`, which has local/blob/spool behind one protocol and
    takes S3 and GCS without touching a caller.

    `send` receives events that are ALREADY redacted and has no way to
    recover what was removed. Everything interesting happened before the
    call.

    A sink may also define `end_flush()`, which the pipeline calls after
    each flush. It is optional and not part of this protocol.
    """

    def send(self, events: Sequence[RedactedEvent]) -> int: ...

    def describe(self) -> dict[str, Any]: ...

    def close(self) -> None: ...

    # Capabilities the CORE respects when batching, rather than every
    # exporter re-chunking and two of them getting it wrong. HEC is about
    # 1 MB, CloudWatch PutLogEvents is 1 MB and 10k events, Datadog is 5 MB.
    @property
    def max_batch_bytes(self) -> int: ...

    @property
    def max_batch_events(self) -> int: ...

    # CloudWatch requires per-stream chronological order; OTLP does not
    # care. Declared here because it constrains the QUEUE, which the core
    # owns, and not the exporter.
    @property
    def requires_ordering(self) -> bool: ...
