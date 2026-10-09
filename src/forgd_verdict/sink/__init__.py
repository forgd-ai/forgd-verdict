"""Adapter 5 -- the outbound control point.

A1-A4 all answer "something arrived, what do we do about it". This one
answers "something is leaving, what should it look like". It is the only
adapter that changes what a third party receives, and it is optional: a
deployment that configures no sink builds nothing and runs nothing.

The split that keeps it honest:

    the CORE owns what leaves -- scan, redact, filter, annotate
    a SINK owns only how it travels -- encode, batch, ship

Redaction happens once, before any sink sees an event, and a sink is handed
an already-redacted object it has no way to widen. If redaction lived in an
exporter, every future exporter would reimplement it and one of them would
get it subtly wrong -- and getting redaction subtly wrong is a leak, not a
bug report.

Only `otlp` is implemented. Everything here is shaped so Splunk HEC,
CloudWatch Logs, Datadog or Cribl are a new `Sink` and nothing else: the
config takes a LIST of sinks with a `type` discriminator from the first
commit, so no later adapter is a special case bolted onto the one that
happened to be built first.
"""

from .base import (
    RedactedEvent,
    Sink,
    SinkConfig,
    SinkUnavailable,
)
from .redact import RedactionPlan, redact_events

__all__ = [
    "RedactedEvent",
    "RedactionPlan",
    "Sink",
    "SinkConfig",
    "SinkUnavailable",
    "redact_events",
]
