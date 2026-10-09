"""Adapter 5: a resource shared by many records is checked once per call.

Every record in an OTLP resource group carries the same resource, so a check
per record repeats the same work for each one.
"""

from __future__ import annotations

from conftest import FAKE_AWS_KEY

from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.metadata import METADATA_MAX_CHARS, MetadataGuard
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.redact import RedactionPlan, redact_events

KEY = "AKIAQYLPMN5HGZTHX4UQ"  # gitleaks:allow
DETS = [T0RegexDetector()]


def _cfg():
    return SinkConfig(name="s", endpoint="https://collector.test",
                      redact=["regex:aws-access-key"])


def _redact(records):
    cfg = _cfg()
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key"])
    return redact_events(records, {}, plan, cfg, surface="s", org="o",
                         observed_at="t", detectors=DETS)


def _records(resource, n):
    return [OtelRecord(kind="log", name="claude_code.user_prompt",
                       attributes={"session.id": f"s{i}", "prompt": "hello there"},
                       resource=resource)
            for i in range(n)]


def _counting(monkeypatch, marker):
    calls = []
    real = MetadataGuard.matches

    def counted(self, values):
        if marker in values or marker in values.values():
            calls.append(dict(values))
        return real(self, values)

    monkeypatch.setattr(MetadataGuard, "matches", counted)
    return calls


def test_a_shared_resource_is_checked_once_per_call(monkeypatch):
    resource = {"service.name": FAKE_AWS_KEY, "host.name": "laptop-01", KEY: "x"}
    baseline = [_redact([r])[0] for r in _records(resource, 3)]
    calls = _counting(monkeypatch, "host.name")
    out = _redact(_records(resource, 200))
    # One check of the values, one of the names.
    assert len(calls) == 2
    assert len(out) == 200
    for event in out:
        assert event.resource == baseline[0].resource
        assert event.redactions == baseline[0].redactions
    assert FAKE_AWS_KEY not in repr(out[0].resource) and KEY not in repr(out[0].resource)
    assert out[0].resource["host.name"] == "laptop-01"
    # Each event has its own copy.
    out[0].resource["host.name"] = "changed"
    assert out[1].resource["host.name"] == "laptop-01"


def test_a_resource_value_over_the_metadata_limit_is_masked_unscanned(monkeypatch):
    long_value = "z" * (METADATA_MAX_CHARS + 1)
    at_limit = "y" * METADATA_MAX_CHARS
    calls = _counting(monkeypatch, long_value)
    (event,) = _redact(_records({"process.command_line": long_value,
                                 "host.name": at_limit}, 1))
    assert calls == []
    assert event.resource["process.command_line"] == "[redacted:metadata-long:whole-value]"
    assert event.resource["host.name"] == at_limit
    assert event.redactions == {"metadata-long": 1}
