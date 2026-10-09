"""`sinks[].metadata` is checked by the metadata guard at startup."""

from __future__ import annotations

import json
import logging

import pytest
from conftest import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN
from test_sink_redact_scan_parity import MARKER, Marker

from forgd_verdict.detectors.base import TIER_T1
from forgd_verdict.metadata import METADATA_MAX_CHARS
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.policy import load_policy
from forgd_verdict.sink.base import SinkUnavailable
from forgd_verdict.sink.factory import build_forwarders
from forgd_verdict.sink.redact import redact_events

IDS = ("regex:aws-access-key",)
LONG = "x" * (METADATA_MAX_CHARS + 1)


@pytest.fixture(scope="module")
def cheap():
    return [d for d in load_policy("policy.yaml").build_detectors()
            if d.tier < 2 and d.name != "gitleaks"]


def _sink(metadata, endpoint="https://x:4318"):
    return [{"name": "siem", "endpoint": endpoint, "metadata": metadata}]


@pytest.mark.parametrize("metadata, part, index, detector", [
    ({"env": "prod", f"x.{FAKE_AWS_KEY}": "1"}, "key", 1, "regex:aws-access-key"),
    ({"env": "prod", "owner": FAKE_AWS_KEY}, "value", 1, "regex:aws-access-key"),
    ({"token": FAKE_GITHUB_TOKEN}, "value", 0, "regex:github"),
    ({"env": LONG}, "value", 0, None),
    ({LONG: "prod"}, "key", 0, None),
])
def test_a_matching_or_overlong_entry_refuses_to_start(metadata, part, index, detector,
                                                       cheap, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    with pytest.raises(SinkUnavailable) as e:
        build_forwarders(_sink(metadata), IDS, cheap_detectors=cheap, background=False)
    message = str(e.value)
    assert f"sinks.siem.metadata entry {index}: the {part}" in message
    if detector:
        assert detector in message
    else:
        assert f"longer than {METADATA_MAX_CHARS}" in message
    out = capsys.readouterr()
    for shown in (message, caplog.text, out.out, out.err):
        assert FAKE_AWS_KEY not in shown and FAKE_GITHUB_TOKEN not in shown
        assert LONG not in shown
        for key in metadata:
            if key not in ("env", "token", "owner"):
                assert key not in shown


def test_a_lone_surrogate_entry_refuses_to_start(cheap):
    with pytest.raises(SinkUnavailable, match="entry 0: the value is not valid UTF-8"):
        build_forwarders(_sink({"env": json.loads('"\\ud800"')}), IDS,
                         cheap_detectors=cheap, background=False)


def test_it_is_checked_even_where_the_sink_is_not_configured(cheap, monkeypatch):
    monkeypatch.delenv("SINK_EP_MISSING", raising=False)
    with pytest.raises(SinkUnavailable, match="entry 0: the value matches"):
        build_forwarders(_sink({"owner": FAKE_AWS_KEY}, endpoint="$SINK_EP_MISSING"), IDS,
                         cheap_detectors=cheap, background=False)


def test_a_value_is_not_an_env_reference(cheap, monkeypatch):
    monkeypatch.setenv("SINK_META_ENV", FAKE_AWS_KEY)
    (fw,) = build_forwarders(_sink({"env": "$SINK_META_ENV"}), IDS,
                             cheap_detectors=cheap, background=False)
    assert fw.config.metadata == {"env": "$SINK_META_ENV"}


def test_a_metadata_section_that_is_not_a_mapping_refuses_to_start(cheap):
    with pytest.raises(SinkUnavailable, match="not a mapping"):
        build_forwarders(_sink(["env=prod"]), IDS, cheap_detectors=cheap, background=False)


def test_benign_metadata_is_forwarded_unchanged(cheap):
    metadata = {"env": "prod", "business_unit": "platform", "region": "eu-west-1"}
    (fw,) = build_forwarders(_sink(metadata), IDS, cheap_detectors=cheap, background=False)
    assert fw.config.metadata == metadata
    rec = OtelRecord(kind="log", name="claude_code.user_prompt",
                     attributes={"prompt": "hello there", "session.id": "s1"},
                     resource={"service.name": "claude-code"})
    (out,) = redact_events([rec], {}, fw.plan, fw.config, surface="s", org="o",
                           observed_at="t", detectors=cheap)
    for key, value in metadata.items():
        assert out.attributes[key] == value
    assert "metadata" not in out.redactions


def test_the_collector_refuses_to_start(tmp_path, monkeypatch):
    from forgd_verdict.otel.app import Collector
    from forgd_verdict.policy import Policy

    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "findings"))
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["otel"]["orgs"] = [{"id": "org-abc", "label": "primary",
                            "token": "otel-token-for-the-tests-only"}]
    raw["sinks"] = _sink({"owner": FAKE_AWS_KEY})
    with pytest.raises(SinkUnavailable) as e:
        Collector(Policy(raw=raw), store=None)
    assert FAKE_AWS_KEY not in str(e.value)


def test_a_detector_that_fails_while_checking_refuses(cheap):
    from forgd_verdict.detectors.base import TIER_T0, DetectorFailed

    class Fails:
        name, tier, severity = "flaky", TIER_T0, "block"

        def available(self):
            return True

        def scan(self, units):
            raise DetectorFailed("daemon went away")

    with pytest.raises(SinkUnavailable) as exc:
        build_forwarders(_sink({"env": "prod"}), IDS,
                         cheap_detectors=[*cheap, Fails()], background=False)
    assert "could not be checked: flaky failed" in str(exc.value)
    assert "prod" not in str(exc.value) and "env" not in str(exc.value)


def test_a_match_only_a_subprocess_t1_detector_finds_refuses_to_start():
    with pytest.raises(SinkUnavailable, match="entry 0: the value matches marker:token"):
        build_forwarders(_sink({"owner": f"own-{MARKER}"}), IDS,
                         cheap_detectors=[Marker(TIER_T1)], background=False)
