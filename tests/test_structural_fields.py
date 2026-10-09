"""A block's `id`, `tool_use_id`, `name` and `tool_name` are scanned by
every tier but entropy."""

from __future__ import annotations

import uuid

import pytest
from conftest import FAKE_GITHUB_TOKEN

from forgd_verdict.core import decide, scan
from forgd_verdict.detectors.entropy import EntropyDetector
from forgd_verdict.extract import chat_units, compliance_units, frame_units
from forgd_verdict.models import ScanUnit
from forgd_verdict.policy import load_policy


def _uuid(n: int) -> str:
    """A version-4 UUID string, built at run time: the export refuses UUID literals."""
    return str(uuid.UUID(int=n, version=4))


TOOLU = "toolu_01A09q90qw90lq917835lq9X"
# An id that is not an Anthropic tool-use id, so it is scanned.
OTHER_ID = "call_8aB7c9Dd0eF1gH2iJ3kL4m"


def _decide(units):
    policy = load_policy("policy.yaml")
    detectors = [d for d in policy.build_detectors() if d.name != "gitleaks"]
    result = scan(units, detectors)
    return result, decide(result.findings, policy, dropped=result.detectors_skipped)


def _blocks(field: str, value: str) -> list[dict]:
    """A tool_use and its tool_result, with `value` in `field` of one of them."""
    use = {"type": "tool_use", "id": TOOLU, "name": "run", "input": {"cmd": "ls"}}
    res = {"type": "tool_result", "tool_use_id": TOOLU, "content": "ok"}
    if field in ("id", "name"):
        use[field] = value
    else:
        res[field] = value
    return [use, res]


@pytest.mark.parametrize("field", ["id", "tool_use_id", "name"])
def test_a_token_in_a_structural_field_of_a_frame_denies(field):
    messages = [{"role": "assistant", "content": _blocks(field, FAKE_GITHUB_TOKEN)}]
    result, verdict = _decide(frame_units(messages))
    assert verdict.action == "deny"
    assert any(f.detector.startswith("regex:github") for f in result.findings)


@pytest.mark.parametrize("field", ["id", "tool_use_id", "name"])
def test_a_token_in_a_structural_field_of_a_compliance_transcript_denies(field):
    messages = [{"role": "assistant", "content": _blocks(field, FAKE_GITHUB_TOKEN)}]
    _, verdict = _decide(compliance_units(messages))
    assert verdict.action == "deny"


def test_a_token_in_an_unknown_blocks_id_denies():
    messages = [{"role": "user", "content": [
        {"type": "wingding", "id": FAKE_GITHUB_TOKEN, "text": "hi"}]}]
    _, verdict = _decide(frame_units(messages))
    assert verdict.action == "deny"


def test_a_token_in_a_chat_blocks_id_denies():
    chat = {"chat_messages": [{"content": [
        {"type": "tool_use", "id": FAKE_GITHUB_TOKEN, "name": "x", "input": {}}]}]}
    _, verdict = _decide(chat_units(chat))
    assert verdict.action == "deny"


def test_structural_units_are_marked():
    blocks = _blocks("id", OTHER_ID)
    blocks[1]["tool_use_id"] = OTHER_ID + "x"
    units = frame_units([{"role": "assistant", "content": blocks}])
    marked = {u.locator: u.structural for u in units}
    assert marked["msg[0].content[0].id"] is True
    assert marked["msg[0].content[1].tool_use_id"] is True
    assert marked["msg[0].content[0].input.cmd"] is False


@pytest.mark.parametrize("value", [TOOLU, "srvtoolu_01ABCdef", "mcptoolu_9Zz"])
def test_an_anthropic_tool_use_id_adds_no_unit(value):
    units = frame_units([{"role": "assistant", "content": [
        {"type": "tool_use", "id": value, "name": "Bash", "input": {"cmd": "ls"}},
        {"type": "tool_result", "tool_use_id": value, "content": "ok"}]}])
    assert value not in [u.text for u in units]


def test_a_repeated_structural_value_is_one_unit():
    name = "mcp__github__create_issue"
    blocks = [{"type": "tool_use", "id": f"toolu_{i}", "name": name, "input": {}}
              for i in range(50)]
    units = frame_units([{"role": "assistant", "content": blocks}])
    assert [u.text for u in units].count(name) == 1


def test_a_short_structural_value_adds_no_unit():
    units = frame_units([{"role": "assistant", "content": [
        {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"cmd": "ls"}}]}])
    assert [u.locator for u in units] == ["msg[0].content[0].input.cmd"]


def test_entropy_skips_a_structural_unit():
    text = f"api_key={TOOLU}abcdefXYZ0123"
    plain = ScanUnit(locator="a", tool_name=None, text=text)
    structural = ScanUnit(locator="b", tool_name=None, text=text, structural=True)
    detector = EntropyDetector()
    assert detector.scan([plain])
    assert detector.scan([structural]) == []
    assert list(detector.matches([structural])) == []


def test_a_real_tool_use_id_raises_no_entropy_finding():
    messages = [{"role": "assistant", "content": _blocks("id", TOOLU)}]
    result, verdict = _decide(frame_units(messages))
    assert not [f for f in result.findings if f.detector.startswith("entropy")]
    assert verdict.action == "allow"


def _otel(records: list[dict]):
    from test_otel_payload import RESOURCE, logs_json

    from forgd_verdict.otel.payload import decode

    body = logs_json([{"attributes": a, "body": ""} for a in records], RESOURCE)
    return decode(body, "application/json", "logs")


def _collect(records):
    from forgd_verdict.otel.collect import collect

    policy = load_policy("policy.yaml").for_profile("otel")
    detectors = [d for d in policy.build_detectors() if d.name != "gitleaks"]
    (rec,), _ = collect(records, detectors, budget_ms=1000, policy=policy)
    return rec


@pytest.mark.parametrize("key", ["tool_use_id", "note_id", "prompt.id", "message.uuid"])
def test_a_token_in_an_otel_identity_attribute_denies(key):
    rec = _collect(_otel([{"event.name": "claude_code.tool_result", "session.id": "s",
                           key: FAKE_GITHUB_TOKEN}]))
    assert rec.action == "deny"
    assert rec.findings_count == 1


def test_ordinary_otel_identity_values_allow():
    rec = _collect(_otel([{
        "event.name": "claude_code.tool_result",
        "session.id": _uuid(1),
        "prompt.id": _uuid(2),
        "tool_use_id": TOOLU,
        "user.email": "ann@example.com",
        "event.timestamp": "2026-10-05T12:34:56.789Z",
        "tool_name": "Bash",
    }]))
    assert rec.action == "allow"
    assert rec.findings_count == 0


def test_a_repeated_otel_identity_value_is_one_unit():
    from forgd_verdict.otel.extract import records_units

    event, session = "claude_code.user_prompt", "sess-0042-abcdefgh"
    records = _otel([{"event.name": event, "session.id": session} for _ in range(100)])
    texts = sorted(u.text for u in records_units(records) if u.structural)
    assert texts == sorted([event, session])


def test_plain_otel_identity_values_add_no_unit():
    from forgd_verdict.otel.extract import records_units

    plain = {"session.id": _uuid(3),
             "event.timestamp": "2026-10-05T12:34:56.789Z",
             "trace_id": "0af7651916cd43dd8448eb211c80319c",
             "span_id": "b7ad6b7169203331",
             "tool_use_id": TOOLU}
    records = _otel([{"event.name": "x", **plain}])
    texts = [u.text for u in records_units(records)]
    assert not set(plain.values()) & set(texts)
