"""A value over an adapter's size limit: head and tail are scanned and the
middle is reported as unscanned.

Each case places a fixture key just inside or just outside a boundary and
asserts either that the key is found, or that the verdict denies for the
size limit under either `on_tier_dropped` while the policy has a blocking
detector.
"""

from __future__ import annotations

import json

import pytest
from conftest import FAKE_AWS_KEY, WHSEC, ASGIClient, frame, make_policy, sign

from forgd_verdict.core import UNSCANNED, decide, scan
from forgd_verdict.detectors.base import TIER_T2
from forgd_verdict.extract import MAX_UNIT_BYTES, TAIL_UNIT_BYTES, frame_units, hook_units
from forgd_verdict.otel.extract import record_units, record_units_by_key
from forgd_verdict.otel.payload import MAX_VALUE_CHARS, TAIL_VALUE_CHARS, decode
from forgd_verdict.policy import Policy, load_policy
from forgd_verdict.server.app import VerdictServer

KEY = FAKE_AWS_KEY
M, T = MAX_UNIT_BYTES, TAIL_UNIT_BYTES
FAR = 1000


def pad(n: int) -> str:
    return " " * n


@pytest.fixture(scope="module")
def detectors():
    """T0 and T1 without gitleaks: the regex tier finds the key, and the
    tests do not depend on a gitleaks binary or the budget."""
    return [d for d in load_policy("policy.yaml").build_detectors()
            if d.tier < TIER_T2 and d.name != "gitleaks"]


def _policy(on_tier_dropped: str):
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["server"]["on_tier_dropped"] = on_tier_dropped
    return Policy(raw=raw)


def _verdict(units, detectors, on_tier_dropped):
    result = scan(units, detectors)
    return result, decide(result.findings, _policy(on_tier_dropped),
                          dropped=result.detectors_skipped)


def _found(result) -> bool:
    return any(f.detector.startswith("regex:aws") for f in result.findings)


def _no_content_anywhere(result, verdict):
    for shown in (repr(result.truncated), repr(result.findings),
                  verdict.deny_reason or "", verdict.reference_id or "",
                  repr(result.detectors_skipped)):
        assert KEY not in shown


# Texts where the key is in a part that is scanned.
SCANNED = {
    "end of the head": pad(M - len(KEY)) + KEY + pad(T + FAR),
    "start of the tail": pad(M + FAR) + KEY + pad(T - len(KEY)),
    "start of the head": KEY + pad(M + T + FAR),
    "end of the tail": pad(M + T + FAR) + KEY,
}

# Texts where the key, or part of it, is in the unscanned middle.
UNSCANNED_TEXTS = {
    "just past the head": pad(M) + KEY + pad(T + FAR),
    "just before the tail": pad(M + FAR) + KEY + pad(T),
    "across the end of the head": pad(M - 10) + KEY + pad(T + FAR),
    "across the start of the tail": pad(M + FAR) + KEY + pad(T - 10),
    "in the middle": pad(M + FAR) + KEY + pad(T + FAR),
}


@pytest.mark.parametrize("where", sorted(SCANNED))
@pytest.mark.parametrize("on_tier_dropped", ["allow", "deny"])
def test_a_key_in_the_head_or_tail_is_found(where, on_tier_dropped, detectors):
    units = frame_units([{"role": "user", "content": [
        {"type": "text", "text": SCANNED[where]}]}])
    result, verdict = _verdict(units, detectors, on_tier_dropped)
    assert _found(result), where
    assert verdict.action == "deny"
    assert UNSCANNED in result.detectors_skipped
    _no_content_anywhere(result, verdict)


@pytest.mark.parametrize("where", sorted(UNSCANNED_TEXTS))
def test_a_key_in_the_middle_denies_under_deny(where, detectors):
    units = frame_units([{"role": "user", "content": [
        {"type": "text", "text": UNSCANNED_TEXTS[where]}]}])
    result, verdict = _verdict(units, detectors, "deny")
    assert not _found(result), where
    assert verdict.action == "deny"
    assert "over the size limit for scanning" in verdict.deny_reason
    assert verdict.reference_id
    _no_content_anywhere(result, verdict)


@pytest.mark.parametrize("where", sorted(UNSCANNED_TEXTS))
def test_a_key_in_the_middle_denies_under_allow(where, detectors):
    units = frame_units([{"role": "user", "content": [
        {"type": "text", "text": UNSCANNED_TEXTS[where]}]}])
    result, verdict = _verdict(units, detectors, "allow")
    assert not _found(result), where
    assert verdict.action == "deny"
    assert "over the size limit for scanning" in verdict.deny_reason
    assert UNSCANNED in result.detectors_skipped
    assert result.truncated == ["msg[0].content[0]"]
    _no_content_anywhere(result, verdict)


def test_no_match_is_made_across_the_gap(detectors):
    """The head ends with the first half of the key and the tail starts
    with the second. The seam re-scan would join them."""
    text = pad(M - 10) + KEY[:10] + pad(FAR) + KEY[10:] + pad(T - 10)
    units = frame_units([{"role": "user", "content": [{"type": "text", "text": text}]}])
    head, tail = units
    assert head.text.endswith(KEY[:10]) and tail.text.startswith(KEY[10:])
    result, verdict = _verdict(units, detectors, "allow")
    assert not _found(result)
    assert "over the size limit for scanning" in verdict.deny_reason


def test_a_key_across_head_and_tail_with_no_gap_is_found(detectors):
    """Head and tail are adjacent when the value fits in both, so the seam
    between them is scanned."""
    text = pad(M - 10) + KEY + pad(50)
    units = frame_units([{"role": "user", "content": [{"type": "text", "text": text}]}])
    assert len(units) == 2 and not any(u.truncated for u in units)
    result, verdict = _verdict(units, detectors, "allow")
    assert _found(result)
    assert UNSCANNED not in result.detectors_skipped
    assert verdict.action == "deny"


def test_a_policy_with_no_blocking_detector_allows_under_deny(detectors):
    """Nothing in the middle could have denied."""
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["server"]["on_tier_dropped"] = "deny"
    for cfg in raw["detectors"].values():
        if isinstance(cfg, dict):
            cfg["severity"] = "warn"
    verdict = decide([], Policy(raw=raw), dropped=[UNSCANNED])
    assert verdict.action == "allow"
    raw["server"]["on_tier_dropped"] = "allow"
    assert decide([], Policy(raw=raw), dropped=[UNSCANNED]).action == "allow"


def test_the_hook_scans_head_and_tail(detectors):
    """Adapter 2 and the intake's /scan build units through the same `_add`."""
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Write",
               "tool_input": {"content": pad(M + T + FAR) + KEY}}
    result, verdict = _verdict(hook_units(payload), detectors, "allow")
    assert _found(result)
    payload["tool_input"]["content"] = pad(M + FAR) + KEY + pad(T + FAR)
    result, verdict = _verdict(hook_units(payload), detectors, "deny")
    assert not _found(result)
    assert verdict.action == "deny"


def test_a_truncated_frame_does_not_advance_the_session_cache(detectors):
    from forgd_verdict.budget import Budget
    from forgd_verdict.cache import InMemoryLRUCache
    from forgd_verdict.core import scan_frame

    messages = [{"role": "user", "content": [
        {"type": "text", "text": UNSCANNED_TEXTS["in the middle"]}]}]
    cache = InMemoryLRUCache()
    scan_frame(messages, frame_units, detectors, Budget(60000), cache, ("t", "s"))
    assert cache.get(("t", "s")) is None


# -- adapter 1, end to end ----------------------------------------------


def _server(tmp_path, on_tier_dropped):
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "on_tier_dropped": on_tier_dropped,
                "csv_path": str(tmp_path / "t.csv")},
    )
    server = VerdictServer(policy)
    rows = []
    server.sink.submit = lambda row, findings: rows.append(row)
    return server, rows


async def _post(server, text):
    raw = json.dumps(frame([{"role": "user", "content": [
        {"type": "text", "text": text}]}])).encode()
    return await ASGIClient(server).post("/hook", raw, sign(raw))


async def test_the_server_denies_an_unscanned_middle_under_deny(tmp_path):
    server, rows = _server(tmp_path, "deny")
    try:
        status, body = await _post(server, UNSCANNED_TEXTS["in the middle"])
    finally:
        server.close()
    assert status == 200
    assert body["action"] == "deny"
    assert "over the size limit for scanning" in body["deny_reason"]
    assert KEY not in json.dumps(body)
    assert rows[0]["tiers_dropped"] == [UNSCANNED]


async def test_the_server_denies_and_reports_an_unscanned_middle_under_allow(tmp_path):
    server, rows = _server(tmp_path, "allow")
    try:
        status, body = await _post(server, UNSCANNED_TEXTS["in the middle"])
        counters = server.metrics.snapshot()["counters"]
    finally:
        server.close()
    assert status == 200
    assert body["action"] == "deny"
    assert "over the size limit for scanning" in body["deny_reason"]
    assert KEY not in json.dumps(body)
    assert rows[0]["tiers_dropped"] == [UNSCANNED]
    assert counters["oversize_unscanned"] == 1
    assert counters["tiers_dropped"] == 1
    assert KEY not in json.dumps(rows)


async def test_the_server_finds_a_key_in_the_tail(tmp_path):
    server, rows = _server(tmp_path, "allow")
    try:
        status, body = await _post(server, SCANNED["end of the tail"])
    finally:
        server.close()
    assert body["action"] == "deny"
    assert "AWS" in body["deny_reason"]


# -- adapter 4 ----------------------------------------------------------

MV, TV = MAX_VALUE_CHARS, TAIL_VALUE_CHARS


def _otel_record(prompt: str):
    from test_otel_payload import RESOURCE, logs_json

    body = logs_json([{"attributes": {"event.name": "claude_code.user_prompt",
                                      "prompt": prompt, "session.id": "s"},
                       "body": ""}], RESOURCE)
    return decode(body, "application/json", "logs")[0]


def _otel_record_pb(prompt: str):
    from test_otel_payload import RESOURCE, logs_protobuf

    body = logs_protobuf([{"attributes": {"event.name": "claude_code.user_prompt",
                                          "prompt": prompt, "session.id": "s"},
                           "body": ""}], RESOURCE)
    return decode(body, "application/x-protobuf", "logs")[0]


OTEL_SCANNED = {
    "end of the head": pad(MV - len(KEY)) + KEY + pad(TV + FAR),
    "start of the tail": pad(MV + FAR) + KEY + pad(TV - len(KEY)),
    "end of the tail": pad(MV + TV + FAR) + KEY,
}
OTEL_UNSCANNED = {
    "just past the head": pad(MV) + KEY + pad(TV + FAR),
    "just before the tail": pad(MV + FAR) + KEY + pad(TV),
    "in the middle": pad(MV + FAR) + KEY + pad(TV + FAR),
}


@pytest.mark.parametrize("build", [_otel_record, _otel_record_pb], ids=["json", "protobuf"])
@pytest.mark.parametrize("where", sorted(OTEL_SCANNED))
def test_otel_finds_a_key_in_the_head_or_tail(where, build, detectors):
    rec = build(OTEL_SCANNED[where])
    result = scan(record_units(rec), detectors)
    assert _found(result), where
    assert UNSCANNED in result.detectors_skipped


@pytest.mark.parametrize("build", [_otel_record, _otel_record_pb], ids=["json", "protobuf"])
@pytest.mark.parametrize("where", sorted(OTEL_UNSCANNED))
def test_otel_reports_a_key_in_the_middle(where, build, detectors):
    rec = build(OTEL_UNSCANNED[where])
    units = record_units(rec)
    assert all(u.truncated for u in units if "prompt" in u.locator)
    result = scan(units, detectors)
    assert not _found(result), where
    assert UNSCANNED in result.detectors_skipped
    assert KEY not in repr(result.truncated)


def test_otel_forwards_only_the_head():
    """Adapter 5 puts values back on the attribute they came from, so the
    keyed units it reads are the heads, and the head is what is forwarded."""
    rec = _otel_record(OTEL_SCANNED["end of the tail"])
    assert len(rec.attributes["prompt"]) == MV
    assert not any(u.tail for _, u in record_units_by_key(rec))
    assert any(u.tail for u in record_units(rec))


async def test_the_collector_records_and_counts_an_unscanned_middle(tmp_path, monkeypatch):
    from test_otel_collector import auth, stored
    from test_otel_collector import make_policy as otel_policy
    from test_otel_payload import RESOURCE, logs_json

    from forgd_verdict.otel.app import Collector
    from forgd_verdict.store.local import LocalFileStore

    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    raw = otel_policy().raw
    raw["server"]["metrics_token"] = "stats-token-0123456789abcdef"
    c = Collector(Policy(raw=raw), store=LocalFileStore(tmp_path / "f", instance="t"))
    try:
        body = logs_json([{"attributes": {
            "event.name": "claude_code.user_prompt", "session.id": "s",
            "prompt.id": "p", "prompt": OTEL_UNSCANNED["in the middle"]},
            "body": ""}], RESOURCE)
        client = ASGIClient(c)
        status, _ = await client.post("/v1/logs", body, auth())
        assert status == 200
        _, stats = await client.get("/stats", {"authorization": "Bearer " + "stats-token-0123456789abcdef"})
        records = stored(c)
    finally:
        c.close()
    assert stats["counts"]["oversize_unscanned"] == 1
    assert UNSCANNED in records[0].tiers_dropped
    assert records[0].findings_count == 0


def _nested_kvlist(leaf: str, depth: int) -> dict:
    node: dict = {"stringValue": leaf}
    for _ in range(depth):
        node = {"kvlistValue": {"values": [{"key": "k", "value": node}]}}
    return node


def test_a_deeply_nested_value_stays_bounded_and_is_reported(monkeypatch):
    """Each nesting level JSON-escapes the one below, doubling every
    backslash, so the text grows exponentially with depth unless each
    level is bounded. The top-level cap alone hides that from the result,
    so the size of every intermediate serialisation is measured."""
    from forgd_verdict.otel import payload
    from forgd_verdict.otel.payload import MAX_DEPTH, CappedValue, _any_value

    sizes: list[int] = []
    real = payload.json.dumps

    def measured(*a, **kw):
        out = real(*a, **kw)
        sizes.append(len(out))
        return out

    monkeypatch.setattr(payload.json, "dumps", measured)
    value = _any_value(_nested_kvlist('"' * 2000, MAX_DEPTH))
    monkeypatch.undo()
    assert max(sizes) <= 4 * MAX_VALUE_CHARS
    assert len(value) <= MAX_VALUE_CHARS
    assert isinstance(value, CappedValue) and value.gap > 0


def test_a_nested_value_cut_inside_an_array_is_reported_as_unscanned(detectors):
    from forgd_verdict.otel.payload import OtelRecord, _any_value

    value = _any_value({"arrayValue": {"values": [
        {"stringValue": pad(MV + FAR) + KEY}, {"stringValue": "short"}]}})
    rec = OtelRecord(kind="log", name="x", attributes={"prompt": value})
    result = scan(record_units(rec), detectors)
    assert UNSCANNED in result.detectors_skipped


def test_an_unknown_frame_field_gets_head_and_tail(detectors):
    from forgd_verdict.extract import unknown_frame_units

    units = unknown_frame_units({"type": "future", "blob": pad(M + T + FAR) + KEY})
    result = scan(units, detectors)
    assert _found(result)
    assert UNSCANNED in result.detectors_skipped


# -- adapters 3 and 6: an unscanned middle denies there too ---------------

MIDDLE = UNSCANNED_TEXTS["in the middle"]


def _compliance_policy(tmp_path, on_tier_dropped):
    return make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        compliance={"state_path": str(tmp_path / "state.json"), "api_key": "sk-ant-api01-x"},
        server={"on_tier_dropped": on_tier_dropped},
    )


@pytest.mark.parametrize("on_tier_dropped, action", [("deny", "deny"), ("allow", "deny")])
def test_a_compliance_session_with_an_unscanned_middle_denies(
        on_tier_dropped, action, tmp_path):
    from test_compliance import SESSION, StubClient, transcript

    from forgd_verdict.compliance.scanner import ComplianceScanner

    stub = StubClient(sessions=[SESSION], messages={SESSION["id"]: transcript(MIDDLE)})
    scanner = ComplianceScanner(_compliance_policy(tmp_path, on_tier_dropped), client=stub)
    (report,) = list(scanner.scan_sessions())
    assert not report.findings
    assert UNSCANNED in report.tiers_dropped
    assert report.action == action


@pytest.mark.parametrize("on_tier_dropped, action", [("deny", "deny"), ("allow", "deny")])
def test_a_compliance_chat_with_an_unscanned_middle_denies(
        on_tier_dropped, action, tmp_path):
    from test_compliance import CHAT, ChatStub, chat_with

    from forgd_verdict.compliance.scanner import ComplianceScanner

    stub = ChatStub(chats=[CHAT], full={CHAT["id"]: chat_with(MIDDLE)})
    scanner = ComplianceScanner(_compliance_policy(tmp_path, on_tier_dropped), client=stub)
    (report,) = list(scanner.scan_chats())
    assert not report.findings
    assert UNSCANNED in report.tiers_dropped
    assert report.action == action


@pytest.mark.parametrize("on_tier_dropped, action", [("deny", "deny"), ("allow", "deny")])
def test_a_managed_session_with_an_unscanned_middle_denies(
        on_tier_dropped, action, tmp_path, monkeypatch):
    from test_managed_agents import KEY, WS_KEY, FakeClient, history, session

    from forgd_verdict.managed.scanner import ManagedScanner
    from forgd_verdict.policy import DEFAULT_POLICY, _deep_merge

    monkeypatch.chdir(tmp_path)
    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "privacy": {"hash_salt": "s"},
        "detectors": {"gitleaks": {"enabled": False, "severity": "block"}},
        "server": {"on_tier_dropped": on_tier_dropped},
        "managed_agents": {"workspaces": [{"key": WS_KEY, "label": "prod", "api_key": KEY}]},
    }))
    s = session("sesn_1")
    scanner = ManagedScanner(policy, {"key": WS_KEY, "label": "prod", "api_key": KEY},
                             client=FakeClient([s], {"sesn_1": history(MIDDLE)}))
    (report,) = list(scanner.scan())
    assert UNSCANNED in report.tiers_dropped
    assert not [f for f in report.findings if f.severity == "block"]
    assert report.action == action


# -- adapter 4: on_tier_dropped applies there too --------------------------

class _BlockingT2:
    """A T2 detector named after a `block` detector in policy.yaml."""

    name = "gitleaks"
    tier = TIER_T2
    severity = "block"

    def available(self) -> bool:
        return True

    def scan(self, units):
        raise AssertionError("budget_ms=0 must drop this tier before it runs")


@pytest.mark.parametrize("on_tier_dropped, action", [("deny", "deny"), ("allow", "deny")])
def test_an_otel_turn_with_an_unscanned_middle_denies(
        on_tier_dropped, action, detectors):
    from forgd_verdict.otel.collect import collect

    (rec,), _ = collect([_otel_record(OTEL_UNSCANNED["in the middle"])], detectors,
                        budget_ms=1000, policy=_policy(on_tier_dropped))
    assert not rec.findings
    assert UNSCANNED in rec.tiers_dropped
    assert rec.action == action


@pytest.mark.parametrize("on_tier_dropped, action", [("deny", "deny"), ("allow", "allow")])
def test_an_otel_turn_whose_blocking_tier_was_budget_dropped_follows_on_tier_dropped(
        on_tier_dropped, action, detectors):
    from forgd_verdict.otel.collect import collect

    (rec,), _ = collect([_otel_record("nothing to find here")],
                        [*detectors, _BlockingT2()],
                        budget_ms=0, policy=_policy(on_tier_dropped))
    assert rec.tiers_dropped == ["gitleaks"]
    assert rec.action == action


def test_an_otel_turn_with_no_policy_given_decides_as_allow(detectors):
    from forgd_verdict.otel.collect import collect

    (rec,), _ = collect([_otel_record(OTEL_UNSCANNED["in the middle"])], detectors,
                        budget_ms=1000)
    assert UNSCANNED in rec.tiers_dropped
    assert rec.action == "allow"


# -- a wide value cannot multiply its size by its width ----------------------

ESCAPED = '"\\' * 1000


def _pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _pb_len(field_no: int, payload: bytes) -> bytes:
    return _pb_varint(field_no << 3 | 2) + _pb_varint(len(payload)) + payload


def _pb_string(text: str) -> bytes:
    return _pb_len(1, text.encode())


def _pb_array(values: list[bytes]) -> bytes:
    return _pb_len(5, b"".join(_pb_len(1, v) for v in values))


def _pb_kvlist(pairs: list[tuple[str, bytes]]) -> bytes:
    return _pb_len(6, b"".join(
        _pb_len(1, _pb_len(1, k.encode()) + _pb_len(2, v)) for k, v in pairs))


def _json_wide(width: int, depth: int) -> dict:
    chain: dict = {"stringValue": ESCAPED}
    for _ in range(depth):
        chain = {"arrayValue": {"values": [chain]}}
    return {"kvlistValue": {"values": [{"key": f"k{i}", "value": chain}
                                       for i in range(width)]}}


def _pb_wide(width: int, depth: int) -> bytes:
    chain = _pb_string(ESCAPED)
    for _ in range(depth):
        chain = _pb_array([chain])
    return _pb_kvlist([(f"k{i}", chain) for i in range(width)])


def _measured_dumps(monkeypatch, limit):
    from forgd_verdict.otel import payload

    sizes: list[int] = []
    real = payload.json.dumps

    def measured(*a, **kw):
        out = real(*a, **kw)
        sizes.append(len(out))
        if len(out) > limit:
            raise AssertionError(f"one json.dumps call built {len(out):,} characters")
        return out

    monkeypatch.setattr(payload.json, "dumps", measured)
    return sizes


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_a_wide_nested_value_is_built_within_its_budget(monkeypatch, encoding):
    """Every child was capped at MAX_VALUE_CHARS, and then the parent
    serialised all of them together: twenty children of about a million
    characters each is one twenty-million-character call from a body of
    a few tens of kilobytes. Every child here doubles in size at each
    level because it is all quotes and backslashes."""
    from forgd_verdict.otel.payload import MAX_DEPTH, CappedValue, _any_value, _pb_any

    width, depth = 20, MAX_DEPTH - 1
    body = (json.dumps(_json_wide(width, depth)).encode() if encoding == "json"
            else _pb_wide(width, depth))
    assert len(body) < 1_000_000
    sizes = _measured_dumps(monkeypatch, 2 * MAX_VALUE_CHARS + 16)
    value = (_any_value(_json_wide(width, depth)) if encoding == "json"
             else _pb_any(body))
    monkeypatch.undo()
    assert sum(sizes) <= 40 * MAX_VALUE_CHARS
    assert len(value) <= MAX_VALUE_CHARS
    assert isinstance(value, CappedValue) and value.gap > 0


def test_a_value_cut_for_its_budget_is_scanned_as_truncated(detectors):
    from forgd_verdict.otel.payload import MAX_DEPTH, OtelRecord, _any_value

    value = _any_value(_json_wide(20, MAX_DEPTH - 1))
    rec = OtelRecord(kind="log", name="x", attributes={"prompt": value})
    units = record_units(rec)
    assert units and units[0].truncated
    assert UNSCANNED in scan(units, detectors).detectors_skipped


def _unbounded(node) -> str:
    """The encoding before the budget, for values that are under it."""
    if isinstance(node, dict) and "stringValue" in node:
        return node["stringValue"]
    if isinstance(node, dict) and "arrayValue" in node:
        return json.dumps([_unbounded(v) for v in node["arrayValue"]["values"]])
    return json.dumps({p["key"]: _unbounded(p["value"])
                       for p in node["kvlistValue"]["values"]})


NORMAL = {"kvlistValue": {"values": [
    {"key": "command", "value": {"stringValue": 'echo "hi" \\ done'}},
    {"key": "env", "value": {"arrayValue": {"values": [
        {"stringValue": "A=1"}, {"stringValue": "naïve ✓"},
        {"kvlistValue": {"values": [
            {"key": "nested", "value": {"stringValue": "tab\there"}},
            {"key": "nested", "value": {"stringValue": "second wins"}},
            {"key": "other", "value": {"arrayValue": {"values": [
                {"stringValue": "x"}]}}}]}}]}}},
    {"key": "command", "value": {"stringValue": "replaced, first position"}},
]}}


def test_a_normal_nested_value_is_byte_identical():
    from forgd_verdict.otel.payload import CappedValue, _any_value

    assert _any_value(NORMAL) == _unbounded(NORMAL)
    assert not isinstance(_any_value(NORMAL), CappedValue)


def test_a_normal_nested_protobuf_value_is_byte_identical():
    from forgd_verdict.otel.payload import _pb_any

    def pb(node) -> bytes:
        if "stringValue" in node:
            return _pb_string(node["stringValue"])
        if "arrayValue" in node:
            return _pb_array([pb(v) for v in node["arrayValue"]["values"]])
        return _pb_kvlist([(p["key"], pb(p["value"])) for p in node["kvlistValue"]["values"]])

    assert _pb_any(pb(NORMAL)) == _unbounded(NORMAL)


# -- content nested past MAX_DEPTH ----------------------------------------

SIBLING = "a sibling after the deep branch"


def _json_deep(levels: int) -> dict:
    """`levels` arrays around KEY, the outermost holding SIBLING after it."""
    node: dict = {"stringValue": f"deploy with {KEY}"}
    for _ in range(levels - 1):
        node = {"arrayValue": {"values": [node]}}
    return {"arrayValue": {"values": [node, {"stringValue": SIBLING}]}}


def _pb_deep(levels: int) -> bytes:
    from test_otel_payload import _any_string, _len_field

    node = _any_string(f"deploy with {KEY}")
    for _ in range(levels - 1):
        node = _len_field(5, _len_field(1, node))
    return _len_field(5, _len_field(1, node) + _len_field(1, _any_string(SIBLING)))


def _deep_value(encoding: str, levels: int) -> str:
    from forgd_verdict.otel.payload import _any_value, _pb_any

    return (_any_value(_json_deep(levels)) if encoding == "json"
            else _pb_any(_pb_deep(levels)))


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_content_past_max_depth_marks_the_value_cut(encoding):
    """Past MAX_DEPTH a level rendered as "" and nothing recorded it, so the
    value looked complete and the content was neither scanned nor reported
    as unscanned."""
    from forgd_verdict.otel.payload import MAX_DEPTH, CappedValue

    value = _deep_value(encoding, MAX_DEPTH + 2)
    assert KEY not in value
    assert SIBLING in value
    assert isinstance(value, CappedValue) and value.gap > 0


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_content_at_max_depth_decodes_whole(encoding):
    from forgd_verdict.otel.payload import MAX_DEPTH, CappedValue

    value = _deep_value(encoding, MAX_DEPTH)
    assert KEY in value and SIBLING in value
    assert not isinstance(value, CappedValue)


@pytest.mark.parametrize("encoding", ["json", "protobuf"])
def test_a_value_cut_at_max_depth_is_scanned_as_truncated(detectors, encoding):
    from forgd_verdict.otel.payload import MAX_DEPTH, OtelRecord

    rec = OtelRecord(kind="log", name="x",
                     attributes={"tool_parameters": _deep_value(encoding, MAX_DEPTH + 2)})
    units = record_units(rec)
    assert units and units[0].truncated
    assert UNSCANNED in scan(units, detectors).detectors_skipped


async def test_the_collector_records_content_past_max_depth_as_unscanned(tmp_path, monkeypatch):
    from test_otel_collector import auth, stored
    from test_otel_collector import make_policy as otel_policy
    from test_otel_payload import RESOURCE, _json_attrs

    from forgd_verdict.otel.app import Collector
    from forgd_verdict.otel.payload import MAX_DEPTH
    from forgd_verdict.store.local import LocalFileStore

    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    raw = otel_policy().raw
    raw["server"]["metrics_token"] = "stats-token-0123456789abcdef"
    c = Collector(Policy(raw=raw), store=LocalFileStore(tmp_path / "f", instance="t"))
    attrs = _json_attrs({"event.name": "claude_code.tool_result", "session.id": "s",
                         "prompt.id": "p"})
    attrs.append({"key": "tool_parameters", "value": _json_deep(MAX_DEPTH + 2)})
    body = json.dumps({"resourceLogs": [{
        "resource": {"attributes": _json_attrs(RESOURCE)},
        "scopeLogs": [{"logRecords": [{"attributes": attrs}]}]}]}).encode()
    try:
        client = ASGIClient(c)
        status, _ = await client.post("/v1/logs", body, auth())
        assert status == 200
        _, stats = await client.get("/stats", {"authorization": "Bearer " + "stats-token-0123456789abcdef"})
        records = stored(c)
    finally:
        c.close()
    assert stats["counts"]["oversize_unscanned"] == 1
    assert UNSCANNED in records[0].tiers_dropped
