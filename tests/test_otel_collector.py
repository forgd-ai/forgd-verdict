"""Adapter 4's receiver: auth, routing, and what must never leak.

The security-relevant tests here are the last three. This service takes raw
prompt text over the wire from surfaces Anthropic does not redact, which
makes it the most sensitive listener in the project.
"""

from __future__ import annotations

import json
import logging

import pytest
from conftest import ASGIClient
from test_otel_payload import RESOURCE, logs_json, logs_protobuf, traces_json

from forgd_verdict.otel import SURFACE_CODE
from forgd_verdict.otel.app import Collector
from forgd_verdict.policy import Policy, load_policy
from forgd_verdict.store.base import SOURCE_OTEL_COLLECT
from forgd_verdict.store.local import LocalFileStore

TOKEN = "otel-token-for-the-tests-only"
ORG = "org-abc"
SEEDED = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture(autouse=True)
def _store_in_tmp(tmp_path, monkeypatch):
    """The shipped policy names its store as `$FORGD_VERDICT_STORE`.

    Tests here that pass `store=None` fall through to that spec. Unset, it
    is refused, so point it somewhere disposable.
    """
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "findings"))
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")


def make_policy(**otel_overrides):
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["otel"].update(
        {"orgs": [{"id": ORG, "label": "primary", "token": TOKEN}], **otel_overrides}
    )
    return Policy(raw=raw)


@pytest.fixture
def collector(tmp_path):
    store = LocalFileStore(tmp_path / "findings", instance="test")
    c = Collector(make_policy(), store=store)
    yield c
    c.close()


def code_batch(prompt: str = f"deploy with {SEEDED}"):
    return logs_json(
        [
            {
                "attributes": {
                    "event.name": "claude_code.user_prompt",
                    "prompt": prompt,
                    "session.id": "sess-1",
                    "prompt.id": "turn-1",
                    "user.email": "someone@example.com",
                },
                "body": "",
            }
        ],
        RESOURCE,
    )


def auth(extra: dict | None = None) -> dict:
    return {"authorization": f"Bearer {TOKEN}",
            "content-type": "application/json", **(extra or {})}


def stored(collector):
    collector.sink.close()
    return list(collector.sink.store.read_verdicts())


async def test_a_claude_code_export_produces_a_finding_for_the_right_org(collector):
    client = ASGIClient(collector)
    status, body = await client.post("/v1/logs", code_batch(), auth())
    assert status == 200
    assert body == {"partialSuccess": {}}

    records = stored(collector)
    assert len(records) == 1
    rec = records[0]
    assert rec.source == SOURCE_OTEL_COLLECT
    assert rec.surface == SURFACE_CODE
    assert rec.tenant_hash and rec.tenant_hash.startswith("org_")
    assert rec.findings_count >= 1
    # Detection, never enforcement: this control cannot prevent anything.
    assert rec.is_inline is False


async def test_office_agent_traces_route_to_the_traces_path(collector):
    spans = [
        {
            "name": "agent.query",
            "attributes": {"session.id": "s-9", "prompt.id": "t-9"},
            "events": [
                {
                    "name": "agent.tool_execution",
                    "attributes": {"tool.input": f"write {SEEDED} to the sheet"},
                }
            ],
        }
    ]
    client = ASGIClient(collector)
    status, _ = await client.post(
        "/v1/traces", traces_json(spans, {"service.name": "claude-sheet",
                                          "organization.id": ORG}), auth()
    )
    assert status == 200
    records = stored(collector)
    assert len(records) == 1
    assert records[0].surface == "office-excel"
    assert records[0].findings_count >= 1


async def test_a_turn_is_one_record_not_one_per_event(collector):
    """A single turn emits a prompt, a response and an event per tool call.

    Counting those as requests would report the surface several times
    busier than it is and skew every rate on the dashboard.
    """
    events = [
        {"attributes": {"event.name": "claude_code.user_prompt",
                        "prompt": "a prompt long enough to scan",
                        "prompt.id": "turn-7", "session.id": "s-7"}, "body": ""},
        {"attributes": {"event.name": "claude_code.tool_result",
                        "tool_parameters": '{"command": "echo hello there"}',
                        "prompt.id": "turn-7", "session.id": "s-7"}, "body": ""},
        {"attributes": {"event.name": "claude_code.assistant_response",
                        "response": "a response long enough to scan",
                        "prompt.id": "turn-7", "session.id": "s-7"}, "body": ""},
    ]
    client = ASGIClient(collector)
    status, _ = await client.post("/v1/logs", logs_json(events, RESOURCE), auth())
    assert status == 200
    records = stored(collector)
    assert len(records) == 1
    assert records[0].messages_total == 3
    assert records[0].session_id == "s-7"


async def test_protobuf_and_json_reach_the_same_verdict(collector):
    client = ASGIClient(collector)
    records = [{"attributes": {"event.name": "claude_code.user_prompt",
                               "prompt": f"deploy with {SEEDED}",
                               "prompt.id": "t"}, "body": ""}]
    s1, _ = await client.post("/v1/logs", logs_json(records, RESOURCE), auth())
    s2, _ = await client.post(
        "/v1/logs",
        logs_protobuf(records, RESOURCE),
        auth({"content-type": "application/x-protobuf"}),
    )
    assert (s1, s2) == (200, 200)
    got = stored(collector)
    assert len(got) == 2
    assert got[0].findings_count == got[1].findings_count >= 1


# --- auth ----------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"authorization": "Bearer wrong-token"},
        {"authorization": "Bearer "},
        {"authorization": TOKEN[:-1]},
    ],
)
async def test_an_export_without_a_valid_token_is_refused(collector, headers):
    status, body = await ASGIClient(collector).post(
        "/v1/logs", code_batch(), {"content-type": "application/json", **headers}
    )
    assert status == 401
    assert body == {"error": "unauthorized"}
    assert stored(collector) == []


async def test_a_bare_token_header_is_accepted(collector):
    """Anthropic's console takes OTLP headers as key=value pairs, so an
    operator can configure a header that is not `Authorization`."""
    status, _ = await ASGIClient(collector).post(
        "/v1/logs", code_batch(),
        {"content-type": "application/json", "x-forgd-token": TOKEN},
    )
    assert status == 200


async def test_the_body_is_not_parsed_before_the_token_is_checked(collector, caplog):
    """An unauthenticated sender must not be able to make this process
    decode 8 MB of someone else's prompt text."""
    status, _ = await ASGIClient(collector).post(
        "/v1/logs", b"{definitely not valid json", {"content-type": "application/json"}
    )
    assert status == 401  # not 400: we never got as far as decoding


async def test_an_org_that_does_not_match_the_token_is_refused(collector):
    """The token is what we issued; `organization.id` is what the sender
    claims. Trusting the claim would let one org file findings under
    another org's name."""
    body = logs_json(
        [{"attributes": {"event.name": "claude_code.user_prompt",
                         "prompt": f"deploy with {SEEDED}"}, "body": ""}],
        {"service.name": "claude-code", "organization.id": "some-other-org"},
    )
    status, payload = await ASGIClient(collector).post("/v1/logs", body, auth())
    assert status == 403
    assert payload == {"error": "organization_mismatch"}
    assert stored(collector) == []


# --- failure handling ----------------------------------------------------


async def test_an_undecodable_body_is_400_not_500(collector):
    """It will not parse on retry either, so asking for it again is waste."""
    status, body = await ASGIClient(collector).post(
        "/v1/logs", b"\xff\xff\xff\xff", auth({"content-type": "application/x-protobuf"})
    )
    assert status == 400
    assert body == {"error": "undecodable"}


async def test_an_oversized_body_is_413(tmp_path):
    c = Collector(make_policy(max_body_bytes=64), store=None)
    status, body = await ASGIClient(c).post("/v1/logs", b"x" * 500, auth())
    assert status == 413
    c.close()


async def test_healthz_needs_no_token_and_names_the_build(collector):
    status, body = await ASGIClient(collector).get("/healthz")
    assert status == 200
    assert body["status"] == "ok"
    assert body["build"]
    assert body["orgs_configured"] == 1


async def test_unknown_paths_and_methods_are_refused(collector):
    client = ASGIClient(collector)
    assert (await client.post("/v1/nonsense", b"{}", auth()))[0] == 404
    assert (await client.get("/v1/logs"))[0] == 405


async def test_with_no_orgs_configured_every_export_is_refused(tmp_path):
    """Fail closed: no token means no org to attribute anything to."""
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["otel"]["orgs"] = []
    c = Collector(Policy(raw=raw), store=None)
    status, _ = await ASGIClient(c).post("/v1/logs", code_batch(), auth())
    assert status == 401
    c.close()


# --- privacy -------------------------------------------------------------


async def test_the_prompt_never_reaches_the_store(collector):
    await ASGIClient(collector).post("/v1/logs", code_batch(), auth())
    blob = "".join(repr(r) for r in stored(collector))
    assert SEEDED not in blob
    assert "someone@example.com" not in blob


@pytest.mark.parametrize("body", [
    f"deploy with {SEEDED}".encode(),  # unparseable, so the error path runs
    None,
])
async def test_the_prompt_never_reaches_a_log_record(collector, caplog, body):
    """The error path is where this normally leaks: a decoder that quotes
    the bytes it choked on is quoting someone's prompt."""
    caplog.set_level(logging.DEBUG)
    payload = body if body is not None else code_batch()
    await ASGIClient(collector).post("/v1/logs", payload, auth())
    emitted = "".join(
        [r.getMessage() for r in caplog.records]
        + [repr(getattr(r, "fields", "")) for r in caplog.records]
    )
    assert SEEDED not in emitted
    assert "someone@example.com" not in emitted


async def test_the_collector_token_never_renders_on_the_policy_tab():
    from forgd_verdict.policy import redacted

    blob = repr(redacted(make_policy()))
    assert TOKEN not in blob
    assert "<redacted>" in blob


# --- /stats: did anything arrive, and on which signal -------------------


def stats_policy(**over):
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["otel"].update({"orgs": [{"id": ORG, "label": "primary", "token": TOKEN}]})
    raw["server"]["metrics_token"] = "stats-token-0123456789abcdef"
    raw.update(over)
    return Policy(raw=raw)


async def test_stats_answers_whether_anything_arrived_and_on_which_signal(tmp_path):
    """The question the collector exists to be asked when a surface looks
    silent: traces are the office agents, logs are Cowork and Claude Code.
    A zero distinguishes "not configured" from "configured and failing" --
    and successful exports are deliberately never logged, because logging
    this service's request bodies is how prompt text escapes."""
    c = Collector(stats_policy(), store=LocalFileStore(tmp_path / "s", instance="t"))
    client = ASGIClient(c)
    auth_hdr = {"authorization": "Bearer " + "stats-token-0123456789abcdef"}

    status, body = await client.get("/stats", auth_hdr)
    assert status == 200
    assert body["records_logs"] == 0 and body["records_traces"] == 0

    await client.post("/v1/logs", code_batch(), auth())
    status, body = await client.get("/stats", auth_hdr)
    assert body["records_logs"] == 1, body
    assert body["records_traces"] == 0, body
    assert body["counts"]["accepted"] == 1
    c.close()


async def test_stats_is_absent_without_a_token_and_refuses_a_wrong_one(tmp_path):
    """Fail closed, like the verdict server's /metrics: it reports volumes
    and attribute names rather than content, but a deny rate is still not
    something to publish by default."""
    no_token = stats_policy()
    no_token.raw["server"]["metrics_token"] = ""
    c = Collector(no_token, store=None)
    assert await ASGIClient(c).get("/stats") == (404, {"error": "not_found"})
    c.close()

    c = Collector(stats_policy(), store=None)
    assert await ASGIClient(c).get("/stats") == (401, {"error": "unauthorized"})
    assert await ASGIClient(c).get("/stats", {"authorization": "Bearer wrong"}) == (
        401, {"error": "unauthorized"})
    c.close()


async def test_stats_carries_no_content(tmp_path):
    """It exists to diagnose a silent surface, not to become a second way
    to read findings."""
    c = Collector(stats_policy(), store=LocalFileStore(tmp_path / "s", instance="t"))
    client = ASGIClient(c)
    await client.post("/v1/logs", code_batch(), auth())
    _, body = await client.get("/stats", {"authorization": "Bearer " + "stats-token-0123456789abcdef"})
    blob = json.dumps(body)
    assert SEEDED not in blob
    assert "someone@example.com" not in blob
    c.close()


# -- CORS, and why office agents sent nothing ----------------------------


async def test_a_preflight_is_answered_rather_than_405(collector):
    """The bug that cost every office-agent export.

    Office add-ins are HTML/JS in an embedded WebView -- inside desktop
    Excel, Word and PowerPoint -- and a WebView enforces CORS like a
    browser. Their exporter sends OPTIONS first; this answered 405 to
    anything that was not a POST, so the WebView never sent the POST and
    the collector saw nothing at all. 29 preflights, zero exports, counters
    at zero: indistinguishable from a surface nobody configured.
    """
    client = ASGIClient(collector)
    for path in ("/v1/traces", "/v1/logs", "/v1/metrics"):
        status, _, headers = await client.request(
            "OPTIONS", path, headers={"origin": "https://example.test"}
        )
        assert status == 204, path
        assert headers.get("access-control-allow-origin"), path
        assert "POST" in headers.get("access-control-allow-methods", ""), path


async def test_the_preflight_allows_the_authorization_header(collector):
    """A preflight that omits it fails for a request that carries one --
    which is every request here, since the token is how an org is named."""
    _, _, headers = await ASGIClient(collector).request(
        "OPTIONS", "/v1/traces", headers={"origin": "https://example.test"}
    )
    allowed = headers.get("access-control-allow-headers", "").lower()
    assert "authorization" in allowed, allowed
    assert "content-type" in allowed, allowed


async def test_the_preflight_is_cached_by_the_caller(collector):
    """Without max-age a WebView preflights every single export."""
    _, _, headers = await ASGIClient(collector).request(
        "OPTIONS", "/v1/traces", headers={"origin": "https://example.test"}
    )
    assert int(headers.get("access-control-max-age", "0")) > 0


async def test_an_accepted_export_carries_the_cors_header(collector):
    """Without it the WebView discards a reply it did receive, and the
    exporter records a delivery failure for an export that was stored."""
    status, _, headers = await ASGIClient(collector).request(
        "POST", "/v1/logs", body=code_batch(),
        headers={**auth(), "origin": "https://example.test"},
    )
    assert status == 200
    assert headers.get("access-control-allow-origin")


async def test_a_preflight_still_requires_a_token_on_the_post(collector):
    """CORS is not authentication. The preflight says the browser may try;
    the token still decides."""
    status, _, _ = await ASGIClient(collector).request(
        "OPTIONS", "/v1/logs", headers={"origin": "https://evil.test"}
    )
    assert status == 204
    status, body = await ASGIClient(collector).post(
        "/v1/logs", code_batch(), {"authorization": "Bearer wrong"}
    )
    assert status == 401


# -- metrics -------------------------------------------------------------


async def test_metrics_are_accepted_rather_than_404(collector):
    """An exporter sends every enabled signal to the same base endpoint.

    404 is a delivery failure it retries forever, and an operator reads it
    as the collector being broken. Seen live: OTel-OTLP-Exporter-JavaScript
    posting /v1/metrics and getting 404.
    """
    body = json.dumps({"resourceMetrics": [{"scopeMetrics": [{"metrics": [
        {"name": "claude_code.token.usage"}, {"name": "claude_code.cost.usage"},
    ]}]}]}).encode()
    status, _ = await ASGIClient(collector).post("/v1/metrics", body, auth())
    assert status == 200
    stats = collector.stats()
    assert stats["counts"].get("metrics_accepted") == 1
    assert "claude_code.token.usage" in stats["metrics_names"]


async def test_metrics_still_need_a_token(collector):
    body = json.dumps({"resourceMetrics": []}).encode()
    status, _ = await ASGIClient(collector).post("/v1/metrics", body, {})
    assert status == 401


async def test_a_metrics_body_that_will_not_parse_is_still_accepted(collector):
    """Rejecting it would make an exporter retry forever over a signal we
    do not use. The names are best effort; the acceptance is not."""
    status, _ = await ASGIClient(collector).post("/v1/metrics", b"not-otlp", auth())
    assert status == 200
    assert collector.stats()["metrics_names"] == {}


async def test_the_shipped_policy_allows_the_preflight(tmp_path):
    """A fork gets working add-in telemetry without configuring anything.

    A default that refuses every preflight shows up as zero exports with
    no error -- the shape of default CLAUDE.md warns about: safe-looking,
    and only safe to someone who already knows.
    """
    c = Collector(load_policy("policy.yaml"), store=None)
    try:
        _, _, headers = await ASGIClient(c).request(
            "OPTIONS", "/v1/traces", headers={"origin": "https://addin.example"}
        )
        assert headers.get("access-control-allow-origin") == "*"
    finally:
        c.close()


async def test_a_narrowed_allowlist_refuses_and_records_the_origin(tmp_path):
    """A refused preflight is otherwise visible only in the WebView's own
    console, which is the hardest place to look."""
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["otel"]["cors_origins"] = ["https://allowed.example"]
    c = Collector(Policy(raw=raw), store=None)
    try:
        client = ASGIClient(c)
        _, _, ok = await client.request(
            "OPTIONS", "/v1/traces", headers={"origin": "https://allowed.example"}
        )
        assert ok.get("access-control-allow-origin") == "https://allowed.example"

        _, _, no = await client.request(
            "OPTIONS", "/v1/traces", headers={"origin": "https://other.example"}
        )
        assert "access-control-allow-origin" not in no
        assert c.stats()["refused_origins"] == {"https://other.example": 1}
    finally:
        c.close()


# -- an org token with no id ---------------------------------------------


def test_a_token_without_an_org_id_is_refused():
    """With the id empty the cross-check against the payload's
    `organization.id` cannot run, and any org's batch is accepted on a
    valid token. CLAUDE.md names `otel.orgs[].id` as load-bearing.

    The Helm chart already refuses both a missing and an empty id. A
    deployment that does not go through Helm had nothing stopping it, and
    the only startup diagnostic fires when there are NO tokens at all --
    so this org was indistinguishable from a correct one in the log.
    """
    from forgd_verdict.otel.app import _token_map

    with pytest.raises(ValueError, match="no id"):
        _token_map({"orgs": [{"label": "prod", "token": "a-real-token-0123456789abcdef", "id": ""}]})


def test_an_unresolved_org_id_variable_is_refused(monkeypatch):
    """The realistic shape: `id: $FORGD_ORG_ID_X` with the variable unset
    resolves to empty, which is the same hole arrived at by omission."""
    from forgd_verdict.otel.app import _token_map

    monkeypatch.delenv("FORGD_ORG_ID_MISSING", raising=False)
    with pytest.raises(ValueError, match="no id"):
        _token_map({"orgs": [{"label": "prod", "token": "a-real-token-0123456789abcdef",
                              "id": "$FORGD_ORG_ID_MISSING"}]})


def test_an_org_with_no_usable_token_is_still_just_skipped():
    """Not configured is not the same as misconfigured."""
    from forgd_verdict.otel.app import _token_map

    assert _token_map({"orgs": [{"label": "prod", "id": ""}]}) == {}


# -- every org claim, not the first --------------------------------------


async def test_a_mixed_batch_with_one_evil_claim_is_refused(collector):
    """`next(...)` stopped at the first non-empty claim, so a batch whose
    first resource matched and whose second claimed another org was
    accepted whole.

    Both records landed under the TOKEN's org, so it is a bypass of the
    check rather than tenant selection -- the sender defeats the refusal
    but cannot choose where records go.
    """
    import json as _json

    def group(org_id, text):
        return {"resource": {"attributes": [
                    {"key": "organization.id", "value": {"stringValue": org_id}}]},
                "scopeLogs": [{"logRecords": [
                    {"body": {"stringValue": text},
                     "attributes": [{"key": "event.name",
                                     "value": {"stringValue": "claude_code.user_prompt"}}]}]}]}

    body = _json.dumps({"resourceLogs": [group(ORG, "benign"),
                                         group("org-EVIL", "smuggled")]}).encode()
    status, payload = await ASGIClient(collector).post("/v1/logs", body, auth())
    assert status == 403, payload
    assert payload == {"error": "organization_mismatch"}
    assert stored(collector) == []


async def test_a_batch_whose_claims_all_match_is_accepted(collector):
    import json as _json

    body = _json.dumps({"resourceLogs": [
        {"resource": {"attributes": [
            {"key": "organization.id", "value": {"stringValue": ORG}}]},
         "scopeLogs": [{"logRecords": [
             {"body": {"stringValue": "benign"},
              "attributes": [{"key": "event.name",
                              "value": {"stringValue": "claude_code.user_prompt"}}]}]}]}
    ]}).encode()
    status, _ = await ASGIClient(collector).post("/v1/logs", body, auth())
    assert status == 200


# -- a token too short to be one -----------------------------------------


def test_a_weak_token_is_refused_rather_than_ignored():
    """Separate from `usable_secret`, whose None means NOT CONFIGURED --
    an org with no key is skipped, which is right. Folding a length test
    into that would make a real-but-weak token silently disappear instead
    of being reported."""
    from forgd_verdict.otel.app import _token_map

    with pytest.raises(ValueError, match="characters"):
        _token_map({"orgs": [{"label": "prod", "id": "org-1", "token": "short"}]})


def test_a_strong_token_is_accepted():
    from forgd_verdict.otel.app import _token_map

    m = _token_map({"orgs": [{"label": "prod", "id": "org-1",
                              "token": "a-token-long-enough-to-be-one"}]})
    assert len(m) == 1


# -- a session's findings are recorded once ----------------------------------

def _body_batch(prompt_id: str, messages_text: str, session: str = "sess-9"):
    """A Claude Code `api_request_body` event: the whole conversation so far."""
    return logs_json(
        [{"attributes": {"event.name": "claude_code.api_request_body",
                         "body": messages_text, "session.id": session,
                         "prompt.id": prompt_id, "user.email": "someone@example.com"},
          "body": ""}],
        RESOURCE,
    )


async def test_a_repeated_body_records_its_finding_once(collector):
    """One card number, re-sent by every retry and every later turn of the
    cumulative body, is one finding."""
    c = ASGIClient(collector)
    convo = f"user: pay with {SEEDED}"
    for turn in range(5):
        status, _ = await c.post("/v1/logs", _body_batch(f"turn-{turn}", convo), auth())
        assert status == 200
        convo += f"\nassistant: step {turn}"
    recs = [r for r in stored(collector) if r.session_id == "sess-9"]
    assert len(recs) == 5
    assert sum(r.findings_count for r in recs) == 1


async def test_a_new_secret_later_in_the_session_is_still_recorded(collector):
    c = ASGIClient(collector)
    await c.post("/v1/logs", _body_batch("t1", f"pay with {SEEDED}"), auth())
    await c.post("/v1/logs", _body_batch("t2", f"pay with {SEEDED}\nand ghp_{'a1B2' * 9} ok"),
                 auth())
    recs = [r for r in stored(collector) if r.session_id == "sess-9"]
    assert sum(r.findings_count for r in recs) == 2


async def test_another_session_records_the_same_secret_again(collector):
    c = ASGIClient(collector)
    await c.post("/v1/logs", _body_batch("t1", f"pay with {SEEDED}", session="a"), auth())
    await c.post("/v1/logs", _body_batch("t1", f"pay with {SEEDED}", session="b"), auth())
    recs = stored(collector)
    assert sum(r.findings_count for r in recs if r.session_id in ("a", "b")) == 2


def test_the_sink_still_sees_every_finding_so_repeats_are_still_masked():
    """De-duplication is for what is stored. A forwarded event must be
    masked even when its secret was recorded already."""
    from forgd_verdict.detectors.t0_regex import T0RegexDetector
    from forgd_verdict.otel.collect import SeenFindings, collect
    from forgd_verdict.otel.payload import OtelRecord

    seen, handed = SeenFindings(), []
    rec = OtelRecord(kind="log", name="claude_code.api_request_body",
                     attributes={"body": f"pay with {SEEDED}", "session.id": "s",
                                 "prompt.id": "p"})
    for _ in range(3):
        out, _ = collect([rec], [T0RegexDetector()], budget_ms=5000, org_id="o",
                         on_group=lambda m, f, s, sk: handed.append(len(f)), seen=seen)
    assert handed == [1, 1, 1]
    assert out[0].findings_count == 0


@pytest.mark.parametrize("on_tier_dropped, action", [("deny", "deny"), ("allow", "deny")])
async def test_the_collector_denies_an_unscanned_middle(on_tier_dropped, action, tmp_path):
    from forgd_verdict.otel.payload import MAX_VALUE_CHARS, TAIL_VALUE_CHARS

    policy = make_policy()
    policy.raw["server"]["on_tier_dropped"] = on_tier_dropped
    c = Collector(policy, store=LocalFileStore(tmp_path / "findings", instance="test"))
    try:
        pad = " " * (MAX_VALUE_CHARS + TAIL_VALUE_CHARS + 1000)
        status, _ = await ASGIClient(c).post("/v1/logs", code_batch(f"{pad}x{pad}"), auth())
        assert status == 200
        (rec,) = stored(c)
        assert "unscanned:oversize" in rec.tiers_dropped
        assert rec.action == action
    finally:
        c.close()


OTHER_TOKEN = "otel-token-for-the-second-org"


def _two_orgs(first_token, second_token):
    return [{"id": ORG, "label": "primary", "token": first_token},
            {"id": "$FORGD_ORG_ID_SECOND", "label": "second", "token": second_token}]


@pytest.mark.parametrize("via_env", [False, True])
def test_two_orgs_with_one_token_refuse_to_start(tmp_path, monkeypatch, via_env):
    """The map is token -> org, so a shared token would attribute one org's
    exports to the other. Named by index and label, never the token."""
    monkeypatch.setenv("FORGD_ORG_ID_SECOND", "9a1e0000-0000-0000-0000-000000000000")
    if via_env:
        monkeypatch.setenv("FORGD_OTEL_TOKEN_A", TOKEN)
        monkeypatch.setenv("FORGD_OTEL_TOKEN_B", TOKEN)
        orgs = _two_orgs("$FORGD_OTEL_TOKEN_A", "$FORGD_OTEL_TOKEN_B")
    else:
        orgs = _two_orgs(TOKEN, TOKEN)
    store = LocalFileStore(tmp_path / "findings", instance="test")
    with pytest.raises(ValueError, match="same token") as exc:
        Collector(make_policy(orgs=orgs), store=store)
    message = str(exc.value)
    assert "otel.orgs[0] ('primary')" in message and "otel.orgs[1] ('second')" in message
    assert TOKEN not in message
    assert "9a1e0000" not in message and ORG not in message


def test_two_orgs_with_their_own_tokens_start(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGD_ORG_ID_SECOND", "9a1e0000-0000-0000-0000-000000000000")
    store = LocalFileStore(tmp_path / "findings", instance="test")
    c = Collector(make_policy(orgs=_two_orgs(TOKEN, OTHER_TOKEN)), store=store)
    try:
        assert sorted(o["label"] for o in c.tokens.values()) == ["primary", "second"]
    finally:
        c.close()


async def test_an_export_past_the_decode_budget_is_refused_whole(collector):
    """Nothing from a body refused part-way through decoding is recorded,
    including a finding in a record decoded before the budget ran out."""
    from test_otel_payload import amplified_logs

    body = json.loads(amplified_logs("json", 40, 1))
    recs = body["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    recs.insert(0, {"body": {"stringValue": f"deploy with {SEEDED}"},
                    "attributes": [{"key": "event.name",
                                    "value": {"stringValue": "user.message"}}]})
    status, resp, headers = await ASGIClient(collector).request(
        "POST", "/v1/logs", json.dumps(body).encode(), auth())
    assert status == 503, resp
    assert resp["error"] == "decoded_too_large"
    assert headers.get("retry-after")
    assert stored(collector) == []
    assert SEEDED not in json.dumps(resp)


async def test_an_export_over_the_record_cap_is_refused_whole(collector):
    """A 200 with partialSuccess for the tail is final under OTLP, so the
    tail was never scanned. The whole batch is refused, retryably, and
    nothing in it is recorded -- including a finding in the part that
    would have fit."""
    from test_otel_payload import _log_batch

    from forgd_verdict.otel.payload import MAX_RECORDS

    body = json.loads(_log_batch(MAX_RECORDS, tail_text=f"deploy with {SEEDED}"))
    head = body["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    head[0]["body"]["stringValue"] = f"deploy with {SEEDED}"
    status, resp, headers = await ASGIClient(collector).request(
        "POST", "/v1/logs", json.dumps(body).encode(), auth())
    assert status == 503, resp
    assert resp["error"] == "too_many_records"
    assert headers.get("retry-after")
    assert "partialSuccess" not in resp
    assert stored(collector) == []
    assert SEEDED not in json.dumps(resp)


async def test_an_export_at_the_record_cap_is_accepted(collector):
    from test_otel_payload import _log_batch

    from forgd_verdict.otel.payload import MAX_RECORDS

    status, resp = await ASGIClient(collector).post(
        "/v1/logs", _log_batch(MAX_RECORDS), auth())
    assert status == 200
    assert resp == {"partialSuccess": {}}


def test_findings_of_a_batch_that_was_not_accepted_are_recorded_on_the_retry():
    from forgd_verdict.models import Finding
    from forgd_verdict.otel.collect import SeenFindings

    seen = SeenFindings()
    f = Finding(detector="regex:aws-access-key-id", severity="block", locator="l",
                excerpt_hash="h")
    added: list = []
    assert seen.new("o", "s", [f], added) == [f]
    seen.forget(added)
    assert seen.new("o", "s", [f]) == [f]
    assert seen.new("o", "s", [f]) == []


def _gated_sink(store, salt, max_queue):
    """A StoreSink whose writer does not start reading its queue until
    `gate` is set."""
    import threading

    from forgd_verdict.store.sink import StoreSink

    class _Gated(StoreSink):
        def __init__(self, *a, **kw):
            self.gate = threading.Event()
            super().__init__(*a, **kw)

        def _run(self):
            self.gate.wait()
            super()._run()

    return _Gated(store, salt=salt, max_queue=max_queue, flush_interval_s=0.1)


async def test_an_export_the_queue_cannot_hold_whole_is_refused_whole(tmp_path):
    """Verdicts were queued one at a time and the first refusal answered
    503, so those queued before it were written AND sent again on the
    retry: records and their findings counted twice."""
    import time

    from forgd_verdict.store.base import SOURCE_CODE_HOOK, VerdictRecord

    store = LocalFileStore(tmp_path / "findings", instance="test")
    c = Collector(make_policy(), store=store)
    c.sink.close()
    sink = c.sink = _gated_sink(store, c.salt, max_queue=10)
    turns = 8
    body = logs_json([{"attributes": {
        "event.name": "claude_code.user_prompt", "prompt": f"deploy with {SEEDED}",
        "session.id": f"sess-{i}", "prompt.id": f"turn-{i}"}, "body": ""}
        for i in range(turns)], RESOURCE)
    try:
        for i in range(5):
            assert sink.submit_record(VerdictRecord(source=SOURCE_CODE_HOOK,
                                                    request_id=f"filler-{i}"))
        client = ASGIClient(c)
        status, _ = await client.post("/v1/logs", body, auth())
        assert status == 503
        assert sink.stats()["queued"] == 5
        sink.gate.set()
        deadline = time.monotonic() + 5
        while sink.stats()["queued"] and time.monotonic() < deadline:
            time.sleep(0.02)
        status, _ = await client.post("/v1/logs", body, auth())
        assert status == 200
        rows = [r for r in stored(c) if r.source == SOURCE_OTEL_COLLECT]
    finally:
        sink.gate.set()
        c.close()
    assert len(rows) == turns
    assert sum(r.findings_count for r in rows) == turns


def test_the_store_queue_takes_a_full_size_export_while_other_traffic_is_queued(
        tmp_path, monkeypatch):
    """Verdicts are queued all or none, and an export may hold MAX_RECORDS
    turns: a queue smaller than that refused such an export on every retry."""
    import threading

    from forgd_verdict.otel.payload import MAX_RECORDS
    from forgd_verdict.store.base import SOURCE_CODE_HOOK, VerdictRecord
    from forgd_verdict.store.sink import StoreSink

    release = threading.Event()
    monkeypatch.setattr(StoreSink, "_run", lambda self: release.wait(5))
    c = Collector(make_policy(), store=LocalFileStore(tmp_path / "f", instance="t"))
    try:
        assert c.sink._queue.maxsize >= 2 * MAX_RECORDS
        record = VerdictRecord(source=SOURCE_CODE_HOOK)
        assert c.sink.submit_records([record] * 100)
        assert c.sink.submit_records([record] * MAX_RECORDS)
    finally:
        release.set()
        c.close()


@pytest.mark.parametrize("header", ["authorization", "x-forgd-token"])
async def test_a_non_ascii_export_token_is_a_401_not_a_500(collector, header):
    value = "tökén" if header == "x-forgd-token" else "Bearer tökén"
    status, _ = await ASGIClient(collector).post("/v1/logs", code_batch(), {header: value})
    assert status == 401


async def test_a_non_ascii_stats_token_is_a_401_not_a_500(tmp_path):
    c = Collector(stats_policy(), store=LocalFileStore(tmp_path / "s", instance="t"))
    try:
        status, _ = await ASGIClient(c).get("/stats", {"authorization": "Bearer stäts"})
        assert status == 401
    finally:
        c.close()


# --- decode: bounded, and off the event loop ------------------------------


async def test_json_nested_past_the_recursion_limit_is_400(collector):
    deep = b'{"resourceLogs":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    status, body = await ASGIClient(collector).post("/v1/logs", deep, auth())
    assert status == 400
    assert body == {"error": "undecodable"}
    assert collector._counts.get("undecodable") == 1


async def test_a_deeply_nested_protobuf_value_is_cut_at_max_depth(collector):
    from test_otel_payload import _attrs, _len_field, _str_field

    value = _str_field(1, "leaf")
    for _ in range(2_000):
        kv = _str_field(1, "k") + _len_field(2, value)
        value = _len_field(6, _len_field(1, kv))
    record = _len_field(2, _attrs(6, {"event.name": "claude_code.user_prompt",
                                      "session.id": "s"}) + _len_field(5, value))
    pb = _len_field(1, _len_field(1, _attrs(1, RESOURCE)) + _len_field(2, record))
    status, _ = await ASGIClient(collector).post(
        "/v1/logs", pb, auth({"content-type": "application/x-protobuf"}))
    assert status == 200


async def test_a_body_of_empty_fields_is_refused_not_walked(collector):
    pb = b"\x10\x00" * (collector.max_body // 2)
    status, body = await ASGIClient(collector).post(
        "/v1/logs", pb, auth({"content-type": "application/x-protobuf"}))
    assert status == 400
    assert body == {"error": "undecodable"}


async def test_decode_runs_off_the_event_loop(collector, monkeypatch):
    import threading

    from forgd_verdict.otel import app as app_mod

    ran_on = []

    def fake_decode(*a, **kw):
        ran_on.append(threading.current_thread())
        return []

    monkeypatch.setattr(app_mod, "decode", fake_decode)
    status, _ = await ASGIClient(collector).post("/v1/logs", code_batch(), auth())
    assert status == 200
    assert ran_on and ran_on[0] is not threading.current_thread()


async def test_metric_names_runs_off_the_event_loop(collector, monkeypatch):
    import threading

    from forgd_verdict.otel import app as app_mod

    ran_on = []

    def fake_names(*a, **kw):
        ran_on.append(threading.current_thread())
        return []

    monkeypatch.setattr(app_mod, "metric_names", fake_names)
    status, _ = await ASGIClient(collector).post("/v1/metrics", b"{}", auth())
    assert status == 200
    assert ran_on and ran_on[0] is not threading.current_thread()


# --- organization.id: the record's attribute AND its resource ------------

ORG_UUID = "00000000-0000-0000-0000-000000000001"
OTHER_UUID = "00000000-0000-0000-0000-000000000002"


@pytest.fixture
def uuid_collector(tmp_path):
    store = LocalFileStore(tmp_path / "findings", instance="test")
    c = Collector(make_policy(orgs=[{"id": ORG_UUID, "label": "primary", "token": TOKEN}]),
                  store=store)
    yield c
    c.close()


def _claiming(attribute_org, resource_org):
    return logs_json(
        [{"attributes": {"event.name": "claude_code.user_prompt", "prompt": "hello",
                         "session.id": "s", "organization.id": attribute_org},
          "body": ""}],
        {"service.name": "claude-code", "organization.id": resource_org},
    )


@pytest.mark.parametrize("attribute_org,resource_org", [
    (ORG_UUID, OTHER_UUID),
    (OTHER_UUID, ORG_UUID),
])
async def test_a_mismatch_in_either_claim_is_refused(uuid_collector, attribute_org,
                                                     resource_org):
    status, body = await ASGIClient(uuid_collector).post(
        "/v1/logs", _claiming(attribute_org, resource_org), auth())
    assert status == 403
    assert body == {"error": "organization_mismatch"}
    assert uuid_collector._counts.get("org_mismatch") == 1


async def test_both_claims_matching_is_accepted(uuid_collector):
    status, _ = await ASGIClient(uuid_collector).post(
        "/v1/logs", _claiming(ORG_UUID, ORG_UUID), auth())
    assert status == 200
    assert not uuid_collector._counts.get("org_mismatch")


# --- diagnostic tables are bounded -------------------------------------


@pytest.fixture
def capped(tmp_path, monkeypatch):
    from forgd_verdict.otel import app as app_mod

    monkeypatch.setattr(app_mod, "MAX_DIAGNOSTIC_KEYS", 3, raising=False)
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["otel"].update({"orgs": [{"id": ORG, "label": "primary", "token": TOKEN}],
                        "cors_origins": ["https://allowed.example"]})
    c = Collector(Policy(raw=raw), store=LocalFileStore(tmp_path / "f", instance="t"))
    yield c
    c.close()


async def test_refused_origins_are_bounded(capped):
    client = ASGIClient(capped)
    for origin in [f"https://o{i}.example" for i in range(5)] + ["https://o0.example"]:
        await client.request("OPTIONS", "/v1/traces", headers={"origin": origin})
    stats = capped.stats()
    assert len(stats["refused_origins"]) == 3
    assert stats["refused_origins"]["https://o0.example"] == 2
    assert stats["counts"]["refused_origins_overflow"] == 2


async def test_unrecognised_attributes_are_bounded(capped):
    attrs = {f"custom.field{i}": "x" * 64 for i in range(5)}
    for _ in range(2):
        status, _ = await ASGIClient(capped).post("/v1/logs", logs_json(
            [{"attributes": {"event.name": "claude_code.user_prompt",
                             "session.id": "s", **attrs}, "body": ""}], RESOURCE), auth())
        assert status == 200
    stats = capped.stats()
    assert len(stats["unrecognised_attributes"]) == 3
    assert all(n == 2 for n in stats["unrecognised_attributes"].values())
    assert stats["counts"]["unrecognised_attributes_overflow"] == 4


async def test_metric_names_are_bounded(capped):
    names = [{"name": f"m{i}"} for i in range(5)] + [{"name": "m0"}]
    body = json.dumps({"resourceMetrics": [{"scopeMetrics": [{"metrics": names}]}]}).encode()
    status, _ = await ASGIClient(capped).post("/v1/metrics", body, auth())
    assert status == 200
    stats = capped.stats()
    assert len(stats["metrics_names"]) == 3
    assert stats["metrics_names"]["m0"] == 2
    assert stats["counts"]["metrics_names_overflow"] == 2


# --- unrecognised attribute names are scrubbed once per batch -------------

NAME_KEY = "AKIAQYLPMN5HGZTHX4UQ"  # gitleaks:allow


def _name_probes(collector, monkeypatch, names):
    """{detector name: scan calls whose units include one of `names`}."""
    from forgd_verdict.core import _cheap

    calls: dict[str, int] = {}
    for det in _cheap(collector.detectors):
        real = det.scan

        def counting(units, _real=real, _name=det.name):
            units = list(units)
            if any(u.text in names for u in units):
                calls[_name] = calls.get(_name, 0) + 1
            return _real(units)

        monkeypatch.setattr(det, "scan", counting)
    return calls


async def test_a_batch_of_unrecognised_names_is_scrubbed_in_one_pass(collector, monkeypatch):
    names = {f"custom_attribute_{i:04d}" for i in range(1000)}
    ordered = sorted(names)
    calls = _name_probes(collector, monkeypatch, names)
    records = [{"attributes": {"event.name": "claude_code.user_prompt",
                               "session.id": "s", "prompt.id": "p",
                               **{n: "x" * 64 for n in ordered[i:i + 10]}},
                "body": ""} for i in range(0, 1000, 10)]
    status, _ = await ASGIClient(collector).post("/v1/logs", logs_json(records, RESOURCE),
                                                 auth())
    assert status == 200
    assert calls, "no detector was asked about the names"
    assert max(calls.values()) <= 2, calls


async def test_a_name_that_is_a_key_reaches_stats_redacted(collector):
    record = {"attributes": {"event.name": "claude_code.user_prompt",
                             "session.id": "s", "prompt.id": "p",
                             NAME_KEY: "x" * 64, "custom_attribute_ok": "y" * 64},
              "body": ""}
    status, _ = await ASGIClient(collector).post("/v1/logs", logs_json([record], RESOURCE),
                                                 auth())
    assert status == 200
    stats = collector.stats()
    seen = stats["unrecognised_attributes"]
    assert "<redacted>" in seen and "custom_attribute_ok" in seen
    assert NAME_KEY not in json.dumps(stats)


def test_the_batch_label_scrub_matches_the_single_one():
    from forgd_verdict.core import scrub_label, scrub_labels

    detectors = load_policy("policy.yaml").build_detectors()
    texts = [NAME_KEY, f"send_{NAME_KEY}", "custom_attribute_ok", "", "short",
             "sk-ant-api03-" + "Z" * 40]
    assert scrub_labels(texts, detectors) == [scrub_label(t, detectors) for t in texts]


async def test_stats_counts_store_writes_and_drops(tmp_path):
    """The store write runs after the 200, so /stats is where a batch dropped
    after its retries is visible."""
    store = LocalFileStore(tmp_path / "s", instance="t")
    c = Collector(stats_policy(), store=store)
    client = ASGIClient(c)
    auth_hdr = {"authorization": "Bearer " + "stats-token-0123456789abcdef"}

    status, body = await client.get("/stats", auth_hdr)
    assert status == 200
    assert body["store"] == {"written": 0, "dropped": 0, "errors": 0, "held": 0}

    c.sink.dropped += 3
    c.sink.errors += 1
    status, body = await client.get("/stats", auth_hdr)
    assert body["store"] == {"written": 0, "dropped": 3, "errors": 1, "held": 0}
    c.close()


class _FailingStore(LocalFileStore):
    """A local store whose writes fail while `down` is set."""

    down = False

    def write_verdicts(self, records):
        if self.down:
            raise OSError("store unreachable")
        return super().write_verdicts(records)


def _turn_batch(n: int):
    return logs_json([{"attributes": {
        "event.name": "claude_code.user_prompt", "prompt": f"deploy with {SEEDED}",
        "session.id": f"sess-{n}", "prompt.id": f"turn-{n}"}, "body": ""}], RESOURCE)


async def test_a_batch_answered_200_is_written_once_the_store_recovers(tmp_path):
    """The collector answered 200 on queueing, and the writer dropped the
    batch after two failed retries. An exporter does not resend a batch it
    got a 200 for, so its findings were lost with only a counter to show."""
    store = _FailingStore(tmp_path / "findings", instance="test")
    store.down = True
    c = Collector(make_policy(), store=store)
    c.sink.hold_retry_s = c.sink.hold_retry_max_s = 0.02
    client = ASGIClient(c)
    try:
        status, _ = await client.post("/v1/logs", _turn_batch(1), auth())
        assert status == 200
        assert not c.sink.flush(timeout_s=0.2)
        # Past the point where the bounded retry dropped it.
        assert _wait_for(lambda: c.sink.errors > c.sink.max_retries + 1)
        assert c.sink.degraded and c.sink.dropped == 0

        # While the writer holds the failed batch, an export is refused
        # and the exporter keeps it.
        status, body = await client.post("/v1/logs", _turn_batch(2), auth())
        assert status == 503
        assert body == {"error": "store_unavailable"}
        assert c._counts["store_unavailable"] == 1

        store.down = False
        assert _wait_for(lambda: not c.sink.degraded)
        status, _ = await client.post("/v1/logs", _turn_batch(2), auth())
        assert status == 200
        rows = stored(c)
    finally:
        c.close()
    assert c.sink.dropped == 0
    assert sorted(r.session_id for r in rows) == ["sess-1", "sess-2"]
    assert all(r.findings_count == 1 for r in rows)


def _wait_for(cond, timeout=5.0):
    import time

    deadline = time.monotonic() + timeout
    while not cond() and time.monotonic() < deadline:
        time.sleep(0.01)
    return cond()


def test_a_short_metrics_token_refuses_to_start_the_collector():
    weak = stats_policy()
    weak.raw["server"]["metrics_token"] = "s3kr1t"
    with pytest.raises(ValueError, match="server.metrics_token"):
        Collector(weak, store=None)
