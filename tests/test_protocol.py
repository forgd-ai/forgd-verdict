"""Protocol conformance: golden frames in, correct verdict shape out.

No network, no server -- the ASGI app is driven directly.
"""

from __future__ import annotations

import json

import pytest
from conftest import (
    FAKE_AWS_KEY,
    FAKE_SSN,
    UNPARSEABLE_DEPTH,
    WHSEC,
    ASGIClient,
    frame,
    make_policy,
    max_json_depth,
    nested_json,
    sign,
    text_msg,
)

from forgd_verdict.models import REFERENCE_ID_CHARSET
from forgd_verdict.server.app import VerdictServer


@pytest.fixture
def client(policy):
    server = VerdictServer(policy)
    yield ASGIClient(server)
    server.close()


async def post_frame(client, body: dict, **sign_kwargs):
    raw = json.dumps(body).encode()
    return await client.post("/hook", raw, sign(raw, **sign_kwargs))


# -- golden frames ---------------------------------------------------------


async def test_simple_text_frame_allows(client):
    status, verdict = await post_frame(client, frame())
    assert status == 200
    assert verdict["action"] == "allow"
    assert "deny_reason" not in verdict


async def test_secret_in_text_denies_with_valid_shape(client):
    status, verdict = await post_frame(
        client, frame([text_msg(f"deploy with {FAKE_AWS_KEY}")])
    )
    assert status == 200
    assert verdict["action"] == "deny"
    assert 0 < len(verdict["deny_reason"]) <= 500
    ref = verdict["reference_id"]
    assert 0 < len(ref) <= 50
    assert set(ref) <= REFERENCE_ID_CHARSET
    assert ref.startswith("fv_")
    assert verdict["findings_count"] >= 1


@pytest.mark.parametrize("card", [4539148803436467, 4539148803436467.0], ids=["int", "float"])
async def test_a_card_number_held_as_a_json_number_denies(client, card):
    use = {"type": "tool_use", "id": "t1", "name": "run", "input": {"card": card}}
    status, verdict = await post_frame(client, frame([{"role": "assistant", "content": [use]}]))
    assert status == 200
    assert verdict["action"] == "deny"
    assert "4539148803436467" not in json.dumps(verdict)


@pytest.mark.parametrize("key", [FAKE_SSN, "4532015112830"], ids=["ssn", "pan-13"])
async def test_a_short_identifier_held_as_a_tool_input_key_denies(client, key, caplog):
    use = {"type": "tool_use", "id": "t1", "name": "run", "input": {key: "x"}}
    status, verdict = await post_frame(client, frame([{"role": "assistant", "content": [use]}]))
    assert status == 200
    assert verdict["action"] == "deny"
    assert key not in json.dumps(verdict)
    assert key not in caplog.text


async def test_tool_use_and_tool_result_blocks_are_scanned(client):
    messages = [
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "tool_name": "Bash",
                    "input": {"command": f"export AWS_KEY={FAKE_AWS_KEY}"},
                }
            ],
        },
    ]
    status, verdict = await post_frame(client, frame(messages))
    assert status == 200 and verdict["action"] == "deny"

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "tool_name": "Read",
                    "is_error": False,
                    "content": f"line one\n{FAKE_AWS_KEY}\nline three",
                }
            ],
        }
    ]
    status, verdict = await post_frame(
        client, frame(messages, session_id="s2"), webhook_id="req_tr"
    )
    assert status == 200 and verdict["action"] == "deny"


async def test_attachment_text_is_scanned(client):
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Summarize the attached report."},
                {
                    "type": "attachment",
                    "file_name": "q2-report.pdf",
                    "media_type": "application/pdf",
                    "size_bytes": 48213,
                    "text": f"Q2 revenue grew. Key: {FAKE_AWS_KEY}",
                },
            ],
        }
    ]
    status, verdict = await post_frame(client, frame(messages))
    assert status == 200 and verdict["action"] == "deny"


async def test_null_fields_tolerated(client):
    """Most fields can be null; an image arrives as an attachment with nulls."""
    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "attachment",
                    "file_name": None,
                    "media_type": "image/png",
                    "size_bytes": None,
                    "text": None,
                },
                {"type": "text", "text": "what is this"},
            ],
        }
    ]
    body = frame(messages, tenant_id=None, session_id=None, model=None)
    body["actor"] = {"type": "user", "id": None, "email_address": None}
    status, verdict = await post_frame(client, body)
    assert status == 200 and verdict["action"] == "allow"


async def test_unknown_block_type_is_not_rejected_and_is_still_scanned(client):
    """Forward compatible: never reject, and still read what is there."""
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "some_future_block", "payload": {"note": f"key {FAKE_AWS_KEY}"}}
            ],
        }
    ]
    status, verdict = await post_frame(client, frame(messages))
    assert status == 200
    assert verdict["action"] == "deny"  # scanned, not skipped


async def test_an_unknown_top_level_type_is_scanned_and_denied(client):
    """A signed frame of a type other than `prompt` is scanned and decided
    like a prompt, so a credential in it denies in `enforce`."""
    status, verdict = await post_frame(
        client, frame(type="some_future_event", messages=[text_msg(FAKE_AWS_KEY)])
    )
    assert status == 200
    assert verdict["action"] == "deny"
    assert verdict["findings_count"] >= 1


async def test_an_unknown_type_is_scanned_outside_messages_too(client):
    body = frame(type="some_future_event", messages=None)
    del body["messages"]
    body["input"] = {"tool_call": {"arguments": f"export K={FAKE_AWS_KEY}"}}
    status, verdict = await post_frame(client, body)
    assert status == 200 and verdict["action"] == "deny"


async def test_a_benign_unknown_type_is_allowed(client):
    status, verdict = await post_frame(
        client, frame(type="some_future_event", messages=[text_msg("hello there")])
    )
    assert status == 200
    assert verdict["action"] == "allow"


async def test_the_unknown_type_envelope_is_not_scanned(client):
    """The actor's email and the ids are identifiers, as on a prompt."""
    status, verdict = await post_frame(client, frame(type="some_future_event"))
    assert status == 200 and verdict == {"action": "allow", "findings_count": 0}


async def test_an_unknown_type_is_recorded_like_a_prompt(policy):
    server = VerdictServer(policy)
    rows = []
    server.sink.submit = lambda row, findings: rows.append((row, findings))
    try:
        body = frame(type="some_future_event", messages=[text_msg(FAKE_AWS_KEY)])
        raw = json.dumps(body).encode()
        client = ASGIClient(server)
        _, first = await client.post("/hook", raw, sign(raw, webhook_id="req_u1"))
        _, again = await client.post("/hook", raw, sign(raw, webhook_id="req_u1"))
        counters = server.metrics.snapshot()["counters"]
    finally:
        server.close()
    assert first == again and first["action"] == "deny"
    assert counters["unknown_frame_type"] == 1
    assert counters["dedupe_hits"] == 1
    assert rows[0][0]["action"] == "deny"
    assert rows[0][0]["findings_count"] >= 1
    assert rows[0][1]


async def test_an_unknown_type_value_is_not_logged_raw(client, caplog):
    import logging

    caplog.set_level(logging.INFO)
    await post_frame(client, frame(type=f"event-{FAKE_AWS_KEY}"))
    assert FAKE_AWS_KEY not in caplog.text
    assert FAKE_AWS_KEY not in repr([getattr(r, "fields", None) for r in caplog.records])


async def test_missing_type_is_scanned(client):
    body = frame([text_msg(FAKE_AWS_KEY)])
    del body["type"]
    status, verdict = await post_frame(client, body)
    assert status == 200 and verdict["action"] == "deny"


async def test_config_test_source_answered_normally(client):
    """Connection test and circuit-breaker recovery probe."""
    body = frame(messages=[text_msg("synthetic test prompt")])
    body["source"] = {"application": "config-test"}
    status, verdict = await post_frame(client, body, webhook_id="req_cfg")
    assert status == 200 and verdict["action"] == "allow"


async def test_unknown_source_application_not_rejected(client):
    body = frame()
    body["source"] = {"application": "claude-in-some-new-surface"}
    status, verdict = await post_frame(client, body)
    assert status == 200 and verdict["action"] == "allow"


async def test_unknown_actor_type_and_extra_top_level_fields_ignored(client):
    body = frame()
    body["actor"] = {"type": "service_account", "id": "svc_1"}
    body["some_future_field"] = {"anything": True}
    body["metadata"] = {"future_key": "future_value"}
    status, verdict = await post_frame(client, body)
    assert status == 200 and verdict["action"] == "allow"


async def test_content_as_plain_string_tolerated(client):
    status, verdict = await post_frame(
        client, frame([{"role": "user", "content": f"inline {FAKE_AWS_KEY}"}])
    )
    assert status == 200 and verdict["action"] == "deny"


# -- transport semantics ---------------------------------------------------


async def test_dedupe_replays_recorded_verdict(client):
    body = frame([text_msg(f"key {FAKE_AWS_KEY}")])
    raw = json.dumps(body).encode()
    headers = sign(raw, webhook_id="req_dupe")
    s1, v1 = await client.post("/hook", raw, headers)
    s2, v2 = await client.post("/hook", raw, headers)
    assert s1 == s2 == 200
    # Same verdict object, including the reference_id -- a rescan would mint
    # a new ULID and break the Activity Feed join.
    assert v1 == v2
    assert client.app.verdicts.hits == 1


async def test_any_path_is_the_endpoint(client):
    for path in ("/", "/hook", "/deeply/nested/path"):
        status, verdict = await post_frame(client, frame(), webhook_id=f"req{path}")
        assert status == 200 and verdict["action"] == "allow"


async def test_invalid_signature_is_401_not_a_deny(client):
    raw = json.dumps(frame()).encode()
    headers = sign(raw)
    headers["webhook-signature"] = "v1,AAAA"
    status, body = await client.post("/hook", raw, headers)
    assert status == 401


async def test_unsigned_request_rejected_when_secret_configured(client):
    raw = json.dumps(frame()).encode()
    status, _ = await client.post("/hook", raw, {"content-type": "application/json"})
    assert status == 401


async def test_unparseable_body_is_400(client):
    raw = b"{not json"
    status, _ = await client.post("/hook", raw, sign(raw))
    assert status == 400


async def test_a_body_nested_too_deeply_is_400(client, caplog):
    inner = json.dumps(frame([text_msg(f"deploy with {FAKE_AWS_KEY}")]))
    raw = nested_json(inner, UNPARSEABLE_DEPTH).encode()
    status, body = await client.post("/hook", raw, sign(raw))
    assert status == 400
    assert body == {"error": "invalid_json"}
    assert FAKE_AWS_KEY not in caplog.text


@pytest.mark.parametrize("margin", [None, 20])
async def test_a_secret_at_the_bottom_of_a_parseable_nesting_denies(client, margin):
    depth = 900 if margin is None else max_json_depth() - margin
    inner = json.dumps(f"deploy with {FAKE_AWS_KEY}")
    use = ('{"type": "tool_use", "id": "t1", "name": "run", "input": {"q": '
           + nested_json(inner, depth) + "}}")
    envelope = json.dumps(frame([{"role": "assistant", "content": ["SLOT"]}]))
    raw = envelope.replace('"SLOT"', use).encode()
    status, verdict = await client.post("/hook", raw, sign(raw))
    assert status == 200
    assert verdict["action"] == "deny"
    assert FAKE_AWS_KEY not in json.dumps(verdict)


async def test_oversized_body_is_413():
    policy = make_policy(
        server={"mode": "enforce", "secrets": [WHSEC], "max_body_bytes": 128, "csv_path": None}
    )
    server = VerdictServer(policy)
    try:
        raw = json.dumps(frame([text_msg("x" * 500)])).encode()
        status, _ = await ASGIClient(server).post("/hook", raw, sign(raw))
        assert status == 413
    finally:
        server.close()


async def test_missing_signing_secret_is_503_not_a_silent_allow():
    policy = make_policy(
        server={"mode": "enforce", "secrets": [], "require_signature": True, "csv_path": None}
    )
    server = VerdictServer(policy)
    try:
        raw = json.dumps(frame()).encode()
        status, body = await ASGIClient(server).post("/hook", raw, sign(raw))
        assert status == 503 and body["error"] == "no_signing_secret_configured"
    finally:
        server.close()


async def test_required_header_second_factor():
    policy = make_policy(
        server={
            "mode": "enforce",
            "secrets": [WHSEC],
            "required_headers": {"X-Forgd-Shared": "hunter2"},
            "csv_path": None,
        }
    )
    server = VerdictServer(policy)
    try:
        client = ASGIClient(server)
        raw = json.dumps(frame()).encode()
        status, _ = await client.post("/hook", raw, sign(raw))
        assert status == 401
        headers = sign(raw, webhook_id="req_hdr")
        headers["x-forgd-shared"] = "hunter2"
        status, verdict = await client.post("/hook", raw, headers)
        assert status == 200 and verdict["action"] == "allow"
    finally:
        server.close()


# -- modes -----------------------------------------------------------------


async def test_observe_mode_never_denies():
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC], "csv_path": None},
    )
    server = VerdictServer(policy)
    try:
        status, verdict = await post_frame(
            ASGIClient(server), frame([text_msg(f"key {FAKE_AWS_KEY}")])
        )
        assert status == 200
        assert verdict["action"] == "allow"
        # ...but it still scanned and counted.
        assert verdict["findings_count"] >= 1
    finally:
        server.close()


async def test_archive_mode_allows_and_persists_after_responding(tmp_path):
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={
            "mode": "archive",
            "secrets": [WHSEC],
            "csv_path": None,
            "archive_dir": str(tmp_path / "arc"),
        },
    )
    server = VerdictServer(policy)
    try:
        status, verdict = await post_frame(
            ASGIClient(server), frame([text_msg(f"key {FAKE_AWS_KEY}")])
        )
        assert status == 200 and verdict["action"] == "allow"
    finally:
        server.close()  # joins the writer thread
    files = list((tmp_path / "arc").glob("frames-*.jsonl.gz"))
    assert files, "archive mode should have persisted the frame"
    import gzip

    content = gzip.decompress(files[0].read_bytes()).decode()
    assert FAKE_AWS_KEY in content  # archive holds transcripts, by design


# -- our own endpoints -----------------------------------------------------


async def test_metrics_disabled_without_a_token(client):
    """Fail closed. On a platform with all-or-nothing ingress an open
    /metrics is internet-readable, and while it holds no matched content it
    does expose traffic volume, active Claude surfaces, and the deny rate."""
    await post_frame(client, frame(), webhook_id="req_m0")
    status, body = await client.get("/metrics")
    assert (status, body) == (404, {"error": "not_found"})


async def test_metrics_requires_the_bearer_token():
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={
            "mode": "enforce",
            "secrets": [WHSEC],
            "csv_path": None,
            "metrics_token": "metrics-token-for-the-tests-only",
        },
    )
    server = VerdictServer(policy)
    try:
        client = ASGIClient(server)
        await post_frame(client, frame(), webhook_id="req_m1")

        status, body = await client.get("/metrics")
        assert (status, body) == (401, {"error": "unauthorized"}), "no header must not serve metrics"

        status, body = await client.get("/metrics", {"authorization": "Bearer wrong"})
        assert (status, body) == (401, {"error": "unauthorized"})

        status, body = await client.get("/metrics", {"authorization": "metrics-token-for-the-tests-only"})
        assert (status, body) == (401, {"error": "unauthorized"}), "the Bearer prefix is required"

        status, body = await client.get("/metrics", {"authorization": "Bearer " + "metrics-token-for-the-tests-only"})
        assert status == 200
        assert body["by_source_application"]["claude-ai"]["requests"] == 1
        assert "total_ms" in body["by_source_application"]["claude-ai"]
    finally:
        server.close()


async def test_healthz(client):
    status, body = await client.get("/healthz")
    assert status == 200 and body["status"] == "ok"


async def test_shadow_deny_keeps_a_reference_id_for_logging_only():
    """A shadow deny must be identifiable in the same namespace as an
    enforced one, or a shadow run cannot be reconciled against Activity
    Feed denials after the switch to enforcing. The id must not reach
    Anthropic, though -- the wire verdict is an allow."""
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC], "csv_path": None},
    )
    server = VerdictServer(policy)
    try:
        status, wire = await post_frame(
            ASGIClient(server), frame([text_msg(f"key {FAKE_AWS_KEY}")])
        )
        assert status == 200
        # On the wire: a plain allow, no reference_id.
        assert wire["action"] == "allow"
        assert "reference_id" not in wire
        assert wire["findings_count"] >= 1
    finally:
        server.close()


def test_to_wire_never_emits_reference_id_on_allow():
    from forgd_verdict.models import Verdict

    v = Verdict(action="allow", reference_id="fv_x_01", findings_count=3)
    assert "reference_id" not in v.to_wire()
    assert v.to_wire()["action"] == "allow"


# -- a non-string session_id ---------------------------------------------


@pytest.mark.parametrize("bad", [[], {}, 7, None, {"a": 1}])
def test_an_unhashable_session_id_does_not_stop_the_scan(bad):
    """`_scan` validated that `messages` is a list and validated nothing
    about the cache key, both halves of which come straight out of the
    request body.

    `InMemoryLRUCache.get((None, []))` raised `unhashable type: 'list'`
    before anything was scanned -- in observe an allow with no scan, and
    in enforce with `on_internal_error: fail` a 500 per request, which
    trips Anthropic's circuit breaker and bypasses the hook entirely.
    """
    assert VerdictServer._key_part(bad) == ""


def test_a_string_session_id_is_used_as_is():
    assert VerdictServer._key_part("sess-123") == "sess-123"


async def test_a_non_ascii_metrics_token_is_a_401_not_a_500():
    """`hmac.compare_digest` raises TypeError on a str with non-ASCII
    characters, and headers are decoded as latin-1."""
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": None,
                "metrics_token": "metrics-token-for-the-tests-only"},
    )
    server = VerdictServer(policy)
    try:
        status, _ = await ASGIClient(server).get(
            "/metrics", {"authorization": "Bearer " + "metrics-token-for-the-tests-onlyé"})
        assert status == 401
    finally:
        server.close()


def test_each_archive_writer_has_its_own_file(tmp_path):
    """`--workers 2` builds one FrameArchive per process. A frame is a gzip
    member written in several write() calls, so two processes appending to
    one file can interleave them and corrupt the stream."""
    import gzip
    import json as _json

    from forgd_verdict.server.archive import FrameArchive

    workers = [FrameArchive(str(tmp_path)) for _ in range(2)]
    for n, archive in enumerate(workers):
        for i in range(3):
            archive.submit({"worker": n, "i": i})
    for archive in workers:
        archive.close()

    files = sorted(tmp_path.glob("frames-*.jsonl.gz"))
    assert len(files) == 2
    seen = set()
    for path in files:
        rows = [_json.loads(line) for line in gzip.decompress(path.read_bytes()).splitlines()]
        assert len({r["worker"] for r in rows}) == 1
        assert [r["i"] for r in rows] == [0, 1, 2]
        seen.add(rows[0]["worker"])
    assert seen == {0, 1}


def test_a_short_metrics_token_refuses_to_start_the_server():
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": None,
                "metrics_token": "s3kr1t"},
    )
    with pytest.raises(ValueError, match="server.metrics_token is 6 characters"):
        VerdictServer(policy)


# -- tool call frames --------------------------------------------------------


def _tool_call_frame(command: str, tool_info: dict | None = None) -> dict:
    """A tool call frame as docs/PROTOCOL.md describes it: the assistant
    message alone, with one tool_use block per call."""
    return frame(type="tool_call", messages=[{
        "role": "assistant",
        "content": [
            {"type": "text", "text": "Listing the reports."},
            {"type": "tool_use", "id": "toolu_01HiJkLmNoPqRsTuVwXyZaBc", "tool_name": "bash",
             "input": {"command": command},
             "tool_info": tool_info or {"type": "client", "tool_type": "bash_20250124"}},
        ],
    }])


async def test_a_tool_call_frame_with_a_credential_denies(policy, caplog):
    """Counted as a tool call frame, not an unrecognized type, and scanned
    whole rather than through the transcript path. Mutation: count it as
    unknown, or scan it with _scan."""
    import logging

    caplog.set_level(logging.INFO)
    server = VerdictServer(policy)

    def transcript_scan(*_a, **_k):
        raise AssertionError("a tool call frame went through the transcript scan")

    server._scan = transcript_scan
    try:
        raw = json.dumps(_tool_call_frame(f"export AWS_ACCESS_KEY_ID={FAKE_AWS_KEY}")).encode()
        status, verdict = await ASGIClient(server).post("/hook", raw, sign(raw))
        counters = server.metrics.snapshot()["counters"]
    finally:
        server.close()
    assert status == 200 and verdict["action"] == "deny"
    assert counters["tool_call_frames"] == 1
    assert "unknown_frame_type" not in counters
    assert "unrecognized frame type" not in caplog.text


async def test_a_benign_tool_call_frame_allows(client):
    """`tool_info` names who runs the tool; a server's origin is not a
    finding."""
    status, verdict = await post_frame(client, _tool_call_frame(
        "ls -la reports/", {"type": "third_party", "toolset_name": "reports",
                            "origin": "https://mcp.example.com", "verified_origin": True}))
    assert status == 200 and verdict == {"action": "allow", "findings_count": 0}
