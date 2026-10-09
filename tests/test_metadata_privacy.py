"""Identity and metadata values never carry a matched secret to a sink.

Each cheap-detector fixture is placed in each metadata position on each
path, and every place the value could land is searched for it: log
records, stored rows, the CSV, the spool, `/stats`, `/metrics` and the
response body.
"""

from __future__ import annotations

import json
import logging

import pytest
from conftest import (
    FAKE_AWS_KEY,
    FAKE_GITHUB_TOKEN,
    FAKE_PAN,
    FAKE_SSN,
    WHSEC,
    ASGIClient,
    frame,
    make_policy,
    sign,
)

from forgd_verdict.metadata import METADATA_MAX_CHARS, MetadataGuard
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge, load_policy
from forgd_verdict.store.base import SOURCE_CODE_HOOK, FindingRow, VerdictRecord
from forgd_verdict.store.local import LocalFileStore

FIXTURES = {"aws": FAKE_AWS_KEY, "github": FAKE_GITHUB_TOKEN, "ssn": FAKE_SSN,
            "pan": FAKE_PAN}


def _leaks(*texts: str) -> list[str]:
    joined = "\n".join(texts)
    return [name for name, value in FIXTURES.items() if value in joined]


def _logged(caplog, capsys) -> str:
    out = capsys.readouterr()
    records = [f"{r.getMessage()} {getattr(r, 'fields', '')}" for r in caplog.records]
    return "\n".join([out.out, out.err, *records])


def _stored(store) -> str:
    return "\n".join(r.to_json() for r in store.read_verdicts())


def _files(root) -> str:
    return "\n".join(p.read_text(errors="replace") for p in root.rglob("*") if p.is_file())


@pytest.fixture
def cheap():
    return [d for d in load_policy("policy.yaml").build_detectors()
            if d.tier < 2 and d.name != "gitleaks"]


# -- the guard itself ----------------------------------------------------


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_a_matching_value_becomes_a_placeholder(name, cheap):
    guard = MetadataGuard(cheap, salt="s")
    value = f"sess-{FIXTURES[name]}"
    out = guard.one(value)
    assert out.startswith("redacted_") and FIXTURES[name] not in out
    assert guard.redacted == 1


@pytest.mark.parametrize("value", [
    "22222222-2222-2222-2222-222222222222", "req_01HZY8K3V5Q2W7E9R4T6Y8U0IO",
    "toolu_01EXAMPLEa1b2c3d4e5f6g7", "claude-opus-5", "claude-code", "sheet_agent",
    "msg_01EXAMPLEz8XyWvUt7sRq", "clls_01ABCdefGHIjklMNOpqr",
])
def test_an_ordinary_identifier_is_kept(value, cheap):
    guard = MetadataGuard(cheap, salt="s")
    assert guard.one(value) == value
    assert guard.redacted == 0


def test_a_value_over_the_bound_becomes_a_placeholder(cheap):
    guard = MetadataGuard(cheap, salt="s")
    out = guard.one("x" * (METADATA_MAX_CHARS + 1))
    assert out.startswith("long_")


def test_a_failing_detector_fails_closed():
    from forgd_verdict.detectors.base import TIER_T0, DetectorFailed

    class Broken:
        name = "broken"
        tier = TIER_T0

        def scan(self, units):
            raise DetectorFailed("down")

    assert MetadataGuard([Broken()]).one("an-ordinary-id").startswith("redacted_")


def _broken_guard():
    from forgd_verdict.detectors.base import TIER_T0, DetectorFailed

    class Broken:
        name = "broken"
        tier = TIER_T0

        def scan(self, units):
            raise DetectorFailed("down")

    return MetadataGuard([Broken()])


def test_sink_metadata_a_failing_detector_could_not_check_is_refused():
    from forgd_verdict.sink import SinkUnavailable
    from forgd_verdict.sink.factory import _metadata

    with pytest.raises(SinkUnavailable) as exc:
        _metadata("siem", {"team": "an-ordinary-value"}, _broken_guard())
    assert "could not be checked" in str(exc.value)
    assert "an-ordinary-value" not in str(exc.value) and "team" not in str(exc.value)


def test_a_label_a_failing_detector_could_not_check_is_refused():
    from forgd_verdict.metadata import refuse_unsafe_labels

    with pytest.raises(ValueError) as exc:
        refuse_unsafe_labels(["prod-eu"], _broken_guard(), "compliance.orgs")
    assert "could not be checked" in str(exc.value)
    assert "prod-eu" not in str(exc.value)


def test_a_placeholder_is_a_valid_request_id_part(cheap):
    from forgd_verdict.overrides import _REQUEST_ID

    out = MetadataGuard(cheap, salt="s").one(FAKE_AWS_KEY)
    assert _REQUEST_ID.fullmatch(out)
    assert _REQUEST_ID.fullmatch(f"PreToolUse:{out}:{out}")


def test_a_non_string_value_is_turned_into_text_first(cheap):
    out = MetadataGuard(cheap).one({"nested": FAKE_AWS_KEY})
    assert FAKE_AWS_KEY not in out


# -- adapter 1 -----------------------------------------------------------

@pytest.mark.parametrize("value", [int(FAKE_PAN), float(FAKE_PAN)], ids=["int", "float"])
def test_a_matching_number_becomes_a_placeholder(value, cheap, caplog):
    """`_clean` probed strings only, so a card number sent as a JSON number
    under `model` was stored as it came."""
    guard = MetadataGuard(cheap, salt="s")
    with caplog.at_level(logging.DEBUG):
        out = guard.clean({"model": value, "count": 3})
    assert isinstance(out["model"], str) and out["model"].startswith("redacted_")
    assert out["count"] == 3
    assert guard.redacted == 1
    assert _leaks(json.dumps(out), caplog.text) == []


@pytest.mark.parametrize("value", [3, 0, -12, 2.5, True, False, 1727000000000])
def test_an_ordinary_number_or_bool_is_kept_with_its_type(value, cheap):
    guard = MetadataGuard(cheap, salt="s")
    out = guard.one(value)
    assert out == value and type(out) is type(value)
    assert guard.redacted == 0


def test_a_number_over_the_bound_becomes_a_placeholder(cheap):
    out = MetadataGuard(cheap, salt="s").one(int("7" * (METADATA_MAX_CHARS + 1)))
    assert isinstance(out, str) and out.startswith("long_")


def test_a_guard_that_fails_replaces_numbers_and_keeps_bools(cheap, monkeypatch):
    guard = MetadataGuard(cheap, salt="s")

    def boom(*a, **kw):
        raise RuntimeError("guard down")

    monkeypatch.setattr(guard, "_clean", boom)
    out = guard.clean({"model": int(FAKE_PAN), "flag": True, "none": None})
    assert out["model"].startswith("failed_")
    assert out["flag"] is True and out["none"] is None


SERVER_POSITIONS = ("request_id", "tenant_id", "source.application", "model", "webhook-id")


def _server_frame(position: str, value: str) -> tuple[bytes, dict]:
    body = frame()
    webhook_id = f"msg_{position.replace('.', '_')}"
    if position == "source.application":
        body["source"] = {"application": value}
    elif position == "webhook-id":
        webhook_id = value
    else:
        body[position] = value
    raw = json.dumps(body).encode()
    return raw, sign(raw, webhook_id=webhook_id)


@pytest.mark.parametrize("name", sorted(FIXTURES))
async def test_the_verdict_server_keeps_metadata_out_of_every_sink(name, tmp_path,
                                                                   caplog, capsys):
    from forgd_verdict.server.app import VerdictServer

    store = LocalFileStore(tmp_path / "store", instance="t")
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": str(tmp_path / "t.csv")},
    )
    server = VerdictServer(policy, store=store)
    client = ASGIClient(server)
    bodies = []
    caplog.set_level(logging.DEBUG)
    try:
        for position in SERVER_POSITIONS:
            raw, headers = _server_frame(position, FIXTURES[name])
            status, body = await client.post("/hook", raw, headers)
            assert status == 200, (position, body)
            bodies.append(json.dumps(body))
        # An unsigned request: the id is logged before anything is verified.
        raw, headers = _server_frame("webhook-id", FIXTURES[name])
        headers["webhook-signature"] = "v1,AAAA"
        status, body = await client.post("/hook", raw, headers)
        assert status == 401
        bodies.append(json.dumps(body))
        metrics = json.dumps(server._metrics_body())
    finally:
        server.close()
    assert _leaks(*bodies, metrics, _stored(store), _files(tmp_path),
                  _logged(caplog, capsys)) == []
    # The four frame fields reach the row. `webhook-id` reaches only log
    # lines, which digest it without a detector.
    assert json.loads(metrics)["counters"]["metadata_redacted"] >= 4


async def test_the_verdict_server_keeps_a_numeric_model_out_of_every_sink(tmp_path, caplog,
                                                                         capsys):
    from forgd_verdict.server.app import VerdictServer

    store = LocalFileStore(tmp_path / "store", instance="t")
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": str(tmp_path / "t.csv")},
    )
    server = VerdictServer(policy, store=store)
    caplog.set_level(logging.DEBUG)
    try:
        body = frame()
        body["model"] = int(FAKE_PAN)
        raw = json.dumps(body).encode()
        status, resp = await ASGIClient(server).post("/hook", raw, sign(raw, webhook_id="msg_n"))
        assert status == 200, resp
        metrics = json.dumps(server._metrics_body())
    finally:
        server.close()
    assert _leaks(json.dumps(resp), metrics, _stored(store), _files(tmp_path),
                  _logged(caplog, capsys)) == []


async def test_a_request_that_fails_the_signature_runs_no_detector(tmp_path, caplog):
    """Before authentication nothing is scanned: the id is logged as a
    salted digest."""
    from forgd_verdict.server.app import VerdictServer

    class Counting:
        name, tier, severity = "counting", 0, "block"
        calls = 0

        def scan(self, units):
            Counting.calls += 1
            return []

    policy = make_policy(server={"mode": "enforce", "secrets": [WHSEC],
                                 "csv_path": str(tmp_path / "t.csv")})
    log = logging.getLogger("test.metadata.unsigned")
    log.propagate = True
    server = VerdictServer(policy, detectors=[Counting()], logger=log)
    caplog.set_level(logging.DEBUG)
    try:
        raw, headers = _server_frame("webhook-id", FAKE_AWS_KEY)
        headers["webhook-signature"] = "v1,AAAA"
        status, _ = await ASGIClient(server).post("/hook", raw, headers)
    finally:
        server.close()
    assert status == 401
    assert Counting.calls == 0
    assert FAKE_AWS_KEY not in caplog.text
    logged = [getattr(r, "fields", {}) for r in caplog.records
              if r.getMessage() == "signature verification failed"]
    assert logged and logged[0]["request_id"].startswith("id_")


# -- adapter 4 -----------------------------------------------------------

OTEL_POSITIONS = ("session.id", "service.name", "model", "prompt.id", "tool_name",
                  "request_id", "client_request_id")
OTEL_TOKEN = "otel-token-for-the-tests-only"
OTEL_ORG = "org-abc"


def _otel_policy(**otel) -> Policy:
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["otel"].update({"orgs": [{"id": OTEL_ORG, "label": "primary", "token": OTEL_TOKEN}],
                        **otel})
    raw["server"]["metrics_token"] = "stats-token-0123456789abcdef"
    return Policy(raw=raw)


def _otel_batch(value: str, encode):
    from test_otel_payload import logs_json, logs_protobuf

    attributes = {"event.name": "claude_code.user_prompt", "prompt": "hello there"}
    attributes.update({k: value for k in OTEL_POSITIONS if k != "service.name"})
    resource = {"service.name": value, "organization.id": OTEL_ORG}
    records = [{"attributes": attributes, "body": ""}]
    if encode == "json":
        return logs_json(records, resource), "application/json"
    return logs_protobuf(records, resource), "application/x-protobuf"


@pytest.mark.parametrize("encode", ["json", "protobuf"])
@pytest.mark.parametrize("name", sorted(FIXTURES))
async def test_the_collector_keeps_metadata_out_of_every_sink(name, encode, tmp_path,
                                                              monkeypatch, caplog, capsys):
    from test_otel_payload import logs_json

    from forgd_verdict.otel.app import Collector

    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "findings"))
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    store = LocalFileStore(tmp_path / "store", instance="t")
    c = Collector(_otel_policy(cors_origins=["https://ok.test"]), store=store)
    client = ASGIClient(c)
    value = FIXTURES[name]
    caplog.set_level(logging.DEBUG)
    bodies = []
    try:
        body, ctype = _otel_batch(value, encode)
        status, out = await client.post(
            "/v1/logs", body, {"authorization": f"Bearer {OTEL_TOKEN}", "content-type": ctype})
        assert status == 200, out
        bodies.append(json.dumps(out))
        # A claimed org that does not match the token is logged on refusal.
        bad = logs_json([{"attributes": {"event.name": "x", "prompt": "hi there"},
                          "body": ""}], {"service.name": "claude-code", "organization.id": value})
        status, out = await client.post(
            "/v1/logs", bad, {"authorization": f"Bearer {OTEL_TOKEN}",
                              "content-type": "application/json"})
        assert status == 403
        bodies.append(json.dumps(out))
        metrics = json.dumps({"resourceMetrics": [{"scopeMetrics": [
            {"metrics": [{"name": f"m.{value}"}]}]}]}).encode()
        await client.post("/v1/metrics", metrics, {"authorization": f"Bearer {OTEL_TOKEN}",
                                                   "content-type": "application/json"})
        await client.request("OPTIONS", "/v1/logs", headers={"origin": f"https://{value}"})
        _, stats = await client.get("/stats", {"authorization": "Bearer " + "stats-token-0123456789abcdef"})
        c.sink.close()
        stored = _stored(store)
    finally:
        c.close()
    assert _leaks(*bodies, json.dumps(stats), stored, _logged(caplog, capsys)) == []
    assert stats["counts"]["metadata_redacted"] >= 1


def test_the_forwarder_masks_a_matching_identity_attribute(cheap):
    from test_sink import _cfg

    from forgd_verdict.otel.payload import OtelRecord
    from forgd_verdict.sink.redact import RedactionPlan, redact_events

    rec = OtelRecord(kind="log", name="claude_code.user_prompt",
                     attributes={"session.id": FAKE_AWS_KEY, "prompt": "hello there"},
                     resource={"service.name": FAKE_AWS_KEY})
    cfg = _cfg(redact=["regex:aws-access-key"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key"])
    out = redact_events([rec], {}, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=cheap)
    assert FAKE_AWS_KEY not in json.dumps(out[0].attributes)
    assert FAKE_AWS_KEY not in json.dumps(out[0].resource)
    assert out[0].redactions["metadata"] == 2
    assert out[0].attributes["prompt"] == "hello there"


# -- adapter 2, through the intake ----------------------------------------

INTAKE_TOKEN = "intake-token-for-alice-0123456789"


def _intake(tmp_path):
    from forgd_verdict.intake.app import Intake

    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"clients": [{"name": "alice-laptop", "token": INTAKE_TOKEN}]},
        "detectors": {"gitleaks": {"enabled": False}},
        "privacy": {"hash_salt": "s"}}))
    return Intake(policy, store=LocalFileStore(tmp_path / "store", instance="t"))


@pytest.mark.parametrize("name", sorted(FIXTURES))
async def test_the_intake_keeps_metadata_out_of_every_sink(name, tmp_path, caplog, capsys):
    value = FIXTURES[name]
    app = _intake(tmp_path)
    client = ASGIClient(app)
    caplog.set_level(logging.DEBUG)
    bodies = []
    scan_auth = {"authorization": f"Bearer {INTAKE_TOKEN}", "content-type": "application/json"}
    try:
        for payload in (
            {"hook_event_name": "UserPromptSubmit", "prompt": "hello there",
             "session_id": value, "prompt_id": value},
            {"hook_event_name": "PreToolUse", "tool_name": value, "tool_use_id": value,
             "session_id": value, "tool_input": {"command": "ls"}},
            {**frame(), "session_id": value, "model": value, "request_id": value,
             "source": {"application": value}},
        ):
            status, out = await client.post("/scan", json.dumps(payload).encode(), scan_auth)
            assert status == 200, out
            bodies.append(json.dumps(out))
        shipped = VerdictRecord(
            source=SOURCE_CODE_HOOK, request_id=value, session_id=value, surface=value,
            model=value, reported_as=value, salt_namespace=value, tiers_dropped=[value],
            action="deny", reference_id=value, shadow_action=value, build=value,
            actor_hash=value,
            findings=[FindingRow(value, "block", f"cmd.{value}", value, tool_name=value)],
            findings_count=1)
        status, out = await client.post(
            "/intake", (shipped.to_json() + "\n").encode(),
            {"authorization": f"Bearer {INTAKE_TOKEN}", "content-type": "application/x-ndjson"})
        assert status == 200, out
        bodies.append(json.dumps(out))
        stats = json.dumps(app.stats())
        app.flush()
        stored = _stored(app.store)
    finally:
        app.close()
    # The two clean hook allows share a session, so they are one tally row.
    assert len(stored.splitlines()) == 3
    assert '"tally":2' in stored
    assert _leaks(*bodies, stats, stored, _logged(caplog, capsys)) == []


# -- adapter 2, scanned on the laptop -------------------------------------


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_the_hook_spool_keeps_metadata_out(name, tmp_path, caplog, capsys):
    from forgd_verdict.hook.cli import run

    value = FIXTURES[name]
    spool = tmp_path / "spool"
    policy = Policy(raw=_deep_merge(load_policy("policy.yaml").raw, {
        "hook": {"spool": str(spool), "spool_enabled": True, "scan_endpoint": "",
                 "ship_mode": "off"},
        "detectors": {"gitleaks": {"enabled": False}}}))
    outputs = []
    for payload in (
        {"hook_event_name": "UserPromptSubmit", "prompt": "hello there",
         "session_id": value, "prompt_id": value},
        {"hook_event_name": "PreToolUse", "tool_name": value, "tool_use_id": value,
         "session_id": value, "tool_input": {"command": "ls"}},
    ):
        code, out = run(payload, policy)
        outputs.append(out)
    spooled = _files(spool)
    assert len(spooled.strip().splitlines()) == 2
    assert _leaks(*outputs, spooled, _logged(caplog, capsys)) == []


def test_the_hook_keeps_a_claude_code_session_id():
    """The UUID joins the hook's record with OTel's `session.id`."""
    from forgd_verdict.hook import cli

    captured = []
    sid = "22222222-2222-2222-2222-222222222222"

    class _Spool:
        def __init__(self, root=None):
            pass

        def append(self, record):
            captured.append(record)

    import unittest.mock as mock

    from forgd_verdict.core import ScanResult
    from forgd_verdict.models import Verdict
    with mock.patch.object(cli, "Spool", _Spool):
        cli._spool(load_policy("policy.yaml"), {"session_id": sid, "tool_name": "Bash",
                                                "tool_use_id": "toolu_01"},
                   "PreToolUse", Verdict(action="allow"), ScanResult(), "salt", ())
    assert captured[0].session_id == sid
    assert captured[0].request_id.startswith("PreToolUse:Bash:id_")
    assert "toolu_01" not in captured[0].request_id


async def test_an_unauthenticated_export_runs_no_detector(tmp_path, monkeypatch):
    """A refused Origin on a request with no token is held, bounded, and
    cleaned only when an authenticated /stats is read."""
    from forgd_verdict.detectors.t0_regex import T0RegexDetector
    from forgd_verdict.otel.app import Collector

    class Counting(T0RegexDetector):
        calls = 0

        def scan(self, units):
            Counting.calls += 1
            return super().scan(units)

    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    c = Collector(_otel_policy(cors_origins=["https://ok.test"]),
                  store=LocalFileStore(tmp_path, instance="t"), detectors=[Counting()])
    # Startup checks the shipped sink's metadata; only requests count here.
    Counting.calls = 0
    try:
        client = ASGIClient(c)
        status, _ = await client.post("/v1/logs", b"{}",
                                      {"origin": f"https://{FAKE_AWS_KEY}",
                                       "content-type": "application/json"})
        assert status == 401
        assert Counting.calls == 0
        _, stats = await client.get("/stats", {"authorization": "Bearer " + "stats-token-0123456789abcdef"})
    finally:
        c.close()
    assert Counting.calls >= 1
    assert FAKE_AWS_KEY not in json.dumps(stats)


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_the_forwarder_masks_a_matching_attribute_name(name, cheap):
    from test_sink import _cfg

    from forgd_verdict.otel.payload import OtelRecord
    from forgd_verdict.sink.redact import RedactionPlan, redact_events

    value = FIXTURES[name]
    rec = OtelRecord(kind="log", name="claude_code.user_prompt",
                     attributes={f"x.{value}": "plain", "prompt": "hello there",
                                 "session.id": "s1"},
                     resource={value: "claude-code", "service.name": "claude-code"})
    cfg = _cfg(redact=["regex:aws-access-key"])
    plan = RedactionPlan.build(cfg, ["regex:aws-access-key"])
    out = redact_events([rec], {}, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=cheap)
    assert _leaks(json.dumps(out[0].attributes), json.dumps(out[0].resource)) == []
    assert out[0].redactions["metadata-name"] == 2
    assert out[0].attributes["prompt"] == "hello there"
    assert out[0].attributes["session.id"] == "s1"
    assert out[0].resource["service.name"] == "claude-code"
