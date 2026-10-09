"""Refusal and error log lines carry no org id and no request-supplied secret.

Each test plants a credential-shaped value and an org UUID in one position
a refusal logs, drives the real refusal, and searches every captured
record -- message, `fields`, and exception text -- for both.
"""

from __future__ import annotations

import json
import logging

import pytest
from conftest import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, ASGIClient
from test_dashboard_admin import auth, pem, store  # noqa: F401 - fixtures

from forgd_verdict.models import pseudonym
from forgd_verdict.policy import Policy, load_policy
from forgd_verdict.store.local import LocalFileStore

SALT = "test-deployment-salt"
ORG_UUID = "00000000-1111-2222-3333-444444444444"
OTHER_UUID = "9a1e0000-0000-0000-0000-000000000000"
PLANTED = (FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, ORG_UUID, OTHER_UUID)


def _logged(caplog) -> str:
    out = []
    for r in caplog.records:
        out.append(r.getMessage())
        out.append(json.dumps(getattr(r, "fields", None), default=str))
        if r.exc_info:
            out.append(logging.Formatter().formatException(r.exc_info))
        if r.exc_text:
            out.append(r.exc_text)
    return "\n".join(out)


@pytest.fixture
def watch(caplog):
    """Attaches caplog to the `forgd_verdict` logger, which a service's
    `configure_logging` stops propagating. Call after building the app."""
    logger = logging.getLogger("forgd_verdict")
    level = logger.level

    def attach():
        caplog.set_level(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        if not logger.propagate:
            logger.addHandler(caplog.handler)

    yield attach
    logger.removeHandler(caplog.handler)
    logger.setLevel(level)


def _assert_clean(caplog) -> None:
    text = _logged(caplog)
    assert [v for v in PLANTED if v in text] == []


# -- otel collector ------------------------------------------------------------

OTEL_TOKEN = "otel-token-for-the-log-privacy-tests"


def _collector(tmp_path, monkeypatch, **otel):
    from forgd_verdict.otel.app import Collector

    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "findings"))
    monkeypatch.setenv("FORGD_HASH_SALT", SALT)
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["privacy"]["hash_salt"] = SALT
    raw["otel"].update({"orgs": [{"id": ORG_UUID, "label": "prod", "token": OTEL_TOKEN}],
                        **otel})
    return Collector(Policy(raw=raw), store=LocalFileStore(tmp_path / "s", instance="t"))


def _otel_auth(ctype="application/json"):
    return {"authorization": f"Bearer {OTEL_TOKEN}", "content-type": ctype}


def _claiming(org: str) -> bytes:
    from test_otel_payload import logs_json

    return logs_json([{"attributes": {"event.name": "claude_code.user_prompt",
                                      "prompt": "hello there"}, "body": ""}],
                     {"service.name": "claude-code", "organization.id": org})


@pytest.mark.parametrize("claimed", [FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, OTHER_UUID])
async def test_otel_an_org_mismatch_logs_neither_org(tmp_path, monkeypatch, caplog, watch,
                                                     claimed):
    app = _collector(tmp_path, monkeypatch)
    watch()
    try:
        status, _ = await ASGIClient(app).post("/v1/logs", _claiming(claimed), _otel_auth())
    finally:
        app.close()
    assert status == 403
    (rec,) = [r for r in caplog.records if "does not match" in r.getMessage()]
    assert rec.fields["token_org"] == pseudonym(ORG_UUID, SALT, "org")
    assert rec.fields["claimed"] == pseudonym(claimed, SALT, "org")
    _assert_clean(caplog)


async def test_otel_an_oversized_body_logs_no_org_id(tmp_path, monkeypatch, caplog, watch):
    app = _collector(tmp_path, monkeypatch, max_body_bytes=64)
    watch()
    try:
        status, _ = await ASGIClient(app).post(
            "/v1/logs", _claiming(ORG_UUID) + b" " * 128, _otel_auth())
    finally:
        app.close()
    assert status == 413
    assert any(r.getMessage() == "export body exceeded max_body_bytes"
               for r in caplog.records)
    _assert_clean(caplog)


async def test_otel_an_undecodable_body_logs_no_org_id(tmp_path, monkeypatch, caplog, watch):
    app = _collector(tmp_path, monkeypatch)
    watch()
    try:
        status, _ = await ASGIClient(app).post(
            "/v1/logs", b"\xff\xff\xff\xff" + FAKE_AWS_KEY.encode(),
            _otel_auth("application/x-protobuf"))
    finally:
        app.close()
    assert status == 400
    assert any(r.getMessage() == "undecodable export body" for r in caplog.records)
    _assert_clean(caplog)


@pytest.mark.usefixtures("control_identity")
async def test_otel_a_cold_collector_logs_no_org_id(tmp_path, monkeypatch, caplog, watch):
    from conftest import OVERRIDES_PUBLIC_TEXT

    from forgd_verdict.otel.app import Collector

    monkeypatch.setenv("FORGD_VERDICT_STORE", str(tmp_path / "findings"))
    raw = json.loads(json.dumps(load_policy("policy.yaml").raw, default=str))
    raw["privacy"]["hash_salt"] = SALT
    raw["otel"]["orgs"] = [{"id": ORG_UUID, "label": "prod", "token": OTEL_TOKEN}]
    raw.update({"dashboard": {"admins": {"groups": [{"group": "ops"}]}},
                "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}})
    app = Collector(Policy(raw=raw), store=LocalFileStore(tmp_path / "s", instance="t"))
    watch()
    try:
        status, _ = await ASGIClient(app).post("/v1/logs", _claiming(ORG_UUID), _otel_auth())
    finally:
        app.close()
    assert status == 503
    assert any("runtime overrides not ready" in r.getMessage() for r in caplog.records)
    _assert_clean(caplog)


# -- connector -----------------------------------------------------------------


def _connector(tmp_path):
    pytest.importorskip("mcp", reason="needs forgd-verdict[connector]")
    import yaml
    from test_connector_server import API_CLIENT, ISSUER, JWKS_URL, RESOURCE, SCOPE_FULL
    from test_connector_server import create_app as connector_app

    from forgd_verdict.connector import config

    block = {"enabled": True, "resource": RESOURCE, "scopes": [SCOPE_FULL],
             "required_scope": "findings.read",
             "auth": {"mode": "oidc_jwt", "issuer": ISSUER, "jwks_url": JWKS_URL,
                      "audience": [RESOURCE, API_CLIENT]}}
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({
        "privacy": {"hash_salt": SALT},
        "orgs": [{"id": ORG_UUID, "label": "prod"}],
        "connector": block}))
    cfg = config.load(load_policy(path))
    cfg._store_root = tmp_path / "store"
    return connector_app(cfg)


@pytest.mark.parametrize("planted", [FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, ORG_UUID])
async def test_connector_a_refused_origin_is_screened(tmp_path, caplog, jwks, signing_key,
                                                      planted):
    from test_connector_server import INITIALIZE, _bearer, _call, _token

    app = _connector(tmp_path)
    caplog.set_level(logging.DEBUG)
    status, _h, _b = await _call(app, "POST", "/mcp", INITIALIZE,
                                 {**_bearer(_token(signing_key)),
                                  "origin": f"https://{planted}.example"})
    assert status == 403
    assert any(r.getMessage() == "connector request refused" for r in caplog.records)
    _assert_clean(caplog)


@pytest.mark.parametrize("planted", [FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, ORG_UUID])
async def test_connector_a_missing_scope_does_not_log_the_subject(
        tmp_path, caplog, jwks, signing_key, planted):
    from test_connector_server import INITIALIZE, _bearer, _call, _token

    app = _connector(tmp_path)
    caplog.set_level(logging.DEBUG)
    status, _h, _b = await _call(app, "POST", "/mcp", INITIALIZE,
                                 _bearer(_token(signing_key, sub=f"user-{planted}",
                                                scp="something.else")))
    assert status == 403
    (rec,) = [r for r in caplog.records if r.getMessage() == "connector request refused"]
    assert "who" in rec.fields
    _assert_clean(caplog)


# -- dashboard -----------------------------------------------------------------


def _dashboard(tmp_path, monkeypatch, name: str, *, incomplete: bool):
    import yaml

    from forgd_verdict.dashboard.app import POLICY_CACHE, Dashboard
    from forgd_verdict.dashboard.auth import AuthConfig
    from forgd_verdict.entitlements import MODE_TRUSTED_HEADER, Principal

    raw = {"privacy": {"hash_salt": SALT},
           "orgs": [{"id": ORG_UUID, "label": "prod"}],
           "dashboard": {"auth": {"mode": "oidc_jwt", "jwks_url": "https://idp/keys",
                                  "issuer": "https://idp", "audience": "aud"},
                         "entitlements": {"map": [{"group": "g", "orgs": [ORG_UUID]}]}}}
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(raw))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(path))
    POLICY_CACHE.clear()

    class FixedAuth(AuthConfig):
        def authenticate(self, headers):
            return Principal(name, ("g",), groups_incomplete=incomplete)

    return Dashboard(LocalFileStore(tmp_path / "store", instance="t"),
                     auth=FixedAuth(mode=MODE_TRUSTED_HEADER),
                     entitlements=Policy(raw=raw).entitlements())


@pytest.mark.parametrize("planted", [FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, ORG_UUID])
async def test_dashboard_missing_groups_do_not_log_the_name(tmp_path, monkeypatch, caplog,
                                                            planted):
    from forgd_verdict.dashboard.app import POLICY_CACHE

    dash = _dashboard(tmp_path, monkeypatch, f"user-{planted}", incomplete=True)
    caplog.set_level(logging.DEBUG)
    try:
        status, body = await ASGIClient(dash).get("/")
    finally:
        POLICY_CACHE.clear()
    assert status == 403 and body["error"] == "groups_unavailable"
    _assert_clean(caplog)


@pytest.mark.parametrize("planted", [FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, ORG_UUID])
async def test_dashboard_a_refused_org_does_not_log_the_name(tmp_path, monkeypatch, caplog,
                                                             planted):
    from forgd_verdict.dashboard.app import POLICY_CACHE

    dash = _dashboard(tmp_path, monkeypatch, f"user-{planted}", incomplete=False)
    caplog.set_level(logging.DEBUG)
    try:
        status, body = await ASGIClient(dash).get(
            f"/?org={pseudonym(OTHER_UUID, SALT, 'org')}")
    finally:
        POLICY_CACHE.clear()
    assert status == 403 and body == {"error": "forbidden"}
    _assert_clean(caplog)


# -- compliance and the policy's org labels ------------------------------------


def _compliance_policy(**entry) -> Policy:
    return Policy(raw={"privacy": {"hash_salt": SALT}, "detectors": {},
                       "compliance": {"orgs": [{"id": ORG_UUID, "api_key": "k", **entry}]}})


def test_policy_an_org_without_a_label_is_labelled_by_its_pseudonym():
    (org,) = _compliance_policy().compliance_orgs()
    assert org["label"] == pseudonym(ORG_UUID, SALT, "org")


def test_policy_a_registry_org_without_a_label_is_labelled_by_its_pseudonym():
    policy = _compliance_policy()
    policy.raw["orgs"] = [{"id": ORG_UUID}]
    (org,) = policy.compliance_orgs()
    assert org["label"] == pseudonym(ORG_UUID, SALT, "org")


def test_policy_a_shared_cursor_names_entries_by_position_not_id():
    policy = Policy(raw={"privacy": {"hash_salt": SALT}, "compliance": {"orgs": [
        {"id": ORG_UUID, "api_key": "k", "state_path": "./x.json"},
        {"id": OTHER_UUID, "api_key": "k", "state_path": "./x.json"}]}})
    with pytest.raises(ValueError, match="share state_path") as exc:
        policy.compliance_orgs()
    assert ORG_UUID not in str(exc.value) and OTHER_UUID not in str(exc.value)
    assert "entries 0 and 1" in str(exc.value)


def test_compliance_a_missing_family_logs_no_org_id(tmp_path, monkeypatch, caplog):
    import forgd_verdict.compliance.ingest as mod
    from forgd_verdict.compliance.client import ComplianceError
    from forgd_verdict.compliance.scanner import ComplianceScanner

    class NoFamily(ComplianceScanner):
        def scan_sessions(self, **kw):
            raise ComplianceError(404, f"no such family {ORG_UUID}",
                                  f"https://api.test/v1/organizations/{ORG_UUID}/x")
            yield  # pragma: no cover

        def scan_chats(self, **kw):
            return iter(())

    monkeypatch.setattr(mod, "ComplianceScanner", NoFamily)
    caplog.set_level(logging.DEBUG)
    mod.run_ingest(_compliance_policy(), LocalFileStore(tmp_path, instance="t"),
                   include_denials=False, include_chats=False)
    assert any(r.getMessage() == "session family not available for this org"
               for r in caplog.records)
    _assert_clean(caplog)


# -- the verdict server ------------------------------------------------------


def _server(tmp_path, watch):
    from conftest import WHSEC, make_policy

    from forgd_verdict.server.app import VerdictServer

    policy = make_policy(
        privacy={"hash_salt": SALT},
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC], "csv_path": str(tmp_path / "t.csv")})
    findings = LocalFileStore(tmp_path / "store", instance="t")
    server = VerdictServer(policy, store=findings)
    watch()
    return server, findings


def _signed(**over):
    from conftest import frame, sign

    raw = json.dumps({**frame(), **over}).encode()
    return raw, sign(raw, webhook_id="msg_log_privacy")


async def test_server_the_tenant_id_is_logged_as_its_pseudonym(tmp_path, caplog, watch):
    server, findings = _server(tmp_path, watch)
    try:
        raw, headers = _signed(tenant_id=ORG_UUID)
        status, _ = await ASGIClient(server).post("/hook", raw, headers)
        assert status == 200
    finally:
        server.close()
    _assert_clean(caplog)
    org = pseudonym(ORG_UUID, SALT, "org")
    (line,) = [r for r in caplog.records if r.getMessage() == "verdict"]
    assert line.fields["tenant_id"] == org
    csv_text = (tmp_path / "t.csv").read_text()
    assert org in csv_text and ORG_UUID not in csv_text
    assert [r.tenant_hash for r in findings.read_verdicts()] == [org]


async def test_server_a_scan_failure_logs_no_exception_text(tmp_path, caplog, watch):
    server, _ = _server(tmp_path, watch)

    def boom(*a, **kw):
        raise RuntimeError(f"choked on {FAKE_AWS_KEY} for {ORG_UUID}")

    server._scan = boom
    try:
        raw, headers = _signed()
        await ASGIClient(server).post("/hook", raw, headers)
    finally:
        server.close()
    _assert_clean(caplog)
    (line,) = [r for r in caplog.records if r.getMessage() == "scan failed"]
    assert line.fields["error"] == "RuntimeError"


async def test_server_a_provenance_failure_logs_no_exception_text(tmp_path, caplog, watch):
    server, _ = _server(tmp_path, watch)

    class Broken:
        provenance = taint_severity = None
        checks = ["provenance"]

        def check(self, *a, **kw):
            raise RuntimeError(f"choked on {FAKE_GITHUB_TOKEN} for {ORG_UUID}")

    server.provenance = Broken()
    try:
        raw, headers = _signed()
        status, _ = await ASGIClient(server).post("/hook", raw, headers)
    finally:
        server.close()
    assert status == 200
    assert any(r.getMessage() == "provenance check failed" for r in caplog.records)
    _assert_clean(caplog)


# -- the intake, adapter 4's grouping, and the Azure Monitor sink ----------------


async def test_intake_a_store_failure_logs_no_exception_text(tmp_path, caplog, watch):
    from forgd_verdict.intake.app import Intake
    from forgd_verdict.policy import DEFAULT_POLICY, _deep_merge
    from forgd_verdict.store.base import SOURCE_CODE_HOOK, VerdictRecord

    token = "intake-token-for-the-log-privacy-tests"
    app = Intake(Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"clients": [{"name": "laptop", "token": token}]},
        "detectors": {"gitleaks": {"enabled": False}},
        "privacy": {"hash_salt": SALT}})),
        store=LocalFileStore(tmp_path / "store", instance="t"))
    watch()

    def boom(records):
        raise RuntimeError(f"store said no to {FAKE_AWS_KEY} in {ORG_UUID}")

    app.store.write_verdicts = boom
    shipped = VerdictRecord(source=SOURCE_CODE_HOOK, action="allow")
    status, _ = await ASGIClient(app).post(
        "/intake", (shipped.to_json() + "\n").encode(),
        {"authorization": f"Bearer {token}", "content-type": "application/x-ndjson"})
    app.close()
    assert status == 503
    assert any(r.getMessage() == "intake could not write a batch" for r in caplog.records)
    _assert_clean(caplog)


async def test_intake_a_failed_scan_write_logs_no_exception_text(tmp_path, caplog, watch):
    from forgd_verdict.intake.app import Intake
    from forgd_verdict.policy import DEFAULT_POLICY, _deep_merge

    token = "intake-token-for-the-log-privacy-tests"
    app = Intake(Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"clients": [{"name": "laptop", "token": token}]},
        "detectors": {"gitleaks": {"enabled": False}},
        "privacy": {"hash_salt": SALT}})),
        store=LocalFileStore(tmp_path / "store", instance="t"))
    watch()

    def boom(records):
        raise RuntimeError(f"store said no to {FAKE_AWS_KEY} in {ORG_UUID}")

    app.store.write_verdicts = boom
    scan = {"hook_event_name": "UserPromptSubmit", "prompt": "summarise the notes",
            "session_id": "550e8400-e29b-41d4-a716-446655440000"}
    status, _ = await ASGIClient(app).post(
        "/scan", json.dumps(scan).encode(),
        {"authorization": f"Bearer {token}", "content-type": "application/json"})
    assert status == 200
    app.flush()
    app.close()
    assert any(r.getMessage() == "store flush failed" for r in caplog.records)
    _assert_clean(caplog)


def test_collect_a_failing_sink_hook_logs_no_exception_text(caplog):
    from forgd_verdict.detectors.t0_regex import T0RegexDetector
    from forgd_verdict.otel.collect import collect
    from forgd_verdict.otel.payload import OtelRecord

    def boom(*a):
        raise RuntimeError(f"sink choked on {FAKE_AWS_KEY} for {ORG_UUID}")

    rec = OtelRecord(kind="log", name="claude_code.user_prompt",
                     attributes={"prompt": "hello there", "session.id": "s"})
    caplog.set_level(logging.DEBUG)
    collect([rec], [T0RegexDetector()], budget_ms=5000, org_id="o", on_group=boom)
    assert any(r.getMessage() == "sink hook failed" for r in caplog.records)
    _assert_clean(caplog)


def test_azmonitor_a_credential_failure_does_not_carry_its_message():
    from test_sink_azmonitor import _capture, _cfg, _event

    from forgd_verdict.sink.azmonitor import AzureMonitorSink
    from forgd_verdict.sink.otlp import SinkSendFailed

    def boom():
        raise RuntimeError(f"AADSTS700016: {FAKE_AWS_KEY} not found in tenant {ORG_UUID}")

    sink = AzureMonitorSink(_cfg(), connect=_capture()[0], token_provider=boom)
    with pytest.raises(SinkSendFailed) as exc:
        sink.send([_event()])
    assert "RuntimeError" in str(exc.value)
    assert [v for v in PLANTED if v in str(exc.value)] == []


# -- sink send failures ------------------------------------------------------

LEAK = "MATCHED-VALUE-LEAK"


def _drop_one(sink, caplog) -> logging.LogRecord:
    from test_sink import _event

    from forgd_verdict.sink.pipeline import SinkPipeline

    caplog.set_level(logging.DEBUG)
    pipe = SinkPipeline(sink, background=False)
    pipe.max_retries = 0
    pipe.offer([_event()])
    pipe.flush()
    assert pipe.stats()["dropped"] == 1
    (rec,) = [r for r in caplog.records if r.getMessage() == "sink batch dropped"]
    return rec


def _raising(exc):
    from conftest import FakeConnect

    return FakeConnect(error=exc)


def test_sink_an_http_error_body_is_not_logged(caplog):
    from conftest import FakeConnect
    from test_sink import _cfg

    from forgd_verdict.sink.otlp import OtlpSink

    rec = _drop_one(OtlpSink(_cfg(), connect=FakeConnect(400, body=LEAK.encode())), caplog)
    assert rec.fields["error"] == "SinkSendFailed" and rec.fields["status"] == 400
    assert LEAK not in _logged(caplog)


@pytest.mark.parametrize("sink_type", ["otlp", "azure-monitor"])
def test_sink_a_url_error_reason_is_not_logged(sink_type, caplog):
    import urllib.error

    err = urllib.error.URLError(LEAK)
    if sink_type == "otlp":
        from test_sink import _cfg

        from forgd_verdict.sink.otlp import OtlpSink

        sink = OtlpSink(_cfg(), connect=_raising(err))
    else:
        from test_sink_azmonitor import _cfg

        from forgd_verdict.sink.azmonitor import AzureMonitorSink

        sink = AzureMonitorSink(_cfg(), connect=_raising(err),
                                token_provider=lambda: ("t", 4_102_444_800.0))
    rec = _drop_one(sink, caplog)
    assert rec.fields["error"] == "SinkSendFailed" and "status" not in rec.fields
    assert LEAK not in _logged(caplog)


def test_sink_a_plugin_style_send_failure_is_not_logged(caplog):
    from forgd_verdict.sink.fake import FakeSink

    class Plugin(FakeSink):
        def send(self, events):
            raise RuntimeError(LEAK)

    rec = _drop_one(Plugin(max_events=10, max_bytes=10_000), caplog)
    assert rec.fields["error"] == "RuntimeError"
    assert LEAK not in _logged(caplog)


def test_sink_a_non_int_status_attribute_is_not_logged(caplog):
    from forgd_verdict.sink.fake import FakeSink

    class Shaped(RuntimeError):
        status = LEAK

    class Plugin(FakeSink):
        def send(self, events):
            raise Shaped("x")

    rec = _drop_one(Plugin(max_events=10, max_bytes=10_000), caplog)
    assert "status" not in rec.fields
    assert LEAK not in _logged(caplog)


# -- the dashboard's admin refusals ------------------------------------------


async def test_dashboard_admin_a_sec_fetch_site_value_is_not_logged(
        tmp_path, caplog, watch, store, auth, pem):  # noqa: F811
    from test_dashboard_admin import _app, _call, _form, _headers

    from forgd_verdict.overrides import ACTION_SET, KEY_MODE

    app = _app(store, auth)
    watch()
    status, _, _ = await _call(app, "POST", "/admin/actions",
                               _headers(pem, **{"sec-fetch-site": FAKE_AWS_KEY}),
                               _form(app, ACTION_SET, KEY_MODE, "enforce"))
    assert status == 403
    (line,) = [r for r in caplog.records if r.getMessage() == "dashboard admin action refused"]
    assert line.fields["sec_fetch_site"] == "other"
    _assert_clean(caplog)


# -- every remaining catch-all -------------------------------------------------


def test_no_log_call_in_src_emits_an_exception_message_or_traceback():
    """`exc_info=True` and `log.exception` put `str(exc)` and a traceback in
    the record, and `JsonFormatter` emits both. Catch-alls use `exc_fields`."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent / "src" / "forgd_verdict"
    hits = [f"{p.relative_to(root)}:{n}" for p in sorted(root.rglob("*.py"))
            for n, line in enumerate(p.read_text().splitlines(), 1)
            if not line.lstrip().startswith("#")
            and re.search(r"exc_info=True|\b(?:log|_log|self\.log|logger)\.exception\(", line)]
    assert hits == []


def test_exc_fields_names_the_type_and_place_and_never_the_message():
    from forgd_verdict.applog import exc_fields

    try:
        raise RuntimeError(f"{FAKE_AWS_KEY} {ORG_UUID}")
    except RuntimeError as exc:
        out = exc_fields(exc)
    assert out["error"] == "RuntimeError"
    assert out["at"].startswith("test_log_privacy.py:")
    assert [v for v in PLANTED if v in json.dumps(out)] == []
