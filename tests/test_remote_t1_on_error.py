"""A T1 that did not run on the scan service follows `hook.on_error`, as it
does when the hook scans locally.

The intake decides under its own `server.on_tier_dropped` and reports the
tiers that did not run in `tiers_dropped`. The hook acts on that list."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import ASGIClient, make_policy

from forgd_verdict.hook import cli
from forgd_verdict.intake.app import Intake
from forgd_verdict.store import LocalFileStore

TOKEN = "intake-token-for-alice-0123456789"
PROMPT = {"session_id": "abc123", "hook_event_name": "UserPromptSubmit",
          "prompt": "please summarise the release notes"}
FAILING = "#!/bin/sh\ncat >/dev/null\nexit 3\n"


def _failing_gitleaks(tmp_path: Path) -> str:
    path = tmp_path / "opt" / "gitleaks"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(FAILING, encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _policy(tmp_path: Path, gitleaks: dict, on_error: str = "allow"):
    return make_policy(
        detectors={"gitleaks": {"severity": "block", "timeout_ms": 300, **gitleaks}},
        hook={"on_error": on_error, "ship_mode": "off", "spool_enabled": False},
        intake={"clients": [{"name": "alice-laptop", "token": TOKEN}]},
        privacy={"hash_salt": "s"})


async def _intake_reply(tmp_path: Path, policy) -> dict:
    app = Intake(policy, store=LocalFileStore(tmp_path / "store", instance="t"))
    try:
        status, body = await ASGIClient(app).post(
            "/scan", json.dumps(PROMPT).encode(),
            {"authorization": f"Bearer {TOKEN}", "content-type": "application/json"})
    finally:
        app.close()
    assert status == 200
    return body


def _run_with_reply(monkeypatch, reply: dict, on_error: str):
    monkeypatch.setattr(cli, "_remote_verdict", lambda *a, **k: dict(reply))
    policy = make_policy(hook={"on_error": on_error, "ship_mode": "off",
                               "spool_enabled": False})
    return cli.run(PROMPT, policy)


def _outcome(out: str) -> tuple[str, bool]:
    """(decision, whether the session was told T1 did not run)."""
    body = json.loads(out) if out else {}
    decision = "block" if body.get("decision") == "block" else "allow"
    told = "gitleaks (T1) did not run" in body.get("systemMessage", "") \
        or "gitleaks" in body.get("reason", "")
    return decision, told


# -- (a) the hook reads `tiers_dropped` ------------------------------------

REPLY = {"action": "allow", "detectors": [], "tiers_dropped": ["gitleaks"]}


def test_a_remote_t1_that_did_not_run_blocks_under_on_error_block(monkeypatch, capsys):
    code, out = _run_with_reply(monkeypatch, REPLY, "block")
    err = capsys.readouterr().err
    assert code == 0
    body = json.loads(out)
    assert body["decision"] == "block"
    assert "could not be checked" in body["reason"]
    assert "gitleaks (T1) did not run" in err and "is blocked" in err


def test_a_remote_t1_that_did_not_run_warns_under_on_error_allow(monkeypatch, capsys):
    code, out = _run_with_reply(monkeypatch, REPLY, "allow")
    err = capsys.readouterr().err
    assert code == 0
    body = json.loads(out)
    assert "decision" not in body
    message = body["systemMessage"]
    assert "gitleaks (T1) did not run" in message
    assert "is let through without T1" in message
    assert message in err


def test_a_remote_warning_and_a_dropped_t1_carry_both_messages(monkeypatch, capsys):
    reply = {**REPLY, "detectors": ["shell_exfil:pipe-to-network"]}
    _, out = _run_with_reply(monkeypatch, reply, "allow")
    capsys.readouterr()
    message = json.loads(out)["systemMessage"]
    assert "looks like it contains" in message
    assert "gitleaks (T1) did not run" in message


def test_a_remote_deny_is_unchanged_by_a_dropped_t1(monkeypatch, capsys):
    reply = {"action": "deny", "deny_reason": "blocked by the scan service",
             "tiers_dropped": ["gitleaks"]}
    _, out = _run_with_reply(monkeypatch, reply, "allow")
    assert json.loads(out)["reason"] == "blocked by the scan service"


@pytest.mark.parametrize("on_error", ["allow", "block"])
def test_a_remote_reply_with_every_tier_run_says_nothing(monkeypatch, capsys, on_error):
    reply = {"action": "allow", "detectors": [], "tiers_dropped": []}
    code, out = _run_with_reply(monkeypatch, reply, on_error)
    assert (code, out) == (0, "")
    assert "did not run" not in capsys.readouterr().err


@pytest.mark.parametrize("dropped", ["gitleaks", 7, [None]])
def test_a_tiers_dropped_that_is_not_a_list_of_names_falls_back(monkeypatch, capsys,
                                                                 dropped):
    """`_remote_verdict` refuses the reply and the hook scans locally."""
    import io

    class Reply(io.BytesIO):
        status = 200

    body = json.dumps({"action": "allow", "tiers_dropped": dropped}).encode()
    monkeypatch.setattr(cli, "open_url", lambda *a, **k: Reply(body))
    policy = make_policy(hook={"scan_endpoint": "https://scan.example/scan"})
    assert cli._remote_verdict(policy, PROMPT, 100) is None
    assert "unrecognised verdict" in capsys.readouterr().err


# -- (b) the intake reports a T1 it could not build -------------------------


async def test_the_intake_reports_a_t1_left_out_at_build(tmp_path):
    missing = str(tmp_path / "opt" / "no-such-gitleaks")
    body = await _intake_reply(tmp_path, _policy(tmp_path, {"enabled": "auto",
                                                            "binary": missing}))
    assert body["action"] == "allow"
    assert "gitleaks" in body["tiers_dropped"]


async def test_the_intake_reports_a_t1_that_failed_during_the_scan(tmp_path):
    body = await _intake_reply(tmp_path, _policy(
        tmp_path, {"enabled": True, "binary": _failing_gitleaks(tmp_path)}))
    assert body["tiers_dropped"] == ["gitleaks"]


async def test_the_intake_reports_no_t1_when_it_is_disabled(tmp_path):
    body = await _intake_reply(tmp_path, _policy(tmp_path, {"enabled": False}))
    assert "gitleaks" not in body["tiers_dropped"]


# -- (c) local and remote agree ---------------------------------------------


@pytest.mark.parametrize("on_error", ["allow", "block"])
@pytest.mark.parametrize("failure", ["fails-during-the-scan", "missing-at-build"])
async def test_local_and_remote_reach_the_same_outcome(tmp_path, monkeypatch, capsys,
                                                       on_error, failure):
    gitleaks = ({"enabled": True, "binary": _failing_gitleaks(tmp_path)}
                if failure == "fails-during-the-scan"
                else {"enabled": "auto", "binary": str(tmp_path / "no-such-gitleaks")})
    policy = _policy(tmp_path, gitleaks, on_error)

    _, local_out = cli.run(PROMPT, policy)
    reply = await _intake_reply(tmp_path, policy)
    _, remote_out = _run_with_reply(monkeypatch, reply, on_error)
    capsys.readouterr()

    local, remote = _outcome(local_out), _outcome(remote_out)
    assert local == remote
    assert local == ("block" if on_error == "block" else "allow", True)


# -- records carry the tiers that did not run --------------------------------


def _written(app) -> list:
    app.flush()
    return list(app.store.read_verdicts("1990-01-01T00:00:00Z", None))


@pytest.mark.parametrize("failure", ["fails-during-the-scan", "missing-at-build"])
async def test_the_intake_hook_record_carries_tiers_dropped(tmp_path, failure):
    gitleaks = ({"enabled": True, "binary": _failing_gitleaks(tmp_path)}
                if failure == "fails-during-the-scan"
                else {"enabled": "auto", "binary": str(tmp_path / "no-such-gitleaks")})
    app = Intake(_policy(tmp_path, gitleaks),
                 store=LocalFileStore(tmp_path / "store", instance="t"))
    try:
        _, body = await ASGIClient(app).post(
            "/scan", json.dumps(PROMPT).encode(),
            {"authorization": f"Bearer {TOKEN}", "content-type": "application/json"})
        [record] = _written(app)
    finally:
        app.close()
    assert record.tiers_dropped == body["tiers_dropped"] == ["gitleaks"]


@pytest.mark.parametrize("failure", ["fails-during-the-scan", "missing-at-build"])
async def test_the_intake_frame_record_carries_tiers_dropped(tmp_path, failure):
    gitleaks = ({"enabled": True, "binary": _failing_gitleaks(tmp_path)}
                if failure == "fails-during-the-scan"
                else {"enabled": "auto", "binary": str(tmp_path / "no-such-gitleaks")})
    app = Intake(_policy(tmp_path, gitleaks),
                 store=LocalFileStore(tmp_path / "store", instance="t"))
    frame = {"type": "prompt", "session_id": "sess-1",
             "messages": [{"role": "user", "content": "summarise the notes"}]}
    try:
        _, body = await ASGIClient(app).post(
            "/scan", json.dumps(frame).encode(),
            {"authorization": f"Bearer {TOKEN}", "content-type": "application/json"})
        [record] = _written(app)
    finally:
        app.close()
    assert "gitleaks" in body["tiers_dropped"]
    assert record.tiers_dropped == body["tiers_dropped"]


@pytest.mark.parametrize("failure", ["fails-during-the-scan", "missing-at-build"])
def test_the_hook_spooled_record_carries_tiers_dropped(tmp_path, monkeypatch, failure):
    gitleaks = ({"enabled": True, "binary": _failing_gitleaks(tmp_path)}
                if failure == "fails-during-the-scan"
                else {"enabled": "auto", "binary": str(tmp_path / "no-such-gitleaks")})
    appended = []

    class Spool:
        def __init__(self, root):
            pass

        def append(self, record):
            appended.append(record)

    monkeypatch.setattr(cli, "Spool", Spool)
    policy = _policy(tmp_path, gitleaks)
    policy.raw["hook"]["spool_enabled"] = True
    cli.run(PROMPT, policy)
    [record] = appended
    assert record.tiers_dropped == ["gitleaks"]


def test_a_complete_local_scan_spools_no_tiers_dropped(tmp_path, monkeypatch):
    appended = []
    monkeypatch.setattr(cli, "Spool", lambda root: type(
        "S", (), {"append": staticmethod(appended.append)})())
    policy = _policy(tmp_path, {"enabled": False})
    policy.raw["hook"]["spool_enabled"] = True
    cli.run(PROMPT, policy)
    [record] = appended
    assert record.tiers_dropped == []


# -- the intake records the outcome the hook enforces -------------------------


def test_the_hook_sends_its_on_error(monkeypatch):
    from forgd_verdict.intake.verify import ON_ERROR_HEADER

    sent = {}

    def capture(request, *a, **k):
        sent.update({k.lower(): v for k, v in request.header_items()})
        raise OSError("not reached")

    monkeypatch.setattr(cli, "open_url", capture)
    for on_error in ("allow", "block"):
        policy = make_policy(hook={"scan_endpoint": "https://scan.example/scan",
                                   "on_error": on_error})
        cli._remote_verdict(policy, PROMPT, 100)
        assert sent[ON_ERROR_HEADER] == on_error


async def _post(app, on_error=None, body=PROMPT):
    from forgd_verdict.intake.verify import ON_ERROR_HEADER

    sent = {"authorization": f"Bearer {TOKEN}", "content-type": "application/json"}
    if on_error is not None:
        sent[ON_ERROR_HEADER] = on_error
    return await ASGIClient(app).post("/scan", json.dumps(body).encode(), sent)


@pytest.mark.parametrize("failure", ["fails-during-the-scan", "missing-at-build"])
async def test_under_a_blocking_hook_the_intake_records_and_returns_a_deny(tmp_path,
                                                                           failure):
    gitleaks = ({"enabled": True, "binary": _failing_gitleaks(tmp_path)}
                if failure == "fails-during-the-scan"
                else {"enabled": "auto", "binary": str(tmp_path / "no-such-gitleaks")})
    app = Intake(_policy(tmp_path, gitleaks),
                 store=LocalFileStore(tmp_path / "store", instance="t"))
    try:
        _, body = await _post(app, "block")
        [record] = _written(app)
    finally:
        app.close()
    assert body["action"] == "deny"
    assert "could not be checked" in body["deny_reason"]
    assert body["reference_id"].startswith("fv_gitleaks_")
    assert (record.action, record.reference_id) == ("deny", body["reference_id"])
    assert record.tiers_dropped == ["gitleaks"]


@pytest.mark.parametrize("header", [None, "allow", "BLOCK", "deny", ""])
async def test_any_other_on_error_leaves_the_intake_verdict_alone(tmp_path, header):
    app = Intake(_policy(tmp_path, {"enabled": True, "binary": _failing_gitleaks(tmp_path)}),
                 store=LocalFileStore(tmp_path / "store", instance="t"))
    try:
        _, body = await _post(app, header)
        [record] = _written(app)
    finally:
        app.close()
    assert body["action"] == record.action == "allow"


async def test_a_blocking_hook_changes_nothing_when_t1_ran(tmp_path):
    app = Intake(_policy(tmp_path, {"enabled": False}),
                 store=LocalFileStore(tmp_path / "store", instance="t"))
    try:
        _, body = await _post(app, "block")
        [record] = _written(app)
    finally:
        app.close()
    assert body["action"] == record.action == "allow"


async def test_the_hook_shows_the_reference_the_intake_stored(tmp_path, monkeypatch,
                                                              capsys):
    app = Intake(_policy(tmp_path, {"enabled": True, "binary": _failing_gitleaks(tmp_path)}),
                 store=LocalFileStore(tmp_path / "store", instance="t"))
    try:
        _, reply = await _post(app, "block")
        [record] = _written(app)
    finally:
        app.close()
    _, out = _run_with_reply(monkeypatch, reply, "block")
    capsys.readouterr()
    assert json.loads(out)["reason"] == reply["deny_reason"]
    assert record.reference_id == reply["reference_id"]
