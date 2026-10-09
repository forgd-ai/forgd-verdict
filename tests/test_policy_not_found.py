"""A policy file that was named and is missing refuses; one that was never
named falls back to the defaults with the environment overrides applied."""

import sys
import types

import pytest

from forgd_verdict.policy import PolicyNotFound, load_identity, load_policy, policy_error

SECRET = "hunter2-must-not-print"


@pytest.fixture
def no_policy(tmp_path, monkeypatch):
    """No argument, no FORGD_VERDICT_POLICY, and no ./policy.yaml."""
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_a_missing_path_from_the_argument_refuses_and_names_it(tmp_path, monkeypatch):
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    missing = tmp_path / "absent.yaml"
    with pytest.raises(PolicyNotFound) as exc:
        load_policy(str(missing))
    assert str(missing) in str(exc.value)
    assert "--policy" in str(exc.value)
    assert exc.value.source == "--policy"


def test_a_missing_path_from_the_environment_refuses_and_names_it(tmp_path, monkeypatch):
    missing = tmp_path / "absent.yaml"
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(missing))
    with pytest.raises(PolicyNotFound) as exc:
        load_policy()
    assert str(missing) in str(exc.value)
    assert exc.value.source == "FORGD_VERDICT_POLICY"


def test_policy_not_found_is_a_file_not_found_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_policy(str(tmp_path / "absent.yaml"))


def test_policy_error_names_the_missing_path(tmp_path):
    missing = tmp_path / "absent.yaml"
    try:
        load_policy(str(missing))
    except PolicyNotFound as exc:
        assert str(missing) in policy_error(exc)


def test_no_policy_at_all_applies_the_environment_overrides(no_policy, monkeypatch):
    monkeypatch.setenv("FORGD_VERDICT_MODE", "enforce")
    monkeypatch.setenv("FORGD_VERDICT_STORE", str(no_policy / "store"))
    policy = load_policy()
    assert policy.mode == "enforce"
    assert policy.server["store"] == str(no_policy / "store")


def test_no_policy_at_all_does_not_share_the_defaults(no_policy, monkeypatch):
    monkeypatch.setenv("FORGD_VERDICT_MODE", "enforce")
    load_policy()
    monkeypatch.delenv("FORGD_VERDICT_MODE")
    assert load_policy().mode == "observe"


def test_identity_of_no_policy_tracks_the_overrides(no_policy, monkeypatch):
    before = load_identity()
    monkeypatch.setenv("FORGD_VERDICT_MODE", "enforce")
    assert load_identity() != before


# -- each server-side entry point refuses to start -----------------------


@pytest.fixture
def fake_uvicorn(monkeypatch):
    started = []
    monkeypatch.setitem(sys.modules, "uvicorn",
                        types.SimpleNamespace(run=lambda *a, **kw: started.append(kw)))
    return started


def _entry(name):
    return __import__(f"forgd_verdict.{name}.__main__", fromlist=["main"]).main


@pytest.mark.parametrize("name", ["server", "otel", "intake", "connector"])
def test_a_service_refuses_a_missing_policy_argument(name, tmp_path, monkeypatch, capsys,
                                                    fake_uvicorn):
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    missing = tmp_path / "absent.yaml"
    assert _entry(name)(["--policy", str(missing)]) == 2
    err = capsys.readouterr().err
    assert str(missing) in err
    assert "Traceback" not in err
    assert fake_uvicorn == []


@pytest.mark.parametrize("name", ["server", "otel", "intake", "connector", "dashboard"])
def test_a_service_refuses_a_missing_policy_from_the_environment(name, tmp_path, monkeypatch,
                                                                 capsys, fake_uvicorn):
    missing = tmp_path / "absent.yaml"
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(missing))
    argv = ["--store", str(tmp_path / "store"), "--host", "127.0.0.1"] \
        if name == "dashboard" else []
    assert _entry(name)(argv) == 2
    err = capsys.readouterr().err
    assert str(missing) in err and "FORGD_VERDICT_POLICY" in err
    assert len(err.strip().splitlines()) == 1
    assert fake_uvicorn == []


def test_ingest_refuses_a_missing_policy(tmp_path, monkeypatch, capsys):
    from forgd_verdict.cli import main

    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    missing = tmp_path / "absent.yaml"
    assert main(["--policy", str(missing), "ingest", "--store", str(tmp_path / "s")]) == 2
    err = capsys.readouterr().err
    assert str(missing) in err
    assert len(err.strip().splitlines()) == 1


# -- the CLI ---------------------------------------------------------------


def test_cli_policy_with_no_path_shows_the_defaults(no_policy, capsys):
    import json

    from forgd_verdict.cli import main

    assert main(["policy"]) == 0
    assert json.loads(capsys.readouterr().out)["server"]["mode"] == "observe"


def test_cli_policy_with_a_wrong_path_fails_clearly(tmp_path, monkeypatch, capsys):
    from forgd_verdict.cli import main

    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    missing = tmp_path / "absent.yaml"
    assert main(["--policy", str(missing), "policy"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(missing) in captured.err


# -- the hook keeps running on the defaults --------------------------------


def test_the_hook_still_runs_on_the_defaults_for_a_missing_path(tmp_path, monkeypatch):
    import io

    from forgd_verdict.hook import cli as hook_cli

    seen = {}

    def fake_evaluate(payload, policy):
        seen["mode"] = policy.mode
        return 0, None, None

    monkeypatch.setattr(hook_cli, "evaluate", fake_evaluate)
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    hook_cli.main(["--policy", str(tmp_path / "absent.yaml")])
    assert seen["mode"] == "observe"


def test_the_refusal_never_prints_file_content(tmp_path, monkeypatch, capsys, fake_uvicorn):
    """The message is built from the path alone; a directory beside it
    holding a secret-bearing file is never read."""
    (tmp_path / "policy.yaml").write_text(f"privacy:\n  hash_salt: {SECRET}\n")
    missing = tmp_path / "absent.yaml"
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(missing))
    monkeypatch.chdir(tmp_path)
    assert _entry("server")([]) == 2
    assert SECRET not in capsys.readouterr().err


# -- the dashboard's per-request reload ------------------------------------


async def _get(app, path):
    scope = {"type": "http", "method": "GET", "path": path, "headers": [],
             "query_string": b""}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        sent.append(m)

    await app(scope, receive, send)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return sent[0]["status"], body.decode()


async def test_a_policy_deleted_under_a_running_dashboard_is_not_replaced_by_defaults(
        tmp_path, monkeypatch):
    from forgd_verdict.dashboard.app import POLICY_CACHE, create_app

    path = tmp_path / "named.yaml"
    path.write_text("server:\n  mode: enforce\n")
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(path))
    monkeypatch.delenv("FORGD_VERDICT_MODE", raising=False)
    POLICY_CACHE.clear()
    app = create_app(str(tmp_path / "store"))
    status, page = await _get(app, "/policy")
    assert status == 200 and "enforce" in page

    path.unlink()
    status, page = await _get(app, "/policy")
    assert "does not exist" in page and "named.yaml" in page
    assert "observe" not in page, "the tab served the built-in defaults"
    POLICY_CACHE.clear()
