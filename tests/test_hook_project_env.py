"""What a Claude Code project's environment cannot change about the hook.

A project's `.claude/settings.json` `env` block reaches the environment of
every hook Claude Code runs, the managed one included. Each test here sets
a variable the way such a block would and checks that the hook, or
`hook-ship`, ignores it unless the policy file sets
`hook.project_overrides: true`."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
import yaml
from conftest import FAKE_AWS_KEY

from forgd_verdict.hook import cli

AWS_PROMPT = {"hook_event_name": "UserPromptSubmit", "session_id": "s",
              "prompt": f"key {FAKE_AWS_KEY}"}


def _write(path: Path, data: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


def _hook(monkeypatch, capsys, argv: list[str], payload: dict) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def _allows_everything(tmp_path: Path) -> dict:
    """A policy a hostile project would write: nothing detects."""
    return {"detectors": {name: {"enabled": False} for name in
                          ("t0_regex", "checksums", "entropy", "shell_exfil", "gitleaks")}}


# -- A: which policy file the hook reads ----------------------------------


def test_the_hook_does_not_read_a_policy_named_by_the_environment(
        tmp_path, monkeypatch, capsys):
    hostile = _write(tmp_path / "project" / "lax.yaml", _allows_everything(tmp_path))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", hostile)
    code, out, err = _hook(monkeypatch, capsys, [], AWS_PROMPT)
    assert code == 0, err
    body = json.loads(out)
    assert body["decision"] == "block"
    assert "built-in defaults" in body["systemMessage"]


def test_the_hook_does_not_read_policy_yaml_from_the_project_directory(
        tmp_path, monkeypatch, capsys):
    project = tmp_path / "project"
    _write(project / "policy.yaml", _allows_everything(tmp_path))
    monkeypatch.chdir(project)
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    code, out, err = _hook(monkeypatch, capsys, [], AWS_PROMPT)
    assert code == 0, err
    body = json.loads(out)
    assert body["decision"] == "block"
    assert "built-in defaults" in body["systemMessage"]


def test_hook_ship_does_not_read_a_policy_named_by_the_environment(
        tmp_path, monkeypatch, capsys):
    from forgd_verdict.hook import ship

    store = tmp_path / "project" / "store"
    hostile = _write(tmp_path / "project" / "ship.yaml",
                     {"hook": {"ship_store": f"file://{store}"}})
    monkeypatch.setenv("FORGD_VERDICT_POLICY", hostile)
    assert ship.main([]) == 0
    assert json.loads(capsys.readouterr().out)["skipped"] == "no destination configured"


def test_hook_ship_does_not_read_policy_yaml_from_the_project_directory(
        tmp_path, monkeypatch, capsys):
    from forgd_verdict.hook import ship

    project = tmp_path / "project"
    _write(project / "policy.yaml", {"hook": {"ship_store": f"file://{project / 'store'}"}})
    monkeypatch.chdir(project)
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    assert ship.main([]) == 0
    assert json.loads(capsys.readouterr().out)["skipped"] == "no destination configured"


def test_the_detached_drain_is_given_the_hooks_policy_path(tmp_path, monkeypatch, capsys):
    from forgd_verdict.hook import ship

    spawned: list[list[str]] = []
    monkeypatch.setattr(ship.subprocess, "Popen", lambda argv, **kw: spawned.append(argv))
    policy = _write(tmp_path / "etc" / "policy.yaml", {"hook": {
        "ship_mode": "detached", "spool_enabled": False,
        "detectors": {"gitleaks": {"enabled": False}}},
        "detectors": {"gitleaks": {"enabled": False}}})
    _hook(monkeypatch, capsys, ["--policy", policy], {"hook_event_name": "UserPromptSubmit",
                                                      "prompt": "hello"})
    assert [argv[-2:] for argv in spawned] == [["--policy", policy]]


# -- B: where the spool and the device salt live --------------------------


def _quiet_policy(tmp_path: Path, **hook) -> str:
    return _write(tmp_path / "etc" / "policy.yaml", {
        "detectors": {"gitleaks": {"enabled": False}},
        "hook": {"ship_mode": "off", **hook}})


def _files(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()) \
        if root.exists() else []


@pytest.mark.parametrize("name", ["FORGD_VERDICT_SPOOL", "XDG_STATE_HOME", "HOME"])
def test_the_project_cannot_move_the_spool_or_the_salt(
        tmp_path, monkeypatch, capsys, trusted_home, name):
    project = tmp_path / "project"
    if name != "FORGD_VERDICT_SPOOL":
        monkeypatch.delenv("FORGD_VERDICT_SPOOL")
    monkeypatch.setenv(name, str(project / ("spool" if name == "FORGD_VERDICT_SPOOL" else "")))
    code, out, err = _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)],
                           AWS_PROMPT)
    assert json.loads(out)["decision"] == "block", err
    assert _files(project) == []
    state = trusted_home / ".local" / "state" / "forgd-verdict"
    assert "device-salt" in _files(state)
    assert any(f.startswith("spool/") for f in _files(state))


def test_a_planted_salt_is_not_used(tmp_path, monkeypatch, capsys, trusted_home):
    from forgd_verdict.hook.device import salt_namespace

    project = tmp_path / "project"
    (project / "spool").mkdir(parents=True)
    planted = "ab" * 32
    (project / "device-salt").write_text(planted)
    monkeypatch.setenv("FORGD_VERDICT_SPOOL", str(project / "spool"))
    _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)], AWS_PROMPT)
    state = trusted_home / ".local" / "state" / "forgd-verdict"
    spooled = "".join(p.read_text() for p in (state / "spool").rglob("*") if p.is_file())
    assert salt_namespace(planted) not in spooled
    assert (state / "device-salt").read_text().strip() != planted


def test_project_overrides_keep_the_spool_variable(tmp_path, monkeypatch, capsys):
    project = tmp_path / "project"
    monkeypatch.setenv("FORGD_VERDICT_SPOOL", str(project / "spool"))
    _hook(monkeypatch, capsys,
          ["--policy", _quiet_policy(tmp_path, project_overrides=True)], AWS_PROMPT)
    assert "device-salt" in _files(project)
    assert any(f.startswith("spool/") for f in _files(project))


def test_the_spool_argument_moves_the_spool_and_the_salt(tmp_path, monkeypatch, capsys):
    chosen = tmp_path / "chosen"
    _hook(monkeypatch, capsys,
          ["--policy", _quiet_policy(tmp_path), "--spool", str(chosen / "spool")], AWS_PROMPT)
    assert "device-salt" in _files(chosen)
    assert any(f.startswith("spool/") for f in _files(chosen))


def test_the_detached_drain_is_given_the_spool_argument(tmp_path, monkeypatch, capsys):
    from forgd_verdict.hook import ship

    spawned: list[list[str]] = []
    monkeypatch.setattr(ship.subprocess, "Popen", lambda argv, **kw: spawned.append(argv))
    chosen = str(tmp_path / "chosen" / "spool")
    policy = _quiet_policy(tmp_path, ship_mode="detached")
    _hook(monkeypatch, capsys, ["--policy", policy, "--spool", chosen], AWS_PROMPT)
    assert [argv[-4:] for argv in spawned] == [["--policy", policy, "--spool", chosen]]


def test_hook_ship_does_not_drain_a_spool_the_project_names(
        tmp_path, monkeypatch, capsys, trusted_home):
    from forgd_verdict.hook import ship
    from forgd_verdict.store.base import VerdictRecord
    from forgd_verdict.store.spool import Spool

    project = tmp_path / "project" / "spool"
    Spool(str(project)).append(VerdictRecord(source="planted", action="allow"))
    monkeypatch.setenv("FORGD_VERDICT_SPOOL", str(project))
    store = tmp_path / "store"
    policy = _quiet_policy(tmp_path, ship_store=f"file://{store}")
    assert ship.main(["--policy", policy]) == 0
    assert json.loads(capsys.readouterr().out)["shipped"] == 0
    assert _files(project)


def test_home_comes_from_the_password_database(monkeypatch, tmp_path):
    import os
    import pwd

    from forgd_verdict.hook import trust

    monkeypatch.setenv("HOME", str(tmp_path))
    assert trust.passwd_home() == Path(pwd.getpwuid(os.getuid()).pw_dir)


# -- C: who a spooled decision is attributed to ---------------------------


def _spooled(trusted_home: Path) -> list[dict]:
    spool = trusted_home / ".local" / "state" / "forgd-verdict" / "spool"
    return [json.loads(line) for p in spool.rglob("*") if p.is_file()
            for line in p.read_text().splitlines() if line.strip()]


def test_the_project_cannot_choose_who_a_decision_is_attributed_to(
        tmp_path, monkeypatch, capsys, trusted_home):
    import os
    import pwd

    from forgd_verdict.store.base import pseudonym

    for name in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.setenv(name, "someone-else")
    _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)], AWS_PROMPT)
    salt = (trusted_home / ".local" / "state" / "forgd-verdict" / "device-salt").read_text()
    (record,) = _spooled(trusted_home)
    me = pwd.getpwuid(os.getuid()).pw_name
    assert record["actor_hash"] == pseudonym(me, salt.strip(), "user")


# -- D: how stdin is decoded ------------------------------------------------

LATIN1 = "en_US.ISO8859-1"


def _latin1_available() -> bool:
    import subprocess
    import sys

    done = subprocess.run([sys.executable, "-I", "-c", "import sys; print(sys.stdin.encoding)"],
                          env={"LC_ALL": LATIN1, "PATH": "/usr/bin:/bin"},
                          stdin=subprocess.DEVNULL, capture_output=True, text=True)
    return done.stdout.strip().lower().replace("-", "") == "iso88591"


@pytest.mark.skipif(not _latin1_available(), reason=f"no {LATIN1} locale")
@pytest.mark.parametrize("key", ["AKIA​QYLPMN5HGZTHX4UQ",  # zero-width space inside
                                 "ＡKIAQYLPMN5HGZTHX4UQ"])  # fullwidth A
def test_the_project_locale_does_not_change_how_the_payload_is_read(tmp_path, key):
    import os
    import subprocess
    import sys

    policy = _quiet_policy(tmp_path, spool_enabled=False)
    payload = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": f"key {key}"},
                         ensure_ascii=False).encode("utf-8")
    done = subprocess.run(
        [sys.executable, "-I", "-m", "forgd_verdict.cli", "hook", "--policy", policy,
         "--spool", str(tmp_path / "spool")],
        input=payload, capture_output=True, timeout=60,
        env={**os.environ, "LC_ALL": LATIN1, "LANG": LATIN1, "LC_CTYPE": LATIN1})
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["decision"] == "block"


@pytest.mark.skipif(not _latin1_available(), reason=f"no {LATIN1} locale")
def test_stdin_that_is_not_utf8_is_refused_under_any_locale(tmp_path):
    import os
    import subprocess
    import sys

    policy = _quiet_policy(tmp_path, spool_enabled=False, on_error="block")
    done = subprocess.run(
        [sys.executable, "-I", "-m", "forgd_verdict.cli", "hook", "--policy", policy,
         "--spool", str(tmp_path / "spool")],
        input=b'{"hook_event_name":"UserPromptSubmit","prompt":"caf\xe9"}',
        capture_output=True, timeout=60, env={**os.environ, "LC_ALL": LATIN1})
    assert done.returncode == 2
    assert b"not valid UTF-8" in done.stderr


def test_stdin_is_decoded_as_utf8_whatever_its_text_encoding(tmp_path, monkeypatch, capsys):
    payload = json.dumps({"hook_event_name": "UserPromptSubmit",
                          "prompt": "key AKIA​QYLPMN5HGZTHX4UQ"}, ensure_ascii=False)
    stdin = io.TextIOWrapper(io.BytesIO(payload.encode("utf-8")), encoding="latin-1")
    monkeypatch.setattr("sys.stdin", stdin)
    assert cli.main(["--policy", _quiet_policy(tmp_path, spool_enabled=False)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "block"


# -- E: the hook's environment overrides -----------------------------------


def test_every_hook_override_needs_project_overrides():
    from forgd_verdict.policy import ENV_OVERRIDES, PROJECT_OVERRIDE_ENV

    hook = {name for name, (path, _cast) in ENV_OVERRIDES.items() if path[0] == "hook"}
    assert hook
    assert hook <= PROJECT_OVERRIDE_ENV


@pytest.mark.parametrize(("name", "value"), [
    ("FORGD_VERDICT_MODE", "observe"),
    ("FORGD_VERDICT_BUDGET_MS", "0"),
    ("FORGD_VERDICT_STORE", "file:///nonexistent-project-store"),
])
def test_server_overrides_do_not_reach_the_hook(tmp_path, monkeypatch, capsys, trusted_home,
                                                name, value):
    monkeypatch.setenv(name, value)
    code, out, err = _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)],
                           AWS_PROMPT)
    assert (code, json.loads(out)["decision"]) == (0, "block"), err
    (record,) = _spooled(trusted_home)
    assert record["findings_count"] >= 1


@pytest.mark.parametrize("name", ["FORGD_VERDICT_MODE", "FORGD_VERDICT_BUDGET_MS",
                                  "FORGD_VERDICT_STORE"])
def test_server_overrides_do_not_reach_the_hooks_policy(tmp_path, monkeypatch, name):
    from forgd_verdict.policy import load_policy

    path = _quiet_policy(tmp_path)
    plain = load_policy(path, for_hook=True).raw
    monkeypatch.setenv(name, {"FORGD_VERDICT_BUDGET_MS": "1"}.get(name, "observe-or-store"))
    assert load_policy(path, for_hook=True).raw == plain


# -- F: `$VAR` placeholders in the policy ---------------------------------


@pytest.mark.parametrize("key", ["ship_store", "ship_endpoint"])
def test_hook_ship_does_not_resolve_a_destination_from_the_project(
        tmp_path, monkeypatch, capsys, key):
    from forgd_verdict.hook import ship

    store = tmp_path / "project" / "store"
    monkeypatch.setenv("PROJECT_DEST", f"file://{store}" if key == "ship_store"
                       else "https://127.0.0.1:9/intake")
    policy = _quiet_policy(tmp_path, **{key: "$PROJECT_DEST"})
    assert ship.main(["--policy", policy]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["skipped"] == "no destination configured"
    assert "hook.project_overrides: true" in out.err
    assert not store.exists()


def test_a_placeholder_spool_is_not_resolved(tmp_path, monkeypatch, capsys, trusted_home):
    project = tmp_path / "project"
    monkeypatch.setenv("PROJECT_SPOOL", str(project))
    _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path, spool="$PROJECT_SPOOL")],
          AWS_PROMPT)
    assert _files(project) == []
    assert _spooled(trusted_home)


def test_hook_ship_has_one_placeholder_resolver():
    from forgd_verdict.hook import ship

    assert not hasattr(ship, "_resolve")


# -- G: the gitleaks subprocess's environment ------------------------------


def test_gitleaks_runs_with_only_the_environment_it_needs(tmp_path, monkeypatch, capsys):
    import os

    dump = tmp_path / "env.json"
    fake = tmp_path / "bin" / "gitleaks"
    fake.parent.mkdir()
    fake.write_text(f"#!{os.path.realpath(__import__('sys').executable)}\n"
                    "import json, os, sys\nsys.stdin.read()\n"
                    f"json.dump(dict(os.environ), open({str(dump)!r}, 'w'))\n"
                    "print('[]')\n")
    fake.chmod(0o755)
    for name, value in {"GITLEAKS_CONFIG": "/project/x.toml", "GITLEAKS_CONFIG_TOML": "x",
                        "GODEBUG": "x509ignoreCN=0", "LD_PRELOAD": "/project/x.so",
                        "PROJECT_SECRET": "x"}.items():
        monkeypatch.setenv(name, value)
    policy = _write(tmp_path / "etc" / "policy.yaml", {
        "detectors": {"gitleaks": {"enabled": True, "binary": str(fake)}},
        "hook": {"ship_mode": "off", "spool_enabled": False}})
    _hook(monkeypatch, capsys, ["--policy", policy], {"hook_event_name": "UserPromptSubmit",
                                                      "prompt": "hello"})
    passed = json.loads(dump.read_text())
    allowed = {"SYSTEMROOT"} if os.name == "nt" else set()
    # macOS's loader and the interpreter set these in the child itself.
    started = {"__CF_USER_TEXT_ENCODING", "LC_CTYPE", "__PYVENV_LAUNCHER__"}
    assert set(passed) - started <= allowed, sorted(passed)


# -- H: the temporary directory --------------------------------------------


@pytest.mark.skipif(__import__("shutil").which("gitleaks") is None, reason="needs gitleaks")
def test_a_tmpdir_holding_gitleaks_ignore_files_does_not_suppress_a_finding(
        tmp_path, monkeypatch, capsys):
    """Both files suppress the probe when they are in gitleaks' working
    directory, `--config` pinned or not."""
    import shutil
    import tempfile

    project_tmp = tmp_path / "project-tmp"
    project_tmp.mkdir()
    (project_tmp / ".gitleaks.toml").write_text(
        '[extend]\nuseDefault = true\n[allowlist]\nregexes = [".*"]\n')
    (project_tmp / ".gitleaksignore").write_text(
        ":gitlab-pat:1\nstdin:gitlab-pat:1\n-:gitlab-pat:1\n")
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(name, str(project_tmp))
    monkeypatch.setattr(tempfile, "tempdir", None)
    policy = _write(tmp_path / "etc" / "policy.yaml", {
        "detectors": {"gitleaks": {"enabled": True, "binary": shutil.which("gitleaks")}},
        "hook": {"ship_mode": "off", "spool_enabled": False}})
    probe = {"hook_event_name": "UserPromptSubmit",
             "prompt": "token " + "glpat-" + "V9v0M48onQvilZzFz0tS"}
    code, out, err = _hook(monkeypatch, capsys, ["--policy", policy], probe)
    assert json.loads(out)["decision"] == "block", err


# -- I: TLS trust, proxies and store SDKs ----------------------------------


class _Collector:
    """An HTTP listener that accepts anything; `hits` counts requests."""

    def __init__(self, body: bytes):
        import http.server
        import threading

        outer = self
        self.hits = 0

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self):
                outer.hits += 1
                n = int(self.headers.get("content-length", 0) or 0)
                self.rfile.read(n)
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET = do_CONNECT = _answer

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()


PROXY_VARS = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
              "all_proxy"]


@pytest.mark.parametrize("name", PROXY_VARS)
def test_hook_ship_does_not_use_a_proxy_from_the_environment(
        tmp_path, monkeypatch, capsys, trusted_home, name):
    from forgd_verdict.hook import ship

    _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)], AWS_PROMPT)
    proxy = _Collector(b'{"accepted": 1}')
    try:
        for var in ("NO_PROXY", "no_proxy", *PROXY_VARS):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv(name, proxy.url)
        policy = _quiet_policy(tmp_path, ship_endpoint="http://127.0.0.1:9/intake")
        assert ship.main(["--policy", policy]) == 0
        assert json.loads(capsys.readouterr().out)["shipped"] == 0
        assert proxy.hits == 0
    finally:
        proxy.close()


@pytest.mark.parametrize("name", PROXY_VARS)
def test_the_remote_scan_does_not_use_a_proxy_from_the_environment(
        tmp_path, monkeypatch, capsys, name):
    proxy = _Collector(b'{"action": "allow"}')
    try:
        for var in ("NO_PROXY", "no_proxy", *PROXY_VARS):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv(name, proxy.url)
        policy = _quiet_policy(tmp_path, spool_enabled=False,
                               scan_endpoint="http://127.0.0.1:9/scan")
        code, out, err = _hook(monkeypatch, capsys, ["--policy", policy], AWS_PROMPT)
        assert json.loads(out)["decision"] == "block", err
        assert proxy.hits == 0
    finally:
        proxy.close()


@pytest.mark.parametrize("spec", ["s3://bucket/prefix", "gs://bucket/prefix",
                                  "https://acct.blob.core.windows.net/findings"])
def test_hook_ship_refuses_a_remote_store_without_project_overrides(
        tmp_path, monkeypatch, capsys, trusted_home, spec):
    import forgd_verdict.store as store

    _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)], AWS_PROMPT)
    opened: list[str] = []
    monkeypatch.setattr(store, "open_store", lambda s, **kw: opened.append(s))
    from forgd_verdict.hook import ship

    assert ship.main(["--policy", _quiet_policy(tmp_path, ship_store=spec)]) == 0
    out = capsys.readouterr()
    assert opened == []
    assert json.loads(out.out)["shipped"] == 0
    assert "hook.project_overrides: true" in out.err
    assert _spooled(trusted_home)


def test_hook_ship_opens_a_remote_store_with_project_overrides(
        tmp_path, monkeypatch, capsys, trusted_home):
    import forgd_verdict.store as store

    opened: list[str] = []

    class _Store:
        def write_verdicts(self, records):
            return len(records)

    monkeypatch.setattr(store, "open_store", lambda s, **kw: opened.append(s) or _Store())
    from forgd_verdict.hook import ship

    policy = _quiet_policy(tmp_path, ship_store="s3://bucket/prefix", project_overrides=True)
    assert ship.main(["--policy", policy]) == 0
    assert opened == ["s3://bucket/prefix"]


class _OpenedStore:
    def write_verdicts(self, records):
        return len(records)


def _recording_open_store(monkeypatch) -> list[str]:
    import forgd_verdict.store as store

    opened: list[str] = []
    monkeypatch.setattr(store, "open_store",
                        lambda s, **kw: opened.append(s) or _OpenedStore())
    return opened


@pytest.mark.parametrize("spec", ["s3://bucket/prefix", "gs://bucket/prefix",
                                  "https://acct.blob.core.windows.net/findings"])
def test_hook_ship_opens_a_remote_store_given_with_store(
        tmp_path, monkeypatch, capsys, trusted_home, spec):
    """A project sets the environment, not argv."""
    _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)], AWS_PROMPT)
    opened = _recording_open_store(monkeypatch)
    from forgd_verdict.hook import ship

    assert ship.main(["--policy", _quiet_policy(tmp_path), "--store", spec]) == 0
    out = capsys.readouterr()
    assert opened == [spec]
    assert json.loads(out.out)["shipped"] == 1
    assert "project_overrides" not in out.err


@pytest.mark.parametrize("windows,marked,opens", [
    (True, True, False),
    (False, True, True),
    (True, False, True),
], ids=["windows-hook", "posix-hook", "windows-admin-terminal"])
def test_a_remote_store_given_with_store_from_a_windows_hook_needs_project_overrides(
        tmp_path, monkeypatch, capsys, trusted_home, windows, marked, opens):
    """On Windows the hook's environment is the project's, and the store's
    SDK takes its endpoint and credentials from it. POSIX starts the hook
    under `env -i`."""
    import sys

    from forgd_verdict.hook import ship

    _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)], AWS_PROMPT)
    opened = _recording_open_store(monkeypatch)
    monkeypatch.setattr(ship, "_windows", lambda: windows)
    if marked:
        monkeypatch.setitem(sys._xoptions, "forgd_verdict_hook", True)
    else:
        monkeypatch.delitem(sys._xoptions, "forgd_verdict_hook", raising=False)
    assert ship.main(["--policy", _quiet_policy(tmp_path), "--store", "s3://bucket/p"]) == 0
    out = capsys.readouterr()
    assert opened == (["s3://bucket/p"] if opens else [])
    assert json.loads(out.out)["shipped"] == (1 if opens else 0)
    if not opens:
        assert "not shipping to --store" in out.err
        assert "hook.project_overrides: true" in out.err
        assert _spooled(trusted_home)


def test_a_windows_hook_opens_a_remote_store_given_with_store_with_project_overrides(
        tmp_path, monkeypatch, capsys, trusted_home):
    import sys

    from forgd_verdict.hook import ship

    opened = _recording_open_store(monkeypatch)
    monkeypatch.setattr(ship, "_windows", lambda: True)
    monkeypatch.setitem(sys._xoptions, "forgd_verdict_hook", True)
    policy = _quiet_policy(tmp_path, project_overrides=True)
    assert ship.main(["--policy", policy, "--store", "s3://bucket/p"]) == 0
    assert opened == ["s3://bucket/p"]


def test_hook_ship_refuses_a_remote_store_from_the_environment(
        tmp_path, monkeypatch, capsys, trusted_home):
    _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)], AWS_PROMPT)
    opened = _recording_open_store(monkeypatch)
    monkeypatch.setenv("FORGD_VERDICT_SHIP_STORE", "s3://project-bucket/prefix")
    from forgd_verdict.hook import ship

    assert ship.main(["--policy", _quiet_policy(tmp_path)]) == 0
    assert opened == []
    assert json.loads(capsys.readouterr().out)["shipped"] == 0
    assert _spooled(trusted_home)


def test_hook_ship_refuses_a_remote_store_named_by_a_placeholder(
        tmp_path, monkeypatch, capsys, trusted_home):
    _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)], AWS_PROMPT)
    opened = _recording_open_store(monkeypatch)
    monkeypatch.setenv("SHIP_STORE", "s3://project-bucket/prefix")
    from forgd_verdict.hook import ship

    assert ship.main(["--policy", _quiet_policy(tmp_path, ship_store="$SHIP_STORE")]) == 0
    assert opened == []
    assert json.loads(capsys.readouterr().out)["shipped"] == 0
    assert _spooled(trusted_home)


def test_hook_ship_still_writes_a_local_store(tmp_path, monkeypatch, capsys, trusted_home):
    from forgd_verdict.hook import ship

    _hook(monkeypatch, capsys, ["--policy", _quiet_policy(tmp_path)], AWS_PROMPT)
    store = tmp_path / "store"
    assert ship.main(["--policy", _quiet_policy(tmp_path, ship_store=f"file://{store}")]) == 0
    assert json.loads(capsys.readouterr().out)["shipped"] == 1


# -- J: the build stamp ----------------------------------------------------


def test_the_project_cannot_stamp_the_build_on_a_spooled_decision(tmp_path):
    import os
    import subprocess
    import sys

    from forgd_verdict import __version__

    spool = tmp_path / "state" / "spool"
    done = subprocess.run(
        [sys.executable, "-I", "-m", "forgd_verdict.cli", "hook",
         "--policy", _quiet_policy(tmp_path), "--spool", str(spool)],
        input=json.dumps(AWS_PROMPT), capture_output=True, text=True, timeout=60,
        env={**os.environ, "FORGD_BUILD_COMMIT": "0123456789abcdef"})
    assert json.loads(done.stdout)["decision"] == "block", done.stderr
    (record,) = [json.loads(line) for p in spool.rglob("*") if p.is_file()
                 for line in p.read_text().splitlines() if line.strip()]
    assert record["build"].split("+")[0] == __version__
    assert "0123456789ab" not in record["build"]


# -- K: executables found through PATH --------------------------------------

SPAWN = r"\b(subprocess\.(run|Popen|call|check_call|check_output)|" \
        r"os\.(system|popen|exec\w*|spawn\w*|posix_spawn\w*)|shutil\.which)\("


def test_every_process_the_package_starts_is_reviewed_here():
    """detectors/gitleaks.py runs an absolute `binary` on the hook (or PATH
    with project overrides), and hook/ship.py runs sys.executable. cli.py
    looks up and runs the `bash` on PATH for `verify-deployment`, an operator
    command the hook never reaches. A new call site anywhere in the package
    fails this until it is checked against a PATH a project sets."""
    import re

    src = Path(__file__).resolve().parents[1] / "src" / "forgd_verdict"
    found = {str(p.relative_to(src)): len(re.findall(SPAWN, p.read_text(encoding="utf-8")))
             for p in src.rglob("*.py") if re.search(SPAWN, p.read_text(encoding="utf-8"))}
    assert found == {"cli.py": 2, "detectors/gitleaks.py": 3, "hook/ship.py": 1}


def test_the_detached_drain_runs_this_interpreter_not_one_on_path(tmp_path, monkeypatch):
    import os
    import sys

    from forgd_verdict.hook import ship

    project_bin = tmp_path / "project-bin"
    project_bin.mkdir()
    for name in ("python", "python3", "forgd-verdict"):
        (project_bin / name).write_text("#!/bin/sh\nexit 0\n")
        (project_bin / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{project_bin}{os.pathsep}{os.environ['PATH']}")
    spawned: list[list[str]] = []
    monkeypatch.setattr(ship.subprocess, "Popen", lambda argv, **kw: spawned.append(argv))
    assert ship.spawn_detached("/etc/forgd/policy.yaml")
    (argv,) = spawned
    assert argv[0] == sys.executable and os.path.isabs(argv[0])
    assert argv[1:6] == ["-I", "-X", "forgd_verdict_hook", "-m", "forgd_verdict.cli"]
