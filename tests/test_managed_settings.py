"""The shipped managed-settings fragment registers every event the hook scans.

`hook.enabled_events` decides what the hook scans; the settings file decides
what Claude Code CALLS it for. An event enabled in one and not registered in
the other is scanned by nothing. `UserPromptExpansion` was added to the
policy -- a slash command's expanded prompt reached the model unscanned
-- and never to this file, so that fix was dormant anywhere the
shipped fragment was used.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml
from conftest import managed_interpreter_argv

from forgd_verdict.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]
POSIX = ROOT / "deploy" / "managed-settings.fragment.json"
WINDOWS = ROOT / "deploy" / "managed-settings.windows.fragment.json"
FRAGMENTS = {"posix": POSIX, "windows": WINDOWS}
PATHS = {
    "posix": ("/opt/forgd/venv/bin/python", "/etc/forgd/policy.yaml"),
    "windows": (r"C:\Program Files\forgd\venv\Scripts\python.exe",
                r"C:\ProgramData\forgd\policy.yaml"),
}
ABSOLUTE = {
    "posix": re.compile(r"/[^/]"),
    "windows": re.compile(r"[A-Za-z]:\\[^\\]"),
}


def _load(name: str) -> dict:
    return json.loads(FRAGMENTS[name].read_text())


def _hooks_of(fragment: dict):
    for event, entries in fragment["hooks"].items():
        for entry in entries:
            for hook in entry["hooks"]:
                yield event, hook


def _hooks(name: str):
    return _hooks_of(_load(name))


@pytest.mark.parametrize("name", sorted(FRAGMENTS))
def test_every_enabled_event_is_registered(name):
    fragment = _load(name)
    registered = set(fragment["hooks"])
    enabled = set(load_policy(str(ROOT / "policy.yaml")).hook.get("enabled_events") or [])
    missing = sorted(enabled - registered)
    assert not missing, f"enabled in policy.yaml but never registered: {missing}"


def test_the_platform_doc_example_registers_them_too():
    doc = (ROOT / "docs" / "PLATFORM.md").read_text()
    enabled = load_policy(str(ROOT / "policy.yaml")).hook.get("enabled_events") or []
    start = doc.index("## Adapter 2")
    example = doc[start:doc.index("```", doc.index("```jsonc", start) + 1)]
    missing = [e for e in enabled if f'"{e}"' not in example]
    assert not missing, f"PLATFORM.md hook example omits {missing}"


def test_the_platform_doc_example_runs_the_fragments_command():
    doc = (ROOT / "docs" / "PLATFORM.md").read_text()
    start = doc.index("## Adapter 2")
    block = doc[doc.index("```jsonc", start) + len("```jsonc"):doc.index("```", doc.index("```jsonc", start) + 1)]
    example = json.loads("\n".join(line for line in block.splitlines()
                                    if not line.lstrip().startswith("//")))
    fragment = {(h["command"], tuple(h["args"])) for _, h in _hooks("posix")
                if "hook" in h["args"]}
    shown = {(h["command"], tuple(h["args"])) for entries in example["hooks"].values()
             for entry in entries for h in entry["hooks"]}
    assert shown == fragment


def _comment(name: str = "posix") -> str:
    fragment = _load(name)
    return " ".join(" ".join(fragment["_comment"]).split())


def test_the_lock_precedence_is_stated_only_under_merge():
    """Under the default first-wins, allowManagedHooksOnly is read from the
    selected source only; the strictest value wins only under merge."""
    sentences = [s for s in re.split(r"(?<=\.)\s", _comment()) if "strictest" in s]
    assert sentences
    assert all("merge" in s for s in sentences), sentences


@pytest.mark.parametrize("name", sorted(FRAGMENTS))
def test_the_verified_date_matches_mdm(name):
    mdm = (ROOT / "deploy" / "MDM.md").read_text()
    [doc] = re.findall(r"Verified (\d{4}-\d{2}-\d{2})", mdm)
    assert re.findall(r"verified (\d{4}-\d{2}-\d{2})", _comment(name)) == [doc]


@pytest.mark.parametrize("name", sorted(FRAGMENTS))
def test_the_expansion_status_message_does_not_claim_expanded_content(name):
    fragment = _load(name)
    [entry] = fragment["hooks"]["UserPromptExpansion"]
    [hook] = entry["hooks"]
    assert "expand" not in hook["statusMessage"].lower()


def test_the_timeout_comment_gives_the_user_prompt_submit_default():
    comment = _comment()
    paragraph = comment[comment.index("timeout is in"):comment.index("THE FOUR HOOKS")]
    assert "UserPromptSubmit" in paragraph and "30" in paragraph, paragraph


def test_the_protocol_doc_gives_each_hook_timeout_default():
    """600 s is the default for most events, not all of them."""
    text = " ".join((ROOT / "docs" / "PROTOCOL.md").read_text().split())
    paragraph = text[text.index("Hook `timeout`"):]
    paragraph = paragraph[:paragraph.index(" ## ")]
    assert "default 600." not in paragraph
    for needed in ("600", "30", "UserPromptSubmit", "SessionEnd", "1.5"):
        assert needed in paragraph, needed


@pytest.mark.parametrize("name", sorted(FRAGMENTS))
def test_every_hook_runs_the_module_isolated_with_an_absolute_policy(name):
    """`-I` needs the interpreter, so the command is never a console script."""
    python, policy = PATHS[name]
    hooks = list(_hooks(name))
    assert hooks
    for event, hook in hooks:
        argv = managed_interpreter_argv(hook)
        assert argv[0] == python, event
        assert ABSOLUTE[name].match(argv[0]), event
        assert argv[1:6] == ["-I", "-X", "forgd_verdict_hook", "-m", "forgd_verdict.cli"], event
        i = argv.index("--policy")
        assert argv[i + 1] == policy, event
        assert ABSOLUTE[name].match(argv[i + 1]), event


def test_every_posix_hook_starts_the_interpreter_with_an_empty_environment():
    """A project's `.claude/settings.json` `env` block reaches the hook's
    environment, and `OPENSSL_CONF`, `OPENSSL_MODULES` and
    `OPENSSL_ENGINES` are read when `forgd_verdict` imports hashlib,
    before `main()` arms the watchdog. `-I` does not clear them."""
    python, _policy = PATHS["posix"]
    hooks = list(_hooks("posix"))
    commands = {a for _, hook in hooks for a in hook["args"] if a in ("hook", "hook-ship")}
    assert commands == {"hook", "hook-ship"}
    for event, hook in hooks:
        assert hook["command"] == "/usr/bin/env", event
        assert hook["args"][:3] == ["-i", python, "-I"], event


def test_every_windows_hook_marks_the_interpreter_as_a_hook():
    """Windows has no `env -i`. `-X forgd_verdict_hook` makes
    `forgd_verdict/__init__.py` remove the variables in
    `forgd_verdict._hookenv` before anything else is imported. A project
    cannot set it: `-X` options come only from argv, and `-I` ignores
    `PYTHON*`."""
    python, _policy = PATHS["windows"]
    hooks = list(_hooks("windows"))
    commands = {a for _, hook in hooks for a in hook["args"] if a in ("hook", "hook-ship")}
    assert commands == {"hook", "hook-ship"}
    for event, hook in hooks:
        assert hook["command"] == python, event
        assert hook["args"][:5] == ["-I", "-X", "forgd_verdict_hook", "-m",
                                    "forgd_verdict.cli"], event


POLICY_DIR_RULES = {"posix": "Read(//etc/forgd/**)",
                    "windows": "Read(//c/ProgramData/forgd/**)"}


def _without_paths(name: str) -> dict:
    python, policy = PATHS[name]
    fragment = _load(name)
    fragment.pop("_comment")
    fragment["permissions"]["deny"] = ["Read(POLICY_DIR)" if r == POLICY_DIR_RULES[name] else r
                                       for r in fragment["permissions"]["deny"]]
    for _, hook in _hooks_of(fragment):
        argv = managed_interpreter_argv(hook)
        hook["command"] = "PYTHON"
        hook["args"] = ["POLICY" if a == policy else a for a in argv[1:]]
    return fragment


def test_the_windows_fragment_differs_only_in_paths():
    assert _without_paths("windows") == _without_paths("posix")


def test_the_windows_fragment_names_the_windows_location_and_the_rest():
    comment = _comment("windows")
    assert r"C:\Program Files\ClaudeCode\managed-settings.json" in comment
    assert "/Library/" not in comment and "/etc/claude-code" not in comment
    assert "managed-settings.fragment.json" in comment
    assert "deploy/MDM.md" in comment


# --- The fragment's command, run --------------------------------------------------------

PROBE = "AKIAQYLPMN5HGZTHX4UQ"  # gitleaks:allow
PAYLOADS = {
    "UserPromptSubmit": {"hook_event_name": "UserPromptSubmit", "session_id": "s",
                         "prompt": f"key {PROBE}"},
    "UserPromptExpansion": {"hook_event_name": "UserPromptExpansion", "session_id": "s",
                            "expansion_type": "slash_command", "command_name": "deploy",
                            "command_args": f"key {PROBE}", "prompt": f"/deploy key {PROBE}"},
    "PreToolUse": {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
                   "tool_input": {"command": f"echo {PROBE}"}},
    "SessionEnd": {"hook_event_name": "SessionEnd", "session_id": "s", "reason": "exit"},
}
# A run that hangs is stopped here, so a failure costs this long and no more.
STOP_S = 15


def _fragment_argv(name: str, hook: dict, policy: str) -> list[str]:
    """The fragment's argv with only the interpreter and policy paths
    pointed at this checkout's venv and a test policy."""
    python, shipped = PATHS[name]
    argv = [hook["command"], *hook["args"]]
    assert argv.count(python) == 1 and argv.count(shipped) == 1
    return [sys.executable if a == python else policy if a == shipped else a for a in argv]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a FIFO")
@pytest.mark.parametrize("event", sorted(PAYLOADS))
@pytest.mark.parametrize("name", sorted(FRAGMENTS))
def test_the_fragment_command_is_not_hung_by_an_openssl_conf_fifo(tmp_path, name, event):
    """The Windows command has no `env -i`, so it runs here under the
    import-time scrub alone."""
    assert set(PAYLOADS) == set(_load(name)["hooks"])
    [entry] = _load(name)["hooks"][event]
    [hook] = entry["hooks"]
    policy = tmp_path / "policy.yaml"
    policy.write_text(yaml.safe_dump({
        "detectors": {"gitleaks": {"enabled": False}},
        "hook": {"ship_mode": "off", "spool": str(tmp_path / "state" / "spool")}}))
    fifo = tmp_path / "openssl.cnf"
    os.mkfifo(fifo)
    env = {**os.environ, "OPENSSL_CONF": str(fifo)}
    budget = min(hook["timeout"], STOP_S)
    started = time.monotonic()
    try:
        done = subprocess.run(_fragment_argv(name, hook, str(policy)),
                              input=json.dumps(PAYLOADS[event]), capture_output=True,
                              text=True, env=env, timeout=budget)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{name} {event}: the fragment's command hung on OPENSSL_CONF={fifo}")
    assert time.monotonic() - started < budget
    assert done.returncode == 0, done.stderr
    assert PROBE not in done.stdout + done.stderr
    if event != "SessionEnd":
        assert '"block"' in done.stdout or '"deny"' in done.stdout, done.stdout
