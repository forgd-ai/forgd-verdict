"""`hook.expansions`: allowing or denying a `UserPromptExpansion` by the
command it names, before any scan."""

from __future__ import annotations

import json
import logging

import pytest
from conftest import FAKE_AWS_KEY, make_policy

from forgd_verdict.hook.cli import run
from forgd_verdict.policy import load_policy

MARKER = "ZQX-distinctive-7731"


def expansion(command_name="deploy", command_args="", *, prompt=None,
              command_source="project", expansion_type="slash_command") -> dict:
    return {
        "session_id": "abc123",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": "/repo",
        "permission_mode": "default",
        "hook_event_name": "UserPromptExpansion",
        "expansion_type": expansion_type,
        "command_name": command_name,
        "command_args": command_args,
        "command_source": command_source,
        "prompt": prompt if prompt is not None else f"/{command_name} {command_args}",
    }


def policy_with(expansions: dict, **hook):
    return make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        hook={"spool_enabled": False, "expansions": expansions, **hook},
    )


def _reason(out: str) -> str:
    return json.loads(out)["reason"]


def test_the_default_allows_every_expansion():
    code, out = run(expansion(), policy_with({}))
    assert (code, out) == (0, "")


def test_deny_by_command_source():
    policy = policy_with({"deny": [{"command_source": "plugin"}]})
    code, out = run(expansion(command_source="plugin"), policy)
    assert code == 0
    assert _reason(out) == ("forgd-verdict: /deploy is not permitted by policy "
                            "(expansion control)")
    assert run(expansion(command_source="project"), policy) == (0, "")


def test_deny_by_command_name():
    policy = policy_with({"deny": [{"command_name": "deploy"}]})
    assert "/deploy is not permitted" in _reason(run(expansion("deploy"), policy)[1])
    assert run(expansion("review"), policy) == (0, "")


def test_a_rule_matches_only_when_every_key_it_sets_matches():
    policy = policy_with({"deny": [{"command_name": "deploy",
                                    "expansion_type": "mcp_prompt"}]})
    assert run(expansion("deploy"), policy) == (0, "")
    out = run(expansion("deploy", expansion_type="mcp_prompt"), policy)[1]
    assert "expansion control" in _reason(out)


def test_deny_wins_over_allow():
    policy = policy_with({"allow": [{"command_name": "deploy"}],
                          "deny": [{"command_source": "plugin"}]})
    out = run(expansion("deploy", command_source="plugin"), policy)[1]
    assert "expansion control" in _reason(out)


def test_default_deny_passes_an_allowlisted_command_and_still_scans_it():
    policy = policy_with({"default": "deny", "allow": [{"command_name": "deploy"}]})
    assert "expansion control" in _reason(run(expansion("review"), policy)[1])
    assert run(expansion("deploy", "to staging"), policy) == (0, "")

    code, out = run(expansion("deploy", f"prod {FAKE_AWS_KEY}"), policy)
    assert code == 0
    reason = _reason(out)
    assert "expansion control" not in reason
    assert FAKE_AWS_KEY not in out


def test_a_prompt_submit_is_unaffected():
    policy = policy_with({"default": "deny"})
    payload = {"session_id": "abc123", "hook_event_name": "UserPromptSubmit",
               "prompt": "/deploy now"}
    assert run(payload, policy) == (0, "")


def test_a_blocked_expansion_carries_no_content(tmp_path):
    spool = tmp_path / "spool"
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        hook={"spool": str(spool), "expansions": {"deny": [{"command_name": "deploy"}]}},
    )
    payload = expansion("deploy", f"args {MARKER}", prompt=f"/deploy {MARKER}")
    code, out = run(payload, policy)
    assert code == 0
    assert "expansion control" in _reason(out)
    assert MARKER not in out

    written = [p.read_bytes() for p in spool.rglob("*") if p.is_file()]
    assert written, "the deny was not spooled"
    assert not any(MARKER.encode() in body for body in written)


def test_a_blocked_expansion_blocks_without_calling_remote(monkeypatch):
    from forgd_verdict.hook import cli

    def remote(*_a, **_k):
        raise AssertionError("remote called for a blocked expansion")

    monkeypatch.setattr(cli, "_remote_verdict", remote)
    policy = policy_with({"deny": [{"command_name": "deploy"}]},
                         scan_endpoint="https://scan.example/scan")
    assert "expansion control" in _reason(run(expansion("deploy"), policy)[1])


# -- validation at load ---------------------------------------------------


def _load(tmp_path, expansions):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"hook": {"expansions": expansions}}))
    return load_policy(path)


def test_the_shipped_policy_loads_with_the_default_allow():
    assert load_policy("policy.yaml").hook["expansions"]["default"] == "allow"


@pytest.mark.parametrize("expansions, match", [
    ({"defualt": "deny"}, "defualt"),
    ({"default": "block"}, "default"),
    ({"deny": [{}]}, "at least one"),
    ({"deny": [{"command": "deploy"}]}, "command"),
    ({"allow": [{"expansion_type": "skill"}]}, "expansion_type"),
    ({"deny": [{"command_name": 7}]}, "string"),
    ({"deny": [{"command_name": ["deploy"]}]}, "string"),
    ({"deny": {"command_name": "deploy"}}, "list"),
    ({"allow": ["deploy"]}, "mapping"),
    ("deny", "mapping"),
])
def test_an_invalid_expansion_config_is_refused(tmp_path, expansions, match):
    with pytest.raises(ValueError, match=match):
        _load(tmp_path, expansions)


# -- not reachable from the environment or a project -----------------------


def test_no_override_path_reaches_expansions():
    from forgd_verdict.overrides import ALLOWLIST
    from forgd_verdict.policy import ENV_OVERRIDES

    paths = [p for p, _c in ENV_OVERRIDES.values()] + [p for p, _c in ALLOWLIST.values()]
    assert not [p for p in paths if "expansions" in p or p == ("hook",)]


def test_a_project_override_cannot_loosen_expansions(tmp_path, monkeypatch):
    from forgd_verdict.policy import ENV_OVERRIDES, PROJECT_OVERRIDE_ENV

    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"hook": {
        "project_overrides": True,
        "expansions": {"default": "deny", "allow": [{"command_name": "review"}]},
    }}))
    for name, (_path, caster) in ENV_OVERRIDES.items():
        if name in PROJECT_OVERRIDE_ENV or _path[0] == "hook":
            monkeypatch.setenv(name, "1" if caster is int else "off")
    policy = load_policy(path, for_hook=True)
    assert policy.hook["expansions"] == {
        "default": "deny", "deny": [], "allow": [{"command_name": "review"}]}
    policy.hook["spool_enabled"] = False
    assert "expansion control" in _reason(run(expansion("deploy"), policy)[1])


# -- expansions set while the event is off ---------------------------------


def _load_hook(tmp_path, hook: dict):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"hook": hook}))
    return load_policy(path)


def _unread(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records
            if r.name == "forgd_verdict.policy" and "UserPromptExpansion" in r.getMessage()]


def test_expansions_with_the_event_off_warn_at_load(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.policy"):
        _load_hook(tmp_path, {"enabled_events": ["UserPromptSubmit", "PreToolUse"],
                              "expansions": {"default": "deny"}})
    assert len(_unread(caplog)) == 1


@pytest.mark.parametrize("hook", [
    {"enabled_events": ["UserPromptSubmit", "UserPromptExpansion"],
     "expansions": {"default": "deny"}},
    # The built-in `expansions` is not the customer's setting.
    {"enabled_events": ["UserPromptSubmit", "PreToolUse"]},
    {},
])
def test_expansions_do_not_warn_otherwise(tmp_path, caplog, hook):
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.policy"):
        _load_hook(tmp_path, hook)
    assert _unread(caplog) == []
