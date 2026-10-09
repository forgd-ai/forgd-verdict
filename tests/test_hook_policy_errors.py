"""The hook when its policy is found but will not load, and when there is
no policy at all."""

import io
import json
import sys

import pytest
from conftest import FAKE_AWS_KEY, UNPARSEABLE_DEPTH, max_json_depth, nested_json

from forgd_verdict.hook import cli as hook_cli
from forgd_verdict.hook.cli import EXIT_ERROR

FAKE_SECRET = "sk-ant-api03-" + "Zq7Rk2Vm9Xw4Lp8Ny3Bt6Hc1Jd5Fg0Ss"  # gitleaks:allow


def _prompt(text):
    return {"hook_event_name": "UserPromptSubmit", "session_id": "s",
            "prompt_id": "550e8400-e29b-41d4-a716-446655440000", "prompt": text}


def _main(monkeypatch, argv, payload):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    return hook_cli.main(argv)


def _contract(out: str) -> dict:
    """stdout is one JSON object starting with `{` and ending with `}`."""
    assert out.startswith("{") and out.endswith("}"), repr(out)
    return json.loads(out)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("FORGD_VERDICT_POLICY", "FORGD_VERDICT_MODE", "FORGD_VERDICT_BUDGET_MS"):
        monkeypatch.delenv(name, raising=False)


# -- found, but it will not load -------------------------------------------


def _broken(tmp_path, on_error):
    """A mapping that parse_allow refuses, so load_policy raises."""
    path = tmp_path / "policy.yaml"
    hook = f"hook:\n  on_error: {on_error}\n" if on_error else ""
    path.write_text(hook + "plugins: not-a-mapping\n")
    return path


def test_found_but_broken_with_on_error_block_blocks(tmp_path, monkeypatch, capsys):
    path = _broken(tmp_path, "block")
    assert _main(monkeypatch, ["--policy", str(path)], _prompt("hello")) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"could not load policy {path}" in captured.err


def test_found_but_broken_with_on_error_allow_is_a_non_blocking_error(
        tmp_path, monkeypatch, capsys):
    path = _broken(tmp_path, "allow")
    assert _main(monkeypatch, ["--policy", str(path)], _prompt("hello")) == EXIT_ERROR
    assert capsys.readouterr().out == ""


def test_found_but_broken_without_on_error_uses_the_default(tmp_path, monkeypatch):
    path = _broken(tmp_path, None)
    assert _main(monkeypatch, ["--policy", str(path)], _prompt("hello")) == EXIT_ERROR


def test_an_unparseable_file_falls_back_to_the_default_allow(tmp_path, monkeypatch, capsys):
    path = tmp_path / "policy.yaml"
    path.write_text("hook:\n  on_error: block\n  budget_ms: [unclosed\n")
    assert _main(monkeypatch, ["--policy", str(path)], _prompt("hello")) == EXIT_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"could not load policy {path}" in captured.err


def test_an_unparseable_line_is_never_quoted(tmp_path, monkeypatch, capsys):
    path = tmp_path / "policy.yaml"
    path.write_text(f'privacy:\n  hash_salt: "{FAKE_SECRET}\nhook:\n  on_error: block\n')
    _main(monkeypatch, ["--policy", str(path)], _prompt("hello"))
    captured = capsys.readouterr()
    assert FAKE_SECRET not in captured.err
    assert FAKE_SECRET not in captured.out
    assert "could not load policy" in captured.err


def test_found_but_broken_never_scans(tmp_path, monkeypatch):
    path = _broken(tmp_path, "allow")
    monkeypatch.setattr(hook_cli, "evaluate", lambda *a: pytest.fail("the hook scanned"))
    _main(monkeypatch, ["--policy", str(path)], _prompt("hello"))


# -- no policy at all ------------------------------------------------------


@pytest.fixture(params=["explicit", "implicit"])
def no_policy(request, tmp_path, monkeypatch):
    """argv for a hook with no policy: a named path that is missing, or
    nothing named and no ./policy.yaml."""
    monkeypatch.chdir(tmp_path)
    if request.param == "explicit":
        missing = tmp_path / "absent.yaml"
        return ["--policy", str(missing)], str(missing)
    return [], "no policy file was given"


def test_no_policy_on_a_clean_prompt_emits_only_a_system_message(no_policy, monkeypatch,
                                                                  capsys):
    argv, named = no_policy
    assert _main(monkeypatch, argv, _prompt("hello")) == 0
    captured = capsys.readouterr()
    body = _contract(captured.out)
    assert list(body) == ["systemMessage"]
    message = body["systemMessage"]
    assert named in message
    assert "built-in defaults" in message
    assert "hook.on_error is allow" in message
    assert "through unscanned" in message
    for line in message.splitlines():
        assert line in captured.err
    assert "permissionDecision" not in captured.out


def test_no_policy_on_a_blocking_prompt_blocks_and_warns(no_policy, monkeypatch, capsys):
    argv, named = no_policy
    monkeypatch.setenv("FORGD_VERDICT_MODE", "enforce")
    assert _main(monkeypatch, argv, _prompt(f"key {FAKE_AWS_KEY}")) == 0
    body = _contract(capsys.readouterr().out)
    assert body["decision"] == "block"
    assert named in body["systemMessage"]
    assert FAKE_AWS_KEY not in json.dumps(body)


def test_no_policy_on_a_tool_call_never_emits_allow(no_policy, monkeypatch, capsys):
    argv, _named = no_policy
    payload = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
               "tool_input": {"command": "ls"}}
    assert _main(monkeypatch, argv, payload) == 0
    out = capsys.readouterr().out
    assert list(_contract(out)) == ["systemMessage"]
    assert "allow" not in json.loads(out).get("hookSpecificOutput", {}).values()


def test_a_policy_that_loads_says_nothing_extra(tmp_path, monkeypatch, capsys):
    path = tmp_path / "policy.yaml"
    path.write_text("hook:\n  on_error: allow\ndetectors:\n  gitleaks:\n    enabled: false\n")
    assert _main(monkeypatch, ["--policy", str(path)], _prompt("hello")) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "built-in defaults" not in captured.err


def test_the_default_policy_states_on_error():
    from forgd_verdict.policy import DEFAULT_POLICY

    assert DEFAULT_POLICY["hook"]["on_error"] == "allow"


# -- a payload that does not parse ---------------------------------------


def _policy_file(tmp_path, on_error):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"hook": {"on_error": on_error, "spool_enabled": False},
                                "detectors": {"gitleaks": {"enabled": False}}}))
    return path


class _BadBytes(io.StringIO):
    def read(self, *a):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")


MALFORMED = {
    "not json": io.StringIO('{"prompt": "hello", '),
    "not an object": io.StringIO(json.dumps(["hello"])),
    "empty": io.StringIO(""),
    "whitespace": io.StringIO("  \n"),
    "not utf-8": _BadBytes(),
    "nested too deeply": io.StringIO("[" * 100_000 + "]" * 100_000),
}


@pytest.mark.parametrize("on_error, code", [("block", 2), ("allow", EXIT_ERROR)])
@pytest.mark.parametrize("shape", sorted(MALFORMED))
def test_a_malformed_payload_runs_under_on_error(shape, on_error, code, tmp_path,
                                                 monkeypatch, capsys):
    stdin = MALFORMED[shape]
    stdin.seek(0)
    monkeypatch.setattr(sys, "stdin", stdin)
    path = _policy_file(tmp_path, on_error)
    assert hook_cli.main(["--policy", str(path)]) == code
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "could not parse hook payload" in captured.err
    assert FAKE_SECRET not in captured.err


_PROMPT_WITH_SECRET = json.dumps(_prompt(f"key {FAKE_AWS_KEY}"))

MALFORMED_WITH_SECRET = {
    "not json": '{"prompt": "' + FAKE_SECRET + '", ',
    "not an object": json.dumps([FAKE_SECRET]),
    "nested too deeply": nested_json(_PROMPT_WITH_SECRET, UNPARSEABLE_DEPTH),
}


@pytest.mark.parametrize("on_error", ["block", "allow"])
@pytest.mark.parametrize("shape", sorted(MALFORMED_WITH_SECRET))
def test_a_malformed_payload_carrying_a_secret_blocks(shape, on_error, tmp_path,
                                                      monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(MALFORMED_WITH_SECRET[shape]))
    path = _policy_file(tmp_path, on_error)
    assert hook_cli.main(["--policy", str(path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "could not parse hook payload" in captured.err
    for value in (FAKE_SECRET, FAKE_AWS_KEY):
        assert value not in captured.err


@pytest.mark.parametrize("on_error", ["block", "allow"])
def test_a_payload_holding_an_integer_over_the_digit_limit_is_scanned(on_error, tmp_path,
                                                                     monkeypatch, capsys):
    path = _policy_file(tmp_path, on_error)
    clean = json.dumps(_prompt("hello"))[:-1] + ', "n": ' + "1" * 5000 + "}"
    monkeypatch.setattr(sys, "stdin", io.StringIO(clean))
    assert hook_cli.main(["--policy", str(path)]) == 0
    assert capsys.readouterr().out == ""
    secret = _PROMPT_WITH_SECRET[:-1] + ', "n": ' + "1" * 5000 + "}"
    monkeypatch.setattr(sys, "stdin", io.StringIO(secret))
    code = hook_cli.main(["--policy", str(path)])
    captured = capsys.readouterr()
    assert "could not parse" not in captured.err
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["decision"] == "block"
    assert "AWS access key" in payload["reason"]
    assert FAKE_AWS_KEY not in captured.out + captured.err


def _deep_tool_call(depth):
    inner = json.dumps(f"key {FAKE_AWS_KEY}")
    return ('{"hook_event_name": "PreToolUse", "session_id": "s", '
            '"tool_name": "mcp__x__run", "tool_input": {"q": '
            + nested_json(inner, depth) + "}}")


@pytest.mark.parametrize("margin", [None, 20])
def test_a_secret_at_the_bottom_of_a_parseable_nesting_blocks(margin, tmp_path,
                                                              monkeypatch, capsys):
    depth = 900 if margin is None else max_json_depth() - margin
    monkeypatch.setattr(sys, "stdin", io.StringIO(_deep_tool_call(depth)))
    path = _policy_file(tmp_path, "allow")
    code = hook_cli.main(["--policy", str(path)])
    captured = capsys.readouterr()
    assert FAKE_AWS_KEY not in captured.out + captured.err
    if code == 0:
        body = _contract(captured.out)
        assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    else:
        assert code == 2, captured.err


# -- a scan that raises --------------------------------------------------


@pytest.mark.parametrize("on_error, code", [("block", 2), ("allow", EXIT_ERROR)])
def test_a_failed_scan_names_only_the_exception_type(on_error, code, tmp_path,
                                                     monkeypatch, capsys):
    """Under exit 2, stderr goes back to the user and the model, and a
    detector's exception text can carry what it matched."""
    from forgd_verdict.policy import Policy

    class DetectorBroke(RuntimeError):
        pass

    class Raising:
        name = "raising"
        tier = 0
        severity = "block"

        def scan(self, units):
            raise DetectorBroke(f"could not handle {FAKE_SECRET} near {FAKE_AWS_KEY}")

    monkeypatch.setattr(Policy, "build_detectors", lambda self, **kw: [Raising()])
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(_prompt("hello"))))
    path = _policy_file(tmp_path, on_error)
    assert hook_cli.main(["--policy", str(path)]) == code
    err = capsys.readouterr().err
    assert "scan failed: DetectorBroke" in err
    assert FAKE_SECRET not in err and FAKE_AWS_KEY not in err


# -- an environment variable the hook does not read ----------------------


NOT_HOOK_ENV = {
    "FORGD_VERDICT_BUDGET_MS": "abc",
    "FORGD_DASHBOARD_ISSUERS": "notjson",
    "FORGD_CONNECTOR_SCOPES": "notjson",
    "FORGD_DASHBOARD_AUTH_MODE": "bogus",
}


def _enforcing_file(tmp_path, project_overrides=False):
    path = tmp_path / "policy.yaml"
    path.write_text("hook:\n  on_error: allow\n  spool_enabled: false\n"
                    f"  project_overrides: {str(project_overrides).lower()}\n")
    return path


def _assert_blocked(code, captured):
    assert code == 0, captured.err
    body = _contract(captured.out)
    assert body["decision"] == "block"
    assert FAKE_AWS_KEY not in captured.out + captured.err


@pytest.mark.parametrize("name", sorted(NOT_HOOK_ENV))
def test_a_bad_value_outside_hook_still_blocks_with_a_policy_file(
        name, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(name, NOT_HOOK_ENV[name])
    path = _enforcing_file(tmp_path)
    code = _main(monkeypatch, ["--policy", str(path)], _prompt(f"key {FAKE_AWS_KEY}"))
    _assert_blocked(code, capsys.readouterr())


@pytest.mark.parametrize("name", sorted(NOT_HOOK_ENV))
def test_a_bad_value_outside_hook_still_blocks_with_no_policy(
        name, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(name, NOT_HOOK_ENV[name])
    code = _main(monkeypatch, [], _prompt(f"key {FAKE_AWS_KEY}"))
    _assert_blocked(code, capsys.readouterr())


def test_a_bad_hook_value_is_skipped_with_a_warning_that_omits_it(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FORGD_VERDICT_SCAN_TIMEOUT_MS", "abc-not-a-number")
    path = _enforcing_file(tmp_path, project_overrides=True)
    code = _main(monkeypatch, ["--policy", str(path)], _prompt(f"key {FAKE_AWS_KEY}"))
    captured = capsys.readouterr()
    _assert_blocked(code, captured)
    assert "FORGD_VERDICT_SCAN_TIMEOUT_MS" in captured.err
    assert "abc-not-a-number" not in captured.err


UNCOERCIBLE_ENV = ["FORGD_CONNECTOR_SCOPES", "FORGD_DASHBOARD_ISSUERS",
                   "FORGD_VERDICT_BUDGET_MS", "FORGD_VERDICT_SCAN_TIMEOUT_MS"]


@pytest.mark.parametrize("name", UNCOERCIBLE_ENV)
def test_every_other_caller_still_refuses_a_bad_value(name, tmp_path, monkeypatch):
    from forgd_verdict.policy import default_policy, load_policy

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(name, "abc")
    with pytest.raises(ValueError, match=name):
        load_policy(_enforcing_file(tmp_path, project_overrides=True))
    if name != "FORGD_VERDICT_SCAN_TIMEOUT_MS":
        with pytest.raises(ValueError, match=name):
            default_policy()
