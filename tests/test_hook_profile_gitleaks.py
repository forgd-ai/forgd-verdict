"""The hook runs gitleaks as its own profile, `hook.detectors.gitleaks`,
configures it.

deploy/MDM.md has a laptop set the binary there. The local hook built its
detectors from the top-level section only, so a `binary` under `hook:` was
never seen: the hook said the binary was not set and dropped T1.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
import yaml

from forgd_verdict.hook import cli
from forgd_verdict.policy import load_policy

REPO = Path(__file__).resolve().parents[1]
PROMPT = {"session_id": "abc123", "hook_event_name": "UserPromptSubmit",
          "prompt": "please summarise the release notes"}


def _stub(tmp_path: Path) -> tuple[str, Path]:
    """An absolute gitleaks that reports one finding and leaves a marker."""
    marker = tmp_path / "gitleaks-ran"
    path = tmp_path / "opt" / "gitleaks"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "#!/bin/sh\ncat >/dev/null\n"
        f"touch '{marker}'\n"
        "printf '[{\"StartLine\": 1, \"RuleID\": \"stub-rule\", \"Secret\": \"s\"}]'\n",
        encoding="utf-8")
    path.chmod(0o755)
    return str(path), marker


def _write(tmp_path: Path, data: dict) -> str:
    data.setdefault("hook", {}).setdefault("spool", str(tmp_path / "state" / "spool"))
    data["hook"].setdefault("ship_mode", "off")
    path = tmp_path / "etc" / "policy.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


def _main(policy: str, monkeypatch, capsys) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(PROMPT)))
    code = cli.main(["--policy", policy])
    out = capsys.readouterr()
    return code, out.out, out.err


def _ran_t1(code: int, out: str, err: str) -> None:
    assert code == 0, err
    assert json.loads(out)["decision"] == "block", out
    assert "did not run" not in out + err


def test_a_binary_set_only_in_the_hook_profile_runs(tmp_path, monkeypatch, capsys):
    binary, marker = _stub(tmp_path)
    policy = _write(tmp_path, {"hook": {"detectors": {"gitleaks": {"binary": binary}}}})
    _ran_t1(*_main(policy, monkeypatch, capsys))
    assert marker.exists()


@pytest.mark.parametrize("binary", ["gitleaks", "./bin/gitleaks", "$GITLEAKS"])
def test_a_hook_profile_binary_that_is_not_absolute_is_refused(
        tmp_path, monkeypatch, capsys, binary):
    """Through `evaluate`, with the value set after `load_policy`, which
    anchors a relative path to the policy's directory."""
    stub, marker = _stub(tmp_path)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "gitleaks").write_bytes(Path(stub).read_bytes())
    (tmp_path / "bin" / "gitleaks").chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    monkeypatch.setenv("GITLEAKS", stub)
    policy = load_policy(_write(tmp_path, {
        "hook": {"on_error": "allow",
                 "detectors": {"gitleaks": {"binary": binary}}}}), for_hook=True)
    policy.raw["hook"]["detectors"]["gitleaks"]["binary"] = binary
    code, out = cli.run(PROMPT, policy)
    err = capsys.readouterr().err
    assert not marker.exists()
    message = json.loads(out)["systemMessage"]
    assert "gitleaks (T1) did not run" in message
    assert "hook.detectors.gitleaks.binary is not an absolute path" in message
    assert message in err


def test_a_bare_hook_profile_binary_is_refused_through_main(tmp_path, monkeypatch, capsys):
    stub, marker = _stub(tmp_path)
    monkeypatch.setenv("PATH", str(Path(stub).parent))
    policy = _write(tmp_path, {"hook": {"on_error": "block",
                                        "detectors": {"gitleaks": {"binary": "gitleaks"}}}})
    code, out, err = _main(policy, monkeypatch, capsys)
    assert not marker.exists()
    assert json.loads(out)["decision"] == "block"
    assert "could not be checked" in json.loads(out)["reason"]
    assert "hook.detectors.gitleaks.binary is not an absolute path" in err


def test_the_hook_profile_turns_gitleaks_off(tmp_path, monkeypatch, capsys):
    binary, marker = _stub(tmp_path)
    policy = _write(tmp_path, {
        "detectors": {"gitleaks": {"enabled": True, "binary": binary}},
        "hook": {"on_error": "block", "detectors": {"gitleaks": {"enabled": False}}}})
    code, out, err = _main(policy, monkeypatch, capsys)
    assert not marker.exists()
    assert code == 0 and out == "", (out, err)
    assert "did not run" not in err


def test_an_unset_binary_names_both_places_it_can_be_set(tmp_path, monkeypatch, capsys):
    policy = _write(tmp_path, {"hook": {"on_error": "allow"}})
    code, out, err = _main(policy, monkeypatch, capsys)
    message = json.loads(out)["systemMessage"]
    assert "detectors.gitleaks.binary is not set" in message
    assert "hook.detectors.gitleaks.binary" in message


@pytest.mark.parametrize("name", ["policy.yaml", "examples/policy/enforce.yaml"])
def test_the_shipped_policy_runs_t1_from_the_hook_profile_binary(
        tmp_path, monkeypatch, capsys, name):
    """A laptop following deploy/MDM.md: the shipped policy with its
    hook-profile `binary` installed, and no FORGD_GITLEAKS_SOCKET."""
    monkeypatch.delenv("FORGD_GITLEAKS_SOCKET", raising=False)
    data = yaml.safe_load((REPO / name).read_text(encoding="utf-8"))
    hook_gitleaks = data["hook"]["detectors"]["gitleaks"]
    assert hook_gitleaks["binary"] == "/opt/forgd/bin/gitleaks"
    binary, marker = _stub(tmp_path)
    hook_gitleaks["binary"] = binary
    data["hook"].pop("ship_endpoint", None)
    data["hook"].pop("scan_endpoint", None)
    data["hook"]["spool"] = str(tmp_path / "state" / "spool")
    _ran_t1(*_main(_write(tmp_path, data), monkeypatch, capsys))
    assert marker.exists()


def test_the_top_level_example_binary_is_admin_owned():
    text = (REPO / "policy.yaml").read_text(encoding="utf-8")
    assert "# binary: /usr/local/bin/gitleaks" not in text
    assert "# binary: /opt/forgd/bin/gitleaks" in text
