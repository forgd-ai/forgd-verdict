"""Relative gitleaks paths at load, unset `$VAR` secrets on the Policy tab,
and the fleet token's place in the secrets list."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from forgd_verdict.policy import (
    SECRET_LIST_PATHS,
    SECRET_PATHS,
    Policy,
    load_policy,
    redacted,
)

REPO = Path(__file__).resolve().parent.parent

# -- relative gitleaks paths ----------------------------------------------


def _write_policy(tmp_path: Path, section: dict) -> Path:
    path = tmp_path / "conf" / "policy.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump({"privacy": {"allow_unsalted": True}, **section}))
    return path


@pytest.mark.parametrize("where", ["detectors", "hook"])
@pytest.mark.parametrize("key,value", [("config", "./gitleaks.toml"),
                                       ("binary", "bin/gitleaks")])
def test_a_relative_gitleaks_path_is_anchored_or_refused_at_load(
        tmp_path, monkeypatch, where, key, value):
    gitleaks = {"gitleaks": {"enabled": False, key: value}}
    section = ({"detectors": gitleaks} if where == "detectors"
               else {"hook": {"detectors": gitleaks}})
    path = _write_policy(tmp_path, section)
    elsewhere = tmp_path / "cwd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)

    try:
        policy = load_policy(path)
    except ValueError as exc:
        assert key in str(exc)
        return
    node = policy.raw["detectors"] if where == "detectors" \
        else policy.raw["hook"]["detectors"]
    got = node["gitleaks"][key]
    assert os.path.isabs(got), got
    assert Path(got) == (path.parent / value).resolve() or \
        Path(got) == path.parent.absolute() / value


def gitleaks_config_examples(text: str) -> list[str]:
    """Each `config:` naming a gitleaks file, commented out or not."""
    out = []
    for line in text.splitlines():
        stripped = line.strip().lstrip("#").strip()
        if stripped.startswith("config:") and "gitleaks" in stripped:
            out.append(stripped.split(":", 1)[1].strip())
    return out


def test_the_shipped_gitleaks_config_example_is_absolute():
    examples = gitleaks_config_examples((REPO / "policy.yaml").read_text())
    assert examples
    assert all(os.path.isabs(e) for e in examples), examples


# -- unset secrets --------------------------------------------------------


def _policy(raw: dict) -> Policy:
    return Policy(raw={"privacy": {"allow_unsalted": True}, **raw})


def test_an_unresolved_secret_reference_says_it_is_unset(monkeypatch):
    monkeypatch.delenv("FORGD_METRICS_TOKEN_UNSET", raising=False)
    monkeypatch.delenv("FORGD_INTAKE_TOKEN_UNSET", raising=False)
    shown = redacted(_policy({
        "server": {"metrics_token": "$FORGD_METRICS_TOKEN_UNSET"},
        "intake": {"clients": [{"name": "alice", "token": "$FORGD_INTAKE_TOKEN_UNSET"}]},
    }))
    assert shown["server"]["metrics_token"] == "<unset: $FORGD_METRICS_TOKEN_UNSET empty>"
    assert shown["intake"]["clients"][0]["token"] == \
        "<unset: $FORGD_INTAKE_TOKEN_UNSET empty>"


def test_a_resolved_secret_reference_is_still_redacted(monkeypatch):
    monkeypatch.setenv("FORGD_METRICS_TOKEN_SET", "metrics-0123456789abcdef0123")
    shown = redacted(_policy({"server": {"metrics_token": "$FORGD_METRICS_TOKEN_SET"}}))
    assert shown["server"]["metrics_token"] == "<redacted>"


def test_the_dashboard_salt_wording_is_unchanged(monkeypatch):
    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    shown = redacted(Policy(raw={"privacy": {"hash_salt": "$FORGD_HASH_SALT"}}),
                     hashes_here=False)
    assert shown["privacy"]["hash_salt"] == \
        "<not shown here: this service is not given the salt>"


# -- the fleet token ------------------------------------------------------


def test_the_fleet_tokens_are_in_the_secrets_list():
    assert ((("intake", "fleet"), "tokens") in SECRET_LIST_PATHS
            or ("intake", "fleet", "tokens") in SECRET_PATHS)


def test_a_literal_fleet_token_never_reaches_the_policy_tab():
    token = "fleet-token-literal-0123456789abcdef"
    shown = redacted(_policy({"intake": {"fleet": [
        {"name": "corp-laptops", "tokens": [token], "org": "$FORGD_ORG_ID_PROD"}]}}))
    assert token not in yaml.safe_dump(shown)


@pytest.mark.parametrize("how", ["inline-env", "inline-gz-env", "policy-dir"])
def test_a_relative_gitleaks_path_in_an_inline_policy_is_refused(tmp_path, monkeypatch, how):
    path = _write_policy(tmp_path, {"detectors": {"gitleaks": {
        "enabled": False, "config": "./gitleaks.toml"}}})
    for name in ("FORGD_POLICY_INLINE", "FORGD_POLICY_INLINE_GZ", "FORGD_POLICY_DIR"):
        monkeypatch.delenv(name, raising=False)
    if how == "inline-env":
        monkeypatch.setenv("FORGD_POLICY_INLINE", "x")
    elif how == "inline-gz-env":
        monkeypatch.setenv("FORGD_POLICY_INLINE_GZ", "x")
    else:
        monkeypatch.setenv("FORGD_POLICY_DIR", str(path.parent))
    with pytest.raises(ValueError, match=r"gitleaks\.config.*relative path.*inline"):
        load_policy(path)


def test_an_absolute_gitleaks_path_in_an_inline_policy_loads(tmp_path, monkeypatch):
    path = _write_policy(tmp_path, {"detectors": {"gitleaks": {
        "enabled": False, "config": "/opt/forgd/etc/gitleaks.toml", "binary": "gitleaks"}}})
    monkeypatch.setenv("FORGD_POLICY_INLINE_GZ", "x")
    policy = load_policy(path)
    assert policy.raw["detectors"]["gitleaks"]["config"] == "/opt/forgd/etc/gitleaks.toml"


def test_a_literal_org_id_in_an_otel_ids_list_never_reaches_the_policy_tab():
    literal = "00000000-0000-0000-0000-00000000000a"
    shown = redacted(_policy({"otel": {"orgs": [
        {"label": "laptops", "ids": [literal, "$FORGD_ORG_ID_DEV"],
         "token": "$FORGD_OTEL_TOKEN_FLEET"}]}}))
    assert literal not in yaml.safe_dump(shown)
    assert shown["otel"]["orgs"][0]["ids"][1] == "$FORGD_ORG_ID_DEV"
