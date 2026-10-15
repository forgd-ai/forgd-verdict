"""`forgd-verdict policy --check` against the roles it stands in for.

Each case is a class of policy a role refuses at start. The case passes
only when the role, started the way its entry point starts it, refuses,
AND the check exits 2 naming that role. A check that drifts from the
roles fails here in the direction that matters: a policy the roles refuse
and the check accepts.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from forgd_verdict import policycheck
from forgd_verdict.policy import load_policy

ROOT = Path(__file__).resolve().parent.parent
ORG = "00000000-0000-4000-8000-000000000001"
ENV = {
    "FORGD_ORG_ID_PRIMARY": ORG,
    "FORGD_OTEL_TOKEN_PRIMARY": "otel-" + "x7Kq2mNp9wRt4vZs8bLcQ3jH",
    "FORGD_INTAKE_FLEET_TOKEN": "fleet-" + "a8Lr3nOq0xSu5wAt9cMdR4kJ",
}


def base(tmp: Path) -> dict:
    return {
        "privacy": {"hash_salt": "salt-" + "p9Vb2nXq7rTz4mKw8cLs3jHd"},
        "detectors": {"gitleaks": {"enabled": False}},
        "server": {"mode": "observe", "store": str(tmp / "server-store"),
                   "csv_path": str(tmp / "timings.csv")},
        "otel": {"orgs": [{"label": "primary", "id": "$FORGD_ORG_ID_PRIMARY",
                           "token": "$FORGD_OTEL_TOKEN_PRIMARY"}]},
        "intake": {"fleet": [{"name": "laptops", "tokens": ["$FORGD_INTAKE_FLEET_TOKEN"],
                              "org": "$FORGD_ORG_ID_PRIMARY"}]},
    }


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    # Set first, so teardown removes what `serve` and the dashboard set.
    monkeypatch.setenv("FORGD_VERDICT_POLICY", "")
    monkeypatch.delenv("FORGD_VERDICT_POLICY")
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    return monkeypatch


def write(tmp: Path, policy: dict) -> Path:
    path = tmp / "policy.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    return path


# -- how each role starts --------------------------------------------------


def start_server(path: Path, tmp: Path) -> None:
    """`serve`'s pre-checks, with uvicorn stubbed, then the app uvicorn builds."""
    import uvicorn

    from forgd_verdict.server.__main__ import main
    from forgd_verdict.server.app import VerdictServer

    real, uvicorn.run = uvicorn.run, lambda *a, **k: None
    try:
        if main(["--policy", str(path)]) != 0:
            raise SystemExit("serve refused")
    finally:
        uvicorn.run = real
    VerdictServer(load_policy(str(path))).close()


def start_collector(path: Path, tmp: Path) -> None:
    from forgd_verdict.otel.app import Collector

    Collector(load_policy(str(path))).close()


def start_intake(path: Path, tmp: Path) -> None:
    from forgd_verdict.intake.app import Intake

    Intake(load_policy(str(path))).close()


def start_dashboard(path: Path, tmp: Path) -> None:
    import os

    from forgd_verdict.dashboard.app import create_app

    os.environ["FORGD_VERDICT_POLICY"] = str(path)
    try:
        create_app(str(tmp / "dashboard-store"))
    finally:
        del os.environ["FORGD_VERDICT_POLICY"]


def start_connector(path: Path, tmp: Path) -> None:
    from forgd_verdict.connector.__main__ import main

    if main(["--policy", str(path)]) != 0:
        raise SystemExit("connector refused")


def start_compliance(path: Path, tmp: Path) -> None:
    policy = load_policy(str(path))
    policy.refuse_unsalted("compliance scanner")
    policy.compliance_orgs()


START: dict[str, Callable[[Path, Path], None]] = {
    "server": start_server, "collector": start_collector, "intake": start_intake,
    "dashboard": start_dashboard, "connector": start_connector,
    "compliance": start_compliance,
}


def _set(path: str, value):
    def edit(p: dict) -> None:
        *parents, leaf = path.split(".")
        node = p
        for key in parents:
            node = node.setdefault(key, {})
        node[leaf] = value
    return edit


CASES = [
    ("an unset org id behind a set token", lambda p: None,
     {"FORGD_ORG_ID_PRIMARY": None}, {"collector", "intake"}),
    ("a detector severity that does not exist", _set("detectors.entropy",
                                                     {"enabled": True, "severity": "loud"}),
     {}, {"server", "collector"}),
    ("an enabled detector that is not one", _set("detectors.made_up", {"enabled": True}),
     {}, {"server", "collector"}),
    ("no hash salt", _set("privacy.hash_salt", ""), {}, {"server", "collector", "intake"}),
    ("a store URL carrying a user", _set("server.store",
                                         "https://someone@acct.blob.core.windows.net/findings"),
     {}, {"server", "collector", "intake"}),
    ("a metrics token too short to be one", _set("server.metrics_token", "short"),
     {}, {"server", "collector", "intake"}),
    ("a limit_concurrency of zero", _set("server.limit_concurrency", 0), {}, {"server"}),
    ("a weak otel token", lambda p: None, {"FORGD_OTEL_TOKEN_PRIMARY": "short"}, {"collector"}),
    ("a sink with an endpoint and an unset token",
     _set("sinks", [{"name": "s", "type": "otlp", "endpoint": "https://otlp.example/v1/logs",
                     "token": "$FORGD_TEST_SINK_TOKEN"}]),
     {"FORGD_TEST_SINK_TOKEN": None}, {"collector"}),
    ("an intake tally interval of zero", _set("intake.tally_flush_s", 0), {}, {"intake"}),
    ("oidc_jwt dashboard auth without an audience",
     _set("dashboard.auth", {"mode": "oidc_jwt", "issuer": "https://issuer.example/v2.0",
                             "jwks_url": "https://issuer.example/keys"}),
     {}, {"dashboard"}),
    ("an enabled connector with no auth", _set("connector", {"enabled": True}),
     {}, {"connector"}),
    ("a compliance key whose org id is unset",
     _set("compliance.orgs", [{"id": "$FORGD_ORG_ID_UNSET", "api_key": "$FORGD_TEST_CAK"}]),
     {"FORGD_ORG_ID_UNSET": None, "FORGD_TEST_CAK": "cak-" + "m3Nb7vCx1zLk5jHg9fDs2aQw"},
     {"compliance"}),
]


# Intake builds its detectors on the first scan; the check builds them now,
# so it refuses intake too where only a detector setting is wrong.
STRICTER = {"a detector severity that does not exist": {"intake"},
            "an enabled detector that is not one": {"intake"}}


@pytest.mark.parametrize(("edit", "env_edit", "roles", "stricter"),
                         [(*c[1:], STRICTER.get(c[0], set())) for c in CASES],
                         ids=[c[0] for c in CASES])
def test_a_policy_the_role_refuses_the_check_refuses(env, tmp_path, edit, env_edit, roles,
                                                     stricter):
    policy = base(tmp_path)
    edit(policy)
    for k, v in env_edit.items():
        if v is None:
            env.delenv(k, raising=False)
        else:
            env.setenv(k, v)
    path = write(tmp_path, policy)
    for role in roles:
        with pytest.raises((Exception, SystemExit)):
            START[role](path, tmp_path)
    file, checked, refusals = policycheck.check(str(path))
    assert file == path
    refused = {r.role for r in refusals}
    assert roles <= refused, refusals
    assert refused - roles <= stricter, refusals


def test_the_base_policy_starts_every_role_and_passes(env, tmp_path):
    path = write(tmp_path, base(tmp_path))
    for role in ("server", "collector", "intake", "dashboard"):
        START[role](path, tmp_path)
    _, checked, refusals = policycheck.check(str(path))
    assert refusals == []
    assert checked == ("server", "collector", "intake", "dashboard")


def test_the_check_writes_nothing_outside_its_temporary_directory(env, tmp_path):
    policy = base(tmp_path)
    policy["server"].pop("csv_path")
    policy["server"]["store"] = "./findings"
    path = write(tmp_path, policy)
    before = sorted(p.name for p in tmp_path.iterdir())
    assert policycheck.check(str(path))[2] == []
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_a_detector_this_machine_cannot_run_is_not_probed(env, tmp_path):
    """The daemon socket and config are the pod's; the check builds the
    tier without reaching for either, where the role would refuse."""
    policy = base(tmp_path)
    policy["detectors"]["gitleaks"] = {"enabled": True, "daemon": str(tmp_path / "none.sock"),
                                       "config": str(tmp_path / "gitleaks.toml")}
    path = write(tmp_path, policy)
    with pytest.raises(RuntimeError):
        start_collector(path, tmp_path)
    assert policycheck.check(str(path))[2] == []


def test_an_unknown_top_level_key_is_refused(env, tmp_path):
    policy = base(tmp_path)
    policy["otle"] = {}
    _, _, refusals = policycheck.check(str(write(tmp_path, policy)))
    assert [(r.role, r.message) for r in refusals] == [
        ("policy", "'otle' is not a section any role reads")]


def test_a_parse_error_names_the_line_and_withholds_the_text(env, tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text('privacy:\n  hash_salt: "' + "unterminated-" + 'value\n', encoding="utf-8")
    _, _, refusals = policycheck.check(str(path))
    (r,) = refusals
    assert r.role == "policy"
    assert "line" in r.message
    assert "unterminated" not in r.message


def test_a_missing_file_is_refused(env, tmp_path):
    _, _, refusals = policycheck.check(str(tmp_path / "absent.yaml"))
    assert [r.role for r in refusals] == ["policy"]


def test_the_connector_and_scanner_are_checked_when_configured(env, tmp_path):
    policy = base(tmp_path)
    assert "connector" not in policycheck.configured_roles(load_policy(str(write(tmp_path,
                                                                                 policy))))
    policy["connector"] = {"enabled": True}
    policy["compliance"] = {"orgs": [{"id": "$FORGD_ORG_ID_PRIMARY", "api_key": "$X"}]}
    roles = policycheck.configured_roles(load_policy(str(write(tmp_path, policy))))
    assert roles[-2:] == ("connector", "compliance")


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "forgd_verdict.cli", *args],
                          capture_output=True, text=True, timeout=120, cwd=cwd)


def test_the_cli_exits_2_naming_the_path_and_each_role(env, tmp_path):
    policy = base(tmp_path)
    policy["privacy"]["hash_salt"] = ""
    path = write(tmp_path, policy)
    r = _cli("policy", "--check", "--policy", str(path), cwd=tmp_path)
    assert r.returncode == 2
    lines = [x for x in r.stderr.splitlines() if x.startswith("forgd-verdict policy: ")]
    assert {x.split(": ")[2] for x in lines} == {"server", "collector", "intake"}
    assert all(x.startswith(f"forgd-verdict policy: {path}: ") for x in lines)


def test_the_cli_says_ok_with_the_roles_it_checked(env, tmp_path):
    path = write(tmp_path, base(tmp_path))
    r = _cli("--policy", str(path), "policy", "--check", "--role", "server", cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == f"ok: {path}: server"


def test_the_known_sections_are_the_documented_ones():
    text = (ROOT / "docs" / "POLICY.md").read_text(encoding="utf-8")
    section = text.split("## Sections", 1)[1].split("\n## ", 1)[0]
    documented = set(re.findall(r"^\| `([a-z_]+)` \|", section, re.M))
    assert documented == policycheck.KNOWN_SECTIONS


def test_the_shipped_policy_uses_only_known_sections():
    raw = yaml.safe_load((ROOT / "policy.yaml").read_text(encoding="utf-8"))
    assert set(raw) <= policycheck.KNOWN_SECTIONS


def test_every_role_has_a_start_here():
    assert set(START) == set(policycheck.ROLES)
    from forgd_verdict import cli

    assert cli.ROLES == policycheck.ROLES
    assert policycheck.ROLES[:4] == policycheck.ALWAYS
