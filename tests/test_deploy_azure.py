"""scripts/deploy_azure.sh, run for real against fake cloud executables.

`az`, `docker` and `sleep` are fakes first on PATH, each appending its argv
to a log. The script is copied next to a fake verify_deployment.sh, where
its VERIFY resolves, so the gate can be made to pass or fail without the
real script growing an override.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "deploy_azure.sh"

SHA = "0123456789ab"
ACR = "acrexample"
IMAGE = f"{ACR}.azurecr.io/forgd-verdict:{SHA}"

FAKE = r'''
import json, os, sys
tool = os.path.basename(sys.argv[0])
argv = sys.argv[1:]
entry = {"tool": tool, "argv": argv}
if tool == "verify_deployment.sh":
    entry["max_uptime"] = os.environ.get("VERIFY_MAX_UPTIME_S")
    entry["connector_url"] = os.environ.get("FORGD_CONNECTOR_URL")
    entry["intake_url"] = os.environ.get("FORGD_INTAKE_URL")
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(entry) + "\n")

def opt(name):
    return argv[argv.index(name) + 1] if name in argv else None

if tool == "docker" and argv[:2] == ["image", "inspect"]:
    print("amd64")
if tool == "az" and argv[:1] == ["containerapp"]:
    name = opt("-n")
    if argv[1] == "show":
        if name in os.environ.get("FAKE_MISSING", "").split(","):
            sys.exit(3)
        if opt("--query") == "properties.configuration.ingress.fqdn":
            print(f"{name}.example.test")
    elif argv[1] == "update" and name == os.environ.get("FAKE_FAIL_APP"):
        sys.exit(1)
if tool == "verify_deployment.sh":
    fail = os.environ.get("FAKE_VERIFY_FAIL", "")
    calls = sum(1 for line in open(os.environ["FAKE_LOG"]) if '"verify_deployment.sh"' in line)
    if fail and calls == int(fail):
        sys.exit(1)
'''


def _exe(path: Path, body: str) -> None:
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def sandbox(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "scripts").mkdir()
    for tool in ("az", "docker", "sleep"):
        _exe(tmp_path / "bin" / tool, FAKE)
    _exe(tmp_path / "scripts" / "verify_deployment.sh", FAKE)
    shutil.copy(SCRIPT, tmp_path / "scripts" / "deploy_azure.sh")
    return tmp_path


def _env(sandbox: Path, **extra: str) -> dict:
    return {
        "PATH": f"{sandbox / 'bin'}:{os.environ['PATH']}",
        "HOME": str(sandbox),
        "FAKE_LOG": str(sandbox / "log.jsonl"),
        "AZURE_RESOURCE_GROUP": "rg", "AZURE_ACR": ACR, "AZURE_DEPLOY_TARGET": "aca",
        "AZURE_CONTAINER_APP": "ca-verdict", "AZURE_DASHBOARD_APP": "ca-dashboard",
        "AZURE_COLLECTOR_APP": "ca-collector", "AZURE_INGEST_JOB": "cj-ingest",
        **extra,
    }


def _run(sandbox: Path, **extra: str) -> tuple[subprocess.CompletedProcess, list[dict]]:
    return _exec(sandbox, _env(sandbox, **extra))


def _run_without(sandbox: Path, name: str, **extra: str) -> tuple[subprocess.CompletedProcess, list[dict]]:
    """As _run, with `name` absent from the environment altogether."""
    env = _env(sandbox, **extra)
    env.pop(name)
    return _exec(sandbox, env)


def _exec(sandbox: Path, env: dict) -> tuple[subprocess.CompletedProcess, list[dict]]:
    proc = subprocess.run(["bash", str(sandbox / "scripts" / "deploy_azure.sh"), SHA],
                          cwd=sandbox, env=env, capture_output=True, text=True, timeout=60)
    log = sandbox / "log.jsonl"
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return proc, calls


def _rolls(calls: list[dict]) -> list[str]:
    """Each app or job updated, in order, and each verify."""
    out = []
    for c in calls:
        if c["tool"] == "az" and c["argv"][:2] == ["containerapp", "update"]:
            out.append(c["argv"][c["argv"].index("-n") + 1])
        elif c["tool"] == "az" and c["argv"][:3] == ["containerapp", "job", "update"]:
            out.append("job")
        elif c["tool"] == "verify_deployment.sh":
            out.append("verify")
    return out


def _verifies(calls: list[dict]) -> list[dict]:
    return [c for c in calls if c["tool"] == "verify_deployment.sh"]


def test_the_connector_rolls_after_the_gate_and_is_verified_with_the_stack(sandbox):
    proc, calls = _run(sandbox, AZURE_CONNECTOR_APP="ca-connector")
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == ["ca-verdict", "verify", "ca-dashboard", "ca-collector", "ca-connector",
                             "verify", "job"], _rolls(calls)
    (update,) = [c for c in calls if c["argv"][:2] == ["containerapp", "update"] and "ca-connector" in c["argv"]]
    assert update["argv"][update["argv"].index("--image") + 1] == IMAGE
    gate, full = _verifies(calls)
    assert gate["argv"] == ["https://ca-verdict.example.test", "", ""]
    assert gate["connector_url"] == "" and gate["max_uptime"]
    assert full["connector_url"] == "https://ca-connector.example.test/mcp"
    assert "connector: https://ca-connector.example.test/mcp" in proc.stdout


def test_a_given_connector_url_is_the_one_verified(sandbox):
    """app-aca's connector_url, which is a custom host when one is set."""
    proc, calls = _run(sandbox, AZURE_CONNECTOR_APP="ca-connector",
                       FORGD_CONNECTOR_URL="https://mcp.example.com/mcp")
    assert proc.returncode == 0, proc.stderr
    gate, full = _verifies(calls)
    assert gate["connector_url"] == ""
    assert full["connector_url"] == "https://mcp.example.com/mcp"


def test_without_the_connector_nothing_of_it_is_touched_or_checked(sandbox):
    proc, calls = _run(sandbox)
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == ["ca-verdict", "verify", "ca-dashboard", "ca-collector", "verify", "job"]
    assert "connector" not in json.dumps([c for c in calls if c["tool"] == "az"])
    assert [v["connector_url"] for v in _verifies(calls)] == ["", ""]


def test_a_failing_gate_stops_the_release_before_the_connector(sandbox):
    proc, calls = _run(sandbox, AZURE_CONNECTOR_APP="ca-connector", FAKE_VERIFY_FAIL="1")
    assert proc.returncode != 0
    assert _rolls(calls) == ["ca-verdict", "verify"]


def test_a_missing_connector_app_fails_before_the_stack_is_verified(sandbox):
    proc, calls = _run(sandbox, AZURE_CONNECTOR_APP="ca-connector", FAKE_MISSING="ca-connector")
    assert proc.returncode != 0
    assert "AZURE_CONNECTOR_APP" in proc.stderr
    assert _rolls(calls) == ["ca-verdict", "verify", "ca-dashboard", "ca-collector"]


def test_a_failing_connector_roll_leaves_the_job_where_it_was(sandbox):
    proc, calls = _run(sandbox, AZURE_CONNECTOR_APP="ca-connector", FAKE_FAIL_APP="ca-connector")
    assert proc.returncode != 0
    assert _rolls(calls)[-1] == "ca-connector" and "job" not in _rolls(calls)
    assert len(_verifies(calls)) == 1


def test_a_connector_url_without_the_app_fails_before_any_call(sandbox):
    proc, calls = _run(sandbox, FORGD_CONNECTOR_URL="https://mcp.example.com/mcp")
    assert proc.returncode != 0
    assert "AZURE_CONNECTOR_APP is not" in proc.stderr
    assert calls == []


def test_the_kubernetes_path_rolls_nothing_and_names_the_connector_check(sandbox):
    """No Container Apps: images only, and the printed verify includes the
    chart's connector when its URL is set."""
    proc, calls = _run(sandbox, AZURE_DEPLOY_TARGET="k8s", FORGD_CONNECTOR_URL="https://mcp.example.com/mcp")
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == []
    assert "FORGD_CONNECTOR_URL=https://mcp.example.com/mcp scripts/verify_deployment.sh" in proc.stdout



# -- the collector ----------------------------------------------------------------

@pytest.mark.parametrize("empty", [True, False], ids=["empty", "unset"])
def test_an_empty_or_unset_collector_app_rolls_the_default_one(sandbox, empty):
    """A CD passes AZURE_COLLECTOR_APP empty when its variable is unset, and
    empty used to mean "not deployed here": the collector stayed on its old
    image, its 401 went unchecked, and the deploy exited 0."""
    if empty:
        proc, calls = _run(sandbox, AZURE_COLLECTOR_APP="")
    else:
        proc, calls = _run_without(sandbox, "AZURE_COLLECTOR_APP")
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == ["ca-verdict", "verify", "ca-dashboard", "ca-forgd-collector", "verify", "job"]
    _, full = _verifies(calls)
    assert full["argv"][1] == "https://ca-forgd-collector.example.test"


def test_none_is_the_only_way_to_skip_the_collector_and_it_says_so(sandbox):
    proc, calls = _run(sandbox, AZURE_COLLECTOR_APP="none")
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == ["ca-verdict", "verify", "ca-dashboard", "verify", "job"]
    assert "collector" not in json.dumps([c for c in calls if c["tool"] == "az"])
    _, full = _verifies(calls)
    assert full["argv"][1] == ""
    assert "collector not deployed here" in proc.stdout


def test_a_missing_collector_app_names_the_opt_out(sandbox):
    proc, calls = _run(sandbox, FAKE_MISSING="ca-collector")
    assert proc.returncode != 0
    assert "AZURE_COLLECTOR_APP" in proc.stderr and "none" in proc.stderr
    assert _rolls(calls) == ["ca-verdict", "verify", "ca-dashboard"]

# -- required inputs and the image name ----------------------------------------

def test_the_printed_roll_names_the_root_policy_unless_told_otherwise(sandbox):
    proc, _ = _run(sandbox, AZURE_DEPLOY_TARGET="k8s")
    assert proc.returncode == 0, proc.stderr
    assert "--set-file policy.inline=policy.yaml" in proc.stdout


def test_the_image_name_defaults_to_forgd_verdict(sandbox):
    proc, calls = _run(sandbox)
    assert proc.returncode == 0, proc.stderr
    pushes = [c["argv"][1] for c in calls if c["tool"] == "docker" and c["argv"][:1] == ["push"]]
    assert pushes == [IMAGE, f"{IMAGE}-ingest"]


@pytest.mark.parametrize("empty", [True, False], ids=["empty", "unset"])
def test_a_missing_registry_is_refused_before_any_call(sandbox, empty):
    proc, calls = _run(sandbox, AZURE_ACR="") if empty else _run_without(sandbox, "AZURE_ACR")
    assert proc.returncode == 2
    assert "AZURE_ACR is required" in proc.stderr and "usage:" in proc.stderr
    assert calls == []


@pytest.mark.parametrize("empty", [True, False], ids=["empty", "unset"])
def test_the_aca_target_without_a_resource_group_is_refused_before_any_call(sandbox, empty):
    if empty:
        proc, calls = _run(sandbox, AZURE_RESOURCE_GROUP="")
    else:
        proc, calls = _run_without(sandbox, "AZURE_RESOURCE_GROUP")
    assert proc.returncode == 2
    assert "AZURE_RESOURCE_GROUP is required" in proc.stderr and "usage:" in proc.stderr
    assert calls == []


@pytest.mark.parametrize("empty", [True, False], ids=["empty", "unset"])
def test_the_k8s_target_needs_no_resource_group(sandbox, empty):
    """It rolls no container app, so nothing on its path reads the group."""
    if empty:
        proc, calls = _run(sandbox, AZURE_RESOURCE_GROUP="", AZURE_DEPLOY_TARGET="k8s")
    else:
        proc, calls = _run_without(sandbox, "AZURE_RESOURCE_GROUP", AZURE_DEPLOY_TARGET="k8s")
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == []
    pushes = [c["argv"][1] for c in calls if c["tool"] == "docker" and c["argv"][:1] == ["push"]]
    assert pushes == [IMAGE, f"{IMAGE}-ingest"]


@pytest.mark.parametrize("app", ["", "ca-verdict"])
def test_the_k8s_target_builds_and_pushes_only(sandbox, app):
    """It publishes the images the chart rolls, whatever AZURE_CONTAINER_APP
    holds: a CD passes every variable, set or not."""
    proc, calls = _run(sandbox, AZURE_DEPLOY_TARGET="k8s", AZURE_CONTAINER_APP=app, FORGD_IMAGE_NAME="acme-verdict")
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == []
    image = f"{ACR}.azurecr.io/acme-verdict:{SHA}"
    pushes = [c["argv"][1] for c in calls if c["tool"] == "docker" and c["argv"][:1] == ["push"]]
    assert pushes == [image, f"{image}-ingest"]
    assert "nothing rolled" in proc.stdout


# -- the target -------------------------------------------------------------------

@pytest.mark.parametrize("target", [None, "", "aks", "ACA", "containerapps", "k8s "],
                         ids=["unset", "empty", "aks", "ACA", "containerapps", "trailing-space"])
def test_no_target_but_aca_or_k8s_is_refused_before_any_call(sandbox, target):
    """A CD passes AZURE_CONTAINER_APP empty when its variable is unset, and
    empty used to mean Kubernetes: the deploy pushed, rolled nothing and
    exited 0."""
    if target is None:
        proc, calls = _run_without(sandbox, "AZURE_DEPLOY_TARGET", AZURE_CONTAINER_APP="")
    else:
        proc, calls = _run(sandbox, AZURE_DEPLOY_TARGET=target, AZURE_CONTAINER_APP="")
    assert proc.returncode == 2, proc.stdout
    assert "AZURE_DEPLOY_TARGET" in proc.stderr and "aca or k8s" in proc.stderr
    assert calls == []


@pytest.mark.parametrize("empty", [True, False], ids=["empty", "unset"])
def test_the_aca_target_without_a_container_app_is_refused_before_any_call(sandbox, empty):
    if empty:
        proc, calls = _run(sandbox, AZURE_CONTAINER_APP="")
    else:
        proc, calls = _run_without(sandbox, "AZURE_CONTAINER_APP")
    assert proc.returncode == 2, proc.stdout
    assert "AZURE_CONTAINER_APP is required" in proc.stderr
    assert calls == []


def test_the_required_inputs_have_no_default_and_the_image_name_one():
    script = SCRIPT.read_text(encoding="utf-8")
    for name in ("AZURE_ACR", "AZURE_RESOURCE_GROUP", "AZURE_DEPLOY_TARGET", "AZURE_CONTAINER_APP"):
        assert not re.search(rf"\$\{{{name}:?-[^}}]", script), name
    assert re.findall(r"\$\{FORGD_IMAGE_NAME:?-([^}]*)\}", script) == ["forgd-verdict"]
    assert re.findall(r"\.azurecr\.io/([^:\"]*)", script) == ["${IMAGE_NAME}"] * 2


def test_the_deploy_still_supports_container_apps():
    """The path is still supported -- a fork composing modules/app-aca sets
    the variables and gets the rollout and the gate. Removing the rollout
    would have been the easy change and the wrong one."""
    script = (ROOT / "scripts" / "deploy_azure.sh").read_text(encoding="utf-8")
    assert "az containerapp update" in script
    assert "verify_deployment.sh" in script or "VERIFY" in script


def test_the_script_names_no_past_deployment():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "cutover" not in text
    assert "ca-forgd-verdict-tf" not in text


# -- the intake -------------------------------------------------------------------

def test_the_intake_rolls_after_the_collector_and_before_the_stack_is_verified(sandbox):
    proc, calls = _run(sandbox, AZURE_INTAKE_APP="ca-intake", AZURE_CONNECTOR_APP="ca-connector")
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == ["ca-verdict", "verify", "ca-dashboard", "ca-collector", "ca-intake",
                             "ca-connector", "verify", "job"], _rolls(calls)
    (update,) = [c for c in calls if c["argv"][:2] == ["containerapp", "update"] and "ca-intake" in c["argv"]]
    assert update["argv"][update["argv"].index("--image") + 1] == IMAGE
    assert "intake:    https://ca-intake.example.test/intake" in proc.stdout


def test_without_the_intake_nothing_of_it_is_touched(sandbox):
    proc, calls = _run(sandbox)
    assert proc.returncode == 0, proc.stderr
    assert "intake" not in json.dumps([c for c in calls if c["tool"] == "az"])


def test_a_missing_intake_app_fails_before_the_stack_is_verified(sandbox):
    proc, calls = _run(sandbox, AZURE_INTAKE_APP="ca-intake", FAKE_MISSING="ca-intake")
    assert proc.returncode != 0
    assert "AZURE_INTAKE_APP" in proc.stderr
    assert _rolls(calls) == ["ca-verdict", "verify", "ca-dashboard", "ca-collector"]


def test_the_intake_is_verified_with_the_stack_and_not_at_the_gate(sandbox):
    proc, calls = _run(sandbox, AZURE_INTAKE_APP="ca-intake")
    assert proc.returncode == 0, proc.stderr
    gate, full = _verifies(calls)
    assert gate["intake_url"] == ""
    assert full["intake_url"] == "https://ca-intake.example.test"
