"""scripts/deploy_gcp.sh, run for real against fake cloud executables.

`gcloud`, `docker`, `helm`, `terraform` and `uname` are fakes first on
PATH, each appending its argv to a log. The script is copied next to a fake
verify_deployment.sh, where its VERIFY resolves, so the gate can be made to
pass or fail without the real script growing an override.
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
from test_ci_gcp import _locals as _ci_gcp_locals
from test_ci_gcp import _strings as _ci_gcp_strings

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "deploy_gcp.sh"

AR = "europe-west2-docker.pkg.dev/acme-verdict/forgd"
REPO = f"{AR}/forgd-verdict"
SHA = "0123456789ab"
URLS = ["https://verdict.example.test", "https://collector.example.test", "https://dashboard.example.test"]

FAKE = r'''
import json, os, sys
tool = os.path.basename(sys.argv[0])
argv = sys.argv[1:]
entry = {"tool": tool, "argv": argv}
if tool == "verify_deployment.sh":
    entry["max_uptime"] = os.environ.get("VERIFY_MAX_UPTIME_S")
    entry["iap"] = os.environ.get("FORGD_DASHBOARD_IAP")
    entry["connector_url"] = os.environ.get("FORGD_CONNECTOR_URL")
    entry["intake_url"] = os.environ.get("FORGD_INTAKE_URL")
if tool == "gcloud":
    entry["kubeconfig"] = os.environ.get("KUBECONFIG")
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(entry) + "\n")
if tool == "docker" and argv[:2] == ["image", "inspect"]:
    print(os.environ.get("FAKE_IMAGE_ARCH", "amd64"))
if tool == "gcloud" and argv[:3] == ["run", "services", "update"] and argv[3] == os.environ.get("FAKE_FAIL_SERVICE"):
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
    for tool in ("gcloud", "docker", "helm", "terraform"):
        _exe(tmp_path / "bin" / tool, FAKE)
    _exe(tmp_path / "scripts" / "verify_deployment.sh", FAKE)
    # The host architecture, as a hosted x86 runner reports it, whatever
    # machine the suite runs on. FAKE_UNAME overrides it per test.
    _exe(tmp_path / "bin" / "uname", 'import os\nprint(os.environ.get("FAKE_UNAME", "x86_64"))\n')
    shutil.copy(SCRIPT, tmp_path / "scripts" / "deploy_gcp.sh")
    return tmp_path


def _env(sandbox: Path, target: str, **extra: str) -> dict[str, str]:
    env = {
        "PATH": f"{sandbox / 'bin'}:{os.environ['PATH']}",
        "HOME": str(sandbox),
        "FAKE_LOG": str(sandbox / "log.jsonl"),
        "GCP_PROJECT_ID": "acme-verdict",
        "GCP_ARTIFACT_REPOSITORY": AR,
        "GCP_DEPLOY_TARGET": target,
        "FORGD_VERDICT_URL": URLS[0],
        "FORGD_COLLECTOR_URL": URLS[1],
        "FORGD_DASHBOARD_URL": URLS[2],
    }
    if target == "cloudrun":
        env.update(GCP_REGION="europe-west2", GCP_RUN_VERDICT_SERVICE="fv-verdict",
                   GCP_RUN_COLLECTOR_SERVICE="fv-collector", GCP_RUN_DASHBOARD_SERVICE="fv-dashboard",
                   GCP_RUN_INGEST_JOB="fv-ingest")
    else:
        env.update(GCP_GKE_CLUSTER="fv", GCP_GKE_LOCATION="europe-west2", GCP_GKE_RELEASE="forgd",
                   GCP_GKE_NAMESPACE="forgd", GCP_GKE_CHART="chart")
    env.update(extra)
    return env


def _run(sandbox: Path, target: str = "cloudrun", **extra: str) -> tuple[subprocess.CompletedProcess, list[dict]]:
    proc = subprocess.run(
        ["bash", str(sandbox / "scripts" / "deploy_gcp.sh"), SHA],
        cwd=sandbox, env=_env(sandbox, target, **extra),
        capture_output=True, text=True, timeout=60,
    )
    log = sandbox / "log.jsonl"
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return proc, calls


def _is(c: dict, *prefix: str) -> bool:
    return c["tool"] == "gcloud" and c["argv"][:len(prefix)] == list(prefix)


def _rolls(calls: list[dict]) -> list[str]:
    """The Cloud Run services updated and the ingest job, in order, and
    each verify as `verify`/`verify-full`."""
    out = []
    for c in calls:
        if _is(c, "run", "services", "update"):
            out.append(c["argv"][3])
        elif _is(c, "run", "jobs", "update"):
            out.append(f"job:{c['argv'][3]}")
        elif c["tool"] == "verify_deployment.sh":
            out.append("verify-full" if c["argv"] == URLS else "verify")
    return out


def _verifies(calls: list[dict]) -> list[dict]:
    return [c for c in calls if c["tool"] == "verify_deployment.sh"]


# --- cloudrun -------------------------------------------------------------

def test_verdict_is_updated_and_verified_before_anything_else_is_touched(sandbox):
    proc, calls = _run(sandbox, GCP_RUN_INTAKE_SERVICE="fv-intake")
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == ["fv-verdict", "verify", "fv-collector", "fv-intake", "fv-dashboard",
                             "verify-full", "job:fv-ingest"], _rolls(calls)
    gate, full = _verifies(calls)
    assert gate["argv"] == [URLS[0], "", ""]
    assert gate["max_uptime"], "the gate must only accept a replica from this roll"
    # The script runs in well under a second here, so its window is its own
    # elapsed time plus the 60 s allowance.
    assert 60 <= int(gate["max_uptime"]) <= 70, gate["max_uptime"]


def test_intake_is_skipped_when_unset(sandbox):
    proc, calls = _run(sandbox)
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == ["fv-verdict", "verify", "fv-collector", "fv-dashboard", "verify-full",
                             "job:fv-ingest"], _rolls(calls)


def test_every_update_replaces_the_image_and_nothing_else(sandbox):
    proc, calls = _run(sandbox, GCP_RUN_INTAKE_SERVICE="fv-intake")
    assert proc.returncode == 0, proc.stderr
    runs = [c["argv"] for c in calls if _is(c, "run")]
    assert len(runs) == 5, runs
    for argv in runs:
        image = f"{REPO}:{SHA}-ingest" if argv[1] == "jobs" else f"{REPO}:{SHA}"
        assert argv[2] == "update", argv
        assert argv[4:] == [f"--image={image}", "--region=europe-west2", "--project=acme-verdict",
                            "--quiet"], argv
    assert [a[1] for a in runs] == ["services"] * 4 + ["jobs"]


def test_a_failing_gate_stops_the_release_with_nothing_else_updated(sandbox):
    proc, calls = _run(sandbox, GCP_RUN_INTAKE_SERVICE="fv-intake", FAKE_VERIFY_FAIL="1")
    assert proc.returncode != 0
    assert _rolls(calls) == ["fv-verdict", "verify"], _rolls(calls)


def test_a_failing_service_update_stops_the_roll(sandbox):
    proc, calls = _run(sandbox, GCP_RUN_INTAKE_SERVICE="fv-intake", FAKE_FAIL_SERVICE="fv-collector")
    assert proc.returncode != 0
    assert _rolls(calls) == ["fv-verdict", "verify", "fv-collector"], _rolls(calls)


def test_a_failing_verdict_update_touches_nothing_else(sandbox):
    proc, calls = _run(sandbox, FAKE_FAIL_SERVICE="fv-verdict")
    assert proc.returncode != 0
    assert _rolls(calls) == ["fv-verdict"], _rolls(calls)


def test_a_failing_stack_verify_leaves_ingest_where_it_was(sandbox):
    proc, calls = _run(sandbox, FAKE_VERIFY_FAIL="2")
    assert proc.returncode != 0
    assert _rolls(calls)[-1] == "verify-full"
    assert not [c for c in calls if _is(c, "run", "jobs")]


def test_only_the_full_verify_expects_the_dashboard_behind_iap(sandbox):
    proc, calls = _run(sandbox)
    assert proc.returncode == 0, proc.stderr
    gate, full = _verifies(calls)
    assert gate["iap"] is None
    assert full["iap"] == "1" and full["max_uptime"] is None


def test_cloudrun_refuses_arm64_even_on_an_arm64_host(sandbox):
    proc, calls = _run(sandbox, GCP_IMAGE_PLATFORM="linux/arm64", FAKE_UNAME="aarch64",
                       FAKE_IMAGE_ARCH="arm64")
    assert proc.returncode != 0 and "linux/amd64 only" in proc.stderr
    assert calls == []


# --- both targets ---------------------------------------------------------

@pytest.mark.parametrize("target", ["cloudrun", "gke"])
def test_both_images_come_from_the_one_commit(sandbox, target):
    proc, calls = _run(sandbox, target)
    assert proc.returncode == 0, proc.stderr
    builds = [c["argv"] for c in calls if c["tool"] == "docker" and c["argv"][:1] == ["build"]]
    assert [b[b.index("--target") + 1] for b in builds] == ["base", "ingest"]
    assert [b[b.index("-t") + 1] for b in builds] == [f"{REPO}:{SHA}", f"{REPO}:{SHA}-ingest"]
    assert all(f"FORGD_BUILD_COMMIT={SHA}" in b and b[b.index("-f") + 1] == "deploy/Dockerfile" for b in builds)
    pushes = [c["argv"][1] for c in calls if c["tool"] == "docker" and c["argv"][:1] == ["push"]]
    assert pushes == [f"{REPO}:{SHA}", f"{REPO}:{SHA}-ingest"]
    (helper,) = [c for c in calls if _is(c, "auth", "configure-docker")]
    assert helper["argv"] == ["auth", "configure-docker", "europe-west2-docker.pkg.dev", "--quiet"]
    first_push = next(i for i, c in enumerate(calls) if c["tool"] == "docker" and c["argv"][:1] == ["push"])
    assert calls.index(helper) < first_push
    assert not [c for c in calls if c["tool"] == "terraform"]


@pytest.mark.parametrize("target", ["cloudrun", "gke"])
def test_nothing_is_rolled_before_both_images_are_pushed(sandbox, target):
    proc, calls = _run(sandbox, target)
    assert proc.returncode == 0, proc.stderr
    last_push = max(i for i, c in enumerate(calls) if c["tool"] == "docker")
    first_roll = min(i for i, c in enumerate(calls)
                     if _is(c, "run") or _is(c, "container") or c["tool"] in ("helm", "verify_deployment.sh"))
    assert last_push < first_roll


def test_every_missing_variable_is_named_at_once(sandbox):
    proc, calls = _run(sandbox, "cloudrun", GCP_PROJECT_ID="", GCP_REGION="", GCP_RUN_INGEST_JOB="",
                       FORGD_DASHBOARD_URL="")
    assert proc.returncode != 0
    (line,) = [ln for ln in proc.stderr.splitlines() if "required and not set" in ln]
    for name in ("GCP_PROJECT_ID", "GCP_REGION", "GCP_RUN_INGEST_JOB", "FORGD_DASHBOARD_URL"):
        assert name in line, name
    assert calls == []


@pytest.mark.parametrize("target,unset", [
    ("cloudrun", "GCP_ARTIFACT_REPOSITORY"), ("cloudrun", "GCP_DEPLOY_TARGET"),
    ("cloudrun", "GCP_RUN_VERDICT_SERVICE"), ("cloudrun", "FORGD_VERDICT_URL"),
    ("gke", "GCP_GKE_CLUSTER"), ("gke", "GCP_GKE_LOCATION"), ("gke", "GCP_GKE_RELEASE"),
    ("gke", "GCP_GKE_NAMESPACE"),
])
def test_a_missing_variable_fails_before_any_call(sandbox, target, unset):
    proc, calls = _run(sandbox, target, **{unset: ""})
    assert proc.returncode != 0
    assert unset in proc.stderr
    assert calls == []


def test_an_unknown_target_is_refused(sandbox):
    proc, calls = _run(sandbox, "eks")
    assert proc.returncode != 0
    assert "cloudrun or gke" in proc.stderr
    assert calls == []


def test_a_repository_that_is_not_artifact_registry_is_refused(sandbox):
    proc, calls = _run(sandbox, GCP_ARTIFACT_REPOSITORY="gcr.io/acme-verdict")
    assert proc.returncode != 0 and "GCP_ARTIFACT_REPOSITORY" in proc.stderr
    assert calls == []


def test_a_cross_architecture_build_is_refused_before_any_call(sandbox):
    proc, calls = _run(sandbox, "gke", GCP_IMAGE_PLATFORM="linux/arm64")
    assert proc.returncode != 0 and "arm64 runner" in proc.stderr
    assert calls == []


def test_an_amd64_build_on_an_arm64_host_is_refused(sandbox):
    proc, calls = _run(sandbox, "cloudrun", FAKE_UNAME="aarch64")
    assert proc.returncode != 0 and "amd64 runner" in proc.stderr
    assert calls == []


def test_a_cross_build_runs_once_explicitly_allowed(sandbox):
    proc, _ = _run(sandbox, "gke", GCP_IMAGE_PLATFORM="linux/arm64", GCP_ALLOW_CROSS_BUILD="1",
                   FAKE_IMAGE_ARCH="arm64")
    assert proc.returncode == 0, proc.stderr


def test_an_image_of_the_wrong_architecture_is_not_pushed(sandbox):
    proc, calls = _run(sandbox, "cloudrun", FAKE_IMAGE_ARCH="arm64")
    assert proc.returncode != 0 and "refusing to push" in proc.stderr
    assert not [c for c in calls if c["tool"] == "docker" and c["argv"][:1] == ["push"]]


def test_the_script_reads_exactly_the_variables_ci_gcp_lists():
    listed = set(_ci_gcp_strings(_ci_gcp_locals()["repository_variables"]))
    script = SCRIPT.read_text(encoding="utf-8")
    # FORGD_IMAGE_NAME is a literal in the workflow, not a repository variable.
    read = set(re.findall(r"\b((?:GCP|FORGD)_[A-Z_]+)\b", script)) - {
        "FORGD_BUILD_COMMIT", "FORGD_DASHBOARD_IAP", "FORGD_IMAGE_NAME"}
    assert read, "parsed nothing from the script"
    # The two the workflow gives google-github-actions/auth instead.
    assert listed - read == {"GCP_WORKLOAD_IDENTITY_PROVIDER", "GCP_SERVICE_ACCOUNT"}
    assert read - listed == set(), sorted(read - listed)


def test_the_image_name_is_forgd_image_name(sandbox):
    proc, calls = _run(sandbox, FORGD_IMAGE_NAME="acme-verdict")
    assert proc.returncode == 0, proc.stderr
    repo = f"{AR}/acme-verdict"
    pushes = [c["argv"][1] for c in calls if c["tool"] == "docker" and c["argv"][:1] == ["push"]]
    assert pushes == [f"{repo}:{SHA}", f"{repo}:{SHA}-ingest"]
    images = {a.split("=", 1)[1] for c in calls if c["tool"] == "gcloud"
              for a in c["argv"] if a.startswith("--image=")}
    assert images == {f"{repo}:{SHA}", f"{repo}:{SHA}-ingest"}


def test_the_image_name_has_one_default():
    script = SCRIPT.read_text(encoding="utf-8")
    assert re.findall(r"\$\{FORGD_IMAGE_NAME:?-([^}]*)\}", script) == ["forgd-verdict"]


# --- gke ------------------------------------------------------------------

def test_gke_fetches_credentials_through_the_dns_endpoint(sandbox):
    proc, calls = _run(sandbox, "gke")
    assert proc.returncode == 0, proc.stderr
    (creds,) = [c for c in calls if _is(c, "container")]
    assert creds["argv"] == ["container", "clusters", "get-credentials", "fv", "--location", "europe-west2",
                             "--project", "acme-verdict", "--dns-endpoint"]
    assert creds["kubeconfig"] and creds["kubeconfig"] != str(Path.home() / ".kube" / "config")


def test_gke_upgrades_both_tags_reusing_values_then_verifies(sandbox):
    proc, calls = _run(sandbox, "gke")
    assert proc.returncode == 0, proc.stderr

    (helm,) = [c for c in calls if c["tool"] == "helm"]
    argv = helm["argv"]
    assert argv[:3] == ["upgrade", "forgd", "chart"]
    assert "--reset-then-reuse-values" in argv and "--wait" in argv
    assert argv[argv.index("--namespace") + 1] == "forgd"
    sets = [argv[i + 1] for i, a in enumerate(argv) if a == "--set"]
    assert sets == [f"image.repository={REPO}", f"ingest.image.repository={REPO}",
                    f"image.tag={SHA}", f"ingest.image.tag={SHA}-ingest"]

    (creds,) = [c for c in calls if _is(c, "container")]
    (verify,) = _verifies(calls)
    assert calls.index(creds) < calls.index(helm) < calls.index(verify)
    assert verify["argv"] == URLS and verify["iap"] == "1"
    assert not [c for c in calls if _is(c, "run")]


def test_gke_chart_defaults_to_the_repository_chart(sandbox):
    proc, calls = _run(sandbox, "gke", GCP_GKE_CHART="")
    assert proc.returncode == 0, proc.stderr
    (helm,) = [c for c in calls if c["tool"] == "helm"]
    assert helm["argv"][2] == "deploy/helm/forgd-verdict"


def test_gke_fails_when_verify_fails(sandbox):
    proc, _ = _run(sandbox, "gke", FAKE_VERIFY_FAIL="1")
    assert proc.returncode != 0


def test_an_arm64_v8_platform_builds_on_an_arm64_host(sandbox):
    proc, _ = _run(sandbox, "gke", GCP_IMAGE_PLATFORM="linux/arm64/v8", FAKE_UNAME="aarch64",
                   FAKE_IMAGE_ARCH="arm64")
    assert proc.returncode == 0, proc.stderr


# --- the findings connector ------------------------------------------------

CONNECTOR_URL = "https://fv-connector-123456789012.europe-west2.run.app/mcp"
CONNECTOR = {"GCP_RUN_CONNECTOR_SERVICE": "fv-connector", "FORGD_CONNECTOR_URL": CONNECTOR_URL}


def test_the_connector_is_updated_after_the_gate_and_verified_with_the_stack(sandbox):
    proc, calls = _run(sandbox, **CONNECTOR)
    assert proc.returncode == 0, proc.stderr
    assert _rolls(calls) == ["fv-verdict", "verify", "fv-collector", "fv-dashboard", "fv-connector",
                             "verify-full", "job:fv-ingest"], _rolls(calls)
    (update,) = [c for c in calls if _is(c, "run", "services", "update") and c["argv"][3] == "fv-connector"]
    assert f"--image={REPO}:{SHA}" in update["argv"]
    gate, full = _verifies(calls)
    assert gate["connector_url"] == ""
    assert full["connector_url"] == CONNECTOR_URL


def test_without_the_connector_nothing_of_it_is_touched_or_checked(sandbox):
    proc, calls = _run(sandbox)
    assert proc.returncode == 0, proc.stderr
    assert "fv-connector" not in json.dumps(calls)
    assert [v["connector_url"] for v in _verifies(calls)] == ["", ""]


def test_a_failing_gate_stops_the_release_before_the_connector(sandbox):
    proc, calls = _run(sandbox, FAKE_VERIFY_FAIL="1", **CONNECTOR)
    assert proc.returncode != 0
    assert _rolls(calls) == ["fv-verdict", "verify"], _rolls(calls)


def test_a_failing_connector_update_stops_before_the_stack_is_verified(sandbox):
    proc, calls = _run(sandbox, FAKE_FAIL_SERVICE="fv-connector", **CONNECTOR)
    assert proc.returncode != 0
    assert _rolls(calls) == ["fv-verdict", "verify", "fv-collector", "fv-dashboard", "fv-connector"]


@pytest.mark.parametrize("given, named", [
    ({"GCP_RUN_CONNECTOR_SERVICE": "fv-connector"}, "FORGD_CONNECTOR_URL"),
    ({"FORGD_CONNECTOR_URL": CONNECTOR_URL}, "GCP_RUN_CONNECTOR_SERVICE is not"),
])
def test_a_half_configured_connector_fails_before_any_call(sandbox, given, named):
    proc, calls = _run(sandbox, **given)
    assert proc.returncode != 0
    assert named in proc.stderr
    assert calls == []


def test_gke_verifies_the_charts_connector_when_its_url_is_set(sandbox):
    proc, calls = _run(sandbox, "gke", FORGD_CONNECTOR_URL=CONNECTOR_URL)
    assert proc.returncode == 0, proc.stderr
    (verify,) = _verifies(calls)
    assert verify["connector_url"] == CONNECTOR_URL and verify["iap"] == "1"


INTAKE_URL = "https://fv-intake-123456789012.europe-west2.run.app"


def test_a_given_intake_url_is_verified_with_the_stack_and_not_at_the_gate(sandbox):
    proc, calls = _run(sandbox, GCP_RUN_INTAKE_SERVICE="fv-intake", FORGD_INTAKE_URL=INTAKE_URL)
    assert proc.returncode == 0, proc.stderr
    gate, full = _verifies(calls)
    assert gate["intake_url"] == ""
    assert full["intake_url"] == INTAKE_URL


def test_the_gke_verify_checks_a_given_intake_url(sandbox):
    proc, calls = _run(sandbox, "gke", FORGD_INTAKE_URL=INTAKE_URL)
    assert proc.returncode == 0, proc.stderr
    assert [v["intake_url"] for v in _verifies(calls)][-1] == INTAKE_URL
