"""scripts/deploy_aws.sh, run for real against fake cloud executables.

`aws`, `docker`, `helm` and `terraform` are fakes first on PATH, each
appending its argv (and the contents of any file:// input) to a log. The
script is copied next to a fake verify_deployment.sh, where its VERIFY
resolves, so the gate can be made to pass or fail without the real script
growing an override.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "deploy_aws.sh"

REPO = "111122223333.dkr.ecr.eu-west-2.amazonaws.com/forgd-verdict"
SHA = "0123456789ab"
ROLES = ("verdict", "collector", "dashboard", "intake", "connector", "ingest")
CONNECTOR_URL = "https://mcp.example.test/mcp"
SCHEDULE_FAMILY_ARN = "arn:aws:ecs:eu-west-2:111122223333:task-definition/fv-ingest:1"

READ_ONLY = ("taskDefinitionArn", "revision", "status", "requiresAttributes",
             "compatibilities", "registeredAt", "registeredBy", "deregisteredAt")


def _revision(role: str, revision: int, image: str, cpu: str, env: list[dict]) -> dict:
    return {
        "taskDefinitionArn": f"arn:aws:ecs:eu-west-2:111122223333:task-definition/fv-{role}:{revision}",
        "family": f"fv-{role}",
        "revision": revision,
        "status": "ACTIVE",
        "requiresAttributes": [{"name": "com.amazonaws.ecs.capability.logging-driver.awslogs"}],
        "compatibilities": ["EC2", "FARGATE"],
        "registeredAt": "2026-09-01T00:00:00+00:00",
        "registeredBy": "arn:aws:sts::111122223333:assumed-role/terraform/x",
        "networkMode": "awsvpc",
        "requiresCompatibilities": ["FARGATE"],
        "cpu": cpu,
        "memory": "1024",
        "executionRoleArn": f"arn:aws:iam::111122223333:role/fv-{role}-execution",
        "runtimePlatform": {"cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX"},
        "containerDefinitions": [{
            "name": role,
            "image": image,
            "essential": True,
            "environment": env,
        }],
    }


# What each service runs now, and what Terraform has since registered as the
# family's latest: a different cpu and an extra env value, still on the first
# apply's image. A release must start from the latter.
RUNNING = {r: _revision(r, 7, f"{REPO}:previous", "256", []) for r in ROLES}
LATEST = {
    r: _revision(r, 9, f"{REPO}:first-apply", "512",
                 [{"name": "FORGD_ADDED_BY_TERRAFORM", "value": "1"}])
    for r in ROLES
}
TAGS = [{"key": "stack", "value": "fv"}]

SCHEDULE = {
    "Arn": "arn:aws:scheduler:eu-west-2:111122223333:schedule/default/fv-ingest",
    "Name": "fv-ingest",
    "GroupName": "default",
    "State": "ENABLED",
    "Description": "ingest",
    "ScheduleExpression": "cron(0 */6 * * ? *)",
    "ScheduleExpressionTimezone": "Europe/London",
    "FlexibleTimeWindow": {"Mode": "OFF"},
    "ActionAfterCompletion": "NONE",
    "CreationDate": "2026-09-01T00:00:00+00:00",
    "LastModificationDate": "2026-09-02T00:00:00+00:00",
    "Target": {
        "Arn": "arn:aws:ecs:eu-west-2:111122223333:cluster/fv",
        "RoleArn": "arn:aws:iam::111122223333:role/fv-scheduler",
        "RetryPolicy": {"MaximumEventAgeInSeconds": 86400, "MaximumRetryAttempts": 185},
        "EcsParameters": {
            "TaskDefinitionArn": SCHEDULE_FAMILY_ARN,
            "LaunchType": "FARGATE",
            "TaskCount": 1,
            "NetworkConfiguration": {"awsvpcConfiguration": {
                "Subnets": ["subnet-a"], "SecurityGroups": ["sg-a"], "AssignPublicIp": "DISABLED",
            }},
        },
    },
}

FAKE_AWS = r'''
import json, os, sys
argv = sys.argv[1:]
state_path = os.environ["FAKE_STATE"]
state = json.load(open(state_path))
entry = {"tool": "aws", "argv": argv, "files": {}}
for a in argv:
    if a.startswith("file://"):
        entry["files"][a] = open(a[len("file://"):]).read()
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(entry) + "\n")

def opt(name):
    return argv[argv.index(name) + 1] if name in argv else None

query = opt("--query") or ""
cmd = argv[:2]
out = ""
if cmd == ["ecr", "get-login-password"]:
    out = "password"
elif cmd == ["ecs", "describe-task-definition"]:
    family = opt("--task-definition")
    if family.startswith("arn:"):
        # A specific revision: only the ones the services run are known.
        latest = next(td for td in state["running"].values() if td["taskDefinitionArn"] == family)
    else:
        role = family.removeprefix("fv-")
        if role not in state["latest"]:
            sys.exit(254)
        latest = state["latest"][role]
    if "cpuArchitecture" in query:
        out = latest["runtimePlatform"]["cpuArchitecture"]
    else:
        out = json.dumps({"taskDefinition": latest, "tags": state["tags"]})
elif cmd == ["ecs", "register-task-definition"]:
    td = json.loads(entry["files"][opt("--cli-input-json")])
    role = td["family"].removeprefix("fv-")
    rev = state["latest"][role]["revision"] + 1
    arn = f"arn:aws:ecs:eu-west-2:111122223333:task-definition/{td['family']}:{rev}"
    state["latest"][role] = dict(td, taskDefinitionArn=arn, revision=rev)
    out = arn
elif cmd == ["ecs", "update-service"]:
    state["services"][opt("--service")] = opt("--task-definition")
    out = "{}"
elif cmd == ["ecs", "describe-services"]:
    names = argv[argv.index("--services") + 1:]
    names = names[:next((i for i, a in enumerate(names) if a.startswith("--")), len(names))]
    if "failures" in query:
        out = "\t".join(n for n in names if n not in state["services"])
    elif "PRIMARY" in query:
        name = names[0]
        out = state["rolled_back"].get(name) or state["services"][name]
    elif "taskDefinition" in query and "deployments" not in query:
        out = state["services"][names[0]]
    else:
        out = "[]"
elif cmd == ["scheduler", "get-schedule"]:
    out = json.dumps(state["schedule"])
elif cmd == ["scheduler", "update-schedule"]:
    state["schedule_updated"] = True
    out = "{}"
json.dump(state, open(state_path, "w"))
if out:
    print(out)
'''

FAKE_LOGGING = r'''
import json, os, sys
entry = {"tool": os.path.basename(sys.argv[0]), "argv": sys.argv[1:], "files": {}}
if entry["tool"] == "verify_deployment.sh":
    entry["max_uptime"] = os.environ.get("VERIFY_MAX_UPTIME_S")
    entry["connector_url"] = os.environ.get("FORGD_CONNECTOR_URL")
    entry["intake_url"] = os.environ.get("FORGD_INTAKE_URL")
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(entry) + "\n")
if entry["tool"] == "docker":
    if sys.argv[1:2] == ["login"]:
        sys.stdin.read()
    if sys.argv[1:3] == ["image", "inspect"]:
        print(os.environ.get("FAKE_IMAGE_ARCH", "amd64"))
if entry["tool"] == "verify_deployment.sh":
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
    _exe(tmp_path / "bin" / "aws", FAKE_AWS)
    for tool in ("docker", "helm", "terraform"):
        _exe(tmp_path / "bin" / tool, FAKE_LOGGING)
    _exe(tmp_path / "scripts" / "verify_deployment.sh", FAKE_LOGGING)
    # The host architecture, as a hosted x86 runner reports it, whatever
    # machine the suite runs on. FAKE_UNAME overrides it per test.
    _exe(tmp_path / "bin" / "uname", 'import os\nprint(os.environ.get("FAKE_UNAME", "x86_64"))\n')
    shutil.copy(SCRIPT, tmp_path / "scripts" / "deploy_aws.sh")
    return tmp_path


def _state(sandbox: Path, *, intake: bool = False, connector: bool = False,
           rolled_back: dict | None = None) -> None:
    roles = [r for r in ROLES if (intake or r != "intake") and (connector or r != "connector")]
    services = {f"fv-{r}": RUNNING[r]["taskDefinitionArn"] for r in roles if r != "ingest"}
    (sandbox / "state.json").write_text(json.dumps({
        "latest": {r: LATEST[r] for r in roles},
        "running": {r: RUNNING[r] for r in roles},
        "tags": TAGS,
        "services": services,
        "rolled_back": rolled_back or {},
        "schedule": SCHEDULE,
    }))


def _env(sandbox: Path, target: str, **extra: str) -> dict[str, str]:
    env = {
        "PATH": f"{sandbox / 'bin'}:{os.environ['PATH']}",
        "HOME": str(sandbox),
        "FAKE_LOG": str(sandbox / "log.jsonl"),
        "FAKE_STATE": str(sandbox / "state.json"),
        "AWS_ECR_REPOSITORY": REPO,
        "AWS_DEPLOY_TARGET": target,
        "FORGD_VERDICT_URL": "https://verdict.example.test",
        "FORGD_COLLECTOR_URL": "https://collector.example.test",
        "FORGD_DASHBOARD_URL": "https://dashboard.example.test",
    }
    if target == "ecs":
        env["AWS_ECS_CLUSTER"] = "fv"
        for role in ("verdict", "collector", "dashboard"):
            env[f"AWS_ECS_{role.upper()}_SERVICE"] = f"fv-{role}"
            env[f"AWS_ECS_{role.upper()}_FAMILY"] = f"fv-{role}"
        env["AWS_ECS_INGEST_FAMILY"] = "fv-ingest"
        env["AWS_INGEST_SCHEDULE"] = "fv-ingest"
    else:
        env.update(AWS_EKS_CLUSTER="fv", AWS_EKS_RELEASE="forgd", AWS_EKS_NAMESPACE="forgd",
                   AWS_EKS_CHART="chart")
    env.update(extra)
    return env


def _run(sandbox: Path, target: str = "ecs", *, intake: bool = False, connector: bool = False,
         rolled_back: dict | None = None, **extra: str) -> tuple[subprocess.CompletedProcess, list[dict]]:
    _state(sandbox, intake=intake, connector=connector, rolled_back=rolled_back)
    proc = subprocess.run(
        ["bash", str(sandbox / "scripts" / "deploy_aws.sh"), SHA],
        cwd=sandbox, env=_env(sandbox, target, **extra),
        capture_output=True, text=True, timeout=60,
    )
    log = sandbox / "log.jsonl"
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return proc, calls


def _index(calls: list[dict], pred) -> list[int]:
    return [i for i, c in enumerate(calls) if pred(c)]


def _is(c: dict, *prefix: str) -> bool:
    return c["tool"] == "aws" and c["argv"][:len(prefix)] == list(prefix)


def _service(c: dict) -> str | None:
    return c["argv"][c["argv"].index("--service") + 1] if _is(c, "ecs", "update-service") else None


def _registered(c: dict) -> dict:
    return json.loads(next(iter(c["files"].values())))


def _verifies(calls: list[dict]) -> list[dict]:
    return [c for c in calls if c["tool"] == "verify_deployment.sh"]


# --- ecs ------------------------------------------------------------------

def test_verdict_is_rolled_and_verified_before_anything_else_is_touched(sandbox):
    proc, calls = _run(sandbox, intake=True,
                       AWS_ECS_INTAKE_SERVICE="fv-intake", AWS_ECS_INTAKE_FAMILY="fv-intake")
    assert proc.returncode == 0, proc.stderr

    updates = [_service(c) for c in calls if _service(c)]
    assert updates == ["fv-verdict", "fv-collector", "fv-dashboard", "fv-intake"], updates

    verdict_update = _index(calls, lambda c: _service(c) == "fv-verdict")[0]
    gate = _index(calls, lambda c: c["tool"] == "verify_deployment.sh")[0]
    assert calls[gate]["argv"] == ["https://verdict.example.test", "", ""]
    assert calls[gate]["max_uptime"], "the gate must only accept a replica from this roll"

    touched_other = _index(calls, lambda c: (
        (_service(c) or "fv-verdict") != "fv-verdict"
        or (_is(c, "ecs", "register-task-definition") and _registered(c)["family"] != "fv-verdict")
        or _is(c, "scheduler", "update-schedule")))
    assert touched_other, "nothing else was rolled"
    assert verdict_update < gate < min(touched_other)

    # Every service is on the image, then the stack is verified, then the
    # schedule moves.
    full = _index(calls, lambda c: c["tool"] == "verify_deployment.sh")[1]
    assert calls[full]["argv"] == ["https://verdict.example.test", "https://collector.example.test",
                                   "https://dashboard.example.test"]
    assert max(_index(calls, lambda c: _service(c) is not None)) < full
    assert full < _index(calls, lambda c: _is(c, "scheduler", "update-schedule"))[0]


def test_a_failing_gate_stops_the_release_before_the_other_services(sandbox):
    proc, calls = _run(sandbox, FAKE_VERIFY_FAIL="1")
    assert proc.returncode != 0

    assert [_service(c) for c in calls if _service(c)] == ["fv-verdict"]
    registered = [_registered(c)["family"] for c in calls if _is(c, "ecs", "register-task-definition")]
    assert registered == ["fv-verdict"]
    assert not _index(calls, lambda c: _is(c, "scheduler", "update-schedule"))
    assert len(_verifies(calls)) == 1


def test_each_revision_is_the_family_latest_with_only_the_image_changed(sandbox):
    proc, calls = _run(sandbox)
    assert proc.returncode == 0, proc.stderr

    registered = {_registered(c)["family"]: _registered(c)
                  for c in calls if _is(c, "ecs", "register-task-definition")}
    assert sorted(registered) == ["fv-collector", "fv-dashboard", "fv-ingest", "fv-verdict"]
    for family, td in registered.items():
        role = family.removeprefix("fv-")
        image = f"{REPO}:{SHA}-ingest" if role == "ingest" else f"{REPO}:{SHA}"
        expected = {k: v for k, v in LATEST[role].items() if k not in READ_ONLY}
        expected["containerDefinitions"] = [dict(expected["containerDefinitions"][0], image=image)]
        expected["tags"] = TAGS
        assert td == expected, family
        # The Terraform change since the running revision survived.
        assert td["cpu"] == "512" != RUNNING[role]["cpu"]

    # And each service moved to exactly the revision registered for it.
    state = json.loads((sandbox / "state.json").read_text())
    for role in ("verdict", "collector", "dashboard"):
        assert state["services"][f"fv-{role}"].endswith(f"task-definition/fv-{role}:10")


def test_the_schedule_update_keeps_every_other_field(sandbox):
    proc, calls = _run(sandbox)
    assert proc.returncode == 0, proc.stderr

    (update,) = [c for c in calls if _is(c, "scheduler", "update-schedule")]
    sent = _registered(update)
    expected = {k: v for k, v in SCHEDULE.items() if k not in ("Arn", "CreationDate", "LastModificationDate")}
    expected["Target"] = json.loads(json.dumps(SCHEDULE["Target"]))
    expected["Target"]["EcsParameters"]["TaskDefinitionArn"] = (
        "arn:aws:ecs:eu-west-2:111122223333:task-definition/fv-ingest:10")
    assert sent == expected


def test_a_service_the_circuit_breaker_rolled_back_fails_the_release(sandbox):
    proc, calls = _run(sandbox, rolled_back={"fv-collector": RUNNING["collector"]["taskDefinitionArn"]})
    assert proc.returncode != 0
    assert "rolled it back" in proc.stderr
    assert [_service(c) for c in calls if _service(c)] == ["fv-verdict", "fv-collector"]
    assert not _index(calls, lambda c: _is(c, "scheduler", "update-schedule"))


def test_a_missing_service_fails_before_anything_is_built(sandbox):
    proc, calls = _run(sandbox, AWS_ECS_INTAKE_SERVICE="fv-intake", AWS_ECS_INTAKE_FAMILY="fv-intake")
    assert proc.returncode != 0
    assert not [c for c in calls if c["tool"] == "docker"]
    assert not [c for c in calls if _service(c)]


def test_half_configured_intake_fails_before_any_call(sandbox):
    proc, calls = _run(sandbox, AWS_ECS_INTAKE_SERVICE="fv-intake")
    assert proc.returncode != 0
    assert "AWS_ECS_INTAKE_FAMILY" in proc.stderr
    assert calls == []


# --- both targets ---------------------------------------------------------

@pytest.mark.parametrize("target", ["ecs", "eks"])
def test_terraform_is_never_invoked(sandbox, target):
    proc, calls = _run(sandbox, target)
    assert proc.returncode == 0, proc.stderr
    assert [c for c in calls if c["tool"] == "docker" and c["argv"][:1] == ["push"]]
    assert not [c for c in calls if c["tool"] == "terraform"]


@pytest.mark.parametrize("target", ["ecs", "eks"])
def test_both_images_come_from_the_one_commit(sandbox, target):
    proc, calls = _run(sandbox, target)
    assert proc.returncode == 0, proc.stderr
    builds = [c["argv"] for c in calls if c["tool"] == "docker" and c["argv"][:1] == ["build"]]
    assert [b[b.index("--target") + 1] for b in builds] == ["base", "ingest"]
    assert [b[b.index("-t") + 1] for b in builds] == [f"{REPO}:{SHA}", f"{REPO}:{SHA}-ingest"]
    assert all(f"FORGD_BUILD_COMMIT={SHA}" in b for b in builds)
    pushes = [c["argv"][1] for c in calls if c["tool"] == "docker" and c["argv"][:1] == ["push"]]
    assert pushes == [f"{REPO}:{SHA}", f"{REPO}:{SHA}-ingest"]
    login = _index(calls, lambda c: c["tool"] == "docker" and c["argv"][:1] == ["login"])
    assert calls[login[0]]["argv"][-1] == REPO.split("/")[0]


@pytest.mark.parametrize("unset", ["AWS_ECR_REPOSITORY", "AWS_DEPLOY_TARGET", "AWS_ECS_CLUSTER",
                                   "AWS_INGEST_SCHEDULE", "FORGD_VERDICT_URL"])
def test_a_missing_variable_fails_before_any_call(sandbox, unset):
    proc, calls = _run(sandbox, "ecs", **{unset: ""})
    assert proc.returncode != 0
    assert unset in proc.stderr
    assert calls == []


def test_an_unknown_target_is_refused(sandbox):
    proc, calls = _run(sandbox, "gke")
    assert proc.returncode != 0
    assert "ecs or eks" in proc.stderr
    assert calls == []


# --- eks ------------------------------------------------------------------

def test_eks_upgrades_both_tags_reusing_values_then_verifies(sandbox):
    proc, calls = _run(sandbox, "eks")
    assert proc.returncode == 0, proc.stderr

    (helm,) = [c for c in calls if c["tool"] == "helm"]
    argv = helm["argv"]
    assert argv[:3] == ["upgrade", "forgd", "chart"]
    assert "--reset-then-reuse-values" in argv and "--wait" in argv
    assert argv[argv.index("--namespace") + 1] == "forgd"
    sets = [argv[i + 1] for i, a in enumerate(argv) if a == "--set"]
    assert sets == [f"image.repository={REPO}", f"ingest.image.repository={REPO}",
                    f"image.tag={SHA}", f"ingest.image.tag={SHA}-ingest"]

    verifies = _index(calls, lambda c: c["tool"] == "verify_deployment.sh")
    assert len(verifies) == 1 and verifies[0] > calls.index(helm)
    assert calls[verifies[0]]["argv"] == ["https://verdict.example.test", "https://collector.example.test",
                                          "https://dashboard.example.test"]
    assert max(_index(calls, lambda c: c["tool"] == "docker")) < calls.index(helm)
    assert not [c for c in calls if _is(c, "ecs") or _is(c, "scheduler")]


def test_eks_fails_when_verify_fails(sandbox):
    proc, _ = _run(sandbox, "eks", FAKE_VERIFY_FAIL="1")
    assert proc.returncode != 0


def test_a_cross_architecture_build_is_refused_before_any_call(sandbox):
    """An arm64 stack built on the x86 runner fails mid-build with `exec
    format error`, so it is refused up front, naming the fix."""
    proc, calls = _run(sandbox, "ecs", AWS_IMAGE_PLATFORM="linux/arm64")
    assert proc.returncode != 0 and "arm64 runner" in proc.stderr
    assert calls == []


def test_a_cross_build_runs_once_explicitly_allowed(sandbox):
    proc, _ = _run(sandbox, "eks", AWS_IMAGE_PLATFORM="linux/arm64", AWS_ALLOW_CROSS_BUILD="1",
                   FAKE_IMAGE_ARCH="arm64")
    assert proc.returncode == 0, proc.stderr


def test_an_arm64_host_building_arm64_needs_no_override(sandbox):
    proc, _ = _run(sandbox, "eks", AWS_IMAGE_PLATFORM="linux/arm64", FAKE_UNAME="aarch64",
                   FAKE_IMAGE_ARCH="arm64")
    assert proc.returncode == 0, proc.stderr


def test_eks_pins_both_image_repositories(sandbox):
    """Only the tags were set, so a release installed from another
    repository kept pulling from it and never came up."""
    proc, calls = _run(sandbox, "eks")
    assert proc.returncode == 0, proc.stderr
    (upgrade,) = [c["argv"] for c in calls if c["tool"] == "helm" and c["argv"][:1] == ["upgrade"]]
    assert f"image.repository={REPO}" in upgrade and f"ingest.image.repository={REPO}" in upgrade


# --- the findings connector ------------------------------------------------

CONNECTOR = {"AWS_ECS_CONNECTOR_SERVICE": "fv-connector", "AWS_ECS_CONNECTOR_FAMILY": "fv-connector",
             "FORGD_CONNECTOR_URL": CONNECTOR_URL}


def test_the_connector_rolls_after_the_gate_and_is_verified_with_the_stack(sandbox):
    proc, calls = _run(sandbox, connector=True, **CONNECTOR)
    assert proc.returncode == 0, proc.stderr

    updates = [_service(c) for c in calls if _service(c)]
    assert updates == ["fv-verdict", "fv-collector", "fv-dashboard", "fv-connector"], updates
    registered = [_registered(c) for c in calls if _is(c, "ecs", "register-task-definition")]
    (td,) = [td for td in registered if td["family"] == "fv-connector"]
    assert td["containerDefinitions"][0]["image"] == f"{REPO}:{SHA}"

    gate, full = _verifies(calls)
    # The gate runs before the connector moves and never checks it, even
    # with the URL in the environment.
    assert gate["connector_url"] == ""
    assert calls.index(gate) < _index(calls, lambda c: _service(c) == "fv-connector")[0]
    assert full["connector_url"] == CONNECTOR_URL
    assert max(_index(calls, lambda c: _service(c) is not None)) < calls.index(full)


def test_without_the_connector_nothing_of_it_is_touched_or_checked(sandbox):
    proc, calls = _run(sandbox)
    assert proc.returncode == 0, proc.stderr
    assert "fv-connector" not in json.dumps(calls)
    assert [v["connector_url"] for v in _verifies(calls)] == ["", ""]


def test_a_failing_gate_stops_the_release_before_the_connector(sandbox):
    proc, calls = _run(sandbox, connector=True, FAKE_VERIFY_FAIL="1", **CONNECTOR)
    assert proc.returncode != 0
    assert [_service(c) for c in calls if _service(c)] == ["fv-verdict"]
    assert "fv-connector" not in json.dumps([c for c in calls if _is(c, "ecs", "register-task-definition")])


def test_a_failing_connector_roll_fails_the_release_before_the_stack_is_verified(sandbox):
    proc, calls = _run(sandbox, connector=True,
                       rolled_back={"fv-connector": RUNNING["connector"]["taskDefinitionArn"]}, **CONNECTOR)
    assert proc.returncode != 0
    assert "rolled it back" in proc.stderr
    assert len(_verifies(calls)) == 1
    assert not _index(calls, lambda c: _is(c, "scheduler", "update-schedule"))


@pytest.mark.parametrize("given, named", [
    ({"AWS_ECS_CONNECTOR_SERVICE": "fv-connector", "FORGD_CONNECTOR_URL": CONNECTOR_URL},
     "AWS_ECS_CONNECTOR_FAMILY"),
    ({"AWS_ECS_CONNECTOR_FAMILY": "fv-connector", "FORGD_CONNECTOR_URL": CONNECTOR_URL},
     "AWS_ECS_CONNECTOR_SERVICE"),
    ({"AWS_ECS_CONNECTOR_SERVICE": "fv-connector", "AWS_ECS_CONNECTOR_FAMILY": "fv-connector"},
     "FORGD_CONNECTOR_URL"),
    ({"FORGD_CONNECTOR_URL": CONNECTOR_URL}, "AWS_ECS_CONNECTOR_SERVICE and AWS_ECS_CONNECTOR_FAMILY are not"),
])
def test_a_half_configured_connector_fails_before_any_call(sandbox, given, named):
    proc, calls = _run(sandbox, connector=True, **given)
    assert proc.returncode != 0
    assert named in proc.stderr
    assert calls == []


def test_a_missing_connector_service_fails_before_anything_is_built(sandbox):
    proc, calls = _run(sandbox, **CONNECTOR)
    assert proc.returncode != 0
    assert not [c for c in calls if c["tool"] == "docker"]
    assert not [c for c in calls if _service(c)]


def test_eks_verifies_the_charts_connector_when_its_url_is_set(sandbox):
    proc, calls = _run(sandbox, "eks", FORGD_CONNECTOR_URL=CONNECTOR_URL)
    assert proc.returncode == 0, proc.stderr
    (verify,) = _verifies(calls)
    assert verify["connector_url"] == CONNECTOR_URL


def test_eks_without_a_connector_url_checks_none(sandbox):
    proc, calls = _run(sandbox, "eks")
    assert proc.returncode == 0, proc.stderr
    (verify,) = _verifies(calls)
    assert verify["connector_url"] == ""


INTAKE_URL = "https://intake.example.com"


def test_a_given_intake_url_is_verified_with_the_stack_and_not_at_the_gate(sandbox):
    proc, calls = _run(sandbox, intake=True, AWS_ECS_INTAKE_SERVICE="fv-intake",
                       AWS_ECS_INTAKE_FAMILY="fv-intake", FORGD_INTAKE_URL=INTAKE_URL)
    assert proc.returncode == 0, proc.stderr
    gate, full = _verifies(calls)
    assert gate["intake_url"] == ""
    assert full["intake_url"] == INTAKE_URL
