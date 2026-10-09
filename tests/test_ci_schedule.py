"""ci.yml re-audits the pinned dependencies every week, and runs only that
and the full-history secret scan on the schedule.

Dependabot does not read deploy/constraints/*.txt, so an advisory published
against a pinned package would otherwise surface only when someone next
pushed.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
NOT_ON_SCHEDULE = "github.event_name != 'schedule'"


def _ci() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))


def _on() -> dict:
    doc = _ci()
    return doc.get("on", doc.get(True))


def test_ci_runs_weekly():
    [entry] = _on()["schedule"]
    minute, hour, dom, month, dow = entry["cron"].split()
    assert dom == "*" and month == "*" and re.fullmatch(r"[0-6]", dow), entry["cron"]


SCHEDULED_JOBS = {"pip-audit", "secret-scan"}


def test_only_the_audit_and_the_secret_scan_run_on_the_schedule():
    jobs = _ci()["jobs"]
    for name in SCHEDULED_JOBS:
        assert "if" not in jobs[name], (name, jobs[name].get("if"))
    for name, job in jobs.items():
        if name not in SCHEDULED_JOBS:
            assert NOT_ON_SCHEDULE in job.get("if", ""), name


def test_the_audit_covers_every_constraint_file():
    steps = " ".join(str(s.get("run", "")) for s in _ci()["jobs"]["pip-audit"]["steps"])
    for path in sorted((ROOT / "deploy" / "constraints").glob("*.txt")):
        assert f"-r deploy/constraints/{path.name}" in steps, path.name


def test_the_workflows_still_pass_the_workflow_check():
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_workflows.py"),
                          str(ROOT / ".github" / "workflows")], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def test_the_weekly_audit_runs_govulncheck_over_gitleaksd():
    """The image's govulncheck step needs the built image and does not run
    on the schedule."""
    jobs = _ci()["jobs"]
    scheduled = [j for j in jobs.values() if NOT_ON_SCHEDULE not in j.get("if", "")]
    steps = [s for j in scheduled for s in j["steps"]]
    [step] = [s for s in steps if "govulncheck" in str(s.get("run", ""))
              and s.get("working-directory") == "sidecar/gitleaksd"]
    assert re.search(r"golang\.org/x/vuln/cmd/govulncheck@v1\.7\.0 \./\.\.\.", step["run"]), step["run"]
    go = [s for s in steps[:steps.index(step)] if s.get("uses", "").startswith("actions/setup-go@")]
    assert go, "govulncheck needs a Go toolchain"


# workflow_dispatch only when ci.yml itself was dispatched: a workflow that
# calls it passes its own event and its own github.workflow.
SCHEDULED_ONLY = ("github.event_name == 'schedule' || "
                  "(github.event_name == 'workflow_dispatch' && github.workflow == 'ci')")


def _audit_steps() -> list[dict]:
    return _ci()["jobs"]["pip-audit"]["steps"]


def _gitleaks_scan() -> tuple[int, dict]:
    [(i, step)] = [(i, s) for i, s in enumerate(_audit_steps())
                   if s.get("name") == "govulncheck the gitleaks the images ship"]
    return i, step


def test_the_weekly_audit_builds_the_gitleaks_the_images_ship():
    """The Dockerfile's gitleaks stage alone: the CLI both images copy in."""
    _, step = _gitleaks_scan()
    assert step.get("if") == SCHEDULED_ONLY, step.get("if")
    run = step["run"]
    assert run.startswith("set -euo pipefail\n"), run
    assert ("docker build -f deploy/Dockerfile --target gitleaks -t forgd-verdict-gitleaks:ci ."
            in run), run
    assert ("docker run --rm --entrypoint cat forgd-verdict-gitleaks:ci /out/gitleaks"
            " > /tmp/gitleaks" in run), run
    assert not [s for s in _audit_steps() if s.get("uses") == "./.github/actions/install-gitleaks"]


def test_the_weekly_audit_runs_govulncheck_over_the_gitleaks_binary():
    steps = _audit_steps()
    i, step = _gitleaks_scan()
    lines = step["run"].splitlines()
    assert lines[-1] == "go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 -mode=binary /tmp/gitleaks"
    assert lines.index("chmod +x /tmp/gitleaks") < len(lines) - 1
    assert any(s.get("uses", "").startswith("actions/setup-go@") for s in steps[:i])


def test_ci_installs_the_gitleaks_version_the_image_builds():
    """GITLEAKS_SHA256 pins the release the test jobs install; the image
    builds the CLI from source, so only the version is shared."""
    env = _ci()["env"]
    dockerfile = (ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
    args = dict(re.findall(r"^ARG (GITLEAKS_\w+)=(\S+)$", dockerfile, re.M))
    assert env["GITLEAKS_VERSION"] == args["GITLEAKS_VERSION"]
