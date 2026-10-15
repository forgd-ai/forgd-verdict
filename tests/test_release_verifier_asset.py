"""The GitHub Release attaches verify_deployment.sh, taken from the core
wheel the job has checked, and lists it in SHA256SUMS."""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"


def _steps() -> dict[str, str]:
    job = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["github-release"]
    return {s.get("name"): s.get("run", "") for s in job["steps"]}


def test_the_verifier_comes_from_the_checked_wheel():
    notes = _steps()["Write the release notes"]
    check = notes.index("sha256sum --check --strict --quiet")
    extract = notes.index("forgd_verdict/verify_deployment.sh")
    assert check < extract
    assert 'unzip -p "dist/forgd_verdict-$VERSION-py3-none-any.whl"' in notes


def test_the_verifier_is_summed_and_attached():
    steps = _steps()
    assert "sha256sum hook.txt verify_deployment.sh" in steps["Write the release notes"]
    assert '"$OUT/verify_deployment.sh"' in steps["Create the release"]
