"""release.yml asks for one approval: every job that names an environment
names the same one, and none of them waits on another, so they reach the
gate together and one review covers them all."""

from __future__ import annotations

import pathlib

import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
RELEASE = REPO / ".github" / "workflows" / "release.yml"


def _jobs() -> dict:
    return yaml.safe_load(RELEASE.read_text(encoding="utf-8"))["jobs"]


def _gated() -> dict:
    return {name: job for name, job in _jobs().items() if job.get("environment")}


def _needs(job: dict) -> set[str]:
    needs = job.get("needs", [])
    return {needs} if isinstance(needs, str) else set(needs)


def test_publishing_jobs_share_the_pypi_environment():
    gated = _gated()
    assert set(gated) == {"images", "chart", "pypi"}
    assert {job["environment"] for job in gated.values()} == {"pypi"}


def test_no_gated_job_waits_on_another():
    gated = _gated()
    for name, job in gated.items():
        assert not _needs(job) & set(gated), name


def test_github_release_runs_after_every_gated_job():
    assert set(_gated()) <= _needs(_jobs()["github-release"])
