"""Every attestation release.yml pushes to a registry is pushed with Docker's
credentials, so the job logs in with docker/login-action before it."""

from __future__ import annotations

import pathlib

import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
RELEASE = REPO / ".github" / "workflows" / "release.yml"


def _jobs() -> dict:
    return yaml.safe_load(RELEASE.read_text(encoding="utf-8"))["jobs"]


def _pushes_attestation(step: dict) -> bool:
    uses = step.get("uses", "")
    return (uses.startswith("actions/attest-build-provenance@")
            and str(step.get("with", {}).get("push-to-registry", "")).lower() == "true")


def _docker_login(step: dict, registry: str) -> bool:
    return (step.get("uses", "").startswith("docker/login-action@")
            and step.get("with", {}).get("registry") == registry)


def test_some_job_pushes_an_attestation():
    assert any(_pushes_attestation(s) for job in _jobs().values() for s in job.get("steps", []))


def test_each_pushed_attestation_follows_a_docker_login_to_ghcr():
    for name, job in _jobs().items():
        steps = job.get("steps", [])
        for i, step in enumerate(steps):
            if _pushes_attestation(step):
                assert any(_docker_login(s, "ghcr.io") for s in steps[:i]), (name, step.get("name"))
