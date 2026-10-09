"""examples/github/deploy.yml: the deploy workflow a fork copies into
.github/workflows/. It names nothing of any one deployment and publishes
nowhere but the fork's own cloud."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "github" / "deploy.yml"
TEXT = EXAMPLE.read_text(encoding="utf-8")

sys.path.insert(0, str(REPO / "scripts"))
from check_workflows import _Strict  # noqa: E402


def _workflow() -> dict:
    return yaml.load(TEXT, Loader=_Strict)


def test_it_parses_as_a_workflow():
    workflow = _workflow()
    assert workflow.get("on", workflow.get(True)) == {
        "push": {"tags": ["v*"]}, "workflow_dispatch": None}
    assert set(workflow["jobs"]) == {"deploy", "deploy-aws", "deploy-gcp", "no-deploy-target"}


def test_it_lives_outside_github_workflows():
    assert ".github" not in EXAMPLE.relative_to(REPO).parts


@pytest.mark.parametrize("rule, pattern", [
    ("uuid", r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    ("azure registry host", r"azurecr\.io"),
    ("forgd host", r"forgd\.(?:ai|com)"),
    ("internal repository", r"-internal\b"),
    ("issue reference", r"(?<![&\w])#[0-9]+(?!\w)"),
    ("internal docs", r"docs[/\\]internal"),
])
def test_it_names_nothing_of_one_deployment(rule, pattern):
    hits = [n for n, line in enumerate(TEXT.splitlines(), 1) if re.search(pattern, line, re.I)]
    assert not hits, f"{rule} on lines {hits}"


def test_it_publishes_nowhere_but_the_forks_cloud():
    for banned in ("ghcr.io", "pypa/gh-action-pypi-publish", "packages: write", "helm push"):
        assert banned not in TEXT, banned


def test_every_deploy_runs_a_script_that_exists():
    for job in ("deploy", "deploy-aws", "deploy-gcp"):
        step = next(s for s in _workflow()["jobs"][job]["steps"] if s.get("name") == "Deploy")
        script = step["run"].split()[0]
        assert (REPO / script).is_file(), script


def test_names_come_from_variables():
    for job in ("deploy", "deploy-aws", "deploy-gcp"):
        step = next(s for s in _workflow()["jobs"][job]["steps"] if s.get("name") == "Deploy")
        literal = {k: v for k, v in step["env"].items()
                   if not re.fullmatch(r"\$\{\{ (vars|steps)\.[\w.]+ \}\}", v)}
        assert not literal, (job, literal)


def test_every_uses_is_pinned_to_a_commit():
    uses = re.findall(r"uses:\s*(\S+)(.*)", TEXT)
    assert uses
    for ref, comment in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), ref
        assert re.fullmatch(r"\s*#\s*v\d+\.\d+\.\d+", comment), ref


def test_every_deploy_passes_its_target():
    for job, name in (("deploy", "AZURE_DEPLOY_TARGET"), ("deploy-aws", "AWS_DEPLOY_TARGET"),
                      ("deploy-gcp", "GCP_DEPLOY_TARGET")):
        step = next(s for s in _workflow()["jobs"][job]["steps"] if s.get("name") == "Deploy")
        assert step["env"].get(name) == f"${{{{ vars.{name} }}}}", (job, name)
