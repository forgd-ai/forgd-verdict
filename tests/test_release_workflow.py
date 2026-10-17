"""release.yml's shape: which jobs run where and when, what has to happen
before anything is pushed, and that docs/RELEASING.md describes the same
gates.

The tag path runs only on a real release, so a mistake in it surfaces as a
failed release (v1.0.0 failed at the chart attestation). These tests read
the workflow and pin what a release depends on. Each names the mutation
that makes it fail.
"""

from __future__ import annotations

import pathlib
import re

import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
RELEASE = REPO / ".github" / "workflows" / "release.yml"
RELEASING = REPO / "docs" / "RELEASING.md"

THIS_REPO = "github.repository == 'forgd-ai/forgd-verdict'"
TAG_PUSH = "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"
PUBLISHING_JOBS = {"images", "chart", "pypi", "github-release"}
# An image lookup as the workflow runs it, not the release notes' mention.
INSPECT = 'docker buildx imagetools inspect "$IMAGE:'
GATES = {"verify", "on-main", "ci"}


def _workflow() -> dict:
    return yaml.safe_load(RELEASE.read_text(encoding="utf-8"))


def _jobs() -> dict:
    return _workflow()["jobs"]


def _needs(job: dict) -> set[str]:
    needs = job.get("needs", [])
    return {needs} if isinstance(needs, str) else set(needs)


def _when(job: dict, step: dict | None = None) -> str:
    """The job's `if:` and the step's, which must both hold."""
    return " && ".join(str(c) for c in (job.get("if"), (step or {}).get("if")) if c)


def _publishes(step: dict) -> bool:
    """A step that writes to a registry, PyPI or the GitHub Release, or logs
    in to do so."""
    uses = step.get("uses", "")
    run = step.get("run", "")
    return (uses.startswith(("pypa/gh-action-pypi-publish@", "actions/attest-build-provenance@",
                             "docker/login-action@"))
            or "helm push" in run or "gh release create" in run)


# --- triggers and where it runs -------------------------------------------------

def test_it_runs_on_a_v_tag_push_and_by_hand_only():
    """Mutation: add a branch push trigger."""
    on = _workflow()[True]  # PyYAML reads the key `on` as True.
    assert set(on) == {"push", "workflow_dispatch"}
    assert on["push"] == {"tags": ["v*"]}


def test_every_job_is_skipped_outside_this_repository():
    """A fork that pushes a tag runs nothing. Mutation: drop a job's `if:`."""
    for name, job in _jobs().items():
        assert THIS_REPO in str(job.get("if", "")), name


def test_every_publishing_step_needs_a_tag_push_in_this_repository():
    """Mutation: drop the condition from any step that logs in, pushes,
    attests, publishes or creates the release."""
    found = 0
    for name, job in _jobs().items():
        for step in job.get("steps", []):
            if _publishes(step):
                found += 1
                when = _when(job, step)
                assert TAG_PUSH in when and THIS_REPO in when, (name, step.get("name"))
    assert found >= 8, found


def test_the_images_push_only_on_a_tag_push_in_this_repository():
    """build-push-action builds either way; `push` decides. Mutation: push
    on a dispatch."""
    [build] = [s for s in _jobs()["images"]["steps"]
               if s.get("uses", "").startswith("docker/build-push-action@")]
    push = build["with"]["push"]
    assert TAG_PUSH in push and THIS_REPO in push, push


# --- order ------------------------------------------------------------------------

def test_nothing_is_published_before_the_gates():
    """The commit is on main, ci has passed on it, and the versions match
    and are new. Mutation: drop one of them from a publishing job's needs."""
    jobs = _jobs()
    for name in PUBLISHING_JOBS:
        assert _needs(jobs[name]) >= GATES, name
    assert "wheels" in _needs(jobs["pypi"])


def test_the_github_release_comes_last():
    """Mutation: drop images, chart or pypi from its needs."""
    jobs = _jobs()
    assert _needs(jobs["github-release"]) == set(jobs) - {"github-release"}
    assert not jobs["github-release"].get("environment")


def test_the_main_check_runs_on_a_tag_push():
    """Mutation: drop the ancestry check or its condition."""
    [check] = [s for s in _jobs()["on-main"]["steps"]
               if "merge-base --is-ancestor" in s.get("run", "")]
    assert check["if"] == TAG_PUSH


# --- logins -----------------------------------------------------------------------

def _docker_login(step: dict) -> bool:
    return (step.get("uses", "").startswith("docker/login-action@")
            and step.get("with", {}).get("registry") == "ghcr.io")


def test_the_image_build_logs_in_to_ghcr_first():
    """build-push-action and imagetools read Docker's credentials.
    Mutation: move the login after the build."""
    steps = _jobs()["images"]["steps"]
    for i, step in enumerate(steps):
        if (step.get("uses", "").startswith("docker/build-push-action@")
                or INSPECT in step.get("run", "")):
            assert any(_docker_login(s) for s in steps[:i]), step.get("name")


def test_each_script_logs_in_with_the_tool_it_then_uses():
    """`helm registry login` for helm, `docker login` for docker, earlier in
    the same script. Mutation: log in to helm with docker, or after the
    lookup."""
    pairs = {"helm push": "helm registry login ghcr.io", "helm show chart \"$CHART_REPO":
             "helm registry login ghcr.io"}
    checked = 0
    for name, job in _jobs().items():
        job_logged_in = any(_docker_login(s) for s in job.get("steps", []))
        for step in job.get("steps", []):
            run = step.get("run", "")
            for use, login in pairs.items():
                if use in run:
                    checked += 1
                    assert login in run and run.index(login) < run.index(use), (name, step["name"])
            if INSPECT in run and not job_logged_in:
                checked += 1
                assert "docker login ghcr.io" in run, (name, step["name"])
                assert run.index("docker login ghcr.io") < run.index(INSPECT)
    assert checked >= 3, checked


# --- already published ------------------------------------------------------------

def _step(job: str, text: str) -> dict:
    [step] = [s for s in _jobs()[job]["steps"] if text in s.get("run", "")]
    return step


def test_verify_looks_up_the_chart_both_image_tags_and_both_wheels():
    """Mutation: drop a lookup, or the ingest tag from it."""
    assert "helm show chart" in _step("verify", "helm show chart")["run"]
    images = _step("verify", INSPECT)["run"]
    assert 'for tag in "$VERSION" "$VERSION-ingest"' in images
    pypi = _step("verify", "pypi.org/pypi")["run"]
    assert "for name in $PROJECTS" in pypi and "404)" in pypi and "200)" in pypi
    version = _step("verify", "projects=")["run"]
    assert 'echo "projects=$core_name $hook_name"' in version
    assert "packaging/forgd-verdict-hook/pyproject.toml" in version


def test_each_push_looks_its_version_up_again_first():
    """A re-run of a failed job checks again rather than pushing twice.
    Mutation: drop a repeated lookup, or move it after the push."""
    jobs = _jobs()
    images = jobs["images"]["steps"]
    lookup = next(i for i, s in enumerate(images) if INSPECT in s.get("run", ""))
    build = next(i for i, s in enumerate(images)
                 if s.get("uses", "").startswith("docker/build-push-action@"))
    assert lookup < build
    push = _step("chart", "helm push")["run"]
    assert push.index("helm show chart") < push.index("helm push")
    pypi = jobs["pypi"]["steps"]
    lookup = next(i for i, s in enumerate(pypi) if "pypi.org/pypi" in s.get("run", ""))
    publish = next(i for i, s in enumerate(pypi)
                   if s.get("uses", "").startswith("pypa/gh-action-pypi-publish@"))
    attest = next(i for i, s in enumerate(pypi)
                  if s.get("uses", "").startswith("actions/attest-build-provenance@"))
    assert lookup < attest < publish
    release = _step("github-release", "gh release create")["run"]
    assert release.index("gh release view") < release.index("gh release create")


def test_a_lookup_that_cannot_tell_fails_the_release():
    """Only "not found" (or 404) counts as absent, and "denied" only before
    the first release. Mutation: treat any lookup error as absent."""
    for job, text in (("verify", "helm show chart"), ("verify", INSPECT),
                      ("images", INSPECT), ("chart", "helm push")):
        run = _step(job, text)["run"]
        assert re.search(r'\*\)\s*echo "::error::could not tell whether', run), (job, text)
        assert "no_release_yet" in run, (job, text)
    for job in ("verify", "pypi"):
        run = _step(job, "pypi.org/pypi")["run"]
        assert re.search(r'\*\) echo "::error::could not tell whether', run), job


# --- docs/RELEASING.md ------------------------------------------------------------

def _reviewers_item() -> str:
    text = RELEASING.read_text(encoding="utf-8")
    start = text.index("**Required reviewers on `pypi`.**")
    return " ".join(text[start:text.index("\n3. ", start)].split())


def test_releasing_md_names_the_environment_the_workflow_uses():
    """Mutation: rename the environment in either file."""
    environments = {j["environment"] for j in _jobs().values() if j.get("environment")}
    assert environments == {"pypi"}
    item = _reviewers_item()
    assert "The images, chart and PyPI jobs all run in `pypi`" in item
    assert "a release asks for one approval" in item
    gated = {n for n, j in _jobs().items() if j.get("environment")}
    assert gated == {"images", "chart", "pypi"}


def test_releasing_md_says_the_github_release_runs_last_with_no_environment():
    """Mutation: give the GitHub Release job an environment."""
    item = _reviewers_item()
    assert "The GitHub Release job runs after all three have succeeded and has no environment" in item
    job = _jobs()["github-release"]
    assert not job.get("environment") and {"images", "chart", "pypi"} <= _needs(job)
