"""examples/deployment-repo: the skeleton of a repository that deploys
forgd-verdict from its public releases without forking it.

It is pinned to this release (cut_release.sh moves it), its Terraform root
is examples/aks with the modules sourced by git ref, its policy is the
shipped one, and the checks its ci.yml runs pass here: the policy check
and the chart render are run from the workflow's own steps, against this
tree's code and chart.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "deployment-repo"
INFRA = EXAMPLE / "infra"
AKS = ROOT / "deploy" / "terraform" / "examples" / "aks"
CHART = ROOT / "deploy" / "helm" / "forgd-verdict"
CI = EXAMPLE / ".github" / "workflows" / "ci.yml"
DEPLOY = EXAMPLE / ".github" / "workflows" / "deploy.yml"
GIT = "git::https://github.com/forgd-ai/forgd-verdict.git//deploy/terraform/modules/"


def _policy_vars(text: str) -> set[str]:
    code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    return set(re.findall(r"\$([A-Z][A-Z0-9_]*)", code))


def _version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def _release() -> dict:
    return yaml.safe_load((EXAMPLE / "release.yaml").read_text(encoding="utf-8"))


def _steps(path: Path) -> list[dict]:
    jobs = yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]
    (job,) = jobs.values()
    return job["steps"]


def _step(path: Path, name: str) -> dict:
    return next(s for s in _steps(path) if s.get("name") == name)


def _local_sources(text: str) -> str:
    return re.sub(re.escape(GIT) + r'([a-z0-9-]+)\?ref=v[^"]+"', r'../../modules/\1"', text)


def _outputs(text: str) -> dict[str, str]:
    return dict(re.findall(r'^output "(\w+)" \{\n(.*?)^\}', text, re.M | re.S))


# --- pinned to this release -------------------------------------------------

def test_the_example_runs_this_release():
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text(encoding="utf-8"))
    assert _release() == {"version": _version(), "chart": chart["version"]}


def test_the_modules_are_sourced_at_this_release():
    refs = re.findall(re.escape(GIT) + r'([a-z0-9-]+)\?ref=v([^"]+)"', (INFRA / "main.tf").read_text(encoding="utf-8"))
    assert [v for _, v in refs] == [_version()] * 3
    local = re.findall(r'source = "\.\./\.\./modules/([a-z0-9-]+)"', (AKS / "main.tf").read_text(encoding="utf-8"))
    assert [m for m, _ in refs] == local


# --- infra is examples/aks ---------------------------------------------------

def test_infra_main_is_examples_aks_with_git_sources():
    """Apart from the header comment."""
    def body(text: str) -> str:
        return text.split("\n\n", 1)[1]
    assert body(_local_sources((INFRA / "main.tf").read_text(encoding="utf-8"))) == \
        body((AKS / "main.tf").read_text(encoding="utf-8"))


def test_infra_variables_are_examples_aks():
    assert (INFRA / "variables.tf").read_text(encoding="utf-8") == (AKS / "variables.tf").read_text(encoding="utf-8")


def test_infra_outputs_are_examples_aks_but_the_install_command():
    """deploy.yml installs the chart, so the hand install is left out."""
    ours = _outputs((INFRA / "outputs.tf").read_text(encoding="utf-8"))
    theirs = _outputs((AKS / "outputs.tf").read_text(encoding="utf-8"))
    theirs.pop("helm_install_command")
    assert ours == theirs


def test_infra_holds_only_the_shared_files_and_access():
    assert sorted(p.name for p in INFRA.glob("*.tf")) == ["access.tf", "main.tf", "outputs.tf", "variables.tf"]


def test_the_values_name_the_service_accounts_infra_federates():
    main = (INFRA / "main.tf").read_text(encoding="utf-8")
    values = yaml.safe_load((EXAMPLE / "values.yaml").read_text(encoding="utf-8"))
    for role in ("writer", "reader"):
        name = re.search(rf'{role}_service_account = "([^"]+)"', main).group(1)
        assert values["serviceAccounts"][role]["name"] == name


def test_infra_validates_with_the_local_modules(tmp_path):
    terraform = shutil.which("terraform")
    if terraform is None:
        if os.environ.get("CI"):
            pytest.fail("terraform is not installed")
        pytest.skip("terraform is not installed")
    root = tmp_path / "infra"
    root.mkdir()
    for f in INFRA.glob("*.tf"):
        text = _local_sources(f.read_text(encoding="utf-8"))
        text = text.replace('"../../modules/', f'"{ROOT}/deploy/terraform/modules/')
        (root / f.name).write_text(re.sub(r'^\s*backend "azurerm" \{\}\n', "", text, flags=re.M), encoding="utf-8")
    init = subprocess.run([terraform, f"-chdir={root}", "init", "-backend=false", "-input=false"],
                          capture_output=True, text=True, timeout=600)
    if init.returncode != 0 and not os.environ.get("CI") and "registry.terraform.io" in init.stderr:
        pytest.skip("the azurerm provider could not be downloaded")
    assert init.returncode == 0, init.stderr
    out = subprocess.run([terraform, f"-chdir={root}", "validate", "-no-color"],
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stdout + out.stderr


# --- policy and chart: ci.yml's own steps -----------------------------------

def test_the_policy_is_the_shipped_policy():
    assert (EXAMPLE / "policy.yaml").resolve() == (ROOT / "policy.yaml").resolve()


def _run_step(name: str, replace: tuple[str, str], extra_env: dict) -> subprocess.CompletedProcess:
    step = _step(CI, name)
    script = step["run"]
    assert script.count(replace[0]) == 1, replace[0]
    names = _policy_vars((EXAMPLE / "policy.yaml").read_text(encoding="utf-8"))
    env = {k: v for k, v in os.environ.items() if k not in names}
    env.update({k: str(v) for k, v in step.get("env", {}).items() if "${{" not in str(v)})
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text(encoding="utf-8"))["version"]
    env.update({"VERSION": _version(), "CHART": chart, **extra_env})
    return subprocess.run(["bash", "-c", script.replace(*replace)], cwd=EXAMPLE, env=env,
                          capture_output=True, text=True, timeout=600)


def test_ci_checks_the_policy_with_the_release_s_command():
    run = _step(CI, "Check the policy")["run"]
    assert 'uvx --from "forgd-verdict==$VERSION" forgd-verdict policy --policy policy.yaml --check' in run


def test_ci_policy_check_passes_here():
    cli = Path(shutil.which("forgd-verdict") or "forgd-verdict")
    out = _run_step("Check the policy",
                    ('uvx --from "forgd-verdict==$VERSION" forgd-verdict', str(cli)), {})
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith("ok: policy.yaml: "), out.stdout


def test_ci_policy_check_fails_on_a_refused_policy(tmp_path):
    """The generated placeholders are not what passes it."""
    cli = Path(shutil.which("forgd-verdict") or "forgd-verdict")
    out = _run_step("Check the policy",
                    ('uvx --from "forgd-verdict==$VERSION" forgd-verdict', str(cli)),
                    {"FORGD_SINK_ENDPOINT_AZMON": "http://not-https.example/"})
    assert out.returncode == 2, out.stdout + out.stderr
    assert "collector" in out.stderr


def test_the_placeholders_cover_two_variables_on_one_line():
    """The shipped policy lists a fleet's current and previous token on
    one line."""
    text = (EXAMPLE / "policy.yaml").read_text(encoding="utf-8")
    assert any(len(_policy_vars(line)) > 1 for line in text.splitlines())
    script = _step(CI, "Check the policy")["run"]
    assert 'line.split("#", 1)[0]' in script


needs_helm = pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
LOCAL_CHART = ("chart=oci://ghcr.io/forgd-ai/charts/forgd-verdict", f"chart={CHART}")


@needs_helm
def test_ci_chart_render_passes_here():
    out = _run_step("Render the chart", LOCAL_CHART, {})
    assert out.returncode == 0, out.stderr


@needs_helm
def test_ci_refuses_a_chart_built_for_another_release():
    out = _run_step("Render the chart", LOCAL_CHART, {"VERSION": "0.0.1"})
    assert out.returncode == 1
    assert "not 0.0.1" in out.stdout + out.stderr


def test_deploy_checks_the_chart_before_rolling():
    names = [s.get("name") for s in _steps(DEPLOY)]
    assert names.index("The chart is the release's") < names.index("Roll")
    assert '[ "$app" = "$VERSION" ]' in _step(DEPLOY, "The chart is the release's")["run"]


def _set_keys(script: str) -> set[str]:
    return set(re.findall(r"--set(?:-string|-file)? ([\w.]+)=", script))


def test_deploy_sets_what_ci_renders_with():
    assert _set_keys(_step(DEPLOY, "Roll")["run"]) == _set_keys(_step(CI, "Render the chart")["run"])


# --- deploy.yml ---------------------------------------------------------------

def test_deploy_is_dispatch_only_in_the_deploy_environment():
    wf = yaml.safe_load(DEPLOY.read_text(encoding="utf-8"))
    assert set(wf[True]) == {"workflow_dispatch"}
    job = wf["jobs"]["deploy"]
    assert job["environment"] == "deploy"
    assert job["permissions"] == {"id-token": "write", "contents": "read"}
    assert "secrets." not in DEPLOY.read_text(encoding="utf-8")


def test_deploy_checks_the_build_then_runs_the_release_s_verifier():
    names = [s.get("name") for s in _steps(DEPLOY)]
    assert names.index("Roll") < names.index("Check the build") < names.index("Verify")
    assert '"$VERSION+"*' in _step(DEPLOY, "Check the build")["run"]
    verify = _step(DEPLOY, "Verify")
    assert 'uvx --from "forgd-verdict==$VERSION" forgd-verdict verify-deployment' in verify["run"]
    assert verify["env"]["VERSION"] == "${{ steps.release.outputs.version }}"


def test_deploy_moves_both_image_tags_and_checks_a_mirror_by_digest():
    roll = _step(DEPLOY, "Roll")["run"]
    assert '--set image.tag="$VERSION"' in roll
    assert '--set ingest.image.tag="$VERSION-ingest"' in roll
    assert '[ "$mirrored" = "$published" ]' in _step(DEPLOY, "The release's images")["run"]


@pytest.mark.parametrize("path", [CI, DEPLOY], ids=lambda p: p.name)
def test_no_expression_is_interpolated_into_a_shell(path):
    for step in _steps(path):
        assert "${{" not in step.get("run", ""), step.get("name")


@pytest.mark.parametrize("path", [CI, DEPLOY], ids=lambda p: p.name)
def test_downloads_are_checksummed(path):
    text = path.read_text(encoding="utf-8")
    assert text.count("curl -fsSL -o") == text.count("sha256sum --check --strict")


def test_every_deploy_variable_is_described_in_its_header():
    text = DEPLOY.read_text(encoding="utf-8")
    header = text.split("\non:", 1)[0]
    for name in set(re.findall(r"\bvars\.(\w+)", text)):
        assert re.search(rf"^#\s.*\b{name}\b", header, re.M), name


def test_deploy_does_not_create_the_namespace_and_uses_infra_s():
    """The identity may write only inside it, and infra's default is the
    workflow's."""
    roll = _step(DEPLOY, "Roll")
    assert "--create-namespace" not in roll["run"]
    assert '-n "$NAMESPACE"' in roll["run"]
    assert roll["env"]["NAMESPACE"] == "${{ vars.NAMESPACE || 'forgd' }}"
    assert '"${local.cluster_id}/namespaces/${var.namespace}"' in (INFRA / "access.tf").read_text(encoding="utf-8")
    default = re.search(r'variable "namespace" \{.*?default = "([^"]+)"', (INFRA / "variables.tf").read_text(encoding="utf-8"), re.S)
    assert default.group(1) == "forgd"


def test_a_mirroring_deploy_identity_can_read_the_digest_back():
    access = (INFRA / "access.tf").read_text(encoding="utf-8")
    assert "importImage/action" in access
    assert re.search(r'"cd_registry_reader" \{.*?role_definition_name = "AcrPull"', access, re.S)


def test_the_runner_is_configurable_for_a_private_cluster():
    job = yaml.safe_load(DEPLOY.read_text(encoding="utf-8"))["jobs"]["deploy"]
    assert job["runs-on"] == "${{ vars.DEPLOY_RUNNER || 'ubuntu-latest' }}"
    assert "private" in DEPLOY.read_text(encoding="utf-8").split("\non:", 1)[0]


# --- docs -----------------------------------------------------------------------

def test_the_readme_and_deploy_guide_point_at_both_paths():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/DEPLOY-FROM-RELEASES.md" in readme
    assert "DEPLOY-FROM-RELEASES.md" in (ROOT / "docs" / "DEPLOY.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "DEPLOY-FROM-RELEASES.md").read_text(encoding="utf-8")
    assert "examples/deployment-repo" in guide
