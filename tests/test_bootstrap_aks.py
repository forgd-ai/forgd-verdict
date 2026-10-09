"""scripts/bootstrap_aks.sh installs cert-manager by OCI digest, not from a
chart repository index, and refuses a version override without a digest.
On a cluster with local accounts disabled it converts the kubeconfig with
kubelogin, and refuses to go on without it.

`az`, `kubectl`, `helm` and `kubelogin` are fakes first on PATH that log
their argv; `az aks show` prints FAKE_DISABLE_LOCAL_ACCOUNTS. `helm` then
exits non-zero, so a run stops at the cert-manager install and its argv can
be read.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bootstrap_aks.sh"
CHART = "oci://quay.io/jetstack/charts/cert-manager"
PINNED_DIGEST = "sha256:3396b90b7268eb1de584b96d90054d8361575983b5e352bc9abf3e26eda31d55"
OTHER_DIGEST = "sha256:" + "ab" * 32

FAKE = r'''
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps({"tool": os.path.basename(sys.argv[0]), "argv": sys.argv[1:]}) + "\n")
if os.path.basename(sys.argv[0]) == "az" and sys.argv[1:3] == ["aks", "show"]:
    print(os.environ.get("FAKE_DISABLE_LOCAL_ACCOUNTS", "false"))
if os.path.basename(sys.argv[0]) == "kubectl" and sys.argv[1:2] == ["cluster-info"] \
        and os.environ.get("FAKE_UNREACHABLE"):
    sys.stderr.write(os.environ["FAKE_UNREACHABLE"])
    sys.exit(1)
sys.exit(3 if os.path.basename(sys.argv[0]) == "helm" else 0)
'''


@pytest.fixture
def bin_dir(tmp_path):
    d = tmp_path / "bin"
    d.mkdir()
    for tool in ("az", "kubectl", "helm", "kubelogin"):
        p = d / tool
        p.write_text(f"#!{sys.executable}\n{FAKE}", encoding="utf-8")
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return d


def _run(bin_dir: Path, path: str | None = None, **env: str):
    log = bin_dir.parent / "log.jsonl"
    proc = subprocess.run(
        ["bash", str(SCRIPT), "rg-x", "aks-x", "label-x"],
        env={"PATH": f"{bin_dir}:{path or os.environ['PATH']}", "HOME": str(bin_dir.parent),
             "FAKE_LOG": str(log), "INGRESS_CLASS": "webapprouting.kubernetes.azure.com",
             **env},
        capture_output=True, text=True, timeout=60,
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return proc, calls


def _helm(calls: list[dict]) -> list[list[str]]:
    return [c["argv"] for c in calls if c["tool"] == "helm"]


def _flag(argv: list[str], name: str) -> str:
    return argv[argv.index(name) + 1]


def test_defaults_install_the_pinned_chart_by_digest_and_add_no_repository(bin_dir):
    proc, calls = _run(bin_dir)
    assert proc.returncode == 3, proc.stderr
    (argv,) = _helm(calls)
    assert argv[:4] == ["upgrade", "--install", "cert-manager", f"{CHART}@{PINNED_DIGEST}"], argv
    assert _flag(argv, "--version") == "v1.16.3"
    assert "helm repo" not in SCRIPT.read_text(encoding="utf-8")


def test_a_version_override_without_a_digest_is_refused_before_any_call(bin_dir):
    proc, calls = _run(bin_dir, CERT_MANAGER_VERSION="v1.17.0")
    assert proc.returncode == 1
    assert calls == []
    assert "CERT_MANAGER_DIGEST" in proc.stderr
    assert f"helm pull {CHART} --version v1.17.0" in proc.stderr


def test_a_version_override_with_a_digest_installs_that_digest(bin_dir):
    proc, calls = _run(bin_dir, CERT_MANAGER_VERSION="v1.17.0", CERT_MANAGER_DIGEST=OTHER_DIGEST)
    assert proc.returncode == 3, proc.stderr
    (argv,) = _helm(calls)
    assert argv[3] == f"{CHART}@{OTHER_DIGEST}"
    assert _flag(argv, "--version") == "v1.17.0"


@pytest.mark.parametrize("digest", [
    "3396b90b7268eb1de584b96d90054d8361575983b5e352bc9abf3e26eda31d55",
    "sha256:3396b90b",
    "sha256:" + "AB" * 32,
    "sha512:" + "ab" * 64,
    "sha256:" + "ab" * 32 + "\nsha256:x",
])
def test_a_malformed_digest_is_refused_before_any_call(bin_dir, digest):
    proc, calls = _run(bin_dir, CERT_MANAGER_DIGEST=digest)
    assert proc.returncode == 1
    assert calls == []
    assert "CERT_MANAGER_DIGEST must be sha256:" in proc.stderr


def _tools(calls: list[dict]) -> list[str]:
    return [" ".join([c["tool"], *c["argv"][:2]]) for c in calls]


def test_local_accounts_disabled_converts_the_kubeconfig_before_kubectl(bin_dir):
    proc, calls = _run(bin_dir, FAKE_DISABLE_LOCAL_ACCOUNTS="true")
    assert proc.returncode == 3, proc.stderr
    assert _tools(calls)[:4] == ["az aks show", "az aks get-credentials",
                                 "kubelogin convert-kubeconfig -l", "kubectl cluster-info"], _tools(calls)
    [show] = [c["argv"] for c in calls if c["argv"][:2] == ["aks", "show"]]
    assert _flag(show, "--query") == "disableLocalAccounts"
    [convert] = [c["argv"] for c in calls if c["tool"] == "kubelogin"]
    assert convert == ["convert-kubeconfig", "-l", "azurecli"]


def test_local_accounts_disabled_without_kubelogin_is_refused_before_kubectl(bin_dir):
    (bin_dir / "kubelogin").unlink()
    proc, calls = _run(bin_dir, path="/usr/bin:/bin", FAKE_DISABLE_LOCAL_ACCOUNTS="true")
    assert proc.returncode == 1
    assert "kubelogin is required" in proc.stderr, proc.stderr
    assert not [c for c in calls if c["tool"] in ("kubectl", "helm")]


@pytest.mark.parametrize("value", ["false", ""])
def test_local_accounts_on_needs_no_kubelogin(bin_dir, value):
    (bin_dir / "kubelogin").unlink()
    proc, calls = _run(bin_dir, path="/usr/bin:/bin", FAKE_DISABLE_LOCAL_ACCOUNTS=value)
    assert proc.returncode == 3, proc.stderr
    assert _tools(calls)[:3] == ["az aks show", "az aks get-credentials", "kubectl cluster-info"], _tools(calls)


def test_an_unexpected_local_accounts_value_is_refused_before_kubectl(bin_dir):
    proc, calls = _run(bin_dir, FAKE_DISABLE_LOCAL_ACCOUNTS="None")
    assert proc.returncode == 1
    assert "disableLocalAccounts=None" in proc.stderr, proc.stderr
    assert not [c for c in calls if c["tool"] in ("kubectl", "helm")]


def test_an_unreachable_api_server_names_both_causes_and_where_to_read(bin_dir):
    """A private API server off this network and a caller with no AKS RBAC
    role both surface as a bare kubectl error."""
    error = "Unable to connect to the server: dial tcp: lookup aks-x-priv.privatelink: no such host\n"
    proc, calls = _run(bin_dir, FAKE_UNREACHABLE=error)
    assert proc.returncode != 0
    assert _tools(calls)[-1] == "kubectl cluster-info", _tools(calls)
    assert error in proc.stderr
    assert "deploy/terraform/README.md" in proc.stderr and "Reaching the AKS API" in proc.stderr
    assert "private" in proc.stderr and "Azure Kubernetes Service RBAC" in proc.stderr
    readme = (ROOT / "deploy" / "terraform" / "README.md").read_text(encoding="utf-8")
    assert "\n### Reaching the AKS API\n" in readme
