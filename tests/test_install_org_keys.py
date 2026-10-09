"""Every documented install names orgIds / otelTokens keys that the policy
file it loads actually reads.

The chart turns orgIds.<key> into FORGD_ORG_ID_<KEY> and otelTokens.<key>
into FORGD_OTEL_TOKEN_<KEY>; policy.yaml resolves only the names it lists.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CHART = REPO / "deploy" / "helm" / "forgd-verdict"
AKS_OUTPUTS = REPO / "deploy" / "terraform" / "examples" / "aks" / "outputs.tf"
HELM_README = REPO / "deploy" / "helm" / "README.md"
BOOTSTRAP_AKS = REPO / "scripts" / "bootstrap_aks.sh"

KEY = re.compile(r"\b(orgIds|otelTokens)\.([A-Za-z0-9_-]+)=")
POLICY_FILE = re.compile(r"policy\.inline=([^\s'\"\\]+)")
PREFIX = {"orgIds": "FORGD_ORG_ID_", "otelTokens": "FORGD_OTEL_TOKEN_"}


def _aks_install_command() -> str:
    src = AKS_OUTPUTS.read_text(encoding="utf-8")
    m = re.search(r'output "helm_install_command" \{(.*?)\n\}', src, re.DOTALL)
    assert m, "examples/aks/outputs.tf has no helm_install_command output"
    return " ".join(re.findall(r'^\s*"([^"]*)",?\s*$', m.group(1), re.MULTILINE))


def _readme_install_command() -> str:
    text = HELM_README.read_text(encoding="utf-8")
    section = text.split("\n## Installing\n", 1)[1].split("\n## ", 1)[0]
    m = re.search(r"```sh\n(helm upgrade --install .*?)\n```", section, re.DOTALL)
    assert m, "deploy/helm/README.md § Installing has no helm upgrade --install block"
    return m.group(1)


def _bootstrap_aks_install_command() -> str:
    text = BOOTSTRAP_AKS.read_text(encoding="utf-8")
    m = re.search(r"^ *(helm upgrade --install .*?)\n *\.\.\.", text, re.DOTALL | re.MULTILINE)
    assert m, "scripts/bootstrap_aks.sh prints no helm upgrade --install command"
    return m.group(1)


def _install_commands() -> dict[str, str]:
    commands = {p.name: p.read_text(encoding="utf-8")
                for p in sorted(CHART.glob("values-*.example.yaml"))}
    commands["aks/outputs.tf helm_install_command"] = _aks_install_command()
    commands["deploy/helm/README.md § Installing"] = _readme_install_command()
    commands["scripts/bootstrap_aks.sh"] = _bootstrap_aks_install_command()
    return commands


def _live_placeholders(policy: Path) -> set[str]:
    live = "\n".join(line for line in policy.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))
    return set(re.findall(r"\$(FORGD_(?:ORG_ID|OTEL_TOKEN)_[A-Z0-9_]+)", live))


COMMANDS = _install_commands()


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_install_names_an_org_id(name):
    assert any(kind == "orgIds" for kind, _ in KEY.findall(COMMANDS[name])), (
        f"{name}: the install sets no orgIds.<key>, so otel.orgs[].id stays unresolved")


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_install_keys_match_live_policy_placeholders(name):
    text = COMMANDS[name]
    [policy] = set(POLICY_FILE.findall(text)) or {"policy.yaml"}
    live = _live_placeholders(REPO / policy)
    missing = sorted(
        f"{kind}.{key} -> ${PREFIX[kind]}{key.upper().replace('-', '_')}"
        for kind, key in KEY.findall(text)
        if f"{PREFIX[kind]}{key.upper().replace('-', '_')}" not in live)
    assert not missing, f"{name} loads {policy}, which never reads: {missing}"
