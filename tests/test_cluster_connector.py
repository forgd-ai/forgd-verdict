"""The findings connector's federation in cluster-aks, cluster-eks and cluster-gke.

With `connector_enabled` false, each module must evaluate exactly as it did
before the variable existed. With it true, it must bind the connector's
service account to the store's READER identity and change nothing else.

Evaluated by terraform itself from the module's own expressions, with no
provider, as test_cluster_eks.py and test_cluster_gke.py do: nothing here
may call a cloud.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import test_cluster_eks as eks
import test_cluster_gke as gke
import yaml
from test_app_ecs import _attr, _blocks, _walk

ROOT = Path(__file__).resolve().parent.parent
MODULES = ROOT / "deploy" / "terraform" / "modules"
AKS = MODULES / "cluster-aks"

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

ON = {"connector_enabled": True, "connector_service_account": "fv-connector",
      "namespace": "forgd-x"}


def _variable(module: str, name: str) -> str:
    text = (MODULES / module / "variables.tf").read_text(encoding="utf-8")
    return {labels[0]: inner for k, labels, inner in _blocks(text)
            if k == "variable"}[name]


@pytest.mark.parametrize("module", ["cluster-aks", "cluster-eks", "cluster-gke"])
def test_the_variable_is_off_by_default(module):
    assert _attr(_variable(module, "connector_enabled"), "default") == "false"
    assert _attr(_variable(module, "connector_service_account"), "default") \
        == '"forgd-verdict-connector"'


# --- cluster-aks ---------------------------------------------------------------

AKS_REQUIRED = {
    "resource_group_name": "rg", "location": "uksouth", "cluster_name": "aks",
    "writer_identity_id": "/subscriptions/0/resourceGroups/rg/providers/"
                          "Microsoft.ManagedIdentity/userAssignedIdentities/writer",
    "reader_identity_id": "/subscriptions/0/resourceGroups/rg/providers/"
                          "Microsoft.ManagedIdentity/userAssignedIdentities/reader",
    "writer_service_account": "forgd-verdict-writer",
    "reader_service_account": "forgd-verdict-reader",
}


def _aks_credentials() -> dict[str, str]:
    text = (AKS / "main.tf").read_text(encoding="utf-8")
    return {labels[1]: inner for k, labels, inner in _blocks(text)
            if k == "resource" and labels[0] == "azurerm_federated_identity_credential"}


def _aks_evaluate(tmp_path: Path, **variables) -> dict[str, dict[str, str]]:
    """name -> the parent identity and subject of every federated credential
    that would be created, from main.tf's own attribute expressions."""
    parts = []
    for name, body in _aks_credentials().items():
        entry = (f"{{ {name} = {{ parent = {_attr(body, 'user_assigned_identity_id')}, "
                 f"subject = {_attr(body, 'subject')} }} }}")
        count = _attr(body, "count")
        parts.append(entry if count is None else f"({count}) == 1 ? {entry} : {{}}")
    shutil.copy(AKS / "variables.tf", tmp_path / "variables.tf")
    (tmp_path / "main.tf").write_text(
        f'output "credentials" {{\n  value = merge({", ".join(parts)})\n}}\n', encoding="utf-8")
    (tmp_path / "terraform.tfvars.json").write_text(
        json.dumps({**AKS_REQUIRED, **variables}), encoding="utf-8")
    for cmd in (["init", "-input=false", "-no-color"],
                ["apply", "-auto-approve", "-input=false", "-no-color"]):
        out = subprocess.run([terraform, f"-chdir={tmp_path}", *cmd],
                             capture_output=True, text=True, timeout=120)
        assert out.returncode == 0, out.stderr
    out = subprocess.run([terraform, f"-chdir={tmp_path}", "output", "-json"],
                         capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)["credentials"]["value"]


def _aks_before(namespace: str = "forgd") -> dict[str, dict[str, str]]:
    """What the module federated before connector_enabled existed."""
    return {
        "writer": {"parent": AKS_REQUIRED["writer_identity_id"],
                   "subject": f"system:serviceaccount:{namespace}:forgd-verdict-writer"},
        "reader": {"parent": AKS_REQUIRED["reader_identity_id"],
                   "subject": f"system:serviceaccount:{namespace}:forgd-verdict-reader"},
    }


@requires_terraform
def test_aks_default_federates_what_it_did_before(tmp_path):
    assert _aks_evaluate(tmp_path) == _aks_before()


@requires_terraform
def test_aks_enabled_adds_only_the_connector_on_the_reader_identity(tmp_path):
    got = _aks_evaluate(tmp_path, **ON)
    assert got == {**_aks_before("forgd-x"), "connector": {
        "parent": AKS_REQUIRED["reader_identity_id"],
        "subject": "system:serviceaccount:forgd-x:fv-connector"}}


def test_aks_refuses_the_writer_or_dashboard_service_account():
    body = _aks_credentials()["connector"]
    [lifecycle] = _walk(body, "lifecycle")
    conditions = [" ".join(_attr(b, "condition").split()) for b in _walk(lifecycle, "precondition")]
    assert ("!contains([var.writer_service_account, var.reader_service_account], "
            "var.connector_service_account)") in conditions


# --- cluster-gke ---------------------------------------------------------------

def _gke_before(namespace: str = "forgd") -> dict[str, dict[str, str]]:
    pool = "example-project.svc.id.goog"
    out = {}
    for role in ("writer", "reader"):
        email = gke.REQUIRED[f"{role}_email"]
        out[role] = {
            "service_account_id": f"projects/example-project/serviceAccounts/{email}",
            "role": "roles/iam.workloadIdentityUser",
            "member": f"serviceAccount:{pool}[{namespace}/forgd-verdict-{role}]",
        }
    return out


@requires_terraform
def test_gke_default_binds_what_it_did_before(tmp_path):
    assert gke._bindings(tmp_path) == _gke_before()


@requires_terraform
def test_gke_enabled_adds_only_the_connector_on_the_reader_account(tmp_path):
    got = gke._bindings(tmp_path, **ON)
    reader = gke.REQUIRED["reader_email"]
    assert got == {**_gke_before("forgd-x"), "connector": {
        "service_account_id": f"projects/example-project/serviceAccounts/{reader}",
        "role": "roles/iam.workloadIdentityUser",
        "member": "serviceAccount:example-project.svc.id.goog[forgd-x/fv-connector]"}}


def test_gke_refuses_the_writer_or_dashboard_service_account():
    conditions = gke._conditions(gke._binding(), "precondition")
    assert ("!var.connector_enabled || !contains([var.writer_service_account, "
            "var.reader_service_account], var.connector_service_account)") in conditions


# --- cluster-eks ---------------------------------------------------------------

EKS_ARN = "arn:aws:eks:us-east-1:123456789012:cluster/c"


def _pod_trust(namespace: str, service_account) -> dict:
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "pods.eks.amazonaws.com"},
        "Action": ["sts:AssumeRole", "sts:TagSession"],
        "Condition": {"StringEquals": {
            "aws:RequestTag/eks-cluster-arn": EKS_ARN,
            "aws:RequestTag/kubernetes-namespace": namespace,
            "aws:RequestTag/kubernetes-service-account": service_account}}}]}


def _eks_trust(tmp_path, **variables) -> dict[str, str]:
    exprs = {r: f'local.pod_identity_trust["{r}"]' for r in ("writer", "reader", "lb_controller")}
    return eks._evaluate(tmp_path, exprs, **variables)


@requires_terraform
def test_eks_default_trust_is_byte_identical_to_before(tmp_path):
    """The JSON string is what store-s3 puts on the role; any change to it,
    even a one-element list for a string, is a change to the plan."""
    got = _eks_trust(tmp_path)
    before = {
        "writer": _pod_trust("forgd", "forgd-verdict-writer"),
        "reader": _pod_trust("forgd", "forgd-verdict-reader"),
        "lb_controller": _pod_trust("kube-system", "aws-load-balancer-controller"),
    }
    # jsonencode sorts keys and writes no whitespace.
    assert got == {r: json.dumps(v, separators=(",", ":"), sort_keys=True)
                   for r, v in before.items()}


@requires_terraform
def test_eks_enabled_adds_the_connector_to_the_reader_trust_only(tmp_path):
    (tmp_path / "off").mkdir()
    (tmp_path / "on").mkdir()
    off = {r: json.loads(v) for r, v in _eks_trust(tmp_path / "off", namespace="forgd-x").items()}
    on = {r: json.loads(v) for r, v in _eks_trust(tmp_path / "on", **ON).items()}
    assert on["writer"] == off["writer"]
    assert on["lb_controller"] == off["lb_controller"]
    assert on["reader"] == _pod_trust("forgd-x", ["forgd-verdict-reader", "fv-connector"])


def _irsa_subjects(tmp_path, **variables) -> dict[str, list[str]]:
    data = {labels[1]: inner for k, labels, inner in
            _blocks((eks.MODULE / "main.tf").read_text(encoding="utf-8"))
            if k == "data" and labels[0] == "aws_iam_policy_document"}
    body = data["irsa_trust"]
    start = body.index("for_each =") + len("for_each =")
    end = "\n  } : {}) : {}"
    for_each = body[start:body.index(end, start) + len(end)].strip()
    [statement] = _walk(data["irsa_trust"], "statement")
    sub = next(c for c in _walk(statement, "condition") if ":sub" in _attr(c, "variable"))
    values = _attr(sub, "values").replace("each.value", "v")
    return eks._evaluate(tmp_path, {"subjects": f"{{ for k, v in {for_each} : k => {values} }}"},
                         identity_mode="irsa", **variables)["subjects"]


@requires_terraform
def test_eks_irsa_default_subjects_are_as_before(tmp_path):
    assert _irsa_subjects(tmp_path) == {
        "writer": ["system:serviceaccount:forgd:forgd-verdict-writer"],
        "reader": ["system:serviceaccount:forgd:forgd-verdict-reader"],
        "lb_controller": ["system:serviceaccount:kube-system:aws-load-balancer-controller"],
    }


@requires_terraform
def test_eks_irsa_enabled_adds_the_connector_to_the_reader_only(tmp_path):
    assert _irsa_subjects(tmp_path, **ON) == {
        "writer": ["system:serviceaccount:forgd-x:forgd-verdict-writer"],
        "reader": ["system:serviceaccount:forgd-x:forgd-verdict-reader",
                   "system:serviceaccount:forgd-x:fv-connector"],
        "lb_controller": ["system:serviceaccount:kube-system:aws-load-balancer-controller"],
    }


def test_eks_association_is_gated_and_on_the_reader_role():
    connector = eks._resources("aws_eks_pod_identity_association")["connector"]
    assert _attr(connector, "count") == "var.connector_enabled && local.pod_identity ? 1 : 0"
    assert _attr(connector, "role_arn") == "var.reader_role_arn"
    assert _attr(connector, "service_account") == "var.connector_service_account"
    assert _attr(connector, "namespace") == "var.namespace"
    [lifecycle] = _walk(connector, "lifecycle")
    conditions = eks._conditions(lifecycle, "precondition")
    assert "var.reader_role_arn != var.writer_role_arn" in conditions
    assert ("!contains([var.writer_service_account, var.reader_service_account], "
            "var.connector_service_account)") in conditions


SUBNETS = {"public_subnet_ids": ["subnet-a", "subnet-b"]}


@requires_terraform
@pytest.mark.parametrize("mode", ["pod_identity", "irsa"])
def test_eks_hint_names_the_connector_only_when_enabled(tmp_path, mode):
    (tmp_path / "off").mkdir()
    (tmp_path / "on").mkdir()
    off = yaml.safe_load(eks._evaluate(tmp_path / "off", ["helm_values_hint"],
                                       identity_mode=mode, namespace="forgd-x",
                                       **SUBNETS)["helm_values_hint"])
    on = yaml.safe_load(eks._evaluate(tmp_path / "on", ["helm_values_hint"],
                                      identity_mode=mode, **SUBNETS, **ON)["helm_values_hint"])
    assert set(off["serviceAccounts"]) == {"writer", "reader"}
    assert "connector" not in off["ingress"]
    connector = on["serviceAccounts"].pop("connector")
    ingress = on["ingress"].pop("connector")
    assert ingress == {"annotations": {"alb.ingress.kubernetes.io/subnets": "subnet-a,subnet-b"}}
    assert on == off
    # The chart puts the reader's annotations on the connector's account.
    assert connector == {"name": "fv-connector"}


def test_no_connector_binding_names_a_writer_identity():
    """Across the three modules, nothing gated on the connector mentions the
    writer's identity except to refuse it."""
    aks = _aks_credentials()["connector"]
    assert "var.writer_identity_id" not in aks
    gke_locals = gke._locals()["workload_identity"]
    connector_entry = gke_locals[gke_locals.index("connector"):]
    assert "writer" not in re.sub(r"\s+", " ", connector_entry.split("}")[0])
    association = eks._resources("aws_eks_pod_identity_association")["connector"]
    assert "var.writer_role_arn" not in _attr(association, "role_arn")
