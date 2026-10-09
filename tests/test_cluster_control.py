"""The dashboard control identity's federation in cluster-aks, cluster-eks and cluster-gke.

With `control_enabled` false each module binds exactly what it did before
(test_cluster_connector.py pins that for the default). With it true, each
binds the chart's control service account to the store's control identity
and nothing else, and refuses a control identity or service account that is
the writer's, the reader's or the connector's.

Evaluated by terraform from the modules' own expressions, with no provider.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import test_cluster_connector as conn
import test_cluster_eks as eks
import test_cluster_gke as gke
import yaml
from test_app_ecs import _attr, _walk

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

CONTROL_SA = "fv-control"


@pytest.mark.parametrize("module", ["cluster-aks", "cluster-eks", "cluster-gke"])
def test_the_control_is_off_by_default(module):
    assert _attr(conn._variable(module, "control_enabled"), "default") == "false"
    assert _attr(conn._variable(module, "control_service_account"), "default") == '"forgd-verdict-control"'


def _evaluate_conditions(module: Path, conditions: list[str], required: dict, root: Path, **variables) -> list[bool]:
    shutil.copy(module / "variables.tf", root / "variables.tf")
    (root / "main.tf").write_text("".join(
        f'output "c{i}" {{\n  value = {c}\n}}\n' for i, c in enumerate(conditions)), encoding="utf-8")
    (root / "terraform.tfvars.json").write_text(json.dumps({**required, **variables}), encoding="utf-8")
    for cmd in (["init", "-input=false", "-no-color"], ["apply", "-auto-approve", "-input=false", "-no-color"]):
        out = subprocess.run([terraform, f"-chdir={root}", *cmd], capture_output=True, text=True, timeout=120)
        assert out.returncode == 0, out.stderr
    out = subprocess.run([terraform, f"-chdir={root}", "output", "-json"],
                         capture_output=True, text=True, timeout=60, check=True)
    got = json.loads(out.stdout)
    return [got[f"c{i}"]["value"] for i in range(len(conditions))]


# --- cluster-aks ---------------------------------------------------------------

AKS_CONTROL_ID = ("/subscriptions/0/resourceGroups/rg/providers/"
                  "Microsoft.ManagedIdentity/userAssignedIdentities/control")
AKS_ON = {"control_enabled": True, "control_identity_id": AKS_CONTROL_ID, "control_service_account": CONTROL_SA}


@requires_terraform
def test_aks_enabled_adds_only_the_control_credential(tmp_path):
    got = conn._aks_evaluate(tmp_path, **AKS_ON)
    assert got == {**conn._aks_before(), "control": {
        "parent": AKS_CONTROL_ID, "subject": f"system:serviceaccount:forgd:{CONTROL_SA}"}}


@requires_terraform
@pytest.mark.parametrize("variables,ok", [
    ({}, True),
    ({"control_identity_id": ""}, False),
    ({"control_identity_id": conn.AKS_REQUIRED["reader_identity_id"]}, False),
    ({"control_identity_id": conn.AKS_REQUIRED["writer_identity_id"]}, False),
    ({"control_service_account": "forgd-verdict-reader"}, False),
    ({"control_service_account": "forgd-verdict-writer"}, False),
    ({"control_service_account": "fv-connector", "connector_enabled": True,
      "connector_service_account": "fv-connector"}, False),
])
def test_aks_refuses_a_control_identity_or_account_that_is_not_its_own(tmp_path, variables, ok):
    [lifecycle] = _walk(conn._aks_credentials()["control"], "lifecycle")
    conditions = [_attr(b, "condition") for b in _walk(lifecycle, "precondition")]
    assert len(conditions) == 2
    got = _evaluate_conditions(conn.AKS, conditions, conn.AKS_REQUIRED, tmp_path, **{**AKS_ON, **variables})
    assert all(got) is ok, (variables, got)


# --- cluster-gke ---------------------------------------------------------------

GKE_CONTROL = "forgd-dashboard-control@example-project.iam.gserviceaccount.com"
GKE_ON = {"control_enabled": True, "control_email": GKE_CONTROL, "control_service_account": CONTROL_SA}


@requires_terraform
def test_gke_enabled_adds_only_the_control_binding(tmp_path):
    got = gke._bindings(tmp_path, **GKE_ON)
    assert got == {**conn._gke_before(), "control": {
        "service_account_id": f"projects/example-project/serviceAccounts/{GKE_CONTROL}",
        "role": "roles/iam.workloadIdentityUser",
        "member": f"serviceAccount:example-project.svc.id.goog[forgd/{CONTROL_SA}]"}}


@requires_terraform
@pytest.mark.parametrize("variables,ok", [
    ({}, True),
    ({"control_email": ""}, False),
    ({"control_email": gke.REQUIRED["reader_email"]}, False),
    ({"control_email": gke.REQUIRED["writer_email"]}, False),
    ({"control_service_account": "forgd-verdict-reader"}, False),
    ({"control_service_account": "forgd-verdict-writer"}, False),
    ({"control_service_account": "fv-connector", "connector_enabled": True,
      "connector_service_account": "fv-connector"}, False),
    ({"control_enabled": False, "control_email": ""}, True),
])
def test_gke_refuses_a_control_account_that_is_not_its_own(tmp_path, variables, ok):
    conditions = [_attr(b, "condition") for b in _walk(gke._binding(), "precondition")
                  if "control" in _attr(b, "condition")]
    assert len(conditions) == 2, conditions
    got = _evaluate_conditions(gke.MODULE, conditions, gke.REQUIRED, tmp_path, **{**GKE_ON, **variables})
    assert all(got) is ok, (variables, got)


# --- cluster-eks ---------------------------------------------------------------

EKS_CONTROL = "arn:aws:iam::123456789012:role/control"
EKS_ON = {"control_enabled": True, "control_role_arn": EKS_CONTROL, "control_service_account": CONTROL_SA}


@requires_terraform
def test_eks_control_trust_names_the_control_account_only(tmp_path):
    exprs = {r: f'local.pod_identity_trust["{r}"]' for r in ("writer", "reader", "lb_controller", "control")}
    got = {r: json.loads(v) for r, v in eks._evaluate(tmp_path, exprs, **EKS_ON).items()}
    assert got["control"] == conn._pod_trust("forgd", CONTROL_SA)
    assert got["reader"] == conn._pod_trust("forgd", "forgd-verdict-reader")
    assert got["writer"] == conn._pod_trust("forgd", "forgd-verdict-writer")


@requires_terraform
def test_eks_irsa_adds_only_the_control_subject(tmp_path):
    got = conn._irsa_subjects(tmp_path, **EKS_ON)
    assert got == {
        "writer": ["system:serviceaccount:forgd:forgd-verdict-writer"],
        "reader": ["system:serviceaccount:forgd:forgd-verdict-reader"],
        "control": [f"system:serviceaccount:forgd:{CONTROL_SA}"],
        "lb_controller": ["system:serviceaccount:kube-system:aws-load-balancer-controller"],
    }


def test_eks_association_is_gated_and_on_the_control_role():
    association = eks._resources("aws_eks_pod_identity_association")["control"]
    assert _attr(association, "count") == "var.control_enabled && local.pod_identity ? 1 : 0"
    assert _attr(association, "role_arn") == "var.control_role_arn"
    assert _attr(association, "service_account") == "var.control_service_account"
    conditions = [_attr(b, "condition") for b in _walk(association, "precondition")]
    assert conditions == ["local.control_ok", "local.control_sa_ok"], conditions
    hint = [_attr(b, "condition") for b in _walk(eks._outputs()["helm_values_hint"], "precondition")]
    assert {"local.control_ok", "local.control_sa_ok"} <= set(hint), hint


def test_eks_control_trust_output_is_null_unless_enabled():
    assert " ".join(eks._output_expr("control_assume_role_policy").split()) == (
        'var.control_enabled ? (local.irsa ? data.aws_iam_policy_document.irsa_trust["control"].json '
        ': local.pod_identity_trust["control"]) : null')


@requires_terraform
@pytest.mark.parametrize("variables,ok", [
    ({}, True),
    ({"control_role_arn": ""}, False),
    ({"control_role_arn": eks.REQUIRED["reader_role_arn"]}, False),
    ({"control_role_arn": eks.REQUIRED["writer_role_arn"]}, False),
    ({"control_service_account": "forgd-verdict-reader"}, False),
    ({"control_service_account": "forgd-verdict-writer"}, False),
    ({"control_service_account": "fv-connector", "connector_enabled": True,
      "connector_service_account": "fv-connector"}, False),
    ({"control_enabled": False, "control_role_arn": ""}, True),
])
def test_eks_refuses_a_control_role_or_account_that_is_not_its_own(tmp_path, variables, ok):
    got = eks._evaluate(tmp_path, {"a": "local.control_ok", "b": "local.control_sa_ok"}, **{**EKS_ON, **variables})
    assert (got["a"] and got["b"]) is ok, (variables, got)


@requires_terraform
@pytest.mark.parametrize("mode", ["pod_identity", "irsa"])
def test_eks_hint_names_the_control_account_only_when_enabled(tmp_path, mode):
    (tmp_path / "off").mkdir()
    (tmp_path / "on").mkdir()
    off = yaml.safe_load(eks._evaluate(tmp_path / "off", ["helm_values_hint"], identity_mode=mode)["helm_values_hint"])
    on = yaml.safe_load(eks._evaluate(tmp_path / "on", ["helm_values_hint"], identity_mode=mode,
                                      **EKS_ON)["helm_values_hint"])
    assert "control" not in off["serviceAccounts"]
    control = on["serviceAccounts"].pop("control")
    assert on == off
    want = {"name": CONTROL_SA}
    if mode == "irsa":
        want["annotations"] = {"eks.amazonaws.com/role-arn": EKS_CONTROL}
    assert control == want
