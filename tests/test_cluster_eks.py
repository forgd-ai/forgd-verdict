"""The cluster-eks module keeps the properties cluster-aks keeps.

Parsed from the .tf source, because nothing here may call AWS and a plan
needs credentials. Each check first asserts it found what it is about, so a
rename or a parse that matches nothing fails rather than passing on an
empty list.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import terraform_render
import yaml
from test_app_ecs import _attr, _blocks, _walk

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "deploy" / "terraform" / "modules" / "cluster-eks"
MAIN = MODULE / "main.tf"
VARIABLES = MODULE / "variables.tf"
OUTPUTS = MODULE / "outputs.tf"
EKS_VALUES = ROOT / "deploy" / "helm" / "forgd-verdict" / "values-eks.example.yaml"

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

# The only roles a pod in this cluster may be associated with.
ASSOCIABLE_ROLES = {
    "var.writer_role_arn",
    "var.reader_role_arn",
    "var.control_role_arn",
    "aws_iam_role.lb_controller[0].arn",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code(text: str) -> str:
    """`text` without comments or the contents of quoted strings, so a word
    in a description or an error message does not count as code."""
    text = re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)
    text = re.sub(r"<<-?(\w+)\n.*?^\s*\1$", "", text, flags=re.S | re.M)
    return re.sub(r"(#|//).*$", "", text, flags=re.M)


def _resources(kind: str) -> dict[str, str]:
    return {labels[1]: inner for k, labels, inner in _blocks(_text(MAIN))
            if k == "resource" and labels[0] == kind}


def _variables() -> dict[str, str]:
    return {labels[0]: inner for k, labels, inner in _blocks(_text(VARIABLES))
            if k == "variable"}


def _cluster() -> str:
    clusters = _resources("aws_eks_cluster")
    assert list(clusters) == ["this"], sorted(clusters)
    return clusters["this"]


def _outputs() -> dict[str, str]:
    return {labels[0]: inner for k, labels, inner in _blocks(_text(OUTPUTS)) if k == "output"}


# The data sources the module reads, as literals, so an expression using
# them can be evaluated without a provider.
DATA_STUBS = {
    "data.aws_partition.current.partition": '"aws"',
    "data.aws_region.current.region": '"us-east-1"',
    "data.aws_caller_identity.current.account_id": '"123456789012"',
}


def _locals() -> dict[str, str]:
    """name -> expression text, for every local in main.tf."""
    body = next(inner for k, _, inner in _blocks(_text(MAIN)) if k == "locals")
    starts = list(re.finditer(r"^  (\w+)\s*=", body, re.M))
    return {m.group(1): body[m.end():(starts[i + 1].start() if i + 1 < len(starts) else len(body))].strip()
            for i, m in enumerate(starts)}


def _output_expr(name: str) -> str:
    m = re.search(r"^  value\s*=\s*(.*?)\n  description\s*=", _outputs()[name], re.S | re.M)
    assert m, name
    return m.group(1)


def _evaluate(tmp_path: Path, exprs: dict[str, str] | list[str], **variables) -> dict:
    """Each expression's value, computed by terraform with the module's
    variables.tf and the locals the expressions read. A list names outputs
    and evaluates their `value`.

    No provider is involved, so this runs without AWS: the data sources in
    DATA_STUBS become literals, and any other reference to a resource or
    data source is left undeclared and fails here."""
    if isinstance(exprs, list):
        exprs = {name: _output_expr(name) for name in exprs}
    exprs = dict(exprs)
    for ref, literal in DATA_STUBS.items():
        exprs = {n: e.replace(ref, literal) for n, e in exprs.items()}
    all_locals = _locals()
    needed, pending = {}, list(exprs.values())
    while pending:
        for name in re.findall(r"\blocal\.(\w+)", pending.pop()):
            if name not in needed:
                expr = all_locals[name]
                for ref, literal in DATA_STUBS.items():
                    expr = expr.replace(ref, literal)
                needed[name] = expr
                pending.append(expr)
    shutil.copy(VARIABLES, tmp_path / "variables.tf")
    (tmp_path / "main.tf").write_text(
        "locals {\n" + "".join(f"  {n} = {e}\n" for n, e in needed.items()) + "}\n"
        + "".join(f'output "{n}" {{\n  value = {e}\n}}\n' for n, e in exprs.items()),
        encoding="utf-8",
    )
    out = _apply(tmp_path, **variables)
    assert out.returncode == 0, out.stderr
    out = subprocess.run([terraform, f"-chdir={tmp_path}", "output", "-json"],
                         capture_output=True, text=True, timeout=60, check=True)
    return {k: v["value"] for k, v in json.loads(out.stdout).items()}


def _apply(tmp_path: Path, **variables) -> subprocess.CompletedProcess:
    """`terraform apply` in `tmp_path` with the module's required variables
    and `variables`. Copies variables.tf there if nothing has, so a call
    with no outputs checks the variables' validations and nothing else."""
    if not (tmp_path / "variables.tf").exists():
        shutil.copy(VARIABLES, tmp_path / "variables.tf")
    (tmp_path / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}), encoding="utf-8")
    out = subprocess.run([terraform, f"-chdir={tmp_path}", "init", "-input=false", "-no-color"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return subprocess.run([terraform, f"-chdir={tmp_path}", "apply", "-auto-approve", "-input=false", "-no-color"],
                          capture_output=True, text=True, timeout=120)


REQUIRED = {"cluster_name": "c", "vpc_id": "vpc-0", "subnet_ids": ["subnet-0", "subnet-1"],
            "writer_role_arn": "arn:aws:iam::123456789012:role/w",
            "reader_role_arn": "arn:aws:iam::123456789012:role/r"}


def _conditions(body: str, kind: str) -> list[str]:
    """The `condition` expression of every `kind` block (precondition,
    validation) in `body`, with whitespace collapsed."""
    return [" ".join(_attr(b, "condition").split()) for b in _walk(body, kind)
            if _attr(b, "condition") is not None]


# --- the shape of the module ---------------------------------------------

def test_the_module_is_exactly_main_variables_and_outputs():
    """Every check here reads main.tf. A resource in a fourth file, or in
    variables.tf or outputs.tf, is one none of them sees. The vendored
    iam_policy.json is data, not Terraform."""
    assert sorted(f.name for f in MODULE.glob("*.tf")) == ["main.tf", "outputs.tf", "variables.tf"]
    assert sorted(f.name for f in MODULE.glob("*.tf.json")) == []
    for other in (OUTPUTS, VARIABLES):
        assert not re.search(r'^\s*(resource|data|locals|module|provider)\b', _text(other), re.M), other.name


def test_nothing_is_installed_into_the_cluster_from_terraform():
    """`helm upgrade` runs on the chart's cadence, not on `terraform apply`,
    and a helm or kubernetes provider needs the cluster to exist before the
    plan that creates it. The controller and the chart are installed with
    the commands in the outputs."""
    for path in sorted(MODULE.glob("*.tf")):
        raw = _text(path)
        assert not re.search(r'^\s*(resource|data)\s+"(helm_|kubernetes_|kubectl_)', raw, re.M), path.name
        assert not re.search(r'^\s*provider\s+"(helm|kubernetes|kubectl)"', raw, re.M), path.name
        assert not re.search(r'^\s*module\s+"', raw, re.M), path.name

    terraform = next(inner for k, _, inner in _blocks(_text(MAIN)) if k == "terraform")
    providers = _walk(terraform, "required_providers")
    assert len(providers) == 1
    assert re.findall(r"^\s*(\w+)\s*=\s*\{", providers[0], re.M) == ["aws"]

    # Not vacuous: the parser does see the module's resources.
    assert _cluster() and _resources("aws_eks_node_group")


# --- the API endpoint ----------------------------------------------------

# The only strings in the module allowed to name a world-open range: the
# messages that refuse one.
WORLD_OPEN_PROSE = {
    "main.tf": [
        ('"endpoint_public_access is true but public_access_cidrs is empty. EKS would open the API endpoint'
         ' to 0.0.0.0/0; list the ranges that may reach it, or turn public access off."'),
    ],
    "variables.tf": [
        ('"Who may reach the public API endpoint. Required, non-empty, when endpoint_public_access is true;'
         ' there is no 0.0.0.0/0 default."'),
        '"api_allowed_cidrs may not contain a /0 such as 0.0.0.0/0 or ::/0. List the ranges that need the API."',
    ],
}


def test_the_public_endpoint_is_off_by_default_and_never_open_to_everyone():
    """EKS answers an empty public_access_cidrs with 0.0.0.0/0. The endpoint
    is the Kubernetes API that holds the forgd-verdict secret."""
    config = _walk(_cluster(), "vpc_config")
    assert len(config) == 1
    config = config[0]
    assert _attr(config, "endpoint_private_access") == "true"
    assert _attr(config, "endpoint_public_access") == "var.endpoint_public_access"
    # The only CIDRs the endpoint takes are the caller's.
    assert _attr(config, "public_access_cidrs") == (
        "var.endpoint_public_access ? var.public_access_cidrs : null")

    variables = _variables()
    assert _attr(variables["endpoint_public_access"], "default") == "false"
    assert _attr(variables["public_access_cidrs"], "default") == "[]"

    # No default anywhere in the module is a world-open CIDR.
    for name, body in variables.items():
        default = _attr(body, "default") or ""
        assert "0.0.0.0" not in default and "::/0" not in default, name
    for path in sorted(MODULE.glob("*.tf")):
        text = re.sub(r"^\s*(#|//).*$", "", _text(path), flags=re.M)
        for prose in WORLD_OPEN_PROSE.get(path.name, ()):
            assert prose in text, (path.name, prose)
            text = text.replace(prose, "")
        for world in ("0.0.0.0", "::/0"):
            assert world not in text, (path.name, world)


def test_public_access_with_no_cidrs_is_refused_at_plan_time():
    assert "!var.endpoint_public_access || length(var.public_access_cidrs) > 0" in _conditions(
        _cluster(), "precondition")


@requires_terraform
@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0", "10.0.0.0/0", "0::0/0"])
def test_the_private_endpoint_cannot_be_opened_to_everyone(tmp_path, cidr):
    out = _apply(tmp_path, api_allowed_cidrs=["10.0.0.0/8", cidr])
    assert out.returncode != 0
    assert "may not contain a /0" in " ".join(out.stderr.split()), out.stderr


@requires_terraform
def test_listed_ranges_may_reach_the_private_endpoint(tmp_path):
    """The /0 check refuses only a /0."""
    out = _apply(tmp_path, api_allowed_cidrs=["10.0.0.0/8", "192.168.1.1/32", "fd00::/8"],
                 api_allowed_security_group_ids=["sg-0123abcd"])
    assert out.returncode == 0, out.stderr


def test_the_private_endpoint_admits_only_the_listed_callers_on_443():
    """The endpoint's network interfaces admit the cluster security group,
    which the nodes carry too. Callers are admitted through a group only
    the control plane holds, so a rule for them opens nothing on a node."""
    config = _walk(_cluster(), "vpc_config")[0]
    assert re.sub(r"\s", "", _attr(config, "security_group_ids") or "") == "[aws_security_group.api.id]"
    assert "cluster_security_group_id" not in _code(_text(MAIN))

    api = _resources("aws_security_group")
    assert sorted(api) == ["api"], sorted(api)
    # No inline ingress or egress: every rule is one of the two below.
    assert [k for k, _, _ in _blocks(api["api"])] == ["lifecycle"]
    assert _resources("aws_security_group_rule") == {}

    rules = _resources("aws_vpc_security_group_ingress_rule")
    assert sorted(rules) == ["api_from_cidr", "api_from_security_group"], sorted(rules)
    for body in rules.values():
        assert _attr(body, "security_group_id") == "aws_security_group.api.id"
        assert (_attr(body, "ip_protocol"), _attr(body, "from_port"), _attr(body, "to_port")) == ('"tcp"', "443", "443")
    assert _attr(rules["api_from_security_group"], "for_each") == "toset(var.api_allowed_security_group_ids)"
    assert _attr(rules["api_from_security_group"], "referenced_security_group_id") == "each.value"
    assert _attr(rules["api_from_cidr"], "for_each") == "toset(var.api_allowed_cidrs)"
    assert {_attr(rules["api_from_cidr"], k) for k in ("cidr_ipv4", "cidr_ipv6")} == {
        'strcontains(each.value, ":") ? null : each.value',
        'strcontains(each.value, ":") ? each.value : null',
    }
    for name in ("api_allowed_cidrs", "api_allowed_security_group_ids"):
        assert _attr(_variables()[name], "default") == "[]", name


# --- cluster access ------------------------------------------------------

def test_listed_admins_get_the_cluster_admin_policy_and_nothing_wider():
    """When CI applies, the bootstrap admin entry is CI's, and without a
    listed principal no human can reach the cluster."""
    entries = _resources("aws_eks_access_entry")
    assert sorted(entries) == ["admin"], sorted(entries)
    assert _attr(entries["admin"], "for_each") == "toset(var.cluster_admin_principal_arns)"
    assert _attr(entries["admin"], "principal_arn") == "each.value"
    assert _attr(entries["admin"], "type") in (None, '"STANDARD"')

    associations = _resources("aws_eks_access_policy_association")
    assert sorted(associations) == ["admin"], sorted(associations)
    admin = associations["admin"]
    assert _attr(admin, "for_each") == "aws_eks_access_entry.admin"
    assert _attr(admin, "principal_arn") == "each.value.principal_arn"
    assert _attr(admin, "policy_arn") == (
        '"arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"')
    scopes = _walk(admin, "access_scope")
    assert len(scopes) == 1 and _attr(scopes[0], "type") == '"cluster"', scopes
    assert _attr(_variables()["cluster_admin_principal_arns"], "default") == "[]"


@requires_terraform
@pytest.mark.parametrize("arn", [
    "arn:aws:sts::123456789012:assumed-role/Admin/alice",
    "arn:aws:iam::123456789012:group/admins",
    "Admin",
])
def test_an_admin_must_be_an_iam_role_or_user(tmp_path, arn):
    """EKS keys an access entry on the role, not a session of it."""
    out = _apply(tmp_path, cluster_admin_principal_arns=["arn:aws:iam::123456789012:role/Admin", arn])
    assert out.returncode != 0
    assert "must be an IAM role or user ARN" in " ".join(out.stderr.split()), out.stderr


@requires_terraform
def test_role_and_user_admins_are_accepted(tmp_path):
    out = _apply(tmp_path, cluster_admin_principal_arns=[
        "arn:aws:iam::123456789012:role/Admin", "arn:aws:iam::123456789012:user/alice",
        "arn:aws-us-gov:iam::123456789012:role/path/Admin"])
    assert out.returncode == 0, out.stderr


@requires_terraform
def test_the_namespace_gets_readiness_gates_before_the_chart(tmp_path):
    """With target-type ip, a rolling update without readiness gates stops
    an old pod before its replacement is a healthy ALB target, and governed
    prompts get 502s in between. The webhook injects gates only into pods
    created in a labelled namespace, so the label comes before the chart."""
    command = _evaluate(tmp_path, ["lb_controller_namespace_command"], namespace="forgd-x")["lb_controller_namespace_command"]
    steps = [shlex.split(s) for s in command.split(" && ")]
    assert steps[0][:4] == ["kubectl", "create", "namespace", "forgd-x"], steps
    assert steps[1] == ["kubectl", "label", "namespace", "forgd-x",
                        "elbv2.k8s.aws/pod-readiness-gate-inject=enabled", "--overwrite"], steps
    target_type = {a["alb.ingress.kubernetes.io/target-type"]
                   for a in _eks_example_ingress_annotations()}
    assert target_type == {"ip"}, target_type


def _eks_example_ingress_annotations() -> list[dict]:
    ingress = yaml.safe_load(EKS_VALUES.read_text(encoding="utf-8"))["ingress"]
    return [ingress["annotations"], ingress["diagnostics"]["annotations"], ingress["dashboard"]["annotations"]]


# --- secrets -------------------------------------------------------------

def test_kubernetes_secrets_are_envelope_encrypted():
    """The chart's secret holds the webhook signing secret, the Compliance
    Access Key and the OTel tokens. Encryption cannot be added to a cluster
    later without a key it was never told about."""
    configs = _walk(_cluster(), "encryption_config")
    assert len(configs) == 1
    assert re.sub(r"\s", "", _attr(configs[0], "resources")) == '["secrets"]'
    provider = _walk(configs[0], "provider")
    assert len(provider) == 1 and _attr(provider[0], "key_arn") == "local.secrets_key"

    # The key is the module's own or the caller's, never nothing.
    key = re.search(r"^\s*secrets_key\s*=\s*(.+)$", _text(MAIN), re.M).group(1).strip()
    assert key == "local.create_kms_key ? aws_kms_key.secrets[0].arn : var.secrets_kms_key_arn"
    assert "enable_key_rotation     = true" in _resources("aws_kms_key")["secrets"]


# --- workload identity ---------------------------------------------------

def test_pods_are_associated_only_with_the_store_roles_and_the_controller():
    """An association is a pod's AWS identity. One naming any other role
    gives the chart's pods, or the controller's, a permission the store
    module did not scope."""
    associations = _resources("aws_eks_pod_identity_association")
    assert sorted(associations) == ["connector", "control", "lb_controller", "reader", "writer"], \
        sorted(associations)
    roles = {name: _attr(body, "role_arn") for name, body in associations.items()}
    assert roles == {
        "writer": "var.writer_role_arn",
        "reader": "var.reader_role_arn",
        "connector": "var.reader_role_arn",
        "control": "var.control_role_arn",
        "lb_controller": "aws_iam_role.lb_controller[0].arn",
    }, roles
    assert set(roles.values()) == ASSOCIABLE_ROLES

    assert _attr(associations["writer"], "service_account") == "var.writer_service_account"
    assert _attr(associations["reader"], "service_account") == "var.reader_service_account"
    assert _attr(associations["connector"], "service_account") == "var.connector_service_account"


@requires_terraform
def test_each_pod_identity_role_trusts_only_its_own_service_account_in_this_cluster(tmp_path):
    """Without these conditions any pod identity association in the account
    could take the role: another cluster's, or this cluster's for another
    service account."""
    # Each role gets its own entry: the outputs store-s3 takes, and the
    # controller's role.
    for role in ("writer", "reader"):
        assert " ".join(_output_expr(f"{role}_assume_role_policy").split()) == (
            f'local.irsa ? data.aws_iam_policy_document.irsa_trust["{role}"].json'
            f' : local.pod_identity_trust["{role}"]')
    assert _attr(_resources("aws_iam_role")["lb_controller"], "assume_role_policy") == (
        'local.irsa ? data.aws_iam_policy_document.irsa_trust["lb_controller"].json'
        ' : local.pod_identity_trust["lb_controller"]')

    exprs = {role: f'local.pod_identity_trust["{role}"]' for role in ("writer", "reader", "lb_controller")}
    got = _evaluate(tmp_path, exprs, cluster_name="prod-eks", namespace="forgd-x",
                    writer_service_account="w-sa", reader_service_account="r-sa")
    subjects = {"writer": ("forgd-x", "w-sa"), "reader": ("forgd-x", "r-sa"),
                "lb_controller": ("kube-system", "aws-load-balancer-controller")}
    for role, (namespace, service_account) in subjects.items():
        [statement] = json.loads(got[role])["Statement"]
        assert statement["Principal"] == {"Service": "pods.eks.amazonaws.com"}, role
        assert statement["Condition"] == {
            "StringEquals": {
                "aws:RequestTag/eks-cluster-arn": "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks",
                "aws:RequestTag/kubernetes-namespace": namespace,
                "aws:RequestTag/kubernetes-service-account": service_account,
            },
        }, role


@requires_terraform
def test_the_readme_trust_policy_is_the_one_the_module_produces(tmp_path):
    readme = (ROOT / "deploy" / "terraform" / "README.md").read_text(encoding="utf-8")
    section = readme[readme.index("## Composing `cluster-eks` with `store-s3`"):]
    documented = json.loads(re.search(r"```json\n(.*?)```", section, re.S).group(1))
    got = _evaluate(tmp_path, {"writer": 'local.pod_identity_trust["writer"]'}, cluster_name="forgd-verdict")
    assert documented == json.loads(got["writer"])


def test_the_trusted_cluster_arn_is_not_read_from_the_cluster():
    """store-s3's roles take this trust policy, and the cluster's
    associations take those roles."""
    locals_ = _locals()
    assert "aws_eks_cluster" not in locals_["cluster_arn"] + locals_["pod_identity_trust"]
    assert "local.cluster_arn" in locals_["pod_identity_trust"]


def test_no_association_disables_the_session_tags_the_trust_matches():
    associations = _resources("aws_eks_pod_identity_association")
    assert associations
    for name, body in associations.items():
        assert _attr(body, "disable_session_tags") in (None, "false"), name


def test_the_dashboard_cannot_be_given_the_writer_role():
    """The dashboard is the one service a human signs into. With the writer
    role it could rewrite the findings it displays.

    Under Pod Identity the check is on the reader's association, so it runs
    before the association is created; nothing orders an output's check
    before it when the ARNs are unknown at plan. That association does not
    exist under IRSA, where the only use of the ARNs is helm_values_hint,
    so the check is there too."""
    check = "var.reader_role_arn != var.writer_role_arn"
    reader = _resources("aws_eks_pod_identity_association")["reader"]
    lifecycles = _walk(reader, "lifecycle")
    assert len(lifecycles) == 1, lifecycles
    assert check in _conditions(lifecycles[0], "precondition")
    assert check in _conditions(_outputs()["helm_values_hint"], "precondition")


def test_pod_identity_is_the_default_and_the_only_alternative_is_irsa():
    identity = _variables()["identity_mode"]
    assert _attr(identity, "default") == '"pod_identity"'
    assert 'contains(["pod_identity", "irsa"], var.identity_mode)' in _conditions(identity, "validation")


# --- nodes ---------------------------------------------------------------

def test_nodes_are_on_demand_by_default():
    """A reclaimed spot node takes the verdict server with it, and a
    governed prompt that cannot reach it fails."""
    capacity = _variables()["node_capacity_type"]
    assert _attr(capacity, "default") == '"ON_DEMAND"'
    assert _attr(_resources("aws_eks_node_group")["this"], "capacity_type") == "var.node_capacity_type"


@requires_terraform
@pytest.mark.parametrize("mode", ["pod_identity", "irsa"])
def test_the_hint_annotates_the_service_accounts_only_under_irsa(tmp_path, mode):
    """Under Pod Identity an eks.amazonaws.com/role-arn annotation makes the
    EKS webhook inject a web identity token, which the AWS SDK tries first,
    so every pod fails to reach S3."""
    hint = yaml.safe_load(_evaluate(tmp_path, ["helm_values_hint"], identity_mode=mode)["helm_values_hint"])
    sas = hint["serviceAccounts"]
    assert set(sas) == {"writer", "reader"}, sas
    if mode == "pod_identity":
        for which in ("writer", "reader"):
            assert "eks.amazonaws.com/role-arn" not in sas[which].get("annotations", {}), sas
    else:
        assert sas["writer"]["annotations"] == {"eks.amazonaws.com/role-arn": REQUIRED["writer_role_arn"]}
        assert sas["reader"]["annotations"] == {"eks.amazonaws.com/role-arn": REQUIRED["reader_role_arn"]}


# --- the load balancer controller ----------------------------------------

def _example_oidc_secret() -> str:
    dashboard = yaml.safe_load(EKS_VALUES.read_text(encoding="utf-8"))["ingress"]["dashboard"]
    return json.loads(dashboard["annotations"]["alb.ingress.kubernetes.io/auth-idp-oidc"])["secretName"]


def test_the_default_oidc_secret_is_the_one_the_eks_example_names():
    default = _attr(_variables()["dashboard_oidc_secret_name"], "default")
    assert default == f'"{_example_oidc_secret()}"', default


@requires_terraform
def test_the_controller_may_read_the_dashboard_oidc_secret_and_nothing_else(tmp_path):
    """Chart 3.5.0 grants the controller no secret access, and one secret it
    cannot read fails the whole ingress group. The grant is a namespaced
    Role naming that one secret, read-only, bound to the controller alone,
    and the command can be run again."""
    command = _evaluate(tmp_path, ["lb_controller_namespace_command"], namespace="forgd-x",
                        dashboard_oidc_secret_name="the-secret")["lb_controller_namespace_command"]
    steps = []
    for step in command.split(" && "):
        if step.startswith("kubectl label "):
            continue
        # Each step renders its object and applies it, so a second run
        # updates rather than failing on AlreadyExists.
        create, sep, apply = step.partition(" | ")
        assert sep and shlex.split(apply) == ["kubectl", "apply", "-f", "-"], step
        argv = shlex.split(create)
        assert argv[-3:] == ["--dry-run=client", "-o", "yaml"], step
        steps.append(argv[:-3])
    creates = {s[2]: s for s in steps if s[:2] == ["kubectl", "create"] and s[2] in ("role", "rolebinding")}
    assert set(creates) == {"role", "rolebinding"}, steps
    assert not any(w in ("clusterrole", "clusterrolebinding") for s in steps for w in s), steps
    assert not any("allowAllSecrets" in w for s in steps for w in s), steps

    def flags(argv: list[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for word in argv:
            if word.startswith("--") and "=" in word:
                k, v = word[2:].split("=", 1)
                out.setdefault(k, []).append(v)
        return out

    role, binding = flags(creates["role"]), flags(creates["rolebinding"])
    assert role == {"namespace": ["forgd-x"], "verb": ["get,list,watch"],
                    "resource": ["secrets"], "resource-name": ["the-secret"]}, role
    assert binding == {"namespace": ["forgd-x"], "role": [creates["role"][3]],
                       "serviceaccount": ["kube-system:aws-load-balancer-controller"]}, binding


# --- the controller chart --------------------------------------------------

LB_CHART = "aws-load-balancer-controller-3.5.0.tgz"
LB_CHART_SHA256 = "45051f634b33e10baccb3354d0681b7de787c60445e599fa276e0c9aedd4ccd5"


def _install_command(tmp_path: Path) -> str:
    expr = (_output_expr("lb_controller_install_command")
            .replace("aws_eks_cluster.this.name", '"c"')
            .replace("aws_iam_role.lb_controller[0].arn", '"arn:aws:iam::123456789012:role/lb"'))
    tmp_path.mkdir()
    return _evaluate(tmp_path, {"cmd": expr})["cmd"]


def test_the_controller_chart_is_installed_from_a_checked_file_not_a_repository():
    out = _outputs()["lb_controller_install_command"]
    assert "helm repo" not in out
    assert f"curl -fsSLo {LB_CHART} https://aws.github.io/eks-charts/{LB_CHART}" in out
    assert f"echo '{LB_CHART_SHA256}  {LB_CHART}' > {LB_CHART}.sha256" in out
    assert (f"if command -v sha256sum >/dev/null; then sha256sum -c {LB_CHART}.sha256; "
            f"else shasum -a 256 -c {LB_CHART}.sha256; fi") in out
    assert f"helm upgrade --install aws-load-balancer-controller ./{LB_CHART}" in out


def _fake_tools(tmp_path: Path, checksum_tools: tuple[str, ...]) -> tuple[Path, Path]:
    """A PATH holding fake curl and helm, which log their argv, and the
    named real checksum tools; nothing else."""
    bin_dir, log = tmp_path / "bin", tmp_path / "calls.log"
    bin_dir.mkdir()
    for tool, body in (("curl", 'printf "%s\\n" "curl $*" >> "$LOG"; printf junk > "$2"'),
                       ("helm", 'printf "%s\\n" "helm $*" >> "$LOG"')):
        (bin_dir / tool).write_text(f"#!/bin/sh\n{body}\n")
        (bin_dir / tool).chmod(0o755)
    for tool in checksum_tools:
        real = shutil.which(tool)
        if real is None:
            pytest.skip(f"{tool} is not installed")
        (bin_dir / tool).symlink_to(real)
    return bin_dir, log


def _run_install(command: str, tmp_path: Path, tools: tuple[str, ...]):
    bin_dir, log = _fake_tools(tmp_path, tools)
    work = tmp_path / "work"
    work.mkdir()
    proc = subprocess.run(["/bin/sh", "-c", command], cwd=work, capture_output=True, text=True,
                          timeout=60, env={"PATH": str(bin_dir), "LOG": str(log)})
    return proc, log.read_text().splitlines() if log.exists() else []


@requires_terraform
@pytest.mark.parametrize("tools", [("sha256sum",), ("shasum",)], ids=["sha256sum", "shasum"])
def test_a_chart_whose_hash_differs_is_not_installed(tmp_path, tools):
    command = _install_command(tmp_path / "tf")
    proc, calls = _run_install(command, tmp_path, tools)
    assert proc.returncode != 0
    assert [c.split()[0] for c in calls] == ["curl"], calls


@requires_terraform
@pytest.mark.parametrize("tools", [("sha256sum",), ("shasum",)], ids=["sha256sum", "shasum"])
def test_a_chart_whose_hash_matches_is_installed_from_the_file(tmp_path, tools):
    junk = hashlib.sha256(b"junk").hexdigest()
    command = _install_command(tmp_path / "tf").replace(LB_CHART_SHA256, junk)
    proc, calls = _run_install(command, tmp_path, tools)
    assert proc.returncode == 0, proc.stderr
    assert calls[1].startswith(f"helm upgrade --install aws-load-balancer-controller ./{LB_CHART} "), calls


# --- NetworkPolicy -------------------------------------------------------

@requires_terraform
@pytest.mark.parametrize("enabled", [None, True, False], ids=["default", "true", "false"])
def test_the_vpc_cni_enforces_network_policy_unless_turned_off(tmp_path, enabled):
    """The default VPC CNI enforces no NetworkPolicy, and the chart's
    trusted_header guard is satisfied by networkPolicy.enabled with the
    ingress controller's selectors."""
    variables = dict(REQUIRED) if enabled is None else {**REQUIRED, "enable_network_policy": enabled}
    rendered = terraform_render.render_module(tmp_path, "cluster-eks", variables)
    addons = rendered.get("aws_eks_addon.vpc_cni", MISSING_ADDON)
    if enabled is False:
        assert addons == [], addons
        return
    assert isinstance(addons, list) and len(addons) == 1, addons
    (addon,) = addons
    assert addon["addon_name"] == "vpc-cni"
    assert addon["cluster_name"] == "c"
    assert json.loads(addon["configuration_values"]) == {"enableNetworkPolicy": "true"}
    assert addon["resolve_conflicts_on_create"] == "OVERWRITE"
    assert addon["tags"] == rendered["aws_eks_addon.pod_identity_agent"][0]["tags"]


MISSING_ADDON = "<aws_eks_addon.vpc_cni is not in the module>"


def test_the_nodes_hold_the_cni_policy_the_add_on_runs_under():
    (attachment,) = [inner for k, labels, inner in _blocks(_text(MAIN))
                     if k == "resource" and labels == ["aws_iam_role_policy_attachment", "node"]]
    assert '"AmazonEKS_CNI_Policy"' in attachment


def test_the_readme_documents_the_network_policy_add_on():
    readme = (ROOT / "deploy" / "terraform" / "README.md").read_text(encoding="utf-8")
    section = readme.split("\n## Composing `cluster-eks` with `store-s3`\n", 1)[1].split("\n## ", 1)[0]
    assert re.search(r'^variable "enable_network_policy"', VARIABLES.read_text(encoding="utf-8"), re.M)
    assert "`enable_network_policy`" in section
    assert "`vpc-cni`" in section and "enableNetworkPolicy" in section


# -- iam_policy.json is upstream's, attributed in NOTICE -----------------------

IAM_POLICY = MODULE / "iam_policy.json"
# docs/install/iam_policy.json at kubernetes-sigs/aws-load-balancer-controller
# v3.5.0, compared against upstream when it was copied.
IAM_POLICY_SHA256 = "16f232c9d9f79366fe949c4550ad517a202380058a9e48d45a4e215044a20a6a"


def _iam_policy_tag() -> str:
    m = re.search(r"iam_policy\.json is docs/install/iam_policy\.json from\s*#\s*"
                  r"kubernetes-sigs/aws-load-balancer-controller at tag (v[\d.]+), unmodified",
                  MAIN.read_text())
    assert m, "main.tf no longer says where iam_policy.json comes from"
    return m.group(1)


def test_the_lb_controller_iam_policy_is_unmodified():
    assert hashlib.sha256(IAM_POLICY.read_bytes()).hexdigest() == IAM_POLICY_SHA256


def test_notice_attributes_the_lb_controller_iam_policy():
    notice = " ".join((ROOT / "NOTICE").read_text(encoding="utf-8").split())
    tag = _iam_policy_tag()
    assert "deploy/terraform/modules/cluster-eks/iam_policy.json" in notice
    assert f"https://github.com/kubernetes-sigs/aws-load-balancer-controller at tag {tag}" in notice
    assert "Apache License, Version 2.0" in notice.split("cluster-eks/iam_policy.json", 1)[1]
