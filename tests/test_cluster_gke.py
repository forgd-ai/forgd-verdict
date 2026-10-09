"""The cluster-gke module keeps the properties cluster-eks keeps.

Parsed from the .tf source, because nothing here may call Google and a plan
needs credentials. Each check first asserts it found what it is about, so a
rename or a parse that matches nothing fails rather than passing on an
empty list.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from test_app_ecs import _attr, _blocks, _walk

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "deploy" / "terraform" / "modules" / "cluster-gke"
MAIN = MODULE / "main.tf"
VARIABLES = MODULE / "variables.tf"
OUTPUTS = MODULE / "outputs.tf"
GKE_VALUES = ROOT / "deploy" / "helm" / "forgd-verdict" / "values-gke.example.yaml"

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

# The only IAM resource types the module may create.
ALLOWED_IAM = {"google_service_account_iam_member", "google_kms_crypto_key_iam_member"}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _resources(kind: str) -> dict[str, str]:
    return {labels[1]: inner for k, labels, inner in _blocks(_text(MAIN))
            if k == "resource" and labels[0] == kind}


def _resource_types() -> set[str]:
    return {labels[0] for k, labels, _ in _blocks(_text(MAIN)) if k == "resource"}


def _variables() -> dict[str, str]:
    return {labels[0]: inner for k, labels, inner in _blocks(_text(VARIABLES))
            if k == "variable"}


def _cluster() -> str:
    clusters = _resources("google_container_cluster")
    assert list(clusters) == ["this"], sorted(clusters)
    return clusters["this"]


def _binding() -> str:
    bindings = _resources("google_service_account_iam_member")
    assert list(bindings) == ["workload_identity"], sorted(bindings)
    return bindings["workload_identity"]


def _locals() -> dict[str, str]:
    """name -> expression text, for every local in main.tf."""
    body = next(inner for k, _, inner in _blocks(_text(MAIN)) if k == "locals")
    starts = list(re.finditer(r"^  (\w+)\s*=", body, re.M))
    return {m.group(1): body[m.end():(starts[i + 1].start() if i + 1 < len(starts) else len(body))].strip()
            for i, m in enumerate(starts)}


def _conditions(body: str, kind: str) -> list[str]:
    """The `condition` expression of every `kind` block (precondition,
    validation) in `body`, with whitespace collapsed."""
    return [" ".join(_attr(b, "condition").split()) for b in _walk(body, kind)
            if _attr(b, "condition") is not None]


REQUIRED = {"project_id": "example-project", "cluster_name": "c", "region": "europe-west2",
            "network": "vpc", "subnetwork": "nodes",
            "writer_email": "forgd-verdict-writer@example-project.iam.gserviceaccount.com",
            "reader_email": "forgd-dashboard-reader@example-project.iam.gserviceaccount.com"}


def _evaluate(tmp_path: Path, exprs: dict[str, str], **variables) -> dict:
    """Each expression's value, computed by terraform with the module's
    variables.tf and the locals the expressions read. No provider is
    involved, so any reference to a resource or data source is left
    undeclared and fails here."""
    all_locals = _locals()
    needed, pending = {}, list(exprs.values())
    while pending:
        for name in re.findall(r"\blocal\.(\w+)", pending.pop()):
            if name not in needed:
                needed[name] = all_locals[name]
                pending.append(all_locals[name])
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


def _bindings(tmp_path: Path, **variables) -> dict[str, dict[str, str]]:
    """key -> the binding's evaluated service_account_id, role and member,
    for every instance of the workloadIdentityUser resource."""
    body = _binding()
    for_each = _attr(body, "for_each")
    attrs = {a: _attr(body, a).replace("each.value", "v").replace("each.key", "k")
             for a in ("service_account_id", "role", "member")}
    expr = ("{ for k, v in " + for_each + " : k => { "
            + ", ".join(f"{a} = {e}" for a, e in attrs.items()) + " } }")
    return _evaluate(tmp_path, {"bindings": expr}, **variables)["bindings"]


# --- the shape of the module ---------------------------------------------

def test_the_module_is_exactly_main_variables_and_outputs():
    """Every check here reads main.tf. A resource in a fourth file, or in
    variables.tf or outputs.tf, is one none of them sees."""
    assert sorted(f.name for f in MODULE.glob("*.tf")) == ["main.tf", "outputs.tf", "variables.tf"]
    assert sorted(f.name for f in MODULE.glob("*.tf.json")) == []
    for other in (OUTPUTS, VARIABLES):
        assert not re.search(r'^\s*(resource|data|locals|module|provider)\b', _text(other), re.M), other.name


def test_nothing_is_installed_into_the_cluster_from_terraform():
    """`helm upgrade` runs on the chart's cadence, not on `terraform apply`,
    and a helm or kubernetes provider needs the cluster to exist before the
    plan that creates it."""
    for path in sorted(MODULE.glob("*.tf")):
        raw = _text(path)
        assert not re.search(r'^\s*(resource|data)\s+"(helm_|kubernetes_|kubectl_)', raw, re.M), path.name
        assert not re.search(r'^\s*provider\s+"(helm|kubernetes|kubectl)"', raw, re.M), path.name
        assert not re.search(r'^\s*module\s+"', raw, re.M), path.name

    terraform_block = next(inner for k, _, inner in _blocks(_text(MAIN)) if k == "terraform")
    providers = _walk(terraform_block, "required_providers")
    assert len(providers) == 1
    assert re.findall(r"^\s*(\w+)\s*=\s*\{", providers[0], re.M) == ["google"]

    # Not vacuous: the parser does see the module's resources.
    assert _cluster() and _binding()


def test_no_project_level_iam_and_no_store_access():
    """A project binding reaches every bucket and cluster in the project.
    The store's access is store-gcs's; this module only lets two Kubernetes
    service accounts act as the accounts store-gcs made."""
    types = _resource_types()
    assert "google_container_cluster" in types, types
    assert not {t for t in types if t.startswith("google_project_iam_")}, types
    assert not {t for t in types if t.startswith(("google_storage_", "google_organization_iam_", "google_folder_iam_"))}, types
    iam = {t for t in types if "_iam_" in t}
    assert iam <= ALLOWED_IAM, iam
    assert "google_service_account_iam_member" in iam, iam


# --- the cluster ---------------------------------------------------------

def test_the_cluster_is_regional_autopilot_on_the_regular_channel():
    cluster = _cluster()
    assert _attr(cluster, "enable_autopilot") == "true"
    assert _attr(cluster, "location") == "var.region"
    assert (_attr(cluster, "network"), _attr(cluster, "subnetwork")) == ("var.network", "var.subnetwork")
    channels = _walk(cluster, "release_channel")
    assert len(channels) == 1 and _attr(channels[0], "channel") == '"REGULAR"', channels


def test_nodes_have_no_public_addresses():
    """A node with a public address is reachable from the internet, and it
    runs the pods that hold the store's credentials."""
    configs = _walk(_cluster(), "private_cluster_config")
    assert len(configs) == 1, configs
    assert _attr(configs[0], "enable_private_nodes") == "true"


@requires_terraform
@pytest.mark.parametrize("region", ["europe-west2-a", "us-central1-f"])
def test_a_zone_is_refused_as_the_location(tmp_path, region):
    out = _apply(tmp_path, region=region)
    assert out.returncode != 0
    assert "must be a region" in " ".join(out.stderr.split()), out.stderr


# --- the API endpoint ----------------------------------------------------

def _authorized_networks() -> str:
    configs = _walk(_cluster(), "master_authorized_networks_config")
    assert len(configs) == 1, configs
    return configs[0]


def test_the_api_endpoint_is_private_by_default():
    """The endpoint is the Kubernetes API that holds the forgd-verdict
    secret. Off by default, the IP endpoint is reachable from the VPC only,
    and the DNS endpoint from Google Cloud only."""
    variables = _variables()
    assert _attr(variables["endpoint_public_access"], "default") == "false"
    assert _attr(variables["dns_endpoint_allow_external_traffic"], "default") == "false"
    assert _attr(variables["dns_endpoint_allow_external_traffic"], "type") == "bool"
    assert _attr(variables["public_access_cidrs"], "default") == "[]"

    [private] = _walk(_cluster(), "private_cluster_config")
    assert _attr(private, "enable_private_endpoint") == "!var.endpoint_public_access"

    # Any Google Cloud VM, in any customer's project, is not a caller.
    assert _attr(_authorized_networks(), "gcp_public_cidrs_access_enabled") == "false"

    [endpoints] = _walk(_cluster(), "control_plane_endpoints_config")
    [dns] = _walk(endpoints, "dns_endpoint_config")
    assert _attr(dns, "allow_external_traffic") == "var.dns_endpoint_allow_external_traffic"

    # No default anywhere in the module is a world-open CIDR.
    for name, body in variables.items():
        default = _attr(body, "default") or ""
        assert "0.0.0.0" not in default and "::/0" not in default, name


def test_public_access_with_no_cidrs_is_refused_at_plan_time():
    """GKE with public access and no authorized networks admits every
    address. The check compares two variables, so it is a precondition."""
    lifecycles = _walk(_cluster(), "lifecycle")
    assert len(lifecycles) == 1, lifecycles
    assert "!var.endpoint_public_access || length(var.public_access_cidrs) > 0" in _conditions(
        lifecycles[0], "precondition")


@requires_terraform
@pytest.mark.parametrize("public", [True, False])
def test_the_listed_cidrs_are_the_only_authorized_networks(tmp_path, public):
    blocks = [inner for k, labels, inner in _blocks(_authorized_networks()) if labels == ["cidr_blocks"]]
    assert len(blocks) == 1, blocks
    [content] = _walk(blocks[0], "content")
    assert _attr(content, "cidr_block") == "cidr_blocks.value"
    assert [k for k, _, _ in _blocks(_authorized_networks())] == ["dynamic"]

    cidrs = ["203.0.113.0/24", "198.51.100.7/32"]
    internal = ["10.20.0.0/24"]
    got = _evaluate(tmp_path, {"networks": _attr(blocks[0], "for_each")},
                    endpoint_public_access=public, public_access_cidrs=cidrs,
                    private_access_cidrs=internal)["networks"]
    assert sorted(got) == (sorted(cidrs + internal) if public else internal), got


def test_private_endpoint_global_access_is_off_by_default():
    assert _attr(_variables()["private_endpoint_global_access"], "default") == "false"
    [private] = _walk(_cluster(), "private_cluster_config")
    [glob] = _walk(private, "master_global_access_config")
    assert _attr(glob, "enabled") == "var.private_endpoint_global_access"


@requires_terraform
def test_a_private_access_entry_must_be_a_cidr(tmp_path):
    out = _apply(tmp_path, private_access_cidrs=["bastion"])
    assert out.returncode != 0 and "Invalid value for variable" in out.stderr, out.stderr


def test_a_customer_key_in_another_region_is_refused_at_plan_time():
    [lifecycle] = _walk(_cluster(), "lifecycle")
    assert ('!local.kms || try(regex("/locations/([^/]+)/", var.database_encryption_key_name)[0], "")'
            ' == var.region') in _conditions(lifecycle, "precondition")


@requires_terraform
def test_a_public_access_entry_must_be_a_cidr(tmp_path):
    out = _apply(tmp_path, public_access_cidrs=["203.0.113.0/24", "office"])
    assert out.returncode != 0
    assert "must be a CIDR block" in " ".join(out.stderr.split()), out.stderr


@requires_terraform
@pytest.mark.parametrize("public,dns,suffix", [
    (False, False, " --internal-ip"), (True, False, ""),
    (False, True, " --dns-endpoint"), (True, True, " --dns-endpoint"),
])
def test_the_kubeconfig_command_reaches_the_endpoint_that_is_open(tmp_path, public, dns, suffix):
    """With the public endpoint off, a kubeconfig naming it cannot connect.
    With the DNS endpoint open to external traffic, that is the one a hosted
    runner can reach."""
    [value] = [_attr(inner, "value") for k, labels, inner in _blocks(_text(OUTPUTS))
               if k == "output" and labels == ["kubeconfig_command"]]
    value = (value.replace("google_container_cluster.this.name", '"c"')
                  .replace("google_container_cluster.this.location", '"europe-west2"'))
    got = _evaluate(tmp_path, {"command": value}, endpoint_public_access=public,
                    dns_endpoint_allow_external_traffic=dns,
                    public_access_cidrs=["203.0.113.0/24"])["command"]
    assert got == ("gcloud container clusters get-credentials c --region europe-west2"
                   " --project example-project" + suffix), got


def test_deletion_protection_is_on_by_default():
    assert _attr(_variables()["deletion_protection"], "default") == "true"
    assert _attr(_cluster(), "deletion_protection") == "var.deletion_protection"


def test_secrets_are_encrypted_with_the_customer_key_when_one_is_given():
    """Off when the key is null, and then GKE's default encryption holds.
    When set, the key is the caller's and GKE's service agent may use it."""
    assert _attr(_variables()["database_encryption_key_name"], "default") == "null"
    assert _locals()["kms"].splitlines()[0] == "var.database_encryption_key_name != null"

    dynamic = [labels for k, labels, _ in _blocks(_cluster()) if k == "dynamic"]
    assert dynamic == [["database_encryption"]], dynamic
    [encryption] = [inner for k, labels, inner in _blocks(_cluster()) if labels == ["database_encryption"]]
    assert _attr(encryption, "for_each") == "local.kms ? [1] : []"
    [content] = _walk(encryption, "content")
    assert _attr(content, "state") == '"ENCRYPTED"'
    assert _attr(content, "key_name") == "var.database_encryption_key_name"

    agent = _resources("google_kms_crypto_key_iam_member")
    assert sorted(agent) == ["gke_agent"], sorted(agent)
    assert _attr(agent["gke_agent"], "count") == "local.kms ? 1 : 0"
    assert _attr(agent["gke_agent"], "crypto_key_id") == "var.database_encryption_key_name"
    assert _attr(agent["gke_agent"], "role") == '"roles/cloudkms.cryptoKeyEncrypterDecrypter"'
    assert "@container-engine-robot.iam.gserviceaccount.com" in _attr(agent["gke_agent"], "member")


# --- workload identity ---------------------------------------------------

@requires_terraform
def test_each_binding_lets_exactly_one_service_account_act_as_one_store_account(tmp_path):
    """A workloadIdentityUser binding is a pod's Google identity. One naming
    a wildcard, a second service account, or an account store-gcs did not
    make gives the chart's pods a permission the store module did not scope."""
    got = _bindings(tmp_path, project_id="p-cluster", namespace="forgd-x",
                    writer_service_account="w-sa", reader_service_account="r-sa",
                    writer_email="w-acct@p-store.iam.gserviceaccount.com",
                    reader_email="r-acct@p-store.iam.gserviceaccount.com")
    assert got == {
        "writer": {
            "service_account_id": "projects/p-store/serviceAccounts/w-acct@p-store.iam.gserviceaccount.com",
            "role": "roles/iam.workloadIdentityUser",
            "member": "serviceAccount:p-cluster.svc.id.goog[forgd-x/w-sa]",
        },
        "reader": {
            "service_account_id": "projects/p-store/serviceAccounts/r-acct@p-store.iam.gserviceaccount.com",
            "role": "roles/iam.workloadIdentityUser",
            "member": "serviceAccount:p-cluster.svc.id.goog[forgd-x/r-sa]",
        },
    }, got
    for key, b in got.items():
        # One member, one account: no list, no principalSet, no wildcard.
        assert re.fullmatch(r"serviceAccount:[a-z0-9-]+\.svc\.id\.goog\[[a-z0-9-]+/[a-z0-9.-]+\]", b["member"]), key
        assert b["service_account_id"].count("/serviceAccounts/") == 1, key


@requires_terraform
def test_the_dashboard_service_account_is_bound_only_to_the_reader_account(tmp_path):
    """The dashboard is the one service a human signs into. Bound to the
    writer account it could rewrite the findings it displays."""
    got = _bindings(tmp_path)
    reader_member = "serviceAccount:example-project.svc.id.goog[forgd/forgd-verdict-reader]"
    holding = [b["service_account_id"] for b in got.values() if b["member"] == reader_member]
    assert holding == [f"projects/example-project/serviceAccounts/{REQUIRED['reader_email']}"], got
    writer_bound = [b["member"] for b in got.values() if b["service_account_id"].endswith(REQUIRED["writer_email"])]
    assert writer_bound == ["serviceAccount:example-project.svc.id.goog[forgd/forgd-verdict-writer]"], got


@requires_terraform
def test_a_store_account_in_another_project_is_named_under_that_project(tmp_path):
    """store-gcs may live in another project than the cluster. The member
    stays in the cluster's pool; the account is addressed in its own."""
    got = _bindings(tmp_path, project_id="p-cluster",
                    writer_email="forgd-verdict-writer@p-store-a.iam.gserviceaccount.com",
                    reader_email="forgd-dashboard-reader@p-store-b.iam.gserviceaccount.com")
    assert {k: (b["service_account_id"], b["member"]) for k, b in got.items()} == {
        "writer": ("projects/p-store-a/serviceAccounts/forgd-verdict-writer@p-store-a.iam.gserviceaccount.com",
                   "serviceAccount:p-cluster.svc.id.goog[forgd/forgd-verdict-writer]"),
        "reader": ("projects/p-store-b/serviceAccounts/forgd-dashboard-reader@p-store-b.iam.gserviceaccount.com",
                   "serviceAccount:p-cluster.svc.id.goog[forgd/forgd-verdict-reader]"),
    }, got


def test_the_dashboard_cannot_be_given_the_writer_account():
    """Both checks run on the binding itself, so they fail the plan before
    either binding is created."""
    lifecycles = _walk(_binding(), "lifecycle")
    assert len(lifecycles) == 1, lifecycles
    conditions = _conditions(lifecycles[0], "precondition")
    assert "var.reader_email != var.writer_email" in conditions, conditions
    assert "var.reader_service_account != var.writer_service_account" in conditions, conditions


def test_the_bindings_wait_for_the_cluster():
    """IAM refuses a member in a Workload Identity pool that does not exist,
    and the pool exists once the project has a cluster that uses it."""
    assert re.sub(r"\s", "", _attr(_binding(), "depends_on") or "") == "[google_container_cluster.this]"


def test_the_default_service_accounts_are_the_ones_the_gke_example_names():
    sas = yaml.safe_load(GKE_VALUES.read_text(encoding="utf-8"))["serviceAccounts"]
    variables = _variables()
    assert _attr(variables["writer_service_account"], "default") == f'"{sas["writer"]["name"]}"'
    assert _attr(variables["reader_service_account"], "default") == f'"{sas["reader"]["name"]}"'


@requires_terraform
@pytest.mark.parametrize("field,value", [
    ("writer_email", "serviceAccount:w@p.iam.gserviceaccount.com"),
    ("writer_email", "forgd-verdict-writer@developer.gserviceaccount.com"),
    ("reader_email", "forgd-dashboard-reader@p1.iam.gserviceaccount.com"),
    ("reader_email", "allUsers"),
    ("reader_service_account", "r-sa]"),
    ("namespace", "forgd/other"),
])
def test_a_value_that_would_change_the_member_is_refused(tmp_path, field, value):
    """Each of these is interpolated into a member or a resource name."""
    out = _apply(tmp_path, **{field: value})
    assert out.returncode != 0, field
    assert f"{field} must be" in " ".join(out.stderr.split()), out.stderr
