"""Dashboard admins in the app-aca module.

Off by default, and then the dashboard is what it was: the reader identity,
the reader's client id, no form key. On, the control identity is attached
and named by AZURE_CLIENT_ID, the form key arrives as a Container Apps
secret, and nothing else in the module sees either. The refusals are
evaluated by terraform on a `terraform_data` resource, as in test_app_aca.py.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import terraform_render
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from test_app_aca import MODULE, REQUIRED, _flat, _top, requires_terraform, terraform
from test_app_aca import ON as CONNECTOR_ON
from test_app_ecs import _attr, _blocks, _walk

from forgd_verdict.overrides_signing import encode

ADMIN_REF = re.compile(r"var\.(dashboard_admins_enabled|control_identity_id|control_client_id|dashboard_form_key"
                       r"|overrides_writer_lockout|overrides_writer_identities|overrides_storage_account_id"
                       r"|dashboard_signing_key_secret_id|overrides_verify_keys)\b")
FORM_KEY = "0123456789abcdef0123456789abcdef"  # gitleaks:allow (a made-up test key)


def _public_key() -> str:
    """A made-up Ed25519 public key, as FORGD_OVERRIDES_VERIFY_KEY lists one."""
    return encode(Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


VERIFY_KEYS = [_public_key(), _public_key()]
SIGNING_SECRET_ID = "https://kv-example.vault.azure.net/secrets/signing"
ON = {"dashboard_admins_enabled": True, "control_identity_id": "/subscriptions/0/rg/control",
      "control_client_id": "control-client", "dashboard_form_key": FORM_KEY,
      "overrides_writer_lockout": True,
      "overrides_writer_identities": [REQUIRED["identity_principal_id"]],
      "overrides_storage_account_id": "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st",
      "dashboard_signing_key_secret_id": SIGNING_SECRET_ID, "overrides_verify_keys": VERIFY_KEYS}


def _dashboard() -> str:
    [body] = [inner for k, labels, inner in _top()
              if k == "resource" and labels == ["azurerm_container_app", "dashboard"]]
    return body


def _container() -> str:
    [template] = _walk(_dashboard(), "template")
    [container] = _walk(template, "container")
    return container


def _variable(name: str) -> str:
    text = (MODULE / "variables.tf").read_text(encoding="utf-8")
    return {labels[0]: inner for k, labels, inner in _blocks(text) if k == "variable"}[name]


def _dynamic(body: str, kind: str, name: str) -> str:
    """The for_each of the dynamic `kind` block whose content names `name`."""
    for k, labels, inner in _blocks(body):
        if k == "dynamic" and labels == [kind]:
            [content] = _walk(inner, "content")
            if _attr(content, "name") == f'"{name}"':
                return inner
    raise AssertionError(f"no dynamic {kind} named {name}")


def _static_env(name: str) -> str:
    for k, _, inner in _blocks(_container()):
        if k == "env" and _attr(inner, "name") == f'"{name}"':
            return inner
    raise AssertionError(name)


def _preconditions() -> list[tuple[str, str]]:
    [lifecycle] = _walk(_dashboard(), "lifecycle")
    out = [(_attr(b, "condition"), _attr(b, "error_message")) for b in _walk(lifecycle, "precondition")]
    assert len(out) == 11, out
    return out


def _run(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([terraform, f"-chdir={root}", *args, "-no-color"],
                          capture_output=True, text=True, timeout=120)


def _evaluate(root: Path, exprs: dict[str, str], **variables) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULE / "variables.tf", root / "variables.tf")
    (root / "main.tf").write_text("".join(
        f'output "{n}" {{\n  sensitive = true\n  value = {e}\n}}\n' for n, e in exprs.items()), encoding="utf-8")
    (root / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}), encoding="utf-8")
    assert _run(root, "init", "-input=false").returncode == 0
    out = _run(root, "apply", "-auto-approve", "-input=false")
    assert out.returncode == 0, out.stderr
    out = subprocess.run([terraform, f"-chdir={root}", "output", "-json"],
                         capture_output=True, text=True, timeout=60, check=True)
    return {k: v["value"] for k, v in json.loads(out.stdout).items()}


# --- off -------------------------------------------------------------------------

def test_admins_are_off_by_default_and_every_setting_has_a_default():
    assert _attr(_variable("dashboard_admins_enabled"), "default") == "false"
    assert _attr(_variable("overrides_writer_lockout"), "default") == "false"
    for name in ("control_identity_id", "control_client_id", "dashboard_form_key",
                 "dashboard_signing_key_secret_id"):
        assert _attr(_variable(name), "default") == '""', name
    assert _attr(_variable("overrides_verify_keys"), "default") == "[]"
    assert _attr(_variable("dashboard_form_key"), "sensitive") == "true"


def test_only_the_dashboard_reads_an_admin_setting():
    """Outside the dashboard, only the flag and the verify keys are read: to
    set FORGD_OVERRIDES_ENABLED, FORGD_OVERRIDES_WRITER_ROLES and
    FORGD_OVERRIDES_VERIFY_KEY for every role, to pick the path the
    readiness probes request, and to add the verdict server's, the
    collector's and the intake's readiness probe."""
    readers = [(k, labels) for k, labels, inner in _top() if ADMIN_REF.search(inner)]
    assert readers == [("locals", []), ("resource", ["azurerm_container_app", "verdict"]),
                       ("resource", ["azurerm_container_app", "collector"]),
                       ("resource", ["azurerm_container_app", "intake"]),
                       ("resource", ["azurerm_container_app", "dashboard"])], readers
    for name in ("verdict", "collector", "intake"):
        [body] = [inner for k, labels, inner in _top() if labels == ["azurerm_container_app", name]]
        assert [m.group(0) for m in ADMIN_REF.finditer(body)] == ["var.dashboard_admins_enabled"], name
        assert 'for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])' in body, name
    [local] = [inner for k, _, inner in _top() if k == "locals" and ADMIN_REF.search(inner)]
    assert [m.group(1) for m in ADMIN_REF.finditer(local)] == [
        "dashboard_admins_enabled", "overrides_verify_keys", "dashboard_admins_enabled"]
    assert ('overrides_env = var.dashboard_admins_enabled ? { FORGD_OVERRIDES_ENABLED = "true" '
            'FORGD_OVERRIDES_WRITER_ROLES = join(",", local.overrides_writer_roles) '
            'FORGD_OVERRIDES_VERIFY_KEY = join(",", var.overrides_verify_keys) } : {}'
            in _flat(local))
    assert 'ready_path = var.dashboard_admins_enabled ? "/readyz" : "/healthz"' in _flat(local)
    assert not ADMIN_REF.search((MODULE / "outputs.tf").read_text(encoding="utf-8"))


def _expressions() -> dict[str, str]:
    [identity] = _walk(_dashboard(), "identity")
    return {
        "identity_ids": _attr(identity, "identity_ids"),
        "client_id": _attr(_static_env("AZURE_CLIENT_ID"), "value"),
        "secret": _attr(_dynamic(_dashboard(), "secret", "dashboard-form-key"), "for_each"),
        "env": _attr(_dynamic(_container(), "env", "FORGD_DASHBOARD_FORM_KEY"), "for_each"),
        "signing_secret": _attr(_dynamic(_dashboard(), "secret", "overrides-signing-key"), "for_each"),
        "signing_env": _attr(_dynamic(_container(), "env", "FORGD_OVERRIDES_SIGNING_KEY"), "for_each"),
    }


@requires_terraform
@pytest.mark.parametrize("left_set", [False, True], ids=["unset", "control-values-left-set"])
def test_off_the_dashboard_is_what_it_was(tmp_path, left_set):
    """Off means off, including with the control values still set."""
    extra = {k: v for k, v in ON.items() if k != "dashboard_admins_enabled"} if left_set else {}
    got = _evaluate(tmp_path, _expressions(), **extra)
    assert got == {"identity_ids": [REQUIRED["reader_identity_id"]],
                   "client_id": REQUIRED["reader_identity_client_id"], "secret": [], "env": [],
                   "signing_secret": [], "signing_env": []}, got


@requires_terraform
def test_on_the_dashboard_runs_as_the_control_identity(tmp_path):
    got = _evaluate(tmp_path, _expressions(), **ON)
    assert got == {"identity_ids": [REQUIRED["reader_identity_id"], ON["control_identity_id"]],
                   "client_id": ON["control_client_id"], "secret": ["admins"], "env": ["admins"],
                   "signing_secret": ["admins"], "signing_env": ["admins"]}, got


# --- on -----------------------------------------------------------------------------

def test_the_registry_pull_stays_on_the_reader():
    [registry] = _walk(_dashboard(), "registry")
    assert _attr(registry, "identity") == "var.reader_identity_id"


def test_the_form_key_is_a_secret_the_dashboard_alone_holds():
    [content] = _walk(_dynamic(_dashboard(), "secret", "dashboard-form-key"), "content")
    assert _attr(content, "value") == 'var.dashboard_form_key_secret_id == "" ? var.dashboard_form_key : null'
    assert _attr(content, "key_vault_secret_id") == \
        'var.dashboard_form_key_secret_id == "" ? null : var.dashboard_form_key_secret_id'
    assert _attr(content, "identity") == 'var.dashboard_form_key_secret_id == "" ? null : var.control_identity_id'
    [content] = _walk(_dynamic(_container(), "env", "FORGD_DASHBOARD_FORM_KEY"), "content")
    assert _attr(content, "secret_name") == '"dashboard-form-key"'
    assert _attr(content, "value") is None
    for _k, labels, inner in _top():
        if labels != ["azurerm_container_app", "dashboard"]:
            assert "FORGD_DASHBOARD_FORM_KEY" not in inner and "dashboard-form-key" not in inner, labels


def test_the_signing_key_is_a_key_vault_reference_the_dashboard_alone_holds():
    """Mutation: give the secret a value, read it with another identity, or
    add the secret or the env to another role."""
    [content] = _walk(_dynamic(_dashboard(), "secret", "overrides-signing-key"), "content")
    assert _attr(content, "key_vault_secret_id") == "var.dashboard_signing_key_secret_id"
    assert _attr(content, "identity") == "var.control_identity_id"
    assert _attr(content, "value") is None
    [content] = _walk(_dynamic(_container(), "env", "FORGD_OVERRIDES_SIGNING_KEY"), "content")
    assert _attr(content, "secret_name") == '"overrides-signing-key"'
    assert _attr(content, "value") is None
    for _k, labels, inner in _top():
        if labels != ["azurerm_container_app", "dashboard"]:
            assert "FORGD_OVERRIDES_SIGNING_KEY" not in inner and "overrides-signing-key" not in inner, labels
            assert "dashboard_signing_key_secret_id" not in inner, labels


def test_the_connector_never_gets_the_control_identity():
    [connector] = [inner for k, labels, inner in _top()
                   if k == "resource" and labels == ["azurerm_container_app", "connector"]]
    assert "control" not in connector
    [identity] = _walk(connector, "identity")
    assert _attr(identity, "identity_ids") == "[var.reader_identity_id]"


# --- the refusals, evaluated by terraform ------------------------------------------

def _harness(root: Path, preconditions: list[tuple[str, str]]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    shutil.copy(MODULE / "variables.tf", root / "variables.tf")
    checks = "".join(
        f"    precondition {{\n      condition     = {c}\n      error_message = {m}\n    }}\n"
        for c, m in preconditions)
    (root / "main.tf").write_text(
        'resource "terraform_data" "dashboard" {\n  lifecycle {\n' + checks + "  }\n}\n", encoding="utf-8")
    assert _run(root, "init", "-input=false").returncode == 0
    return root


def _plan(root: Path, **variables) -> subprocess.CompletedProcess:
    (root / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}), encoding="utf-8")
    return _run(root, "plan", "-input=false", "-lock=false", "-refresh=false")


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    return _harness(tmp_path_factory.mktemp("aca-admins"), _preconditions())


@requires_terraform
def test_off_plans_with_nothing_set(harness):
    out = _plan(harness)
    assert out.returncode == 0, out.stderr


@requires_terraform
def test_on_plans_with_a_control_identity_of_its_own(harness):
    out = _plan(harness, **ON)
    assert out.returncode == 0, out.stderr


REFUSALS = {
    "no control identity": ({"control_identity_id": ""}, "needs control_identity_id and control_client_id"),
    "no control client id": ({"control_client_id": ""}, "needs control_identity_id and control_client_id"),
    "the reader's identity": ({"control_identity_id": REQUIRED["reader_identity_id"]},
                              "control_identity_id equals the reader's or the writer's"),
    "the writer's identity": ({"control_identity_id": REQUIRED["identity_id"]},
                              "control_identity_id equals the reader's or the writer's"),
    "the reader's client id": ({"control_client_id": REQUIRED["reader_identity_client_id"]},
                               "control_client_id equals the reader's or the writer's"),
    "the writer's client id": ({"control_client_id": REQUIRED["identity_client_id"]},
                               "control_client_id equals the reader's or the writer's"),
    "no form key": ({"dashboard_form_key": ""}, "needs dashboard_form_key"),
    "a short form key": ({"dashboard_form_key": "short"}, "needs dashboard_form_key"),
    "no writer lockout": ({"overrides_writer_lockout": False}, "needs overrides_writer_lockout"),
    "no writer identities": ({"overrides_writer_identities": []}, "needs overrides_writer_identities"),
    "the writer not listed": ({"overrides_writer_identities": ["00000000-0000-0000-0000-00000000000a"]},
                              "needs overrides_writer_identities to include identity_principal_id"),
    "no storage account id": ({"overrides_storage_account_id": ""},
                              "needs overrides_writer_identities and overrides_storage_account_id"),
    "no signing key": ({"dashboard_signing_key_secret_id": ""},
                       "needs dashboard_signing_key_secret_id, the Key Vault secret holding "
                       "FORGD_OVERRIDES_SIGNING_KEY"),
    "no verify keys": ({"overrides_verify_keys": []}, "needs overrides_verify_keys"),
    "a form key and its id": ({"dashboard_form_key_secret_id": "https://kv-example.vault.azure.net/secrets/form"},
                              "set dashboard_form_key or dashboard_form_key_secret_id, not both"),
    "an entra secret and its id": ({"dashboard_auth_client_secret": "e" * 32,
                                    "dashboard_auth_client_secret_secret_id":
                                        "https://kv-example.vault.azure.net/secrets/entra"},
                                   "set dashboard_auth_client_secret or dashboard_auth_client_secret_secret_id,"
                                   " not both"),
}


@requires_terraform
def test_on_plans_with_the_form_key_named_in_key_vault(harness):
    out = _plan(harness, **{**ON, "dashboard_form_key": "",
                            "dashboard_form_key_secret_id": "https://kv-example.vault.azure.net/secrets/form"})
    assert out.returncode == 0, out.stderr


@requires_terraform
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_fires(harness, case):
    variables, fragment = REFUSALS[case]
    out = _plan(harness, **{**ON, **variables})
    assert out.returncode != 0, out.stdout
    assert fragment in _flat(out.stderr), out.stderr


@requires_terraform
@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_is_its_own_precondition(tmp_path, case):
    variables, fragment = REFUSALS[case]
    kept = [(c, m) for c, m in _preconditions() if fragment not in m]
    assert len(kept) == len(_preconditions()) - (2 if case == "no writer identities" else 1), case
    out = _plan(_harness(tmp_path, kept), **{**ON, **variables})
    assert out.returncode == 0, out.stderr


# --- the validations, evaluated by terraform ---------------------------------------

VALID = {
    "a versionless secret id": {"dashboard_signing_key_secret_id": SIGNING_SECRET_ID},
    "a versioned secret id": {"dashboard_signing_key_secret_id": SIGNING_SECRET_ID + "/" + "0a" * 16},
    "one verify key": {"overrides_verify_keys": VERIFY_KEYS[:1]},
}
KEY = VERIFY_KEYS[0]
INVALID = {
    "an http secret id": ({"dashboard_signing_key_secret_id": "http" + SIGNING_SECRET_ID[5:]},
                          "must be a Key Vault secret id"),
    "another host": ({"dashboard_signing_key_secret_id": "https://kv-example.example.net/secrets/k"},
                     "must be a Key Vault secret id"),
    "an uppercase vault": ({"dashboard_signing_key_secret_id": "https://KV.vault.azure.net/secrets/k"},
                           "must be a Key Vault secret id"),
    "a key, not a secret": ({"dashboard_signing_key_secret_id": "https://kv.vault.azure.net/keys/k"},
                            "must be a Key Vault secret id"),
    "a short version": ({"dashboard_signing_key_secret_id": SIGNING_SECRET_ID + "/0a0a"},
                        "must be a Key Vault secret id"),
    "a trailing slash": ({"dashboard_signing_key_secret_id": SIGNING_SECRET_ID + "/"},
                         "must be a Key Vault secret id"),
    "a short verify key": ({"overrides_verify_keys": [KEY[:42]]}, "Each overrides_verify_keys entry"),
    "a padded verify key": ({"overrides_verify_keys": [KEY + "="]}, "Each overrides_verify_keys entry"),
    "standard base64": ({"overrides_verify_keys": ["+" + KEY[1:]]}, "Each overrides_verify_keys entry"),
    "one bad among good": ({"overrides_verify_keys": [KEY, ""]}, "Each overrides_verify_keys entry"),
    "two keys in one entry": ({"overrides_verify_keys": [",".join(VERIFY_KEYS)]},
                              "Each overrides_verify_keys entry"),
}


@requires_terraform
@pytest.mark.parametrize("case", sorted(VALID))
def test_each_validation_admits(harness, case):
    out = _plan(harness, **{**ON, **VALID[case]})
    assert out.returncode == 0, out.stderr


@requires_terraform
@pytest.mark.parametrize("case", sorted(INVALID))
def test_each_validation_refuses(harness, case):
    """Mutation: drop a validation, or loosen its pattern."""
    variables, fragment = INVALID[case]
    out = _plan(harness, **{**ON, **variables})
    assert out.returncode != 0, out.stdout
    assert "Invalid value for variable" in out.stderr and fragment in _flat(out.stderr), out.stderr


# --- FORGD_OVERRIDES_ENABLED, over the full rendering -------------------------------

ENABLED = "FORGD_OVERRIDES_ENABLED"
WRITER_ROLES = "FORGD_OVERRIDES_WRITER_ROLES"
VERIFY_KEY = "FORGD_OVERRIDES_VERIFY_KEY"
SIGNING_KEY = "FORGD_OVERRIDES_SIGNING_KEY"
SIGNING_SECRET = "overrides-signing-key"


def _mi(name: str) -> str:
    return f"{terraform_render.RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}"


# REQUIRED with ids the azurerm provider parses, and the connector on.
RENDER = {
    **REQUIRED, **CONNECTOR_ON,
    "identity_id": _mi("writer"), "reader_identity_id": _mi("reader"),
    "identity_principal_id": "11111111-0000-0000-0000-000000000000",
    "reader_identity_principal_id": "22222222-0000-0000-0000-000000000000",
    "registry_id": f"{terraform_render.RG}/providers/Microsoft.ContainerRegistry/registries/acr",
}
RENDER_ON = {**ON, "control_identity_id": _mi("control"),
             "overrides_writer_identities": [RENDER["identity_principal_id"],
                                             "00000000-0000-0000-0000-00000000000a"]}


def _containers(rendered: dict) -> dict[str, dict]:
    """"address.path" -> container, for every container the rendering holds."""
    out = {}

    def walk(value, path):
        if isinstance(value, dict):
            for k, v in value.items():
                if k == "container" and isinstance(v, list):
                    for i, c in enumerate(v):
                        out[".".join(map(str, (*path, k, i)))] = c
                else:
                    walk(v, (*path, k))
        elif isinstance(value, list):
            for i, v in enumerate(value):
                walk(v, (*path, i))

    walk(rendered, ())
    return out


@requires_terraform
def test_on_every_container_has_overrides_enabled(tmp_path):
    """Mutation: drop overrides_env from base_env, or from one role's env."""
    containers = _containers(terraform_render.render_module(
        tmp_path, "app-aca", {**RENDER, **RENDER_ON}))
    assert len(containers) >= 5, sorted(containers)
    for name, c in containers.items():
        env = [e for e in c["env"] if e["name"] == ENABLED]
        assert env == [{"name": ENABLED, "secret_name": None, "value": "true"}], name


# The one change to the module since its baseline was pinned that is not
# about admins: the collector's OTel token secret is per org.
OTEL_TOKEN_SECRET_PER_ORG = [
    'azurerm_container_app.collector.secret.1.name: "otel-token" -> "otel-token-primary"',
    ('azurerm_container_app.collector.template.0.container.0.env.2.secret_name: '
     '"otel-token" -> "otel-token-primary"'),
]


@requires_terraform
@pytest.mark.parametrize("left_set", [False, True], ids=["unset", "control-values-left-set"])
def test_off_no_resource_has_overrides_enabled_and_the_plan_is_the_baseline(tmp_path, left_set):
    """Every resource, rendered in full, equals the pinned baseline's rendering
    of the same variables, apart from OTEL_TOKEN_SECRET_PER_ORG.

    Mutation: set FORGD_OVERRIDES_ENABLED or FORGD_OVERRIDES_WRITER_ROLES
    whatever dashboard_admins_enabled says."""
    current = {k: v for k, v in RENDER_ON.items() if k != "dashboard_admins_enabled"} \
        if left_set else {}
    assert terraform_render.off_versus_baseline(tmp_path, "app-aca", RENDER, current) == OTEL_TOKEN_SECRET_PER_ORG
    rendered = terraform_render.render_module(tmp_path / "off", "app-aca", {**RENDER, **current})
    assert _containers(rendered)
    for name in (ENABLED, WRITER_ROLES, VERIFY_KEY, SIGNING_KEY, SIGNING_SECRET):
        assert name not in json.dumps(rendered), name


@requires_terraform
def test_on_the_baseline_comparison_sees_the_variable(tmp_path):
    """The comparison above can see the change."""
    found = terraform_render.off_versus_baseline(tmp_path, "app-aca", RENDER, RENDER_ON)
    for name in (ENABLED, WRITER_ROLES, VERIFY_KEY, SIGNING_KEY, SIGNING_SECRET):
        assert any(name in d for d in found), (name, found)


# --- FORGD_OVERRIDES_WRITER_ROLES, over the full rendering --------------------------

# FORGD_ROLE -> the writer role it runs as, in the order the variable lists them.
WRITER_OF = {"server": "verdict", "collect": "collector", "intake": "intake", "ingest": "ingest"}
ACA_EDIT = ('FORGD_OVERRIDES_WRITER_ROLES = join(",", local.overrides_writer_roles)',
            'FORGD_OVERRIDES_WRITER_ROLES = "verdict,collector,intake,ingest"')
# Ingest on an identity of its own.
ACA_INGEST_OWN = ("ingest = var.identity_id }", "ingest = var.reader_identity_id }")


def expected_writer_roles(deployed: set[str], identity: dict[str, str] | None = None) -> str:
    """One writer role per distinct identity: the first of verdict,
    collector, intake and ingest deployed that runs as it. `identity` maps a
    role to its identity; without it every writer shares one."""
    identity = identity or {}
    seen, out = set(), []
    for role in WRITER_OF.values():
        if role in deployed and identity.get(role, "writer") not in seen:
            seen.add(identity.get(role, "writer"))
            out.append(role)
    return ",".join(out)


def writer_roles_problems(envs: dict[str, dict[str, str]],
                          identity: dict[str, str] | None = None) -> list[str]:
    """Every workload whose FORGD_OVERRIDES_WRITER_ROLES is not one writer
    role per distinct identity among the workloads in `envs`
    (expected_writer_roles), or that has it without FORGD_OVERRIDES_ENABLED.
    `envs` maps a workload to its {name: value}."""
    deployed = {WRITER_OF[e["FORGD_ROLE"]] for e in envs.values() if e.get("FORGD_ROLE") in WRITER_OF}
    want = expected_writer_roles(deployed, identity)
    out = []
    for name, env in envs.items():
        if ENABLED in env and env.get(WRITER_ROLES) != want:
            out.append(f"{name}: {env.get(WRITER_ROLES)!r}, deployed {want!r}")
        elif ENABLED not in env and WRITER_ROLES in env:
            out.append(f"{name}: {env[WRITER_ROLES]!r} without {ENABLED}")
    return out


def _envs(rendered: dict) -> dict[str, dict[str, str]]:
    return {n: {e["name"]: e["value"] for e in c["env"]} for n, c in _containers(rendered).items()}


@requires_terraform
def test_on_every_container_has_the_writer_roles_the_module_deploys(tmp_path):
    """Container Apps always runs verdict, collector and ingest, and has no
    intake. All three run as the one store identity, so only verdict is
    listed and ingest never is.

    Mutation: list a role the module does not deploy, or ingest beside a
    long-running role on the same identity."""
    envs = _envs(terraform_render.render_module(tmp_path, "app-aca", {**RENDER, **RENDER_ON}))
    assert len(envs) >= 5, sorted(envs)
    assert {e["FORGD_ROLE"] for e in envs.values()} == {"server", "collect", "dashboard", "connector", "ingest"}
    assert writer_roles_problems(envs) == []
    assert {e[WRITER_ROLES] for e in envs.values()} == {"verdict"}


@requires_terraform
def test_ingest_on_an_identity_of_its_own_is_listed(tmp_path):
    """The list follows writer_identity, which the writer apps' identity
    blocks use."""
    envs = _envs(terraform_render.render_edited(tmp_path, "app-aca", {**RENDER, **RENDER_ON},
                                                [ACA_INGEST_OWN]))
    assert {e[WRITER_ROLES] for e in envs.values()} == {"verdict,ingest"}
    assert writer_roles_problems(envs, {"ingest": "own"}) == []


def test_each_writer_app_runs_as_its_writer_identity():
    """Mutation: point a writer app's identity past writer_identity."""
    main = (MODULE / "main.tf").read_text(encoding="utf-8")
    for kind, role in (("azurerm_container_app", "verdict"), ("azurerm_container_app", "collector"),
                       ("azurerm_container_app_job", "ingest")):
        body = main[main.index(f'resource "{kind}" "{role}"'):]
        body = body[:body.index("\n}\n")]
        assert f'identity_ids = [local.writer_identity["{role}"]]' in body, role


@requires_terraform
def test_a_writer_roles_list_that_always_names_intake_is_caught(tmp_path):
    """The check above fails on a module that lists an intake it does not deploy."""
    envs = _envs(terraform_render.render_edited(tmp_path, "app-aca", {**RENDER, **RENDER_ON}, [ACA_EDIT]))
    assert {e[WRITER_ROLES] for e in envs.values()} == {"verdict,collector,intake,ingest"}
    assert len(writer_roles_problems(envs)) == len(envs)



# --- the lockout verification's inputs, over the full rendering ---------------------

EVIDENCE = ("FORGD_OVERRIDES_WRITER_IDENTITIES", "FORGD_OVERRIDES_STORAGE_ACCOUNT_ID")


@requires_terraform
def test_on_only_the_dashboard_gets_the_writer_identities_and_account(tmp_path):
    """Mutation: give every role the variables, or render an identity list
    other than the store output's."""
    rendered = terraform_render.render_module(tmp_path, "app-aca", {**RENDER, **RENDER_ON})
    found = {name: {e["name"]: e["value"] for e in c["env"] if e["name"] in EVIDENCE}
             for name, c in _containers(rendered).items()}
    dashboard = {n: v for n, v in found.items() if n.startswith("azurerm_container_app.dashboard.")}
    assert list(dashboard.values()) == [{
        EVIDENCE[0]: ",".join(RENDER_ON["overrides_writer_identities"]),
        EVIDENCE[1]: ON["overrides_storage_account_id"]}], found
    assert not any(v for n, v in found.items() if n not in dashboard), found


@requires_terraform
def test_off_no_container_gets_the_lockout_inputs(tmp_path):
    current = {k: v for k, v in RENDER_ON.items() if k != "dashboard_admins_enabled"}
    rendered = terraform_render.render_module(tmp_path, "app-aca", {**RENDER, **current})
    assert not any(e in json.dumps(rendered) for e in EVIDENCE)


# --- the signing and verify keys, over the full rendering ---------------------------

def _secrets(rendered: dict) -> dict[str, list[dict]]:
    """address -> the secret blocks, for every container app and job; an
    instance under count as address[i]."""
    out = {}
    for address, value in rendered.items():
        if not address.startswith(("azurerm_container_app.", "azurerm_container_app_job.")):
            continue
        if isinstance(value, list):
            out |= {f"{address}[{i}]": v.get("secret") or [] for i, v in enumerate(value)}
        else:
            out[address] = value.get("secret") or []
    return out


@requires_terraform
def test_on_only_the_dashboard_gets_the_signing_key_from_key_vault(tmp_path):
    """Mutation: give the verdict server the secret or the env, or read the
    reference with the reader identity."""
    rendered = terraform_render.render_module(tmp_path, "app-aca", {**RENDER, **RENDER_ON})
    secrets = _secrets(rendered)
    assert set(secrets) == {"azurerm_container_app.verdict", "azurerm_container_app.collector",
                            "azurerm_container_app.dashboard", "azurerm_container_app_job.ingest",
                            "azurerm_container_app.connector[0]"}, sorted(secrets)
    holders = {a: [s for s in blocks if s["name"] == SIGNING_SECRET] for a, blocks in secrets.items()}
    dashboard_holder = holders.pop("azurerm_container_app.dashboard")
    assert dashboard_holder == [{
        "name": SIGNING_SECRET, "key_vault_secret_id": SIGNING_SECRET_ID,
        "identity": RENDER_ON["control_identity_id"], "value": None}], holders
    assert not any(holders.values()), holders
    envs = {n: [e for e in c["env"] if e["name"] == SIGNING_KEY] for n, c in _containers(rendered).items()}
    [dashboard] = [n for n in envs if n.startswith("azurerm_container_app.dashboard.")]
    dashboard_env = envs.pop(dashboard)
    assert dashboard_env == [{"name": SIGNING_KEY, "secret_name": SIGNING_SECRET, "value": None}]
    assert not any(envs.values()), envs


@requires_terraform
def test_on_every_container_has_the_verify_keys(tmp_path):
    """Mutation: drop FORGD_OVERRIDES_VERIFY_KEY from overrides_env, join
    only the first key, or filter it out of one role's env."""
    containers = _containers(terraform_render.render_module(tmp_path, "app-aca", {**RENDER, **RENDER_ON}))
    roles = {n: next(e["value"] for e in c["env"] if e["name"] == "FORGD_ROLE") for n, c in containers.items()}
    assert sorted(roles.values()) == ["collect", "connector", "dashboard", "ingest", "server"], roles
    for name, c in containers.items():
        env = [e for e in c["env"] if e["name"] == VERIFY_KEY]
        assert env == [{"name": VERIFY_KEY, "secret_name": None, "value": ",".join(VERIFY_KEYS)}], name
