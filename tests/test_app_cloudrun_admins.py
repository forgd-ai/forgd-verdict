"""Dashboard admins in the app-cloudrun module.

The dashboard already runs as an account of its own. With admins the
account moves from `reader_members` to `control_members` under the same key,
so store-gcs keeps its read binding and adds the control writes, and the
dashboard takes FORGD_DASHBOARD_FORM_KEY and FORGD_OVERRIDES_SIGNING_KEY from
Secret Manager, and every service takes FORGD_OVERRIDES_VERIFY_KEY. The module's
dashboard signs in through IAP, whose tokens carry no groups, so enabling
admins is refused at plan. Off, the module evaluates exactly as it did
before any of this.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import terraform_render
import test_app_aca as aca
import test_app_aca_admins as aca_admins
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from test_app_cloudrun import (
    MODULE,
    REF,
    REQUIRED,
    SECRET,
    _attr,
    _blocks_deep,
    _files,
    _services,
    _walk,
    requires_terraform,
    terraform,
)
from test_app_cloudrun import ON as SERVICES_ON

from forgd_verdict.overrides_signing import encode


def _public_key() -> str:
    """A made-up Ed25519 public key, as FORGD_OVERRIDES_VERIFY_KEY lists one."""
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return encode(raw)


FORM_KEY = SECRET + "form-key"
SIGNING_KEY = SECRET + "overrides-signing-key"
VERIFY_KEYS = [_public_key(), _public_key()]
ON = {"dashboard_admins_enabled": True, "dashboard_form_key_secret_id": FORM_KEY,
      "overrides_writer_lockout": True, "dashboard_signing_key_secret_id": SIGNING_KEY,
      "overrides_verify_keys": VERIFY_KEYS}
ADMIN_VARIABLES = {"dashboard_admins_enabled", "dashboard_form_key_secret_id", "overrides_writer_lockout",
                   "dashboard_signing_key_secret_id", "overrides_verify_keys"}
WRITER_ROLES_EXPR = 'join(",", local.writer_roles)'
VERIFY_KEYS_EXPR = 'join(",", var.overrides_verify_keys)'

MAIN_EDITS = [
    ('  # Every role honours runtime overrides only while this is "true".\n'
     "  # FORGD_OVERRIDES_WRITER_ROLES lists one writer role per distinct store\n"
     "  # identity. Each role here runs as its own service account\n"
     "  # (google_service_account.role), so every writer role is listed, ingest\n"
     "  # included. The dashboard and the connector only read.\n"
     "  # FORGD_OVERRIDES_VERIFY_KEY lists the public keys every role verifies the\n"
     "  # override records with.\n"
     '  overrides_env = var.dashboard_admins_enabled ? {\n'
     '    FORGD_OVERRIDES_ENABLED      = "true"\n'
     f'    FORGD_OVERRIDES_WRITER_ROLES = {WRITER_ROLES_EXPR}\n'
     f'    FORGD_OVERRIDES_VERIFY_KEY   = {VERIFY_KEYS_EXPR}\n'
     '  } : {}\n\n', ""),
    ("  # The path each startup and readiness probe requests. /healthz answers 200\n"
     "  # however the runtime overrides read; /readyz answers 503 until they are\n"
     "  # confirmed.\n"
     '  ready_path = var.dashboard_admins_enabled ? "/readyz" : "/healthz"\n\n', ""),
    ("  }, local.org_env, local.overrides_env)\n", "  }, local.org_env)\n"),
    ('  dashboard_secrets = var.dashboard_admins_enabled ? {\n'
     '    FORGD_DASHBOARD_FORM_KEY    = var.dashboard_form_key_secret_id\n'
     '    FORGD_OVERRIDES_SIGNING_KEY = var.dashboard_signing_key_secret_id\n'
     '  } : {}\n', ""),
    ("    dashboard = local.dashboard_secrets\n", "    dashboard = {}\n"),
    ('''      dynamic "env" {
        for_each = local.role_secrets["dashboard"]
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }
''', ""),
]
# The readiness probe only admins add, on each of the five services.
READINESS = '''      # With dashboard_admins_enabled, a failing readiness probe stops new
      # traffic to the instance without shutting it down; traffic returns
      # when it passes again.
      dynamic "readiness_probe" {
        for_each = toset(var.dashboard_admins_enabled ? ["admins"] : [])
        content {
          http_get {
            path = local.ready_path
          }
          period_seconds    = 10
          timeout_seconds   = 4
          failure_threshold = 3
        }
      }
'''
# Every startup probe, one per service.
READY_PATH_USE = "          path = local.ready_path\n"
OUTPUT_EDITS = [
    ('merge(var.dashboard_admins_enabled ? {} : { dashboard = google_service_account.role["dashboard"].member }, ',
     'merge({ dashboard = google_service_account.role["dashboard"].member }, '),
    ("The dashboard's (unless dashboard_admins_enabled) and", "The dashboard's and"),
]


def _dashboard_preconditions(main: str) -> tuple[int, int]:
    """The span of the dashboard's lifecycle preconditions, which only admins add."""
    start = main.index('resource "google_cloud_run_v2_service" "dashboard" {')
    j = main.index("\n    # The dashboard signs in through IAP here", start)
    k = main.index("\n  }\n}\n", j)
    return j, k


def test_the_dashboard_service_is_ordered_as_before():
    """Admins add no depends_on to the dashboard service."""
    body = _services()["dashboard"]
    assert "depends_on" not in body


def _left_out() -> dict[str, str]:
    files = _files()
    main = files["main.tf"]
    j, k = _dashboard_preconditions(main)
    main = main[:j] + main[k:]
    for now, before in MAIN_EDITS:
        assert main.count(now) == 1, now
        main = main.replace(now, before)
    assert main.count(READINESS) == 5
    main = main.replace(READINESS, "")
    assert main.count(READY_PATH_USE) == 5
    main = main.replace(READY_PATH_USE, '          path = "/healthz"\n')
    outputs = aca._without(files["outputs.tf"], lambda k, labels, _: k == "output" and labels == ["control_members"])
    for now, before in OUTPUT_EDITS:
        assert outputs.count(now) == 1, now
        outputs = outputs.replace(now, before)
    variables = aca._without(files["variables.tf"],
                             lambda k, labels, _: k == "variable" and labels[0] in ADMIN_VARIABLES)
    return {"main.tf": main, "variables.tf": variables, "outputs.tf": outputs}


def _evaluate(root: Path, files: dict[str, str], **variables) -> dict:
    return aca._evaluate(root, files, required=REQUIRED, ref=REF, **variables)


def test_leaving_admins_out_removes_every_mention_of_them():
    for name, text in _left_out().items():
        assert "dashboard_admins_enabled" not in text and "dashboard_form_key" not in text, name
        assert "FORGD_DASHBOARD_FORM_KEY" not in text and "control_members" not in text, name
        assert 'role_secrets["dashboard"]' not in text, name
        assert "dashboard_signing_key" not in text and "overrides_verify_keys" not in text, name
        assert "FORGD_OVERRIDES_SIGNING_KEY" not in text and "FORGD_OVERRIDES_VERIFY_KEY" not in text, name


@requires_terraform
@pytest.mark.parametrize("intake", [False, True])
def test_off_evaluates_exactly_as_the_module_with_admins_left_out(tmp_path, intake):
    extra = {"enable_intake": intake, "org_ids": {"prod": "00000000-0000-0000-0000-00000000000b"}, **SERVICES_ON}
    got = _evaluate(tmp_path / "off", _files(), **extra)
    before = _evaluate(tmp_path / "left-out", _left_out(), **extra)
    admins_only = ("dashboard_secrets", "overrides_env", "ready_path")
    assert {k: v for k, v in got["locals"].items() if k not in admins_only} == before["locals"]
    assert got["locals"]["ready_path"] == "/healthz"
    assert got["locals"]["dashboard_secrets"] == {}
    assert got["locals"]["overrides_env"] == {}
    assert got["resources"] == before["resources"]
    control_members = got.pop("o_control_members")
    assert control_members == {}
    assert {k: v for k, v in got.items() if k not in ("locals", "resources")} == \
        {k: v for k, v in before.items() if k not in ("locals", "resources")}


@requires_terraform
def test_on_the_dashboard_moves_to_control_members_and_reads_the_form_key(tmp_path):
    got = _evaluate(tmp_path / "on", _files(), **ON)
    before = _evaluate(tmp_path / "off", _files())
    assert got["o_control_members"] == {"dashboard": "ref"}
    assert got["o_reader_members"] == {k: v for k, v in before["o_reader_members"].items() if k != "dashboard"}
    assert got["locals"]["role_secrets"]["dashboard"] == {"FORGD_DASHBOARD_FORM_KEY": FORM_KEY,
                                                          SIGNING: SIGNING_KEY}
    assert got["locals"]["secret_access"][f"dashboard {FORM_KEY}"] == {"role": "dashboard", "secret": FORM_KEY}
    assert got["locals"]["secret_access"][f"dashboard {SIGNING_KEY}"] == {"role": "dashboard",
                                                                          "secret": SIGNING_KEY}
    assert {k for k in got["locals"]["secret_access"] if k.startswith("dashboard ")} == {
        f"dashboard {FORM_KEY}", f"dashboard {SIGNING_KEY}"}
    assert got["o_writer_members"] == before["o_writer_members"]


SIGNING = "FORGD_OVERRIDES_SIGNING_KEY"
VERIFY = "FORGD_OVERRIDES_VERIFY_KEY"


@requires_terraform
@pytest.mark.parametrize("intake", [True, False], ids=["intake", "no-intake"])
def test_on_only_the_dashboard_reads_the_signing_key(tmp_path, intake):
    """Evaluated with admins on, the refusal aside. The signing key is a
    secret of the dashboard's alone: no other role's secrets, accessor
    bindings or plain environment name it.

    Mutation: put FORGD_OVERRIDES_SIGNING_KEY in base_env, or in another
    role's secrets."""
    got = _evaluate(tmp_path / "on", _files(), **ON, enable_intake=intake,
                    **({"intake_token_secret_ids": {"dev": SECRET + "intake"}} if intake else {}))
    role_secrets = got["locals"]["role_secrets"]
    assert set(role_secrets) == ({"verdict", "collector", "dashboard", "ingest"} | ({"intake"} if intake else set()))
    holders = {role for role, secrets in role_secrets.items()
               if SIGNING in secrets or SIGNING_KEY in secrets.values()}
    assert holders == {"dashboard"}
    readers = {pair["role"] for pair in got["locals"]["secret_access"].values() if pair["secret"] == SIGNING_KEY}
    assert readers == {"dashboard"}
    for name in ("base_env", "overrides_env", "gitleaks_env", "connector_env"):
        assert SIGNING not in json.dumps(got["locals"].get(name, {})), name
        assert SIGNING_KEY not in json.dumps(got["locals"].get(name, {})), name


def test_the_signing_key_is_named_only_in_the_dashboard_secrets():
    """Outside the precondition's message, the source names
    FORGD_OVERRIDES_SIGNING_KEY once, in dashboard_secrets, which only the
    dashboard service's secret env reads
    (test_the_form_key_reaches_the_dashboard_as_a_secret_reference).

    Mutation: add FORGD_OVERRIDES_SIGNING_KEY to another role's secrets."""
    main = re.sub(r'(?m)^\s*error_message\s*=.*$', "", _files()["main.tf"])
    assert main.count(SIGNING) == 1
    assert main.count("var.dashboard_signing_key_secret_id") == 2  # dashboard_secrets and its precondition
    assert SIGNING in _locals()["dashboard_secrets"]


@requires_terraform
@pytest.mark.parametrize("intake", [True, False], ids=["intake", "no-intake"])
def test_on_every_service_takes_the_verify_keys_joined(tmp_path, intake):
    """Evaluated with admins on, the refusal aside: base_env, which every
    container's env takes (test_every_container_takes_overrides_enabled_from_base_env),
    carries FORGD_OVERRIDES_VERIFY_KEY as the listed keys joined by commas.

    Mutation: join with another separator, or list only the first key."""
    got = _evaluate(tmp_path / "on", _files(), **ON, enable_intake=intake)
    want = ",".join(VERIFY_KEYS)
    assert got["locals"]["overrides_env"][VERIFY] == want
    assert got["locals"]["base_env"][VERIFY] == want
    one = _evaluate(tmp_path / "one", _files(), **{**ON, "overrides_verify_keys": VERIFY_KEYS[:1]},
                    enable_intake=intake)
    assert one["locals"]["base_env"][VERIFY] == VERIFY_KEYS[0]


def test_the_form_key_reaches_the_dashboard_as_a_secret_reference():
    body = _services()["dashboard"]
    dynamic = [inner for k, labels, inner in aca._blocks(_walk(body, "containers")[0])
               if k == "dynamic" and labels == ["env"] and 'role_secrets["dashboard"]' in inner]
    assert len(dynamic) == 1
    [ref] = _walk(dynamic[0], "secret_key_ref")
    assert _attr(ref, "secret") == "env.value"
    for name, other in _services().items():
        if name != "dashboard":
            assert 'role_secrets["dashboard"]' not in other, name


# --- refused ---------------------------------------------------------------------------

def _preconditions() -> list[tuple[str, str]]:
    [lifecycle] = _walk(_services()["dashboard"], "lifecycle")
    out = [(_attr(b, "condition"), _attr(b, "error_message")) for b in _walk(lifecycle, "precondition")]
    assert len(out) == 5, out
    return out


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    root = tmp_path_factory.mktemp("cloudrun-admins")
    shutil.copy(MODULE / "variables.tf", root / "variables.tf")
    checks = "".join(
        f"    precondition {{\n      condition     = {c}\n      error_message = {m}\n    }}\n"
        for c, m in _preconditions())
    (root / "main.tf").write_text(
        'resource "terraform_data" "dashboard" {\n  lifecycle {\n' + checks + "  }\n}\n", encoding="utf-8")
    out = subprocess.run([terraform, f"-chdir={root}", "init", "-input=false", "-no-color"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return root


def _plan(root: Path, **variables) -> subprocess.CompletedProcess:
    (root / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}), encoding="utf-8")
    return subprocess.run([terraform, f"-chdir={root}", "plan", "-input=false", "-no-color",
                           "-lock=false", "-refresh=false"], capture_output=True, text=True, timeout=120)


@requires_terraform
def test_off_plans_with_nothing_set(harness):
    out = _plan(harness)
    assert out.returncode == 0, out.stderr


@requires_terraform
@pytest.mark.parametrize("variables,fragment", [
    (ON, "signs in through IAP, whose tokens carry no groups"),
    ({"dashboard_admins_enabled": True}, "needs dashboard_form_key_secret_id"),
    ({**ON, "overrides_writer_lockout": False}, "needs overrides_writer_lockout"),
    ({k: v for k, v in ON.items() if k != "dashboard_signing_key_secret_id"},
     "needs dashboard_signing_key_secret_id, the secret holding FORGD_OVERRIDES_SIGNING_KEY"),
    ({k: v for k, v in ON.items() if k != "overrides_verify_keys"},
     "needs overrides_verify_keys, the public keys listed in FORGD_OVERRIDES_VERIFY_KEY"),
])
def test_admins_are_refused_at_plan(harness, variables, fragment):
    out = _plan(harness, **variables)
    assert out.returncode != 0, out.stdout
    assert fragment in aca._flat(out.stderr), out.stderr


# Each precondition but the IAP refusal, by the fragment its message carries.
NEEDS = ("needs overrides_writer_lockout", "needs dashboard_form_key_secret_id",
         "needs dashboard_signing_key_secret_id", "needs overrides_verify_keys")


@requires_terraform
def test_with_everything_set_only_the_iap_refusal_remains(harness):
    out = _plan(harness, **ON)
    assert out.returncode != 0, out.stdout
    assert "signs in through IAP" in aca._flat(out.stderr), out.stderr
    for fragment in NEEDS:
        assert fragment not in aca._flat(out.stderr), (fragment, out.stderr)


@requires_terraform
@pytest.mark.parametrize("missing,fragment", [
    ("dashboard_signing_key_secret_id", "needs dashboard_signing_key_secret_id"),
    ("overrides_verify_keys", "needs overrides_verify_keys"),
])
def test_each_key_precondition_fires_as_its_own(harness, missing, fragment):
    """With one key left out, its own precondition fires and no other
    precondition but the IAP refusal does.

    Mutation: test the form key, or the other key, in the precondition."""
    out = _plan(harness, **{k: v for k, v in ON.items() if k != missing})
    assert out.returncode != 0, out.stdout
    flat = aca._flat(out.stderr)
    assert fragment in flat, out.stderr
    for other in NEEDS:
        if other != fragment:
            assert other not in flat, (other, out.stderr)


@requires_terraform
@pytest.mark.parametrize("variables,fragment", [
    ({"dashboard_signing_key_secret_id": "overrides-signing-key"}, "dashboard_signing_key_secret_id must be empty"),
    ({"dashboard_signing_key_secret_id": "projects/p/secrets/a/versions/1"},
     "dashboard_signing_key_secret_id must be empty"),
    ({"overrides_verify_keys": ["short"]}, "overrides_verify_keys must list Ed25519 public keys"),
    ({"overrides_verify_keys": [VERIFY_KEYS[0][:42]]}, "overrides_verify_keys must list Ed25519 public keys"),
    ({"overrides_verify_keys": [VERIFY_KEYS[0] + "A"]}, "overrides_verify_keys must list Ed25519 public keys"),
    ({"overrides_verify_keys": [VERIFY_KEYS[0][:42] + "="]}, "overrides_verify_keys must list Ed25519 public keys"),
    ({"overrides_verify_keys": [VERIFY_KEYS[0][:42] + "+"]}, "overrides_verify_keys must list Ed25519 public keys"),
    ({"overrides_verify_keys": [VERIFY_KEYS[0], ""]}, "overrides_verify_keys must list Ed25519 public keys"),
    ({"overrides_verify_keys": [",".join(VERIFY_KEYS)]}, "overrides_verify_keys must list Ed25519 public keys"),
], ids=["signing-not-an-id", "signing-a-version", "verify-short", "verify-42", "verify-44", "verify-padded",
        "verify-standard-alphabet", "verify-empty-entry", "verify-joined-in-one"])
def test_the_key_variables_refuse_bad_input(harness, variables, fragment):
    """Admins off, so only the validation can refuse.

    Mutation: loosen either regex (drop the anchors, or allow + and =)."""
    out = _plan(harness, **variables)
    assert out.returncode != 0, out.stdout
    assert fragment in aca._flat(out.stderr), out.stderr


@requires_terraform
def test_the_key_variables_accept_good_input(harness):
    out = _plan(harness, dashboard_signing_key_secret_id=SIGNING_KEY, overrides_verify_keys=VERIFY_KEYS)
    assert out.returncode == 0, out.stderr


# --- FORGD_OVERRIDES_ENABLED --------------------------------------------------------

ENABLED = "FORGD_OVERRIDES_ENABLED"
WRITER_ROLES = "FORGD_OVERRIDES_WRITER_ROLES"
# Every service: the connector and the intake on.
RENDER = {**REQUIRED, **SERVICES_ON, "enable_intake": True,
          "intake_token_secret_ids": {"dev": SECRET + "intake"}}
NO_INTAKE = {**REQUIRED, **SERVICES_ON, "enable_intake": False}


def _locals() -> dict[str, str]:
    out = {}
    for k, _, inner in aca._blocks(_files()["main.tf"]):
        if k == "locals":
            out |= aca._assignments(inner)
    return out


def test_every_container_takes_overrides_enabled_from_base_env():
    """The module refuses dashboard_admins_enabled at plan, so the rendering
    cannot show the variables on; the source shows where they would come from.

    Mutation: drop overrides_env from base_env, or base_env from one container."""
    found = _locals()
    # _assignments keeps the comment lines that follow an assignment.
    assert aca._flat(found["overrides_env"]).split(" # ")[0] == (
        'var.dashboard_admins_enabled ? { FORGD_OVERRIDES_ENABLED = "true" '
        f'FORGD_OVERRIDES_WRITER_ROLES = {WRITER_ROLES_EXPR} '
        f'FORGD_OVERRIDES_VERIFY_KEY = {VERIFY_KEYS_EXPR} }} : {{}}')
    assert aca._flat(found["base_env"]).endswith("}, local.org_env, local.overrides_env)")
    containers = {}
    for k, labels, inner in aca._blocks(_files()["main.tf"]):
        if k == "resource" and labels[0] in ("google_cloud_run_v2_service", "google_cloud_run_v2_job"):
            for i, (kind, _, body) in enumerate(b for b in _blocks_deep(inner) if b[0] == "containers"):
                containers[f"{labels[1]}.{i}"] = [
                    aca._flat(_attr(env, "for_each") or "") for kind, dyn, env in aca._blocks(body)
                    if kind == "dynamic" and dyn == ["env"]]
    assert len(containers) >= 6, containers
    for name, for_eaches in containers.items():
        assert any(f.startswith("merge(local.base_env") for f in for_eaches), (name, for_eaches)


@requires_terraform
def test_on_the_full_module_is_refused_at_plan(tmp_path):
    with pytest.raises(AssertionError, match="signs in through IAP"):
        terraform_render.render_module(tmp_path, "app-cloudrun", {**RENDER, **ON})


@requires_terraform
@pytest.mark.parametrize("intake", [True, False], ids=["intake", "no-intake"])
@pytest.mark.parametrize("left_set", [False, True], ids=["unset", "admin-inputs-left-set"])
def test_off_no_resource_has_overrides_enabled_and_the_plan_is_the_baseline(tmp_path, left_set, intake):
    """Every resource, rendered in full, equals the pinned baseline's rendering
    of the same variables.

    Mutation: set FORGD_OVERRIDES_ENABLED, FORGD_OVERRIDES_WRITER_ROLES,
    FORGD_OVERRIDES_VERIFY_KEY or FORGD_OVERRIDES_SIGNING_KEY whatever
    dashboard_admins_enabled says."""
    variables = RENDER if intake else NO_INTAKE
    current = {k: v for k, v in ON.items() if k != "dashboard_admins_enabled"} if left_set else {}
    assert terraform_render.off_versus_baseline(tmp_path, "app-cloudrun", variables, current) == []
    rendered = terraform_render.render_module(tmp_path / "off", "app-cloudrun", {**variables, **current})
    for name in (ENABLED, WRITER_ROLES, SIGNING, VERIFY, SIGNING_KEY, *VERIFY_KEYS):
        assert name not in json.dumps(rendered), name


# --- FORGD_OVERRIDES_WRITER_ROLES -----------------------------------------------------

# The resource that deploys each writer role, in the order the variable lists them.
WRITER_RESOURCES = {
    "verdict": "google_cloud_run_v2_service.verdict",
    "collector": "google_cloud_run_v2_service.collector",
    "intake": "google_cloud_run_v2_service.intake",
    "ingest": "google_cloud_run_v2_job.ingest",
}


def _deployed_writers(got: dict) -> str:
    return ",".join(r for r, address in WRITER_RESOURCES.items() if got["resources"][address])


def test_each_writer_resource_runs_its_role():
    """WRITER_RESOURCES reads a role off the resource that runs it."""
    blocks = {".".join(labels): inner for k, labels, inner in aca._blocks(_files()["main.tf"]) if k == "resource"}
    for role, address in WRITER_RESOURCES.items():
        found = re.findall(r'\bFORGD_ROLE\s*=\s*"(\w+)"', blocks[address])
        assert [aca_admins.WRITER_OF[r] for r in found] == [role], (address, found)


def test_each_writer_resource_runs_as_a_service_account_of_its_own():
    """Every writer role is listed, ingest included, because each runs as its
    own account from google_service_account.role, keyed by role.

    Mutation: run a writer resource as another role's account."""
    blocks = {".".join(labels): inner for k, labels, inner in aca._blocks(_files()["main.tf"]) if k == "resource"}
    for role, address in WRITER_RESOURCES.items():
        found = re.findall(r'\bservice_account\s*=\s*(\S+)', blocks[address])
        assert found == [f'google_service_account.role["{role}"].email'], (address, found)


@requires_terraform
@pytest.mark.parametrize("intake", [True, False], ids=["intake", "no-intake"])
def test_on_the_writer_roles_are_the_roles_the_plan_deploys(tmp_path, intake):
    """Evaluated with admins on, the refusal aside: Cloud Run always runs
    verdict, collector and ingest, and intake with enable_intake, each as its
    own identity, so every one is listed. Every container takes the variable
    from base_env, above.

    Mutation: list a role the module does not deploy, or leave one out."""
    got = _evaluate(tmp_path / "on", _files(), **ON, enable_intake=intake)
    want = "verdict,collector,intake,ingest" if intake else "verdict,collector,ingest"
    assert _deployed_writers(got) == want
    assert got["locals"]["overrides_env"] == {ENABLED: "true", WRITER_ROLES: want, VERIFY: ",".join(VERIFY_KEYS)}
    assert got["locals"]["base_env"][WRITER_ROLES] == want


@requires_terraform
def test_a_writer_roles_list_that_always_names_intake_is_caught(tmp_path):
    """The check above fails on a module that lists intake whether or not it deploys it."""
    files = _files()
    assert files["main.tf"].count(WRITER_ROLES_EXPR) == 1
    files["main.tf"] = files["main.tf"].replace(WRITER_ROLES_EXPR, '"verdict,collector,intake,ingest"')
    got = _evaluate(tmp_path / "edited", files, **ON, enable_intake=False)
    assert got["locals"]["overrides_env"][WRITER_ROLES] != _deployed_writers(got)
