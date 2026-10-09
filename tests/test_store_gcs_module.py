"""The store-gcs module grants delete on the store's mutable objects only.

GCS checks `storage.objects.delete` on any write that replaces an object, so
the writer holds it, through an IAM condition, on the cursors and the two
markers. These checks pin that the condition is exactly that, that nothing
else grants delete, and that the reader has none.

Parsed from the .tf source, because nothing here may call Google Cloud. The
delete condition is also evaluated by terraform with no provider and matched
against the object names GCSStore actually writes. Each check first asserts
it found what it is about, so a rename or a parse that matches nothing fails
rather than passing on an empty list.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from terraform_render import off_versus_baseline
from test_app_ecs import _attr, _blocks, _walk
from test_store_conformance import _install_fake_gcs, den, rec

from forgd_verdict.store import open_store
from forgd_verdict.store.base import EXCLUDE_MARKER, RESET_MARKER, STATE_PREFIX

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "deploy" / "terraform" / "modules" / "store-gcs"
MAIN = MODULE / "main.tf"
VARIABLES = MODULE / "variables.tf"
OUTPUTS = MODULE / "outputs.tf"
README = ROOT / "deploy" / "terraform" / "README.md"

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

WRITER = '"serviceAccount:${google_service_account.writer.email}"'
READER = '"serviceAccount:${google_service_account.reader.email}"'
# Every bucket binding iterates one of these: the module's account and the
# extras from writer_members or reader_members.
WRITERS = "local.writer_members"
READERS = "local.reader_members"
# The readers' binding iterates the readers and the control members; the
# control identity's writes iterate the control members alone.
READS = "local.read_members"
CONTROLS = "local.control_members"
CREATOR = '"roles/storage.objectCreator"'
VIEWER = '"roles/storage.objectViewer"'
DELETE_ROLE = "google_project_iam_custom_role.mutable_delete.id"
CONDITION = "local.mutable_delete_condition"
DATA_CONDITION = "local.data_condition"
CONTROL_CREATE = "local.control_create_condition"
CONTROL_DELETE = "local.control_delete_condition"
WRITER_CREATE = "local.writer_create_condition"
WRITER_DELETE = "local.writer_delete_condition"
OVERRIDES_OBJECT = "state/runtime-overrides.json"
AUDIT_PREFIX = "audit/runtime-overrides/"

# Predefined roles that hold storage.objects.delete, or grant IAM on the
# bucket, which amounts to the same thing.
DELETE_CAPABLE_ROLES = (
    "roles/storage.admin",
    "roles/storage.objectAdmin",
    "roles/storage.objectUser",
    "roles/storage.legacyBucketOwner",
    "roles/storage.legacyBucketWriter",
    "roles/storage.legacyObjectOwner",
    "roles/storage.folderAdmin",
    "roles/storage.bucketViewer",
    "roles/owner",
    "roles/editor",
)

# Resource types that grant access somewhere other than a single member on
# this bucket: project, folder and organization IAM, authoritative bucket
# policies that would replace every other binding, and ACLs.
FORBIDDEN_TYPES = re.compile(
    r"^google_(project|folder|organization)_iam_(member|binding|policy|audit_config)$"
    r"|^google_storage_bucket_iam_(binding|policy)$"
    r"|^google_storage_(bucket_acl|object_acl|default_object_acl"
    r"|bucket_access_control|object_access_control|default_object_access_control)$"
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code(text: str) -> str:
    """`text` without comments."""
    return re.sub(r"(?m)^\s*#.*$", "", text)


def _resources(kind: str | None = None) -> dict[tuple[str, str], str]:
    return {(labels[0], labels[1]): inner for k, labels, inner in _blocks(_code(_text(MAIN)))
            if k == "resource" and (kind is None or labels[0] == kind)}


def _bindings() -> dict[str, str]:
    found = {name: inner for (_, name), inner in _resources("google_storage_bucket_iam_member").items()}
    assert found, "no bucket IAM members found"
    return found


def _locals() -> dict[str, str]:
    body = next(inner for k, _, inner in _blocks(_code(_text(MAIN))) if k == "locals")
    starts = list(re.finditer(r"^  (\w+)\s*=", body, re.M))
    return {m.group(1): body[m.end():(starts[i + 1].start() if i + 1 < len(starts) else len(body))].strip()
            for i, m in enumerate(starts)}


def _expected_clauses(bucket: str, prefix: str) -> set[tuple[str, str]]:
    root = f"projects/_/buckets/{bucket}/objects/{prefix + '/' if prefix else ''}"
    return {
        ("startsWith", f"{root}{STATE_PREFIX}/"),
        ("==", f"{root}{RESET_MARKER}"),
        ("==", f"{root}{EXCLUDE_MARKER}"),
    }


def _clauses(cel: str) -> set[tuple[str, str]]:
    """The condition as a set of (operator, operand). Anything but a flat
    disjunction of those two clause shapes fails, so no clause can hide."""
    out = set()
    parts = cel.split(" || ")
    for part in parts:
        m = re.fullmatch(r'resource\.name\.startsWith\("([^"\\]*)"\)', part)
        if m:
            out.add(("startsWith", m.group(1)))
            continue
        m = re.fullmatch(r'resource\.name == "([^"\\]*)"', part)
        assert m, f"unexpected clause in the delete condition: {part!r}"
        out.add(("==", m.group(1)))
    assert len(out) == len(parts), cel
    return out


def _matches(clauses: set[tuple[str, str]], object_name: str, bucket: str) -> bool:
    name = f"projects/_/buckets/{bucket}/objects/{object_name}"
    return any(name.startswith(v) if op == "startsWith" else name == v for op, v in clauses)


def _split_and(cel: str) -> list[str]:
    """`cel`'s top-level conjuncts."""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(cel):
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if depth == 0 and cel.startswith(" && ", i):
            parts.append(cel[start:i])
            start = i + 4
    return [*parts, cel[start:]]


def _conjunction(cel: str) -> tuple[list[set[tuple[str, str]]], set[str]]:
    """(the disjunctions every name must match, the prefixes no name may
    start with). Anything but conjuncts of those two shapes fails."""
    allowed, excluded = [], set()
    for part in _split_and(cel):
        m = re.fullmatch(r'!resource\.name\.startsWith\("([^"\\]*)"\)', part)
        if m:
            excluded.add(m.group(1))
            continue
        if part.startswith("(") and part.endswith(")"):
            part = part[1:-1]
        allowed.append(_clauses(part))
    return allowed, excluded


def _admits(cel: str, object_name: str, bucket: str) -> bool:
    allowed, excluded = _conjunction(cel)
    name = f"projects/_/buckets/{bucket}/objects/{object_name}"
    return (all(_matches(c, object_name, bucket) for c in allowed)
            and not any(name.startswith(p) for p in excluded))


def _expected_exclusions(bucket: str, prefix: str) -> set[str]:
    root = f"projects/_/buckets/{bucket}/objects/{prefix + '/' if prefix else ''}"
    return {f"{root}{OVERRIDES_OBJECT}", f"{root}{AUDIT_PREFIX}"}


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([terraform, f"-chdir={cwd}", *args, "-no-color"],
                          capture_output=True, text=True, timeout=120)


def _evaluate(tmp_path: Path, exprs: dict[str, str], **variables) -> dict:
    """Each expression's value, computed by terraform against the module's
    variables.tf and the locals the expressions read. No provider is
    involved; the bucket's name is taken from var.bucket_name."""
    exprs = {n: e.replace("google_storage_bucket.findings.name", "var.bucket_name")
             for n, e in exprs.items()}
    all_locals, needed, pending = _locals(), {}, list(exprs.values())
    while pending:
        for name in re.findall(r"\blocal\.(\w+)", pending.pop()):
            if name not in needed:
                needed[name] = _no_resources(all_locals[name])
                pending.append(needed[name])
    shutil.copy(VARIABLES, tmp_path / "variables.tf")
    (tmp_path / "main.tf").write_text(
        "locals {\n" + "".join(f"  {n} = {e}\n" for n, e in needed.items()) + "}\n"
        + "".join(f'output "{n}" {{\n  value = {e}\n}}\n' for n, e in exprs.items()),
        encoding="utf-8")
    out = _apply(tmp_path, **variables)
    assert out.returncode == 0, out.stderr
    out = subprocess.run([terraform, f"-chdir={tmp_path}", "output", "-json"],
                         capture_output=True, text=True, timeout=60, check=True)
    return {k: v["value"] for k, v in json.loads(out.stdout).items()}


REQUIRED = {"project_id": "p", "bucket_name": "forgd-findings", "location": "EU"}

# What the module's two accounts stand for when an expression is evaluated
# with no provider.
EMAILS = {"writer": "forgd-verdict-writer@p.iam.gserviceaccount.com",
          "reader": "forgd-dashboard-reader@p.iam.gserviceaccount.com",
          "control[0]": "forgd-dashboard-control@p.iam.gserviceaccount.com"}


def _no_resources(expr: str) -> str:
    for account, email in EMAILS.items():
        expr = expr.replace(f"${{google_service_account.{account}.email}}", email)
    return expr


def _apply(tmp_path: Path, **variables) -> subprocess.CompletedProcess:
    if not (tmp_path / "variables.tf").exists():
        shutil.copy(VARIABLES, tmp_path / "variables.tf")
    (tmp_path / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}),
                                                    encoding="utf-8")
    out = _run(["init", "-input=false"], tmp_path)
    assert out.returncode == 0, out.stderr
    return _run(["apply", "-auto-approve", "-input=false"], tmp_path)


# --- the shape of the module ---------------------------------------------


def test_the_module_is_exactly_main_variables_and_outputs():
    """Every check here reads main.tf. A binding in another file -- an
    override, a .tf.json, a dotfile -- is one none of them sees. Only the
    cache and lock file `terraform init` leaves behind, both gitignored, are
    allowed beside the three."""
    names = sorted(p.name for p in MODULE.iterdir()
                   if p.name not in (".terraform", ".terraform.lock.hcl"))
    assert names == ["main.tf", "outputs.tf", "variables.tf"], names
    for other in (OUTPUTS, VARIABLES):
        assert not re.search(r"^\s*(resource|data|locals|module|provider)\b",
                             _code(_text(other)), re.M), other.name


# The one project-level grant: the control identity's read of role
# definitions, for the lockout check.
ROLE_READ = ("google_project_iam_member", "control_role_read")
ROLE_READ_ROLE = "google_project_iam_custom_role.control_role_read[0].id"


def test_no_resource_grants_access_beyond_a_member_on_this_bucket():
    """Except the control identity's iam.roles.get on the project. Mutation:
    add a permission to that role, or bind it to a writer."""
    resources = _resources()
    types = {kind for kind, _ in resources}
    assert "google_storage_bucket_iam_member" in types, types
    forbidden = {key for key in resources if FORBIDDEN_TYPES.match(key[0])}
    assert forbidden == {ROLE_READ}, forbidden
    binding = resources[ROLE_READ]
    assert _attr(binding, "for_each") == CONTROLS
    assert _attr(binding, "role") == ROLE_READ_ROLE
    assert _attr(binding, "member") == "each.value"
    assert _attr(binding, "project") == "var.project_id"
    assert not [k for k, _, _ in _blocks(binding) if k == "condition"]
    role = resources[("google_project_iam_custom_role", "control_role_read")]
    assert _attr(role, "permissions") == '["iam.roles.get"]'
    assert _attr(role, "count") == "var.control_enabled ? 1 : 0"
    assert _code(_text(MAIN)).count("control_role_read[0]") == 1


# --- the bucket ------------------------------------------------------------


def _bucket() -> str:
    buckets = _resources("google_storage_bucket")
    assert list(buckets) == [("google_storage_bucket", "findings")], list(buckets)
    return buckets[("google_storage_bucket", "findings")]


def test_the_bucket_is_private_versioned_and_survives_a_destroy():
    bucket = _bucket()
    assert _attr(bucket, "force_destroy") == "false"
    assert _attr(bucket, "uniform_bucket_level_access") == "true"
    assert _attr(bucket, "public_access_prevention") == '"enforced"'
    versioning = _walk(bucket, "versioning")
    assert len(versioning) == 1 and _attr(versioning[0], "enabled") == "true"


def test_nothing_deletes_on_a_timer():
    code = _code(_text(MAIN))
    assert "google_storage_bucket" in code
    assert "lifecycle_rule" not in code
    assert "soft_delete_policy" not in code


def test_a_kms_key_encrypts_the_bucket_when_one_is_given():
    enc = [inner for k, labels, inner in _blocks(_bucket())
           if k == "dynamic" and labels == ["encryption"]]
    assert len(enc) == 1 and _attr(enc[0], "for_each") == "local.kms ? [1] : []"
    content = _walk(enc[0], "content")
    assert len(content) == 1 and _attr(content[0], "default_kms_key_name") == "var.kms_key_name"


# --- who holds what --------------------------------------------------------


def test_the_writers_hold_create_read_and_the_scoped_delete_only():
    roles = {_attr(b, "role") for b in _bindings().values() if _attr(b, "for_each") == WRITERS}
    assert roles == {CREATOR, VIEWER, DELETE_ROLE}, roles


def test_the_readers_hold_read_only():
    roles = [_attr(b, "role") for b in _bindings().values() if _attr(b, "for_each") == READS]
    assert roles == [VIEWER], roles


def test_every_binding_is_one_member_of_the_writers_the_readers_or_the_controls():
    """Each binding iterates the writers, the readers (with the control
    members) or the control members, and binds the member it is iterating,
    so a binding cannot name anyone else."""
    for name, binding in _bindings().items():
        assert _attr(binding, "for_each") in (WRITERS, READS, CONTROLS), name
        assert _attr(binding, "member") == "each.value", name


def test_the_writers_and_readers_are_the_modules_account_and_the_extras():
    """The module's own account under a fixed key and each extra under its
    caller's key, so that for_each keys are known at plan time when an
    extra's email is not, and removing one extra leaves the rest in place."""
    got = {k: " ".join(v.split()) for k, v in _locals().items() if k in ("writer_members", "reader_members")}
    for account, member in (("writer", WRITER), ("reader", READER)):
        assert got[f"{account}_members"] == (
            f'merge( {{ module = {member} }}, '
            f'{{ for k, m in var.{account}_members : "extra-${{k}}" => m }}, )'), got


@requires_terraform
def test_extras_become_members_under_their_own_keys(tmp_path):
    extra = {"verdict": "serviceAccount:verdict@p.iam.gserviceaccount.com",
             "ingest": "serviceAccount:ingest@p.iam.gserviceaccount.com"}
    got = _evaluate(tmp_path, {"w": WRITERS, "r": READERS}, writer_members=extra,
                    reader_members={"dashboard": "serviceAccount:dashboard@p.iam.gserviceaccount.com"})
    assert got["w"] == {"module": f"serviceAccount:{EMAILS['writer']}",
                        "extra-verdict": extra["verdict"], "extra-ingest": extra["ingest"]}, got
    assert got["r"] == {"module": f"serviceAccount:{EMAILS['reader']}",
                        "extra-dashboard": "serviceAccount:dashboard@p.iam.gserviceaccount.com"}, got


@requires_terraform
def test_removing_one_extra_leaves_the_others_keys_unchanged(tmp_path):
    """Keyed by position, dropping intake would move ingest to a new key, and
    the replaced binding's destroy can remove the one just created for it."""
    both = {"intake": "serviceAccount:intake@p.iam.gserviceaccount.com",
            "ingest": "serviceAccount:ingest@p.iam.gserviceaccount.com"}
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    before = _evaluate(tmp_path / "a", {"w": WRITERS}, writer_members=both)["w"]
    after = _evaluate(tmp_path / "b", {"w": WRITERS}, writer_members={"ingest": both["ingest"]})["w"]
    assert before["extra-ingest"] == after["extra-ingest"] == both["ingest"]


@requires_terraform
@pytest.mark.parametrize("variable", ["writer_members", "reader_members"])
@pytest.mark.parametrize("member", ["allUsers", "allAuthenticatedUsers", "domain:example.com",
                                    "verdict@p.iam.gserviceaccount.com", "serviceAccount:"])
def test_an_extra_member_that_is_not_one_identity_is_refused(tmp_path, variable, member):
    out = _apply(tmp_path, **{variable: {"x": member}})
    assert out.returncode != 0 and "Invalid value for variable" in out.stderr, out.stderr


def test_an_extra_writers_delete_is_conditioned_exactly_like_the_writers():
    """The module's writer and every extra share one delete binding, which
    always carries the mutable-object condition; nothing else binds the
    delete role."""
    deletes = {n: b for n, b in _bindings().items() if _attr(b, "role") == DELETE_ROLE
               and _attr(b, "for_each") != CONTROLS}
    assert list(deletes) == ["writer_mutable_delete"], list(deletes)
    binding = deletes["writer_mutable_delete"]
    assert _attr(binding, "for_each") == WRITERS
    assert _attr(binding, "member") == "each.value"
    conditions = [inner for k, _, inner in _blocks(binding) if k == "condition"]
    assert len(conditions) == 1 and _attr(conditions[0], "expression") == WRITER_DELETE


@requires_terraform
@pytest.mark.parametrize("prefix", ["", "org/prod"])
def test_every_writers_delete_condition_evaluates_to_the_same_names(tmp_path, prefix):
    """Evaluated per member of the writers: the module's account and an extra
    get the same condition, with the same prefix."""
    got = _evaluate(tmp_path, {"c": f"{{ for k, m in {WRITERS} : k => {WRITER_DELETE} }}"},
                    key_prefix=prefix, control_enabled=True,
                    writer_members={"verdict": "serviceAccount:verdict@p.iam.gserviceaccount.com"})
    assert sorted(got["c"]) == ["extra-verdict", "module"], got
    for key, cel in got["c"].items():
        allowed, excluded = _conjunction(cel)
        assert allowed == [_expected_clauses("forgd-findings", prefix)], (key, cel)
        assert excluded == _expected_exclusions("forgd-findings", prefix), (key, cel)


def test_an_extra_reader_gets_only_read_under_the_data_condition():
    readers = {n: b for n, b in _bindings().items() if _attr(b, "for_each") == READS}
    assert list(readers) == ["reader_read"], list(readers)
    binding = readers["reader_read"]
    assert _attr(binding, "role") == VIEWER
    dynamic = [inner for k, labels, inner in _blocks(binding) if k == "dynamic" and labels == ["condition"]]
    assert len(dynamic) == 1
    assert _attr(_walk(dynamic[0], "content")[0], "expression") == DATA_CONDITION
    # And no writer binding iterates the readers.
    assert "var.reader_members" not in _locals()["writer_members"]


def test_existing_bindings_move_to_the_modules_key():
    """Before the extras, each binding was a single resource. Without a
    `moved` block a plan destroys that address, which removes the binding
    its replacement holds."""
    moves = [inner for k, _, inner in _blocks(_code(_text(MAIN))) if k == "moved"]
    got = {(_attr(m, "from"), _attr(m, "to")) for m in moves}
    assert got == {(f"google_storage_bucket_iam_member.{n}", f'google_storage_bucket_iam_member.{n}["module"]')
                   for n in ("writer_create", "writer_read", "writer_mutable_delete", "reader_read")}, got


def test_no_predefined_role_that_can_delete_appears():
    code = _code(_text(MAIN))
    assert CREATOR.strip('"') in code
    assert not [r for r in DELETE_CAPABLE_ROLES if f'"{r}"' in code]
    roles = set(re.findall(r'"(roles/[^"]+)"', code))
    assert roles == {"roles/storage.objectCreator", "roles/storage.objectViewer",
                     "roles/cloudkms.cryptoKeyEncrypterDecrypter"}, roles


def test_the_custom_role_is_delete_and_nothing_else():
    roles = _resources("google_project_iam_custom_role")
    assert sorted(roles) == [("google_project_iam_custom_role", "control_iam_read"),
                             ("google_project_iam_custom_role", "control_role_read"),
                             ("google_project_iam_custom_role", "mutable_delete")], list(roles)
    assert _attr(roles[("google_project_iam_custom_role", "mutable_delete")],
                 "permissions") == '["storage.objects.delete"]'


def test_the_iam_read_role_is_get_iam_policy_only_and_only_with_control():
    """The control identity's read of the lockout evidence. Mutation: add a
    permission, or create the role with control off."""
    role = _resources("google_project_iam_custom_role")[
        ("google_project_iam_custom_role", "control_iam_read")]
    assert _attr(role, "permissions") == '["storage.buckets.getIamPolicy"]'
    assert _attr(role, "count") == "var.control_enabled ? 1 : 0"


def test_every_delete_grant_is_the_writers_and_carries_the_condition():
    """Any binding of a role other than create or read must be the delete
    role, on the writer, conditioned on exactly the mutable objects, or the
    control identity's, conditioned on the overrides object."""
    others = {name: b for name, b in _bindings().items()
              if _attr(b, "role") not in (CREATOR, VIEWER)}
    assert sorted(others) == ["control_iam_read", "control_overrides_delete",
                              "writer_mutable_delete"], list(others)
    iam_read = others.pop("control_iam_read")
    assert _attr(iam_read, "role") == "google_project_iam_custom_role.control_iam_read[0].id"
    assert _attr(iam_read, "for_each") == CONTROLS
    control = others.pop("control_overrides_delete")
    assert _attr(control, "role") == DELETE_ROLE
    assert _attr(control, "for_each") == CONTROLS
    conditions = [inner for k, _, inner in _blocks(control) if k == "condition"]
    assert len(conditions) == 1 and _attr(conditions[0], "expression") == CONTROL_DELETE
    assert not [1 for k, _, _ in _blocks(control) if k == "dynamic"]
    binding = others["writer_mutable_delete"]
    assert _attr(binding, "role") == DELETE_ROLE
    assert _attr(binding, "for_each") == WRITERS
    conditions = [inner for k, _, inner in _blocks(binding) if k == "condition"]
    assert len(conditions) == 1, "the delete grant has no unconditional condition block"
    assert _attr(conditions[0], "expression") == WRITER_DELETE
    assert not [1 for k, _, _ in _blocks(binding) if k == "dynamic"], (
        "the delete condition must always apply, not only with a key prefix")


def test_each_read_binding_is_scoped_to_the_prefix_when_there_is_one():
    """Read, for both accounts: conditioned on DATA_CONDITION whenever
    `key_prefix` is set, and on nothing else."""
    data = {name: b for name, b in _bindings().items() if _attr(b, "role") in (CREATOR, VIEWER)
            and _attr(b, "for_each") not in (CONTROLS,) and name != "writer_create"}
    assert sorted(data) == ["reader_read", "writer_read"], sorted(data)
    for name, binding in data.items():
        assert not [1 for k, _, _ in _blocks(binding) if k == "condition"], name
        dynamic = [inner for k, labels, inner in _blocks(binding)
                   if k == "dynamic" and labels == ["condition"]]
        assert len(dynamic) == 1, f"{name} is not scoped to the key prefix"
        assert _attr(dynamic[0], "for_each") == "local.prefix_scoped ? [1] : []", name
        content = _walk(dynamic[0], "content")
        assert len(content) == 1 and _attr(content[0], "expression") == DATA_CONDITION, name


def test_the_writers_create_carries_its_condition_with_control_or_a_prefix():
    """With control_enabled, the exclusion holds without a key prefix too."""
    binding = _bindings()["writer_create"]
    assert _attr(binding, "role") == CREATOR and _attr(binding, "for_each") == WRITERS
    assert not [1 for k, _, _ in _blocks(binding) if k == "condition"]
    dynamic = [inner for k, labels, inner in _blocks(binding) if k == "dynamic" and labels == ["condition"]]
    assert len(dynamic) == 1
    assert _attr(dynamic[0], "for_each") == "var.control_enabled || local.prefix_scoped ? [1] : []"
    content = _walk(dynamic[0], "content")
    assert len(content) == 1 and _attr(content[0], "expression") == WRITER_CREATE


@requires_terraform
@pytest.mark.parametrize("prefix", ["", "org/prod"])
def test_off_the_writers_conditions_are_the_data_and_mutable_conditions(tmp_path, prefix):
    """Mutation: AND the exclusion on whatever control_enabled says."""
    got = _evaluate(tmp_path, {"c": WRITER_CREATE, "d": WRITER_DELETE, "data": DATA_CONDITION,
                               "mutable": CONDITION}, key_prefix=prefix)
    assert (got["c"], got["d"]) == (got["data"], got["mutable"]), got
    assert "runtime-overrides" not in got["c"] + got["d"], got


def test_the_delete_permission_is_named_only_in_the_custom_role():
    code = _code(_text(MAIN))
    role = _resources("google_project_iam_custom_role")[
        ("google_project_iam_custom_role", "mutable_delete")]
    assert role.count("storage.objects.delete") >= 1
    assert code.count("storage.objects.delete") == role.count("storage.objects.delete")


# --- the condition itself ---------------------------------------------------


@requires_terraform
@pytest.mark.parametrize("prefix", ["", "demo", "org/prod"])
def test_the_condition_is_exactly_the_state_prefix_and_the_two_markers(tmp_path, prefix):
    cel = _evaluate(tmp_path, {"c": CONDITION}, key_prefix=prefix)["c"]
    assert _clauses(cel) == _expected_clauses("forgd-findings", prefix), cel


@requires_terraform
def test_the_condition_covers_what_the_store_replaces_and_no_record(tmp_path, monkeypatch):
    """Matched against the object names GCSStore writes, not against a copy
    of them: every non-record upload must fall inside the condition and
    every record, and anything merely near a mutable name, outside it."""
    bucket, prefix = "forgd-findings", "org/prod"
    clauses = _clauses(_evaluate(tmp_path, {"c": CONDITION}, key_prefix=prefix)["c"])
    gcs = _install_fake_gcs(monkeypatch)
    store = open_store(f"gs://{bucket}/{prefix}", instance="t")
    store.write_verdicts([rec(), rec(tenant_hash="o2")])
    store.write_denials([den()])
    store.put_state("cursor.json", b"{}")
    store.put_state("compliance-o1.json", b"{}")
    store.set_reset_marker("2026-09-26T00:00:00Z")
    store.set_excluded({"r1"})
    uploads = {k: kw["if_generation_match"]
               for op, k, kw in gcs.clients[-1].calls if op == "upload"}
    records = [k for k, gen in uploads.items() if gen == 0]
    mutable = [k for k, gen in uploads.items() if gen is None]
    assert len(records) == 3 and len(mutable) == 4, uploads
    assert all(_matches(clauses, k, bucket) for k in mutable), mutable
    assert not [k for k in records if _matches(clauses, k, bucket)], records
    for near in (f"{prefix}/verdicts/x.jsonl", f"{prefix}/denials/x.jsonl",
                 f"{prefix}/{STATE_PREFIX}", f"{prefix}/{STATE_PREFIX}-old/x",
                 f"{prefix}/{RESET_MARKER}.bak", f"{prefix}/markers/other",
                 f"{STATE_PREFIX}/cursor.json", f"org/{STATE_PREFIX}/cursor.json"):
        assert not _matches(clauses, near, bucket), near


@requires_terraform
@pytest.mark.parametrize("prefix", ['a"b', "a\\b", "/demo", "demo/", "a//b", "a*b"])
def test_a_prefix_that_could_change_the_condition_is_refused(tmp_path, prefix):
    out = _apply(tmp_path, key_prefix=prefix)
    assert out.returncode != 0 and "Invalid value for variable" in out.stderr, out.stderr


@requires_terraform
@pytest.mark.parametrize("name", ['a"b-c', "a.b.c", "googlefindings", "my-google-bucket", "ab"])
def test_a_bucket_name_that_could_change_the_condition_is_refused(tmp_path, name):
    out = _apply(tmp_path, bucket_name=name)
    assert out.returncode != 0 and "Invalid value for variable" in out.stderr, out.stderr


@requires_terraform
@pytest.mark.parametrize("prefix,scoped", [("", False), ("demo", True), ("org/prod", True)])
def test_the_data_condition_is_the_bucket_and_the_prefix_and_applies_only_with_one(
        tmp_path, prefix, scoped):
    got = _evaluate(tmp_path, {"c": DATA_CONDITION, "s": "local.prefix_scoped"},
                    key_prefix=prefix)
    assert got["s"] is scoped
    if scoped:
        bucket = "projects/_/buckets/forgd-findings"
        assert _clauses(got["c"]) == {("==", bucket),
                                      ("startsWith", f"{bucket}/objects/{prefix}/")}, got["c"]


@requires_terraform
def test_the_data_condition_admits_every_store_write_and_nothing_outside_the_prefix(
        tmp_path, monkeypatch):
    bucket, prefix = "forgd-findings", "org/prod"
    clauses = _clauses(_evaluate(tmp_path, {"c": DATA_CONDITION}, key_prefix=prefix)["c"])
    gcs = _install_fake_gcs(monkeypatch)
    store = open_store(f"gs://{bucket}/{prefix}", instance="t")
    store.write_verdicts([rec()])
    store.write_denials([den()])
    store.put_state("cursor.json", b"{}")
    store.set_reset_marker("2026-09-26T00:00:00Z")
    store.set_excluded({"r1"})
    list(store.read_verdicts())
    keys = {k for op, k, _ in gcs.clients[-1].calls if op != "list"}
    assert len(keys) >= 5, keys
    assert all(_matches(clauses, k, bucket) for k in keys), keys
    for outside in ("org/prod-other/verdicts/x.jsonl", "org/verdicts/x.jsonl",
                    "verdicts/x.jsonl", "org/prod", "other/org/prod/x"):
        assert not _matches(clauses, outside, bucket), outside


# --- the control identity ----------------------------------------------------


def _preconditions(resource: str) -> list[str]:
    binding = _bindings()[resource]
    lifecycle = [inner for k, _, inner in _blocks(binding) if k == "lifecycle"]
    assert len(lifecycle) == 1, resource
    found = [_attr(p, "condition") for k, _, p in _blocks(lifecycle[0]) if k == "precondition"]
    assert found, resource
    return found


def test_the_control_identity_holds_create_and_the_delete_role_only():
    controls = {n: b for n, b in _bindings().items() if _attr(b, "for_each") == CONTROLS}
    assert {n: _attr(b, "role") for n, b in controls.items()} == {
        "control_create": CREATOR, "control_overrides_delete": DELETE_ROLE,
        "control_iam_read": "google_project_iam_custom_role.control_iam_read[0].id"}, controls


def test_both_control_writes_always_carry_their_condition():
    """A dynamic condition could be switched off; these are unconditional
    blocks with exactly the control expressions."""
    for name, expr in (("control_create", CONTROL_CREATE), ("control_overrides_delete", CONTROL_DELETE)):
        binding = _bindings()[name]
        assert not [1 for k, _, _ in _blocks(binding) if k == "dynamic"], name
        conditions = [inner for k, _, inner in _blocks(binding) if k == "condition"]
        assert len(conditions) == 1 and _attr(conditions[0], "expression") == expr, name


def test_the_control_members_are_the_modules_account_and_the_extras():
    got = {k: " ".join(v.split()) for k, v in _locals().items() if k in ("control_members", "read_members")}
    assert got["control_members"] == (
        'var.control_enabled ? merge( { control = "serviceAccount:${google_service_account.control[0].email}" }, '
        '{ for k, m in var.control_members : "extra-${k}" => m }, ) : {}'), got
    assert got["read_members"] == "merge(local.reader_members, local.control_members)", got


def test_the_control_account_exists_only_when_enabled():
    accounts = _resources("google_service_account")
    assert _attr(accounts[("google_service_account", "control")], "count") == "var.control_enabled ? 1 : 0"


@requires_terraform
def test_off_by_default_there_is_no_control_member_and_the_readers_are_unchanged(tmp_path):
    got = _evaluate(tmp_path, {"c": CONTROLS, "r": READS, "old": READERS},
                    reader_members={"connector": "serviceAccount:connector@p.iam.gserviceaccount.com"})
    assert got["c"] == {}, got
    assert got["r"] == got["old"] == {
        "module": f"serviceAccount:{EMAILS['reader']}",
        "extra-connector": "serviceAccount:connector@p.iam.gserviceaccount.com"}, got


@requires_terraform
def test_control_members_are_the_account_and_the_extras_and_also_read(tmp_path):
    dashboard = "serviceAccount:dashboard@p.iam.gserviceaccount.com"
    got = _evaluate(tmp_path, {"c": CONTROLS, "r": READS}, control_enabled=True,
                    control_members={"dashboard": dashboard})
    assert got["c"] == {"control": f"serviceAccount:{EMAILS['control[0]']}", "extra-dashboard": dashboard}, got
    assert got["r"] == {"module": f"serviceAccount:{EMAILS['reader']}", **got["c"]}, got


def _expected_control(bucket: str, prefix: str) -> tuple[set, set]:
    root = f"projects/_/buckets/{bucket}/objects/{prefix + '/' if prefix else ''}"
    return ({("==", f"{root}{OVERRIDES_OBJECT}"), ("startsWith", f"{root}{AUDIT_PREFIX}")},
            {("==", f"{root}{OVERRIDES_OBJECT}")})


@requires_terraform
@pytest.mark.parametrize("prefix", ["", "demo", "org/prod"])
def test_the_control_conditions_are_exactly_the_overrides_object_and_the_audit_prefix(tmp_path, prefix):
    got = _evaluate(tmp_path, {"c": CONTROL_CREATE, "d": CONTROL_DELETE}, key_prefix=prefix)
    create, delete = _expected_control("forgd-findings", prefix)
    assert _clauses(got["c"]) == create, got["c"]
    assert _clauses(got["d"]) == delete, got["d"]


@requires_terraform
def test_the_control_writes_reach_nothing_else(tmp_path):
    """Create reaches the overrides object and audit records only; delete
    reaches the overrides object only, so an audit record cannot be
    replaced."""
    bucket, prefix = "forgd-findings", "org/prod"
    got = _evaluate(tmp_path, {"c": CONTROL_CREATE, "d": CONTROL_DELETE}, key_prefix=prefix)
    create, delete = _clauses(got["c"]), _clauses(got["d"])
    audit = f"{prefix}/{AUDIT_PREFIX}2026-09-28/20260928T140311Z-01J8-request.json"
    assert _matches(create, f"{prefix}/{OVERRIDES_OBJECT}", bucket)
    assert _matches(create, audit, bucket)
    assert _matches(delete, f"{prefix}/{OVERRIDES_OBJECT}", bucket)
    assert not _matches(delete, audit, bucket)
    for outside in (f"{prefix}/{STATE_PREFIX}/cursor.json", f"{prefix}/{STATE_PREFIX}/orgs.json",
                    f"{prefix}/{OVERRIDES_OBJECT}.bak", f"{prefix}/{STATE_PREFIX}/runtime-overrides",
                    f"{prefix}/audit/runtime-overrides", f"{prefix}/audit/other/x.json",
                    f"{prefix}/{RESET_MARKER}", f"{prefix}/{EXCLUDE_MARKER}",
                    f"{prefix}/verdicts/x.jsonl", f"{prefix}/denials/x.jsonl",
                    OVERRIDES_OBJECT, f"{AUDIT_PREFIX}x.json", f"org/{OVERRIDES_OBJECT}"):
        assert not _matches(create, outside, bucket), outside
        assert not _matches(delete, outside, bucket), outside


@requires_terraform
@pytest.mark.parametrize("case,ok", [
    ({"control_members": {"dashboard": "serviceAccount:dashboard@p.iam.gserviceaccount.com"}}, True),
    ({"control_members": {"dashboard": "serviceAccount:dashboard@p.iam.gserviceaccount.com"},
      "reader_members": {"dashboard": "serviceAccount:other@p.iam.gserviceaccount.com"}}, False),
    ({"control_members": {"x": "serviceAccount:connector@p.iam.gserviceaccount.com"},
      "reader_members": {"connector": "serviceAccount:connector@p.iam.gserviceaccount.com"}}, False),
    ({"control_members": {"x": "serviceAccount:verdict@p.iam.gserviceaccount.com"},
      "writer_members": {"verdict": "serviceAccount:verdict@p.iam.gserviceaccount.com"}}, False),
    ({"control_members": {"x": f"serviceAccount:{EMAILS['reader']}"}}, False),
    ({"control_members": {"x": f"serviceAccount:{EMAILS['writer']}"}}, False),
])
def test_a_control_member_that_is_a_reader_or_writer_is_refused(tmp_path, case, ok):
    """Evaluated from the precondition expressions in main.tf."""
    conditions = _preconditions("control_create")
    assert len(conditions) == 2, conditions
    got = _evaluate(tmp_path, {f"p{i}": c for i, c in enumerate(conditions)}, control_enabled=True, **case)
    assert all(got.values()) is ok, (case, got)


@requires_terraform
@pytest.mark.parametrize("member", ["allUsers", "domain:example.com", "dashboard@p.iam.gserviceaccount.com"])
def test_a_control_member_that_is_not_one_identity_is_refused(tmp_path, member):
    out = _apply(tmp_path, control_members={"x": member})
    assert out.returncode != 0 and "Invalid value for variable" in out.stderr, out.stderr


def test_the_control_outputs_are_null_unless_enabled():
    outputs = {labels[0]: inner for k, labels, inner in _blocks(_text(OUTPUTS)) if k == "output"}
    assert _attr(outputs["control_email"], "value") == (
        "var.control_enabled ? google_service_account.control[0].email : null")
    assert _attr(outputs["control_member"], "value") == (
        "var.control_enabled ? google_service_account.control[0].member : null")


# --- outputs ---------------------------------------------------------------


@requires_terraform
@pytest.mark.parametrize("prefix,url", [("", "gs://forgd-findings"),
                                        ("demo", "gs://forgd-findings/demo")])
def test_the_store_url_is_what_open_store_dispatches_on(tmp_path, monkeypatch, prefix, url):
    expr = re.search(r"^  value\s*=\s*(.+)$", dict(
        (labels[0], inner) for k, labels, inner in _blocks(_text(OUTPUTS)) if k == "output"
    )["store_url"], re.M).group(1)
    got = _evaluate(tmp_path, {"u": expr}, key_prefix=prefix)["u"]
    assert got == url
    _install_fake_gcs(monkeypatch)
    store = open_store(got, instance="t")
    assert (store.bucket_name, store.prefix) == ("forgd-findings", prefix)


def test_both_emails_are_output():
    outputs = {labels[0]: inner for k, labels, inner in _blocks(_text(OUTPUTS)) if k == "output"}
    assert _attr(outputs["writer_email"], "value") == "google_service_account.writer.email"
    assert _attr(outputs["reader_email"], "value") == "google_service_account.reader.email"


# --- docs --------------------------------------------------------------------


def test_the_readme_explains_what_the_writer_can_delete():
    text = _text(README)
    assert "modules/store-gcs/" in text
    section = text.split("## `store-gcs`", 1)[1].split("\n## ", 1)[0]
    for phrase in ("storage.objects.delete", "rescan", "noncurrent", "dedicated bucket",
                   "storage.objects.list"):
        assert phrase in section, phrase


# --- the writers cannot write the runtime overrides ------------------------


@requires_terraform
@pytest.mark.parametrize("prefix", ["", "demo", "org/prod"])
def test_the_writers_conditions_exclude_the_overrides_object_and_the_audit_prefix(tmp_path, prefix):
    got = _evaluate(tmp_path, {"c": WRITER_CREATE, "d": WRITER_DELETE}, key_prefix=prefix,
                    control_enabled=True)
    bucket = "projects/_/buckets/forgd-findings"
    for cel in got.values():
        assert _conjunction(cel)[1] == _expected_exclusions("forgd-findings", prefix), cel
    create, _ = _conjunction(got["c"])
    assert create == ([{("==", bucket), ("startsWith", f"{bucket}/objects/{prefix}/")}]
                      if prefix else []), got["c"]
    delete, _ = _conjunction(got["d"])
    assert delete == [_expected_clauses("forgd-findings", prefix)], got["d"]


@requires_terraform
@pytest.mark.parametrize("prefix", ["", "org/prod"])
def test_the_writers_reach_every_store_write_but_the_overrides(tmp_path, monkeypatch, prefix):
    """Against the names GCSStore writes. Mutation: drop the exclusion from
    either writer condition."""
    bucket = "forgd-findings"
    got = _evaluate(tmp_path, {"c": WRITER_CREATE, "d": WRITER_DELETE,
                               "cc": CONTROL_CREATE, "cd": CONTROL_DELETE}, key_prefix=prefix,
                    control_enabled=True)
    gcs = _install_fake_gcs(monkeypatch)
    store = open_store(f"gs://{bucket}/{prefix}" if prefix else f"gs://{bucket}", instance="t")
    store.write_verdicts([rec()])
    store.write_denials([den()])
    store.put_state("cursor.json", b"{}")
    store.set_reset_marker("2026-09-26T00:00:00Z")
    store.set_excluded({"r1"})
    ordinary = {k for op, k, _ in gcs.clients[-1].calls if op == "upload"}
    replaced = {k for op, k, kw in gcs.clients[-1].calls
                if op == "upload" and kw["if_generation_match"] is None}
    store.write_control(b"{}", None)
    store.put_audit("2026-09-28/20260928T140311Z-0123456789ab-request.json", b"{}")
    overrides = {k for op, k, _ in gcs.clients[-1].calls if op == "upload"} - ordinary
    assert len(ordinary) >= 5 and len(replaced) >= 3 and len(overrides) == 2, (ordinary, overrides)
    root = f"{prefix}/" if prefix else ""
    assert overrides == {f"{root}{OVERRIDES_OBJECT}",
                         f"{root}{AUDIT_PREFIX}2026-09-28/20260928T140311Z-0123456789ab-request.json"}
    for key in ordinary:
        assert _admits(got["c"], key, bucket), key
    for key in replaced:
        assert _admits(got["d"], key, bucket), key
    for key in overrides:
        assert not _admits(got["c"], key, bucket), key
        assert not _admits(got["d"], key, bucket), key
        assert _matches(_clauses(got["cc"]), key, bucket), key
    assert _matches(_clauses(got["cd"]), f"{root}{OVERRIDES_OBJECT}", bucket)


# --- off is the plan from before control existed -------------------------------


@requires_terraform
@pytest.mark.parametrize("variables", [
    REQUIRED,
    {**REQUIRED, "key_prefix": "forgd",
     "kms_key_name": "projects/p/locations/eu/keyRings/r/cryptoKeys/k"},
    {**REQUIRED, "writer_members": {"ingest": "serviceAccount:ingest@p.iam.gserviceaccount.com"},
     "reader_members": {"dash": "serviceAccount:dash@p.iam.gserviceaccount.com"}},
], ids=["defaults", "prefix-and-kms", "extra-members"])
@pytest.mark.parametrize("current", [{}, {"control_enabled": False}], ids=["default", "explicit"])
def test_off_every_binding_renders_as_it_did_before_control(tmp_path, variables, current):
    """Every resource and data source in the module, rendered in full with a
    mocked provider, equals the pinned baseline's rendering of the same
    variables: the same for_each keys, and each binding's role, member and
    condition, title included, unchanged, so none is replaced."""
    assert off_versus_baseline(tmp_path, "store-gcs", variables, current) == []


@requires_terraform
@pytest.mark.parametrize("prefix", ["", "forgd"])
def test_on_the_rendering_shows_the_writer_exclusion(tmp_path, prefix):
    """The comparison above can see the control changes."""
    found = off_versus_baseline(tmp_path, "store-gcs", {**REQUIRED, "key_prefix": prefix},
                                {"control_enabled": True})
    for binding in ("writer_create", "writer_mutable_delete"):
        assert any(d.startswith(f"google_storage_bucket_iam_member.{binding}.module.condition")
                   and OVERRIDES_OBJECT in d for d in found), (binding, found)


@requires_terraform
@pytest.mark.parametrize("case,ok", [
    ({}, True),
    ({"control_members": {"dash": "serviceAccount:dash@p.iam.gserviceaccount.com"}}, False),
    ({"control_members": {"dash": "serviceAccount:dash@p.iam.gserviceaccount.com"},
      "control_enabled": True}, True),
])
def test_control_members_without_control_enabled_are_refused(tmp_path, case, ok):
    """Off, a control member would get no binding at all, so it is refused
    rather than dropped."""
    conditions = _preconditions("reader_read")
    assert len(conditions) == 1, conditions
    assert _evaluate(tmp_path, {"p": conditions[0]}, **case)["p"] is ok, case


# --- overrides_writer_lockout --------------------------------------------


def _lockout_output() -> str:
    outputs = {labels[0]: inner for k, labels, inner in _blocks(OUTPUTS.read_text()) if k == "output"}
    return _attr(outputs["overrides_writer_lockout"], "value")


def test_the_writer_lockout_output_is_control_enabled():
    """The app module's overrides_writer_lockout. Mutation: hard-code it true."""
    assert _lockout_output() == "var.control_enabled"


@requires_terraform
@pytest.mark.parametrize("enabled", [False, True])
def test_the_writer_lockout_output_tracks_control_enabled(tmp_path, enabled):
    assert _evaluate(tmp_path, {"lockout": _lockout_output()}, control_enabled=enabled) == {
        "lockout": enabled}


# --- overrides_writer_identities -----------------------------------------


def _gcs_output(name: str) -> str:
    outputs = {labels[0]: inner for k, labels, inner in _blocks(OUTPUTS.read_text()) if k == "output"}
    return re.search(r"^\s*value\s*=\s*(.+?)\s*$", outputs[name], re.M).group(1)


@requires_terraform
@pytest.mark.parametrize("enabled", [False, True])
def test_the_writer_identities_are_every_writer_member_only_with_control(tmp_path, enabled):
    """What app-cloudrun and the chart pass the dashboard's verifier: the
    module's writer and each of writer_members. Mutation: leave out
    writer_members, or drop the gate."""
    extra = "serviceAccount:forgd-ingest@p.iam.gserviceaccount.com"
    got = _evaluate(tmp_path, {"ids": _gcs_output("overrides_writer_identities")},
                    control_enabled=enabled, writer_members={"ingest": extra})
    assert sorted(got["ids"]) == (sorted([f"serviceAccount:{EMAILS['writer']}", extra])
                                  if enabled else [])
