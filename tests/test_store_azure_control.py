"""store-azure's control identity, and the custom roles that come with it.

Off, the writer holds Storage Blob Data Contributor and the reader Storage
Blob Data Reader on the container, as before control existed, and nothing
else is planned. With `control_enabled` both move to custom roles with blob
data actions only, the writer's assignment conditioned off the runtime
overrides object and audit prefix, and the dashboard's control identity
holds a custom role with blob read, write and add, assigned with an ABAC
condition that limits `write` to the runtime overrides object and
`add/action`, which only creates, to the object and the audit prefix. None
holds a delete. The storage account is locked.

Parsed from the .tf source; the condition is evaluated by terraform with no
provider and then checked clause by clause.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import terraform_render
from terraform_render import off_versus_baseline
from test_app_ecs import _blocks

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "deploy" / "terraform" / "modules" / "store-azure"
MAIN = MODULE / "main.tf"
VARIABLES = MODULE / "variables.tf"
OUTPUTS = MODULE / "outputs.tf"

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

WRITE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
ADD = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"
PATH_ATTR = "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path]"
OVERRIDES = "state/runtime-overrides.json"
AUDIT = "audit/runtime-overrides/"
ENABLED_COUNT = "var.control_enabled ? 1 : 0"
BUILT_IN = {"app_writes_findings": '"Storage Blob Data Contributor"',
            "dashboard_reads_findings": '"Storage Blob Data Reader"'}
CUSTOM = {"app_writes_findings": "one(azurerm_role_definition.writer[*].role_definition_resource_id)",
          "dashboard_reads_findings": "one(azurerm_role_definition.reader[*].role_definition_resource_id)",
          "control_writes_overrides": "azurerm_role_definition.control_writes[0].role_definition_resource_id",
          "control_reads_assignments":
              "azurerm_role_definition.control_reads_assignments[0].role_definition_resource_id"}
# The control identity's one control-plane role: reading the writers'
# assignments for the lockout verification.
EVIDENCE_ROLE = "control_reads_assignments"
EVIDENCE_ACTIONS = ["Microsoft.Authorization/roleAssignments/read",
                    "Microsoft.Authorization/roleDefinitions/read"]
REQUIRED = {"resource_group_name": "rg", "location": "uksouth", "storage_account_name": "forgdfindings"}


def _code() -> str:
    return re.sub(r"(?m)^\s*#.*$", "", MAIN.read_text(encoding="utf-8"))


def _attr(body: str, name: str) -> str | None:
    flat = body
    for _, _, inner in _blocks(body):
        flat = flat.replace("{" + inner + "}", "{}", 1)
    m = re.search(rf"^\s*{name}\s*=\s*(.+?)\s*$", flat, re.M)
    return m.group(1) if m else None


def _of(kind: str, block: str = "resource") -> dict[str, str]:
    return {labels[1]: inner for k, labels, inner in _blocks(_code())
            if k == block and labels[0] == kind}


def _control_locals() -> dict[str, str]:
    """The locals block that defines the control condition."""
    bodies = [inner for k, _, inner in _blocks(_code()) if k == "locals"]
    body = next(b for b in bodies if "control_write_condition" in b)
    starts = list(re.finditer(r"^  (\w+)\s*=", body, re.M))
    return {m.group(1): body[m.end():(starts[i + 1].start() if i + 1 < len(starts) else len(body))].strip()
            for i, m in enumerate(starts)}


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([terraform, f"-chdir={cwd}", *args, "-no-color"],
                          capture_output=True, text=True, timeout=120)


def _evaluate(tmp_path: Path, exprs: dict[str, str], **variables) -> dict:
    locals_ = _control_locals()
    shutil.copy(VARIABLES, tmp_path / "variables.tf")
    (tmp_path / "main.tf").write_text(
        "locals {\n" + "".join(f"  {n} = {e}\n" for n, e in locals_.items()) + "}\n"
        + "".join(f'output "{n}" {{\n  value = {e}\n}}\n' for n, e in exprs.items()),
        encoding="utf-8")
    (tmp_path / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}), encoding="utf-8")
    assert _run(["init", "-input=false"], tmp_path).returncode == 0
    out = _run(["apply", "-auto-approve", "-input=false"], tmp_path)
    assert out.returncode == 0, out.stderr
    out = subprocess.run([terraform, f"-chdir={tmp_path}", "output", "-json"],
                         capture_output=True, text=True, timeout=60, check=True)
    return {k: v["value"] for k, v in json.loads(out.stdout).items()}


def _parse(condition: str) -> dict[str, set[tuple[str, str]]]:
    """Each gated action, and the path clauses that admit it.

    The condition must be exactly `((!A) OR (paths)) AND ((!B) OR (paths))`,
    one group per action, and nothing else."""
    flat = " ".join(condition.split())
    groups = re.fullmatch(r"(\( \( .+? \) OR \( .+? \) \))(?: AND (\( \( .+? \) OR \( .+? \) \)))*",
                          flat)
    assert groups, flat
    gated: dict[str, set[tuple[str, str]]] = {}
    for group in re.findall(r"\( \( (!\(ActionMatches\{'[^']+'\}\)) \) OR \( (.+?) \) \)", flat):
        a = re.fullmatch(r"!\(ActionMatches\{'([^']+)'\}\)", group[0])
        assert a, group[0]
        paths = set()
        for part in group[1].split(" OR "):
            m = re.fullmatch(re.escape(PATH_ATTR) + r" (StringEquals|StringStartsWith) '([^']*)'",
                             part)
            assert m, part
            paths.add((m.group(1), m.group(2)))
        assert a.group(1) not in gated
        gated[a.group(1)] = paths
    rebuilt = " AND ".join(
        f"( ( !(ActionMatches{{'{a}'}}) ) OR ( "
        + " OR ".join(f"{PATH_ATTR} {op} '{v}'" for op, v in sorted(p)) + " ) )"
        for a, p in gated.items())
    assert sorted(flat.split()) == sorted(rebuilt.split()), (flat, rebuilt)
    return gated


def _permits(gated: dict[str, set[tuple[str, str]]], action: str, path: str) -> bool:
    if action not in gated:
        return True
    return any(path == v if op == "StringEquals" else path.startswith(v)
               for op, v in gated[action])


# --- off -----------------------------------------------------------------


LOCK_COUNT = "var.control_enabled && var.storage_account_delete_lock ? 1 : 0"


def test_every_control_resource_exists_only_when_enabled():
    found = {(kind, name): _attr(body, "count")
             for kind in ("azurerm_user_assigned_identity", "azurerm_role_assignment", "azurerm_role_definition",
                          "azurerm_management_lock")
             for name, body in _of(kind).items() if _attr(body, "count") is not None}
    assert found == {("azurerm_user_assigned_identity", "control"): ENABLED_COUNT,
                     ("azurerm_role_assignment", "control_writes_overrides"): ENABLED_COUNT,
                     ("azurerm_role_definition", "control_writes"): ENABLED_COUNT,
                     ("azurerm_role_assignment", "control_reads_assignments"): ENABLED_COUNT,
                     ("azurerm_role_definition", "control_reads_assignments"): ENABLED_COUNT,
                     ("azurerm_role_definition", "writer"): ENABLED_COUNT,
                     ("azurerm_role_definition", "reader"): ENABLED_COUNT,
                     ("azurerm_management_lock", "findings"): LOCK_COUNT}, found
    assert _attr(_of("azurerm_resource_group", "data")["findings"], "count") == ENABLED_COUNT


def test_the_existing_resources_do_not_depend_on_the_flag():
    for kind, name in (("azurerm_storage_account", "findings"), ("azurerm_storage_container", "findings"),
                       ("azurerm_user_assigned_identity", "app"), ("azurerm_user_assigned_identity", "reader")):
        body = _of(kind)[name]
        assert "control" not in body, (kind, name)


def test_off_the_assignments_are_the_ones_from_before_control():
    """The two keep the addresses they had, with no count and no move: off,
    each names its built-in role and no custom one, and the writer's has no
    condition. Mutation: name a built-in role while control_enabled."""
    assignments = _of("azurerm_role_assignment")
    for name, role in BUILT_IN.items():
        body = assignments[name]
        assert _attr(body, "count") is None, name
        assert _attr(body, "role_definition_name") == f"var.control_enabled ? null : {role}", name
        assert _attr(body, "role_definition_id") == CUSTOM[name], name
        assert _attr(body, "scope") == "azurerm_storage_container.findings.id", name
        for attr in ("description", "name"):
            assert _attr(body, attr) is None, (name, attr)
    writer, reader = assignments["app_writes_findings"], assignments["dashboard_reads_findings"]
    assert _attr(writer, "condition_version") == 'var.control_enabled ? "2.0" : null'
    assert _attr(writer, "condition") == "var.control_enabled ? local.writer_write_condition : null"
    for attr in ("condition", "condition_version"):
        assert _attr(reader, attr) is None, attr
    assert not [k for k, _, _ in _blocks(_code()) if k == "moved"]


def test_the_control_outputs_are_null_unless_enabled():
    outputs = {labels[0]: inner for k, labels, inner in _blocks(OUTPUTS.read_text()) if k == "output"}
    for name, attr in (("control_identity_id", "id"), ("control_identity_client_id", "client_id"),
                       ("control_identity_principal_id", "principal_id")):
        assert _attr(outputs[name], "value") == (
            f"var.control_enabled ? azurerm_user_assigned_identity.control[0].{attr} : null"), name


# --- what the control identity may do ------------------------------------------


# Each custom role's data actions: the blob operations the store calls
# (store/blob.py: upload_blob, download_blob, list_blobs), mapped to actions by
# learn.microsoft.com/rest/api/storageservices/authorize-with-azure-active-directory
# (Put Blob: write, or add/action for a new blob; Put Block and Put Block
# List: write; Get Blob and List Blobs: read).
ROLE_DATA_ACTIONS = {
    "writer": {"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", WRITE, ADD},
    "reader": {"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"},
    "control_writes": {"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", WRITE, ADD},
}
BLOB_ACTION = re.compile(r"Microsoft\.Storage/storageAccounts/blobServices/containers/blobs/(read|write|add/action)")


def test_each_custom_role_has_no_actions_and_no_exclusions():
    roles = _of("azurerm_role_definition")
    assert set(roles) == {*ROLE_DATA_ACTIONS, EVIDENCE_ROLE}, sorted(roles)
    for name, role in roles.items():
        if name == EVIDENCE_ROLE:
            continue
        permissions = [inner for k, _, inner in _blocks(role) if k == "permissions"]
        assert len(permissions) == 1, name
        assert _attr(permissions[0], "actions") == "[]", name
        assert _attr(permissions[0], "not_actions") is None, name
        assert _attr(permissions[0], "not_data_actions") is None, name


@requires_terraform
def test_each_custom_role_holds_exactly_the_blob_actions_the_store_uses(tmp_path):
    """No container action, no delete, no move, no user delegation key.

    Mutation: add any data action to a role, or take one away."""
    roles = _of("azurerm_role_definition")
    exprs = {name: _attr([i for k, _, i in _blocks(role) if k == "permissions"][0], "data_actions")
             for name, role in roles.items() if name != EVIDENCE_ROLE}
    got = _evaluate(tmp_path, exprs)
    for name, actions in got.items():
        assert len(actions) == len(set(actions)), (name, actions)
        assert set(actions) == ROLE_DATA_ACTIONS[name], (name, actions)
        assert all(BLOB_ACTION.fullmatch(a) for a in actions), (name, actions)


def test_the_evidence_role_reads_assignments_and_definitions_on_the_account_only():
    """Mutation: add an action or a data action, or assign it at another
    scope."""
    role = _of("azurerm_role_definition")[EVIDENCE_ROLE]
    [perm] = [i for k, _, i in _blocks(role) if k == "permissions"]
    assert re.findall(r'"([^"]+)"', perm.split("data_actions")[0]) == EVIDENCE_ACTIONS
    assert _attr(perm, "data_actions") == "[]"
    for attr in ("not_actions", "not_data_actions"):
        assert _attr(perm, attr) is None, attr
    assignment = _of("azurerm_role_assignment")[EVIDENCE_ROLE]
    assert _attr(assignment, "scope") == "azurerm_storage_account.findings.id"
    assert _attr(assignment, "principal_id") == "azurerm_user_assigned_identity.control[0].principal_id"
    for attr in ("condition", "condition_version"):
        assert _attr(assignment, attr) is None, attr


def test_on_no_built_in_role_is_assigned():
    """Every assignment that exists with control_enabled holds one of the
    module's custom roles: Storage Blob Data Contributor holds container
    delete and write, and Reader container read and user delegation keys.
    The built-in roles are named only by the assignments that exist while it
    is off."""
    assignments = _of("azurerm_role_assignment")
    assert {n: _attr(b, "role_definition_id") for n, b in assignments.items()} == CUSTOM
    assert {n: _attr(b, "role_definition_name") for n, b in assignments.items()
            if _attr(b, "role_definition_name") is not None} == {
                n: f"var.control_enabled ? null : {r}" for n, r in BUILT_IN.items()}
    assert _code().count("Storage Blob Data") == 2
    # The writer's condition names the delete actions it excludes; nothing
    # else may.
    code = _code().replace(_control_locals()["writer_mutating_actions"], "")
    assert not re.search(r"/delete|/\*|containers/(read|write)|generateUserDelegationKey", code), \
        "a delete-capable or container-level grant"


def test_the_write_assignment_is_conditioned_on_the_container():
    assignment = _of("azurerm_role_assignment")["control_writes_overrides"]
    assert _attr(assignment, "scope") == "azurerm_storage_container.findings.id"
    assert _attr(assignment, "role_definition_id") == (
        "azurerm_role_definition.control_writes[0].role_definition_resource_id")
    assert _attr(assignment, "principal_id") == "azurerm_user_assigned_identity.control[0].principal_id"
    assert _attr(assignment, "condition_version") == '"2.0"'
    assert _attr(assignment, "condition") == "local.control_write_condition"


def test_nothing_else_uses_the_custom_role():
    uses = [n for n, b in _of("azurerm_role_assignment").items() if "azurerm_role_definition.control_writes" in b]
    assert uses == ["control_writes_overrides"], uses


@requires_terraform
def test_the_condition_gates_write_to_the_object_and_add_to_the_object_and_audit(tmp_path):
    """Mutation: let `write` reach the audit prefix, or drop a clause."""
    got = _evaluate(tmp_path, {"c": "local.control_write_condition"})
    assert _parse(got["c"]) == {
        WRITE: {("StringEquals", OVERRIDES)},
        ADD: {("StringEquals", OVERRIDES), ("StringStartsWith", AUDIT)},
    }


@requires_terraform
def test_the_condition_admits_a_write_nowhere_else(tmp_path):
    gated = _parse(_evaluate(tmp_path, {"c": "local.control_write_condition"})["c"])
    audit = f"{AUDIT}2026-09-28/x-request.json"
    assert _permits(gated, WRITE, OVERRIDES) and _permits(gated, ADD, OVERRIDES)
    assert _permits(gated, ADD, audit)
    assert not _permits(gated, WRITE, audit), "write replaces; the audit prefix is create-only"
    for action in (WRITE, ADD):
        for outside in ("state/cursor.json", f"{OVERRIDES}.bak", "state/runtime-overrides",
                        "audit/runtime-overrides", "audit/other/x.json", "markers/stats_reset",
                        "markers/excluded_requests", "verdicts/x.jsonl", f"findings/{OVERRIDES}",
                        f"/{OVERRIDES}"):
            assert not _permits(gated, action, outside), (action, outside)


# --- refused -------------------------------------------------------------


@requires_terraform
@pytest.mark.parametrize("name,ok", [("mi-forgd-dashboard-control", True),
                                     ("mi-forgd-dashboard", False), ("mi-forgd-verdict-app", False)])
def test_a_control_identity_named_as_another_is_refused(tmp_path, name, ok):
    assignment = _of("azurerm_role_assignment")["control_writes_overrides"]
    lifecycle = next(inner for k, _, inner in _blocks(assignment) if k == "lifecycle")
    [condition] = [_attr(p, "condition") for k, _, p in _blocks(lifecycle) if k == "precondition"]
    got = _evaluate(tmp_path, {"p": condition}, control_identity_name=name)
    assert got["p"] is ok


# --- the writer cannot write the runtime overrides ----------------------------

DELETE = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"
READ = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
WRITER_ACTIONS = {WRITE, ADD, DELETE,
                  "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action",
                  "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/permanentDelete/action",
                  "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action"}


def _parse_exclusion(condition: str) -> tuple[set[str], set[tuple[str, str]]]:
    """(the actions the condition gates, the negated path clauses a gated
    action must pass together). The condition must be exactly
    `((!A AND !B ...) OR (path1 AND path2))` and nothing else."""
    flat = " ".join(condition.split())
    m = re.fullmatch(r"\( \( (.+) \) OR \( (.+) \) \)", flat)
    assert m, flat
    actions = set()
    for part in m.group(1).split(" AND "):
        a = re.fullmatch(r"!\(ActionMatches\{'([^']+)'\}\)", part)
        assert a, part
        actions.add(a.group(1))
    paths = set()
    for part in m.group(2).split(" AND "):
        p = re.fullmatch(re.escape(PATH_ATTR) + r" (StringNotEquals|StringNotStartsWith) '([^']*)'", part)
        assert p, part
        paths.add((p.group(1), p.group(2)))
    return actions, paths


def _writer_permits(actions, paths, action: str, path: str) -> bool:
    if action not in actions:
        return True
    return all(path != v if op == "StringNotEquals" else not path.startswith(v) for op, v in paths)


def test_the_writers_custom_assignment_carries_the_exclusion():
    assignment = _of("azurerm_role_assignment")["app_writes_findings"]
    assert _attr(assignment, "role_definition_id") == CUSTOM["app_writes_findings"]
    assert _attr(assignment, "principal_id") == "azurerm_user_assigned_identity.app.principal_id"
    assert _attr(assignment, "condition_version") == 'var.control_enabled ? "2.0" : null'
    assert _attr(assignment, "condition") == "var.control_enabled ? local.writer_write_condition : null"
    others = [n for n, b in _of("azurerm_role_assignment").items()
              if "azurerm_user_assigned_identity.app." in b]
    assert others == ["app_writes_findings"], others


@requires_terraform
def test_the_writers_condition_excludes_every_mutation_of_the_overrides(tmp_path):
    """Mutation: drop the condition, a gated action, or either path clause."""
    actions, paths = _parse_exclusion(
        _evaluate(tmp_path, {"c": "local.writer_write_condition"})["c"])
    assert actions == WRITER_ACTIONS, actions
    assert paths == {("StringNotEquals", OVERRIDES), ("StringNotStartsWith", AUDIT)}, paths
    audit = f"{AUDIT}2026-09-28/20260928T140311Z-0123456789ab-request.json"
    for action in WRITER_ACTIONS:
        for path in (OVERRIDES, audit):
            assert not _writer_permits(actions, paths, action, path), (action, path)
    for path in ("verdicts/x.jsonl", "denials/x.jsonl", "state/cursor.json", "state/orgs.json",
                 "markers/stats_reset", "markers/excluded_requests", f"{OVERRIDES}.bak",
                 "audit/runtime-overrides", "audit/other/x.json"):
        for action in (WRITE, ADD):
            assert _writer_permits(actions, paths, action, path), (action, path)
    for path in (OVERRIDES, audit, "verdicts/x.jsonl"):
        assert _writer_permits(actions, paths, READ, path), path


# The data actions a REST operation needs, from "Permissions for Blob service
# operations" (learn.microsoft.com/rest/api/storageservices/authorize-with-
# azure-active-directory): any one of them authorises it. Only the operations
# that can create, change or remove a blob.
REPLACE_OR_CREATE = {WRITE}
CREATE_NEW = {WRITE, ADD}
OPERATIONS = {
    "Put Blob (replace)": REPLACE_OR_CREATE,
    "Put Blob (new blob)": CREATE_NEW,
    "Put Blob from URL (replace)": REPLACE_OR_CREATE,
    "Put Blob from URL (new blob)": CREATE_NEW,
    "Put Block": {WRITE},
    "Put Block List": {WRITE},
    "Put Block from URL": {WRITE},
    "Set Blob Properties": {WRITE},
    "Set Blob Metadata": {WRITE},
    "Set Blob Tier": {WRITE},
    "Set Blob Expiry": {WRITE},
    "Lease Blob": {WRITE},
    "Abort Copy Blob": {WRITE},
    "Snapshot Blob": CREATE_NEW,
    "Copy Blob (destination)": CREATE_NEW,
    "Copy Blob from URL (destination)": CREATE_NEW,
    "Append Block": CREATE_NEW,
    "Put Page": {WRITE},
    "Delete Blob": {DELETE},
}
# What each store call sends: azure-storage-blob's upload_blob with
# overwrite=False sets If-None-Match: * and, under max_single_put_size, is one
# Put Blob, which can only create; with an etag it is a Put Blob that replaces.
PUT_AUDIT = "Put Blob (new blob)"
WRITE_CONTROL_CREATE = "Put Blob (new blob)"
WRITE_CONTROL_REPLACE = "Put Blob (replace)"
CONTROL_ROLE = {WRITE, ADD}


def _control_can(gated, operation: str, path: str) -> bool:
    return any(a in CONTROL_ROLE and _permits(gated, a, path) for a in OPERATIONS[operation])


@requires_terraform
def test_the_control_identity_keeps_its_writes_to_the_overrides(tmp_path):
    gated = _parse(_evaluate(tmp_path, {"c": "local.control_write_condition"})["c"])
    audit = f"{AUDIT}2026-09-28/20260928T140311Z-0123456789ab-request.json"
    assert _control_can(gated, PUT_AUDIT, audit)
    assert _control_can(gated, WRITE_CONTROL_CREATE, OVERRIDES)
    assert _control_can(gated, WRITE_CONTROL_REPLACE, OVERRIDES)


@requires_terraform
def test_the_control_identity_can_only_create_under_the_audit_prefix(tmp_path):
    """Every operation that needs `write` is refused on an audit record, and
    one that `add/action` authorises can only make a new blob."""
    gated = _parse(_evaluate(tmp_path, {"c": "local.control_write_condition"})["c"])
    audit = f"{AUDIT}2026-09-28/20260928T140311Z-0123456789ab-request.json"
    for operation, actions in OPERATIONS.items():
        allowed = _control_can(gated, operation, audit)
        assert allowed == (ADD in actions), operation


# The built-in role's data actions, from its definition on
# learn.microsoft.com/azure/role-based-access-control/built-in-roles/storage
# (Storage Blob Data Contributor, ba92f5b4-2d11-453d-a403-e96b0029c9fe).
CONTRIBUTOR_DATA_ACTIONS = {
    DELETE, READ, WRITE, ADD,
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action",
}


@requires_terraform
def test_the_writer_condition_gates_every_mutating_action_the_role_holds(tmp_path):
    """Mutation: drop any gated action the built-in role holds."""
    actions, _ = _parse_exclusion(_evaluate(tmp_path, {"c": "local.writer_write_condition"})["c"])
    assert CONTRIBUTOR_DATA_ACTIONS - {READ} <= actions, CONTRIBUTOR_DATA_ACTIONS - actions


@requires_terraform
def test_the_writer_can_run_no_mutating_operation_on_the_overrides(tmp_path):
    actions, paths = _parse_exclusion(
        _evaluate(tmp_path, {"c": "local.writer_write_condition"})["c"])
    audit = f"{AUDIT}2026-09-28/20260928T140311Z-0123456789ab-request.json"
    for operation, needs in OPERATIONS.items():
        for path in (OVERRIDES, audit):
            assert not any(a in CONTRIBUTOR_DATA_ACTIONS and _writer_permits(actions, paths, a, path)
                           for a in needs), (operation, path)
        assert any(_writer_permits(actions, paths, a, "verdicts/x.jsonl") for a in needs), operation


# --- off is the plan from before control existed -------------------------------

AZURE = {"resource_group_name": "rg", "location": "westeurope", "storage_account_name": "forgdfindings"}

# The one change to the module since its baseline was pinned that is not
# about control: container soft delete, on by default.
CONTAINER_RETENTION = [
    "azurerm_storage_account.findings.blob_properties.0.container_delete_retention_policy: "
    '[] -> [{"days": 30}]',
]


@requires_terraform
@pytest.mark.parametrize("variables", [
    AZURE,
    {**AZURE, "container_name": "evidence", "identity_name": "mi-w", "reader_identity_name": "mi-r",
     "tags": {"team": "sec"}},
], ids=["defaults", "names-and-tags"])
@pytest.mark.parametrize("current", [{}, {"control_enabled": False}], ids=["default", "explicit"])
def test_off_every_assignment_renders_as_it_did_before_control(tmp_path, variables, current):
    """Every resource in the module, rendered in full with a mocked provider,
    equals the pinned baseline's rendering of the same variables, apart
    from CONTAINER_RETENTION, its two assignments under `count`: built-in
    roles, no condition, no custom role, no resource group lookup and no
    lock."""
    assert off_versus_baseline(tmp_path, "store-azure", variables, current) == CONTAINER_RETENTION


@requires_terraform
def test_on_the_rendering_shows_the_writer_condition(tmp_path):
    """The comparison above can see the control changes."""
    found = off_versus_baseline(tmp_path, "store-azure", AZURE, {"control_enabled": True})
    assert any(d.startswith("azurerm_role_assignment.app_writes_findings")
               and "state/runtime-overrides.json" in d for d in found), found
    assert any(d.startswith("azurerm_role_assignment.app_writes_findings") and "Contributor" in d
               for d in found), found


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


# --- over the full rendering ------------------------------------------------------

def _instances(rendered: dict, address: str) -> list[dict]:
    value = rendered.get(address)
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def azure_problems(rendered: dict, lock: bool = True, control: bool = True) -> list[str]:
    """What is wrong with a rendering. With `control`: every assignment holds
    one of the module's custom roles, each role holds exactly its blob
    actions, and the lock exists exactly when `lock`. Without: the writer
    and the reader hold their built-in roles, and there is no custom role,
    resource group lookup or lock."""
    problems = []
    roles = {a.split(".", 1)[1]: v[0] for a in rendered if a.startswith("azurerm_role_definition.")
             for v in [_instances(rendered, a)] if v}
    expected = {*ROLE_DATA_ACTIONS, EVIDENCE_ROLE} if control else set()
    if set(roles) != expected:
        problems.append(f"roles {sorted(roles)}")
    for name, role in roles.items():
        [perm] = role["permissions"]
        if name == EVIDENCE_ROLE:
            if (sorted(perm["actions"]) != EVIDENCE_ACTIONS or perm["data_actions"]
                    or perm.get("not_actions") or perm.get("not_data_actions")):
                problems.append(f"{name}: actions {perm}")
            continue
        if perm["actions"] or perm.get("not_actions") or perm.get("not_data_actions"):
            problems.append(f"{name}: control-plane or excluded actions {perm}")
        if set(perm["data_actions"]) != ROLE_DATA_ACTIONS.get(name):
            problems.append(f"{name}: data actions {sorted(perm['data_actions'])}")
    custom = {r["role_definition_resource_id"] for r in roles.values()}
    held = {}
    for address in rendered:
        if address.startswith("azurerm_role_assignment."):
            for a in _instances(rendered, address):
                held[address.split(".", 1)[1]] = a
    if control:
        if set(held) != set(CUSTOM):
            problems.append(f"assignments {sorted(held)}")
        for name, a in held.items():
            if a["role_definition_id"] not in custom:
                problems.append(f"{name}: not a custom role")
    else:
        if {n: a.get("role_definition_name") for n, a in held.items()} != {
                n: r.strip('"') for n, r in BUILT_IN.items()}:
            problems.append(f"assignments {held}")
        if _instances(rendered, "data.azurerm_resource_group.findings"):
            problems.append("a resource group lookup")
    account = _instances(rendered, "azurerm_storage_account.findings")[0]["id"]
    locks = _instances(rendered, "azurerm_management_lock.findings")
    if lock and [(x["lock_level"], x["scope"]) for x in locks] != [("CanNotDelete", account)]:
        problems.append(f"lock {locks}")
    if not lock and locks:
        problems.append(f"an opted-out lock {locks}")
    return problems


ON = {**AZURE, "control_enabled": True}


@requires_terraform
def test_on_every_assignment_holds_a_custom_role_and_the_account_is_locked(tmp_path):
    rendered = terraform_render.render_module(tmp_path, "store-azure", ON)
    assert azure_problems(rendered) == []


@requires_terraform
def test_the_lock_is_on_by_default_and_can_be_opted_out_of(tmp_path):
    body = [i for k, labels, i in _blocks(VARIABLES.read_text()) if k == "variable"
            and labels == ["storage_account_delete_lock"]][0]
    assert _attr(body, "default") == "true"
    rendered = terraform_render.render_module(tmp_path, "store-azure",
                                              {**ON, "storage_account_delete_lock": False})
    assert azure_problems(rendered, lock=False) == []


@requires_terraform
@pytest.mark.parametrize("current", [{}, {"storage_account_delete_lock": True}], ids=["default", "lock-left-on"])
def test_off_the_built_in_roles_are_assigned_and_there_is_no_lock(tmp_path, current):
    rendered = terraform_render.render_module(tmp_path, "store-azure", {**AZURE, **current})
    assert azure_problems(rendered, lock=False, control=False) == []


@requires_terraform
def test_off_there_is_no_lock_even_when_it_is_left_on(tmp_path):
    """The off comparison against the baseline, with the lock variable set."""
    assert off_versus_baseline(tmp_path, "store-azure", AZURE,
                               {"storage_account_delete_lock": True}) == CONTAINER_RETENTION


RG_ALWAYS = ('data "azurerm_resource_group" "findings" {\n  count = var.control_enabled ? 1 : 0',
             'data "azurerm_resource_group" "findings" {\n  count = 1')


@requires_terraform
@pytest.mark.parametrize("now,then,variables,also", [
    ('description       = "Blob read only: no container action."\n'
     '  assignable_scopes = [data.azurerm_resource_group.findings[0].id]\n\n'
     '  permissions {\n    actions      = []\n    data_actions = [local.blob_read_action]',
     'description       = "Blob read only: no container action."\n'
     '  assignable_scopes = [data.azurerm_resource_group.findings[0].id]\n\n'
     '  permissions {\n    actions      = []\n    data_actions = [local.blob_read_action, '
     '"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"]', ON, []),
    ('description       = "Blob read, write and add only: no container action, no delete, no move."\n'
     '  assignable_scopes = [data.azurerm_resource_group.findings[0].id]\n\n'
     '  permissions {\n    actions      = []',
     'description       = "Blob read, write and add only: no container action, no delete, no move."\n'
     '  assignable_scopes = [data.azurerm_resource_group.findings[0].id]\n\n'
     '  permissions {\n    actions      = ["Microsoft.Storage/storageAccounts/blobServices/containers/delete"]', ON, []),
    ('  role_definition_name = var.control_enabled ? null : "Storage Blob Data Contributor"\n'
     '  role_definition_id   = one(azurerm_role_definition.writer[*].role_definition_resource_id)\n',
     '  role_definition_name = "Storage Blob Data Contributor"\n', ON, []),
    ('  role_definition_name = var.control_enabled ? null : "Storage Blob Data Reader"\n'
     '  role_definition_id   = one(azurerm_role_definition.reader[*].role_definition_resource_id)\n',
     '  role_definition_name = "Storage Blob Data Reader"\n', ON, []),
    ("count      = var.control_enabled && var.storage_account_delete_lock ? 1 : 0", "count      = 0", ON, []),
    ('resource "azurerm_role_definition" "reader" {\n  count             = var.control_enabled ? 1 : 0',
     'resource "azurerm_role_definition" "reader" {\n  count             = 1', AZURE,
     [RG_ALWAYS, ('var.control_enabled ? null : "Storage Blob Data Reader"', "null")]),
    (*RG_ALWAYS, AZURE, []),
], ids=["reader-delete", "writer-container-delete", "writer-built-in", "built-in-left-on",
        "lock-missing", "off-custom-role", "off-resource-group"])
def test_the_checker_catches_excess_permissions_a_built_in_role_or_a_missing_lock(
        tmp_path, now, then, variables, also):
    rendered = terraform_render.render_edited(tmp_path, "store-azure", variables, [(now, then), *also])
    control = variables is ON
    assert azure_problems(rendered, lock=control, control=control)


# --- the migration from the built-in roles ------------------------------------------


def _lifecycle(body: str) -> str:
    found = [inner for k, _, inner in _blocks(body) if k == "lifecycle"]
    return found[0] if found else ""


def _depends_on(body: str) -> list[str]:
    m = re.search(r"depends_on\s*=\s*\[([^\]]*)\]", body)
    return re.findall(r"azurerm_\w+\.(\w+)", m.group(1)) if m else []


def test_each_assignment_the_flag_replaces_is_created_before_it_is_destroyed():
    """The flag changes each one's role, which replaces it; Terraform then
    creates the new assignment before it destroys the old, both ways.

    Mutation: drop a create_before_destroy."""
    assignments = _of("azurerm_role_assignment")
    for name in BUILT_IN:
        assert _attr(_lifecycle(assignments[name]), "create_before_destroy") == "true", name
        assert _depends_on(assignments[name]) == [], name


def test_a_built_in_assignment_is_never_replaced_into_itself():
    """Azure refuses a second assignment with the same scope, principal and
    role (RoleAssignmentExists), whatever its condition. A created-first
    replacement of the reader's assignment always changes one of those,
    because it sets no condition, description or name, and the writer's
    sets a condition only with the custom role. The control identity's is
    replaced in place."""
    assignments = _of("azurerm_role_assignment")
    for name in BUILT_IN:
        for attr in ("description", "name"):
            assert _attr(assignments[name], attr) is None, (name, attr)
    for attr in ("condition", "condition_version"):
        assert _attr(assignments["dashboard_reads_findings"], attr) is None, attr
    assert _attr(_lifecycle(assignments["control_writes_overrides"]), "create_before_destroy") is None


def test_the_lock_is_created_after_and_removed_before_every_assignment():
    lock = _of("azurerm_management_lock")["findings"]
    assert sorted(_depends_on(lock)) == sorted(_of("azurerm_role_assignment")), lock


def _stand_ins(log: Path) -> str:
    """The module's role assignments and lock as terraform_data resources
    with the same count, create_before_destroy and depends_on, each logging
    when its create and destroy start and end."""
    out = ['variable "control_enabled" {\n  type = bool\n}\n',
           'variable "storage_account_delete_lock" {\n  type    = bool\n  default = true\n}\n']
    resources = {**_of("azurerm_role_assignment"), "lock": _of("azurerm_management_lock")["findings"]}
    for name, body in resources.items():
        step = f"echo start-$A-{name} >> {log}; sleep 1; echo end-$A-{name} >> {log}"
        cbd = _attr(_lifecycle(body), "create_before_destroy") == "true"
        depends = [f"terraform_data.{d}" for d in _depends_on(body)]
        count = _attr(body, "count") or "1"
        # A role that follows the flag replaces the assignment when it flips.
        role = _attr(body, "role_definition_name") or ""
        replace = "  triggers_replace = var.control_enabled\n" if "var.control_enabled" in role else ""
        out.append(f'resource "terraform_data" "{name}" {{\n  count = {count}\n{replace}'
                   f'  provisioner "local-exec" {{\n    command = "A=create; {step}"\n  }}\n'
                   f'  provisioner "local-exec" {{\n    when    = destroy\n'
                   f'    command = "A=destroy; {step}"\n  }}\n'
                   + ("  lifecycle {\n    create_before_destroy = true\n  }\n" if cbd else "")
                   + (f"  depends_on = [{', '.join(depends)}]\n" if depends else "") + "}\n")
    return "\n".join(out)


@requires_terraform
def test_the_swap_creates_each_assignment_before_it_destroys_the_one_it_replaces(tmp_path):
    """Applied off, on, then off: each flip creates each replaced assignment
    anew, and never destroys the old one first. Terraform runs no destroy
    provisioner for an object replaced created-first, so a destroy logged
    for one means it was destroyed before its replacement. The lock is
    created after every assignment and destroyed before those the flag
    removes.

    Mutation: drop a create_before_destroy or a depends_on from the module."""
    log = tmp_path / "log"
    (tmp_path / "main.tf").write_text(_stand_ins(log), encoding="utf-8")
    assert _run(["init", "-input=false"], tmp_path).returncode == 0
    events = {}
    for step, enabled in (("off", "false"), ("on", "true"), ("off-again", "false")):
        out = _run(["apply", "-auto-approve", "-input=false", "-var", f"control_enabled={enabled}"],
                   tmp_path)
        assert out.returncode == 0, out.stderr
        events[step] = log.read_text().split()
        log.write_text("")
    assert sorted(events["off"]) == sorted(f"{e}-create-{n}" for n in BUILT_IN for e in ("start", "end"))

    def before(seen, first, then):
        return seen.index(f"end-{first}") < seen.index(f"start-{then}")

    on, off = events["on"], events["off-again"]
    for name in BUILT_IN:
        for seen in (on, off):
            assert f"end-create-{name}" in seen, seen
            assert f"start-destroy-{name}" not in seen, seen
    for name in (*BUILT_IN, "control_writes_overrides"):
        assert before(on, f"create-{name}", "create-lock"), on
    for name in ("control_writes_overrides", "control_reads_assignments"):
        assert before(off, "destroy-lock", f"destroy-{name}"), off


@requires_terraform
def test_off_the_assignments_keep_their_baseline_addresses(tmp_path):
    """Off, the two assignments render at the pinned baseline's addresses,
    as single instances, so an existing store moves nothing."""
    rendered = terraform_render.render_module(tmp_path, "store-azure", AZURE)
    for name, role in BUILT_IN.items():
        value = rendered[f"azurerm_role_assignment.{name}"]
        assert isinstance(value, dict) and value["role_definition_name"] == role.strip('"'), name


# --- overrides_writer_identities and storage_account_id -------------------


def _az_output(name: str) -> str:
    outputs = {labels[0]: inner for k, labels, inner in _blocks(OUTPUTS.read_text()) if k == "output"}
    return re.search(r"^\s*value\s*=\s*(.+?)\s*$", outputs[name], re.M).group(1)


@requires_terraform
@pytest.mark.parametrize("enabled", [False, True])
def test_the_writer_identities_are_the_writer_principal_only_with_control(tmp_path, enabled):
    """Mutation: list the reader or control principal, or drop the gate."""
    principal = "00000000-0000-0000-0000-00000000000a"
    expr = _az_output("overrides_writer_identities").replace(
        "azurerm_user_assigned_identity.app.principal_id", f'"{principal}"')
    assert _evaluate(tmp_path, {"ids": expr}, control_enabled=enabled) == {
        "ids": [principal] if enabled else []}


def test_the_storage_account_id_output_is_the_accounts_id():
    assert _az_output("storage_account_id") == "azurerm_storage_account.findings.id"
