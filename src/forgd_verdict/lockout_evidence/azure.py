"""Azure: each writer principal is locked out when every role assignment
that applies to the findings container and grants a blob mutation carries
the store module's version 2.0 condition, which names every mutation the
role grants and keeps them off the runtime overrides path and the audit
prefix.

A principal with no assignment granting a mutation cannot write the object
at all, and is locked out. One holding any Microsoft.Authorization write,
or a write or delete on the storage account, its blob service or the
container, is not, whatever its conditions: those are control-plane
actions no data-plane condition constrains, and with them it can rewrite
its own assignments or replace the container.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any

from ..safehttp import credential_opener, segment
from . import EvidenceUnavailable

OVERRIDES_KEY = "state/runtime-overrides.json"
AUDIT_PREFIX = "audit/runtime-overrides/"
_BLOBS = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs"
MUTATING_ACTIONS = tuple(f"{_BLOBS}/{a}" for a in (
    "write", "add/action", "delete", "deleteBlobVersion/action",
    "permanentDelete/action", "move/action"))

REASON_UNCONDITIONED = "unconditioned_assignment"
REASON_VERSION = "wrong_condition_version"
REASON_CONDITION = "condition_not_recognised"
REASON_ACTION = "condition_omits_action"
REASON_WILDCARD = "wildcard_data_action"
REASON_KEYS = "grants_account_keys"
# Control-plane actions that hand out a shared key, which RBAC conditions
# do not constrain.
KEY_ACTIONS = ("Microsoft.Storage/storageAccounts/listKeys/action",
               "Microsoft.Storage/storageAccounts/regenerateKey/action")

REASON_AUTHZ = "grants_authorization_write"
REASON_CONTROL_PLANE = "grants_storage_control_plane_write"
# Probes for a role's `actions`: every Microsoft.Authorization write the
# platform defines today, and a name no role lists, which only a wildcard
# over the namespace matches.
AUTHZ_WRITES = tuple(f"Microsoft.Authorization/{r}/write" for r in (
    "roleAssignments", "roleDefinitions", "denyAssignments", "locks", "policyAssignments",
    "policyDefinitions", "policySetDefinitions", "policyExemptions", "roleManagementPolicies",
    "roleEligibilityScheduleRequests", "roleAssignmentScheduleRequests",
    "forgd-verdict-probe"))
_ACCOUNT = "Microsoft.Storage/storageAccounts"
CONTROL_PLANE_WRITES = (
    f"{_ACCOUNT}/write", f"{_ACCOUNT}/delete",
    f"{_ACCOUNT}/blobServices/write", f"{_ACCOUNT}/blobServices/delete",
    f"{_ACCOUNT}/blobServices/containers/write", f"{_ACCOUNT}/blobServices/containers/delete")

_ARM = "https://management.azure.com"
_API = "2022-04-01"
_TIMEOUT_S = 30

_CONDITION = re.compile(
    r"\(\((?P<acts>!\(ActionMatches\{'[^']+'\}\)(?:AND!\(ActionMatches\{'[^']+'\}\))*)\)"
    r"OR\(@Resource\[" + re.escape(_BLOBS) + r":path\]StringNotEquals'(?P<path>[^']*)'"
    r"AND@Resource\[" + re.escape(_BLOBS) + r":path\]StringNotStartsWith'(?P<audit>[^']*)'\)\)")
_ACTION = re.compile(r"ActionMatches\{'([^']+)'\}")


def _get(url: str, token: str) -> dict[str, Any]:
    """GET `url` with the ARM token. ValueError for a URL outside the ARM
    host; a redirect is refused rather than followed."""
    if not url.startswith(f"{_ARM}/"):
        raise ValueError("an ARM request left the ARM host")
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with credential_opener().open(req, timeout=_TIMEOUT_S) as resp:
        return json.loads(resp.read())


def fetch(store: Any, *, account_id: str, writers: Iterable[str] = ()) -> dict[str, Any]:
    """Every role assignment of each writer principal that applies to the
    findings container, each with its role's data actions, as
    `{"container_scope": ..., "assignments": [...]}`.

    Each assignment records `writer`, the writer whose query returned it:
    `assignedTo('<id>')` is transitive, so an assignment made to a group
    the writer belongs to carries the group's principal id.

    UNCONFIRMED: the ARM calls, `roleAssignments?$filter=assignedTo('<id>')`
    at the storage account scope and a GET of each role definition by its
    name at that scope, api-version 2022-04-01, and that the filter returns
    assignments made to the writer directly, to groups containing it, and
    inherited from the resource group, subscription and management groups,
    are from the Azure REST documentation and not exercised against Azure
    here. So is the condition text being returned as it was written.
    """
    container_scope = f"{account_id.rstrip('/')}/blobServices/default/containers/{store.container}"
    try:
        token = store.credential.get_token(f"{_ARM}/.default").token
        assignments: list[dict[str, Any]] = []
        roles: dict[str, dict[str, list[str]]] = {}
        for principal in writers:
            filt = urllib.parse.quote(f"assignedTo('{principal}')")
            url: str | None = (f"{_ARM}{account_id}/providers/Microsoft.Authorization/"
                               f"roleAssignments?api-version={_API}&$filter={filt}")
            while url:
                page = _get(url, token)
                for a in page.get("value") or ():
                    p = a.get("properties") or {}
                    rid = p.get("roleDefinitionId") or ""
                    if rid not in roles:
                        name = segment(rid.rstrip("/").rsplit("/", 1)[-1])
                        rd = _get(f"{_ARM}{account_id}/providers/Microsoft.Authorization/"
                                  f"roleDefinitions/{name}?api-version={_API}", token)
                        perms = (rd.get("properties") or {}).get("permissions") or []
                        roles[rid] = {
                            "actions": [x for q in perms for x in q.get("actions") or ()],
                            "not_actions": [x for q in perms for x in q.get("notActions") or ()],
                            "data_actions": [x for q in perms for x in q.get("dataActions") or ()],
                            "not_data_actions": [x for q in perms
                                                 for x in q.get("notDataActions") or ()]}
                    assignments.append({
                        "id": a.get("id"), "writer": principal,
                        "principal_id": p.get("principalId"),
                        "scope": p.get("scope"), "role_definition_id": rid,
                        "condition": p.get("condition"),
                        "condition_version": p.get("conditionVersion"), **roles[rid]})
                url = page.get("nextLink")
    except Exception as exc:  # noqa: BLE001 - mapped to a fixed code
        status = getattr(exc, "code", None)
        if status in (401, 403):
            raise EvidenceUnavailable("policy_read_denied") from None
        raise EvidenceUnavailable("policy_read_failed") from None
    return {"container_scope": container_scope, "assignments": assignments}


def scope(store: Any) -> dict[str, str]:
    root = f"{store.prefix}/" if store.prefix else ""
    return {"overrides_path": f"{root}{OVERRIDES_KEY}", "audit_prefix": f"{root}{AUDIT_PREFIX}"}


def _glob(pattern: str, value: str) -> bool:
    rx = "".join(".*" if c == "*" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, value, re.IGNORECASE) is not None


def _applies(assignment_scope: str, container_scope: str) -> bool:
    """Whether an assignment at `assignment_scope` holds on the container:
    the container itself or any scope above it."""
    a = (assignment_scope or "").rstrip("/").lower()
    c = container_scope.rstrip("/").lower()
    return a == "" or a == "/" or c == a or c.startswith(a + "/")


def _squeeze(text: str) -> str:
    """`text` without whitespace outside single-quoted literals."""
    out, quoted = [], False
    for ch in text:
        if ch == "'":
            quoted = not quoted
        if quoted or not ch.isspace():
            out.append(ch)
    return "".join(out)


def _grants(a: dict[str, Any]) -> tuple[set[str], bool]:
    """The mutating actions the assignment's role grants, and whether it
    grants any through a wildcard."""
    allow = [x for x in a.get("data_actions") or () if isinstance(x, str)]
    deny = [x for x in a.get("not_data_actions") or () if isinstance(x, str)]
    granted = {m for m in MUTATING_ACTIONS
               if any(_glob(p, m) for p in allow) and not any(_glob(p, m) for p in deny)}
    return granted, bool(granted) and any("*" in p for p in allow)


def _grants_any(a: dict[str, Any], actions: Iterable[str]) -> bool:
    """Whether the assignment's role grants any of the control-plane `actions`."""
    allow = [x for x in a.get("actions") or () if isinstance(x, str)]
    deny = [x for x in a.get("not_actions") or () if isinstance(x, str)]
    return any(any(_glob(p, k) for p in allow) and not any(_glob(p, k) for p in deny)
               for k in actions)


def _grants_keys(a: dict[str, Any]) -> bool:
    return _grants_any(a, KEY_ACTIONS)


def _reason(a: dict[str, Any], overrides_path: str, audit_prefix: str) -> str | None:
    if _grants_any(a, AUTHZ_WRITES):
        return REASON_AUTHZ
    if _grants_any(a, CONTROL_PLANE_WRITES):
        return REASON_CONTROL_PLANE
    granted, wildcard = _grants(a)
    keys = _grants_keys(a)
    if not granted and not keys:
        return None
    condition = a.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        return REASON_UNCONDITIONED
    if keys:
        return REASON_KEYS
    if a.get("condition_version") != "2.0":
        return REASON_VERSION
    m = _CONDITION.fullmatch(_squeeze(condition))
    if m is None or m["path"] != overrides_path or m["audit"] != audit_prefix:
        return REASON_CONDITION
    # A wildcard grants actions no condition can list.
    if wildcard:
        return REASON_WILDCARD
    named = {x.lower() for x in _ACTION.findall(m["acts"])}
    if any(g.lower() not in named for g in granted):
        return REASON_ACTION
    return None


def evaluate(doc: dict[str, Any], *, overrides_path: str, audit_prefix: str,
             writers: Iterable[str]) -> dict[str, str | None]:
    container_scope = doc.get("container_scope") or ""
    assignments = [a for a in doc.get("assignments") or () if isinstance(a, dict)
                   and _applies(a.get("scope") or "", container_scope)]
    out: dict[str, str | None] = {}
    for principal in writers:
        reasons = [_reason(a, overrides_path, audit_prefix)
                   for a in assignments
                   if a.get("writer", a.get("principal_id")) == principal]
        out[principal] = next((r for r in reasons if r is not None), None)
    return out
