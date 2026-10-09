"""GCS: each writer member is locked out when every bucket binding that
names it, other than a read-only role, is conditioned with the exclusion
of the runtime overrides object and the audit prefix ANDed at the top
level.

IAM conditions only allow, so the exclusion must hold on every grant: one
unconditioned or differently conditioned write binding is enough to write
the object.

A binding whose role holds storage.buckets.setIamPolicy fails whatever its
condition: the member can rewrite the bucket policy, conditions and all.
Every role a writer holds other than a read-only one is read from the IAM
API for its permissions, and one that cannot be read fails.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from . import EvidenceUnavailable

OVERRIDES_KEY = "state/runtime-overrides.json"
AUDIT_PREFIX = "audit/runtime-overrides/"
READ_ONLY_ROLES = frozenset({
    "roles/storage.objectViewer",
    "roles/storage.legacyObjectReader",
    "roles/storage.legacyBucketReader",
})

# Members that include every identity, the writer's among them.
PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})

REASON_NO_BINDING = "no_binding_for_writer"
REASON_UNCONDITIONED = "unconditioned_binding"
REASON_MISSING_EXCLUSION = "missing_exclusion"
REASON_SET_IAM = "grants_set_iam_policy"
REASON_ROLE_UNREADABLE = "role_permissions_unreadable"
# The bucket's policy omits grants inherited from the project, folder and
# organization, and does not expand groups, so a clean bucket check proves
# nothing about them. Given to every writer the bucket check passes until
# an operator attests that those grants were audited.
REASON_INHERITED_UNCHECKED = "inherited_grants_unaudited"
SET_IAM_PERMISSION = "storage.buckets.setIamPolicy"

_IAM = "https://iam.googleapis.com/v1/"
_TIMEOUT_S = 30


def fetch(store: Any) -> dict[str, Any]:
    """The bucket's IAM policy, version 3, as `{"bindings": [...], "roles":
    {role: [permission, ...] or None}}`, with the permissions of every role
    a binding holds other than a read-only one, None where they could not
    be read.

    UNCONFIRMED: the call shape, `bucket.get_iam_policy(
    requested_policy_version=3)` returning a Policy whose `bindings` are
    dicts of `role`, `members` and `condition`, and the status codes below,
    are from the google-cloud-storage documentation and not exercised
    against GCS here.
    """
    from ..store.gcs import _status

    try:
        policy = store._bucket.get_iam_policy(requested_policy_version=3)
        bindings = [{"role": b.get("role"), "members": sorted(b.get("members") or ()),
                     "condition": b.get("condition")} for b in policy.bindings]
    except Exception as exc:  # noqa: BLE001 - mapped to a fixed code
        status = _status(exc)
        if status in (401, 403):
            raise EvidenceUnavailable("policy_read_denied") from None
        if status == 404:
            raise EvidenceUnavailable("bucket_not_found") from None
        raise EvidenceUnavailable("policy_read_failed") from None
    held = sorted({b["role"] for b in bindings
                   if isinstance(b["role"], str) and b["role"] not in READ_ONLY_ROLES})
    return {"bindings": bindings, "roles": role_permissions(store, held)}


def role_permissions(store: Any, roles: Iterable[str]) -> dict[str, list[str] | None]:
    """Each role's `includedPermissions` from the IAM API, or None.

    UNCONFIRMED: `GET https://iam.googleapis.com/v1/{name}` for a
    predefined (`roles/...`) or project custom (`projects/.../roles/...`)
    role, answering `includedPermissions`, with the store client's
    credentials, is from the IAM REST documentation and not exercised
    against Google Cloud here.
    """
    out: dict[str, list[str] | None] = {}
    try:
        from google.auth.transport.requests import AuthorizedSession

        session = AuthorizedSession(store._bucket.client._credentials)
    except Exception:  # noqa: BLE001 - no session reads nothing
        return dict.fromkeys(roles)
    for role in roles:
        try:
            resp = session.get(_IAM + role, timeout=_TIMEOUT_S)
            perms = resp.json().get("includedPermissions") if resp.status_code == 200 else None
            out[role] = ([p for p in perms if isinstance(p, str)]
                         if isinstance(perms, list) else None)
        except Exception:  # noqa: BLE001 - an unread role fails its bindings
            out[role] = None
    return out


def scope(store: Any) -> dict[str, str]:
    return {"bucket": store.bucket_name, "prefix": store.prefix}


def exclusion(bucket: str, prefix: str) -> str:
    """The clause the store module ANDs onto each writer condition."""
    root = f"projects/_/buckets/{bucket}/objects/{prefix + '/' if prefix else ''}"
    return (f'!resource.name.startsWith("{root}{OVERRIDES_KEY}") && '
            f'!resource.name.startsWith("{root}{AUDIT_PREFIX}")')


def _closing(expr: str, start: int) -> int:
    """Index of the parenthesis closing the one at `start`, skipping
    string literals, or -1."""
    depth, quote, i = 0, "", start
    while i < len(expr):
        c = expr[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _excludes(expr: str, clause: str) -> bool:
    """Whether `expr` is `clause`, or `(<anything>) && clause`: the two
    shapes the store module writes, where the clause holds on every
    request the expression allows."""
    expr = expr.strip()
    if expr == clause:
        return True
    tail = f" && {clause}"
    if not expr.endswith(tail) or not expr.startswith("("):
        return False
    return _closing(expr, 0) == len(expr) - len(tail) - 1


def evaluate(doc: dict[str, Any], *, bucket: str, prefix: str,
             writers: Iterable[str]) -> dict[str, str | None]:
    clause = exclusion(bucket, prefix)
    bindings = [b for b in doc.get("bindings") or () if isinstance(b, dict)]
    roles = doc.get("roles") if isinstance(doc.get("roles"), dict) else {}
    out: dict[str, str | None] = {}
    for member in writers:
        mine = [b for b in bindings
                if ({member} | PUBLIC_MEMBERS) & set(b.get("members") or ())
                and b.get("role") not in READ_ONLY_ROLES]
        reason: str | None = None if mine else REASON_NO_BINDING
        perms = [roles.get(b.get("role")) for b in mine]
        if any(isinstance(p, list) and SET_IAM_PERMISSION in p for p in perms):
            out[member] = REASON_SET_IAM
            continue
        if any(not isinstance(p, list) for p in perms):
            out[member] = REASON_ROLE_UNREADABLE
            continue
        for b in mine:
            cond = b.get("condition")
            expr = cond.get("expression") if isinstance(cond, dict) else None
            if not isinstance(expr, str) or not expr.strip():
                reason = REASON_UNCONDITIONED
                break
            if not _excludes(expr, clause):
                reason = REASON_MISSING_EXCLUSION
        out[member] = reason
    return out
