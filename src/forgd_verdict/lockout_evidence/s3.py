"""S3: each writer role is locked out when the bucket policy holds an
explicit Deny, for every principal whose `aws:PrincipalArn` is that role,
of put and delete on the runtime overrides object and the audit prefix.

A Deny in the bucket policy holds whatever the role's own policies allow,
so the bucket policy alone decides. The Deny must also cover
s3:PutBucketPolicy and s3:DeleteBucketPolicy on the bucket for that role:
a role that can rewrite the bucket policy can remove the Deny.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from . import EvidenceUnavailable

OVERRIDES_KEY = "state/runtime-overrides.json"
AUDIT_PREFIX = "audit/runtime-overrides/"
DENIED_ACTIONS = ("s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion")
POLICY_ACTIONS = ("s3:PutBucketPolicy", "s3:DeleteBucketPolicy")

REASON_NO_DENY = "no_deny_for_writer"
REASON_UNCOVERED = "deny_does_not_cover_overrides"
REASON_POLICY = "deny_does_not_cover_bucket_policy"

_S3_ARN = re.compile(r"^arn:[a-z0-9-]+:s3:::(.+)\Z")


def fetch(store: Any) -> dict[str, Any]:
    """The bucket policy as a document.

    UNCONFIRMED: the call shape, `get_bucket_policy(Bucket=...)` returning
    the policy as a JSON string under `Policy`, and the error codes below,
    are from the boto3 documentation and not exercised against AWS here.
    """
    from ..store.s3 import _code

    try:
        raw = store._client.get_bucket_policy(Bucket=store.bucket)["Policy"]
    except Exception as exc:  # noqa: BLE001 - mapped to a fixed code
        code = _code(exc)
        if code == "NoSuchBucketPolicy":
            raise EvidenceUnavailable("no_bucket_policy") from None
        if code in ("AccessDenied", "AccessDeniedException", "403"):
            raise EvidenceUnavailable("policy_read_denied") from None
        raise EvidenceUnavailable("policy_read_failed") from None
    try:
        doc = json.loads(raw)
    except (TypeError, ValueError, RecursionError):
        raise EvidenceUnavailable("policy_unparseable") from None
    if not isinstance(doc, dict):
        raise EvidenceUnavailable("policy_unparseable")
    return doc


def scope(store: Any) -> dict[str, str]:
    return {"bucket": store.bucket, "prefix": store.prefix}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _glob(pattern: str, value: str, *, ignore_case: bool = False) -> bool:
    """IAM wildcard match: `*` any run, `?` one character."""
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, value, re.IGNORECASE if ignore_case else 0) is not None


def _covers_resource(pattern: str, target: str) -> bool:
    """Whether a Resource entry covers `target`, a `bucket/key` path. A
    target ending in `*` is a prefix, covered only by an entry matching
    every key under it."""
    m = _S3_ARN.match(pattern) if isinstance(pattern, str) else None
    if pattern == "*":
        return True
    if m is None:
        return False
    path = m.group(1)
    if not target.endswith("*"):
        return _glob(path, target)
    base = target[:-1]
    if not path.endswith("*"):
        return False
    stem = path[:-1]
    return "*" not in stem and "?" not in stem and base.startswith(stem)


def _names_writer(stmt: dict[str, Any], arn: str) -> bool:
    principal = stmt.get("Principal")
    if (isinstance(principal, dict) and set(principal) == {"AWS"}
            and arn in _list(principal["AWS"]) and "Condition" not in stmt):
        return True
    if not (principal == "*" or (isinstance(principal, dict)
                                 and _list(principal.get("AWS")) == ["*"]
                                 and set(principal) == {"AWS"})):
        return False
    condition = stmt.get("Condition")
    # A second operator or key would narrow the Deny, so only the one shape.
    if not isinstance(condition, dict) or list(condition) != ["ArnEquals"]:
        return False
    inner = condition["ArnEquals"]
    if not isinstance(inner, dict) or list(inner) != ["aws:PrincipalArn"]:
        return False
    return arn in _list(inner["aws:PrincipalArn"])


def _denies(stmts: Iterable[dict[str, Any]], action: str, target: str) -> bool:
    return any(
        any(isinstance(a, str) and _glob(a, action, ignore_case=True)
            for a in _list(s.get("Action")))
        and any(_covers_resource(r, target) for r in _list(s.get("Resource")))
        for s in stmts)


def evaluate(doc: dict[str, Any], *, bucket: str, prefix: str,
             writers: Iterable[str]) -> dict[str, str | None]:
    root = f"{prefix}/" if prefix else ""
    targets = (f"{bucket}/{root}{OVERRIDES_KEY}", f"{bucket}/{root}{AUDIT_PREFIX}*")
    deny = [s for s in _list(doc.get("Statement"))
            if isinstance(s, dict) and s.get("Effect") == "Deny"
            and "NotAction" not in s and "NotResource" not in s and "NotPrincipal" not in s]
    out: dict[str, str | None] = {}
    for arn in writers:
        mine = [s for s in deny if _names_writer(s, arn)]
        if not mine:
            out[arn] = REASON_NO_DENY
        elif not all(_denies(mine, a, t) for a in DENIED_ACTIONS for t in targets):
            out[arn] = REASON_UNCOVERED
        elif not all(_denies(mine, a, bucket) for a in POLICY_ACTIONS):
            out[arn] = REASON_POLICY
        else:
            out[arn] = None
    return out
