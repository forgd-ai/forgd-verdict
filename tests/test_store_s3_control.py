"""store-s3's control role: the reader's policy plus the runtime overrides writes.

With `control_enabled` the dashboard's control role may put the overrides
object and audit records and nothing else, an audit put without
If-None-Match is denied in the bucket policy, and the role is on the
no-deletes deny with the other two. Off, none of it exists.

Parsed from the .tf source, as the other store-s3 checks in
test_terraform_modules.py are; the key ARNs are evaluated by terraform with no
provider.
"""

from __future__ import annotations

import fnmatch
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from terraform_render import off_versus_baseline
from test_terraform_modules import STORE_S3, _blocks, _policy_documents, _top_level

MODULE = STORE_S3.parent
VARIABLES = MODULE / "variables.tf"
OUTPUTS = MODULE / "outputs.tf"

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

OVERRIDES = "local.control_overrides_object"
AUDIT = "local.control_audit_objects"
ENABLED_COUNT = "var.control_enabled ? 1 : 0"
REQUIRED = {"bucket_name": "forgd-findings", "writer_assume_role_policy": "{}",
            "reader_assume_role_policy": "{}"}


def _code() -> str:
    return re.sub(r"(?m)^\s*#.*$", "", STORE_S3.read_text(encoding="utf-8"))


def _attr(body: str, name: str) -> str | None:
    m = re.search(rf"^\s*{name}\s*=\s*(.+?)\s*$", _top_level(body), re.M)
    return m.group(1) if m else None


def _resources(kind: str) -> dict[str, str]:
    return {labels[1]: inner for k, labels, inner in _blocks(_code())
            if k == "resource" and labels[0] == kind}


def _locals() -> dict[str, str]:
    body = next(inner for k, _, inner in _blocks(_code()) if k == "locals")
    starts = list(re.finditer(r"^  (\w+)\s*=", body, re.M))
    return {m.group(1): body[m.end():(starts[i + 1].start() if i + 1 < len(starts) else len(body))].strip()
            for i, m in enumerate(starts)}


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([terraform, f"-chdir={cwd}", *args, "-no-color"],
                          capture_output=True, text=True, timeout=120)


def _evaluate(tmp_path: Path, exprs: dict[str, str], **variables) -> dict:
    """Each expression's value against variables.tf and the locals it reads,
    with the bucket's ARN built from var.bucket_name."""
    arn = '"arn:aws:s3:::${var.bucket_name}"'

    def plain(e: str) -> str:
        return e.replace("${aws_s3_bucket.findings.arn}", "arn:aws:s3:::${var.bucket_name}").replace(
            "aws_s3_bucket.findings.arn", arn)

    exprs = {n: plain(e) for n, e in exprs.items()}
    all_locals, needed, pending = _locals(), {}, list(exprs.values())
    while pending:
        for name in re.findall(r"\blocal\.(\w+)", pending.pop()):
            if name not in needed:
                needed[name] = plain(all_locals[name])
                pending.append(needed[name])
    shutil.copy(VARIABLES, tmp_path / "variables.tf")
    (tmp_path / "main.tf").write_text(
        "locals {\n" + "".join(f"  {n} = {e}\n" for n, e in needed.items()) + "}\n"
        + "".join(f'output "{n}" {{\n  value = {e}\n}}\n' for n, e in exprs.items()),
        encoding="utf-8")
    (tmp_path / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}), encoding="utf-8")
    assert _run(["init", "-input=false"], tmp_path).returncode == 0
    out = _run(["apply", "-auto-approve", "-input=false"], tmp_path)
    assert out.returncode == 0, out.stderr
    out = subprocess.run([terraform, f"-chdir={tmp_path}", "output", "-json"],
                         capture_output=True, text=True, timeout=60, check=True)
    return {k: v["value"] for k, v in json.loads(out.stdout).items()}


# --- off -----------------------------------------------------------------


def test_every_control_resource_exists_only_when_enabled():
    found = {}
    for kind in ("aws_iam_role", "aws_iam_policy", "aws_iam_role_policy_attachment"):
        for name, body in _resources(kind).items():
            if "control" in name:
                found[(kind, name)] = _attr(body, "count")
    assert set(found) == {("aws_iam_role", "control"), ("aws_iam_policy", "control"),
                          ("aws_iam_role_policy_attachment", "control_reads"),
                          ("aws_iam_role_policy_attachment", "control_writes")}, found
    assert set(found.values()) == {ENABLED_COUNT}, found
    doc = next(inner for k, labels, inner in _blocks(_code())
               if k == "data" and labels == ["aws_iam_policy_document", "control"])
    assert _attr(doc, "count") == ENABLED_COUNT


def test_off_the_bucket_policy_renders_what_it_did():
    """The no-deletes principals are the two roles plus a splat that is empty
    at count 0, and the writer deny, the bucket-policy deny and the audit
    deny are each a dynamic statement on the flag."""
    bucket = next(inner for k, labels, inner in _blocks(_code())
                  if k == "data" and labels == ["aws_iam_policy_document", "bucket"])
    assert "concat([aws_iam_role.writer.arn, aws_iam_role.reader.arn], aws_iam_role.control[*].arn)" in bucket
    dynamics = [inner for k, labels, inner in _blocks(bucket) if k == "dynamic" and labels == ["statement"]]
    assert len(dynamics) == 3
    assert {_attr(d, "for_each") for d in dynamics} == {"var.control_enabled ? [1] : []"}


def test_the_control_output_is_null_unless_enabled():
    outputs = {labels[0]: inner for k, labels, inner in _blocks(OUTPUTS.read_text()) if k == "output"}
    assert _attr(outputs["control_role_arn"], "value") == (
        "var.control_enabled ? aws_iam_role.control[0].arn : null")


# --- what the control role may do --------------------------------------------


def test_the_control_policy_puts_the_overrides_object_and_audit_records_only():
    statements = _policy_documents()["control"]
    allows = [s for s in statements if s["effect"] == "Allow"]
    assert len(allows) == len(statements) == 3, statements
    evidence = [s for s in allows if s["actions"] == ["s3:GetBucketPolicy"]]
    assert len(evidence) == 1 and evidence[0]["resources"] == ["aws_s3_bucket.findings.arn"], allows
    assert not evidence[0]["conditions"]
    s3 = [s for s in allows if any(a.startswith("s3:") for a in s["actions"]) and s not in evidence]
    assert len(s3) == 1, allows
    assert s3[0]["actions"] == ["s3:PutObject"], s3
    assert sorted(s3[0]["resources"]) == sorted([OVERRIDES, AUDIT]), s3
    assert not s3[0]["conditions"]
    kms = [s for s in allows if s not in s3 and s not in evidence]
    assert kms[0]["actions"] == ["kms:GenerateDataKey"] and kms[0]["resources"] == ["var.kms_key_arn"]


def test_the_control_role_carries_the_readers_policy_and_its_own():
    attachments = _resources("aws_iam_role_policy_attachment")
    assert _attr(attachments["control_reads"], "policy_arn") == "aws_iam_policy.reader.arn"
    assert _attr(attachments["control_writes"], "policy_arn") == "aws_iam_policy.control[0].arn"
    for name in ("control_reads", "control_writes"):
        assert _attr(attachments[name], "role") == "aws_iam_role.control[0].name", name
    others = [n for n, b in attachments.items() if "aws_iam_role.control" in (_attr(b, "role") or "")]
    assert sorted(others) == ["control_reads", "control_writes"], others


def test_no_other_role_gets_the_control_policy():
    for name, body in _resources("aws_iam_role_policy_attachment").items():
        if _attr(body, "policy_arn") == "aws_iam_policy.control[0].arn":
            assert name == "control_writes", name


def test_an_audit_put_without_if_none_match_is_denied_to_the_control_role():
    denies = [s for s in _policy_documents()["bucket"]
              if s["effect"] == "Deny" and "s3:PutObject" in s["actions"]
              and ("aws:PrincipalArn", ["aws_iam_role.control[0].arn"]) in s["conditions"]]
    assert len(denies) == 1, denies
    deny = denies[0]
    assert deny["actions"] == ["s3:PutObject"]
    assert deny["resources"] == [AUDIT]
    assert ["*"] in deny["principals"]
    assert sorted(deny["conditions"]) == sorted([
        ("aws:PrincipalArn", ["aws_iam_role.control[0].arn"]),
        ("s3:if-none-match", ["true"]),
    ]), deny["conditions"]
    body = next(inner for k, labels, inner in _blocks(_code())
                if k == "data" and labels == ["aws_iam_policy_document", "bucket"])
    tests = re.findall(r'test\s*=\s*"(\w+)"\s*\n\s*variable\s*=\s*"s3:if-none-match"', body)
    assert tests == ["Null"], tests


@requires_terraform
@pytest.mark.parametrize("prefix", ["", "org/prod"])
def test_the_control_arns_are_the_overrides_object_and_the_audit_prefix(tmp_path, prefix):
    got = _evaluate(tmp_path, {"o": OVERRIDES, "a": AUDIT}, key_prefix=prefix)
    root = f"arn:aws:s3:::forgd-findings/{prefix + '/' if prefix else ''}"
    assert got == {"o": f"{root}state/runtime-overrides.json",
                   "a": f"{root}audit/runtime-overrides/*"}, got


@requires_terraform
def test_the_control_arns_reach_nothing_else(tmp_path):
    prefix = "org/prod"
    got = _evaluate(tmp_path, {"o": OVERRIDES, "a": AUDIT}, key_prefix=prefix)
    arn = "arn:aws:s3:::forgd-findings/"

    def allowed(key: str) -> bool:
        return any(fnmatch.fnmatchcase(arn + key, pattern) for pattern in got.values())

    assert allowed(f"{prefix}/state/runtime-overrides.json")
    assert allowed(f"{prefix}/audit/runtime-overrides/2026-09-28/x-request.json")
    for outside in (f"{prefix}/state/cursor.json", f"{prefix}/state/runtime-overrides.json.bak",
                    f"{prefix}/audit/runtime-overrides", f"{prefix}/audit/other/x.json",
                    f"{prefix}/markers/stats_reset", f"{prefix}/markers/excluded_requests",
                    f"{prefix}/verdicts/x.jsonl", "state/runtime-overrides.json",
                    "audit/runtime-overrides/x.json"):
        assert not allowed(outside), outside


# --- refused -------------------------------------------------------------


def _control_preconditions() -> list[str]:
    role = _resources("aws_iam_role")["control"]
    lifecycle = next(inner for k, _, inner in _blocks(role) if k == "lifecycle")
    return [_attr(p, "condition") for k, _, p in _blocks(lifecycle) if k == "precondition"]


@requires_terraform
@pytest.mark.parametrize("case,ok", [
    ({"control_assume_role_policy": "{}"}, True),
    ({}, False),
    ({"control_assume_role_policy": "{}", "control_role_name": "forgd-dashboard-reader"}, False),
    ({"control_assume_role_policy": "{}", "control_role_name": "forgd-verdict-writer"}, False),
])
def test_a_control_role_without_trust_or_named_as_another_is_refused(tmp_path, case, ok):
    conditions = _control_preconditions()
    assert len(conditions) == 2, conditions
    got = _evaluate(tmp_path, {f"p{i}": c for i, c in enumerate(conditions)}, control_enabled=True, **case)
    assert all(got.values()) is ok, (case, got)


# --- the writer cannot write the runtime overrides --------------------------


def test_the_writer_role_is_denied_every_write_to_the_overrides_in_the_bucket_policy():
    """A bucket-policy Deny, so no policy attached to the writer role later
    can grant it, present while control is enabled."""
    denies = [s for s in _policy_documents()["bucket"] if s["effect"] == "Deny"
              and s["conditions"] == [("aws:PrincipalArn", ["aws_iam_role.writer.arn"])]
              and "s3:PutObject" in s["actions"]]
    assert len(denies) == 1, denies
    assert denies[0]["actions"] == ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"]
    assert sorted(denies[0]["resources"]) == sorted([OVERRIDES, AUDIT])
    assert ["*"] in denies[0]["principals"]
    body = next(inner for k, labels, inner in _blocks(_code())
                if k == "data" and labels == ["aws_iam_policy_document", "bucket"])
    dynamics = [inner for k, labels, inner in _blocks(body) if k == "dynamic" and labels == ["statement"]]
    gated = [d for d in dynamics if '"WriterCannotWriteRuntimeOverrides"' in d]
    assert len(gated) == 1 and _attr(gated[0], "for_each") == "var.control_enabled ? [1] : []"


def test_the_writer_role_cannot_rewrite_the_bucket_policy():
    """The S3 verifier requires this Deny. Mutation: drop it, or an action."""
    denies = [s for s in _policy_documents()["bucket"] if s["effect"] == "Deny"
              and s["conditions"] == [("aws:PrincipalArn", ["aws_iam_role.writer.arn"])]
              and "s3:PutObject" not in s["actions"]]
    assert len(denies) == 1, denies
    assert denies[0]["actions"] == ["s3:PutBucketPolicy", "s3:DeleteBucketPolicy"]
    assert denies[0]["resources"] == ["aws_s3_bucket.findings.arn"]
    assert ["*"] in denies[0]["principals"]
    body = next(inner for k, labels, inner in _blocks(_code())
                if k == "data" and labels == ["aws_iam_policy_document", "bucket"])
    gated = [inner for k, labels, inner in _blocks(body) if k == "dynamic" and labels == ["statement"]
             and '"WriterCannotRewriteBucketPolicy"' in inner]
    assert len(gated) == 1 and _attr(gated[0], "for_each") == "var.control_enabled ? [1] : []"


ROLE_OF = {"aws_iam_role.writer.arn": "writer", "aws_iam_role.reader.arn": "reader",
           "aws_iam_role.control[0].arn": "control", "aws_iam_role.control[*].arn": "control"}
# The identity policies each role carries.
IDENTITY = {"writer": ["writer"], "reader": ["reader"], "control": ["reader", "control"]}


def _ref(item: str) -> bool:
    return re.fullmatch(r"(local|var|aws_\w+)\.[\w.\[\]*]+", item) is not None


def _decider(tmp_path: Path, prefix: str):
    """A function (role, action, key, if_none_match) -> allowed, evaluating
    the module's identity policies and bucket policy as IAM does: allowed
    when some Allow matches and no Deny does."""
    docs = _policy_documents()
    statements = [(name, st) for name in ("writer", "reader", "control", "bucket")
                  for st in docs[name] if not any(a.startswith("kms:") for a in st["actions"])]
    exprs = {}
    for _, st in statements:
        for item in st["resources"]:
            exprs.setdefault(item, f"r{len(exprs)}")
    got = _evaluate(tmp_path, {n: (e if _ref(e) else json.dumps(e)) for e, n in exprs.items()},
                    key_prefix=prefix, control_enabled=True, control_assume_role_policy="{}")
    resolved = {e: got[n] for e, n in exprs.items()}

    def matches(st, role, action, arn, if_none_match):
        if not any(fnmatch.fnmatchcase(action, a) for a in st["actions"]):
            return False
        if not any(fnmatch.fnmatchcase(arn, resolved[r]) for r in st["resources"]):
            return False
        for variable, values in st["conditions"]:
            if variable == "aws:PrincipalArn":
                if role not in {ROLE_OF[v] for v in values}:
                    return False
            elif variable == "s3:if-none-match":
                assert values == ["true"]
                if if_none_match:
                    return False
            elif variable == "aws:SecureTransport":
                return False
            else:
                raise AssertionError(f"no model of condition {variable}")
        return True

    def allowed(role, action, key, if_none_match=False):
        arn = f"arn:aws:s3:::forgd-findings/{key}"
        allow = any(st["effect"] == "Allow" and doc in IDENTITY[role]
                    and matches(st, role, action, arn, if_none_match) for doc, st in statements)
        deny = any(st["effect"] == "Deny" and (doc == "bucket" or doc in IDENTITY[role])
                   and matches(st, role, action, arn, if_none_match) for doc, st in statements)
        return allow and not deny

    return allowed


@requires_terraform
@pytest.mark.parametrize("prefix", ["", "org/prod"])
def test_the_effective_writes_to_the_overrides_are_the_control_roles_alone(tmp_path, prefix):
    """Mutation: drop the writer's Deny from the bucket policy."""
    allowed = _decider(tmp_path, prefix)
    root = f"{prefix}/" if prefix else ""
    overrides = f"{root}state/runtime-overrides.json"
    audit = f"{root}audit/runtime-overrides/2026-09-28/20260928T140311Z-0123456789ab-request.json"
    for key in (f"{root}verdicts/x.jsonl", f"{root}state/cursor.json",
                f"{root}markers/stats_reset", f"{root}markers/excluded_requests"):
        assert allowed("writer", "s3:PutObject", key), key
        assert not allowed("control", "s3:PutObject", key), key
    for key in (overrides, audit):
        for inm in (False, True):
            assert not allowed("writer", "s3:PutObject", key, inm), (key, inm)
            assert not allowed("reader", "s3:PutObject", key, inm), (key, inm)
        for role in ("writer", "reader", "control"):
            assert not allowed(role, "s3:DeleteObject", key), (role, key)
            assert allowed(role, "s3:GetObject", key), (role, key)
    assert allowed("control", "s3:PutObject", overrides)
    assert allowed("control", "s3:PutObject", audit, True)
    assert not allowed("control", "s3:PutObject", audit, False)


def _output(name: str) -> str:
    outputs = {labels[0]: inner for k, labels, inner in _blocks(OUTPUTS.read_text()) if k == "output"}
    body = outputs[name]
    start = body.index("value =") + len("value =")
    end = body.index("\n  description")
    return body[start:end].strip()


@requires_terraform
@pytest.mark.parametrize("prefix", ["", "org/prod"])
def test_the_writer_deny_output_matches_the_bucket_policys_deny(tmp_path, prefix):
    """It also denies bucket configuration, so a lifecycle rule cannot expire
    the audit chain, and deletes, which the bucket policy denies this
    module's writer role. Mutation: drop an action or a resource from the
    output."""
    got = _evaluate(tmp_path, {"p": _output("writer_deny_policy_json")}, key_prefix=prefix,
                    control_enabled=True)
    policy = json.loads(got["p"])
    statement, policy_deny, configure_deny, delete_deny = policy["Statement"]
    [bucket_deny] = [s for s in _policy_documents()["bucket"]
                     if s["conditions"] == [("aws:PrincipalArn", ["aws_iam_role.writer.arn"])]
                     and "s3:PutObject" in s["actions"]]
    assert policy_deny == {"Sid": "WriterCannotRewriteBucketPolicy", "Effect": "Deny",
                           "Action": ["s3:PutBucketPolicy", "s3:DeleteBucketPolicy"],
                           "Resource": ["arn:aws:s3:::forgd-findings"]}
    assert configure_deny["Sid"] == "WriterCannotReconfigureBucket" and configure_deny["Effect"] == "Deny"
    assert configure_deny["Resource"] == ["arn:aws:s3:::forgd-findings"]
    for action in ("s3:PutLifecycleConfiguration", "s3:PutBucketVersioning", "s3:PutReplicationConfiguration",
                   "s3:PutBucketObjectLockConfiguration", "s3:PutEncryptionConfiguration",
                   "s3:DeleteBucket", "s3:PutBucketAcl"):
        assert any(fnmatch.fnmatchcase(action, a) for a in configure_deny["Action"]), action
    assert delete_deny == {"Sid": "WriterCannotDelete", "Effect": "Deny",
                           "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                           "Resource": ["arn:aws:s3:::forgd-findings/*"]}
    assert statement["Effect"] == "Deny" and "Principal" not in statement
    assert statement["Action"] == bucket_deny["actions"]
    root = f"{prefix}/" if prefix else ""
    assert sorted(statement["Resource"]) == sorted([
        f"arn:aws:s3:::forgd-findings/{root}state/runtime-overrides.json",
        f"arn:aws:s3:::forgd-findings/{root}audit/runtime-overrides/*"])
    audit = f"arn:aws:s3:::forgd-findings/{root}audit/runtime-overrides/2026-09-28/x-request.json"
    for arn in (statement["Resource"][0], audit):
        assert any(fnmatch.fnmatchcase(arn, r) for r in statement["Resource"]), arn
    assert not any(fnmatch.fnmatchcase(f"arn:aws:s3:::forgd-findings/{root}verdicts/x.jsonl", r)
                   for r in statement["Resource"])


# --- off is the plan from before control existed -------------------------------


@requires_terraform
@pytest.mark.parametrize("variables", [
    REQUIRED,
    {**REQUIRED, "key_prefix": "forgd", "kms_key_arn": "arn:aws:kms:eu-west-1:111111111111:key/k"},
    {**REQUIRED, "writer_role_name": "w", "reader_role_name": "r", "tags": {"team": "sec"}},
], ids=["defaults", "prefix-and-kms", "names-and-tags"])
@pytest.mark.parametrize("current", [{}, {"control_enabled": False}], ids=["default", "explicit"])
def test_off_every_resource_renders_as_it_did_before_control(tmp_path, variables, current):
    """Every resource and data source in the module, rendered in full with a
    mocked provider, including every statement of the bucket policy, equals
    the pinned baseline's rendering of the same variables."""
    assert off_versus_baseline(tmp_path, "store-s3", variables, current) == []


@requires_terraform
def test_on_the_rendering_shows_the_writer_deny(tmp_path):
    """The comparison above can see the control changes."""
    found = off_versus_baseline(tmp_path, "store-s3", REQUIRED,
                                {"control_enabled": True, "control_assume_role_policy": "{}"})
    assert any("WriterCannotWriteRuntimeOverrides" in d and d.startswith("data.aws_iam_policy_document.bucket")
               for d in found), found


@requires_terraform
def test_off_the_writer_deny_output_is_null(tmp_path):
    """Off, the bucket policy has no writer Deny, so neither does the output
    a caller attaches to a writer role of its own. Mutation: drop the gate."""
    # `terraform output -json` leaves a null output out.
    assert _evaluate(tmp_path, {"p": _output("writer_deny_policy_json")}).get("p") is None


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


@requires_terraform
@pytest.mark.parametrize("enabled", [False, True])
def test_the_writer_identities_are_the_writer_role_only_with_control(tmp_path, enabled):
    """What app-ecs and the chart pass the dashboard's verifier. Mutation:
    list the reader or the control role, or drop the gate."""
    arn = "arn:aws:iam::111111111111:role/forgd-verdict-writer"
    outputs = {labels[0]: inner for k, labels, inner in _blocks(OUTPUTS.read_text()) if k == "output"}
    expr = re.search(r"^\s*value\s*=\s*(.+?)\s*$", outputs["overrides_writer_identities"],
                     re.M).group(1).replace("aws_iam_role.writer.arn", f'"{arn}"')
    assert _evaluate(tmp_path, {"ids": expr}, control_enabled=enabled) == {
        "ids": [arn] if enabled else []}
