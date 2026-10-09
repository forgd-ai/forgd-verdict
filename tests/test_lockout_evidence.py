"""Each cloud's evaluation of a writer's lockout from its IAM policy, on
policy documents shaped like the store modules' Terraform output."""

from __future__ import annotations

import copy
import json

import pytest

from forgd_verdict.lockout_evidence import EvidenceUnavailable, verifier
from forgd_verdict.lockout_evidence import s3 as s3e

WRITER = "arn:aws:iam::111111111111:role/forgd-verdict-writer"
OTHER = "arn:aws:iam::111111111111:role/forgd-other-writer"
BUCKET = "forgd-findings-example"


class _Store:
    def __init__(self, kind: str, **attrs):
        self.evidence_kind = kind
        self.__dict__.update(attrs)


# -- S3 ---------------------------------------------------------------------

def s3_policy(prefix: str = "tenant", writers=(WRITER,)) -> dict:
    root = f"{prefix}/" if prefix else ""
    arn = f"arn:aws:s3:::{BUCKET}"
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*",
         "Action": "s3:*", "Resource": [arn, f"{arn}/*"],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
        {"Sid": "WriterCannotWriteRuntimeOverrides", "Effect": "Deny",
         "Principal": {"AWS": "*"},
         "Action": ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"],
         "Resource": [f"{arn}/{root}state/runtime-overrides.json",
                      f"{arn}/{root}audit/runtime-overrides/*"],
         "Condition": {"ArnEquals": {"aws:PrincipalArn": list(writers)}}},
        {"Sid": "WriterCannotRewriteBucketPolicy", "Effect": "Deny",
         "Principal": {"AWS": "*"},
         "Action": ["s3:PutBucketPolicy", "s3:DeleteBucketPolicy"],
         "Resource": arn,
         "Condition": {"ArnEquals": {"aws:PrincipalArn": list(writers)}}},
    ]}


def s3_eval(doc, prefix="tenant", writers=(WRITER,)):
    return s3e.evaluate(doc, bucket=BUCKET, prefix=prefix, writers=writers)


def _deny(doc):
    return doc["Statement"][1]


@pytest.mark.parametrize("prefix", ["tenant", ""])
def test_s3_the_module_policy_verifies(prefix):
    assert s3_eval(s3_policy(prefix), prefix) == {WRITER: None}


def test_s3_accepts_string_forms_and_s3_star():
    doc = s3_policy()
    d = _deny(doc)
    d["Principal"] = "*"
    d["Action"] = "s3:*"
    d["Condition"] = {"ArnEquals": {"aws:PrincipalArn": WRITER}}
    d["Resource"] = f"arn:aws:s3:::{BUCKET}/tenant/*"
    assert s3_eval(doc) == {WRITER: None}


def test_s3_no_deny_fails():
    doc = s3_policy()
    del doc["Statement"][1:]
    assert s3_eval(doc) == {WRITER: "no_deny_for_writer"}


def test_s3_an_allow_is_not_a_deny():
    doc = s3_policy()
    for stmt in doc["Statement"][1:]:
        stmt["Effect"] = "Allow"
    assert s3_eval(doc) == {WRITER: "no_deny_for_writer"}


def test_s3_a_writer_absent_from_the_condition_fails():
    assert s3_eval(s3_policy(writers=(OTHER,))) == {WRITER: "no_deny_for_writer"}


def test_s3_a_narrowing_second_condition_fails():
    doc = s3_policy()
    for stmt in doc["Statement"][1:]:
        stmt["Condition"]["StringEquals"] = {"aws:SourceVpce": "vpce-0example"}
    assert s3_eval(doc) == {WRITER: "no_deny_for_writer"}


@pytest.mark.parametrize("change", ["dropped", "put-only", "delete-only", "objects-only", "other-writer"])
def test_s3_a_writer_that_can_rewrite_the_bucket_policy_fails(change):
    """Mutation: skip the bucket-policy check."""
    doc = s3_policy()
    stmt = doc["Statement"][2]
    if change == "dropped":
        del doc["Statement"][2]
    elif change == "put-only":
        stmt["Action"] = ["s3:PutBucketPolicy"]
    elif change == "delete-only":
        stmt["Action"] = ["s3:DeleteBucketPolicy"]
    elif change == "objects-only":
        stmt["Resource"] = f"arn:aws:s3:::{BUCKET}/*"
    else:
        stmt["Condition"] = {"ArnEquals": {"aws:PrincipalArn": [OTHER]}}
    assert s3_eval(doc) == {WRITER: "deny_does_not_cover_bucket_policy"}


def test_s3_one_statement_denying_everything_covers_the_bucket_policy():
    doc = s3_policy()
    del doc["Statement"][2]
    _deny(doc)["Action"] = "s3:*"
    _deny(doc)["Resource"] = [f"arn:aws:s3:::{BUCKET}", f"arn:aws:s3:::{BUCKET}/*"]
    assert s3_eval(doc) == {WRITER: None}


@pytest.mark.parametrize("drop", ["audit", "object"])
def test_s3_a_deny_missing_either_target_fails(drop):
    """Mutation: check only the overrides object, or only the audit prefix."""
    doc = s3_policy()
    keep = "state/" if drop == "audit" else "audit/"
    _deny(doc)["Resource"] = [r for r in _deny(doc)["Resource"] if keep in r]
    assert s3_eval(doc) == {WRITER: "deny_does_not_cover_overrides"}


@pytest.mark.parametrize("action", ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"])
def test_s3_a_deny_missing_an_action_fails(action):
    doc = s3_policy()
    _deny(doc)["Action"] = [a for a in _deny(doc)["Action"] if a != action]
    assert s3_eval(doc) == {WRITER: "deny_does_not_cover_overrides"}


def test_s3_a_deny_under_another_prefix_does_not_cover():
    assert s3_eval(s3_policy("other"), "tenant") == {WRITER: "deny_does_not_cover_overrides"}


def test_s3_a_single_object_does_not_cover_the_audit_prefix():
    doc = s3_policy()
    _deny(doc)["Resource"][1] = (
        f"arn:aws:s3:::{BUCKET}/tenant/audit/runtime-overrides/2026-01-01/one.json")
    assert s3_eval(doc) == {WRITER: "deny_does_not_cover_overrides"}


class _S3Client:
    def __init__(self, policy=None, error=None):
        self.policy, self.error = policy, error

    def get_bucket_policy(self, Bucket):  # noqa: N803 - boto3's keyword
        if self.error:
            exc = Exception("denied")
            exc.response = {"Error": {"Code": self.error}}
            raise exc
        return {"Policy": json.dumps(self.policy)}


@pytest.mark.parametrize("error,code", [("AccessDenied", "policy_read_denied"),
                                        ("NoSuchBucketPolicy", "no_bucket_policy"),
                                        ("SlowDown", "policy_read_failed")])
def test_s3_an_unreadable_policy_is_every_identitys_reason(error, code):
    store = _Store("s3", bucket=BUCKET, prefix="tenant", _client=_S3Client(error=error))
    with pytest.raises(EvidenceUnavailable) as info:
        s3e.fetch(store)
    assert info.value.code == code
    assert verifier.evaluate_store(store, (WRITER, OTHER)) == {WRITER: code, OTHER: code}


def test_s3_fetch_and_scope_reach_the_evaluation():
    store = _Store("s3", bucket=BUCKET, prefix="tenant",
                   _client=_S3Client(policy=s3_policy(writers=(WRITER,))))
    assert verifier.evaluate_store(store, (WRITER, OTHER)) == {
        WRITER: None, OTHER: "no_deny_for_writer"}


def test_s3_evaluation_does_not_mutate_the_document():
    doc = s3_policy()
    before = copy.deepcopy(doc)
    s3_eval(doc)
    assert doc == before


# -- GCS --------------------------------------------------------------------

from forgd_verdict.lockout_evidence import gcs as gcse  # noqa: E402

GWRITER = "serviceAccount:forgd-verdict@example-project.iam.gserviceaccount.com"
GOTHER = "serviceAccount:forgd-other@example-project.iam.gserviceaccount.com"


def gcs_policy(prefix: str = "tenant", members=(GWRITER,)) -> dict:
    """The writer bindings store-gcs emits with control_enabled."""
    root = f"projects/_/buckets/{BUCKET}/objects/{prefix + '/' if prefix else ''}"
    excl = (f'!resource.name.startsWith("{root}state/runtime-overrides.json") && '
            f'!resource.name.startsWith("{root}audit/runtime-overrides/")')
    data = (f'resource.name == "projects/_/buckets/{BUCKET}" || '
            f'resource.name.startsWith("{root}")')
    create = f"({data}) && {excl}" if prefix else excl
    delete = (f'(resource.name.startsWith("{root}state/") || '
              f'resource.name.startsWith("{root}markers/")) && {excl}')
    m = sorted(members)
    return {"bindings": [
        {"role": "roles/storage.objectCreator", "members": m,
         "condition": {"title": "writer-create", "expression": create}},
        {"role": "roles/storage.objectViewer", "members": m,
         "condition": {"title": "writer-read", "expression": data}},
        {"role": "projects/example-project/roles/forgdMutableDelete", "members": m,
         "condition": {"title": "writer-delete", "expression": delete}},
    ], "roles": dict(GCS_ROLES)}


# Each role's permissions as the IAM API would answer, abridged.
GCS_ROLES = {
    "roles/storage.objectCreator": ["storage.objects.create", "storage.multipartUploads.create"],
    "roles/storage.objectAdmin": ["storage.objects.create", "storage.objects.delete",
                                  "storage.objects.get", "storage.objects.list"],
    "roles/storage.admin": ["storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy",
                            "storage.objects.create"],
    "roles/storage.legacyBucketOwner": ["storage.buckets.get", "storage.buckets.setIamPolicy"],
    "projects/example-project/roles/forgdMutableDelete": ["storage.objects.delete"],
}


def gcs_eval(doc, prefix="tenant", writers=(GWRITER,)):
    return gcse.evaluate(doc, bucket=BUCKET, prefix=prefix, writers=writers)


@pytest.mark.parametrize("prefix", ["tenant", ""])
def test_gcs_the_module_policy_verifies(prefix):
    assert gcs_eval(gcs_policy(prefix), prefix) == {GWRITER: None}


def test_gcs_an_unconditioned_write_binding_fails():
    doc = gcs_policy()
    doc["bindings"].append({"role": "roles/storage.objectAdmin", "members": [GWRITER]})
    assert gcs_eval(doc) == {GWRITER: "unconditioned_binding"}


def test_gcs_an_unconditioned_read_binding_is_fine():
    doc = gcs_policy()
    doc["bindings"][1]["condition"] = None
    assert gcs_eval(doc) == {GWRITER: None}


@pytest.mark.parametrize("drop", ["audit", "object"])
def test_gcs_a_condition_missing_either_exclusion_fails(drop):
    """Mutation: require only the overrides object, or only the audit prefix."""
    doc = gcs_policy()
    gone = "audit/runtime-overrides/" if drop == "audit" else "state/runtime-overrides.json"
    for b in doc["bindings"]:
        if b["role"] != "roles/storage.objectViewer":
            c = b["condition"]
            c["expression"] = " && ".join(p for p in c["expression"].split(" && ")
                                          if gone not in p)
    assert gcs_eval(doc) == {GWRITER: "missing_exclusion"}


def test_gcs_an_exclusion_ored_away_fails():
    doc = gcs_policy()
    c = doc["bindings"][0]["condition"]
    c["expression"] = f"(true) || {c['expression']}"
    assert gcs_eval(doc) == {GWRITER: "missing_exclusion"}
    c["expression"] = "(true) || (x) && " + gcse.exclusion(BUCKET, "tenant")
    assert gcs_eval(doc) == {GWRITER: "missing_exclusion"}


def test_gcs_an_exclusion_for_another_prefix_fails():
    assert gcs_eval(gcs_policy("other"), "tenant") == {GWRITER: "missing_exclusion"}


def test_gcs_a_writer_absent_from_the_bindings_fails():
    assert gcs_eval(gcs_policy(members=(GOTHER,))) == {GWRITER: "no_binding_for_writer"}


@pytest.mark.parametrize("role", ["roles/storage.admin", "roles/storage.legacyBucketOwner",
                                  "projects/example-project/roles/forgdMutableDelete"])
@pytest.mark.parametrize("conditioned", [False, True])
def test_gcs_a_role_that_can_set_the_bucket_policy_fails_whatever_its_condition(role, conditioned):
    """Mutation: drop the setIamPolicy check."""
    doc = gcs_policy()
    doc["roles"][role] = [*doc["roles"][role], "storage.buckets.setIamPolicy"] \
        if "setIamPolicy" not in " ".join(doc["roles"][role]) else doc["roles"][role]
    binding = {"role": role, "members": [GWRITER]}
    if conditioned:
        binding["condition"] = {"title": "t", "expression": gcse.exclusion(BUCKET, "tenant")}
    doc["bindings"].append(binding)
    assert gcs_eval(doc) == {GWRITER: "grants_set_iam_policy"}


@pytest.mark.parametrize("roles", ["unread", "missing", "no-roles"])
def test_gcs_a_role_whose_permissions_are_unread_fails(roles):
    """Mutation: treat an unread role as holding nothing."""
    doc = gcs_policy()
    if roles == "unread":
        doc["roles"]["projects/example-project/roles/forgdMutableDelete"] = None
    elif roles == "missing":
        del doc["roles"]["projects/example-project/roles/forgdMutableDelete"]
    else:
        del doc["roles"]
    assert gcs_eval(doc) == {GWRITER: "role_permissions_unreadable"}


def test_gcs_a_read_only_role_needs_no_permissions():
    doc = gcs_policy()
    assert "roles/storage.objectViewer" not in doc["roles"]
    assert gcs_eval(doc) == {GWRITER: None}


class _GCSPolicy:
    def __init__(self, bindings):
        self.bindings = bindings


class _GCSBucket:
    def __init__(self, doc=None, status=None):
        self.doc, self.status = doc, status

    def get_iam_policy(self, requested_policy_version):
        assert requested_policy_version == 3
        if self.status:
            exc = Exception("denied")
            exc.code = self.status
            raise exc
        return _GCSPolicy([dict(b, members=set(b["members"])) for b in self.doc["bindings"]])


@pytest.mark.parametrize("status,code", [(403, "policy_read_denied"),
                                         (404, "bucket_not_found"),
                                         (503, "policy_read_failed")])
def test_gcs_an_unreadable_policy_is_every_identitys_reason(status, code):
    store = _Store("gcs", bucket_name=BUCKET, prefix="tenant", _bucket=_GCSBucket(status=status))
    assert verifier.evaluate_store(store, (GWRITER, GOTHER)) == {GWRITER: code, GOTHER: code}


def test_gcs_fetch_and_scope_reach_the_evaluation(monkeypatch):
    asked = []

    def permissions(store, roles):
        asked.append(list(roles))
        return {r: GCS_ROLES[r] for r in roles}

    monkeypatch.setattr(gcse, "role_permissions", permissions)
    monkeypatch.setenv(verifier.ENV_GCS_INHERITED_AUDITED_BY, "platform team, 2026-10-03")
    store = _Store("gcs", bucket_name=BUCKET, prefix="tenant",
                   _bucket=_GCSBucket(doc=gcs_policy()))
    assert verifier.evaluate_store(store, (GWRITER, GOTHER)) == {
        GWRITER: None, GOTHER: "no_binding_for_writer"}
    assert asked == [["projects/example-project/roles/forgdMutableDelete",
                      "roles/storage.objectCreator"]]


def test_gcs_role_permissions_are_none_without_a_session():
    store = _Store("gcs", _bucket=object())
    assert gcse.role_permissions(store, ["roles/storage.admin"]) == {"roles/storage.admin": None}


# -- Azure ------------------------------------------------------------------

from forgd_verdict.lockout_evidence import azure as aze  # noqa: E402

APRINCIPAL = "00000000-0000-0000-0000-00000000000a"
AOTHER = "00000000-0000-0000-0000-00000000000b"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
ACCOUNT = f"{SUB}/resourceGroups/rg-example/providers/Microsoft.Storage/storageAccounts/acct"
CONTAINER = f"{ACCOUNT}/blobServices/default/containers/findings"
ACCOUNT_URL = "https://acct.blob.core.windows.net"
BLOBS = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs"
MUTATING = [f"{BLOBS}/{a}" for a in ("write", "add/action", "delete", "deleteBlobVersion/action",
                                     "permanentDelete/action", "move/action")]


def az_condition(actions=MUTATING, path="state/runtime-overrides.json",
                 audit="audit/runtime-overrides/") -> str:
    """store-azure's writer_write_condition, as its heredoc renders."""
    acts = "\n  AND\n  ".join(f"!(ActionMatches{{'{a}'}})" for a in actions)
    return (f"(\n (\n  {acts}\n )\n OR\n (\n"
            f"  @Resource[{BLOBS}:path] StringNotEquals '{path}'\n  AND\n"
            f"  @Resource[{BLOBS}:path] StringNotStartsWith '{audit}'\n )\n)\n")


def az_writer(**over) -> dict:
    a = {"id": "a1", "principal_id": APRINCIPAL, "scope": CONTAINER,
         "role_definition_id": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/w",
         "actions": [], "not_actions": [],
         "data_actions": [f"{BLOBS}/read", *MUTATING[:2]], "not_data_actions": [],
         "condition": az_condition(), "condition_version": "2.0"}
    a.update(over)
    return a


def az_doc(*assignments) -> dict:
    return {"container_scope": CONTAINER, "assignments": list(assignments or [az_writer()])}


def az_eval(doc, writers=(APRINCIPAL,)):
    return aze.evaluate(doc, overrides_path="state/runtime-overrides.json",
                        audit_prefix="audit/runtime-overrides/", writers=writers)


def test_azure_the_module_assignment_verifies():
    assert az_eval(az_doc()) == {APRINCIPAL: None}


def test_azure_a_whitespace_variant_verifies():
    doc = az_doc(az_writer(condition=" ".join(az_condition().split()).replace("( (", "((")))
    assert az_eval(doc) == {APRINCIPAL: None}


def test_azure_whitespace_inside_a_literal_is_not_ignored():
    doc = az_doc(az_writer(condition=az_condition(path="state/runtime- overrides.json")))
    assert az_eval(doc) == {APRINCIPAL: "condition_not_recognised"}


def test_azure_a_reader_only_assignment_is_not_write():
    doc = az_doc(az_writer(data_actions=[f"{BLOBS}/read"], condition=None))
    assert az_eval(doc) == {APRINCIPAL: None}


def test_azure_no_assignment_is_locked_out():
    assert az_eval(az_doc(az_writer(principal_id=AOTHER))) == {APRINCIPAL: None}


@pytest.mark.parametrize("assignment_scope", [ACCOUNT, f"{SUB}/resourceGroups/rg-example", SUB])
def test_azure_an_unconditioned_inherited_contributor_fails(assignment_scope):
    contributor = az_writer(id="a2", scope=assignment_scope, data_actions=[f"{BLOBS}/*"],
                            condition=None, condition_version=None)
    assert az_eval(az_doc(az_writer(), contributor)) == {APRINCIPAL: "unconditioned_assignment"}


def test_azure_an_owner_fails_on_its_authorization_writes():
    owner = az_writer(id="a3", scope=SUB, actions=["*"], data_actions=[],
                      condition=None, condition_version=None)
    assert az_eval(az_doc(az_writer(), owner)) == {APRINCIPAL: "grants_authorization_write"}


def test_azure_an_unconditioned_key_grant_fails():
    keys = az_writer(id="a3", scope=ACCOUNT, data_actions=[], condition=None, condition_version=None,
                     actions=["Microsoft.Storage/storageAccounts/listKeys/action"])
    assert az_eval(az_doc(az_writer(), keys)) == {APRINCIPAL: "unconditioned_assignment"}


@pytest.mark.parametrize("action", [
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Authorization/*/write",
    "Microsoft.Authorization/*",
    "microsoft.authorization/ROLEASSIGNMENTS/Write",
])
def test_azure_an_authorization_write_fails_even_on_the_conditioned_assignment(action):
    """Mutation: drop the Microsoft.Authorization check."""
    doc = az_doc(az_writer(actions=[action]))
    assert az_eval(doc) == {APRINCIPAL: "grants_authorization_write"}


@pytest.mark.parametrize("action", [
    "Microsoft.Storage/storageAccounts/write",
    "Microsoft.Storage/storageAccounts/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/*",
    "Microsoft.Storage/*",
])
def test_azure_a_storage_control_plane_write_fails_at_any_applying_scope(action):
    """Mutation: drop the control-plane check."""
    for where in (CONTAINER, ACCOUNT, SUB):
        grant = az_writer(id="a5", scope=where, actions=[action], data_actions=[],
                          condition=None, condition_version=None)
        assert az_eval(az_doc(az_writer(), grant)) == {APRINCIPAL: "grants_storage_control_plane_write"}


def test_azure_a_contributor_fails_on_the_account_but_not_on_authorization():
    """Contributor excludes the Authorization writes, and still writes the
    storage account."""
    contributor = az_writer(id="a6", scope=SUB, actions=["*"], data_actions=[],
                            not_actions=["Microsoft.Authorization/*/Delete",
                                         "Microsoft.Authorization/*/Write",
                                         "Microsoft.Authorization/elevateAccess/Action"],
                            condition=None, condition_version=None)
    assert az_eval(az_doc(az_writer(), contributor)) == {
        APRINCIPAL: "grants_storage_control_plane_write"}


def test_azure_control_plane_reads_and_excluded_writes_pass():
    reads = az_writer(id="a7", scope=ACCOUNT, data_actions=[], condition=None,
                      actions=["Microsoft.Storage/storageAccounts/read",
                               "Microsoft.Authorization/roleAssignments/read"])
    excluded = az_writer(id="a8", scope=ACCOUNT, data_actions=[], condition=None,
                         actions=["Microsoft.Storage/storageAccounts/blobServices/containers/*"],
                         not_actions=["Microsoft.Storage/storageAccounts/blobServices/containers/write",
                                      "Microsoft.Storage/storageAccounts/blobServices/containers/delete"])
    assert az_eval(az_doc(az_writer(), reads, excluded)) == {APRINCIPAL: None}


def test_azure_an_assignment_on_another_container_does_not_apply():
    other = az_writer(id="a4", scope=f"{ACCOUNT}/blobServices/default/containers/other",
                      data_actions=[f"{BLOBS}/*"], condition=None)
    assert az_eval(az_doc(az_writer(), other)) == {APRINCIPAL: None}


def test_azure_a_condition_missing_a_granted_action_fails():
    doc = az_doc(az_writer(data_actions=MUTATING, condition=az_condition(actions=MUTATING[:-1])))
    assert az_eval(doc) == {APRINCIPAL: "condition_omits_action"}


def test_azure_a_wildcard_role_fails_even_with_the_condition():
    assert az_eval(az_doc(az_writer(data_actions=[f"{BLOBS}/*"]))) == {
        APRINCIPAL: "wildcard_data_action"}


@pytest.mark.parametrize("version", ["1.0", None, ""])
def test_azure_a_condition_of_the_wrong_version_fails(version):
    """Mutation: skip the version check."""
    assert az_eval(az_doc(az_writer(condition_version=version))) == {
        APRINCIPAL: "wrong_condition_version"}


@pytest.mark.parametrize("variant", [
    lambda c: c.replace("\n OR\n", "\n OR true OR\n"),
    lambda c: f"true OR {c}",
    lambda c: c.replace(" StringNotStartsWith 'audit/runtime-overrides/'",
                        " StringNotStartsWith 'audit/elsewhere/'"),
    lambda c: c.replace("\n  AND\n  @Resource", "\n  OR\n  @Resource"),
])
def test_azure_a_condition_off_the_module_shape_fails(variant):
    """Mutation: accept a condition that contains the path clauses."""
    assert az_eval(az_doc(az_writer(condition=variant(az_condition())))) == {
        APRINCIPAL: "condition_not_recognised"}


class _Cred:
    def get_token(self, scope):
        raise PermissionError("no token")


def test_azure_an_unreadable_policy_is_every_identitys_reason():
    store = _Store("azure", container="findings", prefix="", account_url=ACCOUNT_URL, credential=_Cred())
    assert verifier.evaluate_store(store, (APRINCIPAL, AOTHER), account_id=ACCOUNT) == {
        APRINCIPAL: "policy_read_failed", AOTHER: "policy_read_failed"}


class _Token:
    token = "fake-token"  # gitleaks:allow


class _TokenCred:
    def get_token(self, scope):
        return _Token()


def test_azure_a_403_from_arm_is_policy_read_denied(monkeypatch):
    import urllib.error

    def forbidden(url, token):
        raise urllib.error.HTTPError(url, 403, "Forbidden", None, None)

    monkeypatch.setattr(aze, "_get", forbidden)
    store = _Store("azure", container="findings", prefix="", account_url=ACCOUNT_URL, credential=_TokenCred())
    assert verifier.evaluate_store(store, (APRINCIPAL,), account_id=ACCOUNT) == {
        APRINCIPAL: "policy_read_denied"}


def test_azure_fetch_pages_and_joins_role_definitions(monkeypatch):
    rid = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/w"
    pages = {"first": {"value": [{"id": "a1", "properties": {
        "principalId": APRINCIPAL, "scope": CONTAINER, "roleDefinitionId": rid,
        "condition": az_condition(), "conditionVersion": "2.0"}}], "nextLink": "second"},
        "second": {"value": [{"id": "a2", "properties": {
            "principalId": APRINCIPAL, "scope": SUB, "roleDefinitionId": rid + "c",
            "condition": None, "conditionVersion": None}}]}}
    roles = {rid: [{"dataActions": [f"{BLOBS}/read", *MUTATING[:2]]}],
             rid + "c": [{"dataActions": [f"{BLOBS}/*"]}]}

    def get(url, token):
        if "roleAssignments" in url:
            return pages["first"]
        if url == "second":
            return pages["second"]
        name = url.split("?")[0].rsplit("/", 1)[-1]
        assert url.startswith(f"{aze._ARM}{ACCOUNT}/providers/Microsoft.Authorization/roleDefinitions/")
        return {"properties": {"permissions": roles[f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{name}"]}}

    monkeypatch.setattr(aze, "_get", get)
    store = _Store("azure", container="findings", prefix="", account_url=ACCOUNT_URL, credential=_TokenCred())
    doc = aze.fetch(store, account_id=ACCOUNT, writers=(APRINCIPAL,))
    assert doc["container_scope"] == CONTAINER and len(doc["assignments"]) == 2
    assert verifier.evaluate_store(store, (APRINCIPAL,), account_id=ACCOUNT) == {
        APRINCIPAL: "unconditioned_assignment"}


def test_s3_a_deny_naming_the_role_as_principal_verifies():
    doc = s3_policy()
    for d in doc["Statement"][1:]:
        d["Principal"] = {"AWS": [WRITER]}
        del d["Condition"]
    assert s3_eval(doc) == {WRITER: None}
    for d in doc["Statement"][1:]:
        d["Condition"] = {"Bool": {"aws:SecureTransport": "false"}}
    assert s3_eval(doc) == {WRITER: "no_deny_for_writer"}


@pytest.mark.parametrize("public", ["allUsers", "allAuthenticatedUsers"])
def test_gcs_a_public_write_binding_counts_against_every_writer(public):
    doc = gcs_policy()
    doc["bindings"].append({"role": "roles/storage.objectCreator", "members": [public]})
    assert gcs_eval(doc) == {GWRITER: "unconditioned_binding"}


@pytest.mark.parametrize("attestation", [None, "", "   "])
def test_gcs_a_clean_bucket_check_is_not_verified_without_the_audit_attestation(
        monkeypatch, attestation):
    """A bucket's IAM policy omits inherited and group grants, so a writer
    the bucket check passes could still write through one of them."""
    monkeypatch.setattr(gcse, "role_permissions", lambda store, roles: {r: GCS_ROLES[r] for r in roles})
    if attestation is None:
        monkeypatch.delenv(verifier.ENV_GCS_INHERITED_AUDITED_BY, raising=False)
    else:
        monkeypatch.setenv(verifier.ENV_GCS_INHERITED_AUDITED_BY, attestation)
    store = _Store("gcs", bucket_name=BUCKET, prefix="tenant",
                   _bucket=_GCSBucket(doc=gcs_policy()))
    assert verifier.evaluate_store(store, (GWRITER, GOTHER)) == {
        GWRITER: gcse.REASON_INHERITED_UNCHECKED, GOTHER: "no_binding_for_writer"}


def test_azure_queries_assignments_transitively_and_counts_a_groups(monkeypatch):
    """`principalId eq` returned only assignments naming the writer, so a
    write grant held through a group was never seen."""
    group = "11111111-2222-3333-4444-555555555555"
    rid = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/w"
    urls = []

    def get(url, token):
        urls.append(url)
        if "roleAssignments" in url:
            return {"value": [{"id": "g1", "properties": {
                "principalId": group, "scope": CONTAINER, "roleDefinitionId": rid,
                "condition": None, "conditionVersion": None}}]}
        return {"properties": {"permissions": [{"dataActions": [f"{BLOBS}/*"]}]}}

    monkeypatch.setattr(aze, "_get", get)
    store = _Store("azure", container="findings", prefix="", account_url=ACCOUNT_URL, credential=_TokenCred())
    result = verifier.evaluate_store(store, (APRINCIPAL,), account_id=ACCOUNT)
    assert "assignedTo%28" in urls[0] and "principalId" not in urls[0]
    assert result[APRINCIPAL] is not None
