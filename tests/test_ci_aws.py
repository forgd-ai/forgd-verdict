"""The ci-aws module: the CD role can roll a release and do nothing else.

Parsed from the .tf source, because nothing here may call AWS and a plan
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
from test_app_ecs import _attr, _blocks, _bracket, _walk

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "deploy" / "terraform" / "modules" / "ci-aws"
MAIN = MODULE / "main.tf"
VARIABLES = MODULE / "variables.tf"
APP_ECS_OUTPUTS = ROOT / "deploy" / "terraform" / "modules" / "app-ecs" / "outputs.tf"
DEPLOY_SCRIPT = ROOT / "scripts" / "deploy_aws.sh"

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

# Neither action supports a resource ARN, so "*" is the only way to grant it.
UNSCOPABLE = {"ecr:GetAuthorizationToken", "ecs:DescribeTaskDefinition"}

# An action no CD role needs: anything that makes, removes or attaches
# infrastructure, runs a task, or touches IAM beyond passing a role.
FORBIDDEN = re.compile(r"^[a-z0-9-]+:(Create|Delete|Put|Run|Attach)|^iam:(?!PassRole$)|\*")
ALLOWED_DESPITE_PATTERN = {"ecr:PutImage"}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _named(path: Path, kind: str, type_: str) -> dict[str, str]:
    return {labels[1]: inner for k, labels, inner in _blocks(_text(path))
            if k == kind and labels[0] == type_}


def _strings(expr: str) -> list[str]:
    return re.findall(r'"([^"]*)"', expr)


def _statements(document: str) -> dict[str, dict]:
    """sid -> {actions, resources, conditions, gate} for each statement of
    the named aws_iam_policy_document, static or dynamic."""
    body = _named(MAIN, "data", "aws_iam_policy_document")[document]
    found = []
    for k, labels, inner in _blocks(body):
        if k == "statement":
            found.append((inner, None))
        elif k == "dynamic" and labels == ["statement"]:
            (content,) = [c for ck, _, c in _blocks(inner) if ck == "content"]
            found.append((content, _attr(inner, "for_each")))
    assert found, document
    out = {}
    for inner, gate in found:
        sid = _attr(inner, "sid")
        sid = sid.strip('"') if sid else f"#{len(out)}"
        assert sid not in out, sid
        assert _attr(inner, "effect") in (None, '"Allow"'), sid
        assert "not_actions" not in inner and "not_resources" not in inner, sid
        out[sid] = {
            "actions": _strings(_bracket(inner, "actions")),
            "resources": _attr(inner, "resources"),
            "conditions": [(_attr(c, "test").strip('"'), _attr(c, "variable").strip('"'), _values(c))
                           for c in _walk(inner, "condition")],
            "gate": gate,
            "body": inner,
        }
    return out


def _values(condition: str) -> list[str]:
    """A condition's values: the strings of a literal list, or the one
    expression that supplies them."""
    if re.search(r"\bvalues\s*=\s*\[", condition):
        return _strings(_bracket(condition, "values"))
    return [_attr(condition, "values")]


def _all_actions() -> list[str]:
    """Every "service:Action" string anywhere in main.tf's policy documents."""
    docs = _named(MAIN, "data", "aws_iam_policy_document")
    return [a for body in docs.values() for a in re.findall(r'"([a-z0-9-]+:[A-Za-z*]+)"', body)
            if not a.startswith(("ecs:CreateAction", "iam:PassedToService"))]


def _locals() -> dict[str, str]:
    body = next(inner for k, _, inner in _blocks(_text(MAIN)) if k == "locals")
    starts = list(re.finditer(r"^  (\w+)\s*=", body, re.M))
    return {m.group(1): body[m.end():(starts[i + 1].start() if i + 1 < len(starts) else len(body))].strip()
            for i, m in enumerate(starts)}


# --- the shape of the module ---------------------------------------------

def test_the_module_is_exactly_main_variables_and_outputs():
    """Every check here reads main.tf. A resource in a fourth file would
    escape all of them."""
    files = sorted(p.name for p in MODULE.iterdir() if p.is_file() and not p.name.startswith("."))
    assert files == ["main.tf", "outputs.tf", "variables.tf"], files


def test_the_role_has_one_inline_policy_and_nothing_attached():
    text = _text(MAIN)
    policies = _named(MAIN, "resource", "aws_iam_role_policy")
    assert list(policies) == ["deploy"], sorted(policies)
    assert _attr(policies["deploy"], "role") == "aws_iam_role.deploy.id"
    assert _attr(policies["deploy"], "policy") == "data.aws_iam_policy_document.deploy.json"
    assert list(_named(MAIN, "resource", "aws_iam_role")) == ["deploy"]
    assert "aws_iam_role_policy_attachment" not in text
    assert "aws_iam_policy\"" not in text
    assert "managed_policy_arns" not in text and "inline_policy" not in text


# --- what the role may do ------------------------------------------------

def test_every_pass_role_names_the_service_it_passes_to():
    statements = _statements("deploy")
    passing = {sid: s for sid, s in statements.items() if "iam:PassRole" in s["actions"]}
    assert sorted(passing) == ["PassSchedulerRole", "PassTaskRoles"], sorted(passing)
    for sid, s in passing.items():
        assert s["actions"] == ["iam:PassRole"], sid
        services = [(t, v) for t, v, values in s["conditions"] if v == "iam:PassedToService"]
        assert services == [("StringEquals", "iam:PassedToService")], (sid, s["conditions"])
        (values,) = [values for _, v, values in s["conditions"] if v == "iam:PassedToService"]
        assert len(values) == 1 and values[0].endswith(".amazonaws.com"), (sid, values)
        assert '"*"' not in s["resources"], sid
    assert dict((sid, s["conditions"][0][2]) for sid, s in passing.items()) == {
        "PassTaskRoles": ["ecs-tasks.amazonaws.com"],
        "PassSchedulerRole": ["scheduler.amazonaws.com"],
    }


def test_only_the_unscopable_actions_have_a_wildcard_resource():
    statements = _statements("deploy")
    wild = {sid: s for sid, s in statements.items() if "*" in s["resources"]}
    assert sorted(a for s in wild.values() for a in s["actions"]) == sorted(UNSCOPABLE), wild
    for sid, s in wild.items():
        assert s["resources"] == '["*"]', sid
        assert len(s["actions"]) == 1, sid

    # Everything else names a resource from an input.
    for sid, s in statements.items():
        if sid in wild:
            continue
        assert re.fullmatch(r"\[?(var|local|statement\.value)\.[\w.]+\]?", s["resources"]), (sid, s["resources"])


def test_no_action_creates_deletes_attaches_or_widens():
    actions = _all_actions()
    assert "ecr:PutImage" in actions and "ecs:UpdateService" in actions, actions
    bad = [a for a in actions if FORBIDDEN.search(a) and a not in ALLOWED_DESPITE_PATTERN]
    assert bad == [], bad


def test_the_role_can_make_every_call_the_script_makes():
    """The other direction: a permission missing here is a release that
    fails at that step."""
    granted = set(_all_actions())
    assert granted == {
        "sts:AssumeRoleWithWebIdentity",
        "ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage",
        "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage",
        "ecs:DescribeTaskDefinition", "ecs:RegisterTaskDefinition", "ecs:TagResource",
        "ecs:DescribeServices", "ecs:UpdateService",
        "iam:PassRole",
        "scheduler:GetSchedule", "scheduler:UpdateSchedule",
        "eks:DescribeCluster",
    }, sorted(granted)
    script = _text(DEPLOY_SCRIPT)
    for call in ("aws ecr get-login-password", "aws ecs describe-task-definition",
                 "aws ecs register-task-definition", "aws ecs update-service", "aws ecs describe-services",
                 "aws ecs wait services-stable", "aws scheduler get-schedule",
                 "aws scheduler update-schedule", "aws eks update-kubeconfig"):
        assert call in script, call
    # And no AWS call the list above does not cover.
    calls = set(re.findall(r"\baws ([a-z0-9-]+ [a-z-]+)", script))
    assert calls == {"ecr get-login-password", "ecs describe-task-definition", "ecs register-task-definition",
                     "ecs update-service", "ecs describe-services", "ecs wait", "scheduler get-schedule",
                     "scheduler update-schedule", "eks update-kubeconfig"}, sorted(calls)


def test_tagging_is_only_as_part_of_a_registration():
    s = _statements("deploy")["EcsTagOnRegister"]
    assert s["actions"] == ["ecs:TagResource"]
    assert s["conditions"] == [("StringEquals", "ecs:CreateAction", ["RegisterTaskDefinition"])]
    assert s["resources"] == _statements("deploy")["EcsRegisterTaskDefinitions"]["resources"]


def test_ecs_and_eks_grants_exist_only_when_their_inputs_do():
    for sid, s in _statements("deploy").items():
        if sid.startswith("Ecr"):
            assert s["gate"] is None, sid
        elif sid == "EksKubeconfig":
            assert s["gate"] == "var.eks == null ? [] : [var.eks]", sid
        else:
            assert s["gate"] == "var.ecs == null ? [] : [var.ecs]", sid


# --- who may assume it ---------------------------------------------------

def test_the_trust_admits_one_environment_of_one_repository():
    (trust,) = _statements("trust").values()
    assert trust["actions"] == ["sts:AssumeRoleWithWebIdentity"]
    principals = _walk(trust["body"], "principals")
    assert len(principals) == 1
    assert _attr(principals[0], "type") == '"Federated"'
    assert _attr(principals[0], "identifiers") == "[local.oidc_provider_arn]"
    assert sorted(trust["conditions"]) == [
        ("StringEquals", "${local.oidc_host}:aud", ["sts.amazonaws.com"]),
        ("StringEquals", "${local.oidc_host}:sub", ["local.subjects"]),
    ], trust["conditions"]

    locals_ = _locals()
    assert locals_["oidc_host"] == '"token.actions.githubusercontent.com"'
    # The short form, and the immutable-identifier form when the ids are
    # given. Both name the one environment.
    subjects = _strings(locals_["subjects"])
    assert subjects == [
        "repo:${var.github_org}/${var.github_repo}:environment:${var.github_environment}",
        ("repo:${var.github_org}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}"
         ":environment:${var.github_environment}"),
    ], subjects
    assert "var.github_owner_id == null ? [] :" in locals_["subjects"]
    role = _named(MAIN, "resource", "aws_iam_role")["deploy"]
    assert _attr(role, "assume_role_policy") == "data.aws_iam_policy_document.trust.json"


def test_the_repository_and_environment_have_no_default():
    variables = {labels[0]: inner for k, labels, inner in _blocks(_text(VARIABLES)) if k == "variable"}
    for name in ("github_org", "github_repo", "github_environment", "ecr_repository_arn"):
        assert name in variables, name
        assert _attr(variables[name], "default") is None, name


def test_exactly_one_oidc_provider_source_is_required():
    role = _named(MAIN, "resource", "aws_iam_role")["deploy"]
    conditions = [" ".join(_attr(p, "condition").split()) for p in _walk(role, "precondition")]
    assert "var.create_oidc_provider != (var.oidc_provider_arn != null)" in conditions, conditions
    assert "(var.github_owner_id == null) == (var.github_repo_id == null)" in conditions, conditions
    assert _attr(_named(MAIN, "resource", "aws_iam_openid_connect_provider")["github"], "count") \
        == "var.create_oidc_provider ? 1 : 0"


# --- eks -----------------------------------------------------------------

def test_the_eks_access_entry_is_edit_in_the_release_namespace_only():
    entries = _named(MAIN, "resource", "aws_eks_access_entry")
    associations = _named(MAIN, "resource", "aws_eks_access_policy_association")
    assert list(entries) == ["deploy"] and list(associations) == ["deploy"]
    assert _attr(entries["deploy"], "principal_arn") == "aws_iam_role.deploy.arn"
    a = associations["deploy"]
    assert _attr(a, "policy_arn").endswith(':cluster-access-policy/AmazonEKSEditPolicy"')
    (scope,) = _walk(a, "access_scope")
    assert _attr(scope, "type") == '"namespace"'
    assert _attr(scope, "namespaces") == "[var.eks.namespace]"
    for body in (entries["deploy"], a):
        assert _attr(body, "count") == "var.eks == null ? 0 : 1"


# --- what the module is fed, and what it tells the workflow --------------

def test_app_ecs_ci_release_has_the_shape_of_the_ecs_input():
    variable = next(inner for k, labels, inner in _blocks(_text(VARIABLES))
                    if k == "variable" and labels == ["ecs"])
    wanted = set(re.findall(r"^\s*(\w+)\s*=\s*(?:list\(string\)|string)", variable, re.M))
    output = next(inner for k, labels, inner in _blocks(_text(APP_ECS_OUTPUTS))
                  if k == "output" and labels == ["ci_release"])
    value = output[output.index("value"):]
    given = set(re.findall(r"^    (\w+)\s*=", value, re.M))
    assert wanted and wanted == given, (wanted, given)


def test_the_repository_variables_are_the_ones_the_script_reads():
    listed = set(_strings(_locals()["repository_variables"]))
    script = _text(DEPLOY_SCRIPT)
    read = set(re.findall(r"\b((?:AWS|FORGD)_[A-Z_]+)\b", script)) - {"FORGD_BUILD_COMMIT"}  # a build arg
    assert read, "parsed nothing from the script"
    # The two the workflow itself needs, for configure-aws-credentials.
    assert listed - read == {"AWS_DEPLOY_ROLE_ARN", "AWS_REGION"}
    assert read - listed == set(), sorted(read - listed)


# --- validations, checked by terraform ----------------------------------

REQUIRED = {"github_org": "acme", "github_repo": "forgd-verdict", "github_environment": "acme-cd",
            "ecr_repository_arn": "arn:aws:ecr:eu-west-2:123456789012:repository/forgd-verdict"}
ECS = {
    "service_arns": ["arn:aws:ecs:eu-west-2:123456789012:service/fv/fv-verdict"],
    "task_definition_arns": ["arn:aws:ecs:eu-west-2:123456789012:task-definition/fv-verdict:*"],
    "task_role_arns": ["arn:aws:iam::123456789012:role/fv-verdict-execution"],
    "schedule_arn": "arn:aws:scheduler:eu-west-2:123456789012:schedule/default/fv-ingest",
    "schedule_role_arn": "arn:aws:iam::123456789012:role/fv-ingest-scheduler",
}


def _apply(tmp_path: Path, **variables) -> subprocess.CompletedProcess:
    """`terraform apply` of variables.tf alone, which runs the variables'
    validations and needs no provider."""
    shutil.copy(VARIABLES, tmp_path / "variables.tf")
    (tmp_path / "terraform.tfvars.json").write_text(json.dumps({**REQUIRED, **variables}), encoding="utf-8")
    out = subprocess.run([terraform, f"-chdir={tmp_path}", "init", "-input=false", "-no-color"],
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    return subprocess.run([terraform, f"-chdir={tmp_path}", "apply", "-auto-approve", "-input=false", "-no-color"],
                          capture_output=True, text=True, timeout=120)


@requires_terraform
def test_a_well_formed_ecs_input_is_accepted(tmp_path):
    out = _apply(tmp_path, ecs=ECS)
    assert out.returncode == 0, out.stderr


@requires_terraform
@pytest.mark.parametrize("field,value", [
    ("service_arns", ["arn:aws:ecs:eu-west-2:123456789012:service/fv/*"]),
    ("task_role_arns", ["arn:aws:iam::123456789012:role/*"]),
    ("schedule_arn", "arn:aws:scheduler:eu-west-2:123456789012:schedule/default/*"),
    ("task_definition_arns", ["arn:aws:ecs:eu-west-2:123456789012:task-definition/*"]),
    ("task_definition_arns", ["arn:aws:ecs:eu-west-2:123456789012:task-definition/fv-verdict:3"]),
])
def test_a_wildcard_or_malformed_ecs_arn_is_refused(tmp_path, field, value):
    out = _apply(tmp_path, ecs={**ECS, field: value})
    assert out.returncode != 0
    assert "ecs" in out.stderr


@requires_terraform
@pytest.mark.parametrize("arn", ["arn:aws:ecr:eu-west-2:123456789012:repository/*",
                                 "arn:aws:ecr:eu-west-2:123456789012:repository/forgd-*"])
def test_a_wildcard_repository_is_refused(tmp_path, arn):
    out = _apply(tmp_path, ecr_repository_arn=arn)
    assert out.returncode != 0
    assert "ecr_repository_arn" in out.stderr


@requires_terraform
@pytest.mark.parametrize("env", ["*", "prod*", "a:b", 'a"||true||"', "a\\", "a b", "a\nb", "", "a" * 256])
def test_the_environment_cannot_be_a_pattern(tmp_path, env):
    out = _apply(tmp_path, github_environment=env)
    assert out.returncode != 0
    assert "github_environment" in out.stderr


@requires_terraform
@pytest.mark.parametrize("name,value", [
    ("github_org", "acme-"), ("github_org", "a" * 40), ("github_org", "ac--me"),
    ("github_repo", "."), ("github_repo", ".."), ("github_repo", "a" * 101),
    ("github_repo", "a/b"),
])
def test_the_owner_and_repository_must_be_github_names(tmp_path, name, value):
    out = _apply(tmp_path, **{name: value})
    assert out.returncode != 0
    assert name in out.stderr


@requires_terraform
@pytest.mark.parametrize("name,value", [
    ("github_org", "a"), ("github_org", "acme-corp"), ("github_org", "a" * 39),
    ("github_repo", "forgd-verdict"), ("github_repo", ".github"), ("github_repo", "a" * 100),
    ("github_environment", "Prod.eu_1"),
])
def test_github_names_are_accepted(tmp_path, name, value):
    out = _apply(tmp_path, **{name: value})
    assert out.returncode == 0, out.stderr
