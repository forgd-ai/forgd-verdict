"""The Terraform modules and example root stacks, parsed from their .tf source.

app-aca's probes and auth provider, store-s3's rule that nothing the app
runs as may delete a finding, and the example roots' regions, defaults and
variable declarations.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TERRAFORM = ROOT / "deploy" / "terraform"

# Keyed on main.tf rather than on the directory: `terraform init` leaves a
# `.terraform` cache behind, so a stack removed from git but init'd locally
# stays a directory and the whole suite then fails on files that are gone.
ROOT_STACKS = sorted(d.name for d in TERRAFORM.glob("examples/*") if (d / "main.tf").is_file())


def _root(stack: str) -> Path:
    return TERRAFORM / "examples" / stack


# --- store-s3: nothing the app runs as may delete a finding ---------------

APP_ACA = TERRAFORM / "modules" / "app-aca" / "main.tf"


def _aca_containers() -> dict[str, str]:
    """Container App or job name -> the body of its template's container."""
    out = {}
    for kind, labels, body in _blocks(APP_ACA.read_text(encoding="utf-8")):
        if kind != "resource" or labels[0] not in (
                "azurerm_container_app", "azurerm_container_app_job"):
            continue
        template = next(inner for k, _, inner in _blocks(body) if k == "template")
        out[labels[1]] = next(inner for k, _, inner in _blocks(template) if k == "container")
    assert {"verdict", "collector", "dashboard", "ingest"} <= set(out), sorted(out)
    return out


def _aca_ingress_port(app: str) -> int:
    for kind, labels, body in _blocks(APP_ACA.read_text(encoding="utf-8")):
        if kind == "resource" and labels[1] == app:
            ingress = next(inner for k, _, inner in _blocks(body) if k == "ingress")
            return int(re.search(r"^\s*target_port\s*=\s*(\d+)", ingress, re.M).group(1))
    raise AssertionError(app)


@pytest.mark.parametrize("app", ["verdict", "collector"])
def test_the_daemon_apps_restart_on_livez(app):
    """/livez fails when the app's gitleaksd stops answering; a restart
    brings the daemon back with it. Same timings as the chart."""
    probes = [inner for k, _, inner in _blocks(_aca_containers()[app])
              if k == "liveness_probe"]
    assert len(probes) == 1, probes
    attrs = dict(re.findall(r'^\s*(\w+)\s*=\s*"?([^"\n]+?)"?\s*$', probes[0], re.M))
    assert attrs["transport"] == "HTTP"
    assert attrs["path"] == "/livez"
    assert int(attrs["port"]) == _aca_ingress_port(app)
    assert (int(attrs["timeout"]), int(attrs["interval_seconds"]),
            int(attrs["failure_count_threshold"])) == (5, 10, 6)


@pytest.mark.parametrize("app", ["verdict", "collector"])
def test_the_liveness_probe_waits_out_the_daemon_compile(app):
    """The entrypoint waits up to 60 s for gitleaksd's socket. azurerm caps
    initial_delay at 60 and `terraform validate` does not enforce the cap,
    so a larger value fails only at apply."""
    probe = next(inner for k, _, inner in _blocks(_aca_containers()[app])
                 if k == "liveness_probe")
    delay = int(re.search(r"^\s*initial_delay\s*=\s*(\d+)", probe, re.M).group(1))
    assert delay == 60, delay


def test_the_dashboard_and_ingest_have_no_liveness_probe():
    """No daemon runs in either, and ingest is a job that exits."""
    containers = _aca_containers()
    for app in ("dashboard", "ingest"):
        assert "liveness_probe" not in containers[app], app


STORE_S3 = TERRAFORM / "modules" / "store-s3" / "main.tf"
_DELETES = ("s3:DeleteObject", "s3:DeleteObjectVersion")


def _close(text: str, i: int, open_: str, close: str) -> int:
    """Index just past the bracket matching text[i], skipping quoted strings
    (which hold `${...}`) and comments."""
    depth, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "#" or text.startswith("//", i):
            i = text.index("\n", i)
        elif c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise AssertionError(f"unbalanced {open_} in {STORE_S3}")


def _blocks(body: str) -> list[tuple[str, list[str], str]]:
    """The blocks directly inside `body`: (type, labels, inner text)."""
    out, i = [], 0
    header = re.compile(r'(\w+)((?:\s+"[^"]*")*)\s*\{')
    while True:
        m = header.search(body, i)
        if m is None:
            return out
        end = _close(body, m.end() - 1, "{", "}")
        out.append((m.group(1), re.findall(r'"([^"]*)"', m.group(2)), body[m.end():end - 1]))
        i = end


def _top_level(body: str) -> str:
    """`body` with every nested block removed, leaving its own attributes."""
    for _, _, inner in _blocks(body):
        body = body.replace("{" + inner + "}", "{}", 1)
    return body


def _list_attr(body: str, name: str) -> list[str]:
    """Items of a list attribute: string contents, or a bare reference such
    as `aws_iam_role.writer.arn` as written. A `concat(...)` of lists and
    splats yields the items of each, an indexed or splat reference as written
    (`aws_iam_role.control[*].arn`)."""
    flat = _top_level(body)
    m = re.search(rf"^\s*{name}\s*=\s*(\[|concat\()", flat, re.M)
    if m is None:
        return []
    if m.group(1) == "[":
        inner = flat[m.end():_close(flat, m.end() - 1, "[", "]") - 1]
    else:
        inner = flat[m.end():_close(flat, m.end() - 1, "(", ")") - 1]
    return [q or ref for q, ref in re.findall(r'"([^"]*)"|([A-Za-z_][\w.]*(?:\[(?:\*|\d+)\]\.\w+)?)', inner)]


def _statements(doc: str) -> list[dict]:
    """Every statement a policy document can render, static or dynamic."""
    out = []
    for kind, labels, inner in _blocks(doc):
        if kind == "dynamic" and labels == ["statement"]:
            inner = next(b for k, _, b in _blocks(inner) if k == "content")
        elif kind != "statement":
            continue
        effect = re.search(r'^\s*effect\s*=\s*"(\w+)"', _top_level(inner), re.M)
        out.append({
            "effect": effect.group(1) if effect else "Allow",
            "actions": _list_attr(inner, "actions"),
            "not_actions": _list_attr(inner, "not_actions"),
            "resources": _list_attr(inner, "resources"),
            "principals": [_list_attr(b, "identifiers") for k, _, b in _blocks(inner) if k == "principals"],
            "conditions": [
                (re.search(r'variable\s*=\s*"([^"]+)"', b).group(1), _list_attr(b, "values"))
                for k, _, b in _blocks(inner) if k == "condition"
            ],
        })
    return out


def _policy_documents() -> dict[str, list[dict]]:
    text = STORE_S3.read_text(encoding="utf-8")
    return {
        labels[1]: _statements(inner)
        for kind, labels, inner in _blocks(text)
        if kind == "data" and labels[0] == "aws_iam_policy_document"
    }


def _grants_a_delete(action: str) -> bool:
    # A wildcard counts: `s3:*` or `s3:Delete*` allows a delete as surely as
    # naming it does.
    return any(fnmatch.fnmatchcase(d.lower(), action.lower()) for d in _DELETES) or (
        action.lower().startswith("s3:delete")
    )


def test_no_store_s3_role_policy_grants_a_delete():
    """The store never deletes, so neither role needs to, and a role that
    can is one compromise away from removing the evidence. Only Allow
    statements are checked: the bucket policy's Deny names the same actions
    on purpose."""
    docs = _policy_documents()
    text = STORE_S3.read_text(encoding="utf-8")

    # Every IAM policy the module creates renders one of the documents
    # checked here, and the roles carry nothing else.
    attached = re.findall(r'policy\s*=\s*data\.aws_iam_policy_document\.(\w+)(?:\[0\])?\.json', text)
    assert sorted(attached) == ["bucket", "control", "reader", "writer"], attached
    assert "aws_iam_role_policy\"" not in text and "inline_policy" not in text
    assert "managed_policy_arns" not in text

    for name in ("writer", "reader", "control"):
        allows = [s for s in docs[name] if s["effect"] == "Allow"]
        actions = [a for s in allows for a in s["actions"]]
        # Not vacuous: a parse that found nothing would pass the check below.
        assert ("s3:PutObject" if name == "control" else "s3:GetObject") in actions, (name, docs[name])
        assert all(s["effect"] == "Allow" for s in docs[name]), name
        assert not any(s["not_actions"] for s in allows), name
        granted = [a for a in actions if _grants_a_delete(a)]
        assert not granted, f"{name} policy grants {granted}"

    assert "s3:PutObject" in [a for s in docs["writer"] for a in s["actions"]]
    assert "s3:PutObject" not in [a for s in docs["reader"] for a in s["actions"]]


def test_the_store_s3_module_has_no_policy_the_check_above_cannot_read():
    """The check above parses main.tf's literal action lists. Each way round
    it is refused here: a policy in another file, an attached managed policy
    such as AmazonS3FullAccess, `not_actions`, and actions built from an
    expression, which the parser reads as an empty list."""
    module = STORE_S3.parent
    assert sorted(f.name for f in module.glob("*.tf")) == ["main.tf", "outputs.tf", "variables.tf"]
    for other in ("outputs.tf", "variables.tf"):
        assert not re.search(r'^\s*(resource|data)\s+"', (module / other).read_text(), re.M), other

    text = STORE_S3.read_text(encoding="utf-8")
    assert "not_actions" not in text
    attachments = [inner for kind, labels, inner in _blocks(text)
                   if kind == "resource" and labels[0] == "aws_iam_role_policy_attachment"]
    arns = sorted(re.search(r"policy_arn\s*=\s*(\S+)", a).group(1) for a in attachments)
    assert arns == ["aws_iam_policy.control[0].arn", "aws_iam_policy.reader.arn",
                    "aws_iam_policy.reader.arn", "aws_iam_policy.writer.arn"], arns

    documents = {labels[1]: inner for kind, labels, inner in _blocks(text)
                 if kind == "data" and labels[0] == "aws_iam_policy_document"}
    assert sorted(documents) == ["bucket", "control", "reader", "writer"]
    for name, doc in documents.items():
        for kind, _, inner in _blocks(doc):
            if kind == "dynamic":
                inner = next(b for k, _, b in _blocks(inner) if k == "content")
            elif kind != "statement":
                continue
            assert re.search(r'^\s*actions\s*=\s*\[', _top_level(inner), re.M), (
                f"{name}: a statement whose actions are not a literal list")
            items = _list_attr(inner, "actions")
            assert items and all(":" in a for a in items), (name, items)


def test_the_store_s3_bucket_policy_denies_deletes_to_both_roles():
    """So a policy attached to either role later cannot grant one: an
    explicit deny in the bucket policy wins over any allow. The control
    role, when there is one, is covered too."""
    denies = [s for s in _policy_documents()["bucket"] if s["effect"] == "Deny"]
    roles = {"aws_iam_role.writer.arn", "aws_iam_role.reader.arn", "aws_iam_role.control[*].arn"}
    for action in _DELETES:
        covering = [
            s for s in denies
            if action in s["actions"]
            and any(r.endswith("}/*") for r in s["resources"])
            and ["*"] in s["principals"]
            and any(var == "aws:PrincipalArn" and roles <= set(vals) for var, vals in s["conditions"])
        ]
        assert covering, f"no Deny of {action} on every object for all three roles"


# --- app-aca: the auth provider ---------------------------------------------

def test_healthz_is_excluded_from_the_dashboards_auth_provider():
    """The deploy gate probes /healthz before asserting anything else.

    Behind an auth provider without this exclusion the probe is redirected,
    `verify_deployment.sh` fails `dashboard.health` on a perfectly healthy
    deployment, and the checks that actually matter never run. A dashboard
    that already has the exclusion looks unaffected by the probe only
    because of it.
    """
    module = (ROOT / "deploy" / "terraform" / "modules" / "app-aca" / "main.tf").read_text(
        encoding="utf-8"
    )
    assert 'excludedPaths = ["/healthz"]' in module


def test_only_the_dashboard_gets_an_auth_provider():
    """The verdict server and the collector must never sit behind one:
    Anthropic authenticates with a signature and an OTLP header, so a
    redirect turns every governed prompt or export into a delivery failure
    rather than a deny."""
    module = (ROOT / "deploy" / "terraform" / "modules" / "app-aca" / "main.tf").read_text(
        encoding="utf-8"
    )
    auth_blocks = module.count("Microsoft.App/containerApps/authConfigs")
    assert auth_blocks == 1, f"{auth_blocks} auth configs; exactly one belongs here"
    # And it hangs off the dashboard, not one of the push endpoints.
    idx = module.index("Microsoft.App/containerApps/authConfigs")
    assert "azurerm_container_app.dashboard.id" in module[idx : idx + 400]


# --- the example root stacks --------------------------------------------------

def test_ci_validates_every_terraform_root_and_module():
    """A stack the loop does not name is one whose first plan is its first
    syntax check. The loop once named a stack explicitly and so skipped the
    next one added
    when it was added."""
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    loop = next(ln for ln in ci.splitlines() if ln.strip().startswith("for d in deploy/terraform"))
    assert "modules/*/" in loop, loop
    assert "examples/*/" in loop, loop
    for stack in ROOT_STACKS:
        assert (_root(stack)).is_dir()


def test_the_aks_stack_takes_its_region_from_its_resource_group():
    """A `location` variable is one more thing that can disagree.

    With a default of its own it can name a region other than the group's,
    so an apply builds the findings store in one region inside a group in
    another, and can fail because the cluster's VM size is not offered to
    the subscription in that region.

    A wrong region is not only a failed apply. Findings are written on the
    verdict path, which has a 5,000 ms end-to-end timeout, and a
    cross-region write spends part of that budget for nothing.
    """
    main = (TERRAFORM / "examples" / "aks" / "main.tf").read_text(encoding="utf-8")
    variables = (TERRAFORM / "examples" / "aks" / "variables.tf").read_text(encoding="utf-8")

    assert 'data "azurerm_resource_group" "target"' in main
    assert "data.azurerm_resource_group.target.location" in main
    assert 'variable "location"' not in variables, (
        "examples/aks declares a location variable again; it derives the region "
        "from the resource group so the two cannot disagree"
    )
    assert "var.location" not in main, main


def test_no_root_stack_hardcodes_a_region_the_others_do_not_share():
    """Two halves of one deployment in two regions is a latency bug that
    reads as a slow verdict path, not as a misconfiguration."""

    regions = {}
    for stack in ROOT_STACKS:
        src = (_root(stack) / "variables.tf").read_text(encoding="utf-8")
        m = re.search(
            r'variable "location"\s*\{(.*?)\n\}', src, re.DOTALL
        )
        if not m:
            continue  # derives it, which is stronger
        d = re.search(r'default\s*=\s*"([^"]+)"', m.group(1))
        if d:
            regions[stack] = d.group(1)
    assert len(set(regions.values())) <= 1, regions


def _declared_defaults(path: Path, documented_only: bool = False) -> dict[str, str]:
    """variable name -> default literal, for variables that have one.

    `documented_only` keeps just those whose block carries a `description`.
    That is the line between a default a module DECIDED and one it merely
    left empty: `tags` defaults to {} in every module with nothing to say
    about it, and a root stack setting its own is the point. node_vm_size
    defaults with a page of quota arithmetic attached, and a root stack
    setting its own throws that away.
    """
    src = path.read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for m in re.finditer(r'variable\s+"(\w+)"\s*\{(.*?)\n\}', src, re.DOTALL):
        body = m.group(2)
        d = re.search(r'^\s*default\s*=\s*(.+?)\s*$', body, re.MULTILINE)
        if not d:
            continue
        if documented_only and not re.search(r"^\s*description\s*=", body, re.MULTILINE):
            continue
        out[m.group(1)] = d.group(1).strip()
    return out


def test_no_root_stack_shadows_a_module_default():
    """A default in two places has one copy that silently loses.

    If node_vm_size were declared in both examples/aks and cluster-aks, the
    module's -- the one carrying the quota arithmetic -- would be dead: a
    change there would fix nothing, because the root passes its own default
    down. A `location` variable has the same shape.

    Either the root does not declare it, or the two defaults agree.
    """
    conflicts = {}
    for stack in ROOT_STACKS:
        root_main = (_root(stack) / "main.tf").read_text(encoding="utf-8")
        root_defaults = _declared_defaults(_root(stack) / "variables.tf")

        for mod in re.finditer(
            r'module\s+"\w+"\s*\{(.*?)\n\}', root_main, re.DOTALL
        ):
            body = mod.group(1)
            src = re.search(r'source\s*=\s*"([^"]+)"', body)
            if not src or not src.group(1).startswith(".."):
                continue
            mod_dir = (_root(stack) / src.group(1)).resolve()
            mod_defaults = _declared_defaults(
                mod_dir / "variables.tf", documented_only=True
            )

            # Straight pass-throughs: `x = var.x`.
            for name in re.findall(r"(\w+)\s*=\s*var\.(\w+)\b", body):
                arg, var = name
                if arg != var:
                    continue
                if (
                    var in root_defaults
                    and arg in mod_defaults
                    and root_defaults[var] != mod_defaults[arg]
                ):
                    conflicts[f"{stack}.{var}"] = (
                        root_defaults[var],
                        mod_defaults[arg],
                    )
    assert not conflicts, (
        f"{conflicts} -- each is a default declared twice with different "
        "values; the module's copy is the one carrying the reasoning, and "
        "the root's is the one that wins"
    )


def test_the_aks_example_does_not_declare_node_sizing():
    """Specifically: it must not take these back.

    They belong beside the quota arithmetic that explains them. Two quotas
    apply to a node pool -- the family and the regional total -- and a
    number chosen away from that explanation is a number chosen blind.
    """
    declared = _declared_defaults(TERRAFORM / "examples" / "aks" / "variables.tf")
    for name in ("node_vm_size", "node_count"):
        assert name not in declared, f"examples/aks re-declares {name}"


def test_every_referenced_variable_is_declared():
    """`var.x` with no `variable "x"` block is a dangling reference.

    Terraform catches it, but only at `validate` -- which runs in CI and not
    in pytest, so it is invisible to a local check. A variable removed from
    an example's variables.tf while its main.tf still passes `var.<name>`
    down passes the local suite, which never looks at Terraform, and fails
    CI.

    Static and cheap on purpose: no `terraform init`, no provider download,
    no network. It is the same diagnostic Terraform gives --

      An input variable with the name "node_vm_size" has not been declared.

    -- available before a push.
    """
    dangling = {}
    for d in [_root(s) for s in ROOT_STACKS] + sorted(TERRAFORM.glob("modules/*")):
        if not d.is_dir():
            continue
        declared = set()
        referenced: dict[str, str] = {}
        for tf in d.glob("*.tf"):
            src = tf.read_text(encoding="utf-8")
            declared |= set(re.findall(r'variable\s+"(\w+)"', src))
            for name in re.findall(r"\bvar\.(\w+)", src):
                referenced.setdefault(name, tf.name)
        gap = {n: f for n, f in referenced.items() if n not in declared}
        if gap:
            dangling[d.name] = gap
    assert not dangling, (
        f"{dangling} reference variables their stack does not declare; "
        "`terraform validate` fails on this and pytest did not"
    )
