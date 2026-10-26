"""Every resource and data source a module plans, rendered with mocked providers.

`render(module_dir, variables, ...)` copies the module's .tf files, runs
`terraform test` with each provider mocked, and returns every resource and
data source in the module by address, with the value terraform computed for
it after a mocked apply: an object, a list under count, a map under
for_each. Nothing reaches a cloud. The value comes back through a failed
assertion's error message, the one place `terraform test` prints an
expression's value.

A mock provider fills every computed attribute with a random string, and the
provider still validates what it receives, so the attributes other resources
read (ARNs, emails, ids) are pinned by `overrides`. Any attribute left
random is found by rendering twice and dropped from both sides of a
comparison by `diff`.

Providers come from the module's own `.terraform/providers`, which
`terraform init` in the module leaves behind; CI's validate step runs it
before the tests.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

terraform = shutil.which("terraform")

ADDRESS = re.compile(r'^(resource|data) "(\w+)" "(\w+)"', re.M)

MISSING = object()


def addresses(module: Path) -> list[tuple[str, str, str]]:
    return [a for f in sorted(module.glob("*.tf")) for a in ADDRESS.findall(f.read_text(encoding="utf-8"))]


def _require(ok: bool, why: str) -> None:
    """Missing in CI is a broken workflow, not a reason to pass; missing
    locally skips."""
    if ok:
        return
    if os.environ.get("CI"):
        raise AssertionError(why)
    pytest.skip(why)


def plugin_dir(module: Path) -> Path:
    """The module's installed providers, on a terraform with mock providers
    and `terraform test -json` (1.7 or later)."""
    out = subprocess.run([terraform, "version", "-json"], capture_output=True, text=True,
                         timeout=60, check=True)
    version = tuple(int(v) for v in json.loads(out.stdout)["terraform_version"].split(".")[:2])
    _require(version >= (1, 7), f"terraform {version} has no mock providers; 1.7 or later renders")
    found = module / ".terraform" / "providers"
    _require(found.is_dir(), f"{found} is missing: run "
             f"`terraform -chdir={module} init -backend=false` to render it")
    return found


def _hcl(value) -> str:
    return json.dumps(value)


def _test_file(module: Path, providers: list[str], mock_data: dict[str, dict],
               overrides: Callable[[str, str, str], dict]) -> str:
    out = []
    for p in providers:
        out.append(f'mock_provider "{p}" {{')
        for kind, defaults in mock_data.items():
            if kind.startswith(p + "_"):
                out.append(f'  mock_data "{kind}" {{\n    defaults = {_hcl(defaults)}\n  }}')
        out.append("}")
    dump = []
    for block, kind, name in addresses(module):
        ref = f"data.{kind}.{name}" if block == "data" else f"{kind}.{name}"
        dump.append(f'    "{ref}" = {ref}')
        values = overrides(block, kind, name)
        if values:
            target = "override_data" if block == "data" else "override_resource"
            out.append(f"{target} {{\n  target = {ref}\n  values = {_hcl(values)}\n}}")
    out.append('run "render" {\n  command = apply')
    out.append("  assert {")
    out.append('    condition     = var.render_never == "fails"')
    # Mocked values only, so a sensitive attribute is safe to print.
    out.append("    error_message = nonsensitive(sensitive(jsonencode({\n" + "\n".join(dump) + "\n    })))")
    out.append("  }\n}")
    return "\n".join(out) + "\n"


def render_once(tmp: Path, module: Path, variables: dict, *, providers: list[str],
                plugins: Path, mock_data: dict[str, dict],
                overrides: Callable[[str, str, str], dict]) -> dict:
    if tmp.exists():
        shutil.rmtree(tmp)
    (tmp / "tests").mkdir(parents=True)
    for f in [*module.glob("*.tf"), *module.glob("*.json")]:
        shutil.copy(f, tmp / f.name)
    (tmp / "render.tf").write_text(
        'variable "render_never" {\n  type    = string\n  default = "never"\n}\n', encoding="utf-8")
    (tmp / "terraform.tfvars.json").write_text(json.dumps(variables), encoding="utf-8")
    (tmp / "tests" / "render.tftest.hcl").write_text(
        _test_file(module, providers, mock_data, overrides), encoding="utf-8")
    init = subprocess.run([terraform, f"-chdir={tmp}", "init", "-input=false", "-no-color",
                           f"-plugin-dir={plugins}"], capture_output=True, text=True, timeout=300)
    assert init.returncode == 0, init.stderr
    run = subprocess.run([terraform, f"-chdir={tmp}", "test", "-json", "-no-color"],
                         capture_output=True, text=True, timeout=300)
    rendered, errors = None, []
    for line in run.stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        diag = event.get("diagnostic") or {}
        if diag.get("summary") == "Test assertion failed" and diag.get("detail"):
            rendered = json.loads(diag["detail"])
        elif diag.get("severity") == "error":
            errors.append(f"{diag.get('summary')}: {diag.get('detail')}")
    assert rendered is not None, "\n".join(errors) or run.stdout[-4000:] + run.stderr[-4000:]
    return rendered


def _noise(a, b, path=()) -> set[tuple]:
    """Paths whose values differ between two renders of the same inputs."""
    if isinstance(a, dict) and isinstance(b, dict) and a.keys() == b.keys():
        return set().union(*(_noise(a[k], b[k], path + (k,)) for k in a)) if a else set()
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return set().union(*(_noise(x, y, path + (i,)) for i, (x, y) in enumerate(zip(a, b, strict=True)))) if a else set()
    return set() if a == b else {path}


def render(tmp: Path, module: Path, variables: dict, **kw) -> tuple[dict, set[tuple]]:
    """The rendering, and the paths in it a mock left random."""
    first = render_once(tmp / "a", module, variables, **kw)
    second = render_once(tmp / "b", module, variables, **kw)
    return first, _noise(first, second)


def _empty(value) -> bool:
    return value in ([], {}, None)


def diff(old: dict, new: dict, noise: set[tuple]) -> list[str]:
    """Every difference between two renderings, outside paths random in both.
    An address only the new rendering has must render as nothing: a count or
    for_each that is empty."""
    found = []

    def walk(a, b, path):
        if path in noise:
            return
        if isinstance(a, dict) and isinstance(b, dict):
            for k in sorted(a.keys() | b.keys(), key=str):
                walk(a.get(k, MISSING), b.get(k, MISSING), path + (k,))
        elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
            for i, (x, y) in enumerate(zip(a, b, strict=True)):
                walk(x, y, path + (i,))
        elif a != b:
            found.append(f"{'.'.join(map(str, path))}: {_short(a)} -> {_short(b)}")

    for address in sorted(old.keys() | new.keys()):
        if address not in old:
            if not _empty(new[address]):
                found.append(f"{address}: new and not empty: {_short(new[address])}")
            continue
        if address not in new:
            found.append(f"{address}: gone")
            continue
        walk(old[address], new[address], (address,))
    return found


def _short(value) -> str:
    return "<absent>" if value is MISSING else json.dumps(value)


# --- the three store modules --------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
BASELINE = Path(__file__).resolve().parent / "pinned" / "store-baseline"
RG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"


def _aws(block: str, kind: str, name: str) -> dict:
    if kind == "aws_s3_bucket":
        return {"arn": "arn:aws:s3:::forgd-findings", "id": "forgd-findings"}
    if kind == "aws_iam_role":
        return {"arn": f"arn:aws:iam::111111111111:role/{name}-role"}
    if kind == "aws_iam_policy":
        return {"arn": f"arn:aws:iam::111111111111:policy/{name}-policy"}
    return {}


def _google(block: str, kind: str, name: str) -> dict:
    if kind == "google_service_account":
        email = f"{name}@p.iam.gserviceaccount.com"
        return {"email": email, "member": f"serviceAccount:{email}",
                "id": f"projects/p/serviceAccounts/{email}", "name": f"projects/p/serviceAccounts/{email}"}
    if kind == "google_storage_project_service_account":
        email = "service-1@gs-project-accounts.iam.gserviceaccount.com"
        return {"email_address": email, "member": f"serviceAccount:{email}", "id": email}
    if kind == "google_project_iam_custom_role":
        return {"id": f"projects/p/roles/{name}", "name": f"projects/p/roles/{name}"}
    return {}


def _azure(block: str, kind: str, name: str) -> dict:
    if kind == "azurerm_storage_account":
        return {"id": f"{RG}/providers/Microsoft.Storage/storageAccounts/forgdfindings"}
    if kind == "azurerm_storage_container":
        return {"id": f"{RG}/providers/Microsoft.Storage/storageAccounts/forgdfindings"
                      "/blobServices/default/containers/findings"}
    if kind == "azurerm_user_assigned_identity":
        digit = {"app": "1", "reader": "2", "control": "3", "control_plane": "5", "alb_controller": "6"}[name]
        return {"id": f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{name}",
                "principal_id": f"{digit * 8}-0000-0000-0000-000000000000",
                "client_id": f"{digit * 8}-1111-1111-1111-111111111111",
                "tenant_id": "00000000-0000-0000-0000-000000000000"}
    if kind == "azurerm_resource_group":
        return {"id": RG}
    if kind == "azurerm_role_definition":
        return {"role_definition_resource_id":
                f"{RG}/providers/Microsoft.Authorization/roleDefinitions/44444444-0000-0000-0000-000000000000"}
    return {}


STORES = {
    "store-s3": {"providers": ["aws"], "overrides": _aws,
                 "mock_data": {"aws_iam_policy_document": {"json": "{}", "minified_json": "{}"}}},
    "store-gcs": {"providers": ["google"], "overrides": _google, "mock_data": {}},
    "store-azure": {"providers": ["azurerm"], "overrides": _azure, "mock_data": {}},
}


# --- the app modules ----------------------------------------------------------

APP_BASELINE = Path(__file__).resolve().parent / "pinned" / "app-baseline"


def _aca(block: str, kind: str, name: str) -> dict:
    if kind == "azurerm_container_app_environment":
        return {"id": f"{RG}/providers/Microsoft.App/managedEnvironments/{name}"}
    if kind == "azurerm_container_app":
        return {"id": f"{RG}/providers/Microsoft.App/containerApps/{name}"}
    return {}


ACCOUNT = "111111111111"
_ECS_ARNS = {
    "aws_iam_role": "arn:aws:iam::{a}:role/{n}",
    "aws_lb": "arn:aws:elasticloadbalancing:us-east-1:{a}:loadbalancer/app/{n}/1",
    "aws_lb_target_group": "arn:aws:elasticloadbalancing:us-east-1:{a}:targetgroup/{n}/1",
    "aws_lb_listener": "arn:aws:elasticloadbalancing:us-east-1:{a}:listener/app/lb/1/{n}",
    "aws_ecs_cluster": "arn:aws:ecs:us-east-1:{a}:cluster/{n}",
    "aws_cloudwatch_log_group": "arn:aws:logs:us-east-1:{a}:log-group:{n}",
    "aws_ecs_task_definition": "arn:aws:ecs:us-east-1:{a}:task-definition/{n}:1",
}


def _ecs(block: str, kind: str, name: str) -> dict:
    arn = _ECS_ARNS.get(kind)
    return {"arn": arn.format(a=ACCOUNT, n=name)} if arn else {}


APPS = {
    "app-aca": {"providers": ["azurerm", "azapi"], "overrides": _aca, "mock_data": {}},
    "app-ecs": {"providers": ["aws"], "overrides": _ecs, "mock_data": {
        "aws_partition": {"partition": "aws", "dns_suffix": "amazonaws.com"},
        "aws_region": {"name": "us-east-1", "region": "us-east-1"},
        "aws_caller_identity": {"account_id": ACCOUNT},
    }},
    "app-cloudrun": {"providers": ["google"], "overrides": _google,
                     "mock_data": {"google_project": {"number": "123456789"}}},
}


# --- the cluster modules ------------------------------------------------------

_EKS_ARNS = {
    "aws_iam_role": "arn:aws:iam::{a}:role/{n}",
    "aws_iam_policy": "arn:aws:iam::{a}:policy/{n}",
    "aws_kms_key": "arn:aws:kms:us-east-1:{a}:key/00000000-0000-0000-0000-000000000000",
    "aws_iam_openid_connect_provider": "arn:aws:iam::{a}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/{n}",
}


def _eks(block: str, kind: str, name: str) -> dict:
    if kind == "aws_launch_template":
        return {"id": "lt-0123456789abcdef0", "latest_version": 1}
    if kind == "aws_eks_cluster":
        return {"arn": f"arn:aws:eks:us-east-1:{ACCOUNT}:cluster/{name}",
                "identity": [{"oidc": [{"issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/0"}]}]}
    arn = _EKS_ARNS.get(kind)
    return {"arn": arn.format(a=ACCOUNT, n=name)} if arn else {}


CLUSTERS = {
    "cluster-eks": {"providers": ["aws"], "overrides": _eks, "mock_data": {
        "aws_partition": {"partition": "aws", "dns_suffix": "amazonaws.com"},
        "aws_region": {"name": "us-east-1", "region": "us-east-1"},
        "aws_caller_identity": {"account_id": ACCOUNT},
        "aws_iam_policy_document": {"json": "{}", "minified_json": "{}"},
    }},
}
MODULES = {**STORES, **APPS, **CLUSTERS}


def module(name: str) -> Path:
    return ROOT / "deploy" / "terraform" / "modules" / name


def baseline(name: str) -> Path:
    return (APP_BASELINE if name in APPS else BASELINE) / name


def render_module(tmp: Path, name: str, variables: dict) -> dict:
    """The current module `name`, rendered once with `variables`."""
    return render_once(tmp, module(name), variables, **MODULES[name],
                       plugins=plugin_dir(module(name)))


def render_edited(tmp: Path, name: str, variables: dict, edits: list[tuple[str, str]]) -> dict:
    """Module `name` with each (now, then) replaced once in its main.tf,
    rendered once with `variables`."""
    src = tmp / "module"
    src.mkdir(parents=True)
    for f in module(name).glob("*.tf"):
        shutil.copy(f, src / f.name)
    main = (src / "main.tf").read_text(encoding="utf-8")
    for now, then in edits:
        assert main.count(now) == 1, now
        main = main.replace(now, then)
    (src / "main.tf").write_text(main, encoding="utf-8")
    return render_once(tmp / "render", src, variables, **MODULES[name],
                       plugins=plugin_dir(module(name)))


def off_versus_baseline(tmp: Path, name: str, variables: dict, current: dict | None = None) -> list[str]:
    """Every difference between the pinned baseline and the current module,
    both given `variables`; the current one also gets `current`."""
    kw = {**MODULES[name], "plugins": plugin_dir(module(name))}
    with ThreadPoolExecutor(2) as pool:
        old = pool.submit(render, tmp / "old", baseline(name), variables, **kw)
        new = pool.submit(render, tmp / "new", module(name), {**variables, **(current or {})}, **kw)
        (old, old_noise), (new, new_noise) = old.result(), new.result()
    return diff(old, new, old_noise & new_noise)


# --- examples/aks, rendered with every module it composes -----------------------

TERRAFORM = ROOT / "deploy" / "terraform"
STACK_EDITS = {("cluster-aks", "main.tf"): [(
    "azurerm_kubernetes_cluster.this.kubelet_identity[0].object_id",
    'try(azurerm_kubernetes_cluster.this.kubelet_identity[0].object_id, "planned")')]}
MODULE_BLOCK = re.compile(r'^module "(\w+)" \{\n(.*?)^\}', re.M | re.S)


def _aks_stack(block: str, kind: str, name: str) -> dict:
    if kind == "azurerm_kubernetes_cluster":
        return {"oidc_issuer_url": "https://issuer.example/", "name": "aks-forgd-verdict",
                "kubelet_identity": [{"object_id": "00000000-0000-0000-0000-000000000009",
                                      "client_id": "", "user_assigned_identity_id": ""}]}
    return _azure(block, kind, name)


def _stack_tree(tmp: Path, source: Path) -> Path:
    """examples/aks and its modules, laid out as in the repository, from
    `source`, a directory laid out the same way; a module `source` does not
    hold comes from the repository. Each module gets a sensitive `render` output holding every resource it
    declares, and the root one per module returning it, because a test's
    assertion cannot read a child module's resources directly. The empty
    backend block is dropped: `terraform test` does not use it, and `init`
    would ask for its settings.

    The kubelet identity is read with `try` in both copies. Terraform 1.9
    applies `override_resource` values only after the plan, and a mock plans
    the computed `kubelet_identity` block as an empty list, so indexing it
    fails before the override is reached."""
    example = source / "examples" / "aks"
    sources = {}
    for m in MODULE_BLOCK.finditer((example / "main.tf").read_text(encoding="utf-8")):
        src = re.search(r'source\s*=\s*"\.\./\.\./modules/([\w-]+)"', m.group(2)).group(1)
        own = source / "modules" / src
        sources[src] = own if own.is_dir() else TERRAFORM / "modules" / src
    root = tmp / "examples" / "aks"
    root.mkdir(parents=True)
    for f in example.glob("*.tf"):
        text = f.read_text(encoding="utf-8")
        (root / f.name).write_text(re.sub(r'^\s*backend "azurerm" \{\}\n', "", text, flags=re.M),
                                   encoding="utf-8")
    for name, src in sources.items():
        dst = tmp / "modules" / name
        dst.mkdir(parents=True)
        for f in src.glob("*.tf"):
            text = f.read_text(encoding="utf-8")
            for now, then in STACK_EDITS.get((name, f.name), ()):
                assert text.count(now) == 1, now
                text = text.replace(now, then)
            (dst / f.name).write_text(text, encoding="utf-8")
        refs = [f"{kind}.{res}" for block, kind, res in addresses(src) if block == "resource"]
        (dst / "render.tf").write_text(
            'output "render" {\n  sensitive = true\n  value = {\n'
            + "".join(f'    "{r}" = {r}\n' for r in refs) + "  }\n}\n", encoding="utf-8")
    (root / "render.tf").write_text(
        'variable "render_never" {\n  type    = string\n  default = "never"\n}\n'
        + "".join(f'output "render_{m.group(1)}" {{\n  sensitive = true\n  value     = module.{m.group(1)}\n}}\n'
                  for m in MODULE_BLOCK.finditer((example / "main.tf").read_text(encoding="utf-8"))),
        encoding="utf-8")
    return root


def _render_stack_once(tmp: Path, source: Path, variables: dict) -> dict:
    root = _stack_tree(tmp, source)
    example = source / "examples" / "aks"
    modules = [m.group(1) for m in MODULE_BLOCK.finditer((example / "main.tf").read_text(encoding="utf-8"))]
    overrides = []
    for m in MODULE_BLOCK.finditer((example / "main.tf").read_text(encoding="utf-8")):
        src = re.search(r'source\s*=\s*"\.\./\.\./modules/([\w-]+)"', m.group(2)).group(1)
        if re.search(r"^\s*count\s*=", m.group(2), re.M):
            continue
        for block, kind, name in addresses(tmp / "modules" / src):
            values = _aks_stack(block, kind, name)
            if values and block == "resource":
                overrides.append(f"override_resource {{\n  target = module.{m.group(1)}.{kind}.{name}\n"
                                 f"  values = {_hcl(values)}\n}}")
    dump = [f'    "module.{m}" = output.render_{m}' for m in modules]
    dump += [f'    "data.{kind}.{name}" = data.{kind}.{name}'
             for block, kind, name in addresses(example) if block == "data"]
    (root / "tests").mkdir()
    (root / "terraform.tfvars.json").write_text(json.dumps(variables), encoding="utf-8")
    (root / "tests" / "render.tftest.hcl").write_text("\n".join([
        'mock_provider "azurerm" {',
        '  mock_data "azurerm_resource_group" {',
        f'    defaults = {_hcl({"location": "uksouth", "id": RG})}',
        "  }",
        "}",
        *overrides,
        'run "render" {\n  command = apply\n  assert {',
        '    condition     = var.render_never == "fails"',
        "    error_message = nonsensitive(sensitive(jsonencode({\n" + "\n".join(dump) + "\n    })))",
        "  }\n}",
    ]) + "\n", encoding="utf-8")
    init = subprocess.run([terraform, f"-chdir={root}", "init", "-input=false", "-no-color",
                           f"-plugin-dir={plugin_dir(TERRAFORM / 'examples' / 'aks')}"],
                          capture_output=True, text=True, timeout=300)
    assert init.returncode == 0, init.stderr
    run = subprocess.run([terraform, f"-chdir={root}", "test", "-json", "-no-color"],
                         capture_output=True, text=True, timeout=300)
    rendered, errors = None, []
    for line in run.stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        diag = event.get("diagnostic") or {}
        if diag.get("summary") == "Test assertion failed" and diag.get("detail"):
            rendered = json.loads(diag["detail"])
        elif diag.get("severity") == "error":
            errors.append(f"{diag.get('summary')}: {diag.get('detail')}")
    if rendered is None:
        raise StackRefused("\n".join(errors) or run.stdout[-4000:] + run.stderr[-4000:])
    return rendered


class StackRefused(AssertionError):
    """Terraform refused the stack's configuration; the message is its errors."""


def render_aks_stack_once(tmp: Path, variables: dict, *, source: Path = TERRAFORM) -> dict:
    """examples/aks rendered once with `variables`, every module's resources
    under `module.<name>`. `source` is laid out like deploy/terraform and
    holds examples/aks and any modules to use in place of the repository's.
    Raises StackRefused with terraform's errors when it rejects the inputs."""
    return _render_stack_once(tmp, source, variables)


def at_commit(tmp: Path, name: str, commit: str) -> Path:
    """Module `name` as it was at `commit`, extracted under `tmp`. Skips
    where the commit is not in this repository's history."""
    if subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=ROOT).returncode:
        pytest.skip(f"{commit} is not in this repository's history")
    import tarfile
    archive = subprocess.run(["git", "archive", commit, f"deploy/terraform/modules/{name}"],
                             cwd=ROOT, capture_output=True, check=True).stdout
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "module.tar").write_bytes(archive)
    with tarfile.open(tmp / "module.tar") as t:
        t.extractall(tmp, filter="data")
    return tmp / "deploy" / "terraform" / "modules" / name


def versus_commit(tmp: Path, name: str, variables: dict, commit: str) -> list[str]:
    """Every difference between module `name` at `commit` and now, both
    given `variables`."""
    kw = {**MODULES[name], "plugins": plugin_dir(module(name))}
    source = at_commit(tmp / "src", name, commit)
    with ThreadPoolExecutor(2) as pool:
        old = pool.submit(render, tmp / "old", source, variables, **kw)
        new = pool.submit(render, tmp / "new", module(name), variables, **kw)
        (old, old_noise), (new, new_noise) = old.result(), new.result()
    return diff(old, new, old_noise & new_noise)


def render_aks_stack(tmp: Path, variables: dict, **kw) -> tuple[dict, set[tuple]]:
    """The rendering, twice, and the paths in it a mock left random."""
    first = render_aks_stack_once(tmp / "a", variables, **kw)
    second = render_aks_stack_once(tmp / "b", variables, **kw)
    return first, _noise(first, second)
