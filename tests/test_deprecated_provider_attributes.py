"""No module or example sets an attribute its provider marks deprecated, and
store-azure sets the storage account's network access with the string
attribute.

The deprecated attributes come from `terraform providers schema -json` in
each module, which reads the providers `terraform init` installed there.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import terraform_render as tr

terraform = shutil.which("terraform")
requires_terraform = pytest.mark.skipif(terraform is None, reason="terraform is not installed")

DIRS = sorted(p for kind in ("modules", "examples") for p in (tr.TERRAFORM / kind).iterdir()
              if p.is_dir() and any(p.glob("*.tf")))

HEADER = re.compile(r'^\s*(resource|data)\s+"(\w+)"\s+"[\w-]+"\s*\{\s*$')
BLOCK = re.compile(r'^\s*(\w+)((?:\s+"[^"]*")*)\s*\{\s*$')
ATTRIBUTE = re.compile(r"^\s*(\w+)\s*=")
BACKEND = re.compile(r'^\s*backend\s+"\w+"\s*\{[^}]*\}\s*$', re.M)
STRING = re.compile(r'"(?:[^"\\]|\\.)*"')


def _deprecated(schema: dict) -> dict[str, set[str]]:
    """Resource or data source type to its deprecated attribute paths, with
    nested blocks joined by dots."""
    found: dict[str, set[str]] = {}

    def walk(kind: str, block: dict, path: tuple[str, ...]) -> None:
        for name, attribute in block.get("attributes", {}).items():
            if attribute.get("deprecated"):
                found.setdefault(kind, set()).add(".".join((*path, name)))
        for name, nested in block.get("block_types", {}).items():
            walk(kind, nested["block"], (*path, name))

    for provider in schema.get("provider_schemas", {}).values():
        for group in ("resource_schemas", "data_source_schemas"):
            for kind, body in provider.get(group, {}).items():
                walk(kind, body["block"], ())
    return found


def _set_attributes(text: str) -> set[tuple[str, str]]:
    """(type, attribute path) for every attribute a resource or data source
    sets, through nested and dynamic blocks. Attributes inside an object or
    map expression are not the resource's own and are left out."""
    found: set[tuple[str, str]] = set()
    kind = None
    stack: list[str] = []
    for raw in text.splitlines():
        if kind is None:
            header = HEADER.match(raw)
            if header:
                kind, stack = header.group(2), []
            continue
        line = STRING.sub('""', raw).split("#", 1)[0].split("//", 1)[0].rstrip()
        opens, closes = line.count("{"), line.count("}")
        block = BLOCK.match(line)
        if block and "=" not in line:
            name = block.group(1)
            if name == "dynamic":
                name = re.match(r'\s*dynamic\s+"([\w-]+)"', raw).group(1)
            stack.append("" if name == "content" and stack and stack[-1] != "=" else name)
            continue
        attribute = ATTRIBUTE.match(line)
        if attribute and "=" not in stack:
            found.add((kind, ".".join([s for s in stack if s] + [attribute.group(1)])))
        for _ in range(opens - closes):
            stack.append("=")
        for _ in range(closes - opens):
            if not stack:
                kind = None
                break
            stack.pop()
    return found


def test_the_parser_follows_nested_and_dynamic_blocks():
    text = (
        'resource "r" "x" {\n'
        '  a = 1\n'
        '  tags = {\n'
        '    b = 2\n'
        '  }\n'
        '  outer {\n'
        '    c = 3\n'
        '  }\n'
        '  dynamic "inner" {\n'
        '    for_each = []\n'
        '    content {\n'
        '      d = 4\n'
        '    }\n'
        '  }\n'
        '}\n'
        'data "s" "y" {\n'
        '  e = "{"\n'
        '}\n'
    )
    assert _set_attributes(text) == {
        ("r", "a"), ("r", "tags"), ("r", "outer.c"), ("r", "inner.for_each"), ("r", "inner.d"),
        ("s", "e"),
    }


@requires_terraform
@pytest.mark.parametrize("directory", DIRS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_no_deprecated_provider_attribute_is_set(directory: Path, tmp_path):
    providers = directory / ".terraform" / "providers"
    tr._require(providers.is_dir(), f"{directory} is not initialised; run terraform init there")
    cwd = directory
    if any(BACKEND.search(f.read_text(encoding="utf-8")) for f in directory.glob("*.tf")):
        # `providers schema` needs an initialised backend. A copy without the
        # backend block, beside a link to the modules it sources, is
        # initialised from the providers already installed.
        cwd = tmp_path / directory.parent.name / directory.name
        cwd.mkdir(parents=True)
        (tmp_path / "modules").symlink_to(tr.TERRAFORM / "modules")
        for f in directory.glob("*.tf"):
            (cwd / f.name).write_text(BACKEND.sub("", f.read_text(encoding="utf-8")), encoding="utf-8")
        subprocess.run([terraform, "init", "-backend=false", "-input=false", f"-plugin-dir={providers}"],
                       cwd=cwd, capture_output=True, text=True, timeout=300, check=True)
    run = subprocess.run([terraform, "providers", "schema", "-json"], cwd=cwd,
                         capture_output=True, text=True, timeout=300, check=True)
    deprecated = _deprecated(json.loads(run.stdout))
    used = set().union(*(_set_attributes(f.read_text(encoding="utf-8"))
                         for f in sorted(directory.glob("*.tf"))))
    assert sorted(f"{k}.{a}" for k, a in used if a in deprecated.get(k, ())) == []


AZURE = {"resource_group_name": "rg", "location": "westeurope", "storage_account_name": "forgdfindings"}


def _account(tmp_path, **variables) -> dict:
    rendered = tr.render_module(tmp_path, "store-azure", {**AZURE, **variables})
    return rendered["azurerm_storage_account.findings"]


@requires_terraform
def test_the_findings_account_takes_public_network_access_by_default(tmp_path):
    assert _account(tmp_path)["public_network_access"] == "Enabled"


@requires_terraform
def test_public_network_access_false_disables_it(tmp_path):
    assert _account(tmp_path, public_network_access=False)["public_network_access"] == "Disabled"
