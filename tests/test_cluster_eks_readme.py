"""deploy/terraform/README.md's `cluster-eks` variables table lists every
variable in the module's variables.tf, in order, with its default.

Each test names the mutation that makes it fail.
"""

from __future__ import annotations

import re
from pathlib import Path

from test_app_ecs import _attr, _blocks

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "deploy" / "terraform" / "README.md"
VARIABLES = ROOT / "deploy" / "terraform" / "modules" / "cluster-eks" / "variables.tf"


def _section() -> str:
    text = README.read_text(encoding="utf-8")
    start = text.index("## Composing `cluster-eks` with `store-s3`")
    return text[start:text.index("\n## ", start + 1)]


def _table() -> list[tuple[str, str]]:
    """(variable, default) for each row of the section's variables table."""
    section = _section()
    table = section[section.index("### Variables"):]
    table = table[:table.index("\n### ")]
    return [(m.group(1), m.group(2)) for m in
            re.finditer(r"^\| `([a-z0-9_]+)` \| (required|`[^`]*`) \|", table, re.M)]


def _variables() -> list[tuple[str, str]]:
    text = VARIABLES.read_text(encoding="utf-8")
    out = []
    for kind, labels, inner in _blocks(text):
        if kind == "variable":
            default = _attr(inner, "default")
            out.append((labels[0], "required" if default is None else f"`{default}`"))
    return out


def test_the_table_lists_every_variable_in_order_with_its_default():
    """Mutation: drop a row, reorder two, or change a default in either file."""
    assert _table() == _variables()


def test_the_table_has_a_meaning_for_every_variable():
    """Mutation: leave a row's last column empty."""
    section = _section()
    rows = re.findall(r"^\| `[a-z0-9_]+` \| [^|]+ \| (.*) \|$", section, re.M)
    assert len(rows) >= len(_variables())
    assert all(r.strip() for r in rows)
