#!/usr/bin/env python3
"""Report the internal import graph of forgd_verdict, and check its layering.

Reports two things from one pass over the source:

  1. Which top-level packages import which, and through which symbols.
     This is a build-time view and says nothing about runtime calls.

  2. Upward dependencies: a module importing one from a higher layer.

`--check` exits 1 on an upward dependency outside KNOWN_UPWARD, on a
KNOWN_UPWARD entry that no longer occurs, on a file that will not parse,
on an import whose target cannot be resolved, on a top-level module
missing from LAYERS, and on a root with no modules for some layer.

Usage:
    python3 scripts/import_graph.py               # report
    python3 scripts/import_graph.py --mermaid     # a mermaid flowchart
    python3 scripts/import_graph.py --check       # exit 1 on a violation
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections import defaultdict
from pathlib import Path

# The six adapters, in the repo's own numbering.
ADAPTERS = {
    "server": "A1 inference hook",
    "hook": "A2 Claude Code hook",
    "compliance": "A3 compliance scanner",
    "otel": "A4 OTel collector",
    "sink": "A5 outbound sink",
    "managed": "A6 managed agents",
}
SHARED = {
    "core": "scan core",
    "detectors": "detectors",
    "store": "findings store",
    "overrides": "runtime overrides",
    "metadata": "metadata boundary",
    "lockout": "writer lockout probe",
    "lockout_evidence": "writer lockout from cloud IAM",
    "behaviour": "provenance + taint",
    "intake": "intake service",
    "dashboard": "dashboard",
    "connector": "findings connector",
    "entrypoint": "cli, spotcheck (composition roots)",
}

# Layers, lowest first. A module may import its own layer or a lower one.
# Every top-level name under the package root must appear here.
LAYERS = {
    0: ("models", "budget", "normalize", "azure_auth", "applog", "entitlements", "fsmode",
        "orgregistry", "_hookenv", "safehttp", "sealing"),
    1: ("core", "policy", "extract", "cache", "detectors", "overrides_signing",
        "plugins"),
    2: ("store", "behaviour", "lockout", "lockout_evidence", "overrides", "metadata"),
    3: ("server", "hook", "compliance", "otel", "sink", "managed", "intake"),
    4: ("dashboard", "connector", "cli", "spotcheck", "unseal", "testing", "policycheck"),
}
LAYER_OF = {mod: n for n, mods in LAYERS.items() for mod in mods}

# Not graded as sources. As a target the root package is layer 0.
ENTRYPOINTS = {"cli", "spotcheck", "__init__"}
ROOT_PACKAGE = "__init__"

# Upward dependencies `--check` tolerates, keyed on (importing module,
# resolved target). An entry that no longer occurs is a failure.
KNOWN_UPWARD: set[tuple[str, str]] = set()


class Unresolved(Exception):
    """An import whose target could not be determined."""


def package_of(path: Path, root: Path) -> str:
    """Top-level package a module belongs to, for the coupling report."""
    rel = path.relative_to(root)
    if len(rel.parts) > 1:
        return rel.parts[0]
    return "entrypoint" if rel.stem in ENTRYPOINTS else "core"


def layer_key(path: Path, root: Path) -> str:
    """The name this module is graded under for layering.

    Root-level modules keep their own name; `package_of` groups them
    all as `core`.
    """
    rel = path.relative_to(root)
    return rel.parts[0] if len(rel.parts) > 1 else rel.stem


def _exists(root: Path, parts: list[str]) -> bool:
    """Whether a dotted path names a module or package under the root."""
    base = root.joinpath(*parts) if parts else root
    return base.with_suffix(".py").is_file() or (base / "__init__.py").is_file()


def targets(node: ast.stmt, pkg_parts: list[str], root: Path) -> set[str]:
    """Every internal module this import statement reaches, dotted.

    Empty when the statement touches nothing internal. Raises
    `Unresolved` when a target cannot be determined.
    """
    if isinstance(node, ast.Import):
        out = set()
        for alias in node.names:
            if alias.name == "forgd_verdict":
                out.add(ROOT_PACKAGE)
            elif alias.name.startswith("forgd_verdict."):
                out.add(alias.name[len("forgd_verdict.") :])
        return out

    if not isinstance(node, ast.ImportFrom):
        return set()

    if node.level == 0:
        if node.module == "forgd_verdict":
            base: list[str] = []
        elif node.module and node.module.startswith("forgd_verdict."):
            base = node.module[len("forgd_verdict.") :].split(".")
        else:
            return set()
    else:
        # Relative. `level` is the number of leading dots: 1 is the current
        # package, 2 its parent, and so on.
        drop = node.level - 1
        if drop > len(pkg_parts):
            raise Unresolved(f"relative import escapes the package: level {node.level}")
        base = pkg_parts[: len(pkg_parts) - drop] if drop else list(pkg_parts)
        if node.module:
            base = base + node.module.split(".")

    # Each name is a submodule of `base`, or a name defined in `base`
    # itself; the filesystem tells them apart.
    spelled = "." * node.level + (node.module or "")
    out = set()
    for alias in node.names:
        if _exists(root, base + [alias.name]):
            out.add(".".join(base + [alias.name]))
        elif _exists(root, base):
            out.add(".".join(base) if base else ROOT_PACKAGE)
        else:
            raise Unresolved(f"from {spelled} import {alias.name}")
    return out


def head_of(target: str) -> str:
    """The top-level name a dotted target belongs to."""
    return target.split(".")[0] if target else ROOT_PACKAGE


def collect(root: Path):
    """Parse the tree. Returns (edges, upward, ungraded, unparsed, seen)."""
    edges: dict[tuple[str, str], set] = defaultdict(set)
    upward: set[tuple[str, str, str]] = set()
    unparsed: list[str] = []
    seen: set[str] = set()

    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(root).with_suffix("")
        src_pkg = package_of(path, root)
        src_layer = layer_key(path, root)
        seen.add(src_layer)
        pkg_parts = list(rel.parts[:-1])

        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            unparsed.append(f"{rel}: {exc}")
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            try:
                found = targets(node, pkg_parts, root)
            except Unresolved as exc:
                unparsed.append(f"{rel}: {exc}")
                continue

            for target in found:
                head = head_of(target)

                dst_pkg = head if head in ADAPTERS or head in SHARED else "core"
                if dst_pkg != src_pkg:
                    names = [a.name for a in node.names]
                    for name in names:
                        edges[(src_pkg, dst_pkg)].add((str(rel), target, name))

                if src_layer in ENTRYPOINTS:
                    continue
                a = LAYER_OF.get(src_layer)
                b = 0 if head == ROOT_PACKAGE else LAYER_OF.get(head)
                if a is not None and b is not None and b > a:
                    upward.add((str(rel), src_layer, target))

    on_disk = {
        p.stem if p.suffix == ".py" else p.name
        for p in root.iterdir()
        if p.name != "__pycache__" and (p.suffix == ".py" or (p / "__init__.py").is_file())
    }
    ungraded = sorted(on_disk - set(LAYER_OF) - ENTRYPOINTS)
    return edges, upward, ungraded, unparsed, seen


def run_check(root: Path, upward, ungraded, unparsed, seen) -> int:
    """Exit 1 on a violation or on anything that could not be graded."""
    problems = []

    for line in unparsed:
        problems.append(f"could not read an import: {line}")
    for name in ungraded:
        problems.append(f"{name!r} is not in LAYERS; give it a layer before importing it")

    for n, mods in sorted(LAYERS.items()):
        if not (set(mods) & seen):
            problems.append(f"no module found for layer L{n}; is {root} the package root?")

    found = {(src_layer, target) for _, src_layer, target in upward}
    for src_layer, target in sorted(found - KNOWN_UPWARD):
        problems.append(f"NEW upward dependency: {src_layer} -> {target}")
    for src_layer, target in sorted(KNOWN_UPWARD - found):
        problems.append(
            f"{src_layer} -> {target} is fixed; remove it from KNOWN_UPWARD in this script"
        )

    if problems:
        print("\n  FAILED")
        for line in problems:
            print(f"    {line}")
        return 1
    print(f"\n  ok: {len(found)} known, 0 new, 0 ungraded, 0 unreadable")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("root", nargs="?", default="src/forgd_verdict")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="exit 1 on a violation")
    mode.add_argument("--mermaid", action="store_true", help="emit a flowchart")
    args = p.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    edges, upward, ungraded, unparsed, seen = collect(root)
    label = {**ADAPTERS, **SHARED}

    if args.mermaid:
        print("flowchart LR")
        for pkg, name in label.items():
            if any(k[0] == pkg or k[1] == pkg for k in edges):
                print(f'    {pkg}["{name}"]')
        for (a, b), refs in sorted(edges.items()):
            arrow = "==>" if a in ADAPTERS and b in ADAPTERS else "-->"
            print(f"    {a} {arrow}|{len(refs)}| {b}")
        return 0

    print("LAYERING")
    print("========")
    for n, mods in sorted(LAYERS.items()):
        print(f"  L{n}  {', '.join(mods)}")
    print("\n  Upward dependencies")
    if upward:
        for mod, src_layer, target in sorted(upward):
            print(f"    {mod}  ({src_layer} L{LAYER_OF[src_layer]})  ->  {target}")
    else:
        print("    none")
    for line in ungraded:
        print(f"    UNGRADED  {line!r} is not in LAYERS")
    for line in unparsed:
        print(f"    UNREADABLE  {line}")

    if args.check:
        return run_check(root, upward, ungraded, unparsed, seen)

    a2a = {k: v for k, v in edges.items() if k[0] in ADAPTERS and k[1] in ADAPTERS}
    a2s = {k: v for k, v in edges.items() if k[0] in ADAPTERS and k[1] not in ADAPTERS}
    other = {k: v for k, v in edges.items() if k[0] not in ADAPTERS}

    def show(title: str, group: dict) -> None:
        print(f"\n\n{title}")
        print("=" * len(title))
        if not group:
            print("  (none)")
            return
        for (a, b), refs in sorted(group.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print(f"\n  {label.get(a, a)}  ->  {label.get(b, b)}   [{len(refs)} symbol(s)]")
            for src_mod, dst_mod, sym in sorted(refs):
                print(f"      {src_mod:<28} imports {sym:<26} from {dst_mod}")

    show("ADAPTER -> ADAPTER  (what would have to be broken to split one out)", a2a)
    show("ADAPTER -> SHARED   (expected: everything uses the core)", a2s)
    show("SHARED -> anything", other)

    cycles = sorted({tuple(sorted(k)) for k in a2a if (k[1], k[0]) in a2a})
    print("\n\nSUMMARY")
    print("=======")
    print(f"  cross-package edges   {len(edges)}")
    print(f"  adapter -> adapter    {len(a2a)}")
    for (a, b), refs in sorted(a2a.items()):
        print(f"      {a} -> {b}  ({len(refs)})")
    # Two-cycles only.
    for a, b in cycles:
        print(f"  CYCLE                 {a} <-> {b}   (neither moves without the other)")
    core_out = [k for k in edges if k[0] == "core" and k[1] in ADAPTERS]
    print(f"  core -> adapter       {len(core_out)}"
          "   (reported, not enforced: the scan core should not know its adapters)")
    for a, b in sorted(core_out):
        print(f"      VIOLATION {a} -> {b}")
    print(f"  upward deps           {len(upward)}   (--check fails on a new one)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
