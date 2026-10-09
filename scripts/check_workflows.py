#!/usr/bin/env python3
"""Reject workflow YAML that GitHub Actions would refuse.

`yaml.safe_load` accepts duplicate mapping keys and keeps the last one.
GitHub does not: it fails the run at startup with no jobs and no log, and
shows the file path instead of the workflow's name. Two `env:` blocks on
one step are valid to PyYAML and invalid to Actions, so a check built on
`safe_load` passes a workflow that never runs.
"""

from __future__ import annotations

import pathlib
import sys

import yaml


class _Strict(yaml.SafeLoader):
    pass


def _no_duplicate_keys(loader: yaml.Loader, node: yaml.MappingNode, deep: bool = False):
    seen: set = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.YAMLError(
                f"duplicate key {key!r} on line {key_node.start_mark.line + 1}"
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_Strict.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys
)


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[1] if len(argv) > 1 else ".github/workflows")
    failures = 0
    for path in sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml")):
        try:
            data = yaml.load(path.read_text(encoding="utf-8"), Loader=_Strict)
        except yaml.YAMLError as exc:
            failures += 1
            print(f"FAIL {path}: {exc}", file=sys.stderr)
            continue
        if not isinstance(data, dict):
            failures += 1
            print(f"FAIL {path}: not a mapping", file=sys.stderr)
            continue
        # `on` is parsed as the boolean True by YAML 1.1, which is why it is
        # checked by either spelling.
        if "on" not in data and True not in data:
            failures += 1
            print(f"FAIL {path}: no trigger", file=sys.stderr)
            continue
        if not data.get("jobs"):
            failures += 1
            print(f"FAIL {path}: no jobs", file=sys.stderr)
            continue
        print(f"ok   {path}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
