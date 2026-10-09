"""Every hook run in CI names its policy.

Without `--policy` the hook reads neither `$FORGD_VERDICT_POLICY` nor
`./policy.yaml`, scans on its built-in defaults and says so on stdout. A CI
step that ran it bare stopped testing the allow path it was named for.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FILES = sorted([*(ROOT / ".github" / "workflows").glob("*.yml"),
                *(ROOT / ".github" / "actions").glob("*/action.yml")])
INVOCATION = re.compile(r"(?:forgd-verdict|forgd_verdict\.cli)\s+(?:hook-ship|hook)\b")
# The end of one command in a shell line.
COMMAND_END = re.compile(r"\||;|&&|\)|\n")


def _runs(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "run" and isinstance(value, str):
                yield value
            else:
                yield from _runs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _runs(item)


def _invocations(path: Path) -> list[str]:
    found = []
    for script in _runs(yaml.safe_load(path.read_text(encoding="utf-8"))):
        joined = script.replace("\\\n", " ")
        for match in INVOCATION.finditer(joined):
            rest = joined[match.start():]
            end = COMMAND_END.search(rest)
            found.append(rest[:end.start()] if end else rest)
    return found


def test_the_hook_invocations_are_found():
    found = [c for path in FILES for c in _invocations(path)]
    assert len(found) >= 2, found


@pytest.mark.parametrize("path", FILES, ids=[p.name for p in FILES])
def test_every_hook_invocation_passes_a_policy(path):
    bare = [c for c in _invocations(path) if "--policy" not in c.split()]
    assert not bare, f"{path.relative_to(ROOT)} runs the hook without --policy: {bare}"


def test_the_ci_policy_turns_gitleaks_off_and_sets_a_contact_line():
    from forgd_verdict.policy import load_policy

    policy = load_policy(str(ROOT / "tests" / "data" / "ci-hook-policy.yaml"), for_hook=True)
    assert policy.raw["detectors"]["gitleaks"]["enabled"] is False
    assert policy.contact_line == "Contact the forgd-verdict CI policy owner."
    assert "Contact the forgd-verdict CI policy owner." in (
        ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
