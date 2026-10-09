"""Comments say what the code does.

Each phrase below was an aphorism, a piece of history, or "our" in a file a
fork receives. They are listed by file so a reworded comment cannot move
one of them somewhere else unnoticed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

REMOVED = {
    "deploy/terraform/modules/cluster-aks/outputs.tf": ["two copies of a guess"],
    "scripts/bootstrap_aks.sh": ["They did.", "Both were wrong."],
    "scripts/bootstrap_tfstate.sh": ["the difference between a gate and a comment"],
    ".github/workflows/ci.yml": [
        "is worse than a red one",
        "is not a gate",
        "is one whose first plan is its first syntax check",
        "NOT a skip",
        "README claimed",
        "not a reason to pass",
    ],
    "policy.yaml": ["until a review checked it", "what this comment claimed", "is now the safe one"],
    "deploy/terraform/modules/cluster-aks/main.tf": ["the first Container Apps apply"],
    "deploy/terraform/modules/app-aca/main.tf": ["has always demanded it"],
    ".gitignore": ["from local dashboard review"],
}


@pytest.mark.parametrize("path", sorted(REMOVED))
def test_the_phrase_is_gone(path):
    text = " ".join((ROOT / path).read_text(encoding="utf-8").replace("#", " ").split())
    assert [p for p in REMOVED[path] if p in text] == []


# RFC 9562 Appendix A.3's UUIDv4 example, assembled so this file is not one
# of the files it checks.
RFC_9562_UUID = "-".join(["919108f7", "52d1", "4320", "9bac", "f847db4148a8"])


def test_every_use_of_the_rfc_uuid_says_where_it_comes_from():
    """A UUID in a fixture looks like a leaked identifier until it is
    labelled as the RFC's example."""
    files = subprocess.run(["git", "-C", str(ROOT), "grep", "-l", RFC_9562_UUID],
                           capture_output=True, text=True, check=True).stdout.split()
    assert files
    unlabelled = [f for f in files if "RFC 9562" not in (ROOT / f).read_text(encoding="utf-8")]
    assert unlabelled == []
