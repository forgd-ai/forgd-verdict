"""docs/SECURITY-MODEL.md states the Claude Code hook's threat model.

The section is the stopping rule for review: a finding inside a listed
residual is a documented limitation, one outside it is a defect. Each
mechanism it names is checked against the code or fragment that provides
it, so removing one fails here until the section changes too.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / "docs" / "SECURITY-MODEL.md").read_text(encoding="utf-8")
MDM = (ROOT / "deploy" / "MDM.md").read_text(encoding="utf-8")
HEADING = "## The Claude Code hook's threat model"
ANCHOR = "the-claude-code-hooks-threat-model"
STOPPING_RULE = ("A finding inside a residual listed here is a documented limitation. A "
                 "finding outside the list is a defect.")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _section(text: str, heading: str, level: str = "## ") -> str:
    start = text.index(heading)
    end = text.find(f"\n{level}", start + 1)
    return text[start:end if end != -1 else len(text)]


SECTION = _flat(_section(DOC, HEADING))


def _sub(heading: str) -> str:
    return _flat(_section(_section(DOC, HEADING), heading, "### "))


def _fragment_args(name: str) -> list[list[str]]:
    fragment = json.loads((ROOT / "deploy" / name).read_text(encoding="utf-8"))
    return [[hook["command"], *hook["args"]] for entries in fragment["hooks"].values()
            for entry in entries for hook in entry["hooks"]]


def test_the_section_has_its_three_parts_and_the_stopping_rule():
    assert STOPPING_RULE in SECTION
    for heading in ("### Strong against", "### Best effort against",
                    "### The controls the hook cannot undermine"):
        assert heading in _section(DOC, HEADING), heading


def test_mdm_links_the_section_from_what_the_hook_cannot_protect_against():
    cannot = _section(MDM, "## What the hook cannot protect against")
    assert f"docs/SECURITY-MODEL.md#{ANCHOR}" in cannot


def test_env_minus_i_is_named_and_in_the_posix_fragment():
    assert "`env -i` on POSIX" in _sub("### Strong against")
    for argv in _fragment_args("managed-settings.fragment.json"):
        assert argv[:2] == ["/usr/bin/env", "-i"]


def test_the_scrub_is_named_and_in_both_fragments():
    from forgd_verdict import _hookenv

    assert f"-X {_hookenv.MARKER}" in _sub("### Strong against")
    for name in ("managed-settings.fragment.json", "managed-settings.windows.fragment.json"):
        for argv in _fragment_args(name):
            i = argv.index("-X")
            assert argv[i + 1] == _hookenv.MARKER
    for variable in ("OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES",
                     "SSL_CERT_FILE", "SSL_CERT_DIR"):
        assert variable in _sub("### Strong against"), variable
        assert _hookenv.removed(variable), variable


def test_the_sigalrm_watchdog_is_named_and_in_the_hook():
    source = (ROOT / "src" / "forgd_verdict" / "hook" / "cli.py").read_text(encoding="utf-8")
    assert "SIGALRM watchdog on POSIX" in _sub("### Strong against")
    assert "signal.setitimer(signal.ITIMER_REAL" in source
    assert "Windows has no SIGALRM" in _sub("### Best effort against")
    assert "threading.Timer(" in source


def test_the_gitleaks_mechanisms_are_named():
    strong = _sub("### Strong against")
    assert "hook.detectors.gitleaks.binary" in strong
    assert "SYSTEMROOT" in strong
    from forgd_verdict.detectors.gitleaks import SUBPROCESS_ENV

    assert SUBPROCESS_ENV == ("SYSTEMROOT",)


@pytest.mark.parametrize("residual", [
    "LD_PRELOAD", "DYLD_", "__COMPAT_LAYER", "PYLAUNCHER_DEBUG", "PYTHONEXECUTABLE",
    "gh-91057", "gh-133525", "MIMALLOC_", "`TZ`", "USERPROFILE", "HOMEDRIVE",
    "`hook.spool`", "SystemRoot", "`TEMP`", "never checks for signals", "local admin",
])
def test_each_residual_is_listed(residual):
    assert residual in _sub("### Best effort against"), residual


def test_pth_files_are_not_offered_as_a_mitigation():
    """Not verified against CPython 3.13's getpath."""
    assert "._pth" not in DOC


def test_the_controls_name_adapters_1_and_3():
    controls = _sub("### The controls the hook cannot undermine")
    assert "adapter 1" in controls and "adapter 3" in controls
    assert re.search(r"rely on adapter 1", controls)
