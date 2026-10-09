"""Legacy exclusions as the dashboard and the CLI show them.

A value in the legacy markers/excluded_requests object was never screened,
so each is shown through `overrides.exclusion_label`: itself when clean,
`withheld (<detector>)` when a detector matches it, `withheld (organization
id)` when it is a configured org id, and `withheld (not scanned)` when the
detectors cannot run. Membership and counts are unchanged.
"""

from __future__ import annotations

import json
import logging
import re

import pytest
from conftest import DETECTORS, FAKE_GITHUB_TOKEN, OVERRIDES_KEY, make_policy
from test_dashboard_admin import (  # noqa: F401 - fixtures
    HEADER,
    _app,
    _call,
    _init,
    _token,
    auth,
    pem,
)
from test_overrides_services import ORG_ID

from forgd_verdict import overrides as ov
from forgd_verdict.detectors.base import TIER_T0, DetectorFailed
from forgd_verdict.overrides import (
    WITHHELD_ORG,
    WITHHELD_UNSCANNED,
    exclusion_label,
)
from forgd_verdict.store import LocalFileStore, VerdictRecord
from forgd_verdict.store.base import FindingRow

ADMINS = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}}}
ORGS = {"orgs": [{"id": "$FORGD_ORG_ID_PROD", "label": "prod"}]}
NO_GITLEAKS = {"detectors": {"gitleaks": {"enabled": False, "severity": "block"}}}
MATCHED = re.compile(r"withheld \([\w:.-]+(, [\w:.-]+)*\)")
CLEAN = "req_clean_legacy"


class Broken:
    name, tier = "broken", TIER_T0

    def scan(self, units):
        raise DetectorFailed("down")


pytestmark = pytest.mark.usefixtures("control_identity")


@pytest.fixture
def store(tmp_path):
    return LocalFileStore(tmp_path / "store", instance="t")


@pytest.fixture(autouse=True)
def org_env(monkeypatch):
    monkeypatch.setenv("FORGD_ORG_ID_PROD", ORG_ID)


def _matched_label() -> str:
    return exclusion_label(FAKE_GITHUB_TOKEN, DETECTORS, ())


def _policy_label() -> str:
    """The label the policies below give the matched value."""
    return exclusion_label(FAKE_GITHUB_TOKEN, make_policy(**NO_GITLEAKS).build_detectors(), ())


# -- the formatter ---------------------------------------------------------


def test_a_clean_value_is_shown_as_it_is():
    assert exclusion_label(CLEAN, DETECTORS, {ORG_ID}) == CLEAN


def test_a_matched_value_names_only_the_detector():
    """Mutation: return the value when a detector matches it."""
    label = _matched_label()
    assert MATCHED.fullmatch(label), label
    assert FAKE_GITHUB_TOKEN not in label


@pytest.mark.parametrize("value", [ORG_ID, ORG_ID.upper()])
def test_an_org_id_is_withheld_whatever_its_case(value):
    """Mutation: drop the org id check, or compare with case."""
    assert exclusion_label(value, DETECTORS, {ORG_ID.upper()}) == WITHHELD_ORG
    assert exclusion_label(value, DETECTORS, {ORG_ID}) == WITHHELD_ORG


@pytest.mark.parametrize("detectors", [None, (), (Broken(),)], ids=["none", "empty", "broken"])
def test_a_value_that_cannot_be_scanned_is_withheld(detectors):
    """Mutation: show the value when the detectors do not run."""
    assert exclusion_label(CLEAN, detectors, ()) == WITHHELD_UNSCANNED
    assert exclusion_label(FAKE_GITHUB_TOKEN, detectors, ()) == WITHHELD_UNSCANNED


# -- the dashboard ---------------------------------------------------------


def _policy_file(tmp_path, monkeypatch, raw):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(raw))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(path))


async def _policy_page(store, cfg, keys):
    app = _app(store, cfg)
    _, _, page = await _call(app, "GET", "/policy", {HEADER: _token(keys)})
    return page.decode()


async def test_the_dashboard_withholds_a_matched_or_org_id_legacy_exclusion(
        store, auth, pem, tmp_path, monkeypatch, caplog):  # noqa: F811
    """Mutation: render a legacy exclusion without the formatter."""
    _policy_file(tmp_path, monkeypatch, {**NO_GITLEAKS, **ORGS})
    store.set_excluded([CLEAN, FAKE_GITHUB_TOKEN, ORG_ID.upper()])
    _init(store)
    with caplog.at_level(logging.DEBUG):
        page = await _policy_page(store, auth, pem)
    assert f"<code>{CLEAN}</code>" in page
    assert f"<code>{_policy_label()}</code>" in page
    assert f"<code>{WITHHELD_ORG}</code>" in page
    for raw in (FAKE_GITHUB_TOKEN, ORG_ID, ORG_ID.upper()):
        assert raw not in page and raw.lower() not in page.lower()
        assert raw not in caplog.text
    assert store.get_excluded() == {CLEAN, FAKE_GITHUB_TOKEN, ORG_ID.upper()}


async def test_the_dashboard_withholds_every_legacy_exclusion_without_detectors(
        store, auth, pem, tmp_path, monkeypatch):  # noqa: F811
    """Mutation: show the values when the policy's detectors cannot be built."""
    _policy_file(tmp_path, monkeypatch, {"detectors": {"gitleaks": {
        "enabled": True, "severity": "block", "binary": str(tmp_path / "no-gitleaks")}}})
    store.set_excluded([CLEAN, FAKE_GITHUB_TOKEN])
    _init(store)
    page = await _policy_page(store, auth, pem)
    assert page.count(f"<code>{WITHHELD_UNSCANNED}</code>") == 2
    assert CLEAN not in page and FAKE_GITHUB_TOKEN not in page


def test_the_panel_withholds_without_a_labeler():
    """Mutation: fall back to the raw value when no labeler is given."""
    from forgd_verdict.dashboard.controls import Panel, panel

    html = panel(Panel(snapshot=ov.BASELINE_ONLY, baseline_mode="observe",
                       baseline_source="policy.yaml", legacy_reset=None,
                       legacy_excluded={FAKE_GITHUB_TOKEN}, history=None, form=None))
    assert FAKE_GITHUB_TOKEN not in html and WITHHELD_UNSCANNED in html


# -- the CLI ---------------------------------------------------------------


def _frames(root, *ids):
    LocalFileStore(root, instance="t").write_verdicts([
        VerdictRecord(source="inference_hook", observed_at=f"2026-09-18T10:0{i}:00Z",
                      surface="claude-ai", action="deny", request_id=rid, findings_count=1,
                      findings=[FindingRow("regex:x", "block", "m", "h")])
        for i, rid in enumerate(ids)])


def _list(tmp_path, capsys, raw, root):
    from forgd_verdict.cli import main

    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(raw))
    assert main(["--policy", str(policy), "exclude", "--store", str(root), "--list"]) == 0
    return capsys.readouterr()


@pytest.mark.parametrize("on", [False, True], ids=["overrides-off", "overrides-on"])
def test_the_cli_listing_withholds_a_matched_or_org_id_exclusion(
        tmp_path, capsys, caplog, monkeypatch, on):
    """Both listings. Mutation: print an excluded id without the formatter."""
    root = tmp_path / "s"
    legacy = [CLEAN, FAKE_GITHUB_TOKEN, ORG_ID.upper()]
    _frames(root, *legacy, "req_not_excluded")
    LocalFileStore(root).set_excluded(legacy)
    if on:
        ov.apply_change(LocalFileStore(root), {"name": "ops"}, ov.Change(ov.ACTION_INIT),
                        detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    with caplog.at_level(logging.DEBUG):
        out = _list(tmp_path, capsys, {**NO_GITLEAKS, **ORGS, **(ADMINS if on else {})}, root)
    lines = out.out.splitlines()
    assert lines[0] == "4 frame(s) with findings; 3 excluded"
    excluded = [line.split()[-1] if "withheld" not in line else line[line.index("withheld"):]
                for line in lines if "EXCLUDED" in line]
    assert sorted(excluded) == sorted([CLEAN, _policy_label(), WITHHELD_ORG])
    assert any(line.rstrip().endswith("req_not_excluded") and "EXCLUDED" not in line
               for line in lines)
    for raw in (FAKE_GITHUB_TOKEN, ORG_ID, ORG_ID.upper()):
        assert raw.lower() not in (out.out + out.err + caplog.text).lower()


@pytest.mark.parametrize("on", [False, True], ids=["overrides-off", "overrides-on"])
def test_the_cli_listing_withholds_every_exclusion_without_detectors(
        tmp_path, capsys, monkeypatch, on):
    """Mutation: print the ids when the policy's detectors cannot be built."""
    root = tmp_path / "s"
    _frames(root, CLEAN, FAKE_GITHUB_TOKEN)
    LocalFileStore(root).set_excluded([CLEAN, FAKE_GITHUB_TOKEN])
    if on:
        ov.apply_change(LocalFileStore(root), {"name": "ops"}, ov.Change(ov.ACTION_INIT),
                        detectors=DETECTORS, signing_key=OVERRIDES_KEY)
    raw = {"detectors": {"gitleaks": {"enabled": True, "severity": "block",
                                      "binary": str(tmp_path / "no-gitleaks")}},
           **(ADMINS if on else {})}
    out = _list(tmp_path, capsys, raw, root)
    assert out.out.count(WITHHELD_UNSCANNED) == 2
    assert CLEAN not in out.out and FAKE_GITHUB_TOKEN not in out.out + out.err
    assert "withheld" in out.err
