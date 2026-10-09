"""Where the Compliance API does not apply -- a Team workspace, or a
deployment with no Compliance org -- adapter 3 is "not applicable", never a
late or failed audit, in every view and in the topology strip."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
import yaml
from conftest import ASGIClient

from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.dashboard.topology import (
    STATE_LATE,
    STATE_LIVE,
    STATE_NA,
    STATE_OFF,
    compliance_plan,
    compliance_view,
    configured_from_policy,
    control_points,
    core_health,
    surface_states,
)
from forgd_verdict.policy import Policy, load_policy
from forgd_verdict.store.base import SOURCE_COMPLIANCE_SCAN, pseudonym
from forgd_verdict.store.local import LocalFileStore
from forgd_verdict.store.query import Summary

SALT = "s"
ENT_ID = "ent-org-synthetic"
TEAM_ID = "team-ws-synthetic"
ENT = pseudonym(ENT_ID, SALT, "org")
TEAM = pseudonym(TEAM_ID, SALT, "org")
WORKDAY = datetime(2026, 9, 21, 14, 0, tzinfo=UTC)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _mark(store, key, when):
    store.put_state(key, json.dumps({"last_run_started_at": _iso(when)}).encode())


def _policy(compliance_orgs, orgs=None, **compliance):
    return Policy(raw={
        "privacy": {"hash_salt": SALT},
        "orgs": orgs if orgs is not None else [
            {"id": ENT_ID, "label": "Enterprise"}, {"id": TEAM_ID, "label": "Team"}],
        "compliance": {**({"orgs": compliance_orgs} if compliance_orgs else {}),
                       **compliance},
    })


def _state_key(policy, org_id):
    entry = {"id": org_id}
    import os
    return os.path.basename(policy._state_path_for(entry, org_id))


# -- configured_from_policy ---------------------------------------------


def test_the_default_placeholder_key_does_not_configure_the_scan(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", raising=False)
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump({"privacy": {"allow_unsalted": True}}))
    assert configured_from_policy(load_policy(str(p)))[SOURCE_COMPLIANCE_SCAN] is False


def test_a_team_only_policy_has_no_compliance_scan():
    policy = _policy([], orgs=[{"id": TEAM_ID, "label": "Team"}])
    assert configured_from_policy(policy)[SOURCE_COMPLIANCE_SCAN] is False


def test_a_compliance_org_configures_the_scan_without_its_key_here(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", raising=False)
    policy = _policy([{"id": ENT_ID, "api_key": "$ANTHROPIC_COMPLIANCE_ACCESS_KEY"}])
    assert configured_from_policy(policy)[SOURCE_COMPLIANCE_SCAN] is True


# -- compliance_view, per selection -------------------------------------


@pytest.fixture
def mixed(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", raising=False)
    policy = _policy([{"id": ENT_ID, "api_key": "$ANTHROPIC_COMPLIANCE_ACCESS_KEY"}])
    store = LocalFileStore(tmp_path / "s", instance="t")
    return policy, store, compliance_plan(policy)


def test_a_team_workspace_selected_is_not_applicable(mixed):
    policy, store, plan = mixed
    _mark(store, _state_key(policy, ENT_ID), WORKDAY - timedelta(days=5))
    configured, beats, _ = compliance_view(plan, store, frozenset({TEAM}))
    assert isinstance(configured, str) and "Team workspace" in configured
    assert beats == {}
    cp = _cp(configured, beats)
    assert cp.state == STATE_NA and not cp.is_alert


def test_the_enterprise_org_selected_is_judged_on_its_own_marker(mixed):
    policy, store, plan = mixed
    _mark(store, _state_key(policy, ENT_ID), WORKDAY - timedelta(hours=2))
    configured, beats, intervals = compliance_view(plan, store, frozenset({ENT}))
    assert configured is True
    assert _cp(configured, beats, intervals).state == STATE_LIVE
    _mark(store, _state_key(policy, ENT_ID), WORKDAY - timedelta(days=5))
    configured, beats, intervals = compliance_view(plan, store, frozenset({ENT}))
    assert _cp(configured, beats, intervals).state == STATE_LATE


def test_a_stale_enterprise_org_does_not_make_a_team_workspace_late(mixed):
    policy, store, plan = mixed
    _mark(store, _state_key(policy, ENT_ID), WORKDAY - timedelta(days=5))
    configured, beats, intervals = compliance_view(plan, store, frozenset({TEAM}))
    assert _cp(configured, beats, intervals).state == STATE_NA


def test_no_run_recorded_and_no_key_here_is_not_applicable_not_late(mixed):
    _, store, plan = mixed
    configured, beats, intervals = compliance_view(plan, store, None)
    cp = _cp(configured, beats, intervals)
    assert cp.state == STATE_NA, cp.detail
    assert "no run recorded" in cp.detail


def test_a_compliance_entry_for_a_team_workspace_never_holds_back_the_aggregate(
        tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY_TEAM", raising=False)
    policy = _policy([{"id": ENT_ID, "api_key": "$ANTHROPIC_COMPLIANCE_ACCESS_KEY"},
                      {"id": TEAM_ID, "api_key": "$ANTHROPIC_COMPLIANCE_ACCESS_KEY_TEAM"}])
    store = LocalFileStore(tmp_path / "s", instance="t")
    _mark(store, _state_key(policy, ENT_ID), WORKDAY - timedelta(hours=1))
    plan = compliance_plan(policy)
    configured, beats, intervals = compliance_view(plan, store, None)
    assert _cp(configured, beats, intervals).state == STATE_LIVE
    configured, beats, intervals = compliance_view(plan, store, frozenset({TEAM}))
    assert _cp(configured, beats, intervals).state == STATE_NA


def test_a_key_visible_here_with_no_run_is_still_late(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", "sk-ant-api01-" + "x" * 40)
    policy = _policy([{"id": ENT_ID, "api_key": "$ANTHROPIC_COMPLIANCE_ACCESS_KEY"}])
    store = LocalFileStore(tmp_path / "s", instance="t")
    configured, beats, intervals = compliance_view(compliance_plan(policy), store, None)
    assert _cp(configured, beats, intervals).state == STATE_LATE


def test_no_compliance_org_at_all_is_off(tmp_path):
    policy = _policy([], orgs=[{"id": TEAM_ID, "label": "Team"}])
    store = LocalFileStore(tmp_path / "s", instance="t")
    configured, _, _ = compliance_view(compliance_plan(policy), store, None)
    assert configured is False


def _cp(configured, beats, intervals=None):
    cfg = {SOURCE_COMPLIANCE_SCAN: configured}
    points = control_points(Summary(), cfg, now=WORKDAY, heartbeats=beats,
                            intervals=intervals)
    return next(p for p in points if p.source == SOURCE_COMPLIANCE_SCAN)


def test_not_applicable_does_not_colour_the_core_or_the_strip():
    cfg = {SOURCE_COMPLIANCE_SCAN: "not applicable: a Team workspace has no Compliance API"}
    points = control_points(Summary(), cfg, now=WORKDAY)
    assert core_health(points) == "ok"
    nodes = surface_states(Summary(), cfg, now=WORKDAY)
    scan = [n for n in nodes if n.surface == "compliance-scan"]
    assert all(n.state not in (STATE_LATE,) for n in scan)
    assert all(n.state in (STATE_NA, STATE_OFF) for n in scan)


# -- every view, end to end ---------------------------------------------


async def test_the_overview_never_says_late_for_a_team_workspace(mixed):
    policy, store, plan = mixed
    _mark(store, _state_key(policy, ENT_ID), datetime.now(UTC) - timedelta(days=5))
    from forgd_verdict.store.base import VerdictRecord
    store.write_verdicts([VerdictRecord(source="otel_collect", tenant_hash=t, surface="cowork",
                                        observed_at=_iso(datetime.now(UTC)))
                          for t in (ENT, TEAM)])
    dash = Dashboard(store, configured=configured_from_policy(policy),
                     scan_state_keys=policy.compliance_state_keys(),
                     compliance=plan, org_labels={ENT: "Enterprise", TEAM: "Team"})
    client = ASGIClient(dash)
    _, team_page = await client.get(f"/?org={TEAM}")
    assert "late: Compliance scan" not in team_page
    assert "not applicable" in team_page
    _, ent_page = await client.get(f"/?org={ENT}")
    assert "late: Compliance scan" in ent_page


async def test_a_team_only_deployment_never_shows_a_late_compliance_scan(
        tmp_path, monkeypatch):
    """The shipped compliance.orgs entry left in place, no key anywhere, no
    run ever recorded."""
    monkeypatch.delenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", raising=False)
    policy = _policy([{"id": TEAM_ID, "api_key": "$ANTHROPIC_COMPLIANCE_ACCESS_KEY"}],
                     orgs=[{"id": TEAM_ID, "label": "Team"}])
    store = LocalFileStore(tmp_path / "s", instance="t")
    dash = Dashboard(store, configured=configured_from_policy(policy),
                     scan_state_keys=policy.compliance_state_keys(),
                     compliance=compliance_plan(policy))
    _, page = await ASGIClient(dash).get("/")
    assert "late: Compliance scan" not in page


async def test_create_app_builds_the_plan(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", raising=False)
    monkeypatch.setenv("FORGD_ORG_ID_TEAMX", TEAM_ID)
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump({
        "privacy": {"hash_salt": SALT},
        "orgs": [{"id": "$FORGD_ORG_ID_TEAMX", "label": "Team"}],
        "compliance": {"orgs": [{"id": "$FORGD_ORG_ID_TEAMX",
                                 "api_key": "$ANTHROPIC_COMPLIANCE_ACCESS_KEY"}]}}))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(p))
    monkeypatch.setenv("FORGD_HASH_SALT", SALT)
    from forgd_verdict.dashboard.app import create_app

    dash = create_app(str(tmp_path / "findings"))
    assert dash.compliance.orgs and dash.compliance.orgs[0].partition == TEAM
    _, page = await ASGIClient(dash).get("/")
    assert "late: Compliance scan" not in page
