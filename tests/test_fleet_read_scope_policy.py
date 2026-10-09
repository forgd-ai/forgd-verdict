"""Readers take a multi-org fleet's partition and orgs from the policy.

The dashboard and the connector read only the fleet partitions a viewer's
orgs can see rows in (`test_fleet_read_scope.py`). Which orgs a fleet is
bound to comes from `intake.fleet[].orgs`, resolved as every other org id a
reader names: with the salt, or through the org registry the writers
publish. A fleet with an org the reader cannot resolve is shown to no
viewer of that org, and the reader says so at startup.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import yaml
from test_intake_fleet import ORG_DEV, ORG_PROD, SALT, _policy, org_env  # noqa: F401

from forgd_verdict.intake.verify import FleetTokens
from forgd_verdict.models import pseudonym
from forgd_verdict.orgregistry import publish_registry
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.attribution import policy_fleets, warn_unresolved_fleets

PROD = pseudonym(ORG_PROD, SALT, "org")
DEV = pseudonym(ORG_DEV, SALT, "org")
MULTI = [{"name": "corp-laptops", "tokens": ["$FORGD_INTAKE_FLEET_TOKEN"],
          "orgs": ["$FORGD_ORG_ID_PROD", "$FORGD_ORG_ID_DEV"]}]


def test_the_map_is_the_partition_and_orgs_the_intake_files_under():
    policy = _policy(fleet=MULTI)
    [cred] = FleetTokens.from_policy(policy).credentials()
    assert policy_fleets(policy)() == {cred.org: frozenset(cred.fleet_orgs)}
    assert policy_fleets(policy)() == {"fleet-corp-laptops": frozenset({PROD, DEV})}


def test_a_single_org_fleet_has_no_partition_of_its_own():
    policy = _policy(fleet=[{"name": "one", "tokens": ["$FORGD_INTAKE_FLEET_TOKEN"],
                             "orgs": ["$FORGD_ORG_ID_PROD", "$FORGD_ORG_ID_PROD"]}])
    assert policy_fleets(policy)() == {}
    assert policy_fleets(_policy())() == {}


def test_a_reader_without_the_salt_resolves_through_the_registry(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    assert publish_registry(store, _policy(fleet=MULTI), "intake")
    reader = Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "orgs": _policy().raw["orgs"], "intake": {"fleet": MULTI}}))
    assert not reader.hash_salt
    assert policy_fleets(reader)() == {"fleet-corp-laptops": frozenset()}
    assert reader.unresolved_fleet_orgs() == ["corp-laptops"]
    reader.use_org_registry(store)
    assert policy_fleets(reader)() == {"fleet-corp-laptops": frozenset({PROD, DEV})}
    assert reader.unresolved_fleet_orgs() == []


def test_an_unset_org_variable_is_reported(monkeypatch):
    monkeypatch.delenv("FORGD_ORG_ID_DEV")
    policy = _policy(fleet=MULTI)
    assert policy.unresolved_fleet_orgs() == ["corp-laptops"]
    assert policy_fleets(policy)() == {}


def test_the_warning_names_the_fleet_and_never_an_org(monkeypatch, caplog):
    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {"intake": {"fleet": MULTI}}))
    with caplog.at_level(logging.WARNING):
        assert warn_unresolved_fleets(policy, "dashboard") == ["corp-laptops"]
    text = " ".join(f"{r.getMessage()} {getattr(r, 'fields', '')}" for r in caplog.records)
    assert "corp-laptops" in text
    assert ORG_PROD not in text and ORG_DEV not in text and PROD not in text


def test_the_dashboard_reads_with_the_policy_map(tmp_path, monkeypatch):
    from forgd_verdict.dashboard import app as dashboard_app

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(_policy(fleet=MULTI).raw))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(path))
    dash = dashboard_app.create_app(str(tmp_path / "store"))
    assert dash.fleets() == {"fleet-corp-laptops": frozenset({PROD, DEV})}


def test_the_connector_reads_with_the_policy_map(tmp_path):
    from forgd_verdict.connector.tools import reader_from_policy

    policy = _policy(fleet=MULTI)
    cfg = SimpleNamespace(auth=None, entitlements=None)
    reader = reader_from_policy(policy, cfg, LocalFileStore(tmp_path / "s", instance="t"))
    assert reader.fleets() == {"fleet-corp-laptops": frozenset({PROD, DEV})}
