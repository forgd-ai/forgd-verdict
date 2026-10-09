"""Org entitlements and labels on a reader that does not hold the salt.

Each salted writer publishes `state/org-registry-<role>.json` (org id ->
store pseudonym) at startup; the dashboard and connector merge the files and
resolve ids through the result.
A reader with the salt computes pseudonyms directly. A reader without one
that cannot find an id in the registry grants nothing and labels nothing,
and says so without naming the org.
"""

from __future__ import annotations

import json
import logging
import types

import pytest
from conftest import ASGIClient, make_policy

from forgd_verdict.entitlements import MODE_OIDC_JWT, Principal
from forgd_verdict.models import pseudonym
from forgd_verdict.orgregistry import (
    REFRESH_S,
    REGISTRY_STATE_NAMES,
    OrgResolver,
    RegistryEntry,
    build_registry,
    publish_registry,
    referenced_orgs,
)
from forgd_verdict.server.app import VerdictServer
from forgd_verdict.store.base import VerdictRecord
from forgd_verdict.store.local import LocalFileStore

SALT = "writer-salt-0123456789"
PROD = "org-id-prod-7f3a"
DEV = "org-id-dev-19bc"
EU = "org-id-eu-5d20"
OTEL_ONLY = "org-id-otel-aa01"
SCAN_ONLY = "org-id-scan-bb02"
ALL_IDS = (PROD, DEV, EU, OTEL_ONLY, SCAN_ONLY)
WS_KEY = "ws-key-agents-k1"

VERDICT = REGISTRY_STATE_NAMES["verdict"]
COLLECTOR = REGISTRY_STATE_NAMES["collector"]
INTAKE = REGISTRY_STATE_NAMES["intake"]

AUTH = {"mode": MODE_OIDC_JWT, "jwks_url": "https://idp/keys", "issuer": "https://idp",
        "audience": "aud"}


def raw_config(salt: str = SALT) -> dict:
    return {
        "privacy": {"hash_salt": salt},
        "orgs": [{"id": PROD, "label": "Prod"}, {"id": "$FORGD_ORG_ID_DEV", "label": "Dev"}],
        "dashboard": {"auth": dict(AUTH), "entitlements": {"map": [
            {"group": "g-prod", "orgs": [PROD]},
            {"group": "g-eu", "orgs": [EU, "$FORGD_ORG_ID_UNSET"]},
        ]}},
        "otel": {"orgs": [{"id": OTEL_ONLY, "label": "otel"},
                          {"id": PROD, "label": "prod-from-otel"}]},
        "compliance": {"orgs": [{"id": SCAN_ONLY, "label": "Scan"}]},
        "managed_agents": {"workspaces": [{"key": WS_KEY, "label": "agents-ws"}]},
        "detectors": {"gitleaks": {"enabled": False, "severity": "block"}},
    }


@pytest.fixture(autouse=True)
def _org_env(monkeypatch):
    monkeypatch.setenv("FORGD_ORG_ID_DEV", DEV)
    monkeypatch.delenv("FORGD_ORG_ID_UNSET", raising=False)


def writer(salt: str = SALT):
    return make_policy(**raw_config(salt))


def reader():
    return make_policy(**raw_config(salt=""))


def org_key(org_id: str, salt: str = SALT) -> str:
    return pseudonym(org_id, salt, "org")


def ws_key(key: str = WS_KEY, salt: str = SALT) -> str:
    return pseudonym(key, salt, "workspace")


def principal(*groups: str) -> Principal:
    return Principal("viewer@example.com", groups=groups)


class CountingStore(LocalFileStore):
    def __init__(self, root):
        super().__init__(root, instance="t")
        self.reads = 0

    def get_state(self, name):
        self.reads += 1
        return super().get_state(name)


def assert_no_org_id_logged(caplog):
    for rec in caplog.records:
        text = rec.getMessage() + json.dumps(getattr(rec, "fields", {}), default=str)
        for org_id in ALL_IDS:
            assert org_id not in text, rec.getMessage()


# --- the registry file ---------------------------------------------------


def test_the_registry_covers_every_org_the_policy_names():
    assert referenced_orgs(writer()) == {
        PROD: "Prod", DEV: "Dev", EU: None, OTEL_ONLY: "otel", SCAN_ONLY: "Scan"}


def test_the_registry_schema_is_exact():
    """Sorted by id; `label` only where one is configured, `orgs` winning
    over `otel.orgs` for the same id."""
    body = json.loads(build_registry(writer()))
    entries = [{"id": v, "pseudonym": org_key(v)} for v in sorted(
        [PROD, DEV, EU, OTEL_ONLY, SCAN_ONLY])]
    labels = {PROD: "Prod", DEV: "Dev", OTEL_ONLY: "otel", SCAN_ONLY: "Scan"}
    for e in entries:
        if e["id"] in labels:
            e["label"] = labels[e["id"]]
    assert body == {"version": 2, "orgs": entries, "workspaces": [
        {"key": WS_KEY, "pseudonym": ws_key(), "label": "agents-ws"}]}


def test_the_single_org_compliance_form_is_covered():
    policy = make_policy(privacy={"hash_salt": SALT}, compliance={"org_id": SCAN_ONLY})
    assert json.loads(build_registry(policy))["orgs"] == [
        {"id": SCAN_ONLY, "pseudonym": org_key(SCAN_ONLY)}]


def test_the_registry_bytes_are_deterministic():
    first = build_registry(writer())
    assert first == build_registry(writer())
    shuffled = raw_config()
    shuffled["orgs"].reverse()
    shuffled["dashboard"]["entitlements"]["map"].reverse()
    assert build_registry(make_policy(**shuffled)) == first
    assert first.endswith(b"\n") and b" " not in first


def test_the_registry_bytes_are_pinned():
    policy = make_policy(privacy={"hash_salt": SALT}, orgs=[{"id": PROD, "label": "Prod"}])
    assert build_registry(policy) == (
        f'{{"orgs":[{{"id":"{PROD}","label":"Prod","pseudonym":"{org_key(PROD)}"}}],'
        '"version":2,"workspaces":[]}\n').encode()


def test_a_salt_rotation_changes_every_pseudonym_in_the_registry():
    old = json.loads(build_registry(writer()))["orgs"]
    new = json.loads(build_registry(writer("rotated-salt-9876543210")))["orgs"]
    assert [e["id"] for e in old] == [e["id"] for e in new]
    assert not {e["pseudonym"] for e in old} & {e["pseudonym"] for e in new}


def test_the_verdict_server_publishes_the_registry_at_startup(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    server = VerdictServer(writer(), store=store, detectors=[])
    try:
        assert store.get_state(VERDICT) == build_registry(writer())
    finally:
        server.close()


def test_the_collector_publishes_the_registry_at_startup(tmp_path):
    """A deployment with the collector and no verdict server, such as Team
    workspaces through OTel, still gets a registry."""
    from forgd_verdict.otel.app import Collector

    store = LocalFileStore(tmp_path, instance="t")
    collector = Collector(writer(), store=store, detectors=[], late_detectors=[])
    try:
        assert store.get_state(COLLECTOR) == build_registry(writer())
    finally:
        collector.close()


def test_the_intake_publishes_the_registry_at_startup(tmp_path):
    from forgd_verdict.intake.app import Intake

    store = LocalFileStore(tmp_path, instance="t")
    intake = Intake(writer(), store=store)
    try:
        assert store.get_state(INTAKE) == build_registry(writer())
    finally:
        intake.close()


def test_a_restart_under_a_rotated_salt_republishes(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    VerdictServer(writer(), store=store, detectors=[]).close()
    rotated = writer("rotated-salt-9876543210")
    VerdictServer(rotated, store=store, detectors=[]).close()
    assert store.get_state(VERDICT) == build_registry(rotated)

    policy = reader()
    policy.use_org_registry(store)
    rotated_key = org_key(PROD, "rotated-salt-9876543210")
    assert policy.org_labels()[rotated_key] == "Prod"
    assert policy.entitlements().allowed(principal("g-prod")) == {rotated_key}


def test_a_failed_publish_does_not_stop_the_server_and_names_no_org(tmp_path, caplog):
    class ReadOnly(LocalFileStore):
        def put_state(self, name, blob):
            raise PermissionError(f"denied writing {PROD}")

    store = ReadOnly(tmp_path, instance="t")
    with caplog.at_level(logging.ERROR):
        server = VerdictServer(writer(), store=store, detectors=[],
                               logger=logging.getLogger("test.orgregistry"))
    server.close()
    assert any("could not publish the org registry" in r.getMessage()
               for r in caplog.records)
    assert_no_org_id_logged(caplog)


def test_an_unsalted_writer_does_not_overwrite_a_published_registry(tmp_path, caplog):
    store = LocalFileStore(tmp_path, instance="t")
    assert publish_registry(store, writer(), "verdict")
    before = store.get_state(VERDICT)
    with caplog.at_level(logging.WARNING):
        server = VerdictServer(reader(), store=store, detectors=[],
                               logger=logging.getLogger("test.orgregistry"))
        server.close()
        assert publish_registry(store, reader(), "verdict") is False
    assert store.get_state(VERDICT) == before
    assert any("not publishing the org registry" in r.getMessage()
               for r in caplog.records)
    assert_no_org_id_logged(caplog)


def test_an_unsalted_writer_publishes_nothing_into_an_empty_store(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    assert publish_registry(store, reader(), "verdict") is False
    assert store.get_state(VERDICT) is None


def test_a_server_with_no_store_publishes_nothing(tmp_path):
    server = VerdictServer(writer(), detectors=[])
    server.close()
    assert not list(tmp_path.iterdir())


# --- a reader without the salt --------------------------------------------


def test_an_unsalted_reader_resolves_entitlements_and_labels_through_the_registry(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer(), "verdict")
    policy = reader()
    policy.use_org_registry(store)

    ent = policy.entitlements()
    assert ent.allowed(principal("g-prod")) == {org_key(PROD)}
    assert ent.allowed(principal("g-eu")) == {org_key(EU)}
    assert policy.org_labels() == {
        org_key(PROD): "Prod", org_key(DEV): "Dev", org_key(OTEL_ONLY): "otel",
        org_key(SCAN_ONLY): "Scan"}
    assert policy.workspace_labels() == {ws_key(): "agents-ws"}


def test_unsalted_labels_come_from_the_registry_and_never_fall_back_to_an_id(tmp_path):
    """EU has no label anywhere; `unlabelled` has none in the writer's policy
    and the reader's own policy would label it by its id."""
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer(), "verdict")
    raw = raw_config(salt="")
    raw["orgs"] = [{"id": PROD, "label": "reader-side-name"}, {"id": EU}]
    policy = make_policy(**raw)
    policy.use_org_registry(store)

    labels = dict(policy.org_labels())
    assert labels[org_key(PROD)] == "Prod"
    assert org_key(EU) not in labels
    served = json.dumps(labels)
    for org_id in ALL_IDS:
        assert org_id not in served


def test_the_connector_names_no_org_id_for_an_unlabelled_org(tmp_path):
    from forgd_verdict.connector.tools import Caller, Reader

    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer(), "verdict")
    policy = reader()
    policy.use_org_registry(store)
    rd = Reader(store=store, auth=None, entitlements=policy.entitlements(),
                org_labels=policy.org_labels())
    caller = Caller(rd, principal("g-eu"))
    assert caller.org(org_key(EU)) == {"org": org_key(EU), "kind": "org", "label": None}
    assert caller.org(org_key(PROD)) == {"org": org_key(PROD), "kind": "org", "label": "Prod"}


def test_entitlements_built_before_the_registry_is_attached_use_it(tmp_path):
    """The connector loads its config before it opens the store."""
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer(), "verdict")
    policy = reader()
    ent, labels = policy.entitlements(), policy.org_labels()
    policy.use_org_registry(store)
    assert ent.allowed(principal("g-prod")) == {org_key(PROD)}
    assert labels[org_key(PROD)] == "Prod"


def test_the_registry_is_reread_after_the_refresh_interval(tmp_path):
    store = CountingStore(tmp_path)
    now = [1000.0]
    resolver = OrgResolver("", store, ttl_s=60, clock=lambda: now[0])

    assert resolver.pseudonym(PROD) is None
    publish_registry(store, writer(), "verdict")
    now[0] += 59
    assert resolver.pseudonym(PROD) is None
    assert store.reads == len(REGISTRY_STATE_NAMES)
    now[0] += 1
    assert resolver.pseudonym(PROD) == org_key(PROD)
    assert resolver.pseudonym(DEV) == org_key(DEV)
    assert store.reads == 2 * len(REGISTRY_STATE_NAMES)


def test_a_reader_with_the_salt_computes_directly_and_only_checks_the_registry(
        tmp_path, caplog):
    """No registry exists: nothing to disagree with, so no warning, and one
    refresh's reads for all the lookups entitlements make."""
    store = CountingStore(tmp_path)
    policy = writer()
    policy.use_org_registry(store)
    with caplog.at_level(logging.WARNING):
        assert policy.entitlements().allowed(principal("g-prod")) == {org_key(PROD)}
        assert policy.org_labels()[org_key(DEV)] == "Dev"
    assert store.reads == len(REGISTRY_STATE_NAMES)
    assert not caplog.records


def test_a_salted_reader_that_agrees_with_the_writers_does_not_warn(tmp_path, caplog):
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer(), "verdict")
    publish_registry(store, writer(), "collector")
    resolver = OrgResolver(SALT, store, clock=lambda: 0.0)
    with caplog.at_level(logging.WARNING):
        assert resolver.pseudonym(PROD) == org_key(PROD)
    assert not caplog.records


def test_a_salted_reader_that_disagrees_warns_once_per_refresh_and_still_computes(
        tmp_path, caplog):
    """The intake agrees with the reader; the verdict server and the collector
    were published under another salt."""
    store = CountingStore(tmp_path)
    publish_registry(store, writer("writers-salt-1111111111"), "verdict")
    publish_registry(store, writer("writers-salt-1111111111"), "collector")
    publish_registry(store, writer(), "intake")
    now = [0.0]
    resolver = OrgResolver(SALT, store, ttl_s=60, clock=lambda: now[0])
    with caplog.at_level(logging.WARNING):
        for org_id in (PROD, DEV, EU, PROD):
            assert resolver.pseudonym(org_id) == org_key(org_id)
        now[0] += 59
        assert resolver.pseudonym(PROD) == org_key(PROD)
    assert store.reads == len(REGISTRY_STATE_NAMES)
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert "salt differs" in record.getMessage()
    assert record.fields == {"roles": ["verdict", "collector"]}
    text = record.getMessage() + json.dumps(record.fields)
    for org_id in ALL_IDS:
        assert org_id not in text
        assert org_key(org_id) not in text
        assert org_key(org_id, "writers-salt-1111111111") not in text
    assert WS_KEY not in text and ws_key() not in text

    now[0] += 1
    with caplog.at_level(logging.WARNING):
        assert resolver.pseudonym(DEV) == org_key(DEV)
    assert len(caplog.records) == 2


def _label_only_salted_policy():
    raw = raw_config()
    del raw["dashboard"]
    return make_policy(**raw)


def _assert_salt_warning_is_privacy_safe(record):
    assert "salt differs" in record.getMessage()
    assert record.fields == {"roles": ["verdict"]}
    text = record.getMessage() + json.dumps(record.fields)
    for org_id in ALL_IDS:
        assert org_id not in text
        assert org_key(org_id) not in text
        assert org_key(org_id, "writers-salt-1111111111") not in text
    assert WS_KEY not in text and ws_key() not in text


def test_attaching_a_mismatching_registry_to_a_salted_policy_warns_at_once(
        tmp_path, caplog):
    """No entitlements map and no label lookup: the attach alone checks."""
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer("writers-salt-1111111111"), "verdict")
    policy = _label_only_salted_policy()
    assert not policy.entitlements().enabled
    with caplog.at_level(logging.WARNING):
        policy.use_org_registry(store)
    assert len(caplog.records) == 1
    _assert_salt_warning_is_privacy_safe(caplog.records[0])


def test_a_label_only_salted_reader_rechecks_after_the_refresh_interval(
        tmp_path, caplog, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("forgd_verdict.orgregistry._monotonic", lambda: now[0])
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer("writers-salt-1111111111"), "verdict")
    policy = _label_only_salted_policy()
    expected = {org_key(PROD): "Prod", org_key(DEV): "Dev"}
    with caplog.at_level(logging.WARNING):
        policy.use_org_registry(store)
        labels = policy.org_labels()
        now[0] += REFRESH_S - 1
        assert dict(labels) == expected
        assert len(caplog.records) == 1
        now[0] += 1
        assert dict(labels) == expected
        assert dict(labels) == expected
    assert len(caplog.records) == 2
    for record in caplog.records:
        _assert_salt_warning_is_privacy_safe(record)


@pytest.mark.parametrize("case", ["unreadable", "malformed"])
def test_a_salted_reader_ignores_registry_failures(case, tmp_path, caplog):
    if case == "unreadable":
        store = Unreadable(tmp_path, instance="t")
    else:
        store = LocalFileStore(tmp_path, instance="t")
        store.put_state(VERDICT, b"{not json")
    policy = writer()
    policy.use_org_registry(store)
    with caplog.at_level(logging.WARNING):
        assert policy.entitlements().allowed(principal("g-prod")) == {org_key(PROD)}
        assert policy.org_pseudonym(DEV) == org_key(DEV)
    assert not caplog.records


# --- fail closed ------------------------------------------------------------


class Unreadable(LocalFileStore):
    def get_state(self, name):
        raise OSError(f"cannot read {PROD}")


def _missing(tmp_path):
    return LocalFileStore(tmp_path, instance="t")


def _unreadable(tmp_path):
    return Unreadable(tmp_path, instance="t")


def _blob(blob):
    def make(tmp_path):
        store = LocalFileStore(tmp_path, instance="t")
        store.put_state(VERDICT, blob)
        return store
    return make


FAILURES = {
    "missing": (_missing, "missing"),
    "unreadable": (_unreadable, "could not be read"),
    "not-json": (_blob(b"{not json"), "malformed"),
    "not-an-object": (_blob(b"[1, 2]"), "malformed"),
    "wrong-version": (_blob(json.dumps({"version": 2, "orgs": [
        {"id": PROD, "pseudonym": org_key(PROD), "label": "Prod"}]}).encode()), "malformed"),
    "orgs-not-a-list": (_blob(json.dumps({"version": 1, "orgs": {PROD: "x"}}).encode()),
                        "malformed"),
    "entry-not-an-object": (_blob(b'{"version": 1, "orgs": ["a"]}'), "malformed"),
    "entry-without-pseudonym": (
        _blob(json.dumps({"version": 1, "orgs": [{"id": PROD}]}).encode()), "malformed"),
}


@pytest.mark.parametrize("case", sorted(FAILURES))
def test_an_unusable_registry_grants_nothing_and_labels_nothing(case, tmp_path, caplog):
    make, phrase = FAILURES[case]
    policy = reader()
    policy.use_org_registry(make(tmp_path))
    with caplog.at_level(logging.WARNING):
        ent = policy.entitlements()
        assert ent.enabled
        assert ent.allowed(principal("g-prod", "g-eu")) == frozenset()
        assert dict(policy.org_labels()) == {}
    messages = [r.getMessage() for r in caplog.records]
    assert sum(phrase in m for m in messages) == 1
    assert not any("no entry in the org registry" in m for m in messages)
    assert_no_org_id_logged(caplog)


def test_an_org_missing_from_the_registry_grants_nothing(tmp_path, caplog):
    """The verdict server's policy predates the reader's: EU is not in it."""
    store = LocalFileStore(tmp_path, instance="t")
    older = raw_config()
    older["dashboard"]["entitlements"]["map"] = [{"group": "g-prod", "orgs": [PROD]}]
    publish_registry(store, make_policy(**older), "verdict")
    policy = reader()
    policy.use_org_registry(store)
    with caplog.at_level(logging.WARNING):
        ent = policy.entitlements()
        assert ent.allowed(principal("g-eu")) == frozenset()
        assert ent.allowed(principal("g-prod", "g-eu")) == {org_key(PROD)}
    assert sum("no entry in the org registry" in r.getMessage()
               for r in caplog.records) == 1
    assert_no_org_id_logged(caplog)


def test_an_unsalted_reader_with_no_store_grants_nothing(caplog):
    policy = reader()
    with caplog.at_level(logging.WARNING):
        assert policy.entitlements().allowed(principal("g-prod")) == frozenset()
        assert dict(policy.org_labels()) == {}
    assert any("no store to read the org registry" in r.getMessage()
               for r in caplog.records)
    assert_no_org_id_logged(caplog)


def test_an_unreadable_registry_drops_entries_it_had_already_read(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer(), "verdict")
    now = [0.0]
    resolver = OrgResolver("", store, ttl_s=60, clock=lambda: now[0])
    assert resolver.pseudonym(PROD) == org_key(PROD)
    store.put_state(VERDICT, b"garbage")
    now[0] += 60
    assert resolver.pseudonym(PROD) is None


# --- merging the writers' files --------------------------------------------


def _resolver(store):
    return OrgResolver("", store, clock=lambda: 0.0)


def test_disjoint_writers_merge(tmp_path):
    """The verdict server names PROD only and the collector OTEL_ONLY only;
    a reader resolves both."""
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, make_policy(privacy={"hash_salt": SALT},
                                        orgs=[{"id": PROD, "label": "Prod"}]), "verdict")
    publish_registry(store, make_policy(privacy={"hash_salt": SALT},
                                        otel={"orgs": [{"id": OTEL_ONLY, "label": "otel"}]}),
                     "collector")
    resolver = _resolver(store)
    assert resolver.entry(PROD) == RegistryEntry(org_key(PROD), "Prod")
    assert resolver.entry(OTEL_ONLY) == RegistryEntry(org_key(OTEL_ONLY), "otel")


def test_a_writer_alone_other_than_the_verdict_server_is_enough(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer(), "intake")
    assert _resolver(store).pseudonym(SCAN_ONLY) == org_key(SCAN_ONLY)


def test_conflicting_salts_fail_only_the_disputed_id_with_one_warning(tmp_path, caplog):
    """The verdict server and the intake both name PROD under different salts;
    DEV, which only the verdict server names, still resolves."""
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, make_policy(privacy={"hash_salt": SALT}, orgs=[
        {"id": PROD, "label": "Prod"}, {"id": DEV, "label": "Dev"}]), "verdict")
    publish_registry(store, make_policy(privacy={"hash_salt": "other-salt-5555"},
                                        orgs=[{"id": PROD, "label": "Prod"}]), "intake")
    resolver = _resolver(store)
    with caplog.at_level(logging.WARNING):
        assert resolver.entry(PROD) is None
        assert resolver.entry(PROD) is None
        assert resolver.pseudonym(DEV) == org_key(DEV)
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert "different pseudonyms" in record.getMessage()
    assert record.fields == {"roles": ["verdict", "intake"]}
    assert_no_org_id_logged(caplog)
    for key in (org_key(PROD), org_key(PROD, "other-salt-5555")):
        assert key not in record.getMessage() + json.dumps(record.fields)


def test_matching_pseudonyms_take_the_label_of_the_first_role(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    for role, orgs in (("intake", [{"id": PROD, "label": "from-intake"},
                                   {"id": EU, "label": "eu-from-intake"}]),
                       ("collector", [{"id": PROD, "label": "from-collector"}, {"id": EU}]),
                       ("verdict", [{"id": PROD, "label": "from-verdict"}])):
        publish_registry(store, make_policy(privacy={"hash_salt": SALT}, orgs=orgs), role)
    resolver = _resolver(store)
    assert resolver.entry(PROD) == RegistryEntry(org_key(PROD), "from-verdict")
    assert resolver.entry(EU) == RegistryEntry(org_key(EU), "eu-from-intake")


def test_a_malformed_file_beside_a_good_one_fails_the_refresh(tmp_path, caplog):
    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer(), "verdict")
    store.put_state(COLLECTOR, b"{not json")
    with caplog.at_level(logging.WARNING):
        assert _resolver(store).pseudonym(PROD) is None
    assert [r.getMessage() for r in caplog.records if "malformed" in r.getMessage()]
    assert_no_org_id_logged(caplog)


def test_a_stale_legacy_registry_is_ignored(tmp_path, caplog):
    """`org-registry.json` from before per-writer files, under an old salt,
    neither overrides nor disputes the verdict server's file."""
    store = LocalFileStore(tmp_path, instance="t")
    store.put_state("org-registry.json", build_registry(writer("old-salt-0000000000")))
    publish_registry(store, writer(), "verdict")
    with caplog.at_level(logging.WARNING):
        assert _resolver(store).pseudonym(PROD) == org_key(PROD)
    assert not caplog.records


def test_a_legacy_registry_alone_counts_as_missing(tmp_path, caplog):
    store = LocalFileStore(tmp_path, instance="t")
    store.put_state("org-registry.json", build_registry(writer()))
    with caplog.at_level(logging.WARNING):
        assert _resolver(store).pseudonym(PROD) is None
    assert any("org registry is missing" in r.getMessage() for r in caplog.records)


def test_publishing_rejects_an_unknown_role(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    with pytest.raises(KeyError):
        publish_registry(store, writer(), "dashboard")
    assert not (tmp_path / "state").exists()


# --- the readers attach the registry --------------------------------------


PROD_SURFACE, DEV_SURFACE = "surface-prodonly-q7", "surface-devonly-k3"
WRITER_LABELS = {PROD: "Registry-Prod-Name", EU: "Registry-Eu-Name",
                 DEV: "Registry-Dev-Name"}


def _two_org_store(root) -> LocalFileStore:
    store = LocalFileStore(root, instance="t")
    store.write_verdicts([
        VerdictRecord(source="otel_collect", tenant_hash=org_key(PROD), surface=PROD_SURFACE),
        VerdictRecord(source="otel_collect", tenant_hash=org_key(DEV), surface=DEV_SURFACE),
    ])
    return store


def _publish_as_the_verdict_server(store):
    raw = raw_config()
    raw["orgs"] = [{"id": k, "label": v} for k, v in WRITER_LABELS.items()]
    VerdictServer(make_policy(**raw), store=store, detectors=[]).close()


def _unsalted_dashboard(tmp_path, monkeypatch, store_dir, groups):
    """`create_app` on a policy whose salt is explicitly empty and whose
    orgs carry no labels, signed in as a viewer in `groups`."""
    raw = raw_config(salt="")
    raw["orgs"] = [{"id": PROD}, {"id": EU}, {"id": "$FORGD_ORG_ID_DEV"}]
    raw["dashboard"]["entitlements"]["map"] = [{"group": "g-both", "orgs": [PROD, EU]}]
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(raw))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy_file))
    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    from forgd_verdict.dashboard.app import create_app

    app = create_app(store_spec=str(store_dir))
    viewer = principal(*groups)
    app.auth = types.SimpleNamespace(mode=app.auth.mode, authenticate=lambda h: viewer,
                                     describe=app.auth.describe)
    return app


def _assert_no_org_id(body: str):
    for org_id in ALL_IDS:
        assert org_id not in body


async def test_an_unsalted_dashboard_scopes_and_labels_through_the_registry(
        tmp_path, monkeypatch):
    """Entitled to PROD and EU; the store has rows for PROD and DEV."""
    store_dir = tmp_path / "store"
    _publish_as_the_verdict_server(_two_org_store(store_dir))
    app = _unsalted_dashboard(tmp_path, monkeypatch, store_dir, ("g-both",))
    client = ASGIClient(app)

    for route in ("/", "/events"):
        status, body = await client.get(route)
        assert status == 200, route
        assert PROD_SURFACE in body and DEV_SURFACE not in body, route
        assert "Registry-Prod-Name" in body and "Registry-Eu-Name" in body, route
        assert "Registry-Dev-Name" not in body and org_key(DEV) not in body, route
        _assert_no_org_id(body)
    status, summary = await client.get("/api/summary")
    assert status == 200
    _assert_no_org_id(json.dumps(summary))


async def test_a_registry_published_after_the_dashboard_starts_is_used_once_the_cache_expires(
        tmp_path, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("forgd_verdict.orgregistry._monotonic", lambda: now[0])
    store_dir = tmp_path / "store"
    store = _two_org_store(store_dir)
    app = _unsalted_dashboard(tmp_path, monkeypatch, store_dir, ("g-both",))
    client = ASGIClient(app)

    _, body = await client.get("/events")
    assert PROD_SURFACE not in body and DEV_SURFACE not in body

    _publish_as_the_verdict_server(store)
    now[0] += REFRESH_S - 1
    _, body = await client.get("/events")
    assert PROD_SURFACE not in body

    now[0] += 1
    _, body = await client.get("/events")
    assert PROD_SURFACE in body and DEV_SURFACE not in body
    assert "Registry-Prod-Name" in body
    _assert_no_org_id(body)


def test_the_connector_reader_resolves_through_the_registry_in_its_store(tmp_path):
    from forgd_verdict.connector.tools import reader_from_policy

    store = LocalFileStore(tmp_path, instance="t")
    publish_registry(store, writer(), "verdict")
    policy = reader()
    cfg = types.SimpleNamespace(auth=None, entitlements=policy.entitlements())
    rd = reader_from_policy(policy, cfg, store)
    assert rd.entitlements.allowed(principal("g-eu")) == {org_key(EU)}
    assert rd.org_labels.get(org_key(DEV)) == "Dev"
