"""A fleet bound to several orgs: records attributed by the OTel session join.

One MDM fleet serves prod, dev and a Team workspace. A laptop says nothing
about its org that is trusted, so the intake files each record under the
fleet's own partition with the fleet's orgs, and a reader attributes it to
the one org whose Claude Code OTel export carries its session id. Until then
it is "org pending", visible only to a reader of every org in the fleet.
"""

from __future__ import annotations

import pytest
from conftest import ASGIClient
from test_intake_fleet import (
    FLEET_TOKEN,
    SALT,
    _headers,
    _ndjson,
    _policy,
    _stored,
    org_env,  # noqa: F401
)

from forgd_verdict.connector.tools import ScopedStore
from forgd_verdict.intake.app import Intake
from forgd_verdict.intake.verify import FleetTokens
from forgd_verdict.models import pseudonym
from forgd_verdict.store import LocalFileStore, attribution
from forgd_verdict.store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_INFERENCE_HOOK,
    SOURCE_OTEL_COLLECT,
    FindingRow,
    VerdictRecord,
    visible,
)
from forgd_verdict.store.views import event_page, read_summary

ORG_TEAM = "org-team-fixture"
PROD = pseudonym("org-prod-fixture", SALT, "org")
DEV = pseudonym("org-dev-fixture", SALT, "org")
TEAM = pseudonym(ORG_TEAM, SALT, "org")
FLEET = "fleet-corp-laptops"
DEVICE = "d000000000001"
# What `policy_fleets` gives a reader for `_multi()`.
FLEETS = {FLEET: frozenset({PROD, DEV})}


def _sid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def _multi(orgs=("$FORGD_ORG_ID_PROD", "$FORGD_ORG_ID_DEV")):
    return _policy(fleet=[{"name": "corp-laptops", "tokens": ["$FORGD_INTAKE_FLEET_TOKEN"],
                           "orgs": list(orgs)}])


# -- configuration ----------------------------------------------------------


def test_a_fleet_with_several_orgs_files_under_its_own_partition():
    [cred] = FleetTokens.from_policy(_multi()).credentials()
    assert cred.org == FLEET
    assert cred.fleet_orgs == tuple(sorted({PROD, DEV}))


def test_orgs_naming_one_org_twice_is_that_org():
    [cred] = FleetTokens.from_policy(
        _multi(("$FORGD_ORG_ID_PROD", "$FORGD_ORG_ID_PROD"))).credentials()
    assert (cred.org, cred.fleet_orgs) == (PROD, ())


@pytest.mark.parametrize("entry,message", [
    ({"org": "$FORGD_ORG_ID_PROD", "orgs": ["$FORGD_ORG_ID_DEV"]}, "both `org` and `orgs`"),
    ({"orgs": []}, "non-empty list"),
    ({"orgs": "$FORGD_ORG_ID_PROD"}, "non-empty list"),
    ({"orgs": ["$FORGD_ORG_ID_PROD", "$FORGD_ORG_ID_UNSET_HERE"]}, "resolves to nothing"),
])
def test_a_bad_orgs_refuses_to_start(entry, message):
    policy = _policy(fleet=[{"name": "corp-laptops",
                             "tokens": ["$FORGD_INTAKE_FLEET_TOKEN"], **entry}])
    with pytest.raises(ValueError, match=message):
        FleetTokens.from_policy(policy)


# -- what the intake writes -------------------------------------------------


def _app(tmp_path, policy=None) -> Intake:
    return Intake(policy or _multi(), store=LocalFileStore(tmp_path / "store", instance="t"))


async def test_a_scan_record_files_under_the_fleet_with_its_orgs(tmp_path):
    app = _app(tmp_path)
    try:
        status, _ = await ASGIClient(app).post(
            "/scan", b'{"hook_event_name": "UserPromptSubmit", "session_id": "'
            + _sid(1).encode() + b'", "prompt": "AKIAIOSFODNN7EXAMPLE"}',
            {**_headers(FLEET_TOKEN, DEVICE), "content-type": "application/json"})
        assert status == 200
        [stored] = _stored(app)
        assert stored.tenant_hash == FLEET
        assert stored.fleet_orgs == sorted({PROD, DEV})
        assert stored.session_id == _sid(1)
    finally:
        app.close()


async def test_a_shipped_record_cannot_choose_its_partition_or_orgs(tmp_path):
    app = _app(tmp_path)
    forged = VerdictRecord(source=SOURCE_CODE_HOOK, action="deny", tenant_hash=TEAM,
                           fleet_orgs=[TEAM], session_id=_sid(2),
                           findings=[FindingRow("regex:aws-access-key", "block", "c", "h")])
    try:
        status, _ = await ASGIClient(app).post("/intake", _ndjson(forged),
                                               _headers(FLEET_TOKEN, DEVICE))
        assert status == 200
        [stored] = _stored(app)
        assert stored.tenant_hash == FLEET
        assert stored.fleet_orgs == sorted({PROD, DEV})
    finally:
        app.close()


async def test_a_single_org_fleet_record_carries_no_fleet_orgs(tmp_path):
    app = _app(tmp_path, _policy())
    try:
        await ASGIClient(app).post("/intake", _ndjson(VerdictRecord(
            source=SOURCE_CODE_HOOK, action="deny", findings=[
                FindingRow("regex:aws-access-key", "block", "c", "h")])),
            _headers(FLEET_TOKEN, DEVICE))
        [stored] = _stored(app)
        assert (stored.tenant_hash, stored.fleet_orgs) == (PROD, None)
    finally:
        app.close()


# -- attribution at read time -----------------------------------------------

DAY = "2026-10-05"


def _hook(n: int, fleet_orgs=(PROD, DEV), action="deny", tenant=FLEET, **kw):
    return VerdictRecord(
        source=SOURCE_CODE_HOOK, observed_at=f"{DAY}T10:00:00Z", session_id=_sid(n),
        surface="claude-code-local", tenant_hash=tenant, fleet_orgs=sorted(fleet_orgs),
        client="corp-laptops", device=DEVICE, action=action, request_id=f"hook-{n}",
        findings=[FindingRow("regex:aws-access-key", "block", "c", f"h{n}")],
        findings_count=1, **kw)


def _otel(n: int, org: str, surface="claude-code", when=f"{DAY}T09:00:00Z"):
    return VerdictRecord(source=SOURCE_OTEL_COLLECT, observed_at=when, session_id=_sid(n),
                         surface=surface, tenant_hash=org, request_id=f"otel-{n}-{org}")


@pytest.fixture
def store(tmp_path):
    s = LocalFileStore(tmp_path / "s", instance="t")
    s.write_verdicts([
        _hook(1), _otel(1, PROD),                     # joins prod
        _hook(2), _otel(2, DEV),                      # joins dev
        _hook(3),                                     # no export: pending
        _hook(4), _otel(4, PROD), _otel(4, DEV),      # two orgs claim it: pending
        _hook(5), _otel(5, TEAM),                     # team is not the fleet's: pending
        _hook(6), _otel(6, PROD, surface="cowork"),   # not a Claude Code export
        _hook(7), _otel(7, FLEET),                    # an export in no org's partition
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at=f"{DAY}T10:00:00Z",
                      tenant_hash=TEAM, request_id="team-live"),
    ])
    return s


def _hook_ids(records) -> set[str]:
    return {r.request_id for r in records if r.source == SOURCE_CODE_HOOK}


def _summary_orgs(store, orgs):
    return read_summary(store, f"{DAY}T00:00:00Z", orgs, fleets=FLEETS).orgs


def _events(store, orgs):
    return _hook_ids(event_page(store, f"{DAY}T00:00:00Z", orgs, fleets=FLEETS).records)


def test_an_unrestricted_reader_sees_joined_records_under_their_orgs(store):
    orgs = _summary_orgs(store, None)
    assert orgs[FLEET] == 5 + 1     # hooks 3 to 7, and the export written under the fleet
    assert orgs[PROD] == 1 + 3      # hook-1, and the exports of sessions 1, 4 and 6
    assert orgs[DEV] == 1 + 2       # hook-2, and the exports of sessions 2 and 4


def test_a_viewer_of_dev_sees_only_the_record_that_joined_dev(store):
    assert _events(store, frozenset({DEV})) == {"hook-2"}
    assert FLEET not in _summary_orgs(store, frozenset({DEV}))


def test_a_viewer_of_prod_never_sees_a_session_dev_also_claims(store):
    assert _events(store, frozenset({PROD})) == {"hook-1"}


def test_a_viewer_of_team_sees_no_fleet_record_even_when_team_claims_its_session(store):
    assert _events(store, frozenset({TEAM})) == set()


def test_pending_records_are_visible_to_a_viewer_of_every_fleet_org(store):
    assert _events(store, frozenset({PROD, DEV})) == {f"hook-{n}" for n in range(1, 8)}


def test_pending_records_are_hidden_from_a_viewer_missing_one_fleet_org(tmp_path):
    s = LocalFileStore(tmp_path / "s", instance="t")
    s.write_verdicts([_hook(3, fleet_orgs=(PROD, DEV, TEAM))])
    assert _events(s, frozenset({PROD, DEV})) == set()
    assert _events(s, frozenset({PROD, DEV, TEAM})) == {"hook-3"}


def test_the_connector_scopes_the_same_way(store):
    scoped = ScopedStore(store, frozenset({DEV}), FLEETS)
    got = _hook_ids(scoped.read_verdicts(f"{DAY}T00:00:00Z", scoped.orgs))
    assert got == {"hook-2"}
    days = _hook_ids(r for _, records in scoped.read_verdict_days(
        f"{DAY}T00:00:00Z", scoped.orgs) for r in records)
    assert days == {"hook-2"}


def test_the_join_is_the_same_whoever_reads(store):
    """A dev viewer reads no prod partition, yet session 4 stays pending for
    them, because the join reads every org's OTel records."""
    reader = attribution.AttributedStore(store)
    assert reader.joins(None)[_sid(4)] == ""
    assert _events(store, frozenset({DEV})) == {"hook-2"}


def test_a_code_hook_record_in_an_org_does_not_create_a_join(tmp_path):
    """A single-org fleet's laptop can write code_hook records under prod
    with any session id. Only the collector's records join."""
    s = LocalFileStore(tmp_path / "s", instance="t")
    s.write_verdicts([_hook(8), _hook(8, fleet_orgs=(), tenant=PROD, action="allow")])
    assert _events(s, frozenset({PROD})) == {"hook-8"}
    reader = attribution.AttributedStore(s)
    assert _sid(8) not in reader.joins(None)
    records = list(reader.read_verdicts(None, None))
    assert {r.tenant_hash for r in records if r.fleet_orgs} == {FLEET}


def test_a_session_id_that_is_not_a_uuid_never_joins(tmp_path):
    s = LocalFileStore(tmp_path / "s", instance="t")
    s.write_verdicts([
        VerdictRecord(source=SOURCE_CODE_HOOK, session_id="sess_abc", tenant_hash=FLEET,
                      fleet_orgs=[DEV, PROD], request_id="h", observed_at=f"{DAY}T10:00:00Z"),
        VerdictRecord(source=SOURCE_OTEL_COLLECT, session_id="sess_abc", tenant_hash=PROD,
                      surface="claude-code", observed_at=f"{DAY}T09:00:00Z")])
    assert _events(s, frozenset({PROD})) == set()


def test_an_export_just_before_the_window_still_joins(tmp_path):
    s = LocalFileStore(tmp_path / "s", instance="t")
    s.write_verdicts([_hook(9), _otel(9, DEV, when="2026-10-04T20:00:00Z")])
    assert _events(s, frozenset({DEV})) == {"hook-9"}


def test_sessions_past_the_join_bound_stay_pending(tmp_path, monkeypatch):
    monkeypatch.setattr(attribution, "MAX_JOINED_SESSIONS", 1)
    s = LocalFileStore(tmp_path / "s", instance="t")
    s.write_verdicts([_otel(10, DEV), _otel(11, DEV, when=f"{DAY}T09:30:00Z"),
                      _hook(10), _hook(11)])
    joined = attribution.AttributedStore(s).joins(None)
    assert len(joined) == 1
    assert len(_events(s, frozenset({DEV}))) == 1


def test_a_record_still_pending_is_not_visible_through_its_own_partition_name_alone():
    rec = _hook(3)
    assert not visible(rec, frozenset({PROD}))
    assert visible(rec, frozenset({PROD, DEV}))
    assert visible(rec, None)
    assert not visible(_hook(3, fleet_orgs=()), frozenset({PROD, DEV}))


def test_a_single_org_store_reads_the_store_once(tmp_path):
    reads = []

    class Counting(LocalFileStore):
        def read_verdicts(self, *a, **kw):
            reads.append(kw.get("sources"))
            return super().read_verdicts(*a, **kw)

    s = Counting(tmp_path / "s", instance="t")
    s.write_verdicts([_hook(1, fleet_orgs=(), tenant=PROD), _otel(1, PROD)])
    read_summary(s, None, frozenset({PROD}), fleets={})
    assert reads == [None]


def test_a_fleet_store_reads_only_otel_partitions_for_the_join(tmp_path):
    reads = []

    class Counting(LocalFileStore):
        def read_verdicts(self, since=None, orgs=None, sources=None):
            reads.append(sources)
            return super().read_verdicts(since, orgs, sources)

    s = Counting(tmp_path / "s", instance="t")
    s.write_verdicts([_hook(2), _otel(2, DEV)])
    read_summary(s, None, frozenset({DEV}), fleets=FLEETS)
    # The join first: it decides whether a fleet bound to dev and prod can
    # hold a row a dev viewer may see.
    assert reads == [(SOURCE_OTEL_COLLECT,), None]


async def test_the_dashboard_refuses_a_fleet_partition_to_an_entitled_viewer(tmp_path):
    from test_intake_entitlements import _dashboard, _raw

    from forgd_verdict.entitlements import Principal
    from forgd_verdict.policy import Policy

    dash = _dashboard(tmp_path, Principal("olu", ("g-org",)), Policy(raw=_raw()))
    status, _ = await ASGIClient(dash).get(f"/events?org={FLEET}")
    assert status == 403


def test_the_event_log_marks_a_pending_record_and_not_a_joined_one(store):
    from forgd_verdict.dashboard.render import render_events

    page = event_page(store, f"{DAY}T00:00:00Z", None).records
    pending = [r for r in page if r.request_id == "hook-3"]
    joined = [r for r in page if r.request_id == "hook-1"]
    assert "org pending" in render_events(pending)
    assert "org pending" not in render_events(joined)


def test_the_connector_names_a_fleet_partition_as_pending():
    from forgd_verdict.connector.tools import Caller, Reader

    caller = Caller.__new__(Caller)
    caller.reader = Reader.__new__(Reader)
    caller.reader.org_labels = {}
    assert caller.org(FLEET)["kind"] == "fleet_pending"
