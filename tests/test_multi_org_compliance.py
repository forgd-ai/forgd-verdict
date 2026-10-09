"""Adapter 3 across several of a customer's orgs.

The Compliance Access Key IS the organization: it is minted inside one org
and reads only that one. So N orgs is N keys, and the interesting failures
are about keeping their state and their errors apart.
"""

from __future__ import annotations

import json

import pytest

from forgd_verdict.compliance.ingest import run_ingest
from forgd_verdict.policy import Policy
from forgd_verdict.store.base import pseudonym
from forgd_verdict.store.local import LocalFileStore

SALT = "s"


def policy_with(orgs, registry=None, **compliance):
    return Policy(raw={
        "privacy": {"hash_salt": SALT},
        "orgs": registry or [],
        "detectors": {},
        "compliance": {"orgs": orgs, **compliance},
    })


# --- resolution ----------------------------------------------------------


def test_each_org_gets_its_own_cursor_file_by_default():
    orgs = policy_with([
        {"id": "org-a", "api_key": "k-a"},
        {"id": "org-b", "api_key": "k-b"},
    ]).compliance_orgs()
    paths = [o["state_path"] for o in orgs]
    assert len(set(paths)) == 2, paths
    assert all(p != "./compliance-state.json" for p in paths)


def test_two_orgs_sharing_a_cursor_file_is_refused():
    """Silent data loss otherwise: a pass that fails midway advances
    `last_run_started_at` for an org it never scanned, and those sessions
    are never looked at again. Nothing would report it."""
    policy = policy_with([
        {"id": "org-a", "api_key": "k-a", "state_path": "./shared.json"},
        {"id": "org-b", "api_key": "k-b", "state_path": "./shared.json"},
    ])
    with pytest.raises(ValueError, match="share state_path"):
        policy.compliance_orgs()


def test_an_org_with_no_key_is_skipped_not_fatal():
    """A deployment that has onboarded one org of three should scan the
    one."""
    orgs = policy_with([
        {"id": "org-a", "api_key": "k-a"},
        {"id": "org-b"},
    ]).compliance_orgs()
    assert [o["id"] for o in orgs] == ["org-a"]


def test_the_single_org_form_still_works_and_keeps_its_cursor_file():
    """The single-org form needs no change to the policy, and its cursor
    file keeps its name -- a new name looks like a first run and rescans
    every session in the org."""
    policy = Policy(raw={
        "privacy": {"hash_salt": SALT},
        "compliance": {
            "org_id": "org-legacy",
            "api_key": "k",
            "state_path": "./compliance-state.json",
        },
    })
    orgs = policy.compliance_orgs()
    assert len(orgs) == 1
    assert orgs[0]["id"] == "org-legacy"
    assert orgs[0]["state_path"] == "./compliance-state.json"


def test_labels_come_from_the_registry_not_the_credentials_block():
    """One place names an org. Two would be free to disagree."""
    policy = policy_with(
        [{"id": "org-a", "api_key": "k"}],
        registry=[{"id": "org-a", "label": "Prod EU"}],
    )
    assert policy.compliance_orgs()[0]["label"] == "Prod EU"


# --- the pass ------------------------------------------------------------


class FakeScanner:
    """Stands in for ComplianceScanner. Fails for whichever org says so."""

    failing: set[str] = set()
    seen: list[str] = []
    detectors: tuple = ()
    sessions_failed = 0
    chats_failed = 0

    def __init__(self, policy, org=None, client=None, store=None, detectors=None):
        org = org or {}
        self.org_id = str(org.get("id") or "")
        self.org_label = str(org.get("label") or self.org_id)
        FakeScanner.seen.append(self.org_id)
        if self.org_id in FakeScanner.failing:
            raise RuntimeError("401 from the Compliance API")

    def scan_sessions(self, **kw):
        from forgd_verdict.compliance.scanner import SessionReport

        yield SessionReport(
            session_id=f"s-{self.org_id}",
            product_surface="claude-code",
            user_id=f"u-{self.org_id}",
            created_at="2026-09-19T00:00:00Z",
            updated_at="2026-09-19T00:00:00Z",
            action="allow",
        )

    def scan_chats(self, **kw):
        return iter(())

    def denials(self, **kw):
        return iter(())

    def extract_reference_id(self, activity):
        return None

    def commit(self):
        pass


@pytest.fixture
def fake_scanner(monkeypatch):
    import forgd_verdict.compliance.ingest as mod

    FakeScanner.failing = set()
    FakeScanner.seen = []
    monkeypatch.setattr(mod, "ComplianceScanner", FakeScanner)
    return FakeScanner


def test_every_org_is_scanned_and_stamped_with_its_own_pseudonym(
    fake_scanner, tmp_path
):
    store = LocalFileStore(tmp_path, instance="t")
    policy = policy_with([
        {"id": "org-a", "api_key": "k-a"},
        {"id": "org-b", "api_key": "k-b"},
    ])
    summary = run_ingest(policy, store, include_denials=False, include_chats=False)

    assert summary["orgs_configured"] == 2
    assert summary["orgs_scanned"] == 2
    assert summary["orgs_failed"] == 0
    assert summary["sessions_scanned"] == 2

    hashes = {r.tenant_hash for r in store.read_verdicts()}
    assert hashes == {pseudonym("org-a", SALT, "org"), pseudonym("org-b", SALT, "org")}
    # And each lands in its own partition.
    paths = [str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*.jsonl")]
    assert len(paths) == 2


def test_one_org_failing_does_not_abandon_the_rest(fake_scanner, tmp_path):
    """A key expiring on one org is the expected failure over time. A pass
    that scanned two of three and reported success would be worse than a
    crash, because nobody would look."""
    store = LocalFileStore(tmp_path, instance="t")
    fake_scanner.failing = {"org-b"}
    policy = policy_with([
        {"id": "org-a", "api_key": "k-a"},
        {"id": "org-b", "api_key": "k-b"},
        {"id": "org-c", "api_key": "k-c"},
    ])
    summary = run_ingest(policy, store, include_denials=False, include_chats=False)

    assert fake_scanner.seen == ["org-a", "org-b", "org-c"]
    assert summary["orgs_scanned"] == 2
    assert summary["orgs_failed"] == 1
    assert summary["sessions_scanned"] == 2

    failed = [o for o in summary["orgs"] if not o["ok"]]
    assert len(failed) == 1
    assert "RuntimeError" in failed[0]["error"]
    # The summary is logged as JSON, so it has to survive serialisation.
    json.dumps(summary, default=str)


def test_orgs_are_scanned_serially_in_configuration_order(fake_scanner, tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    policy = policy_with([
        {"id": f"org-{n}", "api_key": f"k-{n}"} for n in ("a", "b", "c")
    ])
    run_ingest(policy, store, include_denials=False, include_chats=False)
    assert fake_scanner.seen == ["org-a", "org-b", "org-c"]


def test_no_orgs_configured_is_an_empty_pass_not_a_crash(fake_scanner, tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    summary = run_ingest(policy_with([]), store,
                         include_denials=False, include_chats=False)
    assert summary["orgs_configured"] == 0
    assert summary["sessions_scanned"] == 0


# --- the cursor has to outlive the run ------------------------------------


def test_the_cursor_survives_a_replica_when_a_store_is_given(tmp_path):
    """The bug this closes: the ingest job is a scheduled Container Apps
    Job, its replica is destroyed when the pass finishes, and the cursor
    was written to the container filesystem. So every six-hourly pass
    re-walked the same window -- repeating Compliance API calls and
    Presidio compute and appending duplicate records.

    `latest_per_session` collapses those duplicates on the dashboard, so
    nothing there shows them.
    """
    from forgd_verdict.compliance.scanner import State

    store = LocalFileStore(tmp_path / "store", instance="run-1")
    first = State("./compliance-state.json", store=store)
    first.data["last_run_started_at"] = "2026-09-19T10:00:00Z"
    first.save()

    # A new replica: nothing of the previous one's filesystem remains.
    second = State("./compliance-state.json", store=LocalFileStore(
        tmp_path / "store", instance="run-2"))
    assert second.data["last_run_started_at"] == "2026-09-19T10:00:00Z"


def test_a_store_backed_cursor_writes_nothing_to_the_filesystem(tmp_path, monkeypatch):
    from forgd_verdict.compliance.scanner import State

    monkeypatch.chdir(tmp_path)
    State("./compliance-state.json",
          store=LocalFileStore(tmp_path / "store", instance="t")).save()
    assert not (tmp_path / "compliance-state.json").exists()


def test_each_org_keeps_its_own_cursor_in_the_store(tmp_path):
    """Two orgs sharing one is silent data loss: a pass that fails midway
    advances the cursor for an org it never scanned."""
    from forgd_verdict.compliance.scanner import State

    store = LocalFileStore(tmp_path / "store", instance="t")
    a = State("./state/org-a.json", store=store)
    a.data["last_run_started_at"] = "A"
    a.save()
    b = State("./state/org-b.json", store=store)
    b.data["last_run_started_at"] = "B"
    b.save()

    assert State("./state/org-a.json", store=store).data["last_run_started_at"] == "A"
    assert State("./state/org-b.json", store=store).data["last_run_started_at"] == "B"


def test_a_corrupt_cursor_rescans_rather_than_skipping(tmp_path):
    """Re-scanning is wasteful and safe. Trusting a half-parsed cursor
    would skip sessions, which is neither."""
    from forgd_verdict.compliance.scanner import State

    store = LocalFileStore(tmp_path / "store", instance="t")
    store.put_state("compliance-state.json", b'{"last_run_started_at": "2026')
    assert State("./compliance-state.json", store=store).data[
        "last_run_started_at"] is None


def test_a_file_cursor_still_works_without_a_store(tmp_path):
    """Local runs and tests keep a file cursor."""
    from forgd_verdict.compliance.scanner import State

    path = str(tmp_path / "state.json")
    first = State(path)
    first.data["activities_cursor"] = "abc"
    first.save()
    assert State(path).data["activities_cursor"] == "abc"


# -- the run marker the dashboard reads ----------------------------------


def test_the_dashboard_looks_for_the_key_the_scanner_writes(tmp_path, monkeypatch):
    """The drift this would fail as.

    `compliance_state_keys()` exists because the dashboard is given no
    Compliance Access Key and so cannot go through `compliance_orgs()`.
    That means two derivations of one key. If they part, the dashboard
    reads a cursor nobody writes, finds nothing, and silently goes back
    to inferring liveness from records -- which is the bug, returned,
    with every test still green.
    """
    from forgd_verdict.compliance.scanner import ComplianceScanner

    monkeypatch.setenv("ORG_A_KEY", "sk-ant-admin-a")
    monkeypatch.setenv("ORG_B_KEY", "sk-ant-admin-b")
    policy = Policy(raw={"privacy": {"hash_salt": "t"}, "detectors": {},
                         "compliance": {"orgs": [
        {"id": "org-a", "api_key": "$ORG_A_KEY"},
        {"id": "org-b", "api_key": "$ORG_B_KEY",
         "state_path": "./cursor-b.json"},
    ]}})

    advertised = policy.compliance_state_keys()
    written = [
        ComplianceScanner(policy, client=object(), org=org,
                          store=LocalFileStore(str(tmp_path))).state.key
        for org in policy.compliance_orgs()
    ]
    assert sorted(advertised) == sorted(written)
    # And the derived name really is per-org, or two orgs share a cursor.
    assert len(set(advertised)) == 2


def test_the_marker_survives_a_pass_that_found_nothing(tmp_path):
    """What makes it usable as a heartbeat at all."""
    import json as _json

    from forgd_verdict.compliance.scanner import RUN_MARKER, State, last_run_at

    store = LocalFileStore(str(tmp_path))
    state = State("./compliance-state.json", store=store)
    state.data[RUN_MARKER] = "2026-09-21T12:00:25Z"
    state.save()

    assert last_run_at(store, "compliance-state.json") == "2026-09-21T12:00:25Z"
    # Nothing in the blob but the marker and empty cursors -- no session
    # was scanned and no verdict was written.
    raw = _json.loads(store.get_state("compliance-state.json"))
    assert raw["sessions"] == {} and raw["activities_cursor"] is None


def test_an_unreadable_cursor_does_not_take_the_dashboard_down():
    """No marker degrades to the old behaviour; it must not raise."""
    from forgd_verdict.compliance.scanner import last_run_at

    class Broken:
        def get_state(self, name):
            raise RuntimeError("storage account unreachable")

    class Garbage:
        def get_state(self, name):
            return b"{not json"

    assert last_run_at(Broken(), "k") is None
    assert last_run_at(Garbage(), "k") is None
    assert last_run_at(None, "k") is None


@pytest.mark.parametrize("org_id", ["$FORGD_ORG_ID_UNSET_FOR_TEST", ""])
def test_an_org_with_a_key_and_no_resolved_id_is_refused(monkeypatch, org_id):
    """With its id unset, an entry fell back to the single-org cursor
    `./compliance-state.json`: after a move from the single-org form that is
    another org's cursor, and every session before it goes unscanned."""
    monkeypatch.delenv("FORGD_ORG_ID_UNSET_FOR_TEST", raising=False)
    policy = policy_with([
        {"id": "org-a", "api_key": "k-a"},
        {"id": org_id, "api_key": "k-b", "label": "Dev"},
    ])
    with pytest.raises(ValueError, match="no id") as exc:
        policy.compliance_orgs()
    if org_id:
        assert "FORGD_ORG_ID_UNSET_FOR_TEST" in str(exc.value)


def test_an_org_with_no_key_and_no_resolved_id_is_still_skipped(monkeypatch):
    monkeypatch.delenv("FORGD_ORG_ID_UNSET_FOR_TEST", raising=False)
    orgs = policy_with([
        {"id": "org-a", "api_key": "k-a"},
        {"id": "$FORGD_ORG_ID_UNSET_FOR_TEST"},
    ]).compliance_orgs()
    assert [o["id"] for o in orgs] == ["org-a"]


@pytest.mark.parametrize("command", [["ingest", "--store", "STORE"], ["compliance"]])
def test_the_cli_reports_an_org_with_no_id_without_a_traceback(tmp_path, monkeypatch,
                                                              capsys, command):
    from forgd_verdict.cli import main

    monkeypatch.delenv("FORGD_ORG_ID_UNSET_FOR_TEST", raising=False)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "privacy": {"hash_salt": SALT},
        "compliance": {"orgs": [{"id": "$FORGD_ORG_ID_UNSET_FOR_TEST",
                                 "api_key": "k-a", "label": "Prod"}]}}))
    argv = [str(tmp_path / "store") if a == "STORE" else a for a in command]
    code = main(["--policy", str(path), *argv])
    err = capsys.readouterr().err
    assert code == 2
    assert "FORGD_ORG_ID_UNSET_FOR_TEST is unset" in err
    assert "Traceback" not in err


@pytest.mark.parametrize("a, b", [
    ("./prod/cursor.json", "./dev/cursor.json"),
    ("/var/a/cursor.json", "cursor.json"),
    ("./prod/Cursor.json", "./dev/cursor.json"),
])
def test_two_orgs_whose_cursors_share_a_store_key_are_refused(a, b):
    """The store keys a cursor by the state_path's file name, so paths that
    differ only by directory, or by case, are one cursor."""
    policy = policy_with([
        {"id": "org-a", "api_key": "k-a", "state_path": a},
        {"id": "org-b", "api_key": "k-b", "state_path": b},
    ])
    with pytest.raises(ValueError, match="share state_path file name"):
        policy.compliance_orgs()


def test_every_accepted_org_has_its_own_store_key():
    """Standing: whatever compliance_orgs accepts, no two orgs' cursors are
    one store object."""
    from forgd_verdict.compliance.scanner import State

    policy = policy_with([
        {"id": "org-a", "api_key": "k-a", "state_path": "./a/one.json"},
        {"id": "org-b", "api_key": "k-b"},
        {"id": "org-c", "api_key": "k-c", "state_path": "./c/two.json"},
    ])
    keys = [State(o["state_path"]).key.lower() for o in policy.compliance_orgs()]
    assert len(keys) == len(set(keys)) == 3
