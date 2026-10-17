"""Store round-trips, aggregation, and the privacy invariant end-to-end."""

from __future__ import annotations

import json

import pytest
from conftest import FAKE_AWS_KEY, FAKE_SSN, WHSEC, ASGIClient, frame, make_policy, sign, text_msg

from forgd_verdict.models import Finding, pseudonym
from forgd_verdict.server.app import VerdictServer
from forgd_verdict.store import (
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    DenialRecord,
    FindingRow,
    LocalFileStore,
    VerdictRecord,
    build_summary,
)
from forgd_verdict.store.base import SOURCE_CODE_HOOK
from forgd_verdict.store.query import detector_family, families


def rec(source=SOURCE_INFERENCE_HOOK, action="allow", surface="claude-ai",
        findings=(), day="2026-09-17", **kw) -> VerdictRecord:
    return VerdictRecord(
        source=source,
        observed_at=f"{day}T10:00:00Z",
        surface=surface,
        action=action,
        findings=list(findings),
        findings_count=len(findings),
        **kw,
    )


def test_write_read_round_trip(tmp_path):
    store = LocalFileStore(tmp_path, instance="t1")
    assert store.write_verdicts([rec(), rec(action="deny")]) == 2
    back = list(store.read_verdicts())
    assert len(back) == 2
    assert {r.action for r in back} == {"allow", "deny"}


def test_records_are_partitioned_by_source_org_and_date(tmp_path):
    store = LocalFileStore(tmp_path, instance="t1")
    store.write_verdicts([
        rec(day="2026-09-16"),
        rec(day="2026-09-17"),
        rec(source=SOURCE_COMPLIANCE_SCAN, day="2026-09-17"),
    ])
    paths = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*.jsonl"))
    assert any("source=inference_hook/org=unattributed/date=2026-09-16" in p for p in paths)
    assert any("source=inference_hook/org=unattributed/date=2026-09-17" in p for p in paths)
    assert any("source=compliance_scan/org=unattributed/date=2026-09-17" in p for p in paths)


def test_a_batch_spanning_orgs_is_split_into_one_object_per_org(tmp_path):
    """A cross-org object would defeat pruning for every reader, and would
    mean an org-scoped read had to open and filter other orgs' data."""
    store = LocalFileStore(tmp_path, instance="t1")
    store.write_verdicts([
        rec(day="2026-09-17", tenant_hash="org_aaa"),
        rec(day="2026-09-17", tenant_hash="org_bbb"),
        rec(day="2026-09-17"),
    ])
    paths = [str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*.jsonl")]
    assert len(paths) == 3
    assert any("org=org_aaa" in p for p in paths)
    assert any("org=org_bbb" in p for p in paths)
    assert any("org=unattributed" in p for p in paths)
    assert [r.tenant_hash for r in store.read_verdicts(orgs={"org_aaa"})] == ["org_aaa"]
    # A viewer entitled to two orgs reads both partitions and no others.
    both = {r.tenant_hash for r in store.read_verdicts(orgs={"org_aaa", "org_bbb"})}
    assert both == {"org_aaa", "org_bbb"}


def test_since_prunes_by_partition(tmp_path):
    store = LocalFileStore(tmp_path, instance="t1")
    store.write_verdicts([rec(day="2026-09-01"), rec(day="2026-09-17")])
    assert len(list(store.read_verdicts(since="2026-09-10"))) == 1
    assert len(list(store.read_verdicts())) == 2


def test_two_writer_instances_never_collide(tmp_path):
    a, b = LocalFileStore(tmp_path, instance="a"), LocalFileStore(tmp_path, instance="b")
    for _ in range(5):
        a.write_verdicts([rec()])
        b.write_verdicts([rec()])
    assert len(list(a.read_verdicts())) == 10, "both writers' records must be readable"


def test_unknown_fields_from_a_newer_writer_are_tolerated(tmp_path):
    """The store is append-only and objects are immutable, so a reader will
    meet records it was not compiled against."""
    store = LocalFileStore(tmp_path, instance="t1")
    store.write_verdicts([rec()])
    path = next(tmp_path.rglob("*.jsonl"))
    raw = json.loads(path.read_text().strip())
    raw["some_future_field"] = {"nested": True}
    path.write_text(json.dumps(raw) + "\n")
    back = list(store.read_verdicts())
    assert len(back) == 1 and back[0].surface == "claude-ai"


def test_torn_line_does_not_kill_a_read(tmp_path):
    store = LocalFileStore(tmp_path, instance="t1")
    store.write_verdicts([rec(), rec()])
    path = next(tmp_path.rglob("*.jsonl"))
    path.write_text(path.read_text() + '{"source":"inference_hook","obse')
    assert len(list(store.read_verdicts())) == 2


# -- aggregation -----------------------------------------------------------


def test_shadow_deny_counts_as_a_deny_for_analysis():
    """Only enforcement differed; the policy still reached a deny."""
    s = build_summary([
        rec(action="allow", shadow_action="deny"),
        rec(action="allow"),
    ])
    assert s.would_deny == 1
    assert s.enforced_deny == 0
    assert s.deny_rate == 0.5


def test_distinct_values_not_occurrences():
    """One key pasted repeatedly is one exposure."""
    f = FindingRow("regex:aws-access-key", "block", "msg[0]", "hash-a")
    s = build_summary([rec(findings=[f]) for _ in range(40)])
    assert s.total_findings == 40
    assert s.distinct_values == 1
    assert s.detectors[0].unique == 1
    assert s.detectors[0].count == 40


def test_detector_families_collapse_both_tiers():
    """T0 and T1 fire on the same value; counting raw ids double-counts."""
    assert detector_family("regex:aws-access-key") == "aws"
    assert detector_family("gitleaks:aws-access-token") == "aws"
    s = build_summary([rec(findings=[
        FindingRow("regex:aws-access-key", "block", "m", "h1"),
        FindingRow("gitleaks:aws-access-token", "block", "m", "h1"),
    ])])
    assert dict(families(s)) == {"aws": 1}, "one value, one family, counted once"


def test_reconciliation_counts_what_the_live_path_missed():
    live = rec(source=SOURCE_INFERENCE_HOOK,
               findings=[FindingRow("regex:ssn", "block", "m", "seen")])
    post = rec(source=SOURCE_COMPLIANCE_SCAN, action="deny", surface="claude_code",
               findings=[FindingRow("regex:ssn", "block", "m", "seen"),
                         FindingRow("regex:pan", "block", "m", "missed")])
    recon = build_summary([live, post]).reconciliation
    assert recon.live_requests == 1
    assert recon.scanned_sessions == 1
    assert recon.missed_count == 1, "one value found post-hoc and never seen live"


def test_denials_join_by_request_id_then_by_reference_id():
    """A denial matches a live verdict by Anthropic's request id; one with
    no request id falls back to the reference id the verdict returned; one
    matching neither is unmatched, however it is labelled. Mutation: count
    a denial that carries a reference id as joined without matching it."""
    live = [rec(action="deny", request_id="req_1", reference_id="fv_x_01"),
            rec(action="deny", request_id="req_2", reference_id="fv_x_02")]
    recon = build_summary(live, [
        DenialRecord("a1", "2026-09-17T10:00:00Z", request_id="req_1"),
        DenialRecord("a2", "2026-09-17T10:00:00Z", request_id="req_2", reference_id="fv_x_02"),
        DenialRecord("a3", "2026-09-17T10:00:00Z", reference_id="fv_x_01"),
        DenialRecord("a4", "2026-09-17T10:00:00Z", request_id="req_9", reference_id="fv_x_09"),
        DenialRecord("a5", "2026-09-17T10:00:00Z"),
    ]).reconciliation
    assert recon.denial_activities == 5
    assert recon.joined_by_request_id == 2
    assert recon.joined_by_reference == 1
    assert recon.denials_unmatched == 2
    assert recon.denials_without_reference == 2


def test_only_inference_hook_verdicts_are_joined_to():
    """Mutation: collect the ids of every verdict."""
    recon = build_summary([rec(source=SOURCE_CODE_HOOK, request_id="req_1")], [
        DenialRecord("a1", "2026-09-17T10:00:00Z", request_id="req_1"),
    ]).reconciliation
    assert recon.denials_unmatched == 1 and recon.joined_by_request_id == 0


def test_a_tool_call_denial_is_counted_and_an_absent_event_is_a_prompt():
    recon = build_summary([], [
        DenialRecord("a1", "2026-09-17T10:00:00Z", event="tool_call"),
        DenialRecord("a2", "2026-09-17T10:00:00Z", event="prompt"),
        DenialRecord("a3", "2026-09-17T10:00:00Z"),
    ]).reconciliation
    assert recon.denials_tool_call == 1


def test_a_denial_stored_before_request_id_and_event_reads_back():
    old = json.dumps({"activity_id": "a1", "created_at": "2026-09-17T10:00:00Z",
                      "reference_id": "fv_x_01", "schema_version": 1})
    d = DenialRecord.from_json(old)
    assert (d.request_id, d.event, d.reference_id) == (None, None, "fv_x_01")


def test_empty_store_summarizes_without_error():
    s = build_summary([], [])
    assert s.total_requests == 0 and s.deny_rate is None and s.latency["p95"] == 0.0


# -- privacy ---------------------------------------------------------------


def test_pseudonyms_are_stable_and_not_reversible():
    a = pseudonym("user_01ABC", "salt", "user")
    assert a == pseudonym("user_01ABC", "salt", "user")
    assert a != pseudonym("user_01XYZ", "salt", "user")
    assert "user_01ABC" not in a
    assert a.startswith("user_")


def test_pseudonym_of_none_is_none():
    assert pseudonym(None) is None and pseudonym("") is None


async def test_no_secret_reaches_the_store(tmp_path):
    """The store is a sink like the logs and the CSV; the same rule applies."""
    store = LocalFileStore(tmp_path / "findings", instance="t1")
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": None},
    )
    server = VerdictServer(policy, store=store)
    try:
        raw = __import__("json").dumps(
            frame([text_msg(f"key {FAKE_AWS_KEY} ssn {FAKE_SSN}")])
        ).encode()
        status, verdict = await ASGIClient(server).post("/hook", raw, sign(raw))
        assert status == 200 and verdict["action"] == "deny"
    finally:
        server.close()  # joins the sink thread and flushes

    written = "".join(p.read_text() for p in (tmp_path / "findings").rglob("*.jsonl"))
    assert written, "the sink should have written a record"
    for secret in (FAKE_AWS_KEY, FAKE_SSN):
        assert secret not in written, f"{secret} leaked into the store"
    record = VerdictRecord.from_json(written.splitlines()[0])
    assert record.action == "deny"
    assert record.findings_count >= 2
    assert {f.detector for f in record.findings} >= {"regex:aws-access-key", "regex:ssn"}
    assert all(len(f.excerpt_hash) == 64 for f in record.findings)


async def test_a_store_outage_never_breaks_a_verdict(tmp_path):
    """A storage failure must not become a webhook failure."""

    class BrokenStore:
        def write_verdicts(self, records):
            raise OSError("storage is down")

        def write_denials(self, records):
            raise OSError("storage is down")

        def describe(self):
            return {"backend": "broken"}

    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": None},
    )
    server = VerdictServer(policy, store=BrokenStore())
    try:
        raw = __import__("json").dumps(frame()).encode()
        status, verdict = await ASGIClient(server).post("/hook", raw, sign(raw))
        assert status == 200 and verdict["action"] == "allow"
    finally:
        server.close()
    assert server.sink.errors >= 1 or server.sink.dropped >= 1


def test_findings_convert_from_core_findings():
    row = FindingRow.from_finding(
        Finding("regex:ssn", "block", "msg[0]", "abc123", "Bash")
    )
    assert (row.detector, row.severity, row.tool_name) == ("regex:ssn", "block", "Bash")


def test_surface_names_are_normalized_across_adapters():
    """Adapter 1 sends `claude-code`; adapter 3 sends `claude_code`. Left
    alone the dashboard reports one surface twice and overstates coverage."""
    from forgd_verdict.store.query import normalize_surface

    assert normalize_surface("claude_code") == "claude-code"
    assert normalize_surface("claude-code") == "claude-code"
    assert normalize_surface("cowork_remote") == "cowork"
    assert normalize_surface("office_agents/excel") == "claude-for-m365"
    assert normalize_surface("office_agents") == "claude-for-m365"
    assert normalize_surface(None) == "unknown"
    # An unrecognized future surface passes through, hyphenated.
    assert normalize_surface("claude_in_some_new_thing") == "claude-in-some-new-thing"

    s = build_summary([
        rec(source=SOURCE_INFERENCE_HOOK, surface="claude-code"),
        rec(source=SOURCE_COMPLIANCE_SCAN, surface="claude_code"),
    ])
    assert len(s.surfaces) == 1, [r.surface for r in s.surfaces]
    assert s.surfaces[0].requests == 2


def test_surfaces_without_latency_report_none_not_zero():
    """Adapter 3 records have no round trip; 0 ms would read as instant."""
    s = build_summary([
        rec(source=SOURCE_COMPLIANCE_SCAN, surface="claude_code"),
        rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai", total_ms=480.0),
    ])
    by = {r.surface: r for r in s.surfaces}
    assert by["claude-code"].has_latency is False
    assert by["claude-code"].p95 is None
    assert by["claude-ai"].p95 == 480.0


def test_m365_lands_on_one_surface_across_three_conventions():
    """Claude for Microsoft 365 arrives three different ways: the Compliance
    API sends `office_agents` and `office_agents/<app>`, and the inference
    hook sends `sheet_agent` -- undocumented, and underscored where every
    documented source.application value is hyphenated. All must collapse to
    one surface or the dashboard reports the same product twice."""
    from forgd_verdict.store.query import normalize_surface

    for raw in ("office_agents", "office_agents/word", "office_agents/excel",
                "sheet_agent", "doc_agent", "slide_agent", "mail_agent"):
        assert normalize_surface(raw) == "claude-for-m365", raw

    s = build_summary([
        rec(source=SOURCE_INFERENCE_HOOK, surface="sheet_agent"),
        rec(source=SOURCE_COMPLIANCE_SCAN, surface="office_agents/word"),
    ])
    assert len(s.surfaces) == 1
    assert s.surfaces[0].surface == "claude-for-m365"
    assert s.surfaces[0].requests == 2


def test_rescanned_sessions_are_counted_once():
    """The ingest job re-walks active sessions and the store is append-only,
    so a session in use accumulates a record per run. Counting them all
    would report one session as several."""
    from forgd_verdict.store.query import latest_per_session

    runs = [
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T10:00:00Z",
                      session_id="clls_1", surface="claude_code", messages_total=20),
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T16:00:00Z",
                      session_id="clls_1", surface="claude_code", messages_total=40),
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T22:00:00Z",
                      session_id="clls_1", surface="claude_code", messages_total=95),
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T11:00:00Z",
                      session_id="clls_2", surface="claude_code", messages_total=5),
    ]
    kept = latest_per_session(runs)
    assert len(kept) == 2
    # The most recent observation wins, so message counts are not understated.
    by_id = {r.session_id: r for r in kept}
    assert by_id["clls_1"].messages_total == 95

    s = build_summary(runs)
    assert s.total_requests == 2
    assert s.reconciliation.scanned_sessions == 2


def test_inference_hook_records_are_never_collapsed():
    """One record per request. Two requests in a session are two requests."""
    from forgd_verdict.store.query import latest_per_session

    rows = [
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:00:00Z",
                      session_id="sess-1", surface="claude-ai"),
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:00:05Z",
                      session_id="sess-1", surface="claude-ai"),
    ]
    assert len(latest_per_session(rows)) == 2
    assert build_summary(rows).total_requests == 2


def test_compliance_records_without_a_session_id_survive():
    from forgd_verdict.store.query import latest_per_session

    rows = [
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T10:00:00Z",
                      session_id=None, surface="claude_code"),
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T10:00:01Z",
                      session_id=None, surface="claude_code"),
    ]
    assert len(latest_per_session(rows)) == 2


def test_reset_marker_moves_the_floor_without_deleting(tmp_path):
    """A period of testing pollutes every aggregate. The fix is a clean
    slate, not a caveat nobody reads -- and it must not destroy the audit
    trail to get one."""
    from forgd_verdict.store.query import effective_since

    store = LocalFileStore(tmp_path, instance="t")
    store.write_verdicts([
        rec(day="2026-09-17", findings=[FindingRow("regex:ssn", "block", "m", "h1")]),
        rec(day="2026-09-18"),
    ])
    assert store.get_reset_marker() is None
    assert build_summary(store.read_verdicts()).total_requests == 2

    store.set_reset_marker("2026-09-18T00:00:00Z")
    assert store.describe()["reset_at"] == "2026-09-18T00:00:00Z"

    since = effective_since(None, store.get_reset_marker())
    assert build_summary(store.read_verdicts(since), since=since).total_requests == 1
    # The records are still there.
    assert len(list(store.read_verdicts())) == 2


def test_reset_marker_wins_over_a_wider_window(tmp_path):
    """Selecting 'all time' must not reach back past a reset."""
    from forgd_verdict.store.query import effective_since

    assert effective_since(None, "2026-09-18T00:00:00Z") == "2026-09-18T00:00:00Z"
    assert effective_since("2026-09-10T00:00:00Z", "2026-09-18T00:00:00Z") == (
        "2026-09-18T00:00:00Z"
    )
    # A narrower window than the reset still wins, because it is later.
    assert effective_since("2026-09-20T00:00:00Z", "2026-09-18T00:00:00Z") == (
        "2026-09-20T00:00:00Z"
    )
    assert effective_since(None, None) is None


def test_reset_marker_can_be_cleared(tmp_path):
    store = LocalFileStore(tmp_path, instance="t")
    store.set_reset_marker("2026-09-18T00:00:00Z")
    store.set_reset_marker("")
    assert store.get_reset_marker() is None


def test_a_post_hoc_scan_cannot_deny_anything():
    """Category error worth a test. By the time the Compliance API reads a
    transcript, inference has already happened and the response has gone
    back -- there is nothing left to prevent. Counting its findings as
    "would deny" reports a block that was never possible, and conflates
    detection with prevention."""
    live_deny = rec(source=SOURCE_INFERENCE_HOOK, action="allow",
                    findings=[FindingRow("regex:ssn", "block", "m", "h1")])
    live_deny.shadow_action = "deny"
    post_hoc = rec(source=SOURCE_COMPLIANCE_SCAN, surface="claude_code",
                   findings=[FindingRow("regex:pan", "block", "m", "h2")])
    post_hoc.session_id = "clls_1"

    assert live_deny.is_inline is True
    assert post_hoc.is_inline is False
    assert live_deny.disposition == "deny"
    assert post_hoc.disposition == "detected"   # an observation, not a verdict

    s = build_summary([live_deny, post_hoc])
    assert s.would_deny == 1, "only the inline control could have blocked"
    assert s.detections == 1, "the post-hoc finding is a detection"
    # The rate's denominator is inline evaluations, not everything scanned.
    assert s.deny_rate == 1.0
    assert s.detection_rate == 1.0


def test_a_clean_post_hoc_session_is_clean_not_allowed():
    """'Allowed' implies a gate chose to permit it. Nothing did."""
    clean = rec(source=SOURCE_COMPLIANCE_SCAN, surface="claude_code")
    clean.session_id = "clls_2"
    assert clean.disposition == "clean"
    assert build_summary([clean]).detections == 0


def test_warn_findings_are_not_detections_but_are_not_clean_either():
    """A detection means blocking-severity content was found; a warning is a
    signal for the operator, not an exposure, so it is not a detection and
    does not move the headline metric.

    It is not "clean" either, which is where the two-state version went
    wrong: a post-hoc session carrying a hundred warn-severity NER findings
    rendered as CLEAN, telling the reader the scan found nothing when it had
    found plenty. Hence the third state."""
    warned = rec(source=SOURCE_COMPLIANCE_SCAN, surface="claude_code",
                 findings=[FindingRow("shell:pipe-to-net", "warn", "m", "h3")])
    warned.session_id = "clls_3"
    assert warned.detected is False
    assert warned.flagged is True
    assert warned.disposition == "flagged"
    assert build_summary([warned]).detections == 0


def test_observed_at_is_scan_time_not_session_time():
    """A post-hoc pass run today can observe a session that finished last
    week. Dating the record by the session's activity put it in the past, so
    every time window and the statistics reset excluded work that had just
    been done -- the dashboard read zero sessions right after a successful
    ingest."""
    from forgd_verdict.compliance.ingest import report_to_record
    from forgd_verdict.compliance.scanner import SessionReport

    report = SessionReport(
        session_id="clls_1", product_surface="claude_code", user_id="u1",
        created_at="2026-09-10T08:00:00Z", updated_at="2026-09-10T09:00:00Z",
        action="allow", messages=20,
    )
    rec = report_to_record(report)
    assert rec.session_updated_at == "2026-09-10T09:00:00Z"
    assert rec.session_started_at == "2026-09-10T08:00:00Z"
    # Observed now, not a week ago.
    assert rec.observed_at > "2026-09-10T09:00:00Z"

    # And so a reset floor set before the scan does not hide it.
    from forgd_verdict.store.query import build_summary, effective_since

    since = effective_since(None, "2026-09-17T00:00:00Z")
    s = build_summary([rec], since=since)
    assert s.scanned_sessions == 1


def test_sink_batches_rather_than_writing_one_object_per_record(tmp_path):
    """The dashboard reads one object per HTTP request, so a short flush
    interval at low traffic costs one GET per record."""
    import time

    from forgd_verdict.store.sink import StoreSink

    store = LocalFileStore(tmp_path, instance="t")
    sink = StoreSink(store, batch_size=5, flush_interval_s=30.0)
    try:
        for _ in range(5):
            sink.submit({"action": "allow", "findings_count": 0}, [])
        deadline = time.monotonic() + 5
        while sink.written < 5 and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        sink.close()
    assert sink.written == 5
    # One object, not five.
    assert len(list(tmp_path.rglob("*.jsonl"))) == 1


def test_sink_flushes_on_close_so_a_roll_does_not_lose_telemetry(tmp_path):
    """close() runs on lifespan shutdown, which is why a 60s interval is
    acceptable: a normal revision roll still flushes."""
    from forgd_verdict.store.sink import StoreSink

    store = LocalFileStore(tmp_path, instance="t")
    sink = StoreSink(store, batch_size=1000, flush_interval_s=3600.0)
    sink.submit({"action": "deny", "findings_count": 1}, [])
    sink.close()
    assert len(list(store.read_verdicts())) == 1


def test_budget_exceeded_and_dropped_tiers_are_different_facts():
    """`budget_exceeded` latches on elapsed time alone and is true even when
    no droppable tier was configured, so it is a latency signal. A dropped
    tier is a coverage signal: the scan was shallower than the policy asked
    for. The dashboard labelled the first as the second, which on the inline
    path -- where T2 is not configured at all -- could never be true."""
    from forgd_verdict.store.query import build_summary

    ran_long = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    ran_long.budget_exceeded = True

    lost_coverage = rec(source=SOURCE_COMPLIANCE_SCAN, surface="cowork")
    lost_coverage.session_id = "clls_x"
    lost_coverage.budget_exceeded = True
    lost_coverage.tiers_dropped = ["presidio_pii"]

    s = build_summary([ran_long, lost_coverage])
    assert s.budget_exceeded == 2
    assert s.tiers_dropped == 1


def test_dropped_tiers_survive_a_store_round_trip(tmp_path):
    """Recorded, or the shallower scan is indistinguishable from a clean one."""
    from forgd_verdict.store.local import LocalFileStore

    store = LocalFileStore(tmp_path / "s", instance="t")
    r = rec(source=SOURCE_COMPLIANCE_SCAN, surface="cowork")
    r.session_id = "clls_y"
    r.tiers_dropped = ["presidio_pii"]
    store.write_verdicts([r])

    back = list(store.read_verdicts())
    assert [x.tiers_dropped for x in back] == [["presidio_pii"]]


# -- excluding frames from the statistics --------------------------------
#
# A reset marker moves the floor and hides every record before it, real
# findings included. This omits named frames and nothing else, for the case
# it exists for: bait pasted during a demo is a real record of a real
# evaluation, it belongs in the event log, and it has no business in a deny
# rate someone reads as the organization's.


def test_excluded_frames_leave_the_rates_but_stay_in_the_store(tmp_path):
    from forgd_verdict.store.local import LocalFileStore
    from forgd_verdict.store.query import build_summary

    store = LocalFileStore(tmp_path / "s", instance="t")
    real = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    real.request_id = "req-real"
    bait = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai",
               findings=[FindingRow("regex:ssn", "block", "m", "h1")])
    bait.request_id = "req-bait"
    bait.action = "deny"
    store.write_verdicts([real, bait])

    records = list(store.read_verdicts())
    assert len(records) == 2, "the record is kept, not deleted"

    store.set_excluded(["req-bait"])
    assert store.get_excluded() == {"req-bait"}

    s = build_summary(records, excluded=store.get_excluded())
    assert s.live_requests == 1
    assert s.would_deny == 0
    assert s.excluded_frames == 1


def test_no_marker_excludes_nothing(tmp_path):
    from forgd_verdict.store.local import LocalFileStore

    store = LocalFileStore(tmp_path / "s", instance="t")
    assert store.get_excluded() == set()


def test_clearing_the_marker_restores_every_frame(tmp_path):
    from forgd_verdict.store.local import LocalFileStore
    from forgd_verdict.store.query import build_summary

    store = LocalFileStore(tmp_path / "s", instance="t")
    r = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    r.request_id = "req-1"
    store.write_verdicts([r])

    store.set_excluded(["req-1"])
    assert build_summary(list(store.read_verdicts()),
                         excluded=store.get_excluded()).live_requests == 0
    store.set_excluded([])
    assert store.get_excluded() == set()
    assert build_summary(list(store.read_verdicts()),
                         excluded=store.get_excluded()).live_requests == 1


def test_a_record_with_no_request_id_cannot_be_excluded_by_accident(tmp_path):
    """Post-hoc records carry a session id, not a request id. An empty id
    must not match an empty entry in the marker."""
    from forgd_verdict.store.local import LocalFileStore
    from forgd_verdict.store.query import build_summary

    store = LocalFileStore(tmp_path / "s", instance="t")
    r = rec(source=SOURCE_COMPLIANCE_SCAN, surface="cowork")
    r.session_id = "clls_1"
    r.request_id = None
    store.write_verdicts([r])

    store.set_excluded(["", "req-other"])
    s = build_summary(list(store.read_verdicts()), excluded=store.get_excluded())
    assert s.scanned_sessions == 1
    assert s.excluded_frames == 0


def test_a_finding_records_the_build_that_produced_it(tmp_path):
    """`schema_version` covers the record's shape; `build` covers its
    meaning. A finding from before the NHS rule was label-gated is a
    different claim from one after, and without this the only way to tell
    them apart was to delete every record and rescan."""
    from forgd_verdict.store.local import LocalFileStore

    store = LocalFileStore(tmp_path / "s", instance="t")
    r = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    r.build = "0.2.0+0123456789ab"
    store.write_verdicts([r])
    assert [x.build for x in store.read_verdicts()] == ["0.2.0+0123456789ab"]


def test_objects_written_before_the_org_partition_still_read_back(tmp_path):
    """The failure mode is silent: a reader that expects `source=/org=/date=`
    finds nothing under the old `source=/date=` layout, the dashboard goes
    quiet, and a quiet dashboard is indistinguishable from a clean week.

    Written by hand in the old shape rather than by an old version of the
    code, because the point is the layout on disk, not how it got there.
    """
    old = tmp_path / "verdicts" / "source=inference_hook" / "date=2026-09-17"
    old.mkdir(parents=True)
    (old / "legacy-000001.jsonl").write_text(
        rec(day="2026-09-17", request_id="from-before").to_json() + "\n",
        encoding="utf-8",
    )

    store = LocalFileStore(tmp_path, instance="t1")
    store.write_verdicts([rec(day="2026-09-17", request_id="from-after")])

    back = {r.request_id for r in store.read_verdicts()}
    assert back == {"from-before", "from-after"}

    # And it reads as unattributed rather than as a fourth org, so the two
    # are grouped together rather than the old data appearing as a separate
    # tenant nobody configured.
    assert {r.request_id for r in store.read_verdicts(orgs={"unattributed"})} == back


def test_since_still_prunes_across_both_layouts(tmp_path):
    old = tmp_path / "verdicts" / "source=inference_hook" / "date=2026-09-01"
    old.mkdir(parents=True)
    (old / "legacy-000001.jsonl").write_text(
        rec(day="2026-09-01", request_id="ancient").to_json() + "\n", encoding="utf-8"
    )
    store = LocalFileStore(tmp_path, instance="t1")
    store.write_verdicts([rec(day="2026-09-17", request_id="recent")])
    assert {r.request_id for r in store.read_verdicts(since="2026-09-10")} == {"recent"}


# -- probes are traffic but not a product surface ------------------------

def test_config_test_never_appears_as_a_surface():
    """Anthropic's own endpoint validation, not something anyone uses.

    It fires when an admin saves the inference hook URL and again as the
    CIRCUIT-BREAKER RECOVERY PROBE -- so it recurs, and it recurs precisely
    when something is already wrong. Left in, the dashboard grows a surface
    nobody uses whose traffic spikes during an incident.
    """
    from forgd_verdict.store.query import build_summary

    rows = [
        rec(surface="claude-ai", findings=[FindingRow("regex:ssn", "block", "m", "h1")]),
        rec(surface="config-test"),
        rec(surface="config-test"),
    ]
    out = build_summary(rows)
    assert [r.surface for r in out.surfaces] == ["claude-ai"]
    assert out.total_requests == 1
    assert out.synthetic_probes == 2


def test_probes_are_counted_rather_than_discarded():
    """"No traffic" and "only Anthropic's own probe" are different answers,
    and during an incident the second is the interesting one."""
    from forgd_verdict.store.query import build_summary

    out = build_summary([rec(surface="config-test")])
    assert out.total_requests == 0
    assert out.synthetic_probes == 1
    assert out.surfaces == []


def test_a_probe_does_not_move_the_latency_percentiles():
    """Its frame is trivial, so counting it flatters p50 and p95 -- on the
    deployment that exists partly to measure them."""
    from forgd_verdict.store.query import build_summary

    real = [rec(surface="claude-ai", total_ms=100.0) for _ in range(4)]
    out_real = build_summary(list(real))
    out_mixed = build_summary(
        [*real, *[rec(surface="config-test", total_ms=1.0) for _ in range(20)]]
    )
    assert out_real.latency, "expected latency percentiles to be reported"
    assert out_mixed.latency == out_real.latency


# -- a failed flush must not lose findings -------------------------------


def test_a_transient_store_error_is_retried_rather_than_dropped():
    """A failed flush must not discard the batch outright.

    A typical transient error: a pod starts serving before its federated
    token is available, so the first flushes of every roll fail. Dropping
    them loses findings permanently to a condition that clears in seconds.
    """
    import time

    from forgd_verdict.store.sink import StoreSink

    class Flaky:
        def __init__(self):
            self.calls = 0

        def write_verdicts(self, batch):
            self.calls += 1
            if self.calls <= 2:
                raise RuntimeError("credential not ready")
            return len(batch)

    sink = StoreSink(Flaky(), salt="s", batch_size=1, flush_interval_s=0.05)
    sink.submit_record(rec())
    for _ in range(40):
        if sink.written:
            break
        time.sleep(0.05)
    assert sink.written == 1, sink.stats()
    assert sink.dropped == 0, sink.stats()
    assert sink.errors == 2, sink.stats()


def test_a_persistent_store_outage_still_gives_up():
    """Bounded, because the queue is the buffer. An unbounded retry against
    a real outage would hold one batch while the queue behind it fills and
    drops NEWER records to save older ones."""
    import time

    from forgd_verdict.store.sink import StoreSink

    class Down:
        def write_verdicts(self, batch):
            raise RuntimeError("storage account unreachable")

    sink = StoreSink(Down(), salt="s", batch_size=1, flush_interval_s=0.05)
    sink.submit_record(rec())
    for _ in range(60):
        if sink.dropped:
            break
        time.sleep(0.05)
    assert sink.dropped == 1, sink.stats()
    assert sink.written == 0, sink.stats()
    # It tried before giving up, rather than dropping on the first failure.
    assert sink.errors >= 3, sink.stats()


class _Outage:
    """A store that fails every write while `down` is set, and otherwise
    records each call's records."""

    def __init__(self, down=True, fail_on=None):
        self.down = down
        self.fail_on = fail_on
        self.calls: list[list] = []

    def write_verdicts(self, batch):
        if self.down or (self.fail_on is not None and self.fail_on(batch)):
            raise RuntimeError("storage account unreachable")
        self.calls.append(list(batch))
        return len(batch)


def _wait(cond, timeout=5.0):
    import time

    deadline = time.monotonic() + timeout
    while not cond() and time.monotonic() < deadline:
        time.sleep(0.01)
    return cond()


def _holding_sink(store, **kw):
    from forgd_verdict.store.sink import StoreSink

    kw.setdefault("batch_size", 1)
    return StoreSink(store, salt="s", flush_interval_s=0.05, hold_failed=True,
                     hold_retry_s=0.02, hold_retry_max_s=0.05, **kw)


def test_a_holding_sink_writes_an_accepted_record_once_the_store_recovers():
    """The writer exhausting its retries dropped the batch, after the
    collector had answered 200 for it, and an exporter does not resend a
    batch it got a 200 for."""
    store = _Outage()
    sink = _holding_sink(store)
    try:
        assert sink.submit_records([rec(request_id="r1")])
        assert _wait(lambda: sink.errors > sink.max_retries + 1)
        assert sink.degraded
        assert sink.dropped == 0, sink.stats()
        assert sink.stats()["held"] == 1 and sink.stats()["pending"] == 1
        store.down = False
        assert _wait(lambda: sink.written == 1), sink.stats()
        assert not sink.degraded
        assert sink.dropped == 0
        assert [r.request_id for call in store.calls for r in call] == ["r1"]
    finally:
        sink.close()


def test_a_degraded_sink_refuses_new_records_and_takes_them_after_recovery():
    """Refused, so the collector answers 503 and the exporter keeps the
    batch, rather than queueing records a restart would lose."""
    store = _Outage()
    sink = _holding_sink(store)
    try:
        assert sink.submit_records([rec(request_id="r1")])
        assert _wait(lambda: sink.degraded)
        assert not sink.submit_records([rec(request_id="r2")])
        assert not sink.submit_record(rec(request_id="r3"))
        store.down = False
        assert _wait(lambda: not sink.degraded)
        assert sink.submit_records([rec(request_id="r2")])
        assert _wait(lambda: sink.written == 2), sink.stats()
    finally:
        sink.close()


def test_a_held_batch_is_retried_without_rewriting_the_groups_already_written():
    """A store writes one object per (source, org, day). A retry of the
    whole batch after the second object failed wrote the first again."""
    store = _Outage(down=False,
                    fail_on=lambda batch: batch[0].day == "2026-09-18" and fail[0])
    fail = [True]
    sink = _holding_sink(store, batch_size=2)
    try:
        assert sink.submit_records([rec(request_id="a", day="2026-09-17"),
                                    rec(request_id="b", day="2026-09-18")])
        assert _wait(lambda: sink.degraded)
        assert sink.stats()["held"] == 1
        fail[0] = False
        assert _wait(lambda: sink.written == 2), sink.stats()
        assert [[r.request_id for r in call] for call in store.calls] == [["a"], ["b"]]
    finally:
        sink.close()


def test_a_holding_sink_retries_less_often_the_longer_the_outage():
    sink = _holding_sink(None)
    sink.hold_retry_s, sink.hold_retry_max_s = 1.0, 30.0
    delays = []
    for attempt in range(1, 8):
        sink._held_attempts = attempt
        delays.append(sink._hold_delay())
    assert delays == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]
    # 2.0 ** 1024 overflows: about 8.5 hours of outage at the 30 s cap.
    sink._held_attempts = 5000
    assert sink._hold_delay() == 30.0


def test_a_degraded_refusal_is_not_counted_as_dropped():
    """The collector answers it 503 and the exporter sends it again."""
    sink = _holding_sink(_Outage())
    try:
        assert sink.submit_records([rec(request_id="r1")])
        assert _wait(lambda: sink.degraded)
        assert not sink.submit_records([rec(request_id="r2")])
        assert sink.dropped == 0, sink.stats()
    finally:
        sink.close()


def test_flush_on_a_holding_sink_waits_for_the_held_batch_to_be_written():
    store = _Outage()
    sink = _holding_sink(store, batch_size=100)
    try:
        assert sink.submit_records([rec(request_id="r1")])
        assert not sink.flush(timeout_s=0.3)
        assert sink.degraded
        store.down = False
        assert sink.flush(timeout_s=5)
        assert sink.written == 1
    finally:
        sink.close()


def test_closing_a_sink_that_holds_a_batch_counts_and_logs_it(caplog):
    import logging

    store = _Outage()
    sink = _holding_sink(store, close_timeout_s=2.0)
    assert sink.submit_records([rec(request_id="r1"), rec(request_id="r2")])
    assert _wait(lambda: sink.degraded)
    with caplog.at_level(logging.WARNING, logger="forgd_verdict"):
        sink.close()
    assert sink.dropped == 2, sink.stats()
    assert sink.written == 0
    assert any(r.getMessage() == "store flush failed" for r in caplog.records)


def test_a_sink_not_holding_still_drops_after_its_retries():
    """The verdict server and the intake keep the bounded retry: neither
    has a sender that resends on a refusal."""
    from forgd_verdict.store.sink import StoreSink

    sink = StoreSink(_Outage(), salt="s", batch_size=1, flush_interval_s=0.05)
    try:
        assert sink.submit_record(rec())
        assert _wait(lambda: sink.dropped == 1), sink.stats()
        assert not sink.degraded
        assert sink.submit_record(rec())
    finally:
        sink.close()


def test_two_runs_in_one_container_never_name_the_same_object():
    """The instance id must not depend on a variable only one platform sets.

    The id was `CONTAINER_APP_REPLICA_NAME or str(os.getpid())`. That
    variable is set on Container Apps only, so on Kubernetes it fell through
    to the pid -- and the pid of the app in a container is 1. Every pod
    called itself `1`, `_seq` restarts at 0 on every start, and blobs are
    written with overwrite=False. So the first write after any restart
    targeted `1-000001.jsonl`, which already existed, and Azure answered
    BlobAlreadyExists.

    It showed as a 503 from /intake, which writes synchronously. The
    verdict server and the collector go through `store.sink`, which
    retries and then drops with a counter -- so the same fault was SILENT
    DATA LOSS there, and every roll restarts the pods.
    """
    import os
    from unittest import mock

    from forgd_verdict.store.blob import new_instance_id

    with mock.patch.dict(os.environ, {}, clear=True), \
         mock.patch("os.getpid", return_value=1):
        ids = {new_instance_id() for _ in range(50)}
    assert len(ids) == 50, f"collided: {sorted(ids)[:4]}"
    assert all(i.startswith("1-") for i in ids), sorted(ids)[:2]


def test_the_platform_hint_is_kept_so_an_object_can_be_attributed():
    """Uniqueness comes from the random suffix. The hint stays so someone
    reading the container by hand can still tell which replica wrote an
    object -- and so Container Apps keeps the name it always had."""
    import os
    from unittest import mock

    from forgd_verdict.store.blob import new_instance_id

    with mock.patch.dict(os.environ, {"HOSTNAME": "verdict-abc-123"}, clear=True):
        one, two = new_instance_id(), new_instance_id()
    assert one.startswith("verdict-abc-123-") and two.startswith("verdict-abc-123-")
    assert one != two

    with mock.patch.dict(
        os.environ,
        {"CONTAINER_APP_REPLICA_NAME": "ca-rep-7", "HOSTNAME": "ignored"},
        clear=True,
    ):
        assert new_instance_id().startswith("ca-rep-7-")


def test_an_explicit_instance_still_wins():
    """The local store and the tests pass one; it must not be decorated."""
    import inspect

    from forgd_verdict.store.blob import BlobStore

    assert "instance or new_instance_id()" in inspect.getsource(BlobStore.__init__)


# -- inline latency is not audit latency ---------------------------------


def test_a_post_hoc_scan_does_not_land_in_the_round_trip_number():
    """The card says "round trip". Adapter 3 runs on a cron with nobody
    waiting and no 5,000 ms budget, so folding its duration into the same
    percentile makes the number mean nothing -- and would hide a real
    regression in the one control that has a deadline.

    It was right only because adapter 3 and adapter 4 happened not to set
    `total_ms`: a property of the data, not of the code.
    """
    from forgd_verdict.store.base import (
        SOURCE_COMPLIANCE_SCAN,
        SOURCE_INFERENCE_HOOK,
        VerdictRecord,
    )
    from forgd_verdict.store.query import build_summary

    since = "2026-09-01T00:00:00Z"
    records = [
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-10T00:00:00Z",
                      total_ms=40.0, scan_ms=30.0, surface="claude-ai"),
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-10T00:01:00Z",
                      total_ms=60.0, scan_ms=50.0, surface="claude-ai"),
        # An audit pass that took eight seconds. Perfectly fine; nobody
        # was waiting on it.
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-10T00:02:00Z",
                      total_ms=8400.0, scan_ms=8400.0, surface="claude-for-m365"),
    ]
    s = build_summary(records, [], since)
    assert s.latency["max"] == 60.0, "the audit pass reached the round-trip card"
    assert s.latency["n"] == 2
    assert s.post_hoc_latency["max"] == 8400.0
    assert s.post_hoc_latency["n"] == 1


def test_the_slowest_frame_note_is_an_inline_frame():
    from forgd_verdict.store.base import (
        SOURCE_COMPLIANCE_SCAN,
        SOURCE_INFERENCE_HOOK,
        VerdictRecord,
    )
    from forgd_verdict.store.query import build_summary

    records = [
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-10T00:00:00Z",
                      total_ms=40.0, surface="claude-ai"),
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-10T00:02:00Z",
                      total_ms=9999.0, scan_ms=9999.0, surface="claude-for-m365"),
    ]
    s = build_summary(records, [], "2026-09-01T00:00:00Z")
    assert s.slowest["total_ms"] == 40.0


def test_no_post_hoc_records_means_no_box():
    from forgd_verdict.dashboard.render import _post_hoc_stat
    from forgd_verdict.store.query import Summary

    assert _post_hoc_stat(Summary()) == ""


def test_a_store_with_no_partitions_is_reported_as_empty(tmp_path):
    """`open_store` on a path that does not exist returns a WORKING
    LocalFileStore, `_partitions` returns silently when the directory is
    absent, and the dashboard rendered a healthy blank page -- its own
    version of a clean scan, from a one-character configuration error."""
    from forgd_verdict.store import open_store, store_is_empty

    assert store_is_empty(open_store(str(tmp_path / "typo-path")))


def test_a_store_that_has_records_is_not_empty(tmp_path):
    from forgd_verdict.store import open_store, store_is_empty
    from forgd_verdict.store.base import SOURCE_INFERENCE_HOOK, VerdictRecord

    s = open_store(str(tmp_path / "real"))
    s.write_verdicts([VerdictRecord(source=SOURCE_INFERENCE_HOOK,
                                    observed_at="2026-09-10T00:00:00Z")])
    assert not store_is_empty(s)


def test_a_store_whose_describe_raises_is_not_called_empty():
    """`describe` must never decide a page."""
    from forgd_verdict.store import store_is_empty

    class Broken:
        def describe(self):
            raise RuntimeError("unreachable")

    assert not store_is_empty(Broken())


def test_an_unresolved_store_placeholder_is_refused(tmp_path, monkeypatch):
    """`store: $FORGD_VERDICT_STORE` with the variable unset would
    otherwise open a LocalFileStore at a directory literally named
    `$FORGD_VERDICT_STORE`. Writes succeed and health passes, so the
    findings go somewhere nobody configured.
    """

    from forgd_verdict.store import StoreNotConfigured, open_store

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    with pytest.raises(StoreNotConfigured, match="FORGD_VERDICT_STORE is not set"):
        open_store("$FORGD_VERDICT_STORE")
    assert not (tmp_path / "$FORGD_VERDICT_STORE").exists()


def test_the_shipped_policy_with_the_variable_unset_refuses_to_serve(monkeypatch):
    """The fork that forgets the variable gets an error, not a store."""

    from forgd_verdict.policy import load_policy
    from forgd_verdict.store import StoreNotConfigured

    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec_" + "A" * 44)
    with pytest.raises(StoreNotConfigured):
        VerdictServer(load_policy("policy.yaml"))


def test_an_empty_store_is_still_the_way_to_run_without_one(monkeypatch):
    """Refusing the placeholder must not remove the explicit opt-out."""
    from forgd_verdict.policy import Policy, _deep_merge, load_policy

    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec_" + "A" * 44)
    monkeypatch.setenv("FORGD_HASH_SALT", "test-deployment-salt")
    pol = Policy(raw=_deep_merge(load_policy("policy.yaml").raw,
                                 {"server": {"store": ""}}))
    VerdictServer(pol)


def test_claude_design_is_its_own_surface_and_joins_its_underscore_spelling():
    """An undocumented source.application seen live. It must read as a
    product of its own, and a Compliance API `claude_design` -- the
    convention that API uses elsewhere -- must land on the same row."""
    from forgd_verdict.store.query import is_synthetic, normalize_surface

    assert normalize_surface("claude-design") == "claude-design"
    assert normalize_surface("claude_design") == "claude-design"
    assert not is_synthetic("claude-design")


def test_a_post_tool_use_deny_is_not_counted_as_blocked_before_running():
    """The tool had run; the deny only kept its output from the model."""
    block = rec(source=SOURCE_CODE_HOOK, action="deny", request_id="PreToolUse:Bash:t1")
    after = rec(source=SOURCE_CODE_HOOK, action="deny", request_id="PostToolUse:01ABC")
    recon = build_summary([block, after]).reconciliation
    assert recon.code_hook_decisions == 2
    assert (recon.code_hook_denied, recon.code_hook_withheld) == (1, 1)


def test_an_oversize_gap_is_not_coverage_lost_to_budget():
    """A row whose only dropped entry is the unscanned middle of an
    oversized value lost no tier to the budget. It is counted on its own."""
    from forgd_verdict.models import UNSCANNED
    from forgd_verdict.store.query import build_summary

    gap_only = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    gap_only.tiers_dropped = [UNSCANNED]
    both = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    both.tiers_dropped = [UNSCANNED, "presidio_pii"]
    tier_only = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    tier_only.tiers_dropped = ["presidio_pii"]

    s = build_summary([gap_only, both, tier_only])
    assert s.tiers_dropped == 2
    assert s.oversize_unscanned == 2


def test_an_unfetched_artifact_is_counted_on_its_own():
    from forgd_verdict.models import UNSCANNED_ARTIFACT
    from forgd_verdict.store.query import build_summary

    gap = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    gap.tiers_dropped = [UNSCANNED_ARTIFACT]
    s = build_summary([gap])
    assert s.tiers_dropped == 0
    assert s.oversize_unscanned == 0
    assert s.artifacts_unscanned == 1


def test_the_dashboard_shows_unfetched_artifacts():
    from forgd_verdict.dashboard.render import _round_trip_aside
    from forgd_verdict.models import UNSCANNED_ARTIFACT
    from forgd_verdict.store.query import build_summary

    gap = rec(source=SOURCE_INFERENCE_HOOK, surface="claude-ai")
    gap.tiers_dropped = [UNSCANNED_ARTIFACT]
    html = _round_trip_aside(build_summary([gap, gap]))
    assert "Artifacts not scanned" in html


class _GatedStore:
    """A store whose writes wait until `gate` is set."""

    def __init__(self, inner):
        import threading

        self.inner = inner
        self.gate = threading.Event()
        self.entered = threading.Event()

    def write_verdicts(self, batch):
        self.entered.set()
        self.gate.wait()
        return self.inner.write_verdicts(batch)


def _full_sink(tmp_path, **kw):
    """A sink with one batch in flight against a blocked writer and a full
    queue behind it. Returns the sink, its store and how many rows went in."""
    from forgd_verdict.store.sink import StoreSink

    store = _GatedStore(LocalFileStore(tmp_path, instance="t"))
    sink = StoreSink(store, batch_size=2, flush_interval_s=3600.0, max_queue=4, **kw)
    for _ in range(2):
        assert sink.submit_record(VerdictRecord(source=SOURCE_CODE_HOOK, action="allow"))
    assert store.entered.wait(5)
    submitted = 2
    while sink.submit_record(VerdictRecord(source=SOURCE_CODE_HOOK, action="allow")):
        submitted += 1
    sink.dropped = 0          # the refused submit that found the queue full
    return sink, store, submitted


def test_close_with_a_full_queue_still_writes_every_row(tmp_path):
    import threading

    sink, store, submitted = _full_sink(tmp_path)
    threading.Timer(0.2, store.gate.set).start()
    sink.close()
    assert len(list(store.inner.read_verdicts())) == submitted
    assert sink.dropped == 0


def test_close_against_a_stuck_writer_is_bounded_and_counts_what_it_lost(tmp_path, caplog):
    import logging
    import time

    sink, store, submitted = _full_sink(tmp_path, close_timeout_s=0.5)
    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="forgd_verdict"):
        sink.close()
    assert time.monotonic() - started < 3
    assert sink.dropped == submitted
    assert any(r.getMessage().startswith("store sink closed") for r in caplog.records)
    store.gate.set()


def _rec():
    return VerdictRecord(source=SOURCE_CODE_HOOK, action="allow")


def test_close_after_the_writer_died_counts_what_it_left_queued(tmp_path, monkeypatch, caplog):
    import logging
    import threading

    from forgd_verdict.store.sink import StoreSink

    release = threading.Event()
    monkeypatch.setattr(StoreSink, "_run", lambda self: release.wait(5))
    sink = StoreSink(LocalFileStore(tmp_path, instance="t"), flush_interval_s=3600.0)
    for _ in range(3):
        assert sink.submit_record(_rec())
    release.set()
    sink._thread.join(5)
    assert not sink._thread.is_alive()
    with caplog.at_level(logging.WARNING, logger="forgd_verdict"):
        sink.close()
    assert sink.dropped == 3
    assert any(r.getMessage().startswith("store sink closed") for r in caplog.records)


def test_a_clean_close_drops_nothing_and_does_not_warn(tmp_path, caplog):
    import logging

    from forgd_verdict.store.sink import StoreSink

    store = LocalFileStore(tmp_path, instance="t")
    sink = StoreSink(store, batch_size=1000, flush_interval_s=3600.0)
    for _ in range(3):
        assert sink.submit_record(_rec())
    with caplog.at_level(logging.WARNING, logger="forgd_verdict"):
        sink.close()
    assert sink.dropped == 0
    assert len(list(store.read_verdicts())) == 3
    assert not any(r.getMessage().startswith("store sink closed") for r in caplog.records)


def test_a_submit_after_close_is_refused_and_counted(tmp_path):
    from forgd_verdict.store.sink import StoreSink

    sink = StoreSink(LocalFileStore(tmp_path, instance="t"), flush_interval_s=3600.0)
    sink.close()
    assert sink.submit_record(_rec()) is False
    assert sink.dropped == 1
    sink.submit({"action": "allow"})
    assert sink.dropped == 2
    assert sink._queue.qsize() == 0


def test_a_submit_after_the_writer_died_is_refused_and_counted(tmp_path, monkeypatch):
    from forgd_verdict.store.sink import StoreSink

    monkeypatch.setattr(StoreSink, "_run", lambda self: None)
    sink = StoreSink(LocalFileStore(tmp_path, instance="t"), flush_interval_s=3600.0)
    sink._thread.join(5)
    assert sink.submit_record(_rec()) is False
    sink.submit({"action": "allow"})
    assert sink.dropped == 2
    assert sink._queue.qsize() == 0


def _held_sink(tmp_path, monkeypatch, max_queue):
    """A StoreSink whose writer never reads its queue until `release` is set."""
    import threading

    from forgd_verdict.store.sink import StoreSink

    release = threading.Event()
    monkeypatch.setattr(StoreSink, "_run", lambda self: release.wait(5))
    sink = StoreSink(LocalFileStore(tmp_path, instance="t"), flush_interval_s=3600.0,
                     max_queue=max_queue)
    return sink, release


def test_submit_records_queues_all_or_none(tmp_path, monkeypatch):
    sink, release = _held_sink(tmp_path, monkeypatch, max_queue=5)
    try:
        assert sink.submit_records([_rec() for _ in range(3)])
        assert sink.submit_records([_rec() for _ in range(3)]) is False
        assert sink._queue.qsize() == 3 and sink.dropped == 3
        assert sink.submit_records([_rec() for _ in range(2)])
        assert sink._queue.qsize() == 5
        assert sink.submit_records([])
    finally:
        release.set()


def test_submit_records_on_an_unbounded_queue_accepts_any_count(tmp_path, monkeypatch):
    sink, release = _held_sink(tmp_path, monkeypatch, max_queue=0)
    try:
        assert sink.submit_records([_rec() for _ in range(50)])
        assert sink._queue.qsize() == 50
    finally:
        release.set()


def test_submit_records_after_close_or_without_a_store(tmp_path):
    from forgd_verdict.store.sink import StoreSink

    sink = StoreSink(LocalFileStore(tmp_path, instance="t"), flush_interval_s=3600.0)
    sink.close()
    assert sink.submit_records([_rec(), _rec()]) is False
    assert sink.dropped == 2 and sink._queue.qsize() == 0
    assert StoreSink(None).submit_records([_rec()])


def test_a_second_close_does_not_count_the_leftovers_again(tmp_path, monkeypatch):
    import threading

    from forgd_verdict.store.sink import StoreSink

    release = threading.Event()
    monkeypatch.setattr(StoreSink, "_run", lambda self: release.wait(5))
    sink = StoreSink(LocalFileStore(tmp_path, instance="t"), flush_interval_s=3600.0)
    assert sink.submit_record(_rec())
    release.set()
    sink._thread.join(5)
    sink.close()
    sink.close()
    assert sink.dropped == 1


def test_one_key_on_900_laptops_is_one_headline_value_and_900_device_salted_ones():
    """Each laptop hashes with its own salt, so one key leaked on 900 laptops
    arrives as 900 hashes. Those cannot be compared with each other or with
    the deployment's, so they count on their own line, once per laptop, and
    never in the headline or a detector's distinct values."""
    from forgd_verdict.store.views import summary_payload

    finding = FindingRow("regex:aws-access-key", "block", "messages[0]", "sha256:server")
    records = [rec(findings=(finding,))]
    for device in range(900):
        records.append(rec(source=SOURCE_CODE_HOOK, salt_namespace=f"fleet:dev{device}",
                           findings=(FindingRow("regex:aws-access-key", "block", "tool_input",
                                                f"sha256:dev{device}"),)))
    records.append(rec(source=SOURCE_CODE_HOOK, salt_namespace="fleet:dev0",
                       findings=(FindingRow("regex:aws-access-key", "block", "tool_input",
                                            "sha256:dev0"),)))
    s = build_summary(records, [])
    assert s.distinct_values == 1
    assert s.device_salted_values == 900
    (det,) = s.detectors
    assert (det.unique, det.device_salted, det.count) == (1, 900, 902)
    assert families(s) == [("aws", 1)]
    payload = summary_payload(s, "7d")
    assert payload["distinct_values"] == 1
    assert payload["device_salted_values"] == 900
    assert payload["detectors"][0]["distinct_values"] == 1
    assert payload["detectors"][0]["device_salted_values"] == 900


def test_a_value_hashed_with_the_deployment_salt_is_a_headline_value_from_any_source():
    finding = FindingRow("regex:aws-access-key", "block", "messages[0]", "sha256:same")
    s = build_summary([rec(findings=(finding,)),
                       rec(source=SOURCE_CODE_HOOK, salt_namespace="", findings=(finding,))], [])
    assert (s.distinct_values, s.device_salted_values) == (1, 0)


@pytest.mark.parametrize("field", ["total_ms", "scan_ms", "body_bytes", "messages_total",
                                   "messages_scanned", "findings_count"])
@pytest.mark.parametrize("value", [10**400, -10**400, 2**53 + 1, 1e300],
                         ids=["1e400", "minus-1e400", "2^53+1", "float-1e300"])
def test_a_number_no_float_holds_is_refused_or_dropped_at_parse(field, value):
    """JSON integers have no size limit. A stored total_ms of 10**400 made
    the overview and the Event Log raise OverflowError formatting it, so a
    single record could take both pages down for every viewer."""
    from forgd_verdict.dashboard import render
    from forgd_verdict.store.views import summary_payload

    raw = json.loads(rec(source=SOURCE_CODE_HOOK).to_json())
    raw[field] = value
    if field == "findings_count" and isinstance(value, float):
        pytest.skip("an int field takes no float")
    with pytest.raises(ValueError, match=field):
        VerdictRecord.from_json(json.dumps(raw), strict=True)
    r = VerdictRecord.from_json(json.dumps(raw))
    assert getattr(r, field) == VerdictRecord.__dataclass_fields__[field].default
    s = build_summary([r], [])
    json.dumps(summary_payload(s, "7d"))
    render.render(s, "7d", {}, {}, "", "")
    render.render_events([r])


def test_one_value_on_two_laptops_is_two_per_laptop_values_for_its_family():
    """Both tiers fire on each laptop's hash; the family counts it once per
    laptop, the same as the detector table's per-laptop column."""
    from forgd_verdict.store.query import family_device_values

    records = [rec(source=SOURCE_CODE_HOOK, salt_namespace=f"fleet:dev{n}",
                   findings=(FindingRow("regex:aws-access-key", "block", "tool_input",
                                        f"sha256:dev{n}"),
                             FindingRow("gitleaks:aws-access-token", "block", "tool_input",
                                        f"sha256:dev{n}")))
               for n in range(2)]
    s = build_summary(records, [])
    assert family_device_values(s) == {"aws": 2}
    assert {d.detector: d.device_salted for d in s.detectors} == {
        "regex:aws-access-key": 2, "gitleaks:aws-access-token": 2}
    assert families(s) == [("aws", 0)]
