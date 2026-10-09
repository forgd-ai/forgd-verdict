"""Adapter 2's spool: atomic append, rotate-then-ship, and retry."""

from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from conftest import FAKE_AWS_KEY, make_policy

from forgd_verdict.hook.cli import run
from forgd_verdict.hook.ship import run_ship, ship_to_endpoint, ship_to_store
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import SOURCE_CODE_HOOK, FindingRow, VerdictRecord
from forgd_verdict.store.spool import PIPE_BUF, Spool, drain


def one(day="2026-09-17", action="allow", findings=()) -> VerdictRecord:
    return VerdictRecord(
        source=SOURCE_CODE_HOOK, observed_at=f"{day}T10:00:00Z",
        surface="claude-code-local", action=action,
        findings=list(findings), findings_count=len(findings),
    )


def test_append_and_read(tmp_path):
    spool = Spool(tmp_path)
    assert spool.append(one()) is True
    claimed = spool.claim()
    assert len(claimed) == 1
    assert len(list(Spool.read(claimed[0]))) == 1


def test_spool_files_are_owner_only(tmp_path):
    spool = Spool(tmp_path)
    spool.append(one())
    path = next(Path(tmp_path).glob("*.jsonl"))
    assert oct(path.stat().st_mode)[-3:] == "600"


def test_concurrent_appends_do_not_corrupt(tmp_path):
    """Prompts and tool calls overlap, so concurrent hook processes are the
    normal case. A single write under PIPE_BUF on O_APPEND is atomic."""
    spool = Spool(tmp_path)
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda _: spool.append(one()), range(200)))
    path = next(Path(tmp_path).glob("*.jsonl"))
    lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
    assert len(lines) == 200
    for line in lines:
        json.loads(line)  # every line must be whole


def test_record_stays_under_pipe_buf(tmp_path):
    """The atomicity guarantee only holds under PIPE_BUF, so a normal record
    must fit with room to spare."""
    rec = one(findings=[
        FindingRow("gitleaks:aws-access-token", "block",
                   "tool_input.command", "a" * 64, "Bash")
    ])
    assert len(rec.to_json().encode()) < PIPE_BUF // 2


def test_claim_is_atomic_so_two_drains_cannot_double_ship(tmp_path):
    spool = Spool(tmp_path)
    for _ in range(3):
        spool.append(one())
    first = spool.claim()
    second = spool.claim()
    assert len(first) == 1
    assert second == [], "the second drainer must get nothing"


def test_records_written_during_a_drain_are_not_lost(tmp_path):
    spool = Spool(tmp_path)
    spool.append(one())
    claimed = spool.claim()          # rotates the active file away
    spool.append(one())              # lands in a fresh active file
    assert len(list(Spool.read(claimed[0]))) == 1
    assert len(spool.claim()) == 1


def test_failed_batch_is_parked_and_retried(tmp_path):
    spool = Spool(tmp_path)
    spool.append(one())
    result = drain(spool, lambda records: False)
    assert result == {"batches": 1, "shipped": 0, "failed": 1, "rejected": 0}
    assert list(Path(tmp_path).glob("*.failed")), "batch must be parked"
    # Next attempt picks it back up.
    result = drain(spool, lambda records: True)
    assert result["shipped"] == 1
    assert not list(Path(tmp_path).glob("*.failed"))


def test_a_failed_batch_is_claimed_by_one_drainer_only(tmp_path):
    spool = Spool(tmp_path)
    spool.append(one())
    drain(spool, lambda records: False)
    first = spool.claim()
    second = spool.claim()
    assert len(first) == 1
    assert second == [], "a parked batch was handed to two drainers"
    Spool.release(first[0], shipped=False)
    retried = spool.claim()
    assert len(retried) == 1
    assert retried[0].name.count(".retry-") == 1


def test_a_claim_left_by_a_dead_drainer_is_reclaimed_after_the_lease(tmp_path):
    import os
    import time

    from forgd_verdict.store.spool import CLAIM_LEASE_S

    spool = Spool(tmp_path)
    spool.append(one())
    stranded = spool.claim()
    assert len(stranded) == 1
    assert spool.claim() == [], "a live claim must not be taken"
    old = time.time() - CLAIM_LEASE_S - 60
    os.utime(stranded[0], (old, old))
    recovered = spool.claim()
    assert len(recovered) == 1
    assert len(list(Spool.read(recovered[0]))) == 1
    assert spool.claim() == [], "a reclaimed batch is claimed by one drainer only"


def test_a_claim_is_timed_from_the_claim_not_the_last_append(tmp_path):
    import os
    import time

    from forgd_verdict.store.spool import CLAIM_LEASE_S

    spool = Spool(tmp_path)
    spool.append(one())
    active = next(Path(tmp_path).glob("*.jsonl"))
    old = time.time() - CLAIM_LEASE_S - 60
    os.utime(active, (old, old))
    assert len(spool.claim()) == 1
    assert spool.claim() == []


def test_a_raising_shipper_parks_rather_than_loses(tmp_path):
    spool = Spool(tmp_path)
    spool.append(one())

    def boom(records):
        raise OSError("offline")

    assert drain(spool, boom)["failed"] == 1
    assert list(Path(tmp_path).glob("*.failed"))


def test_ship_to_store_round_trip(tmp_path):
    spool = Spool(tmp_path / "spool")
    store = LocalFileStore(tmp_path / "central", instance="t")
    for _ in range(3):
        spool.append(one(action="deny"))
    assert drain(spool, ship_to_store(store))["shipped"] == 3
    assert len(list(store.read_verdicts())) == 3


def test_endpoint_failure_is_a_retry_not_a_loss(tmp_path):
    """Offline, asleep, VPN down -- all normal on a laptop."""
    spool = Spool(tmp_path)
    spool.append(one())
    ship = ship_to_endpoint("http://127.0.0.1:1/ingest", token="t", timeout_s=0.3)
    assert drain(spool, ship)["failed"] == 1
    assert list(Path(tmp_path).glob("*.failed"))


def test_no_destination_configured_is_a_noop(tmp_path):
    policy = make_policy(hook={"spool": str(tmp_path), "ship_mode": "sessionend"})
    result = run_ship(policy)
    assert result["shipped"] == 0
    assert "skipped" in result


# -- integration with the hook --------------------------------------------


def hook_policy(tmp_path, **hook):
    return make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"},
                   "shell_exfil": {"enabled": True, "severity": "warn"}},
        hook={"spool": str(tmp_path / "spool"), "ship_mode": "off", **hook},
    )


def test_hook_spools_its_decision(tmp_path):
    policy = hook_policy(tmp_path)
    code, out = run({"hook_event_name": "UserPromptSubmit", "session_id": "s1",
                     "user_input": f"key {FAKE_AWS_KEY}"}, policy)
    assert code == 0 and json.loads(out)["decision"] == "block"
    records = list(Spool.read(Spool(tmp_path / "spool").claim()[0]))
    assert len(records) == 1
    r = records[0]
    assert r.source == SOURCE_CODE_HOOK
    assert r.action == "deny"
    assert r.surface == "claude-code-local"
    # Not a Claude Code UUID, so stored as a digest rather than as sent.
    assert r.session_id.startswith("sess_") and "s1" not in r.session_id
    # Unique per decision: with the event type alone as the id, any
    # per-frame operation would hit every prompt ever recorded at once.
    assert r.request_id.startswith("UserPromptSubmit:prompt:")
    assert len(r.request_id) > len("UserPromptSubmit:prompt:")
    assert {f.detector for f in r.findings} == {"regex:aws-access-key"}


def test_spooled_record_carries_no_secret(tmp_path):
    policy = hook_policy(tmp_path)
    run({"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash",
         "tool_input": {"command": f"export K={FAKE_AWS_KEY}"}}, policy)
    raw = "".join(p.read_text() for p in (tmp_path / "spool").rglob("*"))
    assert raw and FAKE_AWS_KEY not in raw


def test_allowed_decisions_are_spooled_too(tmp_path):
    """Coverage needs the denominator, not just the denials."""
    policy = hook_policy(tmp_path)
    run({"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "user_input": "hello"}, policy)
    records = list(Spool.read(Spool(tmp_path / "spool").claim()[0]))
    assert len(records) == 1 and records[0].action == "allow"


def test_session_end_drains(tmp_path):
    store_dir = tmp_path / "central"
    policy = hook_policy(tmp_path, ship_mode="sessionend",
                         ship_store=str(store_dir))
    run({"hook_event_name": "UserPromptSubmit", "session_id": "s1",
         "user_input": f"key {FAKE_AWS_KEY}"}, policy)
    code, out = run({"hook_event_name": "SessionEnd", "session_id": "s1"}, policy)
    assert (code, out) == (0, ""), "SessionEnd must emit nothing"
    assert len(list(LocalFileStore(store_dir).read_verdicts())) == 1


def test_session_end_is_silent_when_shipping_is_off(tmp_path):
    policy = hook_policy(tmp_path, ship_mode="off")
    assert run({"hook_event_name": "SessionEnd", "session_id": "s1"}, policy) == (0, "")


def test_a_broken_spool_never_blocks_a_decision(tmp_path):
    """Telemetry failure must not stop a deny from being delivered."""
    blocked = tmp_path / "nope"
    blocked.write_text("not a directory")
    policy = hook_policy(tmp_path, spool=str(blocked / "spool"))
    code, out = run({"hook_event_name": "UserPromptSubmit", "session_id": "s1",
                     "user_input": f"key {FAKE_AWS_KEY}"}, policy)
    assert code == 0
    assert json.loads(out)["decision"] == "block"


def test_detached_shipper_does_not_delay_the_hook(tmp_path, monkeypatch):
    """The exit code is part of the contract, so Claude Code waits for this
    process. The upload therefore has to outlive it, not precede its exit."""
    import io

    from forgd_verdict import cli
    from forgd_verdict.hook import ship

    spawned: list[tuple[list[str], dict]] = []
    waited: list[str] = []

    class FakePopen:
        """Records how the shipper is started and any attempt to wait on it."""

        def __init__(self, argv, **kwargs):
            spawned.append((argv, kwargs))

        def wait(self, *a, **kw):
            waited.append("wait")

        def communicate(self, *a, **kw):
            waited.append("communicate")
            return None, None

        def poll(self):
            waited.append("poll")

    policy_file = tmp_path / "p.json"
    policy_file.write_text(json.dumps({
        "detectors": {"gitleaks": {"enabled": False, "severity": "block"}},
        "hook": {"spool": str(tmp_path / "spool"), "ship_mode": "detached",
                 "ship_store": str(tmp_path / "central")},
        "server": {"csv_path": None},
    }))
    monkeypatch.setattr(ship.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({
        "hook_event_name": "UserPromptSubmit", "session_id": "s1", "user_input": "hello"})))
    assert cli.main(["hook", "--policy", str(policy_file)]) == 0
    assert len(spawned) == 1, spawned
    argv, kwargs = spawned[0]
    assert argv[-3:] == ["hook-ship", "--policy", str(policy_file)], argv
    assert kwargs.get("start_new_session") is True, kwargs
    assert all(kwargs.get(stream) == subprocess.DEVNULL
               for stream in ("stdin", "stdout", "stderr")), kwargs
    assert waited == [], "the hook waited on the shipper"


def test_the_suite_never_writes_to_the_real_spool():
    """A guard on the guard. The autouse fixture in conftest redirects the
    spool, and this asserts it is in force: without it, running pytest
    appends fixture records to the developer's own spool, and with shipping
    enabled those reach a production store."""
    import os

    from forgd_verdict.store.spool import default_spool_root

    root = default_spool_root()
    assert os.environ.get("FORGD_VERDICT_SPOOL"), "spool not isolated"
    assert ".local/state/forgd-verdict" not in root, root


def test_the_request_id_is_unique_per_decision(tmp_path):
    """It was the event type alone -- `UserPromptSubmit:prompt` for every
    prompt in every session -- so excluding one demo frame from the
    dashboard's rates would have removed every prompt decision ever
    recorded."""
    policy = hook_policy(tmp_path)
    for payload in (
        {"hook_event_name": "UserPromptSubmit", "session_id": "s",
         "prompt_id": "pid-1", "prompt": f"key {FAKE_AWS_KEY}"},
        {"hook_event_name": "UserPromptSubmit", "session_id": "s",
         "prompt_id": "pid-2", "prompt": f"key {FAKE_AWS_KEY}"},
        {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash",
         "tool_use_id": "toolu-9",
         "tool_input": {"command": f"echo {FAKE_AWS_KEY}"}},
        # Neither id supplied: a ULID keeps it unique anyway.
        {"hook_event_name": "UserPromptSubmit", "session_id": "s",
         "prompt": f"key {FAKE_AWS_KEY}"},
    ):
        run(payload, policy)

    paths = Spool(tmp_path / "spool").claim()
    ids = [r.request_id for p in paths for r in Spool.read(p)]
    assert len(ids) == 4
    assert len(set(ids)) == 4, ids


# -- the seam between the spool and the intake ---------------------------


def _hook_record(i=0):
    return VerdictRecord(source=SOURCE_CODE_HOOK, request_id=f"r{i}",
                         observed_at="2026-09-21T12:00:00Z")


def test_a_partly_refused_batch_is_not_deleted(tmp_path):
    """The failure, end to end.

    `/intake` returns 200 with {"accepted": 7, "rejected": 3} for a batch
    it partly refuses. `ship_to_endpoint` discarded the body and returned
    True for any 2xx, and `drain` unlinked the whole claimed file. Ten
    records spooled, seven stored, three destroyed, reported
    `shipped: 10, failed: 0`.
    """
    from forgd_verdict.store.spool import REJECTED_SUFFIX, ShipResult, Spool, drain

    spool = Spool(str(tmp_path))
    for i in range(10):
        spool.append(_hook_record(i))

    def ship(records):
        return ShipResult(ok=True, accepted=7, rejected=3)

    result = drain(spool, ship)

    assert result["shipped"] == 7
    assert result["rejected"] == 3
    left = list(tmp_path.glob(f"*{REJECTED_SUFFIX}"))
    assert len(left) == 1, "the refused batch was destroyed"


def test_a_sidelined_batch_is_not_retried_forever(tmp_path):
    """Refusing again is certain -- a wrong `source` does not become right.

    Retrying would re-send the records the server DID accept and
    duplicate them once per drain, forever.
    """
    from forgd_verdict.store.spool import ShipResult, Spool, drain

    spool = Spool(str(tmp_path))
    for i in range(10):
        spool.append(_hook_record(i))
    drain(spool, lambda r: ShipResult(ok=True, accepted=7, rejected=3))

    seen = []
    second = drain(spool, lambda r: seen.append(len(r)) or ShipResult(True, len(r)))
    assert seen == [], "the sidelined batch was claimed again"
    assert second["batches"] == 0


def test_a_fully_accepted_batch_is_still_deleted(tmp_path):
    from forgd_verdict.store.spool import ShipResult, Spool, drain

    spool = Spool(str(tmp_path))
    for i in range(3):
        spool.append(_hook_record(i))
    result = drain(spool, lambda r: ShipResult(ok=True, accepted=len(r)))
    assert result == {"batches": 1, "shipped": 3, "failed": 0, "rejected": 0}
    assert list(tmp_path.iterdir()) == []


def test_a_plain_bool_shipper_still_works(tmp_path):
    """The direct-to-store shipper returns a bool and must keep working."""
    spool = Spool(str(tmp_path))
    spool.append(_hook_record())
    assert drain(spool, lambda r: True)["shipped"] == 1


def test_an_unreadable_line_is_counted_rather_than_vanishing(tmp_path):
    """A torn oversize line is expected -- the module docstring says so --
    and it was dropped on read while the file was deleted anyway."""
    from forgd_verdict.store.spool import REJECTED_SUFFIX, Spool, drain

    spool = Spool(str(tmp_path))
    spool.append(_hook_record())
    active = next(tmp_path.glob("*.jsonl"))
    with active.open("a") as fh:
        fh.write('{"source": "code_hook", "truncated\n')

    result = drain(spool, lambda r: True)
    assert result["rejected"] == 1
    assert list(tmp_path.glob(f"*{REJECTED_SUFFIX}"))


def test_a_file_of_only_unreadable_lines_is_not_silently_deleted(tmp_path):
    """It was released as shipped=True without `ship` ever being called,
    `batches` stayed 0, and nothing anywhere counted it."""
    from forgd_verdict.store.spool import REJECTED_SUFFIX, Spool, drain

    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "2026-09-21.jsonl").write_text("{not json\n{also not\n")
    spool = Spool(str(tmp_path))
    called = []
    result = drain(spool, lambda r: called.append(r) or True)

    assert called == []
    assert result["rejected"] == 2
    assert list(tmp_path.glob(f"*{REJECTED_SUFFIX}"))


def test_the_shipper_reads_the_intake_response(tmp_path, monkeypatch):
    """`ship_to_endpoint` against a server reporting a partial batch."""
    import io
    import json as _json

    class Resp(io.BytesIO):
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(
        "forgd_verdict.hook.ship.open_url",
        lambda req, timeout, ca_file=None: Resp(_json.dumps(
            {"accepted": 2, "rejected": 1}).encode()))

    out = ship_to_endpoint("https://x/intake", "tok")(
        [_hook_record(i) for i in range(3)])
    assert out.ok and out.accepted == 2 and out.rejected == 1


def test_an_endpoint_that_reports_nothing_is_still_trusted(tmp_path, monkeypatch):
    """This has to keep working against a plain collector."""
    import io

    class Resp(io.BytesIO):
        status = 204
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr("forgd_verdict.hook.ship.open_url",
                        lambda req, timeout, ca_file=None: Resp(b""))
    out = ship_to_endpoint("https://x/v1/logs", None)([_hook_record()])
    assert out.ok and out.accepted == 1 and out.rejected == 0


def test_every_retry_for_one_day_keeps_its_own_records(tmp_path):
    """Two parked batches and one expired claim for the same day are each
    claimed under their own name, so no rename replaces another."""
    import os
    import time

    from forgd_verdict.store.spool import CLAIM_LEASE_S

    day = "2026-10-01"
    sources = {
        f"{day}.jsonl.claimed.A.failed": "allow",
        f"{day}.jsonl.claimed.B.failed": "deny",
        f"{day}.jsonl.claimed.C": "warn",
    }
    for name, action in sources.items():
        (tmp_path / name).write_text(one(day=day, action=action).to_json() + "\n")
    old = time.time() - CLAIM_LEASE_S - 60
    os.utime(tmp_path / f"{day}.jsonl.claimed.C", (old, old))

    claimed = Spool(tmp_path).claim()

    assert len(set(claimed)) == 3
    actions = sorted(r.action for path in claimed for r in Spool.read(path))
    assert actions == ["allow", "deny", "warn"]


def test_a_batch_that_keeps_failing_keeps_a_bounded_name(tmp_path):
    spool = Spool(tmp_path)
    spool.append(one())
    drain(spool, lambda records: False)
    names = []
    for _ in range(3):
        assert drain(spool, lambda records: False)["failed"] == 1
        (parked,) = Path(tmp_path).glob("*.failed")
        names.append(parked.name)
    assert len({len(name) for name in names}) == 1
    assert names[-1].count(".claimed.") == 1
    assert names[-1].count(".retry-") == 1
    (claimed,) = spool.claim()
    assert len(list(Spool.read(claimed))) == 1


# -- an append racing a drain ------------------------------------------------


def test_a_drain_between_the_appenders_open_and_write_loses_nothing(tmp_path, monkeypatch):
    """The drainer runs to completion, or as far as it can, after the
    appender opened the active file and before it wrote."""
    import os
    import threading

    root = tmp_path / "spool"
    shipped: list = []
    real_write = os.write
    drained = threading.Event()
    drainer: list[threading.Thread] = []

    def drain_now():
        drain(Spool(root), lambda records: shipped.extend(records) or True)
        drained.set()

    def write(fd, data):
        if not drainer:
            drainer.append(threading.Thread(target=drain_now))
            drainer[0].start()
            drained.wait(1.0)
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", write)
    appended = Spool(root).append(one())
    assert appended is True
    monkeypatch.setattr(os, "write", real_write)
    drainer[0].join(5)
    assert not drainer[0].is_alive()

    left = [r for p in Spool(root).claim() for r in Spool.read(p)]
    assert len(shipped) + len(left) == 1


def test_an_appender_that_locks_a_drained_file_writes_to_the_live_one(tmp_path, monkeypatch):
    """The appender opened the active file, the drainer claimed, read and
    unlinked it, and only then did the appender get its lock."""
    import fcntl

    root = tmp_path / "spool"
    shipped: list = []
    real_flock = fcntl.flock
    ran: list[bool] = []

    def flock(fd, op):
        if op == fcntl.LOCK_SH and not ran:
            ran.append(True)
            drain(Spool(root), lambda records: shipped.extend(records) or True)
        return real_flock(fd, op)

    monkeypatch.setattr(fcntl, "flock", flock)
    appended = Spool(root).append(one())
    assert appended is True
    monkeypatch.setattr(fcntl, "flock", real_flock)
    assert ran, "the appender never took a shared lock"
    assert shipped == []
    left = [r for p in Spool(root).claim() for r in Spool.read(p)]
    assert len(left) == 1


def test_the_shipper_loads_a_policy_the_hook_accepts(tmp_path, monkeypatch, capsys):
    # The hook warns on an event it does not handle and drops it; the
    # shipper it spawns reads the same file and must load it the same way.
    from forgd_verdict.hook.ship import main

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("hook:\n  enabled_events: [PreToolUse, PreToolUsee]\n")
    monkeypatch.setattr("forgd_verdict.hook.ship.run_ship",
                        lambda policy, **kw: {"events": policy.hook["enabled_events"]})
    assert main(["--policy", str(policy_file), "--spool", str(tmp_path / "spool")]) == 0
    assert json.loads(capsys.readouterr().out) == {"events": ["PreToolUse"]}
