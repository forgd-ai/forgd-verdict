"""Stored findings, state, audit records and cursors are owner-only.

They hold org ids, workspace keys, session ids, override state and admin
identities, so every file is 0600 and every directory 0700 under any umask,
and a store opened over older, wider entries tightens them.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path

import pytest

from forgd_verdict.store.base import DenialRecord, VerdictRecord
from forgd_verdict.store.local import LocalFileStore


@pytest.fixture(params=[0o022, 0o000], ids=["umask-022", "umask-000"])
def umask(request):
    old = os.umask(request.param)
    yield request.param
    os.umask(old)


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _wide(root: Path) -> list[tuple[str, str]]:
    """Every entry under `root`, and `root`, that is not owner-only."""
    out = []
    for p in [root, *root.rglob("*")]:
        want = 0o700 if p.is_dir() else 0o600
        if _mode(p) != want:
            out.append((str(p.relative_to(root)), oct(_mode(p))))
    return out


def test_every_store_entry_is_owner_only(tmp_path, umask):
    root = tmp_path / "store"
    store = LocalFileStore(root, instance="t")
    store.write_verdicts([VerdictRecord(source="otel_collect", tenant_hash="org_0123456789")])
    store.write_denials([DenialRecord(activity_id="a1", created_at="2026-01-01T00:00:00Z",
                                       tenant_hash="org_0123456789")])
    store.set_reset_marker("2026-01-01T00:00:00Z")
    store.set_excluded({"req-1"})
    store.put_state("org-registry-verdict.json", b'{"version": 2}')
    store.write_control(b'{"revision": 1}', None)
    store.put_audit("2026-01-01/record.json", b"{}")
    kinds = {p.relative_to(root).parts[0] for p in root.rglob("*") if p.is_file()}
    assert kinds == {"verdicts", "denials", "markers", "state", "audit"}
    assert (root / "state" / "runtime-overrides.lock").exists()
    assert _wide(root) == []
    assert not list(root.rglob("*.tmp"))


def test_a_file_cursor_is_owner_only(tmp_path, umask):
    from forgd_verdict.compliance.scanner import State

    path = tmp_path / "cursors" / "compliance-state.json"
    state = State(str(path))
    state.save()
    assert _mode(path) == 0o600 and _mode(path.parent) == 0o700
    assert json.loads(path.read_text())["sessions"] == {}


def test_the_spool_archive_csv_and_device_salt_are_owner_only(tmp_path, umask):
    from forgd_verdict.applog import TimingCSV
    from forgd_verdict.hook.device import device_salt, device_salt_path
    from forgd_verdict.server.archive import FrameArchive
    from forgd_verdict.store.spool import Spool

    spool = Spool(tmp_path / "spool")
    appended = spool.append(VerdictRecord(source="code_hook"))
    assert appended
    archive = FrameArchive(str(tmp_path / "archive"))
    archive.submit({"frame": 1})
    archive.close()
    csv = TimingCSV(str(tmp_path / "csv" / "timings.csv"))
    csv.close()
    device_salt(tmp_path / "device")
    for directory in ("spool", "archive", "csv", "device"):
        assert _wide(tmp_path / directory) == [], directory
    assert device_salt_path(tmp_path / "device").exists()
    assert list((tmp_path / "archive").iterdir())


def test_opening_a_store_tightens_what_it_already_holds(tmp_path, umask):
    root = tmp_path / "store"
    old = os.umask(0o022)
    try:
        for rel in ("verdicts/source=x/org=y/date=2026-01-01/a.jsonl",
                    "state/compliance-state.json", "audit/runtime-overrides/d/r.json",
                    "markers/stats_reset", "denials/source=denials/b.jsonl"):
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}")
            path.chmod(0o644)
        for d in [root, *[p for p in root.rglob("*") if p.is_dir()]]:
            d.chmod(0o755)
        # Not the store's: beside the root's own directories, and linked in.
        (root / "README").write_text("operator's file")
        (root / "README").chmod(0o644)
        outside = tmp_path / "outside.json"
        outside.write_text("{}")
        outside.chmod(0o644)
        (root / "state" / "linked.json").symlink_to(outside)
        outside_dir = tmp_path / "outside-dir"
        outside_dir.mkdir(mode=0o755)
        outside_dir.chmod(0o755)
        (root / "audit" / "linked-dir").symlink_to(outside_dir)
    finally:
        os.umask(old)

    LocalFileStore(root, instance="t")

    assert _mode(root) == 0o700
    for top in ("verdicts", "denials", "state", "audit", "markers"):
        for p in [root / top, *(root / top).rglob("*")]:
            if p.is_symlink():
                continue
            assert _mode(p) == (0o700 if p.is_dir() else 0o600), p
    assert _mode(outside) == 0o644
    assert _mode(outside_dir) == 0o755
    assert _mode(root / "README") == 0o644


def test_two_concurrent_state_writers_leave_a_whole_file(tmp_path):
    store = LocalFileStore(tmp_path / "store", instance="t")
    blobs = [json.dumps({"writer": w, "pad": "x" * 200_000}).encode() for w in (1, 2)]
    errors: list[Exception] = []

    def write(blob: bytes) -> None:
        try:
            for _ in range(60):
                store.put_state("compliance-state.json", blob)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=write, args=(b,)) for b in blobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert store.get_state("compliance-state.json") in blobs
    assert not list((tmp_path / "store" / "state").glob("*.tmp"))


def test_a_filesystem_that_refuses_chmod_warns_once(tmp_path, monkeypatch, caplog):
    """Every write would otherwise log it again."""
    import logging

    from forgd_verdict import fsmode

    def refuse(*args, **kwargs):
        raise PermissionError("chmod refused")

    wide = []
    for i in range(5):
        path = tmp_path / "rows" / f"{i}.jsonl"
        path.parent.mkdir(exist_ok=True)
        path.write_text("")
        path.chmod(0o644)
        wide.append(path)
    monkeypatch.setattr(fsmode, "_warned", set())
    monkeypatch.setattr(fsmode.os, "fchmod", refuse)
    monkeypatch.setattr(fsmode.os, "chmod", refuse)
    caplog.set_level(logging.WARNING, logger="forgd_verdict.fsmode")
    for i, path in enumerate(wide):
        fsmode.write_private(tmp_path / f"d{i}" / "state.json", b"{}")
        os.close(fsmode.open_private(path, os.O_WRONLY | os.O_APPEND))
    messages = [r.getMessage() for r in caplog.records]
    assert messages.count("a stored file could not be made owner-only") == 1
    assert messages.count("a store directory could not be made owner-only") == 1
