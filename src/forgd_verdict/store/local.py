"""Filesystem store: append-only partitioned JSONL. Stdlib only.

Used for local development, tests, and single-host deployments. The layout
is identical to the blob store's, so a directory can be uploaded to a
container (or a container synced to a directory) without transformation.
"""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Collection, Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..fsmode import create_private, open_private, private_dir, tighten_tree, write_private
from ..models import CONTROL_STATE, safe_state_name
from .base import (
    ABSENT,
    AUDIT_DAY,
    AUDIT_PREFIX,
    EXCLUDE_MARKER,
    ORG_UNATTRIBUTED,
    RESET_MARKER,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    STATE_PREFIX,
    ControlRead,
    DenialRecord,
    StoreConflict,
    StoreReadError,
    VerdictDay,
    VerdictRecord,
    audit_scope,
    by_day_newest_first,
    iter_json_lines,
    partition_keys,
    partition_path,
    safe_audit_name,
)

DENIALS_SOURCE = "denials"
# The top-level directories the store writes under its root.
STORE_TREES = ("verdicts", "denials", STATE_PREFIX, AUDIT_PREFIX.split("/")[0],
               RESET_MARKER.split("/")[0])


class LocalFileStore:
    # Whether a 403 on `put_audit` proves the writer lockout
    # (forgd_verdict.lockout). A directory has no credentials to refuse.
    lockout_provable = False

    def __init__(self, root: str | os.PathLike[str], instance: str | None = None):
        self.root = Path(root)
        self.instance = instance or f"{os.getpid()}"
        self._lock = threading.Lock()
        self._seq = 0
        private_dir(self.root)
        tighten_tree(self.root, STORE_TREES)

    # -- write ------------------------------------------------------------

    def write_verdicts(self, records: Sequence[VerdictRecord]) -> int:
        return self._write_grouped("verdicts", records)

    def write_denials(self, records: Sequence[DenialRecord]) -> int:
        return self._write_grouped("denials", records, source=DENIALS_SOURCE)

    def _write_grouped(
        self, prefix: str, records: Sequence[Any], source: str | None = None
    ) -> int:
        if not records:
            return 0
        # Group by (source, org, day) so one batch can span a midnight
        # boundary, mixed sources or several orgs without splitting the
        # caller's list. Grouping by org is what makes the partition
        # meaningful: a batch is not guaranteed to be single-org, and one
        # cross-org object would defeat pruning for every reader.
        buckets: dict[tuple[str, str, str], list[str]] = {}
        for record in records:
            key = (
                source or getattr(record, "source", DENIALS_SOURCE),
                getattr(record, "org", ORG_UNATTRIBUTED),
                record.day,
            )
            buckets.setdefault(key, []).append(record.to_json())

        written = 0
        with self._lock:
            for (src, org, day), lines in buckets.items():
                self._seq += 1
                rel = partition_path(prefix, src, day, self.instance, self._seq, org)
                path = self._inside_root(rel)
                fd = open_private(path, os.O_WRONLY | os.O_APPEND)
                with os.fdopen(fd, "a", encoding="utf-8") as fh:
                    fh.write("\n".join(lines) + "\n")
                written += len(lines)
        return written

    def _inside_root(self, rel: str) -> Path:
        """`root / rel`, or ValueError if `..` in `rel` would leave the root.

        Lexical: a symlink inside the root is the operator's and is followed.
        """
        root = os.path.normpath(os.path.abspath(self.root))
        path = os.path.normpath(os.path.join(root, rel))
        if os.path.commonpath([root, path]) != root or path == root:
            raise ValueError(f"partition {rel!r} is outside the store root")
        return Path(path)

    # -- read -------------------------------------------------------------

    def read_verdicts(
        self, since: str | None = None, orgs: Collection[str] | None = None,
        sources: Collection[str] | None = None,
    ) -> Iterator[VerdictRecord]:
        for path in self._partitions("verdicts", since, orgs, sources):
            for line in iter_json_lines(path.read_bytes()):
                try:
                    yield VerdictRecord.from_json(line)
                except (ValueError, TypeError):
                    continue  # a torn final line must not kill a dashboard

    def read_denials(
        self, since: str | None = None, orgs: Collection[str] | None = None
    ) -> Iterator[DenialRecord]:
        for path in self._partitions("denials", since, orgs):
            for line in iter_json_lines(path.read_bytes()):
                try:
                    yield DenialRecord.from_json(line)
                except (ValueError, TypeError):
                    continue

    def read_verdict_days(
        self, since: str | None = None, orgs: Collection[str] | None = None,
        until: str | None = None, sources: Collection[str] | None = None,
    ) -> Iterator[tuple[str | None, Iterator[VerdictRecord]]]:
        keys = partition_keys(self._level, self._tree, "verdicts/", since, orgs, until,
                              sources)
        for day, rels in by_day_newest_first(keys, "verdicts/"):
            yield day, VerdictDay(rels, self._object, "verdicts/")

    def _object(self, rel: str) -> bytes:
        return (self.root / rel).read_bytes()

    def _partitions(
        self, prefix: str, since: str | None, orgs: Collection[str] | None = None,
        sources: Collection[str] | None = None,
    ) -> Iterator[Path]:
        for rel in partition_keys(self._level, self._tree, f"{prefix}/", since, orgs,
                                  sources=sources):
            yield self.root / rel

    def _level(self, prefix: str) -> tuple[list[str], list[str]]:
        """Subdirectories and `*.jsonl` files of `root/prefix`, root-relative.
        A symlinked directory is not followed."""
        prefixes, keys = [], []
        try:
            entries = os.scandir(self.root / prefix)
        except (FileNotFoundError, NotADirectoryError):
            return prefixes, keys
        with entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    prefixes.append(f"{prefix}{entry.name}/")
                elif entry.name.endswith(".jsonl") and entry.is_file():
                    keys.append(f"{prefix}{entry.name}")
        return prefixes, keys

    def _tree(self, prefix: str) -> Iterator[str]:
        prefixes, keys = self._level(prefix)
        yield from keys
        for child in prefixes:
            yield from self._tree(child)

    def set_reset_marker(self, when: str) -> None:
        write_private(self.root / RESET_MARKER, when.encode("utf-8"))

    def get_reset_marker(self) -> str | None:
        try:
            return (self.root / RESET_MARKER).read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    def set_excluded(self, request_ids) -> None:
        write_private(self.root / EXCLUDE_MARKER,
                      "\n".join(sorted(set(request_ids))).encode("utf-8"))

    def get_excluded(self) -> set[str]:
        try:
            raw = (self.root / EXCLUDE_MARKER).read_text(encoding="utf-8")
        except OSError:
            return set()
        return {ln.strip() for ln in raw.splitlines() if ln.strip()}

    # -- durable state ----------------------------------------------------

    def put_state(self, name: str, blob: bytes) -> None:
        write_private(self.root / STATE_PREFIX / safe_state_name(name), blob)

    def get_state(self, name: str) -> bytes | None:
        """None when there is no such state object. Any other failure
        raises, as the cloud stores' do."""
        path = self.root / STATE_PREFIX / safe_state_name(name)
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    # -- runtime overrides ------------------------------------------------

    def _control_path(self) -> Path:
        return self.root / STATE_PREFIX / CONTROL_STATE

    def read_control(self) -> ControlRead:
        try:
            body = self._control_path().read_bytes()
        except FileNotFoundError:
            return ABSENT
        except OSError as exc:
            raise StoreReadError(type(exc).__name__) from exc
        return ControlRead("ok", body, hashlib.sha256(body).hexdigest())

    def write_control(self, body: bytes, if_etag: str | None) -> None:
        import fcntl

        path = self._control_path()
        # The etag is a digest of the bytes, so the compare and the replace
        # happen under an exclusive lock on a sibling file that every writer
        # of this store takes.
        with self._lock, os.fdopen(
                open_private(path.with_suffix(".lock"), os.O_WRONLY | os.O_APPEND),
                "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                current = path.read_bytes()
            except FileNotFoundError:
                current = None
            if if_etag is None:
                if current is not None:
                    raise StoreConflict("runtime overrides object exists")
            elif current is None or hashlib.sha256(current).hexdigest() != if_etag:
                raise StoreConflict("runtime overrides object changed")
            write_private(path, body)

    def put_audit(self, name: str, body: bytes) -> None:
        path = self.root / AUDIT_PREFIX / safe_audit_name(name)
        try:
            create_private(path, body)
        except FileExistsError as exc:
            raise StoreConflict(f"audit record exists: {name}") from exc

    def get_audit(self, name: str) -> bytes | None:
        path = self.root / AUDIT_PREFIX / safe_audit_name(name)
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    def audit_modified(self, name: str) -> datetime:
        try:
            mtime = (self.root / AUDIT_PREFIX / safe_audit_name(name)).stat().st_mtime
        except FileNotFoundError as exc:
            raise StoreReadError(f"audit record absent: {name}") from exc
        return datetime.fromtimestamp(mtime, UTC)

    def list_audit(self, day: str | None = None, leaf: str = "") -> list[str]:
        base = self.root / AUDIT_PREFIX
        audit_scope(day, leaf)
        if not base.is_dir():
            return []
        if day is None:
            return sorted(p.relative_to(base).as_posix() for p in base.glob("*/*.json"))
        # `leaf` holds no glob metacharacter: audit_scope refuses them.
        return sorted(f"{day}/{p.name}" for p in (base / day).glob(f"{leaf}*")
                      if p.name.endswith(".json"))

    def audit_days(self) -> list[str]:
        prefixes, _ = self._level(f"{AUDIT_PREFIX}/")
        return sorted(d for d in (p.rsplit("/", 2)[-2] for p in prefixes)
                      if AUDIT_DAY.fullmatch(d))

    def describe(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for prefix in ("verdicts", "denials"):
            counts[prefix] = sum(1 for _ in self._partitions(prefix, None))
        return {
            "backend": "local",
            "root": str(self.root),
            "instance": self.instance,
            "partition_files": counts,
            "reset_at": self.get_reset_marker(),
        }


__all__ = ["LocalFileStore", "SOURCE_COMPLIANCE_SCAN", "SOURCE_INFERENCE_HOOK"]
