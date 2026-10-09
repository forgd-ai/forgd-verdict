"""On-disk spool for adapter 2.

The Claude Code hook is a short-lived process on a developer's laptop that
must decide inside a 200ms budget. That rules out the batched background
writer the server uses -- the process exits before a flush would run -- and
it rules out uploading inline, because the exit code is part of the hook
contract, so Claude Code waits for the process to exit and any network call
delays the developer's action.

So the hook appends here synchronously and something else drains it later.
Two properties make that safe:

  * **Atomic append.** One record is written with a single os.write() of a
    line under PIPE_BUF (4096 bytes), which POSIX guarantees is atomic on a
    file opened O_APPEND. Concurrent hook processes -- and there will be,
    since prompts and tool calls overlap -- interleave whole lines rather
    than corrupting each other.
  * **Rotate-then-ship.** A drain renames the active file before reading it,
    which is atomic, so exactly one drainer claims a batch and records
    written during the drain land in a fresh file rather than being lost.
  * **Append under a shared lock, read under an exclusive one.** An
    appender holds `flock(LOCK_SH)` from open to write; a drainer takes
    `LOCK_EX` on the claimed file before reading it, so a write that began
    before the rename is in the file when it is read. An appender that
    gets its lock on a file already claimed reopens the active path. flock
    locks go when the process exits, so a crashed hook holds none. Where
    `fcntl` is unavailable neither side locks.

Durability is the point. Laptops are offline constantly, so a fire-and-forget
upload loses findings silently; a spool turns shipping into a retryable
operation and leaves the developer their own audit trail either way.

Holds findings only. Never prompt content.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import time
from collections.abc import Iterator, Sequence
from pathlib import Path

from ..fsmode import open_private, private_dir

try:
    import fcntl
except ImportError:  # pragma: no cover - not POSIX
    fcntl = None  # type: ignore[assignment]
from .base import VerdictRecord, iter_json_lines

# POSIX guarantees an atomic append only up to PIPE_BUF. A record that
# exceeds it is written anyway -- a torn line is dropped on read rather than
# corrupting a neighbour -- but it is counted so the cause is visible.
PIPE_BUF = 4096

ACTIVE_SUFFIX = ".jsonl"
CLAIMED_SUFFIX = ".claimed"
FAILED_SUFFIX = ".failed"
# Refused by the server, and refusing again is certain -- a record with the
# wrong `source` or a line that will not parse does not become valid on a
# retry. `claim` does not pick these up: retrying would re-send the records
# the server DID accept and duplicate them once per drain, forever. Left on
# disk because they are findings, and deleting evidence the server declined
# is the failure this whole path exists to avoid.
REJECTED_SUFFIX = ".rejected"
# A claimed batch whose drainer has not released it within this many
# seconds is reclaimed: the drainer is taken to have died after the rename.
CLAIM_LEASE_S = 3600
# Opens of the active file one append makes when each lands on a file a
# drainer has already claimed.
APPEND_ATTEMPTS = 5
# An active file at or past this size is renamed aside after the append
# that reached it, and the next append starts a new one. Each file is
# shipped whole in one request, and the intake refuses a request over its
# queue's capacity (5000 records by default) or `max_body_bytes` (8 MiB);
# at the smallest record, about 560 bytes, 1 MiB is under 1900 records.
MAX_FILE_BYTES = 1024 * 1024


class ShipResult:
    """What one batch actually achieved.

    A bool could not distinguish "the server is down" from "the server
    took seven of ten", and the shipper treated any 2xx as complete
    success and deleted the whole file. Ten records spooled, seven
    stored, three destroyed, reported `shipped: 10, failed: 0`.
    """

    __slots__ = ("ok", "accepted", "rejected", "refused")

    def __init__(self, ok: bool, accepted: int = 0, rejected: int = 0,
                 refused: bool = False):
        self.ok = ok
        self.accepted = accepted
        self.rejected = rejected
        # The whole batch was refused, and a retry would be refused again.
        self.refused = refused

    @classmethod
    def coerce(cls, value: object, total: int) -> ShipResult:
        """Accept a plain bool from an older or simpler shipper."""
        if isinstance(value, cls):
            return value
        ok = bool(value)
        return cls(ok=ok, accepted=total if ok else 0, rejected=0)


class Spool:
    def __init__(self, root: str | os.PathLike[str] | None = None):
        self.root = Path(root or default_spool_root()).expanduser()
        self.oversize = 0

    # -- append (hot path, must stay sub-millisecond) ----------------------

    def append(self, record: VerdictRecord) -> bool:
        """Append one record. Returns False on failure rather than raising:
        a spool problem must never turn into a blocked developer action."""
        try:
            private_dir(self.root)
            line = (record.to_json() + "\n").encode("utf-8")
            if len(line) > PIPE_BUF:
                self.oversize += 1
            path = self.root / f"{record.day}{ACTIVE_SUFFIX}"
            for _ in range(APPEND_ATTEMPTS):
                fd = open_private(path, os.O_WRONLY | os.O_APPEND)
                try:
                    if fcntl is not None:
                        fcntl.flock(fd, fcntl.LOCK_SH)
                        if not _is_live(fd, path):
                            continue
                    os.write(fd, line)  # single write: atomic under O_APPEND
                    if os.fstat(fd).st_size >= MAX_FILE_BYTES and _is_live(fd, path):
                        _rotate(path)
                    return True
                finally:
                    os.close(fd)  # releases the lock
            return False
        except OSError:
            return False

    # -- drain ------------------------------------------------------------

    def claim(self) -> list[Path]:
        """Atomically claim the current batch.

        Renaming before reading means a concurrent drainer cannot ship the
        same records twice, and anything the hook writes mid-drain goes to a
        new active file instead of vanishing.
        """
        if not self.root.exists():
            return []
        claimed: list[Path] = []
        marker = f"{os.getpid()}-{int(time.time())}-{secrets.token_hex(4)}"
        for path in sorted(self.root.glob(f"*{ACTIVE_SUFFIX}")):
            target = path.with_suffix(f"{ACTIVE_SUFFIX}{CLAIMED_SUFFIX}.{marker}")
            if _take(path, target):
                claimed.append(target)
        # Retry anything a previous drain failed to ship, claimed by rename
        # for the same reason: two drainers listing one failed file would
        # both ship it. A claim older than CLAIM_LEASE_S is retried too.
        now = time.time()
        for n, path in enumerate(sorted(self.root.iterdir())):
            name = path.name
            if name.endswith(FAILED_SUFFIX):
                base = name.removesuffix(FAILED_SUFFIX)
            elif _is_claim(name) and _age(path, now) > CLAIM_LEASE_S:
                base = name
            else:
                continue
            base = re.sub(rf"({re.escape(CLAIMED_SUFFIX)}\.[^.]+|\.retry-[^.]+)+$", "", base)
            target = path.with_name(f"{base}{CLAIMED_SUFFIX}.{marker}.retry-{n}")
            if _take(path, target):
                claimed.append(target)
        return claimed

    @staticmethod
    def read(path: Path) -> Iterator[VerdictRecord]:
        yield from Spool.read_counted(path)[0]

    @staticmethod
    def read_counted(path: Path) -> tuple[list[VerdictRecord], int]:
        """Records, and how many lines could not be parsed.

        The count is the point. A torn oversize line -- which the module
        docstring says to expect -- is dropped here, and without the count
        the file would be deleted with nothing anywhere recording the loss.
        """
        try:
            with open(path, "rb") as f:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                blob = f.read()
        except OSError:
            return [], 0
        records: list[VerdictRecord] = []
        unreadable = 0
        for line in iter_json_lines(blob):
            try:
                records.append(VerdictRecord.from_json(line))
            except (ValueError, TypeError):
                unreadable += 1
        return records, unreadable

    @staticmethod
    def release(path: Path, shipped: bool, rejected: bool = False) -> None:
        """Delete a shipped batch, park a failed one, sideline a refused one."""
        try:
            if rejected:
                if not path.name.endswith(REJECTED_SUFFIX):
                    path.rename(path.with_name(
                        path.name.removesuffix(FAILED_SUFFIX) + REJECTED_SUFFIX))
                return
            if shipped:
                path.unlink(missing_ok=True)
            elif not path.name.endswith(FAILED_SUFFIX):
                path.rename(path.with_name(path.name + FAILED_SUFFIX))
        except OSError:
            pass

    def pending(self) -> int:
        if not self.root.exists():
            return 0
        return sum(
            1
            for path in self.root.iterdir()
            if path.is_file() and not path.name.startswith(".")
            for _ in iter_json_lines(path.read_bytes() if path.stat().st_size else b"")
        )

    def set_reset_marker(self, when: str) -> None:
        """No-op. A spool is drained, not summarized, so it has no stats to
        reset."""

    def get_reset_marker(self) -> str | None:
        return None

    def set_excluded(self, request_ids) -> None:
        return None

    def get_excluded(self) -> set[str]:
        return set()

    def describe(self) -> dict[str, object]:
        return {
            "backend": "spool",
            "root": str(self.root),
            "pending_records": self.pending(),
            "oversize_records": self.oversize,
        }


def _take(path: Path, target: Path) -> bool:
    """Rename `path` to `target` and stamp the claim time on it.

    The rename is the claim: the loser of a race gets ENOENT. An existing
    `target` is left in place and the claim fails, since a POSIX rename
    would replace it. The mtime is set afterwards because a rename keeps the
    file's last-append time, and the lease is measured from the claim.
    """
    if target.exists():
        return False
    try:
        path.rename(target)
    except OSError:
        return False
    with contextlib.suppress(OSError):
        os.utime(target)
    return True


def _rotate(path: Path) -> None:
    """Rename the active file `path` aside, still as an active file, so the
    next append starts a new one and `claim` takes both."""
    stem = path.name.removesuffix(ACTIVE_SUFFIX)
    target = path.with_name(f"{stem}.{time.time_ns()}-{secrets.token_hex(2)}{ACTIVE_SUFFIX}")
    with contextlib.suppress(OSError):
        path.rename(target)


def _is_live(fd: int, path: Path) -> bool:
    """Whether `fd` is the file at `path` now, rather than one renamed away."""
    try:
        opened, live = os.fstat(fd), os.stat(path)
    except OSError:
        return False
    return (opened.st_ino, opened.st_dev) == (live.st_ino, live.st_dev)


def _is_claim(name: str) -> bool:
    return (CLAIMED_SUFFIX + "." in name
            and not name.endswith((FAILED_SUFFIX, REJECTED_SUFFIX)))


def _age(path: Path, now: float) -> float:
    try:
        return now - path.stat().st_mtime
    except OSError:
        return 0.0


def default_spool_root() -> str:
    """Per-user, outside the repo.

    Deliberately not inside the project directory: the spool would otherwise
    land in whatever repository the developer happened to be working in, and
    get committed.
    """
    env = os.environ.get("FORGD_VERDICT_SPOOL")
    if env:
        return env
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    return os.path.join(base, "forgd-verdict", "spool")


def drain(
    spool: Spool,
    ship: callable[[Sequence[VerdictRecord]], bool],
    batch_limit: int | None = None,
) -> dict[str, int]:
    """Claim, ship, release. `ship` returns True when the batch is safely
    stored; anything else parks the batch for retry."""
    claimed = spool.claim()
    if batch_limit is not None:
        claimed = claimed[:batch_limit]
    shipped = failed = batches = rejected = 0
    for path in claimed:
        records, unreadable = spool.read_counted(path)
        rejected += unreadable
        if not records:
            # An empty file is finished. A file whose every line was
            # unreadable is not -- released as shipped it would be deleted
            # with `batches` still 0, so nothing would count it.
            spool.release(path, shipped=not unreadable, rejected=bool(unreadable))
            continue
        batches += 1
        try:
            result = ShipResult.coerce(ship(records), len(records))
        except Exception:  # noqa: BLE001 - a transport failure is a retry
            result = ShipResult(ok=False)
        if result.refused:
            # Refused whole, and certain to be refused again: sidelined on
            # disk rather than parked for the next drain.
            spool.release(path, shipped=False, rejected=True)
            rejected += len(records)
            continue
        if not result.ok:
            spool.release(path, shipped=False)
            failed += len(records)
            continue
        shipped += result.accepted
        if result.rejected or unreadable:
            # The server took some and refused the rest. Refusing again is
            # certain, so a retry would loop and duplicate the accepted
            # records; sidelined instead, and counted.
            rejected += result.rejected
            spool.release(path, shipped=False, rejected=True)
        else:
            spool.release(path, shipped=True)
    return {"batches": batches, "shipped": shipped, "failed": failed,
            "rejected": rejected}


__all__ = ["ShipResult", "Spool", "default_spool_root", "drain"]
