"""The control identity's hourly verification of every writer identity's
lockout, from the cloud's IAM policy, written as a verification record
(lockout.write_verification) that readers trust while it is fresh.

Each record also names the overrides head readers must not go behind: the
dashboard's own verified state, or the head a fresh signed record already
names when that is later or the dashboard holds none. With neither, no
record is written, unless the store has never been initialized.

The writer identities come from FORGD_OVERRIDES_WRITER_IDENTITIES, set on
the dashboard by the chart and the app modules: role ARNs on S3, IAM
members on GCS, principal object ids on Azure. Azure also needs the
storage account's resource id, FORGD_OVERRIDES_STORAGE_ACCOUNT_ID, which
must name the account the store URL's host is on.

A GCS bucket's IAM policy omits inherited and group grants, so on GCS a
writer the bucket check passes is verified only when
FORGD_OVERRIDES_GCS_INHERITED_AUDITED_BY names who audited those grants:
an attestation, not a check.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from typing import Any

from .. import lockout
from ..applog import exc_fields
from . import EvidenceUnavailable

ENV_WRITER_IDENTITIES = "FORGD_OVERRIDES_WRITER_IDENTITIES"
ENV_STORAGE_ACCOUNT_ID = "FORGD_OVERRIDES_STORAGE_ACCOUNT_ID"
ENV_GCS_INHERITED_AUDITED_BY = "FORGD_OVERRIDES_GCS_INHERITED_AUDITED_BY"

REASON_UNSUPPORTED = "store_not_verifiable"
REASON_ACCOUNT_UNSET = "storage_account_id_unset"
REASON_ACCOUNT_MISMATCH = "storage_account_id_mismatch"
REASON_FAILED = "verification_failed"

# How often the thread checks whether a run is due before the hourly one.
RETRY_S = 60.0

_log = logging.getLogger("forgd_verdict.lockout")


def writer_identities(environ: Mapping[str, str] | None = None) -> tuple[str, ...]:
    raw = (environ if environ is not None else os.environ).get(ENV_WRITER_IDENTITIES, "")
    return tuple(dict.fromkeys(i.strip() for i in raw.split(",") if i.strip()))


_ACCOUNT_ID = re.compile(r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/"
                         r"Microsoft\.Storage/storageAccounts/([a-z0-9]{3,24})", re.IGNORECASE)
_ACCOUNT_HOST = re.compile(r"([a-z0-9]{3,24})\.(?:privatelink\.)?blob\.[a-z0-9.-]+", re.IGNORECASE)


def account_matches(account_id: str, account_url: str) -> bool:
    """Whether the storage account resource id names the account the store
    URL's host is on: `.../storageAccounts/<name>` and `<name>.blob.<suffix>`.
    False when either does not have that shape."""
    named = _ACCOUNT_ID.fullmatch((account_id or "").rstrip("/"))
    host = (account_url or "").split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    served = _ACCOUNT_HOST.fullmatch(host)
    return bool(named and served and named.group(1).lower() == served.group(1).lower())


def store_kind(store: Any) -> str | None:
    """`s3`, `gcs` or `azure` for a cloud store, else None."""
    kind = getattr(store, "evidence_kind", None)
    return kind if kind in ("s3", "gcs", "azure") else None


def evaluate_store(store: Any, identities: tuple[str, ...], *,
                   account_id: str = "") -> dict[str, str | None]:
    """Each identity -> None when the cloud's IAM policy shows its lockout,
    else a fixed reason. Reads the policy with the store's credentials."""
    kind = store_kind(store)
    if kind is None:
        return {i: REASON_UNSUPPORTED for i in identities}
    try:
        if kind == "s3":
            from . import s3
            return s3.evaluate(s3.fetch(store), **s3.scope(store), writers=identities)
        if kind == "gcs":
            from . import gcs
            results = gcs.evaluate(gcs.fetch(store), **gcs.scope(store), writers=identities)
            if os.environ.get(ENV_GCS_INHERITED_AUDITED_BY, "").strip():
                return results
            if any(r is None for r in results.values()):
                _log.error(
                    "writer lockout on GCS: the bucket's IAM policy does not show grants "
                    "inherited from the project, folder or organization, or held through a "
                    "group. Audit them, then set %s to who did; see docs/OVERRIDES.md",
                    ENV_GCS_INHERITED_AUDITED_BY)
            return {i: r or gcs.REASON_INHERITED_UNCHECKED for i, r in results.items()}
        from . import azure
        if not account_id:
            return {i: REASON_ACCOUNT_UNSET for i in identities}
        if not account_matches(account_id, getattr(store, "account_url", "")):
            _log.error("writer lockout on Azure: %s does not name the storage account the "
                       "store URL is on, so the role assignments it lists are not the "
                       "store's", ENV_STORAGE_ACCOUNT_ID)
            return {i: REASON_ACCOUNT_MISMATCH for i in identities}
        doc = azure.fetch(store, account_id=account_id, writers=identities)
        return azure.evaluate(doc, **azure.scope(store), writers=identities)
    except EvidenceUnavailable as exc:
        return {i: exc.code for i in identities}


def verify(store: Any, identities: tuple[str, ...] | None = None, *,
           account_id: str | None = None, now: datetime | None = None,
           evaluate: Callable[..., Mapping[str, str | None]] | None = None,
           signing_key: Any = None,
           trusted: Callable[[], Mapping[str, Any] | None] | None = None,
           verify_keys: Iterable[Any] | None = None,
           written_by: str | None = None) -> dict[str, Any] | None:
    """Evaluate every writer identity and write the verification record,
    signed with `signing_key` and carrying `written_by`. An empty identity list writes a record that
    verifies nothing.

    The record names the later of `trusted()`, the head of the overrides
    state the caller has verified, and the head a fresh record signed by
    one of `verify_keys` names. With neither, it names lockout.NO_HEAD if
    the store has never been initialized (`uninitialized`), and otherwise
    nothing is written and None is returned. None too when
    lockout.write_verification writes nothing."""
    identities = writer_identities() if identities is None else identities
    account = os.environ.get(ENV_STORAGE_ACCOUNT_ID, "") if account_id is None else account_id
    try:
        results = dict((evaluate or evaluate_store)(store, identities, account_id=account))
    except Exception as exc:  # noqa: BLE001 - a failed check verifies nothing
        _log.error("writer lockout verification failed", extra={"fields": {
            "error": type(exc).__name__}})
        results = {i: REASON_FAILED for i in identities}
    own = None
    if trusted is not None:
        try:
            own = trusted()
        except Exception as exc:  # noqa: BLE001 - a failed read names no head of its own
            _log.error("could not read the dashboard's verified overrides state; the "
                       "verification names the head the newest record names", extra={
                           "fields": {"error": type(exc).__name__}})
    _, fresh = lockout.fresh_head(store, verify_keys, now, identities=False)
    head = lockout.later_head(own, fresh)
    if head is None and not uninitialized(store, verify_keys, now):
        _log.error(
            "writer lockout verification not written: this dashboard holds no verified "
            "runtime overrides state and no fresh signed verification record names one, "
            "so there is no head readers may trust. Readers adopt nothing until "
            "`forgd-verdict overrides recover` runs as the control identity; see Recovery "
            "in docs/OVERRIDES.md")
        return None
    record = lockout.write_verification(store, results, store_kind(store) or "unknown", now,
                                        signing_key, head or lockout.NO_HEAD, written_by)
    if record is None:
        return None
    failing = {i: r for i, r in results.items() if r is not None}
    if failing or not results:
        _log.error("writer lockout not verified: runtime overrides are not adopted until "
                   "every writer identity is shown locked out", extra={"fields": {
                       "identities": failing, "configured": len(identities)}})
    return record


def uninitialized(store: Any, verify_keys: Iterable[Any] | None = None,
                  now: datetime | None = None) -> bool:
    """Whether the store shows no sign of an overrides object: none is
    present, no request record is listed, and no signed verification
    record names a head past lockout.NO_HEAD. False when any read fails."""
    try:
        found = store.read_control()
        if found.status == "ok" and found.body is not None:
            return False
        if any(n.endswith("-request.json")
               for n in lockout.override_records(store, newest_first=True)):
            return False
        named = lockout.anchored_head(store, verify_keys, now)
    except Exception:  # noqa: BLE001 - an unread store is not an empty one
        return False
    return named is None or named == lockout.NO_HEAD


class Verifier:
    """Runs `verify` at start, every `interval_s`, and whenever `due`,
    checked every `retry_s`, on a thread. Each record is signed with
    `signing_key` and names the later of the pending head and the head
    `verify` names from `trusted` and `verify_keys`. When `trusted()` names
    none, `unanchored()` stands in for it: the head of a change whose
    record was not written, read from the store.

    `anchor(head)` writes a record naming a head a change just wrote. Until
    a record names it or a later head, it is pending, and every run names
    it. Each record carries `written_by` (lockout.WRITTEN_BY_*)."""

    def __init__(self, store: Any, *, interval_s: float = lockout.VERIFY_EVERY_S,
                 retry_s: float = RETRY_S,
                 run: Callable[..., Any] | None = None, signing_key: Any = None,
                 trusted: Callable[[], Mapping[str, Any] | None] | None = None,
                 unanchored: Callable[[], Mapping[str, Any] | None] | None = None,
                 verify_keys: Iterable[Any] | None = None,
                 identities: tuple[str, ...] | None = None,
                 evaluate: Callable[..., Mapping[str, str | None]] | None = None,
                 clock: Callable[[], float] | None = None,
                 written_by: str | None = None):
        self.store = store
        self.verify_keys = None if verify_keys is None else tuple(verify_keys)
        self._trusted = trusted
        self._unanchored = unanchored
        self.pending: Mapping[str, Any] | None = None
        # The id of the newest record when the last run that did not raise ended.
        self._seen: str | None = None
        if run is None:
            def run(s: Any) -> Any:
                return verify(s, identities, signing_key=signing_key, trusted=self.head,
                              verify_keys=self.verify_keys, evaluate=evaluate,
                              written_by=written_by)
        self.interval_s = interval_s
        self.retry_s = retry_s
        self._run = run
        self._clock = clock or time.monotonic
        self._last: float | None = None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def head(self) -> Mapping[str, Any] | None:
        """The head the next record names, before the fresh record's own:
        the later of the pending head and `trusted()`, or `unanchored()`
        when `trusted()` names none."""
        own = None
        for source in (self._trusted, self._unanchored):
            if source is None or own is not None:
                continue
            try:
                own = source()
            except Exception as exc:  # noqa: BLE001 - a failed read names no head
                _log.error("could not read the overrides head for the verification",
                           extra={"fields": {"error": type(exc).__name__}})
        return lockout.later_head(own, self.pending)

    def once(self) -> dict[str, Any] | None:
        """One run; the record written, or None. A record naming the
        pending head's revision or later clears it."""
        with self._lock:
            self._last = self._clock()
            try:
                record = self._run(self.store)
            except Exception as exc:  # noqa: BLE001 - the loop outlives any one run
                _log.error("writer lockout verification could not be written",
                           extra={"fields": exc_fields(exc)})
                return None
            self._seen = (record.get("id") if isinstance(record, dict)
                          else self._newest_id())
            named = record.get("head") if isinstance(record, dict) else None
            if (self.pending is not None and isinstance(named, dict)
                    and named.get("revision", 0) >= self.pending["revision"]):
                self.pending = None
            return record

    def anchor(self, head: Mapping[str, Any]) -> dict[str, Any] | None:
        """Write a record naming `head`, a head just written. The record, or
        None when it could not be written: `head` is then pending, and the
        thread retries within `retry_s`."""
        with self._lock:
            self.pending = lockout.later_head(self.pending, dict(head))
            record = self.once()
            if self.pending is not None:
                _log.error(
                    "runtime overrides change applied, but no lockout verification naming "
                    "its head was written. Readers that hold no verified state are not "
                    "ready until one is; it is retried", extra={"fields": {
                        "revision": self.pending["revision"]}})
            return record

    def after_write(self, state: Any) -> dict[str, Any] | None:
        """`anchor` for a ControlState an `apply_change` wrote."""
        return self.anchor({"revision": state.revision, "audit_id": state.audit_id,
                            "audit_hash": state.audit_hash})

    def _newest_id(self) -> str | None:
        try:
            record = lockout.fresh_record(self.store, self.verify_keys)
        except Exception:  # noqa: BLE001 - an unread record is not a fresh one
            return None
        return record.get("id") if record is not None else None

    def due(self) -> bool:
        """Whether a run is due before `interval_s` has passed: a head is
        pending; the newest fresh record does not show every writer
        identity locked out, is not the newest one when the last run
        that did not raise ended, and was not written by a dashboard; or
        the head a run would name is at a later revision than the one the
        newest fresh record names."""
        if self.pending is not None:
            return True
        try:
            record = lockout.fresh_record(self.store, self.verify_keys)
        except Exception:  # noqa: BLE001 - an unread record is not a fresh one
            record = None
        if (record is not None and not lockout.locks_out_every_writer(record)
                and record.get("id") != self._seen
                and record.get("written_by") != lockout.WRITTEN_BY_DASHBOARD):
            return True
        head = self.head()
        if head is None:
            return False
        fresh = record.get("head") if record is not None else None
        return fresh is None or head["revision"] > fresh["revision"]

    def tick(self) -> bool:
        """Run when `interval_s` has passed since the last run or one is
        `due`. Whether it ran."""
        if (self._last is not None and self._clock() - self._last < self.interval_s
                and not self.due()):
            return False
        self.once()
        return True

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="lockout-verifier",
                                        daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        self.once()
        while not self._stop.wait(self.retry_s):
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001 - the loop outlives any one tick
                _log.error("writer lockout verification check failed",
                           extra={"fields": exc_fields(exc)})

    def stop(self) -> None:
        self._stop.set()
