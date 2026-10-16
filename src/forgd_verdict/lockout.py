"""The writer lockout probe, and the per-role reports the dashboard reads.

A writer role (the verdict server, the collector, intake and the ingest
jobs) honours runtime overrides only while it has proven that its own
credentials cannot write the runtime overrides audit prefix. It proves it
by attempting a conditional create of a uniquely named probe record there,
`audit/runtime-overrides/<YYYY-MM-DD>/probe-<role>-<instance>-<timestamp>.json`:
a 403 is the proof. A create that succeeds means the lockout is missing;
any other outcome proves nothing.

Each probe's result is published as `state/overrides-lockout-<role>.json`,
beside the org registry's per-role files, because a refused create leaves
nothing in the audit prefix for anyone else to inspect. Every reader
adopts a new object, and the dashboard allows admin actions, only while
every writer role in FORGD_OVERRIDES_WRITER_ROLES has a fresh `denied`
report. The design is docs/design/overrides.md.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import socket
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .overrides_signing import SignatureError
from .overrides_signing import sign as sign_record
from .overrides_signing import verify as verify_record
from .store.base import StoreConflict, StoreForbidden, audit_names

WRITER_ROLES = ("verdict", "collector", "intake", "ingest")
REPORT_VERSION = 1
PROBE_PREFIX = "probe-"
# How often a role re-proves a lockout it has proven, and how soon it tries
# again after a create that succeeded.
PROBE_S = 3600.0
RETRY_S = 300.0
# A verification dated this far in the future is not accepted.
_SKEW_S = 300.0

RESULT_DENIED = "denied"
RESULT_ALLOWED = "allowed"
RESULT_UNPROVEN = "unproven"
# Only under `allow_unprovable_stores_for_tests`.
RESULT_EXEMPT = "exempt"

LOCKOUT_MISSING = "writer lockout missing"
UNPROVABLE_STORE = "the store cannot prove a writer lockout"

ENV_WRITER_ROLES = "FORGD_OVERRIDES_WRITER_ROLES"

# The control identity's verification of every writer identity's lockout
# from the cloud's IAM policy (lockout_evidence), written under the audit
# prefix. Readers trust only the newest one, and only while it is fresh.
VERIFY_PREFIX = "verify-"
# A record a verification's writer creates to read the store's time from.
CLOCK_PREFIX = "clock-"
VERIFY_KIND = "lockout_verification"
VERIFY_EVERY_S = 3600.0
VERIFIED_FRESH_S = 2 * 3600.0
# What wrote a verification record, in its signed `written_by` field.
WRITTEN_BY_DASHBOARD = "dashboard"
WRITTEN_BY_CLI = "cli"
_IDENTITY = re.compile(r"[A-Za-z0-9:/@._+=,-]{1,256}")
_REASON = re.compile(r"[a-z][a-z0-9_]{0,63}")
_HEAD_ID = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{12}")
_HEAD_HASH = re.compile(r"[0-9a-f]{64}")
# The head a verification record names when the dashboard has seen no
# overrides object.
NO_HEAD = {"revision": 0, "audit_id": None, "audit_hash": None}

_log = logging.getLogger("forgd_verdict.lockout")
_INSTANCE_PART = re.compile(r"[^A-Za-z0-9]+")

# Set only by `allow_unprovable_stores_for_tests`. There is no environment
# variable or policy key for it.
_unprovable_allowed = False


def allow_unprovable_stores_for_tests(allowed: bool = True) -> None:
    """Let a store that cannot prove a lockout, such as a local directory,
    count as locked out. For tests only."""
    global _unprovable_allowed
    _unprovable_allowed = allowed


def unprovable_allowed() -> bool:
    return _unprovable_allowed


def provable(store: Any) -> bool:
    """Whether `store` enforces credentials that a 403 can prove anything
    about. True only for a backend that says so."""
    return getattr(store, "lockout_provable", False) is True


def is_probe(name: str) -> bool:
    """Whether an audit record name is a lockout probe's, a clock probe's or
    a lockout verification's, not an override's."""
    return isinstance(name, str) and name.rsplit("/", 1)[-1].startswith(
        (PROBE_PREFIX, CLOCK_PREFIX, VERIFY_PREFIX))


def override_record_leaf(day: str) -> str:
    """The leaf prefix of an override's audit records on `day`: an audit id
    begins with the day's digits, and a probe's or a verification's name
    with PROBE_PREFIX or VERIFY_PREFIX."""
    return day.replace("-", "")


def override_records(store: Any, *, newest_first: bool = False) -> Iterator[str]:
    """Names of the override audit records, requests and outcomes, day by
    day, never listing a probe or a verification."""
    return audit_names(store, override_record_leaf, newest_first=newest_first)


def new_instance() -> str:
    host = _INSTANCE_PART.sub("", socket.gethostname())[-32:] or "host"
    return f"{host}-{secrets.token_hex(4)}"


def probe_name(role: str, instance: str, now: datetime) -> str:
    return f"{now:%Y-%m-%d}/{PROBE_PREFIX}{role}-{instance}-{now:%Y%m%dT%H%M%SZ}.json"


def report_name(role: str) -> str:
    return f"overrides-lockout-{role}.json"


def _stamp(now: datetime) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ProbeResult:
    result: str
    at: str
    error: str | None = None

    @property
    def proven(self) -> bool:
        return self.result in (RESULT_DENIED, RESULT_EXEMPT)


def probe(store: Any, role: str, instance: str, now: datetime | None = None) -> ProbeResult:
    """Attempt the probe create as `role` and say what it proved."""
    moment = now or datetime.now(UTC)
    at = _stamp(moment)
    if not provable(store):
        if _unprovable_allowed:
            return ProbeResult(RESULT_EXEMPT, at)
        return ProbeResult(RESULT_UNPROVEN, at, UNPROVABLE_STORE)
    body = (json.dumps({"version": REPORT_VERSION, "kind": "probe", "role": role,
                        "instance": instance, "at": at}, sort_keys=True) + "\n").encode()
    try:
        store.put_audit(probe_name(role, instance, moment), body)
    except StoreForbidden:
        return ProbeResult(RESULT_DENIED, at)
    except StoreConflict:
        return ProbeResult(RESULT_UNPROVEN, at, "StoreConflict")
    except Exception as exc:  # noqa: BLE001 - any backend error proves nothing
        return ProbeResult(RESULT_UNPROVEN, at, type(exc).__name__)
    return ProbeResult(RESULT_ALLOWED, at)


def publish_report(store: Any, role: str, instance: str, found: ProbeResult,
                   log: logging.Logger | None = None) -> bool:
    """Write `role`'s report. Logs and returns False when it does not."""
    body = {"version": REPORT_VERSION, "role": role, "instance": instance,
            "result": found.result, "at": found.at}
    if found.error:
        body["error"] = found.error
    try:
        store.put_state(report_name(role),
                        (json.dumps(body, sort_keys=True) + "\n").encode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - any backend's write error
        (log or _log).error(
            "could not publish the writer lockout report; the dashboard refuses admin "
            "actions until it can read one", extra={"fields": {
                "role": role, "error": type(exc).__name__}})
        return False
    return True


class LockoutProbe:
    """A writer role's probe, re-run every `interval_s` once it has proven the
    lockout, every `retry_s` after a create that succeeded, and on every
    `check()` after one that proved nothing, unless the store cannot prove
    it at all.

    A probe that fails with an error keeps a denial proven less than two
    intervals ago.
    """

    def __init__(self, store: Any, role: str, *, instance: str | None = None,
                 interval_s: float = PROBE_S, retry_s: float = RETRY_S,
                 clock: Callable[[], float] | None = None,
                 now: Callable[[], datetime] | None = None,
                 log: logging.Logger | None = None):
        if role not in WRITER_ROLES:
            raise ValueError(f"not a writer role: {role!r}")
        self.store = store
        self.role = role
        self.instance = instance or new_instance()
        self.interval_s = interval_s
        self.retry_s = retry_s
        self.clock = clock or time.monotonic
        self.now = now or (lambda: datetime.now(UTC))
        self.log = log or _log
        self._last: ProbeResult | None = None
        self._last_at: float | None = None
        self._proven_at: float | None = None

    def _due(self) -> bool:
        if self._last is None or self._last_at is None:
            return True
        age = self.clock() - self._last_at
        if self._last.proven:
            return age >= self.interval_s
        if self._last.result == RESULT_ALLOWED:
            return age >= self.retry_s
        if self._last.error == UNPROVABLE_STORE:
            return age >= self.interval_s
        return True

    def check(self) -> ProbeResult:
        if not self._due():
            return self._last  # type: ignore[return-value]
        found = probe(self.store, self.role, self.instance, self.now())
        at = self.clock()
        if (found.result == RESULT_UNPROVEN and found.error != UNPROVABLE_STORE
                and self._proven_at is not None
                and at - self._proven_at < 2 * self.interval_s):
            self.log.warning(
                "the writer lockout probe failed; keeping the lockout proven earlier",
                extra={"fields": {"role": self.role, "error": found.error}})
            return self._last  # type: ignore[return-value]
        if found.proven:
            self._proven_at = at
        if found.result == RESULT_ALLOWED:
            self.log.error(
                "runtime overrides are disabled: writer lockout missing. This role's "
                "credentials created a record under the runtime overrides audit prefix, "
                "so they could forge the overrides and their audit chain. Enable the "
                "store module's control_enabled; on S3, a writer role made outside the "
                "module also needs writer_deny_policy_json",
                extra={"fields": {"role": self.role, "result": found.result}})
        elif not found.proven:
            self.log.error(
                "runtime overrides are disabled: writer lockout missing. The probe "
                "could not prove that this role's credentials cannot write the runtime "
                "overrides audit prefix", extra={"fields": {
                    "role": self.role, "result": found.result, "error": found.error}})
        if found.result != RESULT_EXEMPT:
            publish_report(self.store, self.role, self.instance, found, self.log)
        self._last, self._last_at = found, at
        return found


# -- every reader's view ---------------------------------------------------


def expected_roles(environ: Mapping[str, str] | None = None) -> tuple[str, ...] | None:
    """The writer roles the deployment runs, from ENV_WRITER_ROLES. None
    when it is unset or empty; ValueError for a name that is not a role."""
    raw = (environ if environ is not None else os.environ).get(ENV_WRITER_ROLES, "")
    names = [n.strip() for n in raw.split(",") if n.strip()]
    unknown = sorted(set(names) - set(WRITER_ROLES))
    if unknown:
        raise ValueError(f"{ENV_WRITER_ROLES} names roles that are not writer roles: "
                         f"{', '.join(unknown)}; expected any of {', '.join(WRITER_ROLES)}")
    return tuple(dict.fromkeys(names)) or None


PROBLEM_UNSET = "not configured"
PROBLEM_UNPROVABLE = "store cannot prove it"
PROBLEM_UNVERIFIED = "no verification"
PROBLEM_VERIFY_UNREADABLE = "verification unreadable"
PROBLEM_VERIFY_CHAIN = "verification chain broken"
PROBLEM_VERIFY_SIGNATURE = "verification signature invalid"
PROBLEM_VERIFY_STALE = "verification stale"
PROBLEM_VERIFY_CLOCK = "verification clock out of range"
PROBLEM_VERIFY_EMPTY = "no writer identities verified"
# Logged, with the base id, when write_verification writes nothing because
# the newest record's id is too far ahead of this process's clock.
ERROR_VERIFY_BASE_FUTURE = "verification_base_in_future"
# Logged, with the offset, when write_verification writes nothing because
# this process's clock is too far ahead of the store's.
ERROR_VERIFY_CLOCK_AHEAD = "verification_clock_ahead"


@dataclass(frozen=True)
class LockoutStatus:
    """Whether every expected writer role has a fresh `denied` report.

    `problems` maps a role, or `*` for the deployment, to a short fixed
    phrase or a report's result.
    """

    problems: Mapping[str, str] = field(default_factory=dict)
    # Whether the status was read from a verification record, and the
    # overrides head that record names (None for a record with no head).
    anchor_read: bool = False
    anchor: Mapping[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return not self.problems

    def fields(self) -> dict[str, Any]:
        return {"ok": self.ok, "problems": dict(self.problems)}


def verification_name(audit_id: str) -> str:
    return f"{audit_id[:4]}-{audit_id[4:6]}-{audit_id[6:8]}/{VERIFY_PREFIX}{audit_id}.json"


def _verification_ids(store: Any, *, newest_first: bool = False) -> Iterator[str]:
    """The verification records' ids in order, each day listed only when
    reached."""
    for name in audit_names(store, VERIFY_PREFIX, newest_first=newest_first):
        leaf = name.rsplit("/", 1)[-1]
        if leaf.endswith(".json"):
            yield leaf[len(VERIFY_PREFIX):-len(".json")]


def _verification_listed(store: Any, audit_id: Any) -> bool:
    """Whether a verification record with id `audit_id` is listed."""
    if not isinstance(audit_id, str):
        return False
    name = verification_name(audit_id)
    day, _, leaf = name.partition("/")
    try:
        return name in store.list_audit(day, leaf)
    except ValueError:
        return False


def _sha256(blob: bytes) -> str:
    import hashlib

    return hashlib.sha256(blob).hexdigest()


def write_verification(store: Any, results: Mapping[str, str | None], store_kind: str,
                       now: datetime | None = None,
                       signing_key: Any = None,
                       head: Mapping[str, Any] | None = None,
                       written_by: str | None = None) -> dict[str, Any] | None:
    """Write a verification record of `results` (writer identity -> None
    when its lockout holds, else a fixed reason), naming the overrides
    `head` (revision, audit_id, audit_hash; NO_HEAD when not given), linked
    to the newest one before it by id and SHA-256, and signed with
    `signing_key` when given, with `written_by` (WRITTEN_BY_*) when given.
    Returns the record.

    `now` is first checked against the store's time, the last-modified
    time of a clock probe record written under the audit prefix. When it
    is more than _SKEW_S ahead, nothing more is written,
    ERROR_VERIFY_CLOCK_AHEAD is logged at ERROR with the offset, and None
    is returned. A store that cannot prove a lockout and has no
    `audit_modified` is not checked; one that can prove it and has none
    is treated as a clock that cannot be checked, and nothing is written.

    A record's id is after its base's. When that puts the id too far from
    `now` for _clock_ok, nothing is written, ERROR_VERIFY_BASE_FUTURE is
    logged at ERROR with the base id, and None is returned."""
    moment = now or datetime.now(UTC)
    if not _clock_behind_store(store, moment):
        return None
    base_id = next(_verification_ids(store, newest_first=True), None)
    base_blob = store.get_audit(verification_name(base_id)) if base_id else None
    stamp = f"{moment:%Y%m%dT%H%M%S%f}Z"
    if base_id is not None and stamp <= base_id.split("-", 1)[0]:
        # Ids sort by time, so a record is newer than its base whatever the clock says.
        last = datetime.strptime(base_id.split("-", 1)[0], "%Y%m%dT%H%M%S%fZ")
        stamp = f"{last + timedelta(microseconds=1):%Y%m%dT%H%M%S%f}Z"
    audit_id = f"{stamp}-{secrets.token_hex(6)}"
    if not _clock_ok({"id": audit_id, "at": _stamp(moment)}, moment):
        _log.error("writer lockout verification not written: the newest verification record "
                   "is dated ahead of this clock, and a record chained on it would be too; "
                   "check this process's clock, and if it is right delete that record from "
                   "the store, see Recovery in docs/OVERRIDES.md",
                   extra={"fields": {"code": ERROR_VERIFY_BASE_FUTURE, "base_id": base_id}})
        return None
    record = {
        "version": REPORT_VERSION, "kind": VERIFY_KIND, "id": audit_id, "at": _stamp(moment),
        "store": store_kind, "identities": dict(sorted(results.items())),
        "ok": bool(results) and all(r is None for r in results.values()),
        "base_id": base_id, "base_hash": _sha256(base_blob) if base_blob is not None else None,
        "head": dict(head if head is not None else NO_HEAD),
    }
    if written_by is not None:
        record["written_by"] = written_by
    if not head_ok(record["head"]):
        raise ValueError("not an overrides head")
    if written_by is not None and not _REASON.fullmatch(written_by):
        raise ValueError("not a verification writer")
    if signing_key is not None:
        record = sign_record(record, signing_key)
    store.put_audit(verification_name(audit_id),
                    (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
    return record


def clock_probe_name(now: datetime) -> str:
    return f"{now:%Y-%m-%d}/{CLOCK_PREFIX}{now:%Y%m%dT%H%M%S%f}Z-{secrets.token_hex(6)}.json"


def _clock_behind_store(store: Any, moment: datetime) -> bool:
    """Whether `moment` is at most _SKEW_S ahead of the store's time, read
    from a clock probe record. Logs ERROR_VERIFY_CLOCK_AHEAD when it is
    not."""
    modified = getattr(store, "audit_modified", None)
    if not callable(modified):
        if not provable(store):
            return True
        _log.error("writer lockout verification not written: the store cannot say when a "
                   "record was written, so this process's clock cannot be checked against it",
                   extra={"fields": {"code": ERROR_VERIFY_CLOCK_AHEAD}})
        return False
    name = clock_probe_name(moment)
    store.put_audit(name, (json.dumps({"version": REPORT_VERSION, "kind": "clock",
                                       "at": _stamp(moment)}, sort_keys=True) + "\n").encode())
    ahead = (moment - modified(name)).total_seconds()
    if ahead <= _SKEW_S:
        return True
    _log.error("writer lockout verification not written: this process's clock is ahead of "
               "the store's, and readers refuse a record dated in the future; fix this "
               "process's clock", extra={"fields": {
                   "code": ERROR_VERIFY_CLOCK_AHEAD, "ahead_s": round(ahead)}})
    return False


def _checked_verification(store: Any, now: datetime, verify_keys: Iterable[Any] | None = None,
                          identities: bool = True) -> tuple[dict[str, Any] | None, str | None]:
    """The newest verification record, or None and the fixed problem that
    stops a reader trusting it. With `identities=False`, a record that
    verifies no writer identity is returned too.

    Its base may be any older record, not only the one before it: replicas
    that read the same newest record each write one on it. The base must
    exist and its stored bytes hash to `base_hash`. A record with no base
    is accepted only when the one before it has none either, as replicas
    writing the first record at once leave. With `verify_keys`, the
    newest record and its base must each carry a signature one of them
    verifies.
    """
    try:
        ids = _verification_ids(store, newest_first=True)
        newest = next(ids, None)
        if newest is None:
            return None, PROBLEM_UNVERIFIED
        blob = store.get_audit(verification_name(newest))
        record = json.loads(blob) if blob is not None else None
        if not _well_formed(record, newest):
            return None, PROBLEM_VERIFY_UNREADABLE
        base_id = record["base_id"]
        base_blob = None
        before_id = next(ids, None) if base_id is None else None
        if before_id is not None:
            before = json.loads(store.get_audit(verification_name(before_id)) or b"null")
            if not isinstance(before, dict) or before.get("base_id") is not None:
                return None, PROBLEM_VERIFY_CHAIN
        if base_id is not None:
            if base_id == newest or not _verification_listed(store, base_id):
                return None, PROBLEM_VERIFY_CHAIN
            base_blob = store.get_audit(verification_name(base_id))
    except Exception:  # noqa: BLE001 - an unreadable record verifies nothing
        return None, PROBLEM_VERIFY_UNREADABLE
    if base_id is not None and (base_blob is None or _sha256(base_blob) != record["base_hash"]):
        return None, PROBLEM_VERIFY_CHAIN
    if verify_keys is not None and not _signed(record, verify_keys, base_blob):
        return None, PROBLEM_VERIFY_SIGNATURE
    at = datetime.strptime(record["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    age = (now - at).total_seconds()
    if age > VERIFIED_FRESH_S or age < -_SKEW_S:
        return None, PROBLEM_VERIFY_STALE
    try:
        base = json.loads(base_blob) if base_blob is not None else None
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None, PROBLEM_VERIFY_CHAIN
    if not all(_clock_ok(r, now) for r in (record, base) if r is not None):
        return None, PROBLEM_VERIFY_CLOCK
    if identities and not record["identities"]:
        return None, PROBLEM_VERIFY_EMPTY
    return record, None


def _clock_ok(record: Any, now: datetime) -> bool:
    """Whether the time in the record's id is at most _SKEW_S ahead of `now`
    and within _SKEW_S of its `at`."""
    try:
        minted = datetime.strptime(record["id"].split("-", 1)[0],
                                   "%Y%m%dT%H%M%S%fZ").replace(tzinfo=UTC)
        at = datetime.strptime(record["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    return ((minted - now).total_seconds() <= _SKEW_S
            and abs((minted - at).total_seconds()) <= _SKEW_S)


def _signed(record: Mapping[str, Any], verify_keys: Iterable[Any],
            base_blob: bytes | None) -> bool:
    keys = tuple(verify_keys)
    try:
        verify_record(record, keys)
        if base_blob is not None:
            base = json.loads(base_blob)
            if not isinstance(base, dict):
                return False
            verify_record(base, keys)
    except (SignatureError, ValueError, UnicodeDecodeError, RecursionError):
        return False
    return True


def _well_formed(record: Any, audit_id: str) -> bool:
    if not (isinstance(record, dict) and record.get("version") == REPORT_VERSION
            and record.get("kind") == VERIFY_KIND and record.get("id") == audit_id
            and isinstance(record.get("identities"), dict)):
        return False
    try:
        datetime.strptime(record.get("at"), "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return False
    base_id, base_hash = record.get("base_id"), record.get("base_hash")
    if (base_id is None) != (base_hash is None):
        return False
    if "head" in record and not head_ok(record["head"]):
        return False
    if "written_by" in record and not (isinstance(record["written_by"], str)
                                       and _REASON.fullmatch(record["written_by"])):
        return False
    return all(isinstance(i, str) and _IDENTITY.fullmatch(i)
               and (r is None or (isinstance(r, str) and _REASON.fullmatch(r)))
               for i, r in record["identities"].items())


def head_ok(head: Any) -> bool:
    """Whether `head` is NO_HEAD, or a revision of at least 1 with a
    well-formed audit id and hash."""
    if not (isinstance(head, dict) and set(head) == set(NO_HEAD)):
        return False
    revision = head["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool):
        return False
    if head == NO_HEAD:
        return True
    return (revision >= 1 and isinstance(head["audit_id"], str)
            and bool(_HEAD_ID.fullmatch(head["audit_id"]))
            and isinstance(head["audit_hash"], str)
            and bool(_HEAD_HASH.fullmatch(head["audit_hash"])))


def later_head(first: Mapping[str, Any] | None,
               second: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    """The head with the higher revision; `second` when they are equal."""
    if first is None or second is None:
        return second if first is None else first
    return first if first["revision"] > second["revision"] else second


def anchored_head(store: Any, verify_keys: Iterable[Any] | None,
                  now: datetime | None = None) -> Mapping[str, Any] | None:
    """The head the newest well-formed verification record with a head
    names, fresh or not, counting only records signed by one of
    `verify_keys` when given. None when there is none. Only a recover
    uses a head that is not fresh, to choose what it keeps."""
    moment = now or datetime.now(UTC)
    keys = None if verify_keys is None else tuple(verify_keys)
    for audit_id in _verification_ids(store, newest_first=True):
        try:
            blob = store.get_audit(verification_name(audit_id))
            record = json.loads(blob) if blob is not None else None
        except Exception:  # noqa: BLE001 - an unreadable record names no head
            continue
        if not (_well_formed(record, audit_id) and "head" in record
                and _clock_ok(record, moment)):
            continue
        if keys is not None and not _signed(record, keys, None):
            continue
        return record["head"]
    return None


def fresh_record(store: Any, verify_keys: Iterable[Any] | None,
                 now: datetime | None = None) -> dict[str, Any] | None:
    """The newest verification record when a reader would trust it as
    fresh, whether or not it verifies any writer identity; else None."""
    return _checked_verification(store, now or datetime.now(UTC), verify_keys, False)[0]


def locks_out_every_writer(record: Mapping[str, Any]) -> bool:
    """Whether a verification record shows at least one writer identity,
    and every one it shows locked out."""
    identities = record.get("identities")
    return (isinstance(identities, dict) and bool(identities)
            and all(r is None for r in identities.values()))


def fresh_head(store: Any, verify_keys: Iterable[Any] | None,
               now: datetime | None = None,
               identities: bool = True) -> tuple[bool, Mapping[str, Any] | None]:
    """(whether a fresh verification record is trusted, the head it names).
    With `identities=False`, a record that verifies no writer identity
    counts."""
    record, _ = _checked_verification(store, now or datetime.now(UTC), verify_keys,
                                      identities)
    return record is not None, record.get("head") if record is not None else None


def lockout_status(store: Any, roles: Iterable[str] | None,
                   now: datetime | None = None,
                   verify_keys: Iterable[Any] | None = None) -> LockoutStatus:
    """Whether the newest verification record is fresh, chained to the one
    before it, and shows every writer identity locked out.

    The writers' own reports are not read: a writer that can write them
    could forge them. `problems` maps a failing writer identity to its
    reason, or `*` to why no record is trusted. With `verify_keys`, a
    record and its base must be signed by one of them.
    """
    if not provable(store):
        return LockoutStatus() if _unprovable_allowed else LockoutStatus(
            {"*": PROBLEM_UNPROVABLE})
    if not roles:
        return LockoutStatus({"*": PROBLEM_UNSET})
    record, problem = _checked_verification(store, now or datetime.now(UTC), verify_keys)
    if record is None:
        return LockoutStatus({"*": problem}, anchor_read=True)  # type: ignore[dict-item]
    return LockoutStatus({i: r for i, r in record["identities"].items() if r is not None},
                         anchor_read=True, anchor=record.get("head"))


class LockoutReports:
    """The writers' reports as every reader checks them, re-read every
    `ttl_s` seconds and on `refresh()`."""

    def __init__(self, store: Any, roles: Iterable[str] | None, *, ttl_s: float = 60.0,
                 clock: Callable[[], float] | None = None,
                 now: Callable[[], datetime] | None = None,
                 verify_keys: Iterable[Any] | None = None):
        self.store = store
        self.roles = tuple(roles) if roles else None
        self.verify_keys = None if verify_keys is None else tuple(verify_keys)
        self.ttl_s = ttl_s
        self.clock = clock or time.monotonic
        self.now = now or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._status: LockoutStatus | None = None
        self._loaded_at: float | None = None

    def refresh(self) -> LockoutStatus:
        with self._lock:
            status = lockout_status(self.store, self.roles, self.now(), self.verify_keys)
            self._status, self._loaded_at = status, self.clock()
            return status

    def current(self) -> LockoutStatus:
        with self._lock:
            stale = (self._status is None or self._loaded_at is None
                     or self.clock() - self._loaded_at >= self.ttl_s)
        return self.refresh() if stale else self._status  # type: ignore[return-value]


__all__ = [
    "ENV_WRITER_ROLES", "LOCKOUT_MISSING", "LockoutProbe", "LockoutReports", "LockoutStatus",
    "NO_HEAD", "anchored_head", "fresh_head", "head_ok", "later_head",
    "ProbeResult", "VERIFIED_FRESH_S", "VERIFY_EVERY_S", "WRITER_ROLES",
    "allow_unprovable_stores_for_tests", "expected_roles", "is_probe", "lockout_status", "probe",
    "publish_report", "report_name", "verification_name", "write_verification",
]
