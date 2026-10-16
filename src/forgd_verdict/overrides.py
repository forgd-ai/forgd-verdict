"""Runtime overrides: a closed allowlist of settings changed without a release.

The state is one object in the findings store, `state/runtime-overrides.json`,
written by the dashboard's admins and by the CLI, and read by every service
through `RuntimeOverrides`. Each change is recorded first as an immutable
request record under `audit/runtime-overrides/`, and the object names the
request that produced it by id and SHA-256. Each request carries the hash of
the one before it, and the digest of the object it produces. The design is
docs/design/overrides.md.

Precedence: policy.yaml < ENV_OVERRIDES < runtime overrides. Only the keys in
ALLOWLIST are applied; any other key in the object is ignored and logged.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from itertools import islice
from typing import TYPE_CHECKING, Any

from .applog import exc_fields
from .core import scan
from .lockout import (
    LOCKOUT_MISSING,
    RESULT_ALLOWED,
    RESULT_UNPROVEN,
    WRITER_ROLES,
    LockoutProbe,
    LockoutReports,
    LockoutStatus,
    anchored_head,
    expected_roles,
    fresh_head,
    override_records,
    provable,
)
from .models import (
    DEVICE_ID,
    FINDINGS_CAPPED,
    UNSCANNED,
    UNSCANNED_ARTIFACT,
    UNSCANNED_CAPPED,
    ScanUnit,
    pseudonym,
)
from .orgregistry import REFRESH_S
from .overrides_signing import (
    ENV_VERIFY_KEY,
    SIGNATURE_FIELD,
    KeyConfigError,
    SignatureError,
    key_id,
    refuse_signing_key,
    verify_keys_from_policy,
)
from .overrides_signing import sign as sign_record
from .overrides_signing import verify as verify_record
from .store.base import ControlRead, StoreConflict, StoreForbidden, StoreReadError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    VerifyKeys = Collection[Ed25519PublicKey] | None

VERSION = 1

KEY_MODE = "server.mode"
MODE_VALUES = ("observe", "enforce")


def _mode_value(value: Any) -> str:
    if value not in MODE_VALUES:
        raise ValueError("server.mode override must be observe|enforce")
    return value


# Key -> the policy path it overrides and the validator for its value.
ALLOWLIST: dict[str, tuple[tuple[str, ...], Callable[[Any], Any]]] = {
    KEY_MODE: (("server", "mode"), _mode_value),
}
# Key -> the InvalidState code for a stored value its validator rejects.
_INVALID_VALUE = {KEY_MODE: "invalid_mode"}

# Marker state, held in the object beside `overrides`.
FIELD_RESET = "stats_reset"
FIELD_EXCLUDED = "excluded_requests"
# Intake device ids refused on every route. Written only when non-empty, and
# raises min_reader_version so a reader that predates it does not adopt an
# object whose revocations it would ignore.
FIELD_DENIED_DEVICES = "denied_devices"
MAX_DENIED_DEVICES = 5_000
# Set by legacy.migrate and by nothing else. A reader holding an object
# with it ignores the markers/* objects.
FIELD_RETIRED = "legacy_markers_retired"
FIELD_RETIRED_BY = "legacy_markers_retired_by"
# The lowest release that may apply the object, written with `server.mode`.
FIELD_MIN_READER = "min_reader_version"

ACTION_SET = "override.set"
ACTION_CLEAR = "override.clear"
ACTION_CLEAR_ALL = "override.clear_all"
ACTION_RESET = "stats.reset"
ACTION_RESET_CLEAR = "stats.reset_clear"
ACTION_EXCLUDE = "exclusion.add"
ACTION_UNEXCLUDE = "exclusion.remove"
ACTION_EXCLUDE_CLEAR = "exclusion.clear"
ACTION_DENY_DEVICE = "device.deny"
ACTION_UNDENY_DEVICE = "device.undeny"
ACTION_DENY_CLEAR = "device.clear"
ACTION_MIGRATE = "legacy.migrate"
ACTION_RECOVER = "state.recover"
ACTION_INIT = "state.init"
# Written by apply_change, never requested: the full state, so a reader's
# walk ends here.
ACTION_CHECKPOINT = "state.checkpoint"
# A chain start carries the whole state it starts from, except a write to
# an absent object, which starts from empty.
STARTS = (ACTION_INIT, ACTION_RECOVER, ACTION_CHECKPOINT)
# The most links a reader walks back from the object's head record to a
# chain start or its last-known-good. apply_change writes a checkpoint
# before a change that would take the head further from its start.
CHECKPOINT_EVERY = 100

# What the dashboard may do: everything but migration, which only the CLI
# runs.
DASHBOARD_ACTIONS = frozenset({
    ACTION_SET, ACTION_CLEAR, ACTION_CLEAR_ALL, ACTION_RESET, ACTION_RESET_CLEAR,
    ACTION_EXCLUDE, ACTION_UNEXCLUDE, ACTION_EXCLUDE_CLEAR, ACTION_RECOVER, ACTION_INIT,
    ACTION_DENY_DEVICE, ACTION_UNDENY_DEVICE, ACTION_DENY_CLEAR,
})
ACTIONS = DASHBOARD_ACTIONS | {ACTION_MIGRATE}
# The dashboard actions that change one request's or one device's entry, and
# the record field holding that value. The orgs such an action affects are
# the orgs of the records carrying the value.
SCOPED_ACTIONS = {
    ACTION_EXCLUDE: "request_id", ACTION_UNEXCLUDE: "request_id",
    ACTION_DENY_DEVICE: "device", ACTION_UNDENY_DEVICE: "device",
}
# Every other dashboard action affects every org the deployment serves.
DEPLOYMENT_ACTIONS = DASHBOARD_ACTIONS - SCOPED_ACTIONS.keys()

# The object field a marker action changes, named in its audit record.
_FIELD_OF = {
    ACTION_RESET: FIELD_RESET, ACTION_RESET_CLEAR: FIELD_RESET,
    ACTION_EXCLUDE: FIELD_EXCLUDED, ACTION_UNEXCLUDE: FIELD_EXCLUDED,
    ACTION_EXCLUDE_CLEAR: FIELD_EXCLUDED,
    ACTION_DENY_DEVICE: FIELD_DENIED_DEVICES, ACTION_UNDENY_DEVICE: FIELD_DENIED_DEVICES,
    ACTION_DENY_CLEAR: FIELD_DENIED_DEVICES,
}

STATUS_OK = "ok"
STATUS_ABSENT = "absent"
STATUS_UNREADABLE = "unreadable"
STATUS_INVALID = "invalid"
STATUS_DISABLED = "disabled"

SOURCE_OBJECT = "object"
SOURCE_LKG = "last_known_good"
SOURCE_BASELINE = "baseline"

# Why a cold reader that finds no object is not ready, when the audit
# prefix lists records.
ERROR_ORPHANED = "audit records exist but the object is absent"
REFUSED_ORPHANED = f"{ERROR_ORPHANED}; run `forgd-verdict overrides recover` to rebuild it"
# Why a cold reader that finds no object and no audit records is not ready.
ERROR_UNINITIALIZED = "the store is not initialized; run forgd-verdict overrides init"
# Why a reader does not adopt an object whose min_reader_version is above
# its own release.
ERROR_READER_TOO_OLD = "reader_version_too_old"
# FORGD_OVERRIDES_VERIFY_KEY is unset or does not parse; the store is not read.
ERROR_VERIFY_KEY = "verify_key_misconfigured"
# Runtime overrides are honoured but the service resolved no store to read.
ERROR_NO_STORE = "store_not_configured"
# A cold reader's fresh verification record names no overrides head.
ERROR_ANCHOR_MISSING = "head_anchor_missing"
# The object is older than the head a fresh verification record names, or
# at its revision with another audit id or hash.
ERROR_BEFORE_ANCHOR = "object_before_anchor"
# A cold reader's object is newer than the head the newest fresh
# verification record names.
ERROR_NOT_ANCHORED = "object_not_anchored"
# A cold reader's object is behind a signed request record that has no
# signed `error` outcome (latest_request_revision).
ERROR_BEHIND_REQUEST = "object_behind_request"
# Why every change but `state.recover` is refused over an object behind
# such a request record.
REFUSED_BEHIND_REQUEST = (f"{ERROR_BEHIND_REQUEST}: a signed request record names a later "
                          "revision than the object. If no change is being written, run "
                          "`forgd-verdict overrides recover`")
# Why a recover writes nothing when a signed chain retired the legacy
# markers and the migration that did cannot be verified.
ERROR_RETIREMENT_UNVERIFIED = "retirement_unverified"
REFUSED_RETIREMENT_UNVERIFIED = (f"{ERROR_RETIREMENT_UNVERIFIED}: the legacy markers are retired "
                                 "on a signed chain, but the migration that retired them cannot "
                                 "be verified, so the recovered object can neither carry the "
                                 "retirement nor drop it")
# Why a recover writes nothing when two request records at the newest
# revision each verify and nothing signed says which one was applied.
ERROR_HEAD_AMBIGUOUS = "head_ambiguous"
REFUSED_HEAD_AMBIGUOUS = (f"{ERROR_HEAD_AMBIGUOUS}: more than one signed request record at the "
                          "newest revision verifies, and no verification record or signed "
                          "outcome says which one was applied")
ANCHOR_ERRORS = (ERROR_ANCHOR_MISSING, ERROR_BEFORE_ANCHOR, ERROR_NOT_ANCHORED,
                 ERROR_BEHIND_REQUEST)

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z")
# The hook events that produce a record (extract.hook_units).
HOOK_EVENTS = ("UserPromptSubmit", "UserPromptExpansion", "PreToolUse", "PostToolUse")
_ID_PART = r"[A-Za-z0-9_-]{1,128}"
# A request id as the producers write one: the inference hook's upstream
# `request_id` or `webhook-id` as one part; the Claude Code hook's
# `<event>:<tool name or "prompt">:<tool_use_id, prompt_id or ULID>`; and
# intake's `<event>:<ULID>`.
_REQUEST_ID = re.compile(
    rf"{_ID_PART}|(?:{'|'.join(HOOK_EVENTS)})(?::{_ID_PART}){{1,2}}")
_AUDIT_ID = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{12}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RELEASE = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")


def release(value: Any) -> tuple[int, int, int] | None:
    """`value` as (major, minor, patch) when it is a strict release
    version such as 0.29.8, else None."""
    m = _RELEASE.fullmatch(value) if isinstance(value, str) else None
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def reader_supports(min_reader: str | None, reader: str) -> bool:
    """Whether a reader at release `reader` may apply an object that needs
    `min_reader`. A `reader` that is not a release supports no minimum."""
    if min_reader is None:
        return True
    have, need = release(reader), release(min_reader)
    return have is not None and need is not None and have >= need


def _stamped(state: ControlState, version: str | None) -> ControlState:
    """`state` with its min_reader_version raised to `version`, or kept
    with `version` None, and removed when neither `server.mode` nor a
    denied device is set."""
    if not _needs_reader(state):
        return replace(state, min_reader_version=None)
    if version is None:
        return state
    held = state.min_reader_version
    if held is not None and release(held) >= release(version):  # type: ignore[operator]
        return state
    return replace(state, min_reader_version=version)


def _needs_reader(state: ControlState) -> bool:
    """Whether `state` holds a field an older reader would silently ignore."""
    return KEY_MODE in state.overrides or bool(state.denied_devices)


def _current_version() -> str:
    from . import __version__

    return __version__

_log = logging.getLogger("forgd_verdict.overrides")


class InvalidState(ValueError):
    """The object is present but cannot be applied.

    Its message, also `code`, is a fixed snake_case code naming the check
    that failed. It carries nothing from the object or an audit record.
    """

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NoChange(Exception):
    """The requested change would leave the object as it is."""


class Refused(ValueError):
    """The change is not allowed against the object as it stands."""


class Matched(Refused):
    """A detector found something in a value; names only the detectors."""

    def __init__(self, message: str, detectors: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.detectors = tuple(detectors)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp(value: Any, code: str) -> str | None:
    """`value`, a UTC timestamp or None. InvalidState(`code`) otherwise."""
    if value is None:
        return None
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise InvalidState(code)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ" if "." in value
                          else "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise InvalidState(code) from None
    return value


def device_id_ok(value: Any) -> bool:
    return isinstance(value, str) and DEVICE_ID.fullmatch(value) is not None


def request_id_ok(value: Any) -> bool:
    return isinstance(value, str) and bool(_REQUEST_ID.fullmatch(value))


def _strings(value: Any) -> list[str]:
    """Every non-empty string in `value`, through mappings and sequences."""
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Mapping):
        return [s for k, v in value.items() for s in _strings(k) + _strings(v)]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [s for v in value for s in _strings(v)]
    return []


# How `screen` words each marker `core.scan` adds to `detectors_skipped`.
_SKIP_MARKERS = {
    FINDINGS_CAPPED: "too many findings to review",
    UNSCANNED: "part of it is over the size limit for scanning",
    UNSCANNED_CAPPED: "part of it is over the size limit for scanning",
    UNSCANNED_ARTIFACT: "an artifact could not be fetched to scan",
}


def _not_scanned(skipped: Sequence[str]) -> str:
    """`skipped` as a reason: the detectors that did not run, then each
    marker's wording once."""
    named = sorted({s for s in skipped if s not in _SKIP_MARKERS})
    parts = [", ".join(named) + " did not run"] if named else []
    for marker in skipped:
        wording = _SKIP_MARKERS.get(marker)
        if wording is not None and wording not in parts:
            parts.append(wording)
    return "; ".join(parts)


def screen(values: Iterable[Any], detectors: Sequence[Any]) -> None:
    """Refused, naming only the detectors, when any of `values` holds a finding.

    Each string is scanned as its own unit, so the entropy tier's context
    gate sees the value alone. An empty detector list, or a detector that
    did not run, refuses too.
    """
    if not detectors:
        raise Refused("no detectors are configured, so the change cannot be scanned")
    units = [ScanUnit(f"value[{i}]", None, text)
             for i, text in enumerate(s for v in values for s in _strings(v))]
    if not units:
        return
    result = scan(units, detectors)
    if result.detectors_skipped:
        raise Refused("the change could not be checked: "
                      + _not_scanned(result.detectors_skipped))
    if result.findings:
        names = sorted({f.detector for f in result.findings})
        raise Matched(f"the change matched a detector: {', '.join(names)}", names)


WITHHELD = "<withheld>"


def screened_identity(value: Any, detectors: Sequence[Any], salt: str = "") -> dict[str, Any]:
    """The log fields for an identity a token supplied, such as a
    preferred_username.

    `{"who": value}` when no detector matches it. On a match, `who` is a
    pseudonym salted with `salt` and `who_matched` names the detectors; with
    an empty salt, `who` is WITHHELD, since a truncated bare sha256 of a
    low-entropy value can be guessed. When it cannot be scanned, `who` is
    WITHHELD and `who_unscanned` is set.
    """
    if not isinstance(value, str) or not value:
        return {"who": value}
    try:
        screen([value], detectors)
    except Matched as exc:
        return {"who": pseudonym(value, salt, "who") if salt else WITHHELD,
                "who_matched": list(exc.detectors)}
    except Refused:
        return {"who": WITHHELD, "who_unscanned": True}
    return {"who": value}


WITHHELD_ORG = "withheld (organization id)"
WITHHELD_UNSCANNED = "withheld (not scanned)"


class OrgScreen:
    """Every configured org id in a value, replaced before the value is
    stored, logged, rendered or printed.

    Each occurrence of an org id in a string, compared without case, becomes
    `pseudonym(id, salt, "org")`, or WITHHELD_ORG when there is no salt.
    Mappings, lists and tuples are screened recursively, keys included.
    Built with `org_ids=None`, when the policy could not be read, every
    string becomes WITHHELD_UNSCANNED.
    """

    def __init__(self, org_ids: Collection[str] | None, salt: str = ""):
        self.available = org_ids is not None
        ids = sorted({o.lower() for o in org_ids or () if o}, key=len, reverse=True)
        self._to = {o: pseudonym(o, salt, "org") if salt else WITHHELD_ORG for o in ids}
        self._pattern = (re.compile("|".join(re.escape(o) for o in ids), re.IGNORECASE)
                         if ids else None)

    def __call__(self, value: Any) -> Any:
        if isinstance(value, str):
            if not self.available:
                return WITHHELD_UNSCANNED
            if self._pattern is None:
                return value
            return self._pattern.sub(lambda m: self._to[m.group(0).lower()], value)
        if isinstance(value, Mapping):
            return {(self(k) if self.available else k): self(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self(v) for v in value]
        return value

    def holds(self, value: Any) -> bool:
        """Whether any string in `value` holds an org id."""
        return self._pattern is not None and any(
            self._pattern.search(t) for t in _strings(value))


def org_screen_of(policy: Any) -> OrgScreen:
    """The OrgScreen for the policy's org ids and `privacy.hash_salt`."""
    return OrgScreen(org_ids_of(policy), policy.hash_salt)


ORG_SCREEN_UNAVAILABLE = OrgScreen(None)


def exclusion_label(value: str, detectors: Sequence[Any] | None,
                    org_ids: Collection[str]) -> str:
    """A legacy exclusion as a page or the CLI shows it.

    `value` itself only when it is not one of `org_ids` (compared without
    case) and no detector matches it. Otherwise `withheld (<detector>)`,
    WITHHELD_ORG, or WITHHELD_UNSCANNED when the detectors cannot run.
    """
    if value.lower() in {o.lower() for o in org_ids}:
        return WITHHELD_ORG
    try:
        screen([value], detectors or ())
    except Matched as exc:
        return f"withheld ({', '.join(exc.detectors)})"
    except Refused:
        return WITHHELD_UNSCANNED
    return value


def _clean(value: str, detectors: Sequence[Any]) -> bool:
    try:
        screen([value], detectors)
    except Matched:
        return False
    return True


@dataclass(frozen=True)
class OverrideEntry:
    value: Any
    set_at: str | None = None
    set_by: Mapping[str, Any] = field(default_factory=dict)
    audit_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {"value": self.value, "set_at": self.set_at,
                "set_by": dict(self.set_by), "audit_id": self.audit_id}


@dataclass(frozen=True)
class ControlState:
    revision: int = 0
    audit_id: str | None = None
    audit_hash: str | None = None
    updated_at: str | None = None
    overrides: Mapping[str, OverrideEntry] = field(default_factory=dict)
    stats_reset: str | None = None
    excluded_requests: frozenset[str] = frozenset()
    legacy_markers_retired: bool = False
    # The audit id of the `legacy.migrate` request that retired them.
    retired_by: str | None = None
    # Keys present in the object and not on ALLOWLIST. Never applied.
    ignored: tuple[str, ...] = ()
    # Present only while `server.mode` or a denied device is set.
    min_reader_version: str | None = None
    denied_devices: frozenset[str] = frozenset()

    def value(self, key: str) -> Any:
        entry = self.overrides.get(key)
        return entry.value if entry is not None else None

    def to_json(self) -> dict[str, Any]:
        return {
            "version": VERSION,
            "revision": self.revision,
            "audit_id": self.audit_id,
            "audit_hash": self.audit_hash,
            "updated_at": self.updated_at,
            "overrides": {k: v.to_json() for k, v in sorted(self.overrides.items())},
            FIELD_RESET: self.stats_reset,
            FIELD_EXCLUDED: sorted(self.excluded_requests),
            # Written only when true.
            **({FIELD_RETIRED: True, FIELD_RETIRED_BY: self.retired_by}
               if self.legacy_markers_retired else {}),
            # Written only when set.
            **({FIELD_MIN_READER: self.min_reader_version}
               if self.min_reader_version is not None else {}),
            # Written only when non-empty, so an object without one has the
            # digest it had before the field existed.
            **({FIELD_DENIED_DEVICES: sorted(self.denied_devices)}
               if self.denied_devices else {}),
        }

    def to_bytes(self) -> bytes:
        return (json.dumps(self.to_json(), indent=2, sort_keys=False) + "\n").encode("utf-8")

    def effective(self) -> tuple:
        """What a reader applies, for telling one state from another."""
        return (tuple(sorted((k, v.value) for k, v in self.overrides.items())),
                self.stats_reset, tuple(sorted(self.excluded_requests)),
                self.legacy_markers_retired, tuple(sorted(self.denied_devices)))


EMPTY = ControlState()


def parse_state(blob: bytes) -> ControlState:
    """The object as a ControlState. InvalidState for anything malformed.

    A key that is not on ALLOWLIST does not make the object invalid; it is
    listed in `ignored` and never applied.
    """
    try:
        raw = json.loads(blob)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise InvalidState("not_json") from None
    if not isinstance(raw, dict):
        raise InvalidState("not_object")
    if raw.get("version") != VERSION:
        raise InvalidState("unknown_version")
    revision = raw.get("revision", 0)
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise InvalidState("revision_malformed")
    audit_id = raw.get("audit_id")
    if audit_id is not None and not (isinstance(audit_id, str) and _AUDIT_ID.fullmatch(audit_id)):
        raise InvalidState("audit_id_malformed")
    audit_hash = raw.get("audit_hash")
    if audit_hash is not None and not (isinstance(audit_hash, str)
                                       and _SHA256.fullmatch(audit_hash)):
        raise InvalidState("audit_hash_malformed")
    updated_at = _timestamp(raw.get("updated_at"), "updated_at_malformed")
    entries = raw.get("overrides", {})
    if not isinstance(entries, dict):
        raise InvalidState("overrides_not_mapping")
    overrides: dict[str, OverrideEntry] = {}
    ignored: list[str] = []
    for key, entry in entries.items():
        if key not in ALLOWLIST:
            ignored.append(str(key))
            continue
        if not isinstance(entry, dict) or "value" not in entry:
            raise InvalidState("override_entry_malformed")
        try:
            value = ALLOWLIST[key][1](entry["value"])
        except ValueError:
            raise InvalidState(_INVALID_VALUE[key]) from None
        set_by = entry.get("set_by") or {}
        if not isinstance(set_by, dict):
            raise InvalidState("override_set_by_malformed")
        entry_audit = entry.get("audit_id")
        if entry_audit is not None and not isinstance(entry_audit, str):
            raise InvalidState("override_audit_id_malformed")
        set_at = _timestamp(entry.get("set_at"), "override_set_at_malformed")
        overrides[key] = OverrideEntry(value, set_at, set_by, entry_audit)
    stats_reset = _timestamp(raw.get(FIELD_RESET), "stats_reset_malformed")
    excluded = raw.get(FIELD_EXCLUDED, [])
    if not isinstance(excluded, list) or not all(request_id_ok(r) for r in excluded):
        raise InvalidState("excluded_requests_malformed")
    retired = raw.get(FIELD_RETIRED, False)
    if not isinstance(retired, bool):
        raise InvalidState("retired_malformed")
    retired_by = raw.get(FIELD_RETIRED_BY)
    if retired != (retired_by is not None) or (
            retired_by is not None and not (isinstance(retired_by, str)
                                            and _AUDIT_ID.fullmatch(retired_by))):
        raise InvalidState("retired_by_malformed")
    denied = raw.get(FIELD_DENIED_DEVICES, [])
    if (not isinstance(denied, list) or not all(device_id_ok(d) for d in denied)
            or len(denied) > MAX_DENIED_DEVICES
            or (FIELD_DENIED_DEVICES in raw and not denied)):
        raise InvalidState("denied_devices_malformed")
    min_reader = raw.get(FIELD_MIN_READER)
    if FIELD_MIN_READER in raw and release(min_reader) is None:
        raise InvalidState("min_reader_version_malformed")
    if min_reader is not None and KEY_MODE not in overrides and not denied:
        raise InvalidState("min_reader_version_without_mode")
    if denied and min_reader is None:
        raise InvalidState("denied_devices_without_min_reader")
    return ControlState(revision, audit_id, audit_hash, updated_at, overrides, stats_reset,
                        frozenset(excluded), retired, retired_by, tuple(sorted(ignored)),
                        min_reader, frozenset(denied))


def _forbidden_root(key: str) -> bool:
    return key.split(".", 1)[0] in ("detectors", "privacy")


# -- the chain -------------------------------------------------------------


def _sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def state_digest(state: ControlState) -> str:
    """The SHA-256 of the object's content, less `audit_hash`, canonically.

    A request record carries the digest of the object its write produces,
    which cannot include the hash of the record itself.
    """
    body = state.to_json()
    del body["audit_hash"]
    return _sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                              default=str).encode("utf-8"))


# A record id or `at` this far ahead of now, or this far from each other,
# is refused.
SKEW_S = 300.0


def clock_ok(audit_id: Any, at: Any, now: datetime | None = None) -> bool:
    """Whether the time in `audit_id` is at most SKEW_S ahead of `now` and
    within SKEW_S of `at`."""
    try:
        minted = datetime.strptime(audit_id.split("-", 1)[0], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
        stamped = datetime.strptime(at, "%Y-%m-%dT%H:%M:%S.%fZ" if "." in at
                                    else "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (AttributeError, TypeError, ValueError):
        return False
    moment = now or datetime.now(UTC)
    return ((minted - moment).total_seconds() <= SKEW_S
            and abs((minted - stamped).total_seconds()) <= SKEW_S)


def _request(store: Any, audit_id: Any, expected_hash: Any,
             verify_keys: VerifyKeys = None) -> dict[str, Any]:
    """The request record `audit_id`, if its stored bytes hash to `expected_hash`.

    InvalidState when the id or hash is malformed, the record is missing, or
    its bytes do not match. With `verify_keys`, also when its signature is
    missing or malformed or does not verify under one of them. A failed read
    raises whatever the store raises.
    """
    if not (isinstance(audit_id, str) and _AUDIT_ID.fullmatch(audit_id)):
        raise InvalidState("chain_audit_id_malformed")
    if not (isinstance(expected_hash, str) and _SHA256.fullmatch(expected_hash)):
        raise InvalidState("chain_hash_missing")
    blob = store.get_audit(audit_name(audit_id, "request"))
    if blob is None:
        raise InvalidState("chain_record_missing")
    if _sha256(blob) != expected_hash:
        raise InvalidState("chain_hash_mismatch")
    try:
        record = json.loads(blob)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise InvalidState("chain_record_not_json") from None
    if not (isinstance(record, dict) and record.get("kind") == "request"
            and record.get("id") == audit_id):
        raise InvalidState("chain_record_misnamed")
    if not clock_ok(audit_id, record.get("at")):
        raise InvalidState("chain_record_clock")
    if verify_keys is not None:
        try:
            verify_record(record, verify_keys)
        except SignatureError:
            raise InvalidState("chain_signature_invalid") from None
    return record


def _names_change(record: Mapping[str, Any], state: ControlState) -> bool:
    """Whether the object holds what `record`'s action sets."""
    action, key = record.get("action"), record.get("key")
    old, new = record.get("old_value"), record.get("new_value")
    if action == ACTION_SET:
        entry = state.overrides.get(key)
        return (entry is not None and entry.value == new
                and entry.audit_id == record.get("id"))
    if action == ACTION_CLEAR:
        return key in ALLOWLIST and key not in state.overrides
    if action == ACTION_CLEAR_ALL:
        return not state.overrides
    if action == ACTION_RESET:
        return new is not None and state.stats_reset == new
    if action == ACTION_RESET_CLEAR:
        return state.stats_reset is None
    if action == ACTION_EXCLUDE:
        return new in state.excluded_requests
    if action == ACTION_UNEXCLUDE:
        return old is not None and old not in state.excluded_requests
    if action == ACTION_EXCLUDE_CLEAR:
        return not state.excluded_requests
    if action == ACTION_DENY_DEVICE:
        return new in state.denied_devices
    if action == ACTION_UNDENY_DEVICE:
        return old is not None and old not in state.denied_devices
    if action == ACTION_DENY_CLEAR:
        return not state.denied_devices
    if action == ACTION_MIGRATE:
        return state.legacy_markers_retired and new == {
            FIELD_RESET: state.stats_reset, FIELD_EXCLUDED: sorted(state.excluded_requests),
            FIELD_RETIRED: True}
    if action == ACTION_INIT:
        return (not state.overrides and state.stats_reset is None
                and not state.excluded_requests and not state.legacy_markers_retired
                and not state.denied_devices)
    if action in (ACTION_RECOVER, ACTION_CHECKPOINT):
        return new == snapshot_of(state)
    return False


_NOT_SNAPSHOT = ("version", "revision", "audit_id", "audit_hash", "updated_at")


def snapshot_of(state: ControlState) -> dict[str, Any]:
    """The object's content less its version, revision, audit fields and
    time: what a recover or checkpoint record carries."""
    body = state.to_json()
    for name in _NOT_SNAPSHOT:
        del body[name]
    return body


def _from_snapshot(new: Any, revision: int) -> ControlState:
    """The state a recover or checkpoint record carries, at `revision`.
    InvalidState unless `new` is exactly what snapshot_of writes."""
    if not isinstance(new, dict) or set(new) & set(_NOT_SNAPSHOT):
        raise InvalidState("start_state_malformed")
    state = parse_state(json.dumps({**new, "version": VERSION, "revision": revision}).encode())
    if state.ignored or snapshot_of(state) != new:
        raise InvalidState("start_state_malformed")
    return state


def _transition(parent: ControlState | None, record: Mapping[str, Any]) -> ControlState:
    """The object `record` produces from `parent`, as apply_change writes it,
    with no audit_hash. `parent` is None for a record that starts a chain.

    Only the record's action is applied, with the record's time, principal
    and id; the result then carries the next revision, the record's id and
    time, and no ignored keys. InvalidState when the action cannot be made
    from `parent`, or the record's key, old value or new value is not what
    apply_change records for it.
    """
    action, rid, at = record.get("action"), record.get("id"), record.get("at")
    principal, base = record.get("principal"), record.get("base_revision")
    if not isinstance(principal, dict):
        raise InvalidState("record_no_principal")
    if parent is not None and parent.revision != base:
        raise InvalidState("record_revision_mismatch")
    start = replace(EMPTY, revision=base)
    key = _FIELD_OF.get(action)
    check_old = True
    if action == ACTION_INIT:
        if parent is not None:
            raise InvalidState("init_not_start")
        state, old, new = start, None, {}
    elif action in (ACTION_RECOVER, ACTION_CHECKPOINT):
        new = record.get("new_value")
        state = _from_snapshot(new, base)
        by = record.get("retired_by")
        if state.retired_by != (by.get("id") if isinstance(by, dict) else None):
            raise InvalidState("start_migration_mismatch")
        if action == ACTION_CHECKPOINT and parent is not None and snapshot_of(parent) != new:
            raise InvalidState("checkpoint_state_mismatch")
        old, check_old = None, action == ACTION_CHECKPOINT
    elif action == ACTION_MIGRATE:
        prior = parent or start
        new = record.get("new_value")
        if prior.legacy_markers_retired or not (
                isinstance(new, dict) and set(new) == {FIELD_RESET, FIELD_EXCLUDED, FIELD_RETIRED}
                and new[FIELD_RETIRED] is True and isinstance(new[FIELD_EXCLUDED], list)
                and all(request_id_ok(r) for r in new[FIELD_EXCLUDED])):
            raise InvalidState("migration_malformed")
        reset = _timestamp(new[FIELD_RESET], "migration_malformed")
        excluded = frozenset(new[FIELD_EXCLUDED])
        if not prior.excluded_requests <= excluded or (
                prior.stats_reset is not None and (reset is None or reset < prior.stats_reset)):
            raise InvalidState("migration_drops_state")
        state = replace(prior, stats_reset=reset, excluded_requests=excluded,
                        legacy_markers_retired=True, retired_by=rid)
        old = {FIELD_RESET: prior.stats_reset, FIELD_EXCLUDED: len(prior.excluded_requests),
               FIELD_RETIRED: False}
        new = {FIELD_RESET: reset, FIELD_EXCLUDED: sorted(excluded), FIELD_RETIRED: True}
    else:
        if parent is None and action not in (ACTION_SET, ACTION_RESET, ACTION_EXCLUDE,
                                             ACTION_CLEAR_ALL, ACTION_DENY_DEVICE):
            raise InvalidState("start_action_invalid")
        value = (record.get("old_value") if action in (ACTION_UNEXCLUDE, ACTION_UNDENY_DEVICE)
                 else record.get("new_value"))
        if action in (ACTION_SET, ACTION_CLEAR):
            key = record.get("key")
        change = Change(action, key if action in (ACTION_SET, ACTION_CLEAR) else None, value)
        try:
            state, old, new = _next(parent or start, change, principal, at, rid,
                                    absent=parent is None)
        except (NoChange, Refused):
            raise InvalidState("change_not_applicable") from None
        claimed = record.get(FIELD_MIN_READER)
        stamps = (action == ACTION_SET and key == KEY_MODE) or action == ACTION_DENY_DEVICE
        if stamps and claimed is not None and release(claimed) is None:
            raise InvalidState("min_reader_version_malformed")
        state = _stamped(state, claimed if stamps else None)
    if record.get("key") != key or record.get("new_value") != new or (
            check_old and record.get("old_value") != old):
        raise InvalidState("record_values_mismatch")
    if record.get(FIELD_MIN_READER) != state.min_reader_version:
        raise InvalidState("record_min_reader_mismatch")
    return replace(state, revision=base + 1, audit_id=rid, audit_hash=None, updated_at=at,
                   ignored=())


def _check_produced(state: ControlState, record: Mapping[str, Any]) -> None:
    """InvalidState unless `state` is the object `record` says it produced."""
    if state_digest(state) != record.get("state_sha256"):
        raise InvalidState("record_state_mismatch")


def _replay(parent: ControlState | None, chain: Sequence[Mapping[str, Any]]) -> ControlState:
    """Apply `chain`, oldest first, to `parent`, checking each object it
    produces, and return the last. InvalidState at the first record that does
    not produce its own."""
    state = parent
    for record in chain:
        state = _transition(state, record)
        _check_produced(state, record)
    assert state is not None
    return state


def _retired(record: Mapping[str, Any]) -> bool:
    return record.get(FIELD_RETIRED) is True


def _check_link(parent_retired: bool, record: Mapping[str, Any]) -> None:
    """InvalidState when `record` un-retires, or retires other than by migrating."""
    if record.get("retired_by") is not None:
        raise InvalidState("link_names_migration")
    if parent_retired and not _retired(record):
        raise InvalidState("link_unretires")
    if _retired(record) and not parent_retired and record.get("action") != ACTION_MIGRATE:
        raise InvalidState("link_retires_without_migration")


def _migration(store: Any, audit_id: Any, expected_hash: Any = None,
               verify_keys: VerifyKeys = None) -> dict[str, Any]:
    """The `legacy.migrate` request record `audit_id`. InvalidState otherwise.

    With `expected_hash`, its stored bytes must hash to it. Whether it was
    applied is for the caller to establish from the chain; no outcome
    record is consulted.
    """
    if expected_hash is None:
        if not (isinstance(audit_id, str) and _AUDIT_ID.fullmatch(audit_id)):
            raise InvalidState("chain_audit_id_malformed")
        expected_hash = _stored_hash(store, audit_id)
    record = _request(store, audit_id, expected_hash, verify_keys)
    if record.get("action") != ACTION_MIGRATE or not _retired(record):
        raise InvalidState("start_names_non_migration")
    return record


def _check_start(store: Any, record: Mapping[str, Any],
                 verify_keys: VerifyKeys = None) -> None:
    """InvalidState when a record that starts a chain is retired without a migration.

    A start that is not itself a migration is retired only by naming, in
    `retired_by`, a `legacy.migrate` request record whose bytes match. No
    outcome record is read. A start that is not retired needs nothing.
    """
    by = record.get("retired_by")
    if record.get("action") == ACTION_MIGRATE or not _retired(record):
        if by is not None:
            raise InvalidState("record_names_unneeded_migration")
        return
    if not isinstance(by, dict):
        raise InvalidState("start_retired_unnamed")
    # `record` is verified, so the hash it names vouches for the migration's
    # bytes whichever key signed them; the signature is checked only when no
    # hash is named.
    vouched = by.get("sha256")
    _migration(store, by.get("id"), vouched, None if vouched is not None else verify_keys)


def verify_head(store: Any, state: ControlState,
                verify_keys: VerifyKeys = None) -> dict[str, Any]:
    """The request record that produced `state`, checked against it.

    InvalidState unless the object names a record by id and hash, the
    record's bytes match the hash, it is the write of this revision at this
    time, it carries this object's digest, and its action is the change the
    object shows.
    """
    if state.audit_id is None or state.audit_hash is None:
        raise InvalidState("object_names_no_record")
    record = _request(store, state.audit_id, state.audit_hash, verify_keys)
    base_revision = record.get("base_revision")
    if (not isinstance(base_revision, int) or isinstance(base_revision, bool)
            or base_revision + 1 != state.revision):
        raise InvalidState("head_revision_mismatch")
    if record.get("at") != state.updated_at:
        raise InvalidState("head_write_mismatch")
    if _retired(record) != state.legacy_markers_retired:
        raise InvalidState("head_retirement_mismatch")
    if record.get(FIELD_MIN_READER) != state.min_reader_version:
        raise InvalidState("head_min_reader_mismatch")
    if record.get("action") == ACTION_MIGRATE and state.retired_by != record.get("id"):
        raise InvalidState("migrated_object_unnamed")
    by = record.get("retired_by")
    if isinstance(by, dict) and state.retired_by != by.get("id"):
        raise InvalidState("head_migration_mismatch")
    if record.get("state_sha256") != state_digest(state):
        raise InvalidState("head_state_mismatch")
    if not _names_change(record, state):
        raise InvalidState("head_change_mismatch")
    return record




def anchor_of(state: ControlState) -> dict[str, Any]:
    """The head a verification record names for `state`."""
    return {"revision": state.revision, "audit_id": state.audit_id,
            "audit_hash": state.audit_hash}


def anchor_lapsed(store: Any, verify_keys: VerifyKeys = None) -> bool:
    """Whether a store that can prove a lockout has no fresh verification
    record signed by one of `verify_keys`, so no reader can adopt its
    object. A recover over a valid object is allowed then."""
    return provable(store) and not fresh_head(store, verify_keys, identities=False)[0]


def trusted_head(reader: RuntimeOverrides) -> dict[str, Any] | None:
    """The head of the state `reader` has verified and holds, or None."""
    state = reader.current().state
    return anchor_of(state) if state is not None else None


def unanchored_head(store: Any, verify_keys: VerifyKeys = None) -> dict[str, Any] | None:
    """The object's head when its chain verifies as a cold reader walks it,
    it is at a later revision than the head the newest fresh verification
    record names, and no request record latest_request_revision counts
    names a later revision: the head
    of a change whose verification record was not written. None otherwise,
    and when any read fails."""
    try:
        found = store.read_control()
        if found.status != "ok" or found.body is None:
            return None
        state = parse_state(found.body)
        _walk(store, verify_head(store, state, verify_keys), None, verify_keys)
        fresh, anchor = fresh_head(store, verify_keys, identities=False)
        if not fresh or anchor is None or state.revision <= anchor["revision"]:
            return None
        if latest_request_revision(store, verify_keys) > state.revision:
            return None
    except Exception:  # noqa: BLE001 - an unread or invalid object names no head
        return None
    return anchor_of(state)


def check_anchor(state: ControlState, anchor: Mapping[str, Any] | None, *, cold: bool) -> None:
    """InvalidState unless `state` may be adopted under `anchor`, the head
    the newest fresh verification record names.

    A `cold` reader needs `state` to be exactly that head: the same
    revision, audit id and hash. It refuses an older object or another at
    that revision (ERROR_BEFORE_ANCHOR), a newer one (ERROR_NOT_ANCHORED),
    and any object when there is no anchor (ERROR_ANCHOR_MISSING). A warm
    reader needs `state` at or after the anchor, the same head or a later
    revision, and adopts under no anchor."""
    if anchor is None:
        if cold:
            raise InvalidState("head_anchor_missing")
        return
    if (state.revision == anchor["revision"] and state.audit_id == anchor["audit_id"]
            and state.audit_hash == anchor["audit_hash"]):
        return
    if state.revision > anchor["revision"]:
        if cold:
            raise InvalidState("object_not_anchored")
        return
    raise InvalidState("object_before_anchor")


def check_requests(store: Any, state: ControlState, verify_keys: VerifyKeys = None) -> None:
    """InvalidState (ERROR_BEHIND_REQUEST) when a request record
    latest_request_revision counts names a later revision than `state`."""
    if latest_request_revision(store, verify_keys) > state.revision:
        raise InvalidState("object_behind_request")


def cold_refusal(store: Any, state: ControlState,
                 verify_keys: VerifyKeys = None) -> str | None:
    """The anchor error a cold reader would refuse `state` with under the
    newest fresh verification record signed by one of `verify_keys`
    (check_anchor, then check_requests), or None when it would adopt it.
    Always None on a store whose lockout is not provable, where readers
    check no anchor."""
    if not provable(store):
        return None
    fresh, anchor = fresh_head(store, verify_keys)
    try:
        check_anchor(state, anchor if fresh else None, cold=True)
        check_requests(store, state, verify_keys)
    except InvalidState as exc:
        return exc.code
    return None


def verify_transition(store: Any, candidate: ControlState,
                      trusted: ControlState | None, verify_keys: VerifyKeys = None) -> int:
    """Whether a reader holding `trusted` may adopt `candidate`, and how many
    links back from its head the walk ended.

    Verifies the candidate's head, then walks back from it (`_walk`).
    InvalidState for any failure.
    """
    if (trusted is not None and candidate.audit_id == trusted.audit_id
            and candidate.audit_hash == trusted.audit_hash
            and state_digest(candidate) == state_digest(trusted)):
        return 0
    if (trusted is not None and trusted.legacy_markers_retired
            and not candidate.legacy_markers_retired):
        raise InvalidState("object_unretires")
    record = verify_head(store, candidate, verify_keys)
    if trusted is not None and candidate.revision <= trusted.revision:
        raise InvalidState("revision_not_after_trusted")
    return _walk(store, record, trusted, verify_keys)[1]


def _walk(store: Any, record: dict[str, Any], trusted: ControlState | None,
          verify_keys: VerifyKeys = None,
          vouched: dict[str, str] | None = None) -> tuple[ControlState, int]:
    """The object `record` produced, replayed, and how many links back from
    `record` the walk ended.

    Walks back from `record`, checking each link's hash and that each step
    goes back exactly one revision. With `trusted`, the walk ends at
    `trusted`'s head, or at a chain start (a `state.init`, `state.recover`
    or `state.checkpoint`, or a write to an absent object) made at or after
    its revision. Without it, the walk ends at the newest chain start. The
    record it ends at, `trusted`'s head included, must be at most
    CHECKPOINT_EVERY links back from `record`.
    Along the walk the legacy markers never go from retired to not, only a
    `legacy.migrate` retires them, and a start that is retired names the
    migration that did. The walk then replays every record from where it
    ended (`_transition`), each of which must produce exactly the object it
    recorded. InvalidState for any failure.

    `vouched` is filled with {audit id: SHA-256} for each record the walk
    loaded by a hash its successor names, and for the migration a start
    names.
    """
    floor = trusted.revision if trusted is not None else 0
    vouched = {} if vouched is None else vouched

    def start_checked(start: Mapping[str, Any]) -> None:
        _check_start(store, start, verify_keys)
        by = start.get("retired_by")
        if isinstance(by, dict) and isinstance(by.get("sha256"), str):
            vouched[by["id"]] = by["sha256"]

    chain = [record]
    while True:
        revision = record["base_revision"]
        action = record.get("action")
        base_id, base_hash = record.get("base_audit_id"), record.get("base_hash")
        if (trusted is not None and revision == trusted.revision
                and base_id == trusted.audit_id and base_hash == trusted.audit_hash):
            if len(chain) > CHECKPOINT_EVERY and action not in STARTS:
                raise InvalidState("chain_beyond_checkpoint")
            if action in STARTS:
                start_checked(record)
                parent = trusted if action == ACTION_CHECKPOINT else None
            else:
                _check_link(trusted.legacy_markers_retired, record)
                parent = trusted
            return _replay(parent, chain[::-1]), len(chain) - 1
        if base_id is None and base_hash is not None:
            raise InvalidState("base_hash_without_record")
        if (action in STARTS or base_id is None) and revision >= floor:
            start_checked(record)
            return _replay(None, chain[::-1]), len(chain) - 1
        if revision <= floor:
            raise InvalidState("chain_no_verified_start")
        if len(chain) > CHECKPOINT_EVERY:
            raise InvalidState("chain_beyond_checkpoint")
        parent_record = _request(store, base_id, base_hash, verify_keys)
        vouched[base_id] = base_hash
        if _base_revision(parent_record) != revision - 1:
            raise InvalidState("chain_skips_revision")
        _check_link(_retired(parent_record), record)
        record = parent_record
        chain.append(record)


# -- reading ---------------------------------------------------------------


@dataclass(frozen=True)
class Snapshot:
    """What a reader applies, and what its last read found.

    `state` is None when the baseline is in force. `source` says where the
    values come from; `status` says what the last read found.
    """

    state: ControlState | None
    source: str
    status: str
    error: str | None = None
    held_since: str | None = None
    # False while a process with no last-known-good cannot confirm what is
    # in force: the object is unreadable or invalid, or absent while the
    # audit prefix is not confirmed empty.
    ready: bool = True
    # A writer role's last lockout probe result (lockout.RESULTS); None for
    # a role that does not probe.
    lockout: str | None = None
    # The writer roles whose reports did not show a fresh denial, and why.
    writers: Mapping[str, str] | None = None

    @property
    def in_error(self) -> bool:
        """Whether the last read took the ERROR path: the object was
        unreadable or invalid, absent after a valid read, or absent with
        audit records or an audit listing that failed."""
        return self.status in (STATUS_UNREADABLE, STATUS_INVALID) or (
            self.status == STATUS_ABSENT and (self.source == SOURCE_LKG or not self.ready)
        ) or self.error in (LOCKOUT_MISSING, ERROR_READER_TOO_OLD, ERROR_VERIFY_KEY,
                            ERROR_NO_STORE)

    def fields(self) -> dict[str, Any]:
        # `in_error` is the gauge: 1 while the reader is failing, else 0.
        out: dict[str, Any] = {"status": self.status, "source": self.source,
                               "in_error": int(self.in_error), "ready": self.ready}
        if self.state is not None:
            out["revision"] = self.state.revision
            out["keys"] = sorted(self.state.overrides)
        if self.error:
            out["error"] = self.error
        if self.held_since:
            out["held_since"] = self.held_since
        if self.lockout is not None:
            out["lockout"] = self.lockout
        if self.writers:
            out["writers"] = dict(self.writers)
        return out


BASELINE_ONLY = Snapshot(None, SOURCE_BASELINE, STATUS_DISABLED)


def readiness(reader: RuntimeOverrides | None) -> tuple[int, dict[str, Any]]:
    """The HTTP status and the body fields a readiness route answers with.

    503 while `reader` is not ready. The body names the read's status and
    nothing from the object or the error.
    """
    snapshot = reader.current() if reader is not None else BASELINE_ONLY
    if snapshot.ready:
        return 200, {"status": "ok"}
    return 503, {"status": "not_ready", "reason": _not_ready_reason(snapshot),
                 "runtime_overrides": snapshot.status}


def _not_ready_reason(snapshot: Snapshot) -> str:
    if snapshot.error == ERROR_UNINITIALIZED:
        return "runtime overrides are not initialized"
    if snapshot.error == LOCKOUT_MISSING:
        return f"runtime overrides {LOCKOUT_MISSING}"
    if snapshot.error == ERROR_VERIFY_KEY:
        return "runtime overrides have no valid verify key"
    if snapshot.error == ERROR_NO_STORE:
        return "runtime overrides have no store to read"
    if snapshot.error == ERROR_READER_TOO_OLD:
        return "runtime overrides need a newer forgd-verdict release"
    if snapshot.error == ERROR_BEHIND_REQUEST:
        return "runtime overrides are behind a signed change request"
    if snapshot.error in ANCHOR_ERRORS:
        return "runtime overrides are not the head the signed head anchor names"
    return "runtime overrides could not be confirmed"


def cold(reader: RuntimeOverrides | None) -> str | None:
    """The fixed readiness reason while `reader` honours overrides and holds
    no verified state, else None. A reader holding a last-known-good is
    never cold, ready or not."""
    if reader is None or not (reader.enabled or reader.no_store):
        return None
    snapshot = reader.current()
    if snapshot.state is not None:
        return None
    return _not_ready_reason(snapshot)


def enabled_in(raw: Mapping[str, Any]) -> bool:
    """Whether a policy turns runtime overrides on: `dashboard.admins` lists
    groups. The same test `AdminConfig.parse` uses to decide it is off."""
    admins = (raw.get("dashboard") or {}).get("admins")
    return isinstance(admins, Mapping) and bool(admins.get("groups"))


ENV_ENABLED = "FORGD_OVERRIDES_ENABLED"
CONTROL_IDENTITY_OFF = (
    "dashboard.admins lists groups but this deployment has not enabled the control "
    "identity (chart value dashboard.admins.enabled, module variable "
    f"dashboard_admins_enabled), so {ENV_ENABLED} is not true and runtime overrides "
    "and admin actions are off")


def deployment_enabled() -> bool:
    """Whether the deployment has enabled the control identity."""
    # Not an ENV_OVERRIDES key: it changes no policy value.
    return os.environ.get(ENV_ENABLED) == "true"


def honoured_in(raw: Mapping[str, Any], role: str,
                log: logging.Logger | None = None) -> bool:
    """Whether a service honours runtime overrides: the policy turns them on
    and the deployment has enabled the control identity. Logs one WARNING
    when the policy turns them on and the deployment has not."""
    if not enabled_in(raw):
        return False
    if deployment_enabled():
        return True
    (log or _log).warning(CONTROL_IDENTITY_OFF, extra={"fields": {"role": role}})
    return False


def reader_for(raw: Mapping[str, Any], store: Any, role: str, **kwargs: Any) -> RuntimeOverrides:
    """A `RuntimeOverrides` for `role`, with no store unless `honoured_in`,
    so it never reads the object and reports `disabled`. A writer role's
    reader probes its lockout (`lockout.LockoutProbe`) before every read,
    and every reader checks the writers' reports (`lockout.LockoutReports`,
    for the roles in FORGD_OVERRIDES_WRITER_ROLES) before it adopts one.
    ValueError when that variable names a role that is not a writer.

    RuntimeError when `role` is not the dashboard and is given a signing
    key (overrides_signing.refuse_signing_key).

    Honoured with `store` None, the reader reads nothing and is not ready
    (ERROR_NO_STORE), logging an ERROR on every refresh.

    When honoured, the reader verifies every request record against
    `overrides.verify_keys`. With none configured, or one that does not
    parse, it logs an ERROR and never reads the store (ERROR_VERIFY_KEY)."""
    refuse_signing_key(raw, role)
    honoured = honoured_in(raw, role)
    if honoured and store is not None:
        kwargs["verify_keys"], kwargs["key_error"] = verify_keys_for(raw, role,
                                                                      kwargs.get("log"))
        if role in WRITER_ROLES and "lockout" not in kwargs:
            kwargs["lockout"] = LockoutProbe(store, role, log=kwargs.get("log"))
        if "fleet" not in kwargs:
            kwargs["fleet"] = LockoutReports(store, expected_roles(),
                                             verify_keys=kwargs["verify_keys"])
    if honoured and store is None:
        kwargs["no_store"] = True
    return RuntimeOverrides(store if honoured else None, role, **kwargs)


def verify_keys_for(raw: Mapping[str, Any], role: str,
                     log: logging.Logger | None) -> tuple[tuple[Any, ...], str | None]:
    """(keys, None), or ((), ERROR_VERIFY_KEY) after logging why."""
    try:
        keys = verify_keys_from_policy(raw)
        reason = None if keys else f"{ENV_VERIFY_KEY} is not set"
    except KeyConfigError as exc:
        keys, reason = (), str(exc)
    if reason is None:
        return keys, None
    (log or _log).error("runtime overrides are off for this reader: no valid verify key",
                        extra={"fields": {"role": role, "error": ERROR_VERIFY_KEY,
                                          "reason": reason}})
    return (), ERROR_VERIFY_KEY


class RuntimeOverrides:
    """The overrides object, re-read every `ttl_s` seconds.

    A process that has read a valid object keeps it as its last-known-good
    and applies it while the object is absent, unreadable or invalid. A
    process that has not uses the baseline until its first valid read. Every
    valid read replaces what is applied, so a valid object that clears an
    override is applied as it is.

    `start()` refreshes on a background thread, so a request never waits on
    the store. Without it, `current()` refreshes lazily when the snapshot is
    older than `ttl_s`.

    With `lockout`, every refresh first checks this role's own probe, and
    with `fleet`, every writer role's report. Until each shows a fresh
    denial the status is `disabled` with the error LOCKOUT_MISSING, and
    nothing new is adopted:
    - the last-known-good stays in force; without one, the baseline is,
      and the reader is not ready, even on an empty store;
    - after a probe whose create succeeded, the reader is not ready
      either way.

    With `verify_keys`, every request record the walk loads, the head's
    ancestors included, must carry a signature that verifies under one of
    them; otherwise the object is invalid. With `key_error`, the reader
    reads nothing: it keeps its last-known-good, and without one it is not
    ready. `set_verify_keys` changes both.

    With `no_store`, runtime overrides are honoured but there is no store:
    nothing is read and the reader is not ready (ERROR_NO_STORE).
    """

    def __init__(self, store: Any, role: str, *, baseline: Mapping[str, Any] | None = None,
                 ttl_s: float = REFRESH_S, clock: Callable[[], float] | None = None,
                 log: logging.Logger | None = None, lockout: LockoutProbe | None = None,
                 fleet: LockoutReports | None = None, reader_version: str | None = None,
                 verify_keys: VerifyKeys = None, key_error: str | None = None,
                 no_store: bool = False):
        self.store = store
        self.no_store = no_store
        self.verify_keys = None if verify_keys is None else tuple(verify_keys)
        self.key_error = key_error
        self.role = role
        self.reader_version = reader_version or _current_version()
        self.lockout = lockout
        self.fleet = fleet
        self.baseline = dict(baseline or {})
        self.ttl_s = ttl_s
        self.clock = clock or time.monotonic
        self.log = log or _log
        self._lock = threading.Lock()
        self._snapshot = BASELINE_ONLY
        self._lkg: ControlState | None = None
        self._loaded_at: float | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._warned_archive = False

    @property
    def enabled(self) -> bool:
        return self.store is not None and callable(getattr(self.store, "read_control", None))

    def set_verify_keys(self, keys: VerifyKeys, error: str | None = None) -> None:
        with self._lock:
            self.verify_keys = None if keys is None else tuple(keys)
            self.key_error = error

    # -- refresh --------------------------------------------------------

    def refresh(self) -> Snapshot:
        with self._lock:
            self._loaded_at = self.clock()
            self._snapshot = self._read()
            return self._snapshot

    def current(self) -> Snapshot:
        if self._thread is None or not self._thread.is_alive():
            with self._lock:
                stale = self._loaded_at is None or self.clock() - self._loaded_at >= self.ttl_s
            if stale:
                return self.refresh()
        return self._snapshot

    def start(self) -> None:
        if not self.enabled or (self._thread is not None and self._thread.is_alive()):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name=f"overrides-{self.role}",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(self.ttl_s):
            try:
                self.refresh()
            except Exception as exc:  # noqa: BLE001 - the loop must outlive any one read
                self.log.error("runtime overrides refresh failed",
                               extra={"fields": exc_fields(exc)})

    def _read(self) -> Snapshot:
        if self.no_store:
            self.log.error(
                "runtime overrides are on but this service has no store to read them "
                "from; it is not ready until one is configured",
                extra={"fields": {"role": self.role, "error": ERROR_NO_STORE}})
            return Snapshot(None, SOURCE_BASELINE, STATUS_DISABLED, ERROR_NO_STORE, ready=False)
        if not self.enabled:
            return BASELINE_ONLY
        if self.key_error is not None:
            self.log.error("runtime overrides: no valid verify key, so the store is not read",
                           extra={"fields": {"role": self.role, "error": self.key_error}})
            if self._lkg is not None:
                return Snapshot(self._lkg, SOURCE_LKG, STATUS_DISABLED, self.key_error,
                                self._lkg.updated_at)
            return Snapshot(None, SOURCE_BASELINE, STATUS_DISABLED, self.key_error,
                            ready=False)
        probed = None
        if self.lockout is not None:
            try:
                probed = self.lockout.check()
            except Exception as exc:  # noqa: BLE001 - a probe that raised proves nothing
                self.log.error("the writer lockout probe raised",
                               extra={"fields": {"role": self.role,
                                                 "error": type(exc).__name__}})
                probed = None
            result = probed.result if probed is not None else RESULT_UNPROVEN
            if probed is None or not probed.proven:
                return self._held(result, None, ready=result != RESULT_ALLOWED)
        fleet: LockoutStatus | None = None
        if self.fleet is not None:
            try:
                fleet = self.fleet.refresh()
                problems = dict(fleet.problems)
            except Exception as exc:  # noqa: BLE001 - an unread report is not a denial
                problems = {"*": type(exc).__name__}
            if problems:
                self.log.error(
                    "runtime overrides: not every writer role has a fresh report that its "
                    "lockout holds, so no new object is adopted", extra={"fields": {
                        "role": self.role, "writers": problems}})
                return self._held(probed.result if probed is not None else None, problems)
        snapshot = self._read_object(fleet)
        if probed is not None:
            snapshot = replace(snapshot, lockout=probed.result)
        return snapshot

    def _held(self, lockout: str | None, writers: Mapping[str, str] | None, *,
              ready: bool = True) -> Snapshot:
        """The last-known-good, or the baseline and not ready without one,
        while a lockout is not proven. `ready=False` marks the replica not
        ready with the last-known-good still in force."""
        if self._lkg is not None:
            return Snapshot(self._lkg, SOURCE_LKG, STATUS_DISABLED, LOCKOUT_MISSING,
                            self._lkg.updated_at, ready=ready, lockout=lockout,
                            writers=writers)
        return Snapshot(None, SOURCE_BASELINE, STATUS_DISABLED, LOCKOUT_MISSING,
                        ready=False, lockout=lockout, writers=writers)

    def _read_object(self, fleet: LockoutStatus | None = None) -> Snapshot:
        """Read, verify and adopt the object. With `fleet` read from a
        verification record, the object must also pass check_anchor against
        the head it names, as a cold reader while no state is held, and
        check_requests while no state is held."""
        previous = self._snapshot
        try:
            found: ControlRead = self.store.read_control()
        except Exception as exc:  # noqa: BLE001 - StoreReadError or any backend error
            return self._failed(STATUS_UNREADABLE, type(exc).__name__)
        if found.status != "ok" or found.body is None:
            if self._lkg is None:
                return self._first_run(previous)
            return self._failed(STATUS_ABSENT, None)
        try:
            state = parse_state(found.body)
            verify_transition(self.store, state, self._lkg, self.verify_keys)
            if fleet is not None and fleet.anchor_read:
                check_anchor(state, fleet.anchor, cold=self._lkg is None)
                if self._lkg is None:
                    check_requests(self.store, state, self.verify_keys)
        except InvalidState as exc:
            if exc.code == ERROR_BEHIND_REQUEST:
                self.log.error(
                    "runtime overrides object is not adopted: a signed change request "
                    "names a later revision than the object's head and has no signed "
                    "error outcome, so a reader with no trusted state refuses it. "
                    "Restoring an older version of the object is refused; see Recovery "
                    "in docs/OVERRIDES.md", extra={"fields": {
                        "role": self.role, "error": exc.code, "revision": state.revision}})
            elif exc.code in ANCHOR_ERRORS:
                self.log.error(
                    "runtime overrides object is not adopted: a reader with no trusted "
                    "state needs the head the newest signed lockout verification record "
                    "names, and any reader refuses one before it. Restoring an older "
                    "version of the object is refused; see Recovery in "
                    "docs/OVERRIDES.md", extra={"fields": {
                        "role": self.role, "error": exc.code, "revision": state.revision,
                        "anchor_revision": (fleet.anchor or {}).get("revision")
                        if fleet is not None else None}})
            return self._failed(STATUS_INVALID, exc.code)
        except Exception as exc:  # noqa: BLE001 - an audit record read failed
            return self._failed(STATUS_UNREADABLE, type(exc).__name__)
        if not reader_supports(state.min_reader_version, self.reader_version):
            return self._too_old()
        forbidden = sum(1 for key in state.ignored if _forbidden_root(key))
        if forbidden:
            self.log.error(
                "runtime overrides object names a detection or privacy setting; "
                "it is never applied", extra={"fields": {"keys": forbidden, "role": self.role}})
        if len(state.ignored) > forbidden:
            self.log.error(
                "runtime overrides object names a key that is not on the allowlist; "
                "it is ignored", extra={"fields": {"keys": len(state.ignored) - forbidden,
                                                   "role": self.role}})
        if previous.state is None or previous.state.effective() != state.effective():
            self._announce(state, adopted=previous.source == SOURCE_BASELINE)
        self._lkg = state
        return Snapshot(state, SOURCE_OBJECT, STATUS_OK)

    def _too_old(self) -> Snapshot:
        """The object needs a newer release than this reader: nothing new is
        adopted, and the reader is not ready."""
        self.log.error(
            "runtime overrides object needs a newer forgd-verdict release than this one; "
            "it is not adopted, and this service is not ready until it is upgraded",
            extra={"fields": {"role": self.role, "reader_version": self.reader_version,
                              "error": ERROR_READER_TOO_OLD}})
        if self._lkg is not None:
            return Snapshot(self._lkg, SOURCE_LKG, STATUS_DISABLED, ERROR_READER_TOO_OLD,
                            self._lkg.updated_at, ready=False)
        return Snapshot(None, SOURCE_BASELINE, STATUS_DISABLED, ERROR_READER_TOO_OLD,
                        ready=False)

    def _first_run(self, previous: Snapshot) -> Snapshot:
        """The object is absent and nothing was read before. Not ready either
        way: with audit records an object was written and has gone, and
        without them the store was never initialized (`overrides init`)."""
        try:
            recorded = any(override_records(self.store, newest_first=True))
        except Exception as exc:  # noqa: BLE001 - StoreReadError or any backend error
            return self._unconfirmed(type(exc).__name__)
        return self._unconfirmed(ERROR_ORPHANED if recorded else ERROR_UNINITIALIZED)

    def _unconfirmed(self, error: str) -> Snapshot:
        message = ("runtime overrides are not initialized; not ready until "
                   "`forgd-verdict overrides init` runs as the control identity"
                   if error == ERROR_UNINITIALIZED else
                   "runtime overrides object is absent; not ready until the object "
                   "can be read")
        self.log.error(message, extra={"fields": {
            "status": STATUS_ABSENT, "role": self.role, "error": error}})
        return Snapshot(None, SOURCE_BASELINE, STATUS_ABSENT, error, ready=False)

    def _failed(self, status: str, error: str | None) -> Snapshot:
        fields = {"status": status, "role": self.role}
        if error:
            fields["error"] = error
        if self._lkg is not None:
            fields["held_since"] = self._lkg.updated_at
            self.log.error(
                "runtime overrides could not be read; keeping the values last read",
                extra={"fields": fields})
            return Snapshot(self._lkg, SOURCE_LKG, status, error, self._lkg.updated_at)
        self.log.error(
            "runtime overrides could not be read; running on policy.yaml and "
            "environment settings only, and not ready until they can be read",
            extra={"fields": fields})
        return Snapshot(None, SOURCE_BASELINE, status, error, ready=False)

    def _announce(self, state: ControlState, *, adopted: bool) -> None:
        self.log.info(
            "runtime overrides adopted" if adopted else "runtime overrides changed",
            extra={"fields": {"role": self.role, "revision": state.revision,
                              "keys": sorted(state.overrides),
                              "excluded_requests": len(state.excluded_requests),
                              "stats_reset": state.stats_reset}})
        for key, entry in state.overrides.items():
            base = self.baseline.get(key)
            if key in self.baseline and base != entry.value:
                self.log.warning(
                    "a runtime override masks the policy's value",
                    extra={"fields": {"key": key, "baseline": base, "override": entry.value,
                                      "remediation": "clear it with forgd-verdict overrides "
                                                     "clear, or from the dashboard"}})
        if durability_warning(self.baseline.get(KEY_MODE), state):
            self.log.warning(DURABILITY_TEXT)

    # -- values ---------------------------------------------------------

    def ready(self) -> bool:
        """Whether what is in force is known: a valid object, a confirmed
        first run, a last-known-good, or runtime overrides off."""
        return self.current().ready

    def mode(self, baseline: str) -> str:
        state = self.current().state
        value = state.value(KEY_MODE) if state is not None else None
        if value is None:
            return baseline
        if baseline == "archive":
            if not self._warned_archive:
                self._warned_archive = True
                self.log.warning(
                    "a server.mode override is ignored: the policy's mode is archive, "
                    "which is decided at startup", extra={"fields": {"override": value}})
            return baseline
        return value

    def excluded(self) -> frozenset[str]:
        state = self.current().state
        return state.excluded_requests if state is not None else frozenset()

    def denied_devices(self) -> frozenset[str]:
        state = self.current().state
        return state.denied_devices if state is not None else frozenset()

    def stats_reset(self) -> str | None:
        state = self.current().state
        return state.stats_reset if state is not None else None

    def legacy_retired(self) -> bool:
        state = self.current().state
        return state is not None and state.legacy_markers_retired

    def legacy_applies(self) -> bool:
        """Whether the legacy marker objects count: only while an adopted
        object has not retired them. A reader holding no adopted object
        applies none, since the writer identity can write them."""
        state = self.current().state
        return state is not None and not state.legacy_markers_retired


DURABILITY_TEXT = (
    "server.mode is enforce only because of a runtime override. Replicas run in "
    "observe if dashboard.admins stops listing groups. If the store loses the "
    "overrides object, replicas that start afterwards are not ready and refuse "
    "requests until it is restored or initialized again. To make enforce "
    "durable, set server.mode: enforce in policy.yaml.")


def durability_warning(baseline_mode: Any, state: ControlState | None) -> bool:
    """Whether enforce comes from an override over an observe baseline."""
    return (state is not None and state.value(KEY_MODE) == "enforce"
            and baseline_mode == "observe")


def effective_excluded(legacy: set[str] | frozenset[str],
                       reader: RuntimeOverrides | None) -> set[str]:
    """The legacy marker object's ids and the object's field, together; the
    field alone once the legacy markers are retired, and nothing from
    either while the reader holds no adopted object."""
    if reader is None:
        return set(legacy)
    if not reader.legacy_applies():
        return set(reader.excluded())
    return set(legacy) | reader.excluded()


def effective_reset(legacy: str | None, reader: RuntimeOverrides | None) -> str | None:
    """The later of the legacy marker object and the object's field; the
    field alone once the legacy markers are retired, and None while the
    reader holds no adopted object."""
    if reader is not None and not reader.legacy_applies():
        return reader.stats_reset()
    candidates = [c for c in (legacy, reader.stats_reset() if reader else None) if c]
    return max(candidates) if candidates else None


class OverlaidStore:
    """A store whose markers combine the legacy objects with the object's fields.

    `describe()["reset_at"]` is the later of the two resets and
    `get_excluded()` the union of the two sets, so every reader of either
    sees both; once the object retires the legacy markers, or while the
    reader holds no adopted object, each is the object's field alone.
    `legacy_reset_at` and `get_legacy_excluded()` give the legacy objects
    alone. Everything else passes through.
    """

    def __init__(self, store: Any, reader: RuntimeOverrides):
        self._store = store
        self.overrides = reader

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    def describe(self) -> dict[str, Any]:
        desc = dict(self._store.describe())
        legacy = desc.get("reset_at")
        desc["legacy_reset_at"] = legacy
        desc["reset_at"] = effective_reset(legacy, self.overrides)
        return desc

    def get_legacy_excluded(self) -> set[str]:
        getter = getattr(self._store, "get_excluded", None)
        return set(getter()) if callable(getter) else set()

    def get_excluded(self) -> set[str]:
        return effective_excluded(self.get_legacy_excluded(), self.overrides)


# -- changing --------------------------------------------------------------


def cli_actor() -> dict[str, Any]:
    """The CLI's principal. Unverified: it runs on whatever credentials it is given."""
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no login name in a container
        user = "unknown"
    return {"issuer": "cli", "subject": f"{user}@{socket.gethostname()}",
            "name": user, "verified": False}


def new_audit_id(now: datetime | None = None) -> str:
    moment = now or datetime.now(UTC)
    return f"{moment:%Y%m%dT%H%M%SZ}-{secrets.token_hex(6)}"


def audit_name(audit_id: str, kind: str) -> str:
    return f"{audit_id[:4]}-{audit_id[4:6]}-{audit_id[6:8]}/{audit_id}-{kind}.json"


@dataclass(frozen=True)
class Change:
    action: str
    key: str | None = None
    value: Any = None


@dataclass(frozen=True)
class Applied:
    state: ControlState
    audit_id: str
    record: dict[str, Any]


def _base(store: Any, action: str, verify_keys: VerifyKeys = None,
          vouched: dict[str, str] | None = None,
          ) -> tuple[ControlState, str | None, str, dict | None, int]:
    """(state, etag, status, raw, links) as read before a change. `links` is
    how far the object's head is from its chain start. `vouched` is filled
    as `_walk` fills it.

    An object whose chain does not verify as a cold reader walks it is
    invalid, as one that does not parse is, and so is one before the head a
    fresh verification record names (check_anchor).
    """
    found = store.read_control()
    if found.status != "ok" or found.body is None:
        return EMPTY, None, STATUS_ABSENT, None, 0
    try:
        state = parse_state(found.body)
        record = verify_head(store, state, verify_keys)
        links = _walk(store, record, None, verify_keys, vouched)[1]
        fresh, anchor = fresh_head(store, verify_keys, identities=False)
        if fresh:
            check_anchor(state, anchor, cold=False)
        return state, found.etag, STATUS_OK, None, links
    except InvalidState:
        if action != ACTION_RECOVER:
            raise
        try:
            raw = json.loads(found.body)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raw = None
        return EMPTY, found.etag, STATUS_INVALID, raw if isinstance(raw, dict) else None, 0


def _next(state: ControlState, change: Change, actor: Mapping[str, Any], now: str,
          audit_id: str, absent: bool = False) -> tuple[ControlState, Any, Any]:
    """The state after `change`, and the old and new values for the record."""
    overrides = dict(state.overrides)
    if change.action == ACTION_SET:
        if change.key not in ALLOWLIST:
            raise Refused("that key is not on the runtime overrides allowlist")
        try:
            value = ALLOWLIST[change.key][1](change.value)
        except ValueError as exc:
            raise Refused(str(exc)) from None
        old = state.value(change.key)
        if old == value:
            raise NoChange(f"{change.key} is already {value}")
        overrides[change.key] = OverrideEntry(value, now, dict(actor), audit_id)
        return replace(state, overrides=overrides), old, value
    if change.action == ACTION_CLEAR:
        if change.key not in ALLOWLIST:
            raise Refused("the key is not on the runtime overrides allowlist")
        if change.key not in overrides:
            raise NoChange(f"{change.key} is not overridden")
        old = overrides.pop(change.key).value
        return replace(state, overrides=overrides), old, None
    if change.action == ACTION_CLEAR_ALL:
        if not overrides and not absent:
            raise NoChange("no overrides are set")
        old = {k: v.value for k, v in sorted(overrides.items())}
        return replace(state, overrides={}), old, {}
    if change.action == ACTION_RESET:
        try:
            when = _timestamp(change.value or now, "stats_reset_malformed")
        except InvalidState as exc:
            raise Refused("a reset time must look like 2026-09-28T14:03:11Z") from exc
        return replace(state, stats_reset=when), state.stats_reset, when
    if change.action == ACTION_RESET_CLEAR:
        if state.stats_reset is None:
            raise NoChange("no statistics reset is set")
        return replace(state, stats_reset=None), state.stats_reset, None
    if change.action == ACTION_EXCLUDE:
        if not request_id_ok(change.value):
            raise Refused("not a request id")
        if change.value in state.excluded_requests:
            raise NoChange(f"{change.value} is already excluded")
        return (replace(state, excluded_requests=state.excluded_requests | {change.value}),
                None, change.value)
    if change.action == ACTION_UNEXCLUDE:
        if not request_id_ok(change.value):
            raise Refused("not a request id")
        if change.value not in state.excluded_requests:
            raise NoChange(f"{change.value} is not excluded")
        return (replace(state, excluded_requests=state.excluded_requests - {change.value}),
                change.value, None)
    if change.action == ACTION_EXCLUDE_CLEAR:
        if not state.excluded_requests:
            raise NoChange("no requests are excluded")
        return replace(state, excluded_requests=frozenset()), len(state.excluded_requests), 0
    if change.action == ACTION_DENY_DEVICE:
        if not device_id_ok(change.value):
            raise Refused("not a device id")
        if change.value in state.denied_devices:
            raise NoChange(f"{change.value} is already denied")
        if len(state.denied_devices) >= MAX_DENIED_DEVICES:
            raise Refused(f"at most {MAX_DENIED_DEVICES} devices can be denied; revoke "
                          "the fleet token instead")
        return (replace(state, denied_devices=state.denied_devices | {change.value}),
                None, change.value)
    if change.action == ACTION_UNDENY_DEVICE:
        if not device_id_ok(change.value):
            raise Refused("not a device id")
        if change.value not in state.denied_devices:
            raise NoChange(f"{change.value} is not denied")
        return (replace(state, denied_devices=state.denied_devices - {change.value}),
                change.value, None)
    if change.action == ACTION_DENY_CLEAR:
        if not state.denied_devices:
            raise NoChange("no devices are denied")
        return replace(state, denied_devices=frozenset()), len(state.denied_devices), 0
    raise Refused("unknown action")


def org_ids_of(policy: Any) -> frozenset[str]:
    """Every org id the policy names, `$VAR` references resolved, lowercased."""
    from .orgregistry import referenced_orgs

    return frozenset(o.lower() for o in referenced_orgs(policy))


def apply_change(store: Any, actor: Mapping[str, Any], change: Change, *,
                 detectors: Sequence[Any],
                 org_ids: Collection[str] = (),
                 salt: str = "",
                 expect_revision: int | None = None,
                 migrate: tuple[str | None, frozenset[str]] | None = None,
                 recover_mode: str | None = None,
                 now: datetime | None = None,
                 writer_version: str | None = None,
                 signing_key: Ed25519PrivateKey | None = None,
                 verify_keys: VerifyKeys = None,
                 after_write: Callable[[ControlState], Any] | None = None) -> Applied:
    """Record the request, then write the object conditionally.

    Every value the caller supplies is scanned with `detectors` before
    anything is read, and so are the legacy values a migration folds in and
    the markers a recover keeps. Every string in the finished request
    record, principal included, is scanned again before it is written. An
    exclusion equal to one of `org_ids` (`org_ids_of`) is refused, and a
    migration leaves such a legacy exclusion behind. Every org id in the
    principal is replaced (OrgScreen, with `salt`) before anything is
    built from it, and a request record that would still hold one is
    refused.

    `state.init` is the only change that writes an absent object when the
    audit prefix is empty, and it writes nothing else. With the object
    absent and audit records present, only `state.recover` writes.

    `state.recover` also writes over a valid object while the head anchor
    has lapsed (anchor_lapsed), or while latest_request_revision is later
    than its revision. Every other change is refused with
    REFUSED_BEHIND_REQUEST then.

    Raises NoChange for a change that would leave the object as it is,
    Refused for one that is not allowed or that a detector matched, or
    that the store's initialization state does not permit,
    InvalidState for a present object
    that does not parse or whose head does not verify (only `state.recover`
    accepts one), StoreReadError
    when the object cannot be read, and StoreConflict when the object
    changed between the read and the write or `expect_revision` is stale,
    and StoreForbidden when the credentials may not write the record or the
    object.

    Setting `server.mode`, directly or through a recover's mode, or denying
    a device raises the object's min_reader_version to `writer_version`
    (this build's release by default). Every other write keeps it, and it
    goes when neither `server.mode` nor a denied device is left.

    With `signing_key`, every request record written, a checkpoint's
    included, is signed before its stored bytes are hashed. With
    `verify_keys`, every record read to verify the object, to recover, or
    to name a migration must be signed by one of them, as a reader requires.

    When the head was signed by a key other than `signing_key`, a checkpoint
    signed by `signing_key` is written first. Once it is the newest chain
    start, readers need only the new key: the walk ends there, and the
    migration it names is vouched for by the hash it records.

    `after_write` is called with each state written, a checkpoint's
    included, once its write succeeded. An exception it raises is logged
    at ERROR and the change stands.
    """
    if change.action not in ACTIONS:
        raise Refused("unknown action")
    screen([change.key, change.value, recover_mode], detectors)
    orgs = {o.lower() for o in org_ids}
    org_screen = OrgScreen(orgs, salt)
    actor = org_screen(dict(actor))
    if (change.action == ACTION_EXCLUDE and isinstance(change.value, str)
            and change.value.lower() in orgs):
        raise Refused("that value is a configured organization id, not a request id")
    if (change.action == ACTION_DENY_DEVICE and isinstance(change.value, str)
            and change.value.lower() in orgs):
        raise Refused("that value is a configured organization id, not a device id")
    moment = now or datetime.now(UTC)
    stamp = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    vouched: dict[str, str] = {}
    state, etag, status, raw, links = _base(store, change.action, verify_keys, vouched)
    if expect_revision is not None and expect_revision != state.revision:
        raise StoreConflict("the object changed since the form was rendered")
    if (status == STATUS_OK and change.action != ACTION_RECOVER
            and latest_request_revision(store, verify_keys) > state.revision):
        raise Refused(REFUSED_BEHIND_REQUEST)
    if (status == STATUS_OK and change.action not in (ACTION_INIT, ACTION_RECOVER)
            and (links >= CHECKPOINT_EVERY
                 or (verify_keys is not None and _rotated(store, state, signing_key)))):
        state, etag = _checkpoint(store, actor, state, etag, detectors, moment, org_screen,
                                  signing_key, verify_keys, vouched, after_write)
    if status == STATUS_ABSENT:
        recorded = any(override_records(store, newest_first=True))
        if recorded and change.action != ACTION_RECOVER:
            raise Refused(REFUSED_ORPHANED)
        if change.action != ACTION_INIT and not recorded:
            raise Refused(ERROR_UNINITIALIZED)
        state = replace(state, revision=highest_revision(store))
    audit_id = new_audit_id(moment)
    retired_by = None

    if change.action == ACTION_MIGRATE:
        if state.legacy_markers_retired:
            raise NoChange("the legacy markers are already retired")
        legacy_reset, legacy_ids = migrate or (None, frozenset())
        # A legacy value that is malformed or that a detector matches is
        # left behind; a detector that does not run refuses.
        try:
            legacy_reset = _timestamp(legacy_reset, "stats_reset_malformed")
        except InvalidState:
            legacy_reset = None
        kept = frozenset(r for r in legacy_ids if request_id_ok(r) and r.lower() not in orgs
                         and _clean(r, detectors))
        if len(kept) != len(legacy_ids):
            _log.warning("migrate-markers left legacy exclusions behind",
                         extra={"fields": {"dropped": len(legacy_ids) - len(kept)}})
        reset = max([c for c in (state.stats_reset, legacy_reset) if c], default=None)
        excluded = state.excluded_requests | kept
        new_state = replace(state, stats_reset=reset, excluded_requests=excluded,
                            legacy_markers_retired=True, retired_by=audit_id)
        old = {FIELD_RESET: state.stats_reset, FIELD_EXCLUDED: len(state.excluded_requests),
               FIELD_RETIRED: False}
        new = {FIELD_RESET: reset, FIELD_EXCLUDED: sorted(excluded), FIELD_RETIRED: True}
    elif change.action == ACTION_INIT:
        if status == STATUS_OK:
            raise NoChange("the store is already initialized")
        new_state, old, new = state, None, {}
    elif change.action == ACTION_RECOVER:
        if status == STATUS_OK:
            if not (anchor_lapsed(store, verify_keys)
                    or latest_request_revision(store, verify_keys) > state.revision):
                raise Refused("the object is valid; there is nothing to recover")
            raw = json.loads(state.to_bytes())
        new_state, old, new, retired_by = _recovered(store, status, raw, recover_mode, actor,
                                                     stamp, audit_id, verify_keys)
    else:
        new_state, old, new = _next(state, change, actor, stamp, audit_id)

    stamps = ((change.action == ACTION_SET and change.key == KEY_MODE)
              or (change.action == ACTION_RECOVER and recover_mode is not None)
              or change.action == ACTION_DENY_DEVICE)
    if stamps:
        writer_version = writer_version or _current_version()
        if release(writer_version) is None:
            raise Refused("this build's version is not a release version, so it cannot "
                          "set server.mode or deny a device")
    new_state = _stamped(new_state, writer_version if stamps else None)

    key = (change.key if change.action in (ACTION_SET, ACTION_CLEAR)
           else _FIELD_OF.get(change.action))
    if status == STATUS_OK:
        base_audit, base_hash = state.audit_id, state.audit_hash
    else:
        base_audit = (raw.get("audit_id") if isinstance(raw, dict)
                      and isinstance(raw.get("audit_id"), str) else None)
        base_hash = _stored_hash(store, base_audit)
    return _write(store, actor, change.action, key, old, new, new_state, base_audit, base_hash,
                  retired_by, etag, detectors, stamp, audit_id, org_screen, signing_key,
                  after_write)


def _write(store: Any, actor: Mapping[str, Any], action: str, key: Any, old: Any, new: Any,
           new_state: ControlState, base_audit: str | None, base_hash: str | None,
           retired_by: dict[str, str] | None, etag: str | None, detectors: Sequence[Any],
           stamp: str, audit_id: str, org_screen: OrgScreen,
           signing_key: Ed25519PrivateKey | None = None,
           after_write: Callable[[ControlState], Any] | None = None) -> Applied:
    """Write the request record for `new_state`, then the object over `etag`,
    then call `after_write` with the state written. Refused when the record
    holds an org id or a detector matches it. With `signing_key`, the
    record is signed after it is screened."""
    base_revision = new_state.revision
    new_state = replace(new_state, revision=base_revision + 1, audit_id=audit_id,
                        audit_hash=None, updated_at=stamp, ignored=())
    if action in (ACTION_RECOVER, ACTION_CHECKPOINT):
        new = snapshot_of(new_state)
    record = {
        "version": VERSION,
        "kind": "request",
        "id": audit_id,
        "at": stamp,
        "principal": dict(actor),
        "action": action,
        "key": key,
        "old_value": old,
        "new_value": new,
        "base_revision": base_revision,
        "base_audit_id": base_audit,
        "base_hash": base_hash,
        "state_sha256": state_digest(new_state),
        FIELD_RETIRED: new_state.legacy_markers_retired,
        "retired_by": retired_by,
        FIELD_MIN_READER: new_state.min_reader_version,
    }
    if org_screen.holds(record):
        raise Refused("the audit record would hold an organization id")
    screen([record], detectors)
    if signing_key is not None:
        record = sign_record(record, signing_key)
    blob = _record_bytes(record)
    new_state = replace(new_state, audit_hash=_sha256(blob))
    store.put_audit(audit_name(audit_id, "request"), blob)
    try:
        store.write_control(new_state.to_bytes(), etag)
    except StoreConflict:
        _outcome(store, audit_id, "conflict", signing_key)
        raise
    except StoreForbidden:
        _outcome(store, audit_id, "error", signing_key)
        raise
    except Exception:
        # A timeout or a 5xx may follow a write that committed.
        _outcome(store, audit_id, "unknown", signing_key)
        raise
    _outcome(store, audit_id, "applied", signing_key)
    if after_write is not None:
        try:
            after_write(new_state)
        except Exception as exc:  # noqa: BLE001 - the write has committed
            _log.error("runtime overrides change applied, but the step after the write "
                       "failed", extra={"fields": {"revision": new_state.revision,
                                                   "error": type(exc).__name__}})
    return Applied(new_state, audit_id, record)


def _rotated(store: Any, state: ControlState, signing_key: Ed25519PrivateKey | None) -> bool:
    """Whether the verified head was signed by a key other than `signing_key`."""
    if signing_key is None or state.audit_id is None:
        return False
    blob = store.get_audit(audit_name(state.audit_id, "request"))
    try:
        signature = json.loads(blob or b"{}").get(SIGNATURE_FIELD)
    except (ValueError, UnicodeDecodeError, AttributeError, RecursionError):
        return True
    kid = signature.get("kid") if isinstance(signature, dict) else None
    return kid != key_id(signing_key.public_key())


def _vouched_migration(store: Any, audit_id: Any, vouched: Mapping[str, str] | None,
                       verify_keys: VerifyKeys) -> str | None:
    """The SHA-256 of migration `audit_id`: the one a verified record names
    for it, else its stored hash after checking its signature. InvalidState
    when `_migration` does not accept it."""
    known = (vouched or {}).get(audit_id) if isinstance(audit_id, str) else None
    if known is not None:
        _migration(store, audit_id, known)
        return known
    _migration(store, audit_id, verify_keys=verify_keys)
    return _stored_hash(store, audit_id)


def _start_ref(store: Any, state: ControlState, verify_keys: VerifyKeys = None,
               vouched: Mapping[str, str] | None = None) -> dict[str, str] | None:
    """What a chain start carrying `state` records in `retired_by`: its
    migration's id and SHA-256, or None when `state` is not retired."""
    if not state.legacy_markers_retired:
        return None
    try:
        digest = _vouched_migration(store, state.retired_by, vouched, verify_keys)
    except InvalidState as exc:
        raise Refused("the migration that retired the legacy markers cannot be verified, "
                      "so no chain start can carry the retirement") from exc
    return {"id": state.retired_by, "sha256": digest}


def _checkpoint(store: Any, actor: Mapping[str, Any], state: ControlState, etag: str | None,
                detectors: Sequence[Any], moment: datetime, org_screen: OrgScreen,
                signing_key: Ed25519PrivateKey | None = None,
                verify_keys: VerifyKeys = None,
                vouched: Mapping[str, str] | None = None,
                after_write: Callable[[ControlState], Any] | None = None,
                ) -> tuple[ControlState, str | None]:
    """Write a checkpoint of the verified `state`, and return it and the
    object's new etag. StoreConflict when the object changed meanwhile."""
    stamp = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    applied = _write(store, actor, ACTION_CHECKPOINT, None, None, None, state, state.audit_id,
                     state.audit_hash, _start_ref(store, state, verify_keys, vouched), etag,
                     detectors, stamp, new_audit_id(moment), org_screen, signing_key,
                     after_write)
    found = store.read_control()
    if found.status != "ok" or found.body != applied.state.to_bytes():
        raise StoreConflict("the object changed while its checkpoint was written")
    return applied.state, found.etag


def _retired_ref(store: Any, raw: dict | None, verify_keys: VerifyKeys = None,
                 vouched: Mapping[str, str] | None = None) -> dict[str, str] | None:
    """The migration the invalid object names, as its id and SHA-256, if
    `_migration` accepts it. None otherwise."""
    audit_id = (raw or {}).get(FIELD_RETIRED_BY)
    try:
        digest = _vouched_migration(store, audit_id, vouched, verify_keys)
    except InvalidState:
        return None
    return {"id": audit_id, "sha256": digest}


def _recovered(store: Any, status: str, raw: dict | None, mode: str | None,
               actor: Mapping[str, Any], stamp: str, audit_id: str,
               verify_keys: VerifyKeys = None,
               ) -> tuple[ControlState, Any, Any, dict[str, str] | None]:
    """(state, old value, new value, retired_by) for a recover.

    The state is the one the newest verifiable chain produced, with `mode`
    set over it when given. With no verifiable chain it holds only `mode`,
    and a warning says what was dropped.

    It is retired when the kept state is, when the invalid object names
    a migration `_migration` accepts, or when the migration request
    `_chained_migration` finds verifies and has a signed `applied` outcome.
    That migration is not on the kept chain, which would be retired if it
    were, so nothing but its outcome says it committed. Refused
    (REFUSED_RETIREMENT_UNVERIFIED) when the kept state is retired and its
    migration is not accepted, when `_chained_migration` finds a migration
    with no signed `applied` outcome, and when the state is not retired
    while `_retired_request` finds a retired request.

    Its revision is above every revision a request record or the head the
    newest signed verification record names (lockout.anchored_head).
    """
    vouched: dict[str, str] = {}
    anchor = anchored_head(store, verify_keys)
    kept = _recoverable(store, raw, verify_keys, vouched, anchor)
    if kept is None:
        state = ControlState()
        _log.warning("recover found no verifiable audit chain: the recovered object drops "
                     "every exclusion, the statistics reset and any override but the mode "
                     "given", extra={"fields": {"status": status}})
    else:
        state = replace(kept, audit_id=None, audit_hash=None, updated_at=None, ignored=())
    if state.legacy_markers_retired:
        retired_by = _retired_ref(store, {FIELD_RETIRED_BY: state.retired_by}, verify_keys,
                                  vouched)
        if retired_by is None:
            raise Refused(REFUSED_RETIREMENT_UNVERIFIED)
    else:
        retired_by = (_retired_ref(store, raw, verify_keys)
                      if _applied_by_chain(store, raw) else None)
        named = retired_by is not None
        if not named:
            retired_by = _chained_migration(store, verify_keys)
            if retired_by is not None and not _outcome_says(
                    store, retired_by["id"], verify_keys, ("applied",)):
                _log.warning("recover found a migration off the kept chain with no signed "
                             "`applied` outcome", extra={"fields": {
                                 "migration": retired_by["id"]}})
                raise Refused(REFUSED_RETIREMENT_UNVERIFIED)
        if retired_by is not None:
            state = replace(state, legacy_markers_retired=True, retired_by=retired_by["id"])
            if kept is not None:
                _log.warning("recover kept the retirement the invalid object names over a "
                             "kept state that is not retired" if named else
                             "recover kept the retirement of a migration on a verified chain "
                             "over a kept state that is not retired", extra={"fields": {
                                 "retired_by": retired_by["id"]}})
        elif _retired_request(store, verify_keys):
            raise Refused(REFUSED_RETIREMENT_UNVERIFIED)
    overrides = dict(state.overrides)
    if mode is not None:
        try:
            overrides[KEY_MODE] = OverrideEntry(_mode_value(mode), stamp, dict(actor), audit_id)
        except ValueError as exc:
            raise Refused(str(exc)) from None
    revision = (raw or {}).get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        revision = 0
    revision = max(revision, highest_revision(store),
                   anchor["revision"] if anchor is not None else 0)
    state = replace(state, revision=revision, overrides=overrides)
    return state, {"status": status, "kept": kept is not None}, None, retired_by


# How many head candidates a recover tries before it gives up on the chain.
_RECOVER_CANDIDATES = 10


def _recoverable(store: Any, raw: dict | None, verify_keys: VerifyKeys = None,
                 vouched: dict[str, str] | None = None,
                 anchor: Mapping[str, Any] | None = None) -> ControlState | None:
    """The object the newest verifiable chain produced, or None.

    The first candidate for its head is the request record
    latest_request_revision counts at its revision, when that is later
    than both the object's revision and `anchor`'s and it is the only such
    record without a signed `conflict` outcome. When there are several, the
    one `_settled_head` picks is, whatever the invalid object names. Next is
    the record the
    invalid object names, or the one `anchor` names when the object is not
    at or after it (check_anchor), then request records newest revision
    first. A record that shares its base with another is skipped unless it
    is the first candidate, the object or `anchor` names it, or a record
    names it as its base: one of them lost a conditional write, and only
    the chain, the object, the anchor or a signed `conflict` outcome says
    which.
    """
    candidates: list[str] = []
    named = (raw or {}).get("audit_id")
    revision = (raw or {}).get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool):
        revision = None
    top, latest = _latest_requests(store, verify_keys)
    unsettled = [r["id"] for r in latest
                 if isinstance(r.get("id"), str) and _AUDIT_ID.fullmatch(r["id"])
                 and not _abandoned(store, r, verify_keys, ("conflict",))]
    # The invalid object's revision and audit id do not settle a race at the
    # newest revision: nothing signed them.
    if top > (anchor["revision"] if anchor is not None else 0) and (
            len(unsettled) > 1 or top > (revision or 0)):
        if len(unsettled) > 1:
            unsettled = _settled_head(store, top, unsettled, verify_keys)
        if len(unsettled) == 1:
            candidates.append(unsettled[0])
    if anchor is not None and anchor["audit_id"] is not None and not (
            revision is not None
            and (revision > anchor["revision"]
                 or (revision == anchor["revision"] and named == anchor["audit_id"]
                     and (raw or {}).get("audit_hash") == anchor["audit_hash"]))):
        named = anchor["audit_id"]
    if isinstance(named, str) and _AUDIT_ID.fullmatch(named) and named not in candidates:
        candidates.append(named)
    records = []
    for name in _requests(store):
        audit_id = name.rsplit("/", 1)[-1][: -len("-request.json")]
        try:
            record = json.loads(store.get_audit(name) or b"{}")
        except (ValueError, UnicodeDecodeError, RecursionError):
            continue
        if isinstance(record, dict) and _AUDIT_ID.fullmatch(audit_id):
            base = (record.get("base_audit_id"), record.get("base_hash"))
            records.append((_base_revision(record), audit_id, base))
    siblings: dict[Any, int] = {}
    for _, _, base in records:
        siblings[base] = siblings.get(base, 0) + 1
    built_on = {base[0] for _, _, base in records}
    for _, audit_id, base in sorted(records, key=lambda r: (r[0], r[1]), reverse=True):
        if audit_id in candidates:
            continue
        if siblings[base] > 1 and audit_id not in built_on:
            continue
        candidates.append(audit_id)
    for audit_id in candidates[:_RECOVER_CANDIDATES]:
        expected = _stored_hash(store, audit_id)
        try:
            found: dict[str, str] = {}
            state, _ = _walk(store, _request(store, audit_id, expected, verify_keys), None,
                             verify_keys, found)
        except InvalidState:
            continue
        if audit_id != candidates[0]:
            _log.warning("recover kept the state of an older audit record: the newer ones do "
                         "not verify", extra={"fields": {"kept": audit_id}})
        if vouched is not None:
            vouched.update(found)
            vouched[audit_id] = expected
        return replace(state, audit_hash=expected)
    return None


def _settled_head(store: Any, revision: int, unsettled: list[str],
                  verify_keys: VerifyKeys = None) -> list[str]:
    """Of request records `unsettled`, all at `revision`, the one whose write
    committed: of those with a signed `applied` outcome, or of all of them
    when none has one, the only one whose chain verifies. Refused
    (REFUSED_HEAD_AMBIGUOUS) when more than one does. The walks stop at the
    second chain that verifies."""
    applied = [a for a in unsettled if _outcome_says(store, a, verify_keys, ("applied",))]
    verified: list[str] = []
    for audit_id in sorted(applied or unsettled):
        if _chain_verifies(store, audit_id, verify_keys):
            verified.append(audit_id)
            if len(verified) > 1:
                _log.warning("recover found more than one verifiable request record at the "
                             "newest revision", extra={"fields": {
                                 "revision": revision, "records": sorted(unsettled)}})
                raise Refused(REFUSED_HEAD_AMBIGUOUS)
    return verified


def _chain_verifies(store: Any, audit_id: str, verify_keys: VerifyKeys = None) -> bool:
    """Whether request record `audit_id`'s chain verifies back to a chain
    start (`_walk`)."""
    try:
        _walk(store, _request(store, audit_id, _stored_hash(store, audit_id), verify_keys),
              None, verify_keys)
    except InvalidState:
        return False
    return True


def _chained_migration(store: Any, verify_keys: VerifyKeys = None) -> dict[str, str] | None:
    """The newest `legacy.migrate` request record signed by one of
    `verify_keys`, with no signed `error` or `conflict` outcome, whose
    chain verifies back to a chain start (`_walk`), as its id and SHA-256.
    None when there is none."""
    migrations = []
    for name in _requests(store):
        try:
            record = json.loads(store.get_audit(name) or b"{}")
        except (ValueError, UnicodeDecodeError, RecursionError):
            continue
        if (isinstance(record, dict) and record.get("action") == ACTION_MIGRATE
                and isinstance(record.get("id"), str) and _AUDIT_ID.fullmatch(record["id"])):
            migrations.append((_base_revision(record), record["id"]))
    for _, audit_id in sorted(migrations, reverse=True):
        expected = _stored_hash(store, audit_id)
        try:
            record = _migration(store, audit_id, expected, verify_keys)
            if _abandoned(store, record, verify_keys, ("error", "conflict")):
                continue
            _walk(store, record, None, verify_keys)
        except InvalidState:
            continue
        return {"id": audit_id, "sha256": expected}  # type: ignore[dict-item]
    return None


def _retired_request(store: Any, verify_keys: VerifyKeys = None) -> bool:
    """Whether a request record signed by one of `verify_keys`, with no
    signed `error` or `conflict` outcome, says `legacy_markers_retired`."""
    for name in _requests(store):
        try:
            record = json.loads(store.get_audit(name) or b"{}")
        except (ValueError, UnicodeDecodeError, RecursionError):
            continue
        if (isinstance(record, dict) and _retired(record) and _signed_by(record, verify_keys)
                and not _abandoned(store, record, verify_keys, ("error", "conflict"))):
            return True
    return False


def _applied_by_chain(store: Any, raw: dict | None) -> bool:
    """Whether the invalid object names the migration it says retired the
    markers as its own record."""
    audit_id = (raw or {}).get(FIELD_RETIRED_BY)
    return (isinstance(audit_id, str) and bool(_AUDIT_ID.fullmatch(audit_id))
            and (raw or {}).get("audit_id") == audit_id)


def _requests(store: Any, *, newest_first: bool = False) -> Iterator[str]:
    """Names of the request records, day by day."""
    return (n for n in override_records(store, newest_first=newest_first)
            if n.endswith("-request.json"))


def _stored_hash(store: Any, audit_id: str | None) -> str | None:
    """The SHA-256 of request record `audit_id` as stored, or None."""
    if audit_id is None or not _AUDIT_ID.fullmatch(audit_id):
        return None
    blob = store.get_audit(audit_name(audit_id, "request"))
    return _sha256(blob) if blob is not None else None


def latest_request_revision(store: Any, verify_keys: VerifyKeys = None) -> int:
    """The highest revision a request record signed by one of `verify_keys`
    says it produced, leaving out a request whose outcome record is signed
    by one of them and says `error`. Store read errors propagate."""
    return _latest_requests(store, verify_keys)[0]


def _latest_requests(store: Any, verify_keys: VerifyKeys = None,
                     ) -> tuple[int, list[dict[str, Any]]]:
    """latest_request_revision, and the request records it counts that
    produced that revision."""
    best, latest = 0, []
    for name in _requests(store):
        try:
            record = json.loads(store.get_audit(name) or b"{}")
            revision = int(record.get("base_revision", -1)) + 1
        except (ValueError, TypeError, AttributeError, RecursionError):
            continue
        if (revision >= best and revision > 0 and _signed_by(record, verify_keys)
                and not _abandoned(store, record, verify_keys)):
            if revision > best:
                best, latest = revision, []
            latest.append(record)
    return best, latest


def _abandoned(store: Any, request: Mapping[str, Any], verify_keys: VerifyKeys,
               results: Collection[str] = ("error",)) -> bool:
    """Whether `request` has an outcome record signed by one of
    `verify_keys` that names it and says one of `results`."""
    return _outcome_says(store, request.get("id"), verify_keys, results)


def _outcome_says(store: Any, audit_id: Any, verify_keys: VerifyKeys,
                  results: Collection[str]) -> bool:
    """Whether request `audit_id` has an outcome record signed by one of
    `verify_keys` that names it and says one of `results`."""
    if not (isinstance(audit_id, str) and _AUDIT_ID.fullmatch(audit_id)):
        return False
    blob = store.get_audit(audit_name(audit_id, "outcome"))
    try:
        outcome = json.loads(blob) if blob is not None else None
    except (ValueError, RecursionError):
        return False
    return (isinstance(outcome, dict) and outcome.get("kind") == "outcome"
            and outcome.get("request_id") == audit_id and outcome.get("result") in results
            and _signed_by(outcome, verify_keys))


def highest_revision(store: Any) -> int:
    """The highest revision any request record says it produced."""
    best = 0
    for name in _requests(store):
        try:
            record = json.loads(store.get_audit(name) or b"{}")
            best = max(best, int(record.get("base_revision", -1)) + 1)
        except (ValueError, TypeError, RecursionError):
            continue
    return best


def _record_bytes(record: Mapping[str, Any]) -> bytes:
    return (json.dumps(record, sort_keys=True, default=str) + "\n").encode("utf-8")


def _outcome(store: Any, audit_id: str, result: str,
             signing_key: Ed25519PrivateKey | None = None) -> None:
    """The supplemental outcome record, signed with `signing_key`. Best
    effort. `conflict` and `error` are written only for a write that was
    refused before it committed, and `unknown` for any other failure. A
    signed `error` is read by latest_request_revision, and `conflict` and
    `error` by recover's candidate and retirement checks."""
    record = {"version": VERSION, "kind": "outcome", "request_id": audit_id,
              "result": result, "at": _now()}
    if signing_key is not None:
        record = sign_record(record, signing_key)
    try:
        store.put_audit(audit_name(audit_id, "outcome"), _record_bytes(record))
    except Exception:  # noqa: BLE001 - its absence means nothing
        _log.warning("could not write the outcome record for a runtime override change",
                     extra={"fields": {"request_id": audit_id, "result": result}})


# -- history ---------------------------------------------------------------


@dataclass(frozen=True)
class History:
    applied: list[dict[str, Any]]
    not_applied: list[dict[str, Any]]
    # Ids of records on the chain whose stored bytes do not hash to what the
    # next link names: overwritten or forged.
    tampered: frozenset[str] = frozenset()


def _signed_by(record: Mapping[str, Any], verify_keys: VerifyKeys) -> bool:
    if verify_keys is None:
        return True
    try:
        verify_record(record, verify_keys)
    except SignatureError:
        return False
    return True


def _base_revision(record: Mapping[str, Any]) -> int:
    value = record.get("base_revision")
    return value if isinstance(value, int) and not isinstance(value, bool) else -1


def history(store: Any, state: ControlState | None, limit: int = 20,
            verify_keys: VerifyKeys = None) -> History:
    """The applied changes, newest first, walked back along the chain from
    the object's `audit_id`, and the recent requests that are not on it.

    Each record on the chain is checked against the hash its successor, or
    the object, names for it, and with `verify_keys` its signature is
    checked; a record that fails either is in `tampered`.
    """
    applied: list[dict[str, Any]] = []
    on_chain: set[str] = set()
    tampered: set[str] = set()
    cursor = state.audit_id if state is not None else None
    expected = state.audit_hash if state is not None else None
    while cursor and len(applied) < limit and cursor not in on_chain:
        try:
            blob = store.get_audit(audit_name(cursor, "request"))
            record = json.loads(blob) if blob else None
        except (ValueError, TypeError, OSError, RecursionError):
            record = None
        if not isinstance(record, dict):
            break
        if (expected is None or _sha256(blob) != expected or record.get("id") != cursor
                or not clock_ok(cursor, record.get("at")) or not _signed_by(record, verify_keys)):
            tampered.add(cursor)
        applied.append(record)
        on_chain.add(cursor)
        base = record.get("base_audit_id")
        cursor = base if isinstance(base, str) and _AUDIT_ID.fullmatch(base) else None
        expected = record.get("base_hash")
    not_applied: list[dict[str, Any]] = []
    # A request is off the chain if it was made against a revision the chain
    # covers and is not a link. One made against an older revision predates
    # the chain: a recover starts a new one.
    floor = _base_revision(applied[-1]) if applied else -1
    for name in islice(_requests(store, newest_first=True), limit * 5):
        audit_id = name.rsplit("/", 1)[-1][: -len("-request.json")]
        if audit_id in on_chain:
            continue
        try:
            record = json.loads(store.get_audit(name) or b"{}")
        except (ValueError, TypeError, RecursionError):
            continue
        if (isinstance(record, dict) and record.get("kind") == "request"
                and _base_revision(record) >= floor):
            not_applied.append(record)
        if len(not_applied) >= limit:
            break
    return History(applied, not_applied, frozenset(tampered))


__all__ = [
    "ACTIONS", "ALLOWLIST", "Applied", "Change", "ControlState", "DASHBOARD_ACTIONS",
    "DEPLOYMENT_ACTIONS", "EMPTY", "History", "InvalidState", "KEY_MODE", "NoChange",
    "ORG_SCREEN_UNAVAILABLE", "OrgScreen", "Refused",
    "RuntimeOverrides", "SCOPED_ACTIONS", "Snapshot", "StoreConflict", "StoreForbidden",
    "StoreReadError",
    "apply_change",
    "audit_name", "cli_actor", "cold", "durability_warning", "effective_excluded",
    "effective_reset", "exclusion_label", "history", "org_screen_of", "parse_state",
    "state_digest", "verify_head", "verify_transition",
]
