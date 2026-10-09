"""Identity and metadata values on their way to a sink.

A request id, a session id, a model name or a service name is copied into
records, the CSV, logs, `/metrics` and `/stats`, and is never scanned as
content. `MetadataGuard` probes each such value before it reaches any of
them, with the T0 detectors, and with gitleaks when it runs as a daemon or
when the caller opts in to its subprocess (`guard_detectors`), and probes
what its base64 runs decode to as the scan decodes them. A value that
matches, that a detector fails on, that is longer than `max_chars`, or that
is not encodable as UTF-8 (a lone surrogate) is replaced with a placeholder
that holds a salted digest and never the value. `clean` does not raise: if
the guard itself fails, every value that is not None, a boolean or a number
is replaced.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import fields, replace
from typing import Any

from .core import _batch_hits, _candidates, _decoded, _run_candidates, _utf8_len
from .detectors.base import TIER_T0, TIER_T1
from .models import ScanUnit, digest
from .store.base import DenialRecord, FindingRow, VerdictRecord

log = logging.getLogger("forgd_verdict.metadata")

METADATA_MAX_CHARS = 128
# A finding's locator is structural and can be long; it is bounded by the
# locator scrub's own limit.
LOCATOR_MAX_CHARS = 1024

# The VerdictRecord fields that carry sender or upstream metadata.
RECORD_FIELDS = (
    "request_id", "session_id", "session_started_at", "session_updated_at",
    "deleted_at", "surface", "reported_as", "model", "device",
)
# Every other string a writer can set on a record it ships to the intake.
UNTRUSTED_RECORD_FIELDS = (
    *RECORD_FIELDS, "actor_hash", "salt_namespace", "action", "shadow_action",
    "reference_id", "build",
)
# The DenialRecord fields copied from an Activity Feed item.
DENIAL_FIELDS = ("activity_id", "created_at", "reference_id")
# The fields `MetadataGuard.records` cleans, for each record class a store
# writes.
GUARDED_FIELDS: dict[type, tuple[str, ...]] = {
    VerdictRecord: RECORD_FIELDS,
    DenialRecord: DENIAL_FIELDS,
}

# The most decoded base64 units probed for one value.
_DECODED_PROBES = 64


class _Undecodable(Exception):
    """A value holds more base64 runs than the guard decodes."""


def _probe_texts(value: str) -> list[str]:
    """`value`, its candidates, and the text each of its base64 runs decodes
    to, as the scan decodes them. Raises `_Undecodable` past
    _DECODED_PROBES runs."""
    decoded, over = _decoded([ScanUnit(locator="_", tool_name=None, text=value)],
                             _DECODED_PROBES)
    if over:
        raise _Undecodable
    return list(dict.fromkeys([value, *_candidates(value), *_run_candidates(value),
                               *(u.text for u in decoded)]))


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def is_uuid(value: str) -> bool:
    return bool(_UUID.match(value))


def opaque_id(value: str, salt: str, prefix: str) -> str:
    """`<prefix>_` and 16 hex characters of the salted digest of `value`."""
    return f"{prefix}_{digest(value, salt)[:16]}"


def guard_detectors(detectors: Sequence[Any], *, allow_subprocess: bool = False) -> list[Any]:
    """The detectors the guard probes with: every T0, and a T1 when it scans
    through a daemon, or as a subprocess when `allow_subprocess`."""
    return [d for d in detectors
            if getattr(d, "tier", 0) == TIER_T0
            or (getattr(d, "tier", 0) == TIER_T1
                and (allow_subprocess or getattr(d, "uses_daemon", False)))]


def _is_subprocess(det: Any) -> bool:
    return getattr(det, "tier", 0) == TIER_T1 and not getattr(det, "uses_daemon", False)


def _limit(det: Any) -> int | None:
    """The most UTF-8 bytes of candidate text, separators counted, one call
    hands `det`: an eighth under its `max_bytes`, or None for no limit."""
    cap = getattr(det, "max_bytes", None)
    return cap - cap // 8 if isinstance(cap, int) and not isinstance(cap, bool) else None


def _batches(texts: Sequence[str], limit: int | None) -> list[tuple[int, int]]:
    """`(start, end)` bounds splitting `texts` into runs of at most `limit`
    UTF-8 bytes, counting one separator byte per text; a text over `limit`
    is a run of its own. One run when `limit` is None."""
    if limit is None:
        return [(0, len(texts))] if texts else []
    bounds: list[tuple[int, int]] = []
    start = size = 0
    for k, t in enumerate(texts):
        n = _utf8_len(t) + 1
        if k > start and size + n > limit:
            bounds.append((start, k))
            start, size = k, 0
        size += n
    if texts:
        bounds.append((start, len(texts)))
    return bounds


def _encodable(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def refuse_unsafe_labels(labels: Sequence[Any], guard: MetadataGuard, what: str,
                         noun: str = "label") -> None:
    """Raise ValueError naming the position of the first policy-written
    label the metadata guard would replace, or could not check because a
    guard detector raised, never the label."""
    for i, label in enumerate(labels):
        reason, failed = policy_value_problem(guard, str(label or ""))
        if reason is None and failed:
            reason = f"could not be checked: {', '.join(failed)} failed"
        if reason is not None:
            raise ValueError(f"{what} entry {i}: the {noun} {reason}. It is written "
                             "to logs and run summaries; change it.")


def policy_value_problem(guard: MetadataGuard, text: str) -> tuple[str | None, list[str]]:
    """Why an operator-written policy value must not be used as metadata.

    `(reason, failed)`: `reason` is None when the value is safe, and never
    contains the value; `failed` names guard detectors that raised while
    checking it.
    """
    if len(text) > METADATA_MAX_CHARS:
        return f"is longer than {METADATA_MAX_CHARS} characters", []
    if not _encodable(text):
        return "is not valid UTF-8", []
    matched, failed = guard.probe(text)
    return (f"matches {', '.join(matched)}" if matched else None), failed


def _text(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    try:
        return json.dumps(value, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


class MetadataGuard:
    """Replaces any metadata value a cheap detector matches.

    `redacted` counts replaced values since construction, for `/metrics`
    and `/stats`.
    """

    def __init__(self, detectors: Sequence[Any], salt: str = "",
                 max_chars: int = METADATA_MAX_CHARS, *,
                 allow_subprocess: bool = False) -> None:
        self._cheap = guard_detectors(detectors, allow_subprocess=allow_subprocess)
        self._salt = salt
        self._max = max_chars
        self._lock = threading.Lock()
        self.redacted = 0

    def count(self, n: int) -> None:
        """Add `n` to `redacted`, for values a caller replaced itself."""
        if n:
            with self._lock:
                self.redacted += n

    def placeholder(self, value: str, reason: str = "redacted") -> str:
        """`<reason>_` and 12 hex characters of the salted digest. Letters,
        digits and `_` only, so a placeholder is still a valid request id
        part for the dashboard's exclusion marker."""
        return f"{reason}_{digest(value, self._salt)[:12]}"

    def clean(self, values: Mapping[str, Any], *, max_chars: Mapping[str, int] | None = None,
              where: str = "") -> dict[str, Any]:
        """`values` with each string or number that must not reach a sink
        replaced.

        None and booleans pass through. A number is probed as its `str()`
        and kept, with its type, unless it is replaced. Anything else is
        turned into text first. Each detector call covers as many values
        as fit an eighth under that detector's `max_bytes`, or all of them
        for a detector without one.
        """
        try:
            return self._clean(values, max_chars, where)
        except Exception as exc:  # noqa: BLE001 - must not raise on any input
            out = {k: v if v is None or isinstance(v, bool)
                   else self._failed(v) for k, v in values.items()}
            with self._lock:
                self.redacted += sum(1 for k in out if out[k] is not values[k])
            log.warning("metadata guard failed; every value replaced",
                        extra={"fields": {"where": where, "error": type(exc).__name__}})
            return out

    def _failed(self, value: Any) -> str:
        try:
            return self.placeholder(str(value), "failed")
        except Exception:  # noqa: BLE001
            return "failed"

    def _clean(self, values: Mapping[str, Any], max_chars: Mapping[str, int] | None,
               where: str) -> dict[str, Any]:
        values = {k: _text(v) for k, v in values.items()}
        out = dict(values)
        replaced: dict[str, str] = {}
        probe: dict[str, str] = {}
        for key, value in values.items():
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                value = str(value)
            if not isinstance(value, str) or not value:
                continue
            if len(value) > (max_chars or {}).get(key, self._max):
                out[key] = self.placeholder(value, "long")
                replaced[key] = "long"
            elif not _encodable(value):
                out[key] = self.placeholder(value, "invalid")
                replaced[key] = "invalid"
            else:
                probe[key] = value
        for key in self.matches(probe):
            out[key] = self.placeholder(probe[key])
            replaced[key] = "matched"
        if replaced:
            with self._lock:
                self.redacted += len(replaced)
            # Field names and reasons only, never a value.
            log.warning("metadata value replaced before it reached a sink",
                        extra={"fields": {"where": where, "fields": replaced}})
        return out

    def opaque(self, value: Any) -> str | None:
        """`id_` and 12 hex characters of the salted digest of `value`.

        Runs no detector, so it is cheap enough for a request that has not
        been authenticated, and never carries the value whatever it holds.
        """
        if value is None or value == "":
            return None
        return f"id_{digest(str(value), self._salt)[:12]}"

    def bounded(self, value: str) -> str:
        """`value`, or its `long_` placeholder when it is over the length
        bound. Runs no detector: for holding a value in memory until it can
        be cleaned off the event loop."""
        return self.placeholder(value, "long") if len(value) > self._max else value

    def clean_keys(self, counts: Mapping[str, int], *, where: str = "") -> dict[str, int]:
        """`counts` with each key cleaned, adding up keys that clean to the
        same placeholder."""
        keys = list(counts)
        out: dict[str, int] = {}
        for raw, key in zip(keys, self.many(keys, where=where), strict=True):
            out[key] = out.get(key, 0) + counts[raw]
        return dict(sorted(out.items()))

    def matches(self, values: Mapping[str, str]) -> set[str]:
        """The keys of `values` whose value a cheap detector matches, or
        fails on. Nothing is replaced, counted or logged. If the guard
        itself fails, every key with a non-empty string value."""
        try:
            return self._matches(values)
        except Exception:  # noqa: BLE001 - must not raise on any input
            return {k for k, v in values.items() if isinstance(v, str) and v}

    def _matches(self, values: Mapping[str, str]) -> set[str]:
        texts: list[str] = []
        owner: list[str] = []
        undecodable: set[str] = set()
        for key, value in values.items():
            if not isinstance(value, str) or not value:
                continue
            try:
                cands = _probe_texts(value)
            except _Undecodable:
                undecodable.add(key)
                continue
            for cand in cands:
                texts.append(cand)
                owner.append(key)
        if not texts or not self._cheap:
            return undecodable
        hits: set[int] = set()
        for det in self._cheap:
            for a, b in _batches(texts, _limit(det)):
                batch = texts[a:b]
                found = (self._subprocess_hits(det, batch) if _is_subprocess(det)
                         else _batch_hits(batch, [det]))
                hits |= {a + k for k in found}
        return {owner[k] for k in hits} | undecodable

    @staticmethod
    def _subprocess_hits(det: Any, texts: Sequence[str]) -> set[int]:
        """Indexes of `texts` a subprocess detector matches, from one
        `scan` over all of them. If it raises, every index."""
        units = [ScanUnit(locator=str(i), tool_name=None, text=t) for i, t in enumerate(texts)]
        try:
            return {int(f.locator) for f in det.scan(units) if f.locator.isdigit()}
        except Exception as exc:  # noqa: BLE001 - a failed probe replaces every value
            log.error("detector failed during the metadata guard; every value replaced",
                      extra={"fields": {"detector": det.name, "error": type(exc).__name__}})
            return set(range(len(texts)))

    def probe(self, value: str) -> tuple[list[str], list[str]]:
        """(finding ids the guard's detectors report on `value` or its
        candidates, names of the guard's detectors that raised)."""
        try:
            cands = _probe_texts(value)
        except _Undecodable:
            return [], ["base64"]
        units = [ScanUnit(locator=str(i), tool_name=None, text=t) for i, t in enumerate(cands)]
        matched: set[str] = set()
        failed: list[str] = []
        for det in self._cheap:
            try:
                matched |= {f.detector for f in det.scan(units)}
            except Exception:  # noqa: BLE001 - reported, never raised
                failed.append(det.name)
        return sorted(matched), failed

    def one(self, value: Any, *, where: str = "") -> Any:
        return self.clean({"value": value}, where=where)["value"]

    def many(self, values: Iterable[Any], *, where: str = "") -> list[Any]:
        items = list(values)
        cleaned = self.clean({str(i): v for i, v in enumerate(items)}, where=where)
        return [cleaned[str(i)] for i in range(len(items))]

    def record(self, record: VerdictRecord, *, untrusted: bool = False) -> VerdictRecord:
        """`record` with its metadata fields cleaned.

        `untrusted` is a record a writer shipped whole: every string it
        set is cleaned, including its findings and `tiers_dropped`.
        """
        names = UNTRUSTED_RECORD_FIELDS if untrusted else RECORD_FIELDS
        cleaned = self.clean({n: getattr(record, n) for n in names},
                             where=f"record:{record.source}")
        changes = {n: v for n, v in cleaned.items() if v != getattr(record, n)}
        if untrusted:
            dropped = self.many(record.tiers_dropped, where="record:tiers_dropped")
            if dropped != list(record.tiers_dropped):
                changes["tiers_dropped"] = dropped
            findings = [self._finding(f) for f in record.findings]
            if findings != list(record.findings):
                changes["findings"] = findings
        return replace(record, **changes) if changes else record

    def records(self, records: Sequence[Any], *, untrusted: bool = False) -> list[Any]:
        """Each of `records` with the fields `GUARDED_FIELDS` names for its
        class cleaned, in one `clean` over all of them. For a VerdictRecord
        that is what `record` cleans, findings and `tiers_dropped` included
        when `untrusted`. A class `GUARDED_FIELDS` does not name raises
        TypeError."""
        items = list(records)
        if not items:
            return []
        for r in items:
            if type(r) not in GUARDED_FIELDS:
                raise TypeError(f"no metadata guard for {type(r).__name__}")
        untrusted = untrusted and all(isinstance(r, VerdictRecord) for r in items)
        sources = ",".join(sorted({getattr(r, "source", type(r).__name__) for r in items}))
        values: dict[str, Any] = {}
        max_chars: dict[str, int] = {}
        for i, r in enumerate(items):
            for n in _names(r, untrusted):
                values[f"{i}:{n}"] = getattr(r, n)
            if not untrusted:
                continue
            for j, tier in enumerate(r.tiers_dropped):
                values[f"{i}:t{j}"] = tier
            for k, row in enumerate(r.findings):
                for n in _string_fields(row):
                    values[f"{i}:f{k}:{n}"] = getattr(row, n)
                    if n == "locator":
                        max_chars[f"{i}:f{k}:{n}"] = LOCATOR_MAX_CHARS
        cleaned = self.clean(values, max_chars=max_chars, where=f"record:{sources}")
        out = []
        for i, r in enumerate(items):
            changes: dict[str, Any] = {n: cleaned[f"{i}:{n}"] for n in _names(r, untrusted)
                                       if cleaned[f"{i}:{n}"] != getattr(r, n)}
            if untrusted:
                dropped = [cleaned[f"{i}:t{j}"] for j in range(len(r.tiers_dropped))]
                if dropped != list(r.tiers_dropped):
                    changes["tiers_dropped"] = dropped
                findings = [_rebuilt(row, cleaned, f"{i}:f{k}:")
                            for k, row in enumerate(r.findings)]
                if findings != list(r.findings):
                    changes["findings"] = findings
            out.append(replace(r, **changes) if changes else r)
        return out

    def _finding(self, row: FindingRow) -> FindingRow:
        names = _string_fields(row)
        cleaned = self.clean({n: getattr(row, n) for n in names},
                             max_chars={"locator": LOCATOR_MAX_CHARS},
                             where="record:finding")
        changes = {n: v for n, v in cleaned.items() if v != getattr(row, n)}
        return replace(row, **changes) if changes else row


def _names(record: Any, untrusted: bool) -> tuple[str, ...]:
    return UNTRUSTED_RECORD_FIELDS if untrusted else GUARDED_FIELDS[type(record)]


def _string_fields(row: FindingRow) -> list[str]:
    return [f.name for f in fields(row) if isinstance(getattr(row, f.name), str)]


def _rebuilt(row: FindingRow, cleaned: Mapping[str, Any], prefix: str) -> FindingRow:
    changes = {n: cleaned[prefix + n] for n in _string_fields(row)
               if cleaned[prefix + n] != getattr(row, n)}
    return replace(row, **changes) if changes else row
