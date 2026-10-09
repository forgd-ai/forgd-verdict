"""Verify flagged findings against the content that produced them.

The store keeps hashes, so nothing downstream can tell a real person's name
from a code fragment spaCy mistook for one. That is the right default and it
leaves a real gap: 200 distinct `presidio:person` values were reported and
nobody could say how many were people.

This closes the gap without weakening the invariant. It re-fetches from the
Compliance API, re-runs one detector, and prints matched values to the
terminal only. It writes no store, no spool, no CSV and no log sink, and it
masks by default so a shoulder-read or a pasted terminal does not become the
leak the rest of the design prevents.

Use it to judge precision, then throw the output away.
"""

from __future__ import annotations

import pathlib
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .compliance.client import ComplianceError
from .extract import chat_units, compliance_units
from .models import ScanUnit

# Keep the head and tail, mask the middle. Enough to judge whether
# `943 476 5919` is an NHS number and whether `Dana Whitfield` is a person,
# without reproducing the value in full.
KEEP_EDGE = 2


def mask(value: str) -> str:
    """Mask the middle of a matched value."""
    if len(value) <= KEEP_EDGE * 2:
        return "•" * len(value)
    body = re.sub(r"\w", "•", value[KEEP_EDGE:-KEEP_EDGE])
    return f"{value[:KEEP_EDGE]}{body}{value[-KEEP_EDGE:]}"


def load_env_file(path: str) -> list[str]:
    """Load `KEY=value` lines into os.environ. Returns the names set.

    Explicit rather than implicit: a security tool that silently picks up a
    credential file in the working directory is a tool that behaves
    differently depending on where you ran it. Values are not logged, and
    existing environment variables win so an export always beats a stale
    file.
    """
    import os

    names: list[str] = []
    for raw in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value
            names.append(key)
    return names


@dataclass
class Sample:
    detector: str
    values: Counter[str] = field(default_factory=Counter)
    units_scanned: int = 0
    sources_scanned: int = 0

    def rows(self, limit: int, reveal: bool) -> list[tuple[str, int]]:
        shown = self.values.most_common(limit)
        return [(v if reveal else mask(v), n) for v, n in shown]


def _match_values(units: list[ScanUnit], detectors: list[Any], detector: str,
                  budget_ms: int) -> Counter[str]:
    """Recover the values behind one detector's findings.

    Asks each detector for its own matches rather than reconstructing them
    from hashes. Guessing candidate substrings and re-hashing them returns
    nothing whenever a detector normalised the value before hashing --
    `ChecksumDetector` hashes its capture group, so an NHS number embedded
    in a larger token is never a candidate -- and that reads as "nothing to
    check".

    A detector without `matches` is skipped rather than guessed at.
    """
    prefix = detector.split(":", 1)[0]
    owner = next((d for d in detectors if d.name.startswith(prefix)
                  or prefix.startswith(d.name)), None)
    if owner is not None and not hasattr(owner, "matches"):
        # Loud, not silent. Returning nothing here would read as "clean".
        raise SystemExit(
            f"{owner.name} cannot report its matched values, so "
            f"{detector!r} cannot be spot checked. Supported: "
            "regex:*, checksum:*, entropy:*, presidio:*."
        )
    found: Counter[str] = Counter()
    for det in detectors:
        get = getattr(det, "matches", None)
        if get is None:
            continue
        for name, value in get(units):
            if name == detector or name.startswith(detector):
                found[value] += 1
    return found


def sample_named(scanner, detector: str, ids: list[str],
                 family: str = "local") -> Sample:
    """Spot check exactly the sessions the store says carried the finding.

    Blind sampling from the head of the list is the wrong tool: findings
    for one detector can sit in a few sessions out of hundreds, none of
    them among the first sampled. The store cannot give back a value, but
    it does record which session each hash came from, which is enough to
    go straight there.

    A `claude_chat_*` id is a claude.ai chat and uses the chats endpoint; a
    `clls_*` id is a session. Routing on the prefix rather than asking the
    caller, since the store hands back both kinds mixed together.
    """
    out = Sample(detector=detector)
    budget = scanner.policy.budget_ms
    for sid in ids:
        if not sid:
            continue
        try:
            if sid.startswith("claude_chat_"):
                units = chat_units(scanner.client.chat_messages(sid))
            else:
                units = compliance_units(
                    list(scanner.client.session_messages(
                        sid, family, limit=scanner.page_limit))
                )
        except Exception as exc:  # noqa: BLE001 - one bad id must not stop the rest
            print(f"  ! {sid[:24]}...: {type(exc).__name__}"
                  + (f" {exc.status}" if getattr(exc, "status", None) else ""))
            continue
        out.sources_scanned += 1
        out.units_scanned += len(units)
        # Deliberately UNGUARDED. `_match_values` raises with "Loud, not
        # silent. Returning nothing here would read as 'clean'", and
        # catching it would produce exactly that -- "scanned 2 sessions,
        # nothing to check" -- for a detector that structurally cannot
        # report its matches, which is gitleaks and llmguard_pii today.
        #
        # The raise is about a DETECTOR property, so it fires for every id
        # in the list rather than for one session. `sample_sessions` does
        # not catch it either.
        out.values.update(
            _match_values(units, scanner.detectors, detector, budget)
        )
    return out


def sample_sessions(scanner, detector: str, family: str = "local",
                    since: str | None = None, max_sources: int = 10) -> Sample:
    """Walk sessions, re-run one detector, collect matched values."""
    out = Sample(detector=detector)
    budget = scanner.policy.budget_ms
    for count, session in enumerate(
        scanner.client.list_sessions(family, limit=scanner.page_limit,
                                    **({"updated_at_gte": since} if since else {}))
    ):
        if count >= max_sources:
            break
        sid = session.get("id")
        if not sid:
            continue
        messages = list(scanner.client.session_messages(sid, family,
                                                        limit=scanner.page_limit))
        units = compliance_units(messages)
        out.sources_scanned += 1
        out.units_scanned += len(units)
        out.values.update(_match_values(units, scanner.detectors, detector, budget))
    return out


def sample_chats(scanner, detector: str, max_sources: int = 10) -> Sample:
    out = Sample(detector=detector)
    budget = scanner.policy.budget_ms
    for count, chat in enumerate(scanner.client.list_chats(limit=scanner.page_limit)):
        if count >= max_sources:
            break
        cid = chat.get("uuid") or chat.get("id")
        if not cid:
            continue
        try:
            full = scanner.client.chat_messages(cid)
        except ComplianceError as exc:
            # A chat deleted in claude.ai whose messages are no longer served.
            if exc.status == 404 and chat.get("deleted_at"):
                continue
            raise
        units = chat_units(full)
        out.sources_scanned += 1
        out.units_scanned += len(units)
        out.values.update(_match_values(units, scanner.detectors, detector, budget))
    return out
