# FROZEN: src/forgd_verdict/sink/redact.py as released in v0.45.0, the
# reference for test_sink_redact_differential.py. Only the relative imports
# are rewritten as absolute ones. Do not edit, format or lint it.
# ruff: noqa
"""Turn scanned OTel records into redacted events.

The core of adapter 5, and the only place redaction happens. A sink is
handed the result and cannot widen it.

Two rules here are load-bearing and easy to lose:

**Scan the RAW text, forward the redacted copy.** Detection quality must
not depend on what the customer chose to censor. The scan has already run
on the original by the time anything here is called, so censoring the
outbound stream costs nothing in what verdict catches or stores.

**A sink that cannot apply its redaction policy must not forward.** Adapter
3 degrading is correct -- the audit job under-reports and the findings page
shows fewer detections. Adapter 5 degrading is a LEAK: the data leaves
anyway, uncensored, and the counter that would have told you is in someone
else's system. So a detector named in `redact` that is not available stops
the sink at construction rather than quietly widening it.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace

from forgd_verdict.core import _DECODED_SUFFIX, _cheap, _scrub_names
from forgd_verdict.metadata import METADATA_MAX_CHARS, MetadataGuard
from forgd_verdict.models import TAIL_SUFFIX, UNSCANNED_CAPPED, Finding, ScanUnit
from forgd_verdict.otel.extract import record_units_by_key
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink.base import RedactedEvent, SinkConfig, SinkUnavailable

# What replaces a match. Names the detector and never the value -- the same
# privacy invariant the store holds, applied on the way out.
# WHAT THIS ADAPTER DOES NOT REDACT, stated because it is a property of
# the design and not an oversight:
#
#   * attributes the SCANNER skips -- identity keys (`user.email`,
#     `session.id`, ...), values under MIN_SCAN_CHARS, and anything not a
#     string. They were never scanned, so nothing was detected in them and
#     nothing is masked.
#   * `resource` attributes, copied through unchanged.
#
# The event NAME is not on that list; it is masked. A name is
# sender-controlled and lands verbatim in a finding's locator, so an
# unmasked secret used as one would be both forwarded raw AND copied into
# the evidence.
#
# The guarantee is "a value this deployment DETECTED is not forwarded",
# not "the forwarded stream contains no secrets". Those are different
# claims and only the first is kept. A deployment that cannot accept the
# second should use `drop_events` to cut the event types it does not want,
# or not forward the surface at all.
#
# Identity attributes are the important case and they are deliberate: they
# are pseudonymised on the way into the store precisely because scanning
# them would flag every event. Forwarding them raw to a customer's own
# SIEM is usually what the customer wants -- it is their directory -- but
# it is a choice this file should not make silently.
MASK = "[redacted:{detector}]"

# A detector reported no span, so the whole value goes. Coarse on purpose:
# the alternative is forwarding a value we know contains a match but cannot
# locate, which is the one outcome this adapter exists to prevent.
MASK_WHOLE = "[redacted:{detector}:whole-value]"


# The explicit opt-out. A word rather than an empty list, so that
# "forward my own telemetry raw" is a decision someone typed and a
# reviewer can grep for, instead of the state a config falls into by
# leaving a key out.
NO_REDACTION = "none"


@dataclass
class RedactionPlan:
    """Which detectors this sink censors, resolved against what is running.

    Built once, at startup, so an unavailable tier is a refusal to start
    rather than a per-batch surprise.
    """

    detectors: frozenset[str]

    @classmethod
    def build(
        cls, config: SinkConfig, available: Iterable[str]
    ) -> RedactionPlan:
        """`available` is what the RUNNING scan core can emit.

        Two granularities have to line up here and they nearly did not.
        A detector is named `regex`; the finding it emits is
        `regex:aws-access-key-id`. Checking the config against detector
        names alone would accept `regex:typo` — the tier is running, so
        nothing refuses, and the rule simply never matches. The value then
        leaves uncensored, which is the exact failure this class exists to
        prevent, arriving through a spelling mistake rather than a missing
        tier.

        So a caller passes every id the core can actually produce, and a
        bare detector name is accepted as shorthand for all of its rules.
        """
        wanted = {d.strip() for d in config.redact if d.strip()}
        have = set(available)
        # Fail closed. An operator who said nothing gets everything the
        # running core can find, censored. The opposite default would have
        # a sink with an endpoint and no `redact` send every matched secret
        # on verbatim.
        if not wanted:
            return cls(frozenset(have))
        if wanted == {NO_REDACTION}:
            return cls(frozenset())
        # A bare tier name means "everything this detector finds".
        tiers = {h.split(":", 1)[0] for h in have}
        missing = sorted(w for w in wanted if w not in have and w not in tiers)
        if missing:
            raise SinkUnavailable(
                f"sink {config.name!r} is configured to redact {missing}, "
                f"which no running detector produces. Forwarding would send "
                f"those values to {config.endpoint or 'the sink'} uncensored "
                f"while reporting a clean scan, so this refuses to start "
                f"rather than widen silently. Available: {sorted(have)}"
            )
        return cls(frozenset(wanted))

    def wants(self, detector: str) -> bool:
        if detector in self.detectors:
            return True
        # `regex` as a config entry censors every regex rule.
        return detector.split(":", 1)[0] in self.detectors


def _still_matches(text: str, plan: RedactionPlan, detectors) -> bool:
    """Does anything the sink redacts still fire on this text?

    THE BACKSTOP, and the reason the span arithmetic above is allowed to be
    merely careful rather than provably exhaustive. Three real bugs are
    caught here and none of them were caught by the spans:

    * `core.scan` calls `dedupe_findings`, keyed on
      (detector, locator, excerpt_hash) -- so the SAME secret twice in one
      value collapses to ONE finding with ONE span. Masking that span left
      the second copy on the wire. Demonstrated: "use K and also K again"
      produced one finding at (4, 24).
    * Presidio analyses `prose_only(unit.text)`, so its offsets are in
      transformed coordinates. Applied to the original they mask the wrong
      substring and leave the PII in place.
    * Overlapping or adjacent spans, and anything else that arithmetic on
      offsets can get subtly wrong.

    Re-scanning costs a second pass over one attribute, on an adapter with
    no latency budget. That is a cheap price for turning "the offsets
    should be right" into "the output was checked".
    """
    if not detectors:
        # No detectors means the backstop cannot run, and a redacting sink
        # without it is one whose masking is unverified. `detectors` is a
        # REQUIRED argument for that reason -- it defaulted to () and a
        # caller omitting it silently turned the check off.
        raise SinkUnavailable(
            "redaction was asked for with no detectors to verify it against"
        )
    unit = ScanUnit(locator="verify", tool_name=None, text=text)
    for d in detectors:
        try:
            for f in d.scan([unit]):
                if plan.wants(f.detector):
                    return True
        except Exception:  # pragma: no cover - a detector failing open here
            # would be a detector deciding the output is safe, which is
            # exactly the call it does not get to make.
            return True
    return False


def _findings_for(text: str, plan: RedactionPlan, detectors) -> list[Finding]:
    """Scan one short string against the tiers this sink redacts.

    The event name never went through `record_units`, so there were no
    findings for it and nothing to mask against. Only the cheap tiers:
    a name is not prose.
    """
    if not text:
        return []
    cheap = [d for d in detectors if getattr(d, "tier", 0) < 2]
    if not cheap:
        return []
    unit = ScanUnit(locator="name", tool_name=None, text=text)
    out: list[Finding] = []
    for det in cheap:
        # A detector that fails here must not fail the batch: this is a
        # belt-and-braces pass over a short string, and the value it
        # guards is already masked in the attributes.
        with contextlib.suppress(Exception):
            out.extend(det.scan([unit]))
    return [f for f in out if plan.wants(f.detector)]


def _mask_text(text: str, findings: Sequence[Finding], plan: RedactionPlan,
               detectors) -> tuple[str, dict[str, int]]:
    """Replace every wanted match in one value.

    Right to left, so an earlier replacement cannot move a later offset --
    doing it left to right shifts every subsequent span by the difference
    between the match length and the mask length, which silently censors
    the wrong characters and leaves part of the secret in place.
    """
    counts: dict[str, int] = {}
    wanted = [f for f in findings if plan.wants(f.detector)]
    if not wanted:
        return text, counts

    def whole(f: Finding) -> tuple[str, dict[str, int]]:
        # Counted per finding, not per distinct detector. The dict
        # comprehension here read `counts.get(...)` once per key and never
        # saw its own earlier iterations, so three no-span findings of one
        # detector reported 1.
        totals = dict(counts)
        for g in wanted:
            totals[g.detector] = totals.get(g.detector, 0) + 1
        return MASK_WHOLE.format(detector=f.detector), totals

    # The output, right to left: text after each mask, then the mask.
    pieces: list[str] = []
    # The start of the leftmost mask so far, in ORIGINAL coordinates. Every
    # mask starts at or after the current finding's start, so a finding
    # overlaps one exactly when it ends after this.
    #
    # Two detectors flagging one string is the common path, not an edge
    # case -- `regex:ssn` and `regex:ssn-labeled` both report (20, 31) on
    # a labelled SSN, and the core collapses exactly that pair for deny
    # reasons. Rewriting per finding without tracking coverage put the
    # second mask INSIDE the first:
    #
    #   employee record ssn [redacted:regex:ssn-labeled]egex:ssn] filed
    #
    # The secret was gone and the backstop agreed, so it never leaked. It
    # mangled the prose this feature exists to preserve, and reported two
    # redactions for one value.
    masked_from = len(text)

    # Right to left. Left to right shifts every later offset by the
    # difference between the match length and the mask length, so the
    # second replacement lands in the wrong place and leaves part of the
    # secret behind -- visibly censored and still leaking.
    for f in sorted(wanted, key=lambda f: -1 if f.start is None else f.start,
                    reverse=True):
        # Two ways a span cannot be used, and both mean the same thing:
        # we know this value contains a match and cannot say where.
        # Forwarding it is the one outcome this adapter exists to prevent,
        # so the value goes whole.
        #
        # ONE branch for both. Checking None separately and relying on
        # `int(None or 0)` producing (0, 0) for the bounds check to reject
        # would be two paths to one result, so a mutation deleting either
        # would be invisible because the other would still catch it.
        if f.start is None or f.end is None:
            return whole(f)
        start, end = int(f.start), int(f.end)
        if not (0 <= start < end <= len(text)):
            return whole(f)
        if masked_from < end:
            # Already covered. Skipping keeps the count honest too: one
            # region censored once, however many detectors named it.
            continue
        pieces.append(text[end:masked_from])
        pieces.append(MASK.format(detector=f.detector))
        masked_from = start
        counts[f.detector] = counts.get(f.detector, 0) + 1
    pieces.append(text[:masked_from])
    out = "".join(reversed(pieces))

    # Checked, not assumed. If anything the sink redacts still fires on the
    # masked text, the span work was wrong and the value goes whole.
    if _still_matches(out, plan, detectors):
        return whole(wanted[0])
    return out, counts


def _blind_to(skipped: Sequence[str], plan: RedactionPlan, detectors) -> str | None:
    """The name of a wanted tier that did not run, if any.

    Matched on the detector's FINDING PREFIX, not its `.name`: the
    skipped list carries `presidio_pii` while the redaction plan speaks
    `presidio`, which is the same mismatch that made the whole PII path
    unconfigurable.
    """
    if not skipped or not plan.detectors:
        return None
    by_name = {d.name: getattr(d, "finding_prefix", d.name) for d in detectors}
    for name in skipped:
        prefix = by_name.get(name, name)
        if any(w == prefix or w.split(":", 1)[0] == prefix for w in plan.detectors):
            return name
    return None


# Units the scan derives from a value, located at the value's locator plus
# one of these. Their spans are not offsets into the value.
_DERIVED_SUFFIXES = (_DECODED_SUFFIX, TAIL_SUFFIX, TAIL_SUFFIX + _DECODED_SUFFIX)


def index_findings(findings: Iterable[Finding]) -> dict[str, list[Finding]]:
    """`findings` by locator, for `redact_events`: by `raw_locator` when it
    is set. A seam finding is filed under both sides, the right without a
    span."""
    by_locator: dict[str, list[Finding]] = {}
    for f in findings:
        by_locator.setdefault(f.raw_locator or f.locator, []).append(f)
        if f.seam_right is not None:
            by_locator.setdefault(f.seam_right, []).append(
                replace(f, start=None, end=None))
    return by_locator


def _findings_at(by_locator: dict[str, list[Finding]], locator: str) -> list[Finding]:
    """The findings at `locator`, and those on units derived from it
    without a span."""
    found = list(by_locator.get(locator) or [])
    for suffix in _DERIVED_SUFFIXES:
        found.extend(replace(f, start=None, end=None)
                     for f in by_locator.get(locator + suffix) or [])
    return found


def _rename_matched(where: dict, guard: MetadataGuard) -> int:
    """Replace each name in `where` a cheap detector matches with a numbered
    placeholder, in place. Returns how many were replaced."""
    named = guard.matches({k: k for k in where})
    if not named:
        return 0
    renamed = {}
    for i, (key, value) in enumerate(where.items()):
        renamed[f"[redacted:metadata-name:{i}]" if key in named else key] = value
    where.clear()
    where.update(renamed)
    return len(named)


def _clean_resource(raw: dict, guard: MetadataGuard) -> tuple[dict, dict[str, int]]:
    """A record's resource with matched values masked and matched names
    replaced, and the redaction counts. A value longer than
    METADATA_MAX_CHARS is masked whole without being scanned."""
    resource = dict(raw)
    counts: dict[str, int] = {}
    short = {}
    for key, value in resource.items():
        if isinstance(value, str) and len(value) > METADATA_MAX_CHARS:
            resource[key] = MASK_WHOLE.format(detector="metadata-long")
            counts["metadata-long"] = counts.get("metadata-long", 0) + 1
        else:
            short[key] = value
    for key in guard.matches(short):
        resource[key] = MASK_WHOLE.format(detector="metadata")
        counts["metadata"] = counts.get("metadata", 0) + 1
    n = _rename_matched(resource, guard)
    if n:
        counts["metadata-name"] = n
    return resource, counts


def _cached_resource(cache: dict, raw: dict,
                     guard: MetadataGuard) -> tuple[dict, dict[str, int]]:
    """`_clean_resource(raw)`, computed once per distinct resource in `cache`."""
    try:
        key = tuple(raw.items())
        hash(key)
    except TypeError:
        return _clean_resource(raw, guard)
    if key not in cache:
        cache[key] = _clean_resource(raw, guard)
    return cache[key]


def redact_events(
    records: Sequence[OtelRecord],
    findings_by_locator: dict[str, list[Finding]],
    plan: RedactionPlan,
    config: SinkConfig,
    *,
    surface: str,
    org: str,
    observed_at: str,
    detectors,
    skipped: Sequence[str] = (),
) -> list[RedactedEvent]:
    """Records in, redacted events out.

    `findings_by_locator` comes from the scan that already ran on the raw
    text. The attribute a finding belongs to comes from
    `record_units_by_key`, which is the same function the scanner used --
    not from parsing the locator, which cannot be split back into a record
    name and an attribute key because both contain dots.
    """
    dropped = {e.strip() for e in config.drop_events if e.strip()}

    # A TIER THE BUDGET SKIPPED FOUND NOTHING, WHICH IS NOT THE SAME AS
    # THERE BEING NOTHING.
    #
    # `core.scan` drops tier >= T2 detectors when the budget is spent and
    # records them in `detectors_skipped`. The findings list then looks
    # exactly like a clean scan, so every attribute was forwarded raw --
    # measured at budget_ms=0 on prose containing a name: the value went
    # out verbatim with redactions={} and no forgd.redacted marker.
    #
    # If the sink was asked to redact something that tier produces, the
    # honest answer is that we do not know what is in this batch. Same
    # posture as the unscanned tail.
    blind = _blind_to(skipped, plan, detectors)
    # The scan hit a unit or findings cap, so any scanned value in the
    # group may hold a match the findings do not show.
    capped = bool(plan.detectors) and UNSCANNED_CAPPED in skipped
    guard = MetadataGuard(detectors) if plan.detectors else None
    out: list[RedactedEvent] = []
    # Records in one resource group share their resource, so each distinct
    # resource is cleaned once per call.
    resources: dict[tuple, tuple[dict, dict[str, int]]] = {}

    def is_dropped(record: OtelRecord) -> bool:
        # The record's own name OR its parent span's. A span event is a
        # separate record with its own name, so matching only the first
        # meant dropping a turn kept the event carrying its content.
        parent = str(record.attributes.get("forgd.parent_span") or "")
        return (record.name or record.kind) in dropped or bool(parent and parent in dropped)

    units_of = [[] if is_dropped(record) else record_units_by_key(record, index)
                for index, record in enumerate(records)]
    # "<record name>.<attribute key>" of each unit whose names, or any run
    # of their dotted segments, a cheap detector matches.
    names = {index: [f"{records[index].name or records[index].kind}.{key}"
                     for key, _ in keyed]
             for index, keyed in enumerate(units_of)}
    scrubbed_names, _ = _scrub_names(
        (n for listed in names.values() for n in listed), [], _cheap(detectors))
    named = {n for n, s in scrubbed_names.items() if s != n}

    for index, record in enumerate(records):
        name = record.name or record.kind
        if is_dropped(record):
            continue

        attributes = dict(record.attributes)
        redactions: dict[str, int] = {}
        if guard is None:
            resource = dict(record.resource)
        else:
            cleaned, counts = _cached_resource(resources, record.resource, guard)
            resource = dict(cleaned)
            for det, n in counts.items():
                redactions[det] = redactions.get(det, 0) + n

        # Identity attributes are not scanned as content and are forwarded
        # as they are, unless a cheap detector matches one.
        if guard is not None:
            scanned = {key for key, _ in units_of[index]}
            rest = {k: v for k, v in attributes.items() if k not in scanned}
            for key in guard.matches(rest):
                attributes[key] = MASK_WHOLE.format(detector="metadata")
                redactions["metadata"] = redactions.get("metadata", 0) + 1

        for key, unit in units_of[index]:
            raw = record.attributes.get(key)
            # THE SCAN SAW A PREFIX. `record_units` truncates at
            # MAX_UNIT_BYTES and the attribute forwarded here is the whole
            # value, so anything past the cut was never looked at. With
            # redaction configured, forwarding an unscanned tail is the
            # leak this adapter exists to prevent -- and it is invisible,
            # because the findings list looks normal.
            # UNREACHABLE TODAY, and deliberately kept.
            #
            # `unit.text` is `value[:MAX_UNIT_BYTES]` (1,048,576) while
            # every decode path already caps an attribute at
            # MAX_VALUE_CHARS (1,000,000), so nothing is ever truncated
            # here and the branch never fires. A one-line change to either
            # constant silently decides whether it does -- which is why
            # the relationship is asserted in the tests rather than left
            # as an arithmetic coincidence two files apart.
            if plan.detectors and isinstance(raw, str) and len(raw) > len(unit.text):
                attributes[key] = MASK_WHOLE.format(detector="unscanned-tail")
                redactions["unscanned-tail"] = redactions.get("unscanned-tail", 0) + 1
                continue

            if blind:
                attributes[key] = MASK_WHOLE.format(detector=f"tier-skipped:{blind}")
                redactions["tier-skipped"] = redactions.get("tier-skipped", 0) + 1
                continue

            if capped:
                attributes[key] = MASK_WHOLE.format(detector="unscanned-capped")
                redactions["unscanned-capped"] = redactions.get("unscanned-capped", 0) + 1
                continue

            found = _findings_at(findings_by_locator, unit.locator)
            # A name that matched but whose findings still cannot be placed
            # is masked whole.
            matched = f"{name}.{key}" in named
            if not found and (matched or (
                    guard is not None and guard.matches({key: key}))):
                attributes[key] = MASK_WHOLE.format(detector="metadata-name")
                redactions["metadata-name-value"] = (
                    redactions.get("metadata-name-value", 0) + 1)
                continue
            if not found:
                continue
            masked, counts = _mask_text(unit.text, found, plan, detectors)
            if not counts:
                continue
            attributes[key] = masked
            for det, n in counts.items():
                redactions[det] = redactions.get(det, 0) + n

        # Attribute names are sender data too. A matching name is replaced
        # with a numbered placeholder, which keeps the names unique and
        # carries no digest of the value.
        if guard is not None:
            n = _rename_matched(attributes, guard)
            if n:
                redactions["metadata-name"] = redactions.get("metadata-name", 0) + n

        # Metadata never overwrites an attribute the record already has.
        #
        # An `update()` would let `metadata: {tool.output: stamped}`
        # replace the masked value -- the wire would say "stamped" while
        # `redactions` still reported a redaction, and the operator would
        # lose the attribute without being told. A collision is counted
        # instead.
        for mk, mv in config.metadata.items():
            if mk in attributes:
                redactions["metadata-collision"] = (
                    redactions.get("metadata-collision", 0) + 1
                )
                continue
            attributes[mk] = mv
        # The name, against the same plan. A name is not prose and is
        # almost never long enough to match, so this costs a regex pass
        # over a short string per record and normally changes nothing.
        safe_name, name_counts = _mask_text(
            name, _findings_for(name, plan, detectors), plan, detectors)
        for det, n in name_counts.items():
            redactions[det] = redactions.get(det, 0) + n

        out.append(
            RedactedEvent(
                kind=record.kind,
                name=safe_name,
                observed_at=observed_at,
                surface=surface,
                org=org,
                attributes=attributes,
                resource=resource,
                redactions=redactions,
            )
        )
    return out
