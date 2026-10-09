"""Redacting an export's groups together gives what v0.45.0 gave group by group.

v0.45.0 called `redact_events` once per group. `redact_groups` redacts every
group of an export against one `RedactionContext`. Randomised exports with
planted secrets are run through both, and the events must be identical,
redaction counts included. `_redact_v0_45_0` is the frozen v0.45.0 module.

Since then the redaction guard probes with every tier below T2, and an
identity value the scan placed a finding on is masked. v0.45.0 is run with
that guard, and both are handed the findings without those on identity
units. A seam finding now lies in the units its match lies in, where
v0.45.0 put it on both sides of one join; v0.45.0 is handed the new filing
(`_v045_index`): a value v0.45.0 masked
may now go out unchanged, but only if it holds no fragment of a split
secret, and no planted secret in a value the detectors find something in
on its own. Seeds from 3000 also plant one secret split across
two adjacent values. `_as_v045` undoes the other two changes; `test_sink_redact_scan_parity`
covers all of them.

Ground truth from the generator: no fragment of a planted secret that the
detectors find in every context it is planted in survives in a forwarded
event or a stored record.
"""

from __future__ import annotations

import base64
import dataclasses
import functools
import os
import random

import _redact_v0_45_0 as v045
import pytest
from conftest import (
    FAKE_AWS_KEY,
    FAKE_GITHUB_TOKEN,
    FAKE_PAN,
    FAKE_SSN,
    GITLEAKS_FIXTURES,
    GITLEAKS_STOPWORD_GHP,
)
from test_sink_late import NAME, FakeNER

from forgd_verdict.budget import Budget
from forgd_verdict.core import scan
from forgd_verdict.detectors.gitleaks import GitleaksDetector
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.metadata import MetadataGuard
from forgd_verdict.models import UNSCANNED_CAPPED, ScanUnit
from forgd_verdict.otel.collect import collect
from forgd_verdict.otel.extract import CONTENT_KEYS, _identity_units, records_units
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink import redact
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.factory import emitted_ids

# Bounds on time and memory: run alone, after the parallel suite.
pytestmark = pytest.mark.serial

SECRETS = (FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, FAKE_SSN, FAKE_PAN, GITLEAKS_STOPWORD_GHP,
           *sorted(GITLEAKS_FIXTURES.values())[:6])
# Secrets with a word character touching them, and base64 encodings of
# secrets in the URL-safe alphabet, unpadded, or behind one letter.
GLUED_SECRETS = (
    "key_" + FAKE_AWS_KEY, FAKE_AWS_KEY + "7", "x" + FAKE_GITHUB_TOKEN + "_z",
    "x" + FAKE_SSN, "card_" + FAKE_PAN + "_",
    base64.urlsafe_b64encode(b"\xfb\xff" + FAKE_AWS_KEY.encode()).decode(),
    base64.b64encode(("id=" + FAKE_AWS_KEY).encode()).decode().rstrip("="),
    "x" + base64.b64encode(FAKE_GITHUB_TOKEN.encode()).decode(),
)
# Seeds per gitleaks differential: each seed runs many real gitleaks
# subprocesses. CI on a push to main sets FORGD_FULL_DIFFERENTIAL.
GITLEAKS_SEEDS = 30 if os.environ.get("FORGD_FULL_DIFFERENTIAL") else 10
GITLEAKS_RANDOM = range(1000, 1000 + GITLEAKS_SEEDS)
GITLEAKS_SPLIT = range(4000, 4000 + GITLEAKS_SEEDS)
GITLEAKS_GLUED = range(6000, 6000 + GITLEAKS_SEEDS)

PLAIN_NAMES = ("alphanote", "user.email", "session.id", "model", "tool.name",
               "terminal.type", "decision", "source", "duration_ms", "cost.usd")
EVENT_NAMES = ("claude_code.user_prompt", "claude_code.tool_result", "agent.query",
               "tool.call", "generic.note", "claude_code.api_request")
SERVICES = ("claude-code", "office-agent", "cowork", "", "excel")
METADATA = ({}, {"env": "prod"}, {"tool.output": "stamped", "env": "prod"},
            {"alphanote": "stamped"})


def _value(rng: random.Random, secrets=SECRETS) -> str:
    secret = rng.choice(secrets)
    return rng.choice([
        "plain words only",
        f"use {secret} please",
        secret,
        f"line one\nthen {secret}\nand {rng.choice(secrets)} too",
        "",
        str(rng.randint(0, 10**6)),
        f"key={secret}&other=1",
        "a" * rng.randint(1, 300),
        f"{rng.choice(PLAIN_NAMES)} {rng.random()}",
    ])


def _name(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.08:
        return rng.choice(SECRETS)
    if roll < 0.15:
        return f"x.{rng.choice(SECRETS)}.y"
    if roll < 0.45:
        return rng.choice(CONTENT_KEYS)
    return rng.choice(PLAIN_NAMES)


def _record(rng: random.Random, kinds, secrets=SECRETS) -> OtelRecord:
    attributes = {_name(rng): _value(rng, secrets) for _ in range(rng.randint(1, 6))}
    if rng.random() < 0.3:
        attributes["forgd.parent_span"] = rng.choice(EVENT_NAMES)
    resource = {"service.name": rng.choice(SERVICES)}
    if rng.random() < 0.3:
        resource[rng.choice(("host.name", "deployment", "user.id"))] = _value(rng, secrets)
    name = (rng.choice(EVENT_NAMES) if rng.random() < 0.9
            else f"evt.{rng.choice(SECRETS)}")
    return OtelRecord(kind=rng.choice(kinds), name=name, attributes=attributes,
                      resource=resource)


# Two adjacent values a split secret is planted across: identity values,
# then content values.
SPLIT_PAIRS = (("claude_code.user_prompt", "session.id", "request_id"),
               ("claude_code.api_request", "prompt", "response"))
# A secret cut at c: both fragments; the left beside the right and a whole
# copy; and the mirror.
SPLIT_SHAPES = (("{left}", "{right}"), ("{left}", "{right} {whole}"),
                ("{whole} {left}", "{right}"))


def _split_record(pair, shape, secret: str, cut: int) -> OtelRecord:
    name, first, second = pair
    parts = {"left": secret[:cut], "right": secret[cut:], "whole": secret}
    attributes = {first: shape[0].format(**parts), second: shape[1].format(**parts)}
    if first == "session.id":
        attributes["prompt"] = "hello there"
    return OtelRecord(kind="log", name=name, attributes=attributes,
                      resource={"service.name": "claude-code"})


@functools.cache
def _split_found(detectors, pair, secret: str, cut: int) -> bool:
    """Whether the detectors find anything in `secret` cut at `cut` across
    `pair`, with nothing else beside it."""
    record = _split_record(pair, SPLIT_SHAPES[0], secret, cut)
    return bool(scan(records_units([record]), list(detectors), Budget(60_000)).findings)


def _plant_split(rng: random.Random, detectors, secrets, splits) -> OtelRecord | None:
    """A record with one secret the detectors find in every context split
    across two adjacent values at a cut they find it at, or None when there
    is none; the secret is appended to `splits`."""
    candidates = [s for s in _found(detectors, secrets) if len(s) >= 2 * FRAGMENT]
    if not candidates:
        return None
    secret = rng.choice(candidates)
    pair = rng.choice(SPLIT_PAIRS)
    shape = rng.choice(SPLIT_SHAPES)
    cuts = list(range(FRAGMENT, len(secret) - FRAGMENT + 1))
    rng.shuffle(cuts)
    for cut in cuts:
        if _split_found(tuple(detectors), pair, secret, cut):
            splits.append(secret)
            return _split_record(pair, shape, secret, cut)
    return None


def _export(rng: random.Random, detectors, unrun=(), secrets=SECRETS, splits=None):
    """(config, groups as (records, findings, surface, skipped)). In about
    half the groups, the detectors in `unrun` are left out of the scan and
    reported as skipped. With `splits` a list, one group also holds a
    record with a secret split across two values (`_plant_split`)."""
    resources = [None]
    groups = []
    count = rng.randint(1, 8)
    split_group = rng.randrange(count) if splits is not None else None
    for index in range(count):
        records = []
        for _ in range(rng.randint(1, 5)):
            record = _record(rng, ("log", "span", "event"), secrets)
            # Records in an export often share a resource.
            if resources[-1] is not None and rng.random() < 0.5:
                record.resource = dict(rng.choice(resources[1:]))
            resources.append(record.resource)
            records.append(record)
        if index == split_group:
            split = _plant_split(rng, detectors, secrets, splits)
            if split is not None:
                records.insert(rng.randint(0, len(records)), split)
        blind = bool(unrun) and rng.random() < 0.5
        ran = [d for d in detectors if not (blind and d in unrun)]
        result = scan(records_units(records), ran, Budget(60_000))
        skipped = list(result.detectors_skipped)
        if blind:
            skipped.extend(d.name for d in unrun)
        if rng.random() < 0.1:
            skipped.append(UNSCANNED_CAPPED)
        groups.append((records, list(result.findings), rng.choice(SERVICES) or "s",
                       tuple(skipped)))
    config = SinkConfig(
        name="s", endpoint="https://collector.test",
        drop_events=rng.sample(EVENT_NAMES, rng.randint(0, 2)),
        metadata=dict(rng.choice(METADATA)))
    return config, groups


@pytest.fixture(autouse=True)
def _v045_guard_probes_below_t2(monkeypatch):
    monkeypatch.setattr(v045, "MetadataGuard",
                        functools.partial(MetadataGuard, allow_subprocess=True))


def _without_identity_findings(records, findings) -> list:
    """`findings` without those on an identity unit. One seamed onto an
    identity unit is kept on its left side alone when it counts there, as
    `dedupe_findings` may have merged a finding on that value into it."""
    identity = {u.locator for i, r in enumerate(records) for _, u in _identity_units(r, i)}
    out = []
    for f in findings:
        if (f.raw_locator or f.locator) in identity:
            continue
        others = tuple(o for o in f.seam_others if o not in identity)
        out.append(f if others == f.seam_others
                   else dataclasses.replace(f, seam_others=others))
    return out


def _v045_index(findings):
    """v0.45.0's `index_findings` for findings that carry `seam_others`:
    each filed under its locator, and without a span under every unit it
    also lies in."""
    by_locator: dict[str, list] = {}
    for f in findings:
        by_locator.setdefault(f.raw_locator or f.locator, []).append(f)
        for other in f.seam_others:
            by_locator.setdefault(other, []).append(
                dataclasses.replace(f, start=None, end=None))
    return by_locator


FRAGMENT = 8


def _fragments(secrets) -> set[str]:
    """Every run of `FRAGMENT` characters in `secrets`."""
    return {s[i:i + FRAGMENT] for s in secrets for i in range(len(s) - FRAGMENT + 1)}


# Each way `_value`, `_name` and `_record` plant a secret.
CONTEXTS = ("{}", "use {} please", "key={}&other=1", "line one\nthen {}\nand x too",
            "x.{}.y", "evt.{}")


@functools.cache
def _found_alone(detectors, text: str) -> bool:
    result = scan([ScanUnit(locator="0", tool_name=None, text=text)], list(detectors),
                  Budget(60_000))
    return bool(result.findings)


def _found(detectors, secrets) -> tuple[str, ...]:
    """The `secrets` the detectors find in each context the generator plants
    them in, scanned as a value on its own."""
    return tuple(s for s in secrets
                 if all(_found_alone(tuple(detectors), c.format(s)) for c in CONTEXTS))


def _planted(groups, secrets) -> set[str]:
    """The `secrets` anywhere in the records of `groups`."""
    texts = [str(x) for records, *_ in groups for r in records
             for x in (r.name, *r.attributes, *r.attributes.values(),
                       *r.resource, *r.resource.values())]
    return {s for s in secrets if any(s in t for t in texts)}


def _leaked(text: str, fragments) -> list[str]:
    return sorted(f for f in fragments if f in text)


def _as_v045(new, old, exposes, seamed):
    """`new` with three changes since v0.45.0 undone where `old` shows them,
    and its counts lowered to match: an attribute name the scrub of
    "<record name>.<attribute key>" replaced is renamed, where only the
    guard renamed one before; an identity value a tier the guard lacks
    did not scan, skipped or capped, is masked; and a value v0.45.0 masked
    for a seam finding, that `new` masks under another counter or forwards
    as a value `exposes` is false for, is masked as v0.45.0 masked it, and the event's
    counts are taken from `old`. Otherwise a count of a detector in
    `seamed`, which v0.45.0 also counted on each side it no longer files a
    seam finding under, is taken from `old` where it is no higher."""
    if len(new.attributes) != len(old.attributes):
        return new
    unmasked = False
    redactions = dict(new.redactions)

    def lower(counter):
        redactions[counter] -= 1
        if not redactions[counter]:
            del redactions[counter]

    attributes = {}
    for i, ((nk, nv), (ok, ov)) in enumerate(zip(new.attributes.items(),
                                                  old.attributes.items(), strict=True)):
        if nk != ok and nk == f"[redacted:metadata-name:{i}]":
            nk = ok
            lower("metadata-name")
        if nv != ov and isinstance(ov, str) and not ov.startswith("[redacted:"):
            for counter in ("tier-skipped", "unscanned-capped"):
                if nv.startswith(f"[redacted:{counter}:"):
                    nv = ov
                    lower(counter)
                    break
        if (nv != ov and isinstance(ov, str) and "[redacted:" in ov and isinstance(nv, str)
                and ("[redacted:" in nv or not exposes(nv))):
            nv = ov
            unmasked = True
        attributes[nk] = nv
    if unmasked:
        redactions = dict(old.redactions)
    for k in seamed & set(old.redactions):
        if redactions.get(k, 0) <= old.redactions[k]:
            redactions[k] = old.redactions[k]
    return dataclasses.replace(new, attributes=attributes, redactions=redactions)


def _differ(seed: int, detectors, unrun=(), secrets=SECRETS, split=False) -> int:
    rng = random.Random(seed)
    splits = [] if split else None
    config, groups = _export(rng, detectors, unrun, secrets, splits)
    planted = _planted(groups, secrets)
    split_fragments = _fragments(splits or ())

    def exposes(value: str) -> bool:
        """Whether `value` holds a fragment of the split secret, or a planted
        secret where the detectors find something in it on its own."""
        return bool(_leaked(value, split_fragments)) or (
            any(s in value for s in planted) and _found_alone(tuple(detectors), value))

    groups = [(records, _without_identity_findings(records, findings), surface, skipped)
              for records, findings, surface, skipped in groups]
    ids = emitted_ids(detectors)
    old_plan = v045.RedactionPlan.build(config, ids)
    new_plan = redact.RedactionPlan.build(config, ids)
    kw = {"org": "o", "observed_at": "2026-10-05T00:00:00Z", "detectors": detectors}

    before = [e for records, findings, surface, skipped in groups
              for e in v045.redact_events(records, _v045_index(findings),
                                          old_plan, config, surface=surface,
                                          skipped=skipped, **kw)]
    after = redact.redact_groups(
        [redact.RedactGroup(records, redact.index_findings(findings), surface, skipped)
         for records, findings, surface, skipped in groups],
        new_plan, config, context=redact.RedactionContext(detectors, new_plan), **kw)
    assert len(after) == len(before), f"seed {seed}"
    seamed = {f.detector for _, findings, *_ in groups for f in findings
              if f.seam_others}
    for new, old in zip(after, before, strict=True):
        assert _as_v045(new, old, exposes, seamed) == old, f"seed {seed}"
    return sum(len(records) for records, *_ in groups)


def test_t0_matches_v0_45_0_over_randomised_exports():
    detectors = [T0RegexDetector()]
    records = sum(_differ(seed, detectors) for seed in range(300))
    assert records > 2000


def test_t0_and_gitleaks_match_v0_45_0_over_randomised_exports():
    gitleaks = GitleaksDetector()
    if not gitleaks.available():
        pytest.skip("gitleaks is not installed")
    detectors = [T0RegexDetector(), gitleaks]
    records = sum(_differ(seed, detectors) for seed in GITLEAKS_RANDOM)
    assert records > 10 * GITLEAKS_SEEDS


def test_a_skipped_t2_tier_matches_v0_45_0_over_randomised_exports():
    """The plan redacts what a T2 tier finds; in some groups that tier did
    not run, so every scanned value there is masked whole."""
    ner = FakeNER()
    detectors = [T0RegexDetector(), ner]
    secrets = (*SECRETS, NAME, f"ask {NAME}")
    records = sum(_differ(seed, detectors, (ner,), secrets) for seed in range(2000, 2200))
    assert records > 1000


def _leaks(seed: int, detectors, secrets=SECRETS, split=False) -> list[str]:
    """Secret fragments in what a randomised export forwards and stores:
    one `seed:where:fragment` each."""
    rng = random.Random(seed)
    splits = [] if split else None
    config, groups = _export(rng, detectors, (), secrets, splits)
    fragments = _fragments(_found(detectors, secrets)) | _fragments(splits or ())
    plan = redact.RedactionPlan.build(config, emitted_ids(detectors))
    events = redact.redact_groups(
        [redact.RedactGroup(records, redact.index_findings(findings), surface, skipped)
         for records, findings, surface, skipped in groups],
        plan, config, context=redact.RedactionContext(detectors, plan), org="o",
        observed_at="2026-10-05T00:00:00Z", detectors=detectors)
    out = [f"{seed}:forwarded:{f}" for e in events
           for f in _leaked(repr(dataclasses.asdict(e)), fragments)]
    for records, *_ in groups:
        stored, _ = collect(records, detectors, budget_ms=60_000, salt="x", org_id="o")
        out += [f"{seed}:stored:{f}" for r in stored for f in _leaked(r.to_json(), fragments)]
    return out


def test_t0_leaves_no_secret_fragment_in_randomised_exports():
    detectors = [T0RegexDetector()]
    assert [k for seed in range(300) for k in _leaks(seed, detectors)] == []


def test_t0_and_gitleaks_leave_no_secret_fragment_in_randomised_exports():
    gitleaks = GitleaksDetector()
    if not gitleaks.available():
        pytest.skip("gitleaks is not installed")
    detectors = [T0RegexDetector(), gitleaks]
    assert [k for seed in GITLEAKS_RANDOM for k in _leaks(seed, detectors)] == []


def test_t0_matches_v0_45_0_with_a_split_secret():
    detectors = [T0RegexDetector()]
    assert sum(_differ(seed, detectors, split=True) for seed in range(3000, 3100)) > 500


def test_t0_and_gitleaks_match_v0_45_0_with_a_split_secret():
    gitleaks = GitleaksDetector()
    if not gitleaks.available():
        pytest.skip("gitleaks is not installed")
    detectors = [T0RegexDetector(), gitleaks]
    assert sum(_differ(seed, detectors, split=True) for seed in GITLEAKS_SPLIT) > 5 * GITLEAKS_SEEDS


def test_t0_leaves_no_fragment_of_a_split_secret():
    detectors = [T0RegexDetector()]
    assert [k for seed in range(3000, 3100) for k in _leaks(seed, detectors, split=True)] == []


def test_t0_and_gitleaks_leave_no_fragment_of_a_split_secret():
    gitleaks = GitleaksDetector()
    if not gitleaks.available():
        pytest.skip("gitleaks is not installed")
    detectors = [T0RegexDetector(), gitleaks]
    assert [k for seed in GITLEAKS_SPLIT for k in _leaks(seed, detectors, split=True)] == []


def _crossed_into(records, detectors) -> set[tuple[str, str]]:
    """(key, value) of each identity value in `records` that a detector's
    match on an adjacent seam crosses into, from spans the detectors
    report on the seams `core.scan` builds."""
    from forgd_verdict.core import _on_seams, _seams

    identity = {u.locator: (key, u.text) for i, r in enumerate(records)
                for key, u in _identity_units(r, i)}
    found = _seams(list(records_units(records)))
    parts = {seam.locator: p for seam, p in found}
    units = [seam for seam, _ in found]
    out = set()
    for det in detectors:
        spanned = [f for f in (det.scan(units) if units else [])
                   if f.start is not None and f.end is not None]
        for f in _on_seams(spanned, parts):
            if not f.seam_others:
                continue
            for loc in (f.locator, *f.seam_others):
                if loc in identity:
                    out.add(identity[loc])
    return out


def _over_masked(seed: int, detectors, secrets=SECRETS) -> list[str]:
    """Identity values in a randomised export that hold no planted secret,
    that the detectors match nothing in when scanned alone, that no match
    on an adjacent seam crosses into, and that `redact_groups`, given every
    finding, masked as matched: one `seed:key` each."""
    rng = random.Random(seed)
    config, groups = _export(rng, detectors, (), secrets)
    config = dataclasses.replace(config, drop_events=[])
    plan = redact.RedactionPlan.build(config, emitted_ids(detectors))
    events = iter(redact.redact_groups(
        [redact.RedactGroup(records, redact.index_findings(findings), surface, skipped)
         for records, findings, surface, skipped in groups],
        plan, config, context=redact.RedactionContext(detectors, plan), org="o",
        observed_at="2026-10-05T00:00:00Z", detectors=detectors))
    matched = redact.MASK_WHOLE.format(detector="metadata")
    out = []
    for records, *_ in groups:
        crossed = _crossed_into(records, detectors)
        for record in records:
            values = list(next(events).attributes.values())
            identity = {k for k, _ in _identity_units(record, 0)}
            for position, (key, value) in enumerate(record.attributes.items()):
                if (key in identity and values[position] == matched
                        and not any(s in value for s in secrets)
                        and (key, value) not in crossed):
                    out.append((f"{seed}:{key}", value))
    assert next(events, None) is None, f"seed {seed}"
    alone = scan([ScanUnit(locator=str(i), tool_name=None, text=v)
                  for i, (_, v) in enumerate(out)], detectors, Budget(60_000))
    hit = {int(f.locator) for f in alone.findings if not f.seam_others}
    return [k for i, (k, _) in enumerate(out) if i not in hit]


def test_a_clean_identity_value_is_never_masked_as_matched():
    """Ground truth from the generator: an identity value no planted secret
    is in, and that no detector's match crosses into from a neighbour, keeps
    its value."""
    gitleaks = GitleaksDetector()
    if not gitleaks.available():
        pytest.skip("gitleaks is not installed")
    detectors = [T0RegexDetector(), gitleaks]
    assert [k for seed in GITLEAKS_RANDOM for k in _over_masked(seed, detectors)] == []


def test_t0_finds_every_glued_and_encoded_secret_in_every_context():
    assert _found([T0RegexDetector()], GLUED_SECRETS) == GLUED_SECRETS


def test_t0_leaves_no_fragment_of_a_glued_or_encoded_secret():
    detectors = [T0RegexDetector()]
    assert [k for seed in range(5000, 5100)
            for k in _leaks(seed, detectors, GLUED_SECRETS)] == []


def test_t0_and_gitleaks_leave_no_fragment_of_a_glued_or_encoded_secret():
    gitleaks = GitleaksDetector()
    if not gitleaks.available():
        pytest.skip("gitleaks is not installed")
    detectors = [T0RegexDetector(), gitleaks]
    assert [k for seed in GITLEAKS_GLUED
            for k in _leaks(seed, detectors, GLUED_SECRETS)] == []


# A secret cut across the scalars of one array or kvlist attribute. v0.45.0
# scanned such a value as its rendered JSON text, so these are checked
# against ground truth only.
STRUCTURED_SHAPES = ("array", "kvlist", "nested")


def _structured_record(shape: str, secret: str, cut: int) -> OtelRecord:
    import json

    from forgd_verdict.otel.payload import decode

    left, right = ({"stringValue": secret[:cut]}, {"stringValue": secret[cut:]})
    if shape == "array":
        value = {"arrayValue": {"values": [left, right]}}
    elif shape == "kvlist":
        value = {"kvlistValue": {"values": [{"key": "a", "value": left},
                                            {"key": "b", "value": right}]}}
    else:
        value = {"arrayValue": {"values": [
            {"stringValue": "before"},
            {"arrayValue": {"values": [left, {"kvlistValue": {"values": [
                {"key": "k", "value": right}]}}]}}]}}
    body = {"resourceLogs": [{"resource": {"attributes": [
        {"key": "service.name", "value": {"stringValue": "claude-code"}}]},
        "scopeLogs": [{"logRecords": [{"attributes": [
            {"key": "event.name", "value": {"stringValue": "claude_code.user_prompt"}},
            {"key": "prompt", "value": value}]}]}]}]}
    (record,) = decode(json.dumps(body).encode(), "application/json", "logs")
    return record


def _structured_leaks(seed: int, detectors) -> list[str]:
    """Fragments of a secret split across one array or kvlist attribute,
    in what is forwarded and stored, for a cut the detectors find across two
    adjacent plain values; or a `seed:missed` when the scan finds nothing."""
    rng = random.Random(seed)
    candidates = [s for s in _found(detectors, SECRETS) if len(s) >= 2 * FRAGMENT]
    secret = rng.choice(candidates)
    pair = SPLIT_PAIRS[1]
    cuts = [c for c in range(FRAGMENT, len(secret) - FRAGMENT + 1)
            if _split_found(tuple(detectors), pair, secret, c)]
    if not cuts:
        return []
    record = _structured_record(rng.choice(STRUCTURED_SHAPES), secret, rng.choice(cuts))
    result = scan(records_units([record]), detectors, Budget(60_000))
    if not result.findings:
        return [f"{seed}:missed"]
    config = SinkConfig(name="s", endpoint="https://collector.test")
    plan = redact.RedactionPlan.build(config, emitted_ids(detectors))
    events = redact.redact_groups(
        [redact.RedactGroup([record], redact.index_findings(result.findings), "s",
                            tuple(result.detectors_skipped))],
        plan, config, context=redact.RedactionContext(detectors, plan), org="o",
        observed_at="2026-10-05T00:00:00Z", detectors=detectors)
    fragments = _fragments([secret])
    out = [f"{seed}:forwarded:{f}" for e in events
           for f in _leaked(repr(dataclasses.asdict(e)), fragments)]
    stored, _ = collect([record], detectors, budget_ms=60_000, salt="x", org_id="o")
    out += [f"{seed}:stored:{f}" for r in stored for f in _leaked(r.to_json(), fragments)]
    return out


def test_t0_finds_and_masks_a_secret_split_across_array_or_kvlist_scalars():
    detectors = [T0RegexDetector()]
    assert [k for seed in range(5000, 5100) for k in _structured_leaks(seed, detectors)] == []


def test_t0_and_gitleaks_find_and_mask_a_secret_split_across_array_or_kvlist_scalars():
    gitleaks = GitleaksDetector()
    if not gitleaks.available():
        pytest.skip("gitleaks is not installed")
    detectors = [T0RegexDetector(), gitleaks]
    assert [k for seed in range(6000, 6000 + GITLEAKS_SEEDS)
            for k in _structured_leaks(seed, detectors)] == []
