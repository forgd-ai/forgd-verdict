"""The collector runs gitleaks once per group, on that group's units only.

gitleaks' default `private-key` rule matches `[\\s\\S-]{64,}?` between the
BEGIN and END lines, so a match crosses whatever separates two units in a
joined stream. Scanning an export's groups as one stream would let the end
of one turn and the start of the next form a finding neither holds.
`_collect_v0_45_0` and `_gitleaks_v0_45_0` are the frozen v0.45.0 modules.
"""

from __future__ import annotations

import random
import uuid

import _collect_v0_45_0 as v045_collect
import _gitleaks_v0_45_0 as v045_gitleaks
import pytest
from conftest import (
    FAKE_AWS_KEY,
    FAKE_GITHUB_TOKEN,
    GITLEAKS_FIXTURES,
    GITLEAKS_STOPWORD_GHP,
    GITLEAKS_T1_ONLY,
    make_policy,
)

from forgd_verdict.detectors import gitleaks as gitleaks_mod
from forgd_verdict.detectors.gitleaks import BASELINE_CONFIG, GitleaksDetector
from forgd_verdict.otel.collect import collect
from forgd_verdict.otel.extract import CONTENT_KEYS, records_units
from forgd_verdict.otel.payload import OtelRecord

# Runs real gitleaks against the last release: alone, after the parallel suite.
pytestmark = pytest.mark.serial

BEGIN = "-----BEGIN RSA " + "PRIVATE KEY-----"
END = "-----END RSA " + "PRIVATE KEY-----"
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BODY = "".join(random.Random(7).choice(_B64) for _ in range(80))
GITLAB_PAT = GITLEAKS_T1_ONLY["gitlab-pat"]

SEPARATORS = ("\n", "\n\n", "\n\x00\x1e\n", "\n \n", "\x1e\n\x1e", "\n" * 40)


def _gitleaks(**kw) -> GitleaksDetector:
    detector = GitleaksDetector(**kw)
    if not detector.available():
        pytest.skip("gitleaks is not installed")
    return detector


def _record(prompt_id: str, **attributes: str) -> OtelRecord:
    return OtelRecord(kind="log", name="claude_code.user_prompt",
                      attributes={"prompt.id": prompt_id, **attributes},
                      resource={"service.name": "claude-code"})


def _by_turn(records) -> dict:
    return {r.session_id: r for r in records}


@pytest.mark.parametrize("sep", SEPARATORS, ids=repr)
def test_the_private_key_rule_spans_any_separator(sep):
    gitleaks = _gitleaks()
    # gitleaks 8.30.1 reports EndLine as StartLine for a match that ends
    # the stream, so a third unit follows the key.
    units = [BEGIN, BODY + END, "trailing words in a third unit"]
    starts = [1]
    for text in units[:-1]:
        starts.append(starts[-1] + text.count("\n") + sep.count("\n"))

    def unit_of(line: int) -> int:
        return max(i for i, start in enumerate(starts) if start <= line)

    report = gitleaks._run_subprocess(sep.join(units))

    keys = [item for item in report if item["RuleID"] == "private-key"]
    assert len(keys) == 1
    assert sep in keys[0]["Match"]
    assert unit_of(int(keys[0]["StartLine"])) == 0
    assert unit_of(int(keys[0]["EndLine"])) == 1


def test_a_header_ending_one_group_does_not_pair_with_the_next_group():
    gitleaks = _gitleaks()
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    records = [
        _record(a, prompt=f"the key starts here {BEGIN}"),
        _record(b, prompt=f"{BODY}{END}\nand the token {GITLAB_PAT}"),
    ]
    joined, _ = gitleaks_mod._join(records_units(records), gitleaks.max_bytes)
    assert "private-key" in {i["RuleID"] for i in gitleaks._run_subprocess(joined)}

    out, _ = collect(records, [gitleaks], budget_ms=60_000, org_id="o",
                     policy=make_policy())

    turns = _by_turn(out)
    assert {f.detector for f in turns[b].findings} == {"gitleaks:gitlab-pat"}
    assert turns[b].action == "deny"
    assert not [f for f in turns[a].findings if f.detector == "gitleaks:private-key"]


def test_gitleaks_launches_once_for_each_group_with_text(monkeypatch):
    gitleaks = _gitleaks()
    streams: list[str] = []
    run = GitleaksDetector._run_subprocess

    def counted(self, stream):
        streams.append(stream)
        return run(self, stream)

    monkeypatch.setattr(GitleaksDetector, "_run_subprocess", counted)
    texty = [str(uuid.uuid4()) for _ in range(5)]
    empty = [str(uuid.uuid4()) for _ in range(2)]
    records = [_record(t, prompt=f"group {i} says hello", response=f"group {i} done")
               for i, t in enumerate(texty)]
    records += [_record(t, decision="accept") for t in empty]

    out, _ = collect(records, [gitleaks], budget_ms=60_000, org_id="o")

    assert len(out) == 7
    scans = [s for s in streams if "group " in s]
    assert len(scans) == len(texty)
    # The metadata guard's launches, whatever the number of groups: one for
    # the attribution hints and one for the records' metadata fields.
    assert len(streams) - len(scans) == 2
    for i, stream in enumerate(scans):
        assert sum(f"group {j} " in stream for j in range(len(texty))) == 1
        assert f"group {i} says hello" in stream


SECRETS = (FAKE_GITHUB_TOKEN, FAKE_AWS_KEY, GITLEAKS_STOPWORD_GHP,
           *sorted(GITLEAKS_FIXTURES.values()))
PLAIN = ("plain words only", "nothing to see in this value", "x" * 300,
         "line one\nline two\nline three")


def _value(rng: random.Random) -> str:
    secret = rng.choice(SECRETS)
    return rng.choice([
        rng.choice(PLAIN),
        secret,
        f"{secret} starts this value",
        f"this value ends with {secret}",
        f"middle {secret} of a value",
        f"one\n{secret}\nthree",
        BEGIN + "\n" + BODY + "\n" + END,
        f"a header at the end {BEGIN}",
        f"{BODY}{END} after a header elsewhere",
        BEGIN,
        BODY + END,
    ])


def _export(rng: random.Random) -> list[OtelRecord]:
    records = []
    for _ in range(rng.randint(2, 20)):
        turn = str(uuid.UUID(int=rng.getrandbits(128)))
        for _ in range(rng.randint(1, 4)):
            keys = rng.sample(CONTENT_KEYS, rng.randint(1, 4))
            attributes = {key: _value(rng) for key in keys}
            if rng.random() < 0.3:
                attributes["user.email"] = "dev@example.com"
            records.append(_record(turn, **attributes))
    rng.shuffle(records)
    return records


def _per_group(records) -> dict:
    """Each group's (detector, excerpt) pairs and action. Locators are left
    out: a seam finding is placed on the units its span overlaps, and the
    v0.45.0 gitleaks module reports spans the current one has improved."""
    return {r.session_id: ({(f.detector, f.excerpt_hash) for f in r.findings}, r.action)
            for r in records}


def test_per_group_findings_match_v0_45_0_over_randomised_exports():
    gitleaks = _gitleaks()
    reference = v045_gitleaks.GitleaksDetector(config=str(BASELINE_CONFIG))
    policy = make_policy()
    exports = groups = findings = keys = 0
    for seed in range(50):
        records = _export(random.Random(seed))
        for turn in {r.attributes["prompt.id"] for r in records}:
            text = "\n".join(u.text for u in records_units(
                [r for r in records if r.attributes["prompt.id"] == turn]))
            assert len(text.encode()) < gitleaks.max_bytes

        after, _ = collect(records, [gitleaks], budget_ms=60_000, org_id="o",
                           policy=policy)
        before, _ = v045_collect.collect(records, [reference], budget_ms=60_000,
                                         org_id="o", policy=policy)

        assert _per_group(after) == _per_group(before), f"seed {seed}"
        exports += 1
        groups += len(after)
        findings += sum(len(r.findings) for r in after)
        keys += sum(f.detector == "gitleaks:private-key" for r in after for f in r.findings)
    assert exports == 50
    assert groups > 400
    assert findings > 1000
    assert keys > 50
