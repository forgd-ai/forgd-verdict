"""The JSON walk that turns a payload into ScanUnits.

Three evasions live in one function, and all three are the same shape:
text the sender controls reaching no detector at all.
"""

from __future__ import annotations

import json

import pytest
from conftest import FAKE_AWS_KEY, FAKE_SSN, UNPARSEABLE_DEPTH, nested_json

from forgd_verdict import extract
from forgd_verdict.extract import MAX_KEY_CHARS, frame_units, hook_units
from forgd_verdict.models import MAX_LOCATOR_CHARS, MAX_LOCATOR_SEGMENTS

# -- the JSON walk -------------------------------------------------------

AWS = "AKIAIOSFODNN7EXAMPLE"
ANT = "sk-ant-api03-" + "Z" * 40


def _frame(block):
    return frame_units([{"role": "user", "content": [block]}])


def _texts(units):
    return [u.text for u in units]


def test_a_value_under_a_nested_key_named_id_is_scanned():
    """`_SKIP_KEYS` applied to every dict, so anything under a key named
    `id` was never turned into a unit -- and `tool_result.content` is tool
    output the caller fully controls.

    Depth is the wrong test: `_strings` is called on `content`, so its
    depth 0 is already inside sender data.
    """
    units = _frame({"type": "tool_result",
                    "content": {"id": ANT, "name": "prod key"}})
    assert ANT in _texts(units)


def test_a_blocks_own_structural_fields_are_structural_units():
    """`tool_use_id` is a high-entropy identifier that would trip the
    entropy tier on every call, so its unit is marked for entropy to skip."""
    units = _frame({"type": "wholly-new-block-type",
                    "tool_use_id": "call_01ABCDEFGHIJKLMNOPQRS",
                    "text": "actual content"})
    by_text = {u.text: u for u in units}
    assert by_text["call_01ABCDEFGHIJKLMNOPQRS"].structural
    assert not by_text["actual content"].structural
    assert "wholly-new-block-type" not in by_text


def test_the_skip_does_not_reach_inside_the_block():
    """It names one block's own fields, not every dict underneath it."""
    units = _frame({"type": "wholly-new-block-type",
                    "payload": {"id": ANT}})
    assert ANT in _texts(units)


def test_nesting_past_the_depth_limit_is_serialised_not_dropped():
    """Nine levels around a key produced ZERO units -- not a truncated
    one, none -- and allowed. The caller's comment claimed the serialised
    whole was scanned; it was not."""
    deep = {"k": AWS}
    for _ in range(9):
        deep = {"n": deep}
    units = _frame({"type": "tool_use", "name": "t", "input": deep})
    assert units
    assert any(AWS in t for t in _texts(units))


def test_a_key_long_enough_to_be_a_credential_is_scanned():
    """`{"<AWS key>": "value"}` yielded one unit for the value and never
    looked at the name."""
    units = _frame({"type": "tool_use", "name": "t", "input": {AWS: "value here"}})
    assert AWS in _texts(units)


def test_ordinary_field_names_are_not_scanned_as_units():
    """A unit per field of every object would be noise. Only names long
    enough to be a credential."""
    units = _frame({"type": "tool_use", "name": "t",
                    "input": {"command": "ls -la", "cwd": "/tmp"}})
    assert "command" not in _texts(units)
    assert "cwd" not in _texts(units)
    assert len(units) == 2


def test_a_truncated_unit_says_so():
    """`_add` cut at MAX_UNIT_BYTES and recorded nothing -- no flag, no
    counter, no field on ScanResult -- so 4 MiB of padding followed by a
    key was 0 findings and an allow. `server.max_body_bytes` is 64 MiB."""
    from forgd_verdict.extract import MAX_UNIT_BYTES, TAIL_UNIT_BYTES

    big = "a" * (MAX_UNIT_BYTES * 2) + " AKIAIOSFODNN7EXAMPLE"
    units = _frame({"type": "text", "text": big})
    assert len(units) == 2
    head, tail = units
    assert head.truncated and not head.tail
    assert tail.truncated and tail.tail
    assert len(head.text) == MAX_UNIT_BYTES
    assert len(tail.text) == TAIL_UNIT_BYTES
    assert tail.text.endswith(AWS)
    assert tail.locator == head.locator + "#tail"


def test_a_value_within_head_and_tail_is_not_marked_truncated():
    from forgd_verdict.extract import MAX_UNIT_BYTES

    big = "a" * (MAX_UNIT_BYTES + 100) + " AKIAIOSFODNN7EXAMPLE"
    units = _frame({"type": "text", "text": big})
    assert len(units) == 2
    assert not any(u.truncated for u in units)
    assert units[0].text + units[1].text == big


def test_an_ordinary_unit_is_not_marked_truncated():
    units = _frame({"type": "text", "text": "a short message"})
    assert not units[0].truncated


def test_the_scan_result_carries_the_truncated_locators():
    from forgd_verdict.core import scan
    from forgd_verdict.extract import MAX_UNIT_BYTES
    from forgd_verdict.policy import load_policy

    big = "a" * (MAX_UNIT_BYTES * 2) + " AKIAIOSFODNN7EXAMPLE"
    units = _frame({"type": "text", "text": big})
    result = scan(units, load_policy("policy.yaml").build_detectors())
    assert result.truncated == [units[0].locator]


def test_a_truncated_locator_built_from_a_secret_key_is_scrubbed(caplog):
    """The warning logged `result.truncated` as raw unit locators, and a
    locator carries the sender's dict keys verbatim."""
    import logging

    from forgd_verdict.core import scan
    from forgd_verdict.extract import MAX_UNIT_BYTES
    from forgd_verdict.policy import load_policy

    units = frame_units([
        {"role": "user", "content": [
            {"type": "tool_result",
             "content": {AWS: "a" * (MAX_UNIT_BYTES * 2)}}]},
        {"role": "user", "content": [
            {"type": "text", "text": "b" * (MAX_UNIT_BYTES * 2)}]},
    ])
    cut = [u.locator for u in units if u.truncated and not u.tail]
    assert len(cut) == 2 and AWS in cut[0] and AWS not in cut[1]

    with caplog.at_level(logging.WARNING, logger="forgd_verdict.core"):
        result = scan(units, load_policy("policy.yaml").build_detectors())

    warned = [r for r in caplog.records if r.getMessage().startswith("value over the size limit")]
    assert len(warned) == 1
    fields = warned[0].fields
    assert fields["count"] == 2
    for shown in (repr(fields["locators"]), repr(result), repr(result.truncated)):
        assert AWS not in shown
        assert "<redacted>" in shown
    assert result.truncated[0].startswith("msg[0].content[0].content.<redacted>")
    assert result.truncated[1] == cut[1]
    assert fields["locators"] == result.truncated



# {"alg":"HS256","typ":"JWT"} . {"sub":"1234567890"} . sig -- three dot-joined
# parts, so splitting the locator on "." first hid it from every detector.
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
       ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
       ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")  # gitleaks:allow


def test_a_dotted_secret_key_is_scrubbed_from_truncated_and_finding_locators(caplog):
    """A JWT used as a dict key is matched only as a whole; every one of
    its dot-separated parts on its own matches nothing."""
    import logging

    from forgd_verdict.core import scan
    from forgd_verdict.extract import MAX_UNIT_BYTES
    from forgd_verdict.policy import load_policy

    units = frame_units([
        {"role": "user", "content": [
            {"type": "tool_result",
             "content": {JWT: "a" * (MAX_UNIT_BYTES * 2) + f" {AWS}"}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "content": {JWT: f"short value {AWS}"}}]},
    ])
    assert any(JWT in u.locator for u in units if u.truncated and not u.tail)

    with caplog.at_level(logging.WARNING, logger="forgd_verdict.core"):
        result = scan(units, load_policy("policy.yaml").build_detectors())

    assert result.findings, "the AWS value in the short unit must still be found"
    for f in result.findings:
        assert JWT not in f.locator and "eyJ" not in f.locator
    warned = [r for r in caplog.records if r.getMessage().startswith("value over the size limit")]
    assert warned
    for shown in (repr(warned[0].fields), repr(result.truncated), repr(result)):
        assert JWT not in shown and "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in shown
        assert "<redacted>" in shown



def test_a_prefixed_dotted_secret_key_is_scrubbed(caplog):
    """`send_<JWT>`: the word character before the JWT defeats its leading
    word boundary, so the run is probed with the same separator split a
    single segment gets."""
    import logging

    from forgd_verdict.core import scan
    from forgd_verdict.extract import MAX_UNIT_BYTES
    from forgd_verdict.policy import load_policy

    key = f"send_{JWT}"
    units = frame_units([
        {"role": "user", "content": [
            {"type": "tool_result", "content": {key: "a" * (MAX_UNIT_BYTES * 2)}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "content": {key: f"short value {AWS}"}}]},
    ])
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.core"):
        result = scan(units, load_policy("policy.yaml").build_detectors())
    assert result.findings
    for shown in ([f.locator for f in result.findings], result.truncated, caplog.text):
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in repr(shown)


def test_a_secret_with_many_dotted_parts_is_scrubbed():
    """No cap on run length below the segment limit: a detector whose format
    has more than eight dotted parts still has its whole span redacted."""
    import re as _re

    from forgd_verdict.core import _scrub_locator
    from forgd_verdict.models import Finding as _F

    class _Dots:
        name, tier = "dots", 0
        # fullmatch, not search: a detector need not match a string that
        # merely contains its token, which is what a whole-locator
        # pre-check wrongly assumed.
        pat = _re.compile(r"k(?:\.[a-z0-9]{2,}){10}")

        def scan(self, units):
            return [_F("dots", "warn", u.locator, "0" * 64) for u in units
                    if self.pat.fullmatch(u.text)]

    secret = "k." + ".".join(f"p{i:02d}" for i in range(10))
    out = _scrub_locator(f"msg[0].content.{secret}.tail", [_Dots()])
    assert secret not in out and "p05" not in out
    assert out.startswith("msg[0].content.<redacted>") and out.endswith(".tail")
    assert _scrub_locator("msg[0].content.plain.tail", [_Dots()]) == "msg[0].content.plain.tail"
    long = ".".join(f"s{i}" for i in range(70))
    assert _scrub_locator(long, [_Dots()]).startswith("<redacted>")


def test_a_locator_too_long_to_probe_in_one_bounded_call_is_redacted_whole():
    """Few segments but long ones: the windows would multiply the bytes sent
    to each detector, so past the length bound nothing is probed and the
    locator is redacted."""
    from forgd_verdict.core import MAX_LOCATOR_CHARS, _scrub_locator

    calls = []

    class _Count:
        name, tier = "count", 0

        def scan(self, units):
            calls.append(sum(len(u.text) for u in units))
            return []

    seg = "x" * 200
    loc = ".".join([seg] * 10)
    assert len(loc) > MAX_LOCATOR_CHARS
    assert _scrub_locator(loc, [_Count()]).startswith("<redacted>")
    assert calls == []
    ok = ".".join(["y" * 30] * 32)
    assert len(ok) <= MAX_LOCATOR_CHARS
    assert _scrub_locator(ok, [_Count()]) == ok
    assert calls and max(calls) < 200_000


def _counting_ssn_detector(calls):
    import re as _re

    from forgd_verdict.detectors.base import TIER_T1
    from forgd_verdict.models import Finding as _F

    pat = _re.compile(r"\d{3}-\d{2}-\d{4}")

    class _CountingSSN:
        name, tier = "counting_ssn", TIER_T1

        def scan(self, units):
            calls.append(len(units))
            return [_F(self.name, "block", u.locator, f"{u.locator}:{i}", u.tool_name)
                    for u in units for i, _ in enumerate(pat.finditer(u.text))]

    return _CountingSSN()


def _ssn(i):
    return f"{100 + i // 100:03d}-{10 + i % 90:02d}-{1000 + i:04d}"


@pytest.mark.parametrize("n", [50, 500])
def test_the_metadata_scrub_probes_once_per_detector_whatever_the_finding_count(n):
    """One heredoc of `n` SSNs, plus findings under several locators and tool
    names: the scrub of finding metadata makes one call per detector."""
    from forgd_verdict.core import scan
    from forgd_verdict.models import ScanUnit

    calls = []
    det = _counting_ssn_detector(calls)
    heredoc = "cat <<EOF\n" + "\n".join(_ssn(i) for i in range(n)) + "\nEOF"
    units = [ScanUnit(locator="tool_input.command", tool_name="run_shell_command",
                      text=heredoc)]
    units += [ScanUnit(locator=f"tool_input.files[{k}].content",
                       tool_name=f"write_file_number_{k:02d}", text=_ssn(k))
              for k in range(20)]
    units.append(ScanUnit(locator=f"tool_input.{_ssn(7)}.value",
                          tool_name=f"lookup_{_ssn(8)}", text=_ssn(9)))

    result = scan(units, [det])

    found = len(result.findings)
    assert found >= n + 21
    assert len(calls) == 2
    by_loc = {f.locator: f.tool_name for f in result.findings}
    assert by_loc["tool_input.command"] == "run_shell_command"
    assert by_loc["tool_input.files[3].content"] == "write_file_number_03"
    assert "tool_input.<redacted>.value" in by_loc
    assert by_loc["tool_input.<redacted>.value"] == "<redacted>"


def test_the_truncated_scrub_probes_once_per_detector_whatever_the_locator_count():
    from forgd_verdict.core import scan
    from forgd_verdict.models import ScanUnit

    calls = []
    det = _counting_ssn_detector(calls)
    units = [ScanUnit(locator=f"tool_input.files[{k}].build_output", tool_name=None,
                      text="plain", truncated=True) for k in range(40)]
    units.append(ScanUnit(locator=f"tool_input.{_ssn(1)}", tool_name=None,
                          text="plain", truncated=True))

    result = scan(units, [det])

    assert len(calls) == 2
    assert result.truncated[:2] == ["tool_input.files[0].build_output",
                                    "tool_input.files[1].build_output"]
    assert result.truncated[-1] == "tool_input.<redacted>"


# -- a known block type read only the fields it knew ---------------------


def test_a_sibling_field_on_a_known_block_is_scanned():
    """This inverted the intent stated at the top of `extract.py` -- an
    unrecognised block is where new exfiltration surface appears, so the
    `else` branch walked everything and the RECOGNISED types were the
    porous ones:

        {"type": "text", "text": "hi", "caption": "<key>"}   allow
        the byte-identical block labelled "wingding"         deny
    """
    units = _frame({"type": "text", "text": "hi", "caption": f"key {AWS}"})
    assert any(AWS in t for t in _texts(units))


def test_a_sibling_field_on_an_attachment_is_scanned():
    units = _frame({"type": "attachment", "text": "hi",
                    "file_name": "a.txt", "summary": f"key {AWS}"})
    assert any(AWS in t for t in _texts(units))


def test_an_unknown_block_type_is_still_walked():
    """The half that was already right."""
    units = _frame({"type": "wingding", "caption": f"key {AWS}"})
    assert any(AWS in t for t in _texts(units))


def test_a_known_block_with_no_extra_fields_gains_no_units():
    """Forward compatibility must not cost a unit per ordinary block."""
    units = _frame({"type": "text", "text": "just text"})
    assert len(units) == 1


def test_a_detector_failing_during_the_truncated_scrub_redacts_and_scan_returns():
    """A cheap built-in that raised `DetectorFailed` while probing a
    truncated locator propagated out of `scan()` before any detector ran."""
    from forgd_verdict.core import UNSCANNED, scan
    from forgd_verdict.detectors.base import TIER_T1, DetectorFailed
    from forgd_verdict.extract import MAX_UNIT_BYTES

    class _Broken:
        name = "broken_t1"
        tier = TIER_T1

        def scan(self, units):
            raise DetectorFailed("binary missing")

    units = _frame({"type": "tool_result",
                    "content": {"build_output": "a" * (MAX_UNIT_BYTES * 2)}})
    assert [u.locator for u in units if u.truncated and not u.tail] == [
        "msg[0].content[0].content.build_output"]

    result = scan(units, [_Broken()])

    assert result.detectors_skipped == [UNSCANNED, "broken_t1"]
    assert len(result.truncated) == 1
    segments = result.truncated[0].split(".")
    assert segments[0] == "msg[0]" and segments[2] == "content"
    assert segments[1].startswith("<redacted>") and segments[3].startswith("<redacted>")
    assert "build_output" not in result.truncated[0]


# -- numbers ---------------------------------------------------------------

PAN_INT = 4539148803436467  # Luhn-valid


def _walked(value):
    """{entry point: units} for each extractor that walks a JSON value."""
    from forgd_verdict.extract import (
        chat_units,
        compliance_units,
        hook_units,
        unknown_frame_units,
    )

    tool_use = {"type": "tool_use", "id": "t1", "name": "run", "input": {"card": value}}
    return {
        "frame tool_use input": frame_units([{"role": "assistant", "content": [tool_use]}]),
        "frame unknown block": frame_units(
            [{"role": "user", "content": [{"type": "wingding", "card": value}]}]),
        "frame text block extra field": frame_units(
            [{"role": "user", "content": [{"type": "text", "text": "hi", "card": value}]}]),
        "unknown frame": unknown_frame_units({"type": "novel", "card": value}),
        "hook tool_input": hook_units({"hook_event_name": "PreToolUse",
                                       "tool_name": "mcp__x__run",
                                       "tool_input": {"card": value}}),
        "hook tool_response": hook_units({"hook_event_name": "PostToolUse",
                                          "tool_name": "mcp__x__run",
                                          "tool_response": {"card": value}}),
        "compliance tool_use input string": compliance_units([{"role": "assistant", "content": [
            {**tool_use, "input": json.dumps({"card": value})}]}]),
        "compliance tool_use input bare": compliance_units([{"role": "assistant", "content": [
            {**tool_use, "input": json.dumps(value)}]}]),
        "chat block": chat_units({"chat_messages": [{"content": [tool_use]}]}),
    }


@pytest.mark.parametrize("value, text", [(PAN_INT, "4539148803436467"),
                                         (float(PAN_INT), "4539148803436467.0")],
                         ids=["int", "float"])
def test_a_json_number_is_scanned_as_its_text(value, text):
    for where, units in _walked(value).items():
        assert text in [u.text for u in units], where


@pytest.mark.parametrize("value", [True, False])
def test_a_json_bool_yields_no_unit(value):
    for where, units in _walked(value).items():
        assert not [u for u in units if u.text in ("True", "False", "true", "false")], where


def test_a_compliance_tool_input_nested_too_deeply_is_scanned_as_raw_text():
    from forgd_verdict.budget import Budget
    from forgd_verdict.core import scan
    from forgd_verdict.extract import compliance_units
    from forgd_verdict.policy import default_policy

    raw = nested_json(json.dumps({"cmd": f"deploy {FAKE_AWS_KEY}"}), UNPARSEABLE_DEPTH)
    units = compliance_units([{"role": "assistant", "content": [
        {"type": "tool_use", "id": "t1", "name": "run", "input": raw}]}])
    detectors = [d for d in default_policy().build_detectors() if d.tier == 0]
    findings = scan(units, detectors, Budget(5000)).findings
    assert any(f.detector == "regex:aws-access-key" for f in findings)


SHORT_PAN = "4532015112830"  # 13 digits, Luhn-valid


@pytest.mark.parametrize("key, detector", [(FAKE_SSN, "regex:ssn"), (SHORT_PAN, "regex:pan")],
                         ids=["ssn", "pan-13"])
def test_a_short_identifier_held_as_a_key_is_found_and_kept_out_of_the_locator(key, detector):
    from forgd_verdict.budget import Budget
    from forgd_verdict.core import scan
    from forgd_verdict.policy import default_policy

    units = _frame({"type": "tool_use", "name": "t", "input": {key: "x"}})
    assert key in _texts(units)
    findings = scan(units, default_policy().build_detectors(), Budget(5000)).findings
    assert detector in {f.detector for f in findings}
    for f in findings:
        assert key not in f.locator and key not in json.dumps(f.to_log())


def test_a_key_of_nine_characters_is_a_unit_and_eight_is_not():
    units = _frame({"type": "tool_use", "name": "t",
                    "input": {"abcdefghi": "x", "abcdefgh": "y"}})
    assert "abcdefghi" in _texts(units)
    assert "abcdefgh" not in _texts(units)


# -- bounds at extraction --------------------------------------------------


def _locators(units):
    return [u.locator for u in units]


def test_a_long_key_appears_in_locators_as_a_placeholder():
    long_key = "k" * (MAX_KEY_CHARS + 1)
    units = _frame({"type": "tool_use", "name": "t",
                    "input": {"short_key_1": "a", long_key: {"child": "b"}}})
    assert _locators(units) == [
        "msg[0].content[0].input.short_key_1#key",
        "msg[0].content[0].input.short_key_1",
        "msg[0].content[0].input.<key:1>#key",
        "msg[0].content[0].input.<key:1>.child",
    ]
    assert not any(long_key in loc for loc in _locators(units))


def test_a_long_key_unit_carries_the_whole_key():
    long_key = "k" * 100_000
    units = _frame({"type": "tool_use", "name": "t", "input": {long_key: "v"}})
    keyed = [u for u in units if u.locator.endswith("#key")]
    assert [u.text for u in keyed] == [long_key]


def test_a_key_at_the_limit_is_kept_in_the_locator():
    key = "k" * MAX_KEY_CHARS
    units = _frame({"type": "tool_use", "name": "t", "input": {key: "v"}})
    assert f"msg[0].content[0].input.{key}" in _locators(units)


def test_a_key_that_looks_like_a_placeholder_cannot_collide_with_one():
    units = _frame({"type": "tool_use", "name": "t",
                    "input": {"<key:1>": "a", "k" * 500: "b"}})
    plain = [loc for loc in _locators(units) if not loc.endswith("#key")]
    assert plain == ["msg[0].content[0].input.<key:0>",
                     "msg[0].content[0].input.<key:1>"]


def test_a_matched_long_key_never_reaches_a_locator():
    from forgd_verdict.core import scan
    from forgd_verdict.detectors.t0_regex import T0RegexDetector

    key = f"{AWS} " + "x" * 300
    units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": "ls", key: {"inner": "v"}}})
    result = scan(units, [T0RegexDetector()])
    assert result.findings
    assert all(AWS not in f.locator for f in result.findings)
    assert "tool_input.<key:1>#key" in [f.locator for f in result.findings]


def test_a_key_with_many_dots_is_a_placeholder():
    key = ".".join(["a"] * 40)
    units = _frame({"type": "tool_use", "name": "t", "input": {key: "v"}})
    assert "msg[0].content[0].input.<key:0>" in _locators(units)


def _segments(loc):
    return loc.count(".") + 1


@pytest.mark.parametrize("key", [
    "k" * 100,
    ".".join(["s"] * 15),
    ".".join(["seg_" + "x" * 20] * 5),
], ids=["long", "many-segments", "long-and-segmented"])
def test_locators_stay_within_both_caps_at_every_depth(key):
    node: object = {key: "leaf"}
    for i in range(12):
        node = {key: node, f"{key}{i}": [node, "x"]}
    units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {key: node}})
    assert units
    for u in units:
        assert len(u.locator) <= MAX_LOCATOR_CHARS, u.locator
        assert _segments(u.locator) <= MAX_LOCATOR_SEGMENTS, u.locator


def test_extraction_keeps_the_last_units_in_order_at_the_cap(monkeypatch):
    monkeypatch.setattr(extract, "MAX_SCAN_UNITS", 5)
    units = _frame({"type": "tool_use", "name": "t",
                    "input": {"items": [f"v{i}" for i in range(10)]}})
    assert _texts(units) == ["v5", "v6", "v7", "v8", "v9"]
    assert units.capped


def test_extraction_at_exactly_the_cap_is_not_capped(monkeypatch):
    monkeypatch.setattr(extract, "MAX_SCAN_UNITS", 5)
    units = _frame({"type": "tool_use", "name": "t",
                    "input": {"items": [f"v{i}" for i in range(5)]}})
    assert _texts(units) == [f"v{i}" for i in range(5)]
    assert not units.capped


def test_the_cap_is_kept_across_messages_blocks_and_keys(monkeypatch):
    messages = [
        {"role": "user", "content": [{"type": "text", "text": f"m{m}b{b}"}
                                     for b in range(3)]}
        for m in range(4)
    ]
    messages.append({"role": "assistant", "content": [
        {"type": "tool_use", "name": "t", "input": {"key_000001": "a", "key_000002": "b"}}]})
    whole = frame_units(messages)
    assert not whole.capped
    monkeypatch.setattr(extract, "MAX_SCAN_UNITS", 7)
    capped = frame_units(messages)
    assert capped.capped
    assert _locators(capped) == _locators(whole)[-7:]
    assert _texts(capped) == _texts(whole)[-7:]


def test_a_capped_extraction_is_recorded_as_unscanned_capped(monkeypatch):
    from forgd_verdict.core import scan
    from forgd_verdict.models import UNSCANNED_CAPPED

    monkeypatch.setattr(extract, "MAX_SCAN_UNITS", 3)
    units = hook_units({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": "ls", "a": "1", "b": "2", "c": "3"}})
    assert units.capped
    assert _texts(units) == ["2", "3", "ls"]
    assert UNSCANNED_CAPPED in scan(units, []).detectors_skipped


def test_otel_records_are_capped_keeping_the_last(monkeypatch):
    from forgd_verdict.otel import extract as otel_extract
    from forgd_verdict.otel.payload import OtelRecord

    monkeypatch.setattr(otel_extract, "MAX_SCAN_UNITS", 4)
    records = [OtelRecord(kind="log", name="claude_code.user_prompt",
                          attributes={"prompt": f"prompt number {i}"})
               for i in range(6)]
    units = otel_extract.records_units(records)
    assert units.capped
    assert _texts(units) == [f"prompt number {i}" for i in range(2, 6)]


def test_an_otel_long_attribute_key_and_name_are_placeholders():
    from forgd_verdict.otel.extract import record_units
    from forgd_verdict.otel.payload import OtelRecord

    rec = OtelRecord(kind="log", name="n" * 500,
                     attributes={"k" * 500: "a value long enough"})
    assert _locators(record_units(rec, 2)) == ["otel[2].<key:0>.<key:0>"]


def _reference_walk(value, prefix, depth=0):
    """Forward order, with the same locators: the walk's spec."""
    if isinstance(value, str):
        return [(prefix, value)] if value else []
    if isinstance(value, int | float) and not isinstance(value, bool):
        return [(prefix, str(value))]
    if not isinstance(value, dict | list):
        return []
    if depth >= extract.MAX_DEPTH:
        return [(prefix, json.dumps(value, ensure_ascii=False))]
    out = []
    if isinstance(value, dict):
        for i, (key, sub) in enumerate(value.items()):
            path = extract.locator_key(prefix, key, i)
            if len(key) >= extract.MIN_KEY_CHARS:
                out.append((f"{path}#key", key))
            out.extend(_reference_walk(sub, path, depth + 1))
    else:
        for i, sub in enumerate(value):
            out.extend(_reference_walk(sub, f"{prefix}[{i}]", depth + 1))
    return out


def test_the_walk_matches_a_forward_walk():
    import random

    rng = random.Random(357)
    keys = ["a", "key_number_one", "x.y.z", "k" * 200, "<key:0>", "", "id"]

    def gen(depth):
        roll = rng.random()
        if depth > 10 or roll < 0.3:
            return rng.choice(["s", "", 7, 2.5, True, None, "longer text"])
        if roll < 0.65:
            return {rng.choice(keys) + str(rng.randint(0, 3)): gen(depth + 1)
                    for _ in range(rng.randint(0, 4))}
        return [gen(depth + 1) for _ in range(rng.randint(0, 4))]

    for _ in range(500):
        value = gen(0)
        units = _frame({"type": "tool_use", "name": "t", "input": value})
        got = [(u.locator, u.text) for u in units]
        assert got == _reference_walk(value, "msg[0].content[0].input"), value


@pytest.mark.parametrize("empty", [{}, [], "", None, True, {"k": []}],
                         ids=["dict", "list", "string", "null", "bool", "nested"])
def test_empty_values_past_the_cap_do_not_cap(monkeypatch, empty):
    monkeypatch.setattr(extract, "MAX_SCAN_UNITS", 5)
    units = _frame({"type": "tool_use", "name": "t",
                    "input": {"a": empty, "items": [empty, *(f"v{i}" for i in range(5)), empty],
                              "z": empty}})
    assert _texts(units) == [f"v{i}" for i in range(5)]
    assert not units.capped


def test_one_real_unit_past_the_cap_caps(monkeypatch):
    monkeypatch.setattr(extract, "MAX_SCAN_UNITS", 5)
    units = _frame({"type": "tool_use", "name": "t",
                    "input": {"a": [], "first": "v0", "items": [f"v{i}" for i in range(1, 6)]}})
    assert _texts(units) == [f"v{i}" for i in range(1, 6)]
    assert units.capped


def test_empty_messages_and_records_past_the_cap_do_not_cap(monkeypatch):
    from forgd_verdict.otel import extract as otel_extract
    from forgd_verdict.otel.payload import OtelRecord

    monkeypatch.setattr(extract, "MAX_SCAN_UNITS", 2)
    messages = [{"role": "user", "content": []}, {"role": "user", "content": ""},
                {"role": "user", "content": [{"type": "text", "text": "a"},
                                             {"type": "text", "text": "b"}]}]
    assert not frame_units(messages).capped
    monkeypatch.setattr(otel_extract, "MAX_SCAN_UNITS", 2)
    records = [OtelRecord(kind="log", name="n", attributes={"prompt": "short"}),
               *(OtelRecord(kind="log", name="n", attributes={"prompt": f"prompt number {i}"})
                 for i in range(2))]
    units = otel_extract.records_units(records)
    assert len(units) == 2 and not units.capped


# -- adapter 3 shapes: every field is read or skipped by name ------------------

def _found(units) -> int:
    from forgd_verdict.core import scan
    from forgd_verdict.detectors.t0_regex import T0RegexDetector

    return len(scan(units, [T0RegexDetector()]).findings)


_S = f"token {FAKE_AWS_KEY} here"


@pytest.mark.parametrize("chat", [
    {"name": _S, "chat_messages": []},
    {"chat_messages": [{"text": _S, "content": []}]},
    {"chat_messages": [{"content": _S}]},
    {"chat_messages": [{"content": [_S]}]},
    {"chat_messages": [{"content": [{"type": "text", "text": "hi", "citations": [
        {"cited_text": _S}]}]}]},
    {"chat_messages": [{"content": [], "attachments": [
        {"file_name": "paste.txt", "extracted_content": _S}]}]},
    {"chat_messages": [{"content": [], "files": [{"file_name": _S}]}]},
    {"chat_messages": [{"content": [], "files": [{"filename": _S}]}]},
    {"chat_messages": [{"content": [], "artifacts": [{"id": "a", "title": "t", "content": _S}]}]},
    {"chat_messages": [_S]},
], ids=["name", "message-text", "string-content", "string-block", "text-sibling",
        "attachment", "file_name", "filename", "inline-artifact", "string-message"])
def test_chat_units_read_every_content_shape(chat):
    assert _found(extract.chat_units(chat)) == 1


@pytest.mark.parametrize("messages", [
    [{"role": "user", "content": _S}],
    [{"role": "user", "content": [_S]}],
    [{"role": "user", "content": {"text": _S}}],
], ids=["string-content", "string-block", "dict-content"])
def test_compliance_units_read_every_content_shape(messages):
    assert _found(extract.compliance_units(messages)) == 1


@pytest.mark.parametrize("seed", range(40))
def test_a_secret_under_any_unknown_chat_field_is_found(seed):
    """Standing: a field name the extractor has never seen, at the message,
    block or entry level, is scanned rather than skipped."""
    import random

    rng = random.Random(seed)
    name = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz_") for _ in range(rng.randint(3, 12)))
    if name in extract._CHAT_META or name in extract._CHAT_ITEM_SKIP or name == "content":
        name += "_x"
    where = seed % 3
    message: dict = {"role": "user", "content": [{"type": "text", "text": "hello"}]}
    if where == 0:
        message[name] = _S
    elif where == 1:
        message["content"][0][name] = _S
    else:
        message[name] = [{"id": "f1", name: _S}]
    assert _found(extract.chat_units({"chat_messages": [message]})) == 1, name


def test_chat_ids_and_timestamps_are_not_content_units():
    """An entry's `id` is a structural unit, which entropy does not read."""
    units = extract.chat_units({"chat_messages": [{
        "id": "m1", "uuid": "u1", "created_at": "2026-09-17T20:00:00Z", "role": "user",
        "content": [],
        "files": [{"id": "claude_file_1", "file_uuid": "u2", "filename": "creds.env",
                   "size_bytes": 12, "mime_type": "text/plain"}],
        "artifacts": [{"id": "a1", "version_id": "claude_artifact_version_1", "title": "t"}]}]})
    assert sorted(u.text for u in units if not u.structural) == ["creds.env", "t"]
