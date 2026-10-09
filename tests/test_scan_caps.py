"""`scan` scans at most MAX_SCAN_UNITS units and keeps at most
MAX_SCAN_FINDINGS findings, and records what it did not look at."""

from __future__ import annotations

import base64
import logging

import pytest
from conftest import FAKE_AWS_KEY, make_policy

from forgd_verdict import core
from forgd_verdict.core import MAX_SCAN_FINDINGS, MAX_SCAN_UNITS, _decoded, decide, scan
from forgd_verdict.models import FINDINGS_CAPPED, UNSCANNED_CAPPED, Finding, ScanUnit
from forgd_verdict.policy import load_policy

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _aws_key(i: int) -> str:
    return "AKIA" + "".join(_B32[(i >> (5 * j)) & 31] for j in range(16))


def _t0():
    return [d for d in load_policy("policy.yaml").build_detectors(salt="s" * 32)
            if d.tier == 0]


def _benign(n: int) -> list[ScanUnit]:
    return [ScanUnit(locator=f"$.f{i}", tool_name="t",
                     text=f"some ordinary prose value number {i} here")
            for i in range(n)]


def test_units_over_the_cap_are_not_scanned_and_are_recorded(caplog):
    # The earliest units go: in a cumulative transcript the newest are last.
    units = [ScanUnit(locator="$.first", tool_name="t", text=f"key {FAKE_AWS_KEY}")]
    units.extend(_benign(MAX_SCAN_UNITS))
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.core"):
        result = scan(units, _t0())
    assert UNSCANNED_CAPPED in result.detectors_skipped
    assert result.findings == []
    assert FAKE_AWS_KEY not in caplog.text
    assert "too many units" in caplog.text


@pytest.mark.parametrize("where", ["first", "last"])
def test_units_at_the_cap_are_all_scanned(where):
    units = _benign(MAX_SCAN_UNITS - 1)
    units.insert(0 if where == "first" else len(units),
                 ScanUnit(locator=f"$.{where}", tool_name="t", text=f"key {FAKE_AWS_KEY}"))
    result = scan(units, _t0())
    assert UNSCANNED_CAPPED not in result.detectors_skipped
    assert any(f.locator == f"$.{where}" for f in result.findings)


def test_the_newest_units_are_scanned_when_over_the_cap():
    units = _benign(MAX_SCAN_UNITS)
    units.append(ScanUnit(locator="$.newest", tool_name="t", text=f"key {FAKE_AWS_KEY}"))
    result = scan(units, _t0())
    assert UNSCANNED_CAPPED in result.detectors_skipped
    assert any(f.locator == "$.newest" for f in result.findings)


def test_findings_past_the_cap_are_dropped_and_recorded(caplog):
    n = MAX_SCAN_FINDINGS + 100
    units = [ScanUnit(locator=f"$.f{i}", tool_name="t", text=f"key {_aws_key(i)}")
             for i in range(n)]
    detectors = _t0()
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.core"):
        result = scan(units, detectors)
    assert len(result.findings) <= MAX_SCAN_FINDINGS
    assert "too many findings" in caplog.text
    assert "AKIA" not in caplog.text
    assert result.detectors_run == [d.name for d in detectors]
    assert result.detectors_skipped == [FINDINGS_CAPPED]


class _Fake:
    """Reports a warn finding per unit, then one block finding last."""
    name = "fake"
    tier = 0

    def __init__(self, severity_last="block"):
        self.severity_last = severity_last

    def scan(self, units):
        out = [Finding("fake:warn", "warn", u.locator, f"h{i}")
               for i, u in enumerate(units)]
        out.append(Finding("fake:block", self.severity_last, units[-1].locator, "hb"))
        return out


def test_a_block_finding_is_kept_ahead_of_the_rest(monkeypatch):
    monkeypatch.setattr(core, "MAX_SCAN_FINDINGS", 5)
    result = scan(_benign(20), [_Fake()])
    assert result.detectors_skipped == [FINDINGS_CAPPED]
    assert any(f.detector == "fake:block" for f in result.findings)
    assert len(result.findings) <= 5


@pytest.mark.parametrize("on_tier_dropped", ["deny", "allow"])
def test_a_capped_scan_denies_under_either_on_tier_dropped(on_tier_dropped):
    units = _benign(MAX_SCAN_UNITS + 1)
    result = scan(units, _t0())
    policy = make_policy(server={"on_tier_dropped": on_tier_dropped})
    verdict = decide(result.findings, policy, dropped=result.detectors_skipped)
    assert verdict.action == "deny"
    assert "size limit" in verdict.deny_reason


class _Counting:
    """A detector that records the units of every call to it."""

    def __init__(self, inner):
        self.inner = inner
        self.name = inner.name
        self.tier = inner.tier
        self.calls: list[list[ScanUnit]] = []

    def scan(self, units):
        units = list(units)
        self.calls.append(units)
        return self.inner.scan(units)


def _counted_scan(units: list[ScanUnit]):
    detectors = [_Counting(d) for d in _t0()]
    return scan(units, detectors), detectors


def _assert_bounded_work(detectors) -> None:
    """Each detector's first call is the scan, and every later one a
    locator scrub probe. The scan sees at most MAX_SCAN_UNITS units, decoded
    ones included, and at most two seams per unit, whose text is at most
    four times that of the units; the probes see at most the scrub budget."""
    for det in detectors:
        scanned, *probes = det.calls
        seams = [u for u in scanned if core._SEAM_SUFFIX in u.locator]
        rest = len(scanned) - len(seams)
        assert rest <= MAX_SCAN_UNITS, det.name
        assert len(seams) < 2 * max(rest, 1), det.name
        seam_text = sum(len(u.text) for u in seams)
        assert seam_text <= 4 * (sum(len(u.text) for u in scanned) - seam_text), det.name
        probed = sum(len(u.text.encode()) for call in probes for u in call)
        assert probed <= core._SCRUB_BUDGET_BYTES, det.name


def test_a_scan_at_the_unit_cap_is_bounded():
    result, detectors = _counted_scan(_benign(MAX_SCAN_UNITS))
    assert UNSCANNED_CAPPED not in result.detectors_skipped
    _assert_bounded_work(detectors)
    assert all(len(d.calls[0]) >= MAX_SCAN_UNITS for d in detectors)


def _turns(n: int) -> list[dict]:
    """`n` turns of a coding session, four units each."""
    out = []
    for i in range(n):
        out.append({"role": "user", "content": [{"type": "text", "text":
                    f"Can you look at the parser in module {i}? It fails on trailing commas."}]})
        out.append({"role": "assistant", "content": [
            {"type": "text", "text": f"Reading src/parser_{i}.py to check the commas."},
            {"type": "tool_use", "id": f"toolu_{i}", "name": "Read",
             "input": {"file_path": f"src/parser_{i}.py"}}]})
    return out


def test_a_long_session_on_a_cache_miss_is_scanned_in_full_and_cached():
    # A frame over the unit cap is never cached, so every later frame of
    # the session would rescan it from the start and hit the cap again.
    from forgd_verdict.budget import Budget
    from forgd_verdict.cache import InMemoryLRUCache
    from forgd_verdict.core import scan_frame
    from forgd_verdict.extract import frame_units

    messages = _turns(6_500)
    assert len(frame_units(messages)) > 20_000
    cache, key = InMemoryLRUCache(), ("org", "session")
    detectors = _t0()
    first = scan_frame(messages, frame_units, detectors, Budget(60_000), cache, key)
    assert first.detectors_skipped == []
    messages.append({"role": "user", "content": [{"type": "text", "text": "and module 9?"}]})
    second = scan_frame(messages, frame_units, detectors, Budget(60_000), cache, key)
    assert second.cache_hit


def test_a_scan_at_both_caps_is_bounded():
    units = [ScanUnit(locator=f"$.f{i}", tool_name="t", text=f"key {_aws_key(i)}")
             for i in range(MAX_SCAN_UNITS * 2)]
    result, detectors = _counted_scan(units)
    assert UNSCANNED_CAPPED in result.detectors_skipped
    _assert_bounded_work(detectors)
    assert len(result.findings) <= MAX_SCAN_FINDINGS


class _Warns:
    """An early tier that reports a warn finding per unit."""
    name = "warns"
    tier = 0

    def scan(self, units):
        return [Finding("warns:thing", "warn", u.locator, f"w{i}")
                for i, u in enumerate(units)]


class _Blocks:
    """A later tier that reports one block finding."""
    name = "blocks"
    tier = 1

    def scan(self, units):
        return [Finding("blocks:secret", "block", units[0].locator, "b")]


def test_warn_findings_cannot_crowd_out_a_later_block_finding(monkeypatch):
    monkeypatch.setattr(core, "MAX_SCAN_FINDINGS", 50)
    result = scan(_benign(200), [_Warns(), _Blocks()])
    assert result.detectors_run == ["warns", "blocks"]
    assert any(f.detector == "blocks:secret" for f in result.findings)
    assert len(result.findings) <= 50
    assert result.detectors_skipped == [FINDINGS_CAPPED]
    verdict = decide(result.findings, make_policy(), dropped=result.detectors_skipped)
    assert verdict.action == "deny"


# --- decoded base64 units ---------------------------------------------------


def _runs(*texts: str) -> str:
    """Base64 runs, separated by spaces, that decode to `texts`."""
    return " ".join(base64.b64encode(t.encode()).decode() for t in texts)


def _plain(i: int) -> str:
    return f"plain printable decoded text {i:04d}"


def _encoded(locator: str, *texts: str) -> ScanUnit:
    return ScanUnit(locator=locator, tool_name="t", text=_runs(*texts))


def test_decoded_units_up_to_the_room_are_all_built():
    units = [_encoded("$.a", _plain(0), _plain(1)), _encoded("$.b", _plain(2))]
    decoded, over = _decoded(units, 3)
    assert not over
    assert [u.text for u in decoded] == [_plain(0), _plain(1), _plain(2)]


def test_one_decoded_unit_past_the_room_is_dropped_and_reported():
    units = [_encoded("$.a", _plain(0), _plain(1)), _encoded("$.b", _plain(2))]
    decoded, over = _decoded(units, 2)
    assert over
    # The last unit's runs are kept; the earliest unit gives up its last run.
    assert [u.text for u in decoded] == [_plain(0), _plain(2)]


def test_text_with_nothing_to_decode_past_the_room_is_not_reported():
    units = [ScanUnit(locator="$.a", tool_name="t", text="no base64 here " * 20),
             _encoded("$.b", _plain(0))]
    assert _decoded(units, 1) == (_decoded(units, 5)[0], False)
    assert _decoded([units[0]], 0) == ([], False)


def test_decoding_stops_at_the_room():
    many = _encoded("$.a", *(_plain(i) for i in range(1000)))
    decoded, over = _decoded([many], 10)
    assert over
    assert [u.text for u in decoded] == [_plain(i) for i in range(10)]


def test_units_decoded_from_one_source_share_its_locator():
    decoded, _ = _decoded([_encoded("$." + "k" * 500, _plain(0), _plain(1), _plain(2))], 10)
    assert decoded[0].locator == "$." + "k" * 500 + "#b64"
    assert all(u.locator is decoded[0].locator for u in decoded)


def _encoded_last(n: int) -> list[ScanUnit]:
    """`n` units, the last of which decodes to a key."""
    return _benign(n - 1) + [_encoded("$.enc", f"key {FAKE_AWS_KEY}")]


def test_decoded_units_that_fill_the_cap_exactly_are_not_reported(monkeypatch):
    monkeypatch.setattr(core, "MAX_SCAN_UNITS", 10)
    result = scan(_encoded_last(9), _t0())
    assert UNSCANNED_CAPPED not in result.detectors_skipped
    assert any(f.locator.startswith("$.enc") for f in result.findings)


@pytest.mark.parametrize("on_tier_dropped", ["deny", "allow"])
def test_a_decoded_unit_past_the_cap_is_reported(monkeypatch, caplog, on_tier_dropped):
    # 10 units leave no room, and the key is the one decoded unit past it.
    monkeypatch.setattr(core, "MAX_SCAN_UNITS", 10)
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.core"):
        result = scan(_encoded_last(10), _t0())
    assert result.detectors_skipped.count(UNSCANNED_CAPPED) == 1
    assert FINDINGS_CAPPED not in result.detectors_skipped
    assert not any(f.locator.startswith("$.enc") for f in result.findings)
    assert any("decoded" in r.getMessage() for r in caplog.records)
    policy = make_policy(server={"on_tier_dropped": on_tier_dropped})
    verdict = decide(result.findings, policy, dropped=result.detectors_skipped)
    assert verdict.action == "deny"


def test_decoding_past_an_extraction_cap_records_it_once(monkeypatch):
    monkeypatch.setattr(core, "MAX_SCAN_UNITS", 10)
    result = scan(_encoded_last(11), _t0())
    assert result.detectors_skipped.count(UNSCANNED_CAPPED) == 1
