"""a seam finding whose own span is unusable is
ignored when another finding of the same detector and excerpt on that seam
has a span, so its sides come from the other occurrence."""

from __future__ import annotations

import json
import shutil

import pytest
from test_seam_identity import _content, _detectors, _redacted

pytestmark = pytest.mark.skipif(not shutil.which("gitleaks"),
                                reason="gitleaks binary not installed")

S = "Zx9Qw3Rt7Yp2Lm5Kv8Hj"          # synthetic generic-api-key value
H = "00000000-1111-2222-3333-444444444444"  # patterned heroku-api-key value


def test_generic_key_right_fragment_beside_multiline_crossing_is_masked():
    event = _redacted(_content(f"api_key = {S} and api_key =\n{S[:8]}",
                               f"{S[8:]} more text"))
    assert S[8:] not in json.dumps(event.attributes), event.attributes


def test_heroku_key_right_fragment_beside_multiline_crossing_is_masked():
    event = _redacted(_content(f"heroku_key = {H} also heroku_key =\n{H[:10]}",
                               f"{H[10:]} more"))
    assert H[10:] not in json.dumps(event.attributes), event.attributes


def test_identity_right_fragment_beside_multiline_crossing_is_masked():
    from test_seam_identity import _record
    from test_seam_sides_leak import _out
    forwarded, stored, _ = _out(_record(f"heroku_key = {H} also heroku_key =\n{H[:10]}",
                                        f"{H[10:]} more"))
    assert H[10:] not in forwarded, forwarded
    assert H[10:] not in stored, stored


def test_key_path_right_fragment_beside_multiline_crossing_stays_off_locators():
    """Same root cause in `_crossings`: the right half of the split secret is
    a JSON key, and a finding under that key keeps it in its locator."""
    from forgd_verdict.budget import Budget
    from forgd_verdict.core import scan
    from forgd_verdict.extract import frame_units

    T = "shpat_" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    inp = {"a": f"api_key = {S} and api_key =\n{S[:8]}", S[8:]: f"see {T}"}
    msgs = [{"role": "user", "content": "hi"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1",
                                               "name": "Bash", "input": inp}]}]
    result = scan(frame_units(msgs), _detectors(), Budget(60_000))
    locators = [f.to_log()["locator"] for f in result.findings]
    assert not any(S[8:] in loc for loc in locators), locators
