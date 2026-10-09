"""A token split across a seam is masked on both sides even when one side
also holds the whole token, and a value holding no part of it is unchanged."""

from __future__ import annotations

import json
import shutil

import pytest
from test_seam_identity import _content, _detectors, _record, _redacted

from forgd_verdict.otel.collect import collect

pytestmark = pytest.mark.skipif(not shutil.which("gitleaks"),
                                reason="gitleaks binary not installed")

T = "shpat_" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"
SESSION = "sess-abcdefgh-01"
CLEAN = "request-plain-01"
CUTS = (10, 19, 30)
# A cut the bare split yields no finding at, but whose right side holds
# the whole token.
LEFT_CUTS = (*CUTS, 37)
# At these cuts neither side nor the seam yields a finding.
NO_FINDING_CUTS = (3, 6)


STORED_FINDING_FIELDS = {"detector", "severity", "locator", "excerpt_hash", "tool_name"}


def _out(record):
    """(forwarded attributes as JSON, stored record as JSON, forwarded
    attributes), after checking no stored finding carries a span."""
    event = _redacted(record)
    (stored,), _ = collect([record], _detectors(), budget_ms=60_000, salt="x", org_id="o")
    stored_json = stored.to_json()
    for finding in json.loads(stored_json)["findings"]:
        assert set(finding) == STORED_FINDING_FIELDS
    return json.dumps(event.attributes), stored_json, event.attributes


def _assert_absent(fragment, record):
    forwarded, stored, _ = _out(record)
    assert fragment not in forwarded
    assert fragment not in stored


@pytest.mark.parametrize("cut", LEFT_CUTS)
def test_a_left_fragment_beside_a_right_fragment_and_whole_token_is_masked(cut):
    _assert_absent(T[:cut], _record(T[:cut], f"{T[cut:]} {T}"))


@pytest.mark.parametrize("cut", LEFT_CUTS)
def test_a_left_content_fragment_beside_a_right_fragment_and_whole_token_is_masked(cut):
    _assert_absent(T[:cut], _content(f"see {T[:cut]}", f"{T[cut:]} {T}"))


@pytest.mark.parametrize("cut", CUTS)
def test_a_right_fragment_beside_a_whole_token_and_left_fragment_is_masked(cut):
    _assert_absent(T[cut:], _record(f"{T} {T[:cut]}", T[cut:]))


@pytest.mark.parametrize("cut", CUTS)
def test_a_right_content_fragment_beside_a_whole_token_and_left_fragment_is_masked(cut):
    _assert_absent(T[cut:], _content(f"see {T} {T[:cut]}", f"{T[cut:]} ok"))


@pytest.mark.parametrize("cut", NO_FINDING_CUTS)
@pytest.mark.xfail(strict=True, reason=(
    "the left value is under MIN_SCAN_CHARS, so it is no scan unit and no seam "
    "joins it to the right: it goes out raw"))
def test_a_short_left_fragment_beside_a_right_fragment_and_whole_token_is_masked(cut):
    _assert_absent(T[:cut], _record(T[:cut], f"{T[cut:]} {T}"))


@pytest.mark.xfail(strict=True, reason=(
    "the right value is the secret's whole 32-hex body, a _PLAIN_IDENTITY, and the "
    "left is under MIN_SCAN_CHARS: neither value becomes a scan unit, so the body "
    "goes out raw"))
def test_an_identity_split_after_the_prefix_is_masked():
    _assert_absent(T[6:], _record(T[:6], T[6:]))


@pytest.mark.xfail(strict=True, reason=(
    "the left value is under MIN_SCAN_CHARS, so it is no scan unit and no seam "
    "joins it to the right, the secret's whole 32-hex body, which goes out raw"))
def test_a_content_split_after_the_prefix_is_masked():
    _assert_absent(T[6:], _content(T[:6], T[6:]))


@pytest.mark.xfail(strict=True, reason=(
    "the left value is under MIN_SCAN_CHARS, so it is no scan unit and no seam "
    "joins it to the right: the right fragment goes out beside the masked whole token"))
def test_a_right_content_fragment_beside_a_short_left_fragment_is_masked():
    _assert_absent(T[3:], _content(f"see {T[:3]}", f"{T[3:]} {T}"))


def test_a_content_prefix_beside_the_body_and_whole_token_is_masked():
    _assert_absent(T[:6], _content(f"see {T[:6]}", f"{T[6:]} {T}"))
    _assert_absent(T[6:], _content(f"see {T[:6]}", f"{T[6:]} {T}"))


def test_a_clean_session_beside_a_token_is_unchanged():
    record = _record(SESSION, T)
    forwarded, stored, attributes = _out(record)
    assert attributes["session.id"] == SESSION
    assert json.loads(stored)["session_id"] == SESSION
    assert T not in forwarded and T not in stored


def test_a_token_in_the_session_masks_only_the_session():
    forwarded, stored, attributes = _out(_record(T, CLEAN))
    assert attributes["request_id"] == CLEAN
    assert T not in forwarded and T not in stored


def test_a_token_in_the_request_id_masks_only_the_request_id():
    forwarded, stored, attributes = _out(_record(SESSION, T))
    assert attributes["session.id"] == SESSION
    assert attributes["request_id"].startswith("[redacted:")
    assert T not in forwarded and T not in stored


def test_a_token_in_one_content_value_masks_only_that_value():
    clean = "plain words only here"
    forwarded, _, attributes = _out(_content(f"use {T} please", clean))
    assert attributes["response"] == clean
    assert T not in forwarded
    forwarded, _, attributes = _out(_content(clean, f"use {T} please"))
    assert attributes["prompt"] == clean
    assert T not in forwarded
