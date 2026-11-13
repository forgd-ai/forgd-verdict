"""GitHub tokens in both formats are found, and found to their last character.

GitHub App installation tokens (`ghs_`) moved to a stateless format: three
dot-separated base64url segments, about 520 characters. A rule that takes
only letters and digits after the prefix either misses one, when the first
segment is short, or matches its first segment and leaves the signature for
a redacting sink to forward.

Every value here is synthetic and built by concatenation.
"""

from __future__ import annotations

import base64
import json

import pytest

from forgd_verdict.detectors.gitleaks import GitleaksDetector
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.models import Finding, ScanUnit
from forgd_verdict.otel.payload import OtelRecord
from forgd_verdict.sink.base import SinkConfig
from forgd_verdict.sink.redact import RedactionPlan, redact_events


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _segment(obj: dict) -> str:
    return _b64(json.dumps(obj, separators=(",", ":")).encode())


# 256 bytes whose base64url carries both `-` and `_`.
SIGNATURE = _b64(bytes(range(256)))
PAYLOAD = _segment({"iss": "app", "exp": 1, "inst": 123456, "repo": "contents:read"})

# Header segments of 20, 36 and 51 characters: shorter than, equal to and
# longer than the 36 characters the classic rule needs before the first dot.
HEADERS = {
    "short": _segment({"alg": "ES256"}),
    "36": _segment({"alg": "RS256", "typ": "JWT"}),
    "long": _segment({"typ": "JWT", "alg": "RS256", "kid": "k1"}),
}


def _stateless(prefix: str, header: str) -> str:
    return "gh" + prefix + "_" + header + "." + PAYLOAD + "." + SIGNATURE


CLASSIC = {p: "gh" + p + "_" + "A1b2C3d4E5" * 3 + "F6g7H8" for p in "pousr"}

# What follows a token in prose, a quoted value, a list and a log line.
AFTER = [". Done", "", "\nnext", '"', ", then", " end"]


def _t0_spans(text: str) -> list[str]:
    found = T0RegexDetector().scan([ScanUnit("t", None, text)])
    return [text[f.start:f.end] for f in found if f.detector == "regex:github-token"]


assert all(len(_stateless("s", h)) > 400 for h in HEADERS.values())
assert len(HEADERS["short"]) == 20 and len(HEADERS["36"]) == 36
assert "-" in SIGNATURE and "_" in SIGNATURE


@pytest.mark.parametrize("prefix", ["s", "u"])
@pytest.mark.parametrize("header", HEADERS)
@pytest.mark.parametrize("after", AFTER)
def test_a_stateless_token_is_matched_to_its_last_character(prefix, header, after):
    token = _stateless(prefix, HEADERS[header])
    assert _t0_spans(f"token: {token}{after}") == [token]


@pytest.mark.parametrize("prefix", "pousr")
@pytest.mark.parametrize("after", AFTER)
def test_a_classic_token_still_matches_exactly(prefix, after):
    token = CLASSIC[prefix]
    assert _t0_spans(f"token: {token}{after}") == [token]


@pytest.mark.parametrize("text", [
    "ghs_config.yaml.bak",
    "see ghs_abc.defghijk.lmnopqrs",
    "ghu_" + "a" * 8 + "." + "b" * 8,
    "ghp_" + "a" * 20 + "." + "b" * 20 + "." + "c" * 20,
])
def test_short_or_two_segment_text_after_a_prefix_is_clean(text):
    assert _t0_spans(text) == []


def test_a_redacting_sink_forwards_none_of_a_stateless_token():
    token = _stateless("s", HEADERS["short"])
    text = f"use {token}. Thanks"
    loc = "otel[0].agent.query.user.message"
    rec = OtelRecord(kind="span", name="agent.query", attributes={"user.message": text})
    t0 = T0RegexDetector()
    found = {loc: [f for f in t0.scan([ScanUnit(loc, None, text)])
                   if f.detector == "regex:github-token"]}
    assert len(found[loc]) == 1
    cfg = SinkConfig(name="s", endpoint="https://collector.test",
                     redact=["regex:github-token"])
    plan = RedactionPlan.build(cfg, ["regex:github-token"])
    out = redact_events([rec], found, plan, cfg, surface="s", org="o",
                        observed_at="t", detectors=[t0])
    msg = out[0].attributes["user.message"]
    assert msg == "use [redacted:regex:github-token]. Thanks"
    assert PAYLOAD not in msg and SIGNATURE[-40:] not in msg


@pytest.mark.parametrize("header", HEADERS)
def test_gitleaks_matches_a_stateless_token_to_its_last_character(header):
    gitleaks = GitleaksDetector()
    if not gitleaks.available():
        pytest.skip("gitleaks is not installed")
    token = _stateless("s", HEADERS[header])
    text = f"token: {token}. Done"
    found: list[Finding] = gitleaks.scan([ScanUnit("t", None, text)])
    assert [(f.detector, text[f.start:f.end]) for f in found] == [
        ("gitleaks:github-app-token", token)]
