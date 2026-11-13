"""GitHub tokens in both formats are found, and found to their last character.

GitHub App installation tokens moved to a stateless format, `ghs_<app
id>_<JWT>`, about 520 characters. A rule that takes only letters and digits
after the prefix either misses one, when the JWT header is short, or matches
up to the first dot and leaves the payload and signature for a redacting sink
to forward.

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


APP_IDS = {"app id": "123456" + "_", "no app id": ""}


def _stateless(header: str, app_id: str = APP_IDS["app id"]) -> str:
    return "gh" + "s_" + app_id + header + "." + PAYLOAD + "." + SIGNATURE


CLASSIC = {p: "gh" + p + "_" + "A1b2C3d4E5" * 3 + "F6g7H8" for p in "pousr"}

# What follows a token in prose, a quoted value, a list and a log line.
AFTER = [". Done", "", "\nnext", '"', ", then", " end"]


def _t0_spans(text: str) -> list[str]:
    found = T0RegexDetector().scan([ScanUnit("t", None, text)])
    return [text[f.start:f.end] for f in found if f.detector == "regex:github-token"]


assert all(len(_stateless(h)) > 400 for h in HEADERS.values())
assert len(HEADERS["short"]) == 20 and len(HEADERS["36"]) == 36
assert "-" in SIGNATURE and "_" in SIGNATURE


@pytest.mark.parametrize("app_id", APP_IDS)
@pytest.mark.parametrize("header", HEADERS)
@pytest.mark.parametrize("after", AFTER)
def test_a_stateless_token_is_matched_to_its_last_character(app_id, header, after):
    token = _stateless(HEADERS[header], APP_IDS[app_id])
    assert _t0_spans(f"token: {token}{after}") == [token]


@pytest.mark.parametrize("app_id", APP_IDS)
def test_a_stateless_token_is_one_finding_and_not_also_a_jwt(app_id):
    token = _stateless(HEADERS["36"], APP_IDS[app_id])
    text = f"token: {token}. Done"
    t0 = T0RegexDetector()
    found = t0.scan([ScanUnit("t", None, text)])
    assert [(f.detector, text[f.start:f.end]) for f in found] == [
        ("regex:github-token", token)]
    assert list(t0.matches([ScanUnit("t", None, text)])) == [("regex:github-token", token)]


def test_a_jwt_outside_a_github_token_is_still_reported():
    jwt = HEADERS["36"] + "." + PAYLOAD + "." + SIGNATURE
    text = f"{_stateless(HEADERS['36'])} and {jwt}"
    found = T0RegexDetector().scan([ScanUnit("t", None, text)])
    assert sorted(f.detector for f in found) == ["regex:github-token", "regex:jwt"]
    (j,) = [f for f in found if f.detector == "regex:jwt"]
    assert text[j.start:j.end] == jwt


@pytest.mark.parametrize("prefix", "pousr")
@pytest.mark.parametrize("after", AFTER)
def test_a_classic_token_still_matches_exactly(prefix, after):
    token = CLASSIC[prefix]
    assert _t0_spans(f"token: {token}{after}") == [token]


@pytest.mark.parametrize("text", [
    "ghs_config.yaml.bak",
    "see ghs_abc.defghijk.lmnopqrs",
    "ghs_abcdefgh.ijklmnop.qrstuvwx",
    "ghs_123456_abcdefgh.ijklmnop.qrstuvwx",
    "ghu_" + "a" * 8 + "." + "b" * 8,
    "ghp_" + "a" * 20 + "." + "b" * 20 + "." + "c" * 20,
])
def test_dotted_text_after_a_prefix_is_clean(text):
    assert _t0_spans(text) == []


@pytest.mark.parametrize("prefix", "pousr")
def test_a_classic_token_does_not_take_a_dotted_suffix(prefix):
    token = CLASSIC[prefix]
    assert _t0_spans(f"{token}.release01.archive02") == [token]


@pytest.mark.parametrize("prefix", "pour")
def test_only_an_installation_token_has_a_stateless_form(prefix):
    text = "gh" + prefix + "_123456_" + HEADERS["36"] + "." + PAYLOAD + "." + SIGNATURE
    assert _t0_spans(text) == []


def test_a_redacting_sink_forwards_none_of_a_stateless_token():
    token = _stateless(HEADERS["short"])
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


def _gitleaks() -> GitleaksDetector:
    gitleaks = GitleaksDetector()
    if not gitleaks.available():
        pytest.skip("gitleaks is not installed")
    return gitleaks


def _gitleaks_hits(text: str) -> list[tuple[str, str]]:
    found: list[Finding] = _gitleaks().scan([ScanUnit("t", None, text)])
    return [(f.detector, text[f.start:f.end]) for f in found]


@pytest.mark.parametrize("app_id", APP_IDS)
@pytest.mark.parametrize("header", HEADERS)
def test_gitleaks_matches_a_stateless_token_to_its_last_character(app_id, header):
    token = _stateless(HEADERS[header], APP_IDS[app_id])
    assert _gitleaks_hits(f"token: {token}. Done") == [("gitleaks:github-app-token", token)]


@pytest.mark.parametrize("text", [
    "ghs_abcdefgh.ijklmnop.qrstuvwx",
    "ghu_123456_" + HEADERS["36"] + "." + PAYLOAD + ".abcdefgh",
])
def test_gitleaks_leaves_dotted_text_after_a_prefix(text):
    assert [d for d, _ in _gitleaks_hits(text) if d == "gitleaks:github-app-token"] == []


def test_gitleaks_does_not_extend_a_classic_token_over_a_dotted_suffix():
    token = "gh" + "s_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"
    assert _gitleaks_hits(f"{token}.release01.archive02") == [
        ("gitleaks:github-app-token", token)]


# A classic installation token whose first characters happen to be `eyJ`,
# then a dotted name: the header does not decode, so it is not stateless.
EYJ_CLASSIC = "gh" + "s_" + "eyJAb3Def5Ghi7Jkl9Mno2Pqr4Stu6Vwx8Yz"
DOTTED_SUFFIX = ".release01.archive02"


def test_a_classic_token_starting_eyj_does_not_take_a_dotted_suffix():
    assert _t0_spans(f"{EYJ_CLASSIC}{DOTTED_SUFFIX} next") == [EYJ_CLASSIC]


def test_gitleaks_trims_a_classic_token_starting_eyj_to_its_classic_span():
    assert _gitleaks_hits(f"{EYJ_CLASSIC}{DOTTED_SUFFIX} next") == [
        ("gitleaks:github-app-token", EYJ_CLASSIC)]


def test_an_undecodable_header_that_is_no_classic_token_is_no_finding():
    assert _t0_spans("gh" + "s_eyJhbGciOi.aaaaaaaa.aaaaaaaa next") == []
    assert [d for d, _ in _gitleaks_hits("gh" + "s_eyJhbGciOi.aaaaaaaa.aaaaaaaa next")
            if d == "gitleaks:github-app-token"] == []
