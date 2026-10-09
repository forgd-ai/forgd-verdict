"""A credential with a word character touching it, or base64-encoded in
either alphabet with or without padding, is still denied.

Every value here is synthetic and built by concatenation.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from conftest import FAKE_PAN, FAKE_SSN, ASGIClient, sign

from forgd_verdict.budget import Budget
from forgd_verdict.core import _b64_bytes, _decoded, decide, scan
from forgd_verdict.detectors import checksums, t0_regex
from forgd_verdict.detectors.gitleaks import GitleaksDetector
from forgd_verdict.detectors.t0_regex import T0RegexDetector
from forgd_verdict.models import ScanUnit
from forgd_verdict.policy import default_policy
from forgd_verdict.server.app import VerdictServer

AWS = "AKIAQYLPMN5HGZTHX4UQ"
_JWT = ".".join(["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                 "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ",
                 "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"])

# One value per rule whose prefix carries the match; a letter, digit or `_`
# on either side must not stop it.
FIXED_PREFIX = {
    "aws-access-key": AWS,
    "github-token": "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8",
    "github-pat": "github_pat_" + "1A" * 11 + "_" + "b2C3" * 15,
    "anthropic-api-key": "sk-ant-api03-" + "Ab1_" * 24,
    "anthropic-oauth-token": "sk-ant-oat01-" + "Ab1_" * 24,
    "anthropic-session-key": "sk-ant-sid01-" + "Ab1_" * 24,
    "openai-api-key": "sk-proj-" + "Ab1c" * 10 + "T3Blbk" + "FJ" + "Cd2e" * 10,
    "slack-token": "xoxb-" + "1234567890" + "12-" + "Ab1c" * 6,
    "google-api-key": "AIza" + "Sy" + "Ab1_-" * 6 + "Cd2",
    "stripe-secret-key": "sk_" + "live_" + "Ab1c" * 6,
    "private-key-pem": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
    "jwt": _JWT,
}

# Rules that keep a boundary, the value each is tested with, and the glue
# it is still found through. DETECTORS.md lists what each does not cover.
BOUNDED = {
    "aws-secret-key": ("aws_secret_access_key=" + "a" * 39 + "1", ("", "_", "x", "7")),
    "ssn": (FAKE_SSN, ("_", "x")),
    "ssn-labeled": ("ssn: " + FAKE_SSN.replace("-", ""), ("_", "x")),
    "pan": (FAKE_PAN, ("_",)),
}

CHECKSUM_LABELLED = {
    "aba-routing": "routing: 021000021",
    "nhs-number": "nhs: 943 476 5919",
    "canadian-sin": "sin: 046 454 286",
    "imei": "imei: 490154203237518",
}
CHECKSUM_BOUNDED = {"iban": "GB82WEST12345698765432"}

GLUES = [("x", ""), ("7", ""), ("key_", ""), ("_", ""), ("Q", ""),
         ("", "x"), ("", "7"), ("", "_"), ("", "_x"), ("", "Q")]
# Glue a rule does not see through, as DETECTORS.md documents.
NOT_COVERED = {"aws-access-key": {("7", ""), ("Q", "")}}


def _detectors(gitleaks: bool):
    detectors = default_policy().build_detectors(profile="server")
    if gitleaks:
        if not any(d.name == "gitleaks" for d in detectors):
            pytest.skip("gitleaks is not installed")
        return detectors
    return [d for d in detectors if d.name != "gitleaks"]


def _verdicts(texts: dict[str, str], detectors) -> dict[str, str]:
    """The action `decide` takes on each text, with the default policy, each
    scanned as its own unit in one scan."""
    policy = default_policy()
    units = [ScanUnit(locator=f"msg[{i}]", tool_name=None, text=text)
             for i, text in enumerate(texts.values())]
    result = scan(units, detectors, Budget(60_000))
    out = {}
    for i, name in enumerate(texts):
        own = [f for f in result.findings if f.locator.split("#")[0] == f"msg[{i}]"]
        out[name] = decide(own, policy, dropped=result.detectors_skipped).action
    return out


def test_every_t0_and_checksum_rule_is_classified():
    """A rule added without a decision on its boundary fails here."""
    assert {r.id for r in t0_regex.RULES} == set(FIXED_PREFIX) | set(BOUNDED)
    assert {c.id for c in checksums.CHECKS} == set(CHECKSUM_LABELLED) | set(CHECKSUM_BOUNDED)


def test_every_kept_boundary_is_documented():
    doc = (Path(__file__).parents[1] / "docs" / "DETECTORS.md").read_text()
    section = doc[doc.index("### Characters touching a value"):doc.index("**SSN checks**")]
    for rule in ("aws-access-key", "ssn", "pan", "openai-api-key"):
        assert f"`{rule}` does not match" in section or f"`{rule}` after" in section, rule
    assert "`iban` does not match directly after or before a letter or digit" in doc


@pytest.mark.parametrize("gitleaks", [False, True], ids=["t0", "t0+gitleaks"])
@pytest.mark.parametrize("rule", sorted(FIXED_PREFIX))
def test_a_glued_fixed_prefix_credential_is_denied(rule, gitleaks):
    value = FIXED_PREFIX[rule]
    texts = {"bare": f"use {value} now"}
    for before, after in GLUES:
        if (before, after) not in NOT_COVERED.get(rule, set()):
            texts[f"{before!r}+{after!r}"] = f"use {before}{value}{after} now"
    verdicts = _verdicts(texts, _detectors(gitleaks))
    assert verdicts == dict.fromkeys(texts, "deny")


@pytest.mark.parametrize("gitleaks", [False, True], ids=["t0", "t0+gitleaks"])
@pytest.mark.parametrize("rule", sorted(BOUNDED))
def test_a_bounded_rule_is_denied_through_the_glue_it_covers(rule, gitleaks):
    value, glues = BOUNDED[rule]
    texts = {"bare": f"{value} end"}
    for glue in glues:
        texts[f"after {glue!r}"] = f"{value}{glue} end"
        if not value[0].isalpha():
            texts[f"before {glue!r}"] = f"see {glue}{value} end"
    verdicts = _verdicts(texts, _detectors(gitleaks))
    assert verdicts == dict.fromkeys(texts, "deny")


@pytest.mark.parametrize("rule", sorted(CHECKSUM_LABELLED))
def test_a_labelled_checksum_value_is_denied_with_a_character_after_it(rule):
    value = CHECKSUM_LABELLED[rule]
    texts = {"bare": value, "letter": value + "x", "underscore": value + "_x"}
    assert _verdicts(texts, _detectors(False)) == dict.fromkeys(texts, "deny")


def test_an_iban_is_denied_between_underscores():
    value = CHECKSUM_BOUNDED["iban"]
    texts = {"bare": f"pay {value} now", "glued": f"pay acct_{value}_x now"}
    assert _verdicts(texts, _detectors(False)) == dict.fromkeys(texts, "deny")


def test_a_glued_key_finding_spans_only_the_key():
    text = "use key_" + AWS + "7 now"
    (f,) = T0RegexDetector().scan([ScanUnit("t", None, text)])
    assert text[f.start:f.end] == AWS


# -- shapes the relaxed boundaries must still pass -------------------------


@pytest.mark.parametrize("text", [
    "sha256 " + "ACCA" + "0123456789ABCDEF",
    "digest=ACCA0123456789ABCDEF89ABCDEF0123456789ABCDEF",
    "base32 QAKIAQYLPMN5HGZTHX4UQ",
    "the task-management-and-scheduling-service-for-the-enterprise",
    "use risk-assessment-policy-document-for-the-quarterly-review",
    "sha1 3a4539578763621486ff and 4539578763621486abc",
    "ref ABGB82WEST12345698765432",
])
def test_ordinary_text_beside_a_prefix_is_clean(text):
    assert T0RegexDetector().scan([ScanUnit("t", None, text)]) == []
    assert checksums.ChecksumDetector().scan([ScanUnit("t", None, text)]) == []


def test_an_a3t_key_after_an_underscore_is_found_by_gitleaks():
    gitleaks = GitleaksDetector()
    if not gitleaks.available():
        pytest.skip("gitleaks is not installed")
    a3t = "A3T" + "X" + AWS[4:]
    found = gitleaks.scan([ScanUnit("t", None, f"key_{a3t} and x{AWS}")])
    assert [f.detector for f in found] == ["gitleaks:aws-access-token"] * 2


# -- base64 --------------------------------------------------------------


def _b64_variants(raw: bytes) -> dict[str, str]:
    std = base64.b64encode(raw).decode()
    url = base64.urlsafe_b64encode(raw).decode()
    return {
        "std padded": std,
        "std unpadded": std.rstrip("="),
        "urlsafe padded": url,
        "urlsafe unpadded": url.rstrip("="),
        "glued letter": "x" + std,
        "glued three": "abc" + url.rstrip("="),
        "data uri": "data:text/plain;base64," + std,
        "wrapped urlsafe": "\n".join(url[i:i + 76] for i in range(0, len(url), 76)),
        "wrapped unpadded": "\n".join(std.rstrip("=")[i:i + 64]
                                      for i in range(0, len(std.rstrip("=")), 64)),
    }


@pytest.mark.parametrize("raw", [
    ("key=" + AWS).encode(),
    b"\xfb\xff\xfe" + ("key=" + AWS).encode(),
    ("export AWS_ACCESS_KEY_ID=" + AWS + "\n" + "x" * 120 + "\n").encode(),
    b"\x00\x89" * 20 + AWS.encode() + b"\xff" * 20,
], ids=["text", "urlsafe-chars", "wrapped", "binary"])
def test_a_base64_encoded_key_is_denied_in_every_variant(raw):
    variants = _b64_variants(raw)
    if len(variants["urlsafe padded"]) <= 76:
        del variants["wrapped urlsafe"], variants["wrapped unpadded"]
    assert _verdicts(variants, _detectors(False)) == dict.fromkeys(variants, "deny")


def test_an_unpadded_length_one_over_is_read_without_its_last_character():
    blob = base64.b64encode(("key=" + AWS).encode()).decode() + "A"
    assert len(blob) % 4 == 1
    assert _b64_bytes(blob) == ("key=" + AWS).encode()


def test_random_base64_in_both_alphabets_adds_no_findings():
    import random
    rng = random.Random(7)
    raw = rng.randbytes(30_000)
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        blob = enc(raw).decode()
        text = " ".join(blob[i:i + rng.randint(30, 400)].rstrip("=")
                        for i in range(0, len(blob), 400))
        result = scan([ScanUnit("x", None, text)], [T0RegexDetector(),
                                                     checksums.ChecksumDetector()])
        assert result.findings == []


def test_one_decoded_unit_per_run_in_any_alphabet():
    runs = [base64.urlsafe_b64encode(bytes([i]) * 3 + b"some decoded text here").decode()
            .rstrip("=") for i in range(250, 256)]
    decoded, over = _decoded([ScanUnit("x", None, " ".join(runs))], 100)
    assert not over
    assert len(decoded) == len(runs)


# -- end to end ----------------------------------------------------------


@pytest.mark.parametrize("prompt", [
    "please use key_" + AWS + " for the deploy",
    "please use " + AWS + "x for the deploy",
    "cfg: " + base64.urlsafe_b64encode(b"\xfb\xff" + AWS.encode()).decode(),
    "cfg: " + base64.b64encode(AWS.encode()).decode().rstrip("="),
], ids=["key_ prefix", "letter suffix", "urlsafe base64", "unpadded base64"])
async def test_the_verdict_server_denies_a_signed_glued_or_encoded_key(policy, prompt):
    server = VerdictServer(policy)
    try:
        frame = {"type": "prompt", "request_id": "req_glued", "session_id": "s1",
                 "source": {"application": "claude-code"},
                 "messages": [{"role": "user",
                               "content": [{"type": "text", "text": prompt}]}]}
        raw = json.dumps(frame).encode()
        status, verdict = await ASGIClient(server).post("/hook", raw,
                                                        sign(raw, webhook_id="req_glued"))
    finally:
        server.close()
    assert status == 200
    assert verdict["action"] == "deny"
    assert AWS not in json.dumps(verdict)


# -- the sink masks what the scan now finds --------------------------------


def test_the_sink_masks_a_glued_key_and_keeps_the_glue(tmp_path, monkeypatch):
    from test_sink import _forwarded

    event, findings = _forwarded(tmp_path, monkeypatch,
                                 {"note.text": f"use key_{AWS}7 today"})
    wire = repr(event.attributes)
    assert AWS not in wire and AWS[4:12] not in wire
    assert event.attributes["note.text"].startswith("use key_[redacted:")
    assert event.attributes["note.text"].endswith(" today")
    assert AWS not in repr([f.to_log() for f in findings])


@pytest.mark.parametrize("blob", [
    base64.urlsafe_b64encode(b"\xfb\xff" + ("key=" + AWS).encode()).decode(),
    base64.b64encode(("key=" + AWS).encode()).decode().rstrip("="),
    "x" + base64.b64encode(("key=" + AWS).encode()).decode(),
], ids=["urlsafe", "unpadded", "glued"])
def test_the_sink_masks_a_value_holding_an_encoded_key_whole(tmp_path, monkeypatch, blob):
    from test_sink import _forwarded

    event, findings = _forwarded(tmp_path, monkeypatch, {"blob.data": f"payload {blob} end"})
    assert any(f.locator.endswith("#b64") for f in findings)
    wire = repr(event.attributes)
    assert blob not in wire and AWS not in wire
    assert event.attributes["blob.data"] == "[redacted:regex:aws-access-key:whole-value]"


def test_a_glued_key_in_a_locator_is_scrubbed():
    units = [ScanUnit(locator=f"otel[0].evt.cfg_{AWS}x", tool_name=None, text=AWS)]
    result = scan(units, [T0RegexDetector()])
    assert result.findings
    assert all(AWS not in f.locator for f in result.findings)


@pytest.mark.parametrize("value", [
    "x" + AWS,
    base64.urlsafe_b64encode(b"\xfb\xff" + AWS.encode()).decode(),
    base64.b64encode(("id=" + AWS).encode()).decode().rstrip("="),
], ids=["glued", "urlsafe", "unpadded"])
def test_the_metadata_guard_replaces_a_glued_or_encoded_key(value):
    from forgd_verdict.metadata import MetadataGuard

    guard = MetadataGuard([T0RegexDetector()], salt="s")
    cleaned = guard.clean({"host.name": f"h-{value}", "service.name": "claude-code"})
    assert value not in repr(cleaned) and AWS not in repr(cleaned)
    assert cleaned["service.name"] == "claude-code"


@pytest.mark.parametrize("key", [
    "cfg_" + AWS + "x",
    base64.urlsafe_b64encode(b"\xfb\xff" + AWS.encode()).decode(),
], ids=["glued", "urlsafe"])
def test_a_glued_or_encoded_key_used_as_a_dict_key_is_kept_out_of_locators(key):
    from forgd_verdict.extract import frame_units

    messages = [{"role": "assistant", "content": [
        {"type": "tool_use", "id": "t1", "name": "Bash",
         "input": {key: "a value long enough to be scanned"}}]}]
    result = scan(frame_units(messages), [T0RegexDetector()])
    assert result.findings
    assert all(key not in f.locator and AWS not in f.locator for f in result.findings)
