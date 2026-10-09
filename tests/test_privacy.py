"""The privacy invariant, enforced.

Seed frames with known secrets, then assert the secret string appears
nowhere in the log stream, the timing CSV, the metrics snapshot, or the
verdict body. Archive mode is the one deliberate exception and is excluded --
see test_protocol.py::test_archive_mode_allows_and_persists_after_responding.
"""

from __future__ import annotations

import io
import json

from conftest import (
    FAKE_AWS_KEY,
    FAKE_GITHUB_TOKEN,
    FAKE_PAN,
    FAKE_SSN,
    WHSEC,
    ASGIClient,
    frame,
    make_policy,
    sign,
    text_msg,
)

from forgd_verdict.applog import configure_logging
from forgd_verdict.budget import Budget
from forgd_verdict.core import build_deny_reason, decide, scan
from forgd_verdict.models import ScanUnit
from forgd_verdict.server.app import VerdictServer

SECRETS = [FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, FAKE_SSN, FAKE_PAN]
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD\n-----END RSA PRIVATE KEY-----"


def assert_clean(haystack: str, label: str) -> None:
    for secret in SECRETS:
        assert secret not in haystack, f"{secret!r} leaked into {label}"
        # Also catch a partial leak: the distinctive tail of each value.
        assert secret[-8:] not in haystack, f"tail of {secret!r} leaked into {label}"


async def test_no_secret_reaches_logs_csv_metrics_or_verdict(tmp_path):
    stream = io.StringIO()
    logger = configure_logging("DEBUG", stream=stream)
    csv_path = tmp_path / "timings.csv"
    policy = make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "enforce", "secrets": [WHSEC], "csv_path": str(csv_path)},
    )
    server = VerdictServer(policy, logger=logger)
    client = ASGIClient(server)

    messages = [
        text_msg(f"my key is {FAKE_AWS_KEY} and token {FAKE_GITHUB_TOKEN}"),
        text_msg(f"ssn {FAKE_SSN} card {FAKE_PAN}", role="assistant"),
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_name": "Read", "is_error": False,
                 "content": PEM},
            ],
        },
    ]
    raw = json.dumps(frame(messages)).encode()
    status, verdict = await client.post("/hook", raw, sign(raw))
    assert status == 200 and verdict["action"] == "deny"

    # 1. The verdict body itself.
    assert_clean(json.dumps(verdict), "verdict body")
    assert "PRIVATE KEY" not in verdict["deny_reason"]

    # 2. The structured log stream (which includes every finding).
    server.close()
    logs = stream.getvalue()
    assert "verdict" in logs, "expected a verdict log line"
    assert_clean(logs, "log stream")
    # The findings really were logged -- this is not vacuous.
    logged = [json.loads(line) for line in logs.splitlines() if line.strip()]
    findings = next(e["findings"] for e in logged if "findings" in e)
    assert len(findings) >= 4
    assert all(set(f) == {"detector", "severity", "locator", "excerpt_hash", "tool_name"}
               for f in findings)

    # 3. The timing CSV.
    assert_clean(csv_path.read_text(), "timing CSV")

    # 4. The metrics snapshot.
    assert_clean(json.dumps(server._metrics_body()), "metrics")


def test_deny_reason_never_echoes_the_match():
    for secret in (*SECRETS, PEM):
        result = scan([ScanUnit("t", None, secret)], _t0(), Budget(1000))
        if not result.findings:
            continue
        verdict = decide(result.findings, _policy())
        assert verdict.deny_reason
        assert_clean(verdict.deny_reason, "deny_reason")


def test_reference_id_carries_no_content():
    result = scan([ScanUnit("t", None, FAKE_AWS_KEY)], _t0(), Budget(1000))
    verdict = decide(result.findings, _policy())
    assert verdict.reference_id
    assert_clean(verdict.reference_id, "reference_id")


def test_excerpt_hash_is_not_the_text():
    result = scan([ScanUnit("t", None, FAKE_AWS_KEY)], _t0(), Budget(1000))
    hashes = [f.excerpt_hash for f in result.findings]
    assert hashes and all(len(h) == 64 and FAKE_AWS_KEY not in h for h in hashes)


def test_hash_salt_changes_the_digest():
    """The documented mitigation for brute-forcing low-entropy PII hashes."""
    unsalted = scan([ScanUnit("t", None, FAKE_SSN)], _t0(salt=""), Budget(1000))
    salted = scan([ScanUnit("t", None, FAKE_SSN)], _t0(salt="pepper"), Budget(1000))
    assert unsalted.findings and salted.findings
    assert unsalted.findings[0].excerpt_hash != salted.findings[0].excerpt_hash


def test_deny_reason_is_truncated_to_the_protocol_limit():
    reason = build_deny_reason([f"regex:rule{i}" for i in range(80)], "contact security")
    assert len(reason) <= 500


def _policy():
    return make_policy(detectors={"gitleaks": {"enabled": False, "severity": "block"}})


def _t0(salt: str = ""):
    return make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        privacy={"hash_salt": salt},
    ).build_detectors()


def test_one_phrase_per_distinct_secret_not_per_detector():
    """T0 and T1 flag the same string; the user should not read
    'an AWS access key ID and an AWS credential'."""
    from forgd_verdict.models import Finding

    findings = [
        Finding("regex:aws-access-key", "block", "msg[0]", "hash-a"),
        Finding("gitleaks:aws-access-token", "block", "msg[0]", "hash-a"),
    ]
    reason = decide(findings, _policy()).deny_reason
    assert "an AWS access key ID" in reason
    assert "and an AWS credential" not in reason

    # Two genuinely different secrets still get two phrases.
    findings.append(Finding("regex:ssn", "block", "msg[1]", "hash-b"))
    reason = decide(findings, _policy()).deny_reason
    assert "an AWS access key ID" in reason and "Social Security number" in reason


# --- the hash salt --------------------------------------------------------


def test_an_unsalted_digest_is_reversible_for_a_low_entropy_value():
    """The reason privacy.hash_salt exists, demonstrated rather than asserted.

    An SSN has ~1e9 possibilities. This brute-forces a three-digit space to
    keep the test instant; the arithmetic is the same and so is the
    conclusion -- with no salt, the hash IS the value to anyone holding an
    export.
    """
    from forgd_verdict.models import digest

    secret = "482"
    target = digest(secret)
    recovered = next(f"{i:03d}" for i in range(1000) if digest(f"{i:03d}") == target)
    assert recovered == secret

    # With a salt the same sweep finds nothing, because the attacker is
    # searching the wrong space.
    salted = digest(secret, "a-deployment-secret")
    assert not any(digest(f"{i:03d}") == salted for i in range(1000))


def test_the_shipped_policy_reads_its_salt_from_the_environment():
    """Not a literal in a committed file, for the same reason org ids are
    not: policy.yaml is committed."""
    from forgd_verdict.policy import load_policy

    raw = load_policy("policy.yaml").raw["privacy"]["hash_salt"]
    assert str(raw).startswith("$"), raw


def test_an_empty_salt_warns_at_startup(caplog):
    """Our default becomes every fork's default. A fork that never notices
    ships brute-forceable findings, so it is said where it can be acted on.
    """
    import logging

    from forgd_verdict.applog import warn_if_unsalted
    from forgd_verdict.policy import Policy

    log = logging.getLogger("test.salt")
    with caplog.at_level(logging.WARNING):
        assert warn_if_unsalted(log, Policy(raw={"privacy": {"hash_salt": ""}})) is True
    assert "hash_salt is empty" in caplog.text

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        assert warn_if_unsalted(log, Policy(raw={"privacy": {"hash_salt": "s"}})) is False
    assert caplog.text == ""


def test_every_service_that_writes_findings_warns():
    """Three writers share the store, so all three must say it. The hook is
    deliberately excluded: it runs on a laptop and does not get the
    deployment salt."""
    import inspect

    from forgd_verdict.compliance import ingest
    from forgd_verdict.otel import app as otel_app
    from forgd_verdict.server import app as server_app

    for mod in (server_app, otel_app, ingest):
        assert "warn_if_unsalted" in inspect.getsource(mod), mod.__name__


def test_the_policy_tab_does_not_claim_a_salt_is_set_when_it_is_not():
    """It reported `<set>` whenever the literal was non-empty, so
    `$FORGD_HASH_SALT` with nothing in the environment read as configured
    while findings were being hashed bare. An indicator that lies in the
    direction of safety is worse than none."""
    import os

    from forgd_verdict.policy import load_policy, redacted

    before = os.environ.pop("FORGD_HASH_SALT", None)
    try:
        shown = redacted(load_policy("policy.yaml"))["privacy"]["hash_salt"]
        assert "UNSET" in shown, shown
        os.environ["FORGD_HASH_SALT"] = "a-real-salt"
        blob = repr(redacted(load_policy("policy.yaml")))
        assert "<set>" in blob and "a-real-salt" not in blob
    finally:
        os.environ.pop("FORGD_HASH_SALT", None)
        if before is not None:
            os.environ["FORGD_HASH_SALT"] = before


def test_a_public_placeholder_is_never_a_usable_credential():
    """The bootstrap and the Terraform modules write placeholders so a
    service can exist before its credential does. Those strings are in this
    repository.

    A signing secret has a format and fails to decode, so a placeholder was
    always refused there. A BEARER TOKEN has no format: any non-empty string
    authenticated, which made the published placeholder a working key for
    the OTel collector.
    """
    from forgd_verdict.models import PLACEHOLDERS, usable_secret

    assert usable_secret("placeholder-not-yet-issued") is None
    assert usable_secret("  placeholder-not-yet-issued  ") is None
    assert usable_secret("") is None
    assert usable_secret(None) is None
    assert usable_secret("a-real-token") == "a-real-token"
    assert "placeholder-not-yet-issued" in PLACEHOLDERS


def test_the_collector_configures_no_org_for_a_placeholder_token():
    """The safe failure: zero orgs means every export is refused with 401,
    rather than one accepted on a token anyone can read."""
    from forgd_verdict.otel.app import _token_map

    assert _token_map({"orgs": [{"id": "o", "token": "placeholder-not-yet-issued"}]}) == {}
    assert _token_map({"orgs": [{"id": "o", "token": "a-real-one-0123456789abcdefgh"}]}) != {}


def test_the_ingest_job_treats_a_placeholder_key_as_unconfigured():
    """Otherwise it believes it is configured and makes failing API calls
    every six hours instead of taking the clear 'no key' path."""
    from forgd_verdict.policy import Policy

    p = Policy(raw={"compliance": {"orgs": [
        {"id": "o", "api_key": "placeholder-not-yet-issued"}]}})
    assert p.compliance_orgs() == []


# -- a finding's own metadata --------------------------------------------

AWS = "AKIAIOSFODNN7EXAMPLE"


def _hook_findings(payload):
    from forgd_verdict.extract import hook_units
    from forgd_verdict.policy import load_policy

    policy = load_policy("policy.yaml")
    return scan(hook_units(payload), policy.build_detectors()).findings


def test_a_secret_used_as_a_json_key_does_not_reach_the_locator():
    """`extract._strings` builds the locator out of dict keys, and a key
    is arbitrary sender data. It reached `Finding.locator`, which
    `FindingRow` copies to the store and `to_log` copies to the verdict
    log -- one line below a comment reading "Detector names, locators and
    hashes only -- never the match"."""
    findings = _hook_findings({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"env": {AWS: f"export TOKEN={AWS}"}},
    })
    assert findings
    for f in findings:
        assert AWS not in f.locator
        assert AWS not in json.dumps(f.to_log())


def test_a_secret_used_as_a_tool_name_does_not_reach_the_log():
    findings = _hook_findings({
        "hook_event_name": "PreToolUse", "tool_name": AWS,
        "tool_input": {"command": f"echo {AWS}"},
    })
    assert findings
    for f in findings:
        assert AWS not in (f.tool_name or "")
        assert AWS not in json.dumps(f.to_log())


def test_the_locator_keeps_its_structure():
    """A locator nobody can read is a locator nobody can act on. Only the
    offending segment is replaced."""
    findings = _hook_findings({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"env": {AWS: f"export TOKEN={AWS}"}},
    })
    loc = findings[0].locator
    assert loc.startswith("tool_input.env.")
    assert "<redacted>" in loc


def test_an_ordinary_locator_is_untouched():
    findings = _hook_findings({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": f"echo {AWS}"},
    })
    assert findings[0].locator == "tool_input.command"
    assert findings[0].tool_name == "Bash"


def test_an_otel_attribute_name_does_not_reach_stats():
    """`unrecognised_keys()` is published on /stats, which needs no
    credential, and it returned the raw attribute name."""
    from forgd_verdict.otel.extract import unrecognised_keys
    from forgd_verdict.otel.payload import OtelRecord

    rec = OtelRecord(
        kind="log", name="evt",
        attributes={AWS: "x" * 80, "well.formed_name": "y" * 80},
        resource={},
    )
    from forgd_verdict.policy import load_policy
    detectors = load_policy("policy.yaml").build_detectors()
    keys = unrecognised_keys(rec, detectors)
    assert AWS not in keys
    assert any(k.startswith("<redacted>") for k in keys)
    assert "well.formed_name" in keys


# -- an upstream error body ----------------------------------------------


def test_a_compliance_error_message_carries_no_response_body():
    """500 bytes of arbitrary upstream response travelled into three
    sinks: `log.exception`'s traceback, which `JsonFormatter` emits
    deliberately and which reaches stderr unconfigured -- the cron path --
    the per-org `error` in the run summary, and that summary printed to
    stdout by the CLI.

    Whether Anthropic's error bodies ever contain transcript content is
    speculative; unbounded third-party text arriving in a log is not.
    """
    from forgd_verdict.compliance.client import ComplianceError

    body = f"internal error near {AWS} for user@example.com"
    exc = ComplianceError(500, body, "https://api.anthropic.com/v1/compliance/x")
    assert AWS not in str(exc)
    assert "user@example.com" not in str(exc)
    assert "500" in str(exc)
    # Still reachable for a debugger holding it in memory.
    assert exc.body == body


def test_userinfo_in_a_base_url_is_not_logged():
    from forgd_verdict.compliance.client import ComplianceError

    exc = ComplianceError(403, "nope", "https://user:hunter2@proxy.example/v1/x")
    assert "hunter2" not in str(exc)
    assert "proxy.example" in str(exc)
