"""`privacy.sealing`: matched values sealed to a KMS key no service holds.

A local RSA key stands in for the KMS: sealing needs only the public half,
and each test opens a value with the private half the way `unseal` asks the
KMS to.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json

import pytest
from conftest import FAKE_AWS_KEY, WHSEC, ASGIClient, frame, make_policy, sign, text_msg
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from forgd_verdict import cli, sealing, unseal
from forgd_verdict.core import scan
from forgd_verdict.models import Finding, ScanUnit, pseudonym
from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge, load_policy
from forgd_verdict.sealing import SEALED, Sealer, SealingInvalid, SealingKey, open_sealed
from forgd_verdict.store import LocalFileStore
from forgd_verdict.store.base import SOURCE_CODE_HOOK, FindingRow, VerdictRecord

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
KEY = rsa.generate_private_key(public_exponent=65537, key_size=3072)
ORG_KEY = rsa.generate_private_key(public_exponent=65537, key_size=3072)
ORG_UUID = "33333333-3333-3333-3333-333333333333"
SALT = "sealing-test-salt"


def _pem(private) -> str:
    return private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _key(private=KEY, kms="azure", key_id="https://vault.example/keys/findings/v1") -> dict:
    return {"kms": kms, "id": key_id, "public_key": _pem(private)}


def _config(**over) -> dict:
    return {"enabled": True, "key": _key(), **over}


def _opened(token: str, detector: str, private=KEY) -> tuple[str, bool]:
    return open_sealed(token, detector, lambda wrapped: private.decrypt(wrapped, OAEP))


def _sealer(private=KEY, max_chars=256) -> Sealer:
    return sealing.parse(_config(key=_key(private), max_chars=max_chars)).default


def _aws_unit(text: str = f"key {FAKE_AWS_KEY} here") -> list[ScanUnit]:
    return [ScanUnit("messages[0].content[0].text", None, text)]


def _detectors():
    return make_policy(
        detectors={"gitleaks": {"enabled": False, "severity": "block"}}).build_detectors()


# -- parsing ---------------------------------------------------------------------


@pytest.mark.parametrize("raw", [None, {}, {"enabled": False}, {"enabled": False, "key": 7}])
def test_sealing_is_off_unless_enabled(raw):
    assert sealing.parse(raw) is None


@pytest.mark.parametrize("raw, message", [
    ({"enabled": True}, "privacy.sealing.key is not set"),
    ({"enabled": "yes", "key": {}}, "enabled must be true or false"),
    ({"enabled": True, "key": {"kms": "vault", "id": "x", "public_key": "p"}}, "kms must be"),
    ({"enabled": True, "key": {"kms": "aws", "public_key": "p"}}, "id is required"),
    ({"enabled": True, "key": {"kms": "aws", "id": "arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-44cd-96ef-1234567890ab"}}, "public_key is required"),
    ({"enabled": True, "key": {"kms": "aws", "id": "arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-44cd-96ef-1234567890ab", "public_key": "nope"}}, "not a PEM"),
    ({"enabled": True, "key": {"kms": "aws", "id": "arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-44cd-96ef-1234567890ab", "public_key": "p", "secret": 1}},
     "it takes kms, id and public_key"),
    ({"enabled": True, "colour": "red"}, "privacy.sealing has colour"),
    ({"enabled": True, "max_chars": 0}, "max_chars must be"),
    ({"enabled": True, "max_chars": 2048}, "max_chars must be"),
    ({"enabled": True, "max_chars": True}, "max_chars must be"),
    ({"enabled": True, "orgs": ["x"]}, "orgs must map"),
    ({"enabled": True, "retired": {"a": 1}}, "retired must be a list"),
    ("on", "must be a mapping"),
])
def test_sealing_refuses_a_shape_that_cannot_seal(raw, message):
    if isinstance(raw, dict) and raw.get("enabled") is True and "key" not in raw \
            and "privacy.sealing.key is not set" not in message:
        raw = {**raw, "key": _key()}
    with pytest.raises(SealingInvalid, match=message):
        sealing.parse(raw)


@pytest.mark.parametrize("kms, key_id", [
    ("azure", "https://vault.example/keys/findings"),
    ("aws", "alias/forgd-verdict-seal"),
    ("aws", "1234abcd-12ab-44cd-96ef-1234567890ab"),
    ("gcp", "projects/p/locations/l/keyRings/r/cryptoKeys/k"),
    ("gcp", "arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-44cd-96ef-1234567890ab"),
])
def test_sealing_refuses_a_key_id_that_does_not_name_a_version(kms, key_id):
    with pytest.raises(SealingInvalid, match="id is not"):
        sealing.parse(_config(key=_key(kms=kms, key_id=key_id)))


@pytest.mark.parametrize("kms, key_id", [
    ("azure", "https://vault.example/keys/findings/0123456789abcdef"),
    ("aws", "arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-44cd-96ef-1234567890ab"),
    ("aws", "arn:aws:kms:eu-west-2:111122223333:key/mrk-0123456789abcdef0123456789abcdef"),
    ("gcp", "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3"),
])
def test_sealing_takes_each_kmss_versioned_key_id(kms, key_id):
    assert sealing.parse(_config(key=_key(kms=kms, key_id=key_id))).default.key.id == key_id


def test_two_org_references_to_one_org_id_are_refused(monkeypatch):
    monkeypatch.setenv("FORGD_ORG_ID_PRODUCTION", ORG_UUID)
    monkeypatch.setenv("FORGD_ORG_ID_TEST", ORG_UUID)
    with pytest.raises(SealingInvalid, match="two keys for one org id"):
        sealing.parse(_config(orgs={"$FORGD_ORG_ID_PRODUCTION": _key(ORG_KEY),
                                     "$FORGD_ORG_ID_TEST": _key()}))


def test_sealed_refuses_a_wrapped_key_of_a_length_no_key_produces():
    parts = _sealer().seal("v", "d").split(".")
    assert SEALED.fullmatch(".".join(parts))
    parts[3] = parts[3][:-1]
    assert not SEALED.fullmatch(".".join(parts))


def test_sealing_refuses_a_key_that_is_not_rsa_3072_or_4096():
    small = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(SealingInvalid, match="RSA-2048"):
        sealing.parse(_config(key=_key(small)))
    curve = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(SealingInvalid, match="must be an RSA key"):
        sealing.parse(_config(key=_key(curve)))


def test_sealing_resolves_env_references(monkeypatch):
    monkeypatch.setenv("FORGD_SEAL_PEM", _pem(KEY))
    monkeypatch.setenv("FORGD_SEAL_ID", "arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-44cd-96ef-1234567890ab")
    monkeypatch.setenv("FORGD_ORG_ID_ACME", ORG_UUID)
    parsed = sealing.parse({"enabled": True,
                            "key": {"kms": "aws", "id": "$FORGD_SEAL_ID",
                                    "public_key": "$FORGD_SEAL_PEM"},
                            "orgs": {"$FORGD_ORG_ID_ACME": _key(ORG_KEY)}})
    assert parsed.default.key.id == "arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-44cd-96ef-1234567890ab"
    assert parsed.for_org(ORG_UUID).key.fingerprint == sealing.fingerprint(ORG_KEY.public_key())
    assert parsed.for_org("someone-else") is parsed.default
    assert parsed.for_org(None) is parsed.default


def test_an_org_key_that_resolves_to_nothing_is_refused(monkeypatch):
    monkeypatch.delenv("FORGD_ORG_ID_GONE", raising=False)
    with pytest.raises(SealingInvalid, match="does not resolve"):
        sealing.parse(_config(orgs={"$FORGD_ORG_ID_GONE": _key(ORG_KEY)}))


def test_load_policy_refuses_a_sealing_that_cannot_seal(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"privacy": {"allow_unsalted": True,
                                            "sealing": {"enabled": True}}}))
    with pytest.raises(SealingInvalid):
        load_policy(path)


def test_sealing_is_not_reachable_from_the_environment(monkeypatch):
    """The overrides that reach the policy from the environment never
    include `privacy`."""
    from forgd_verdict import policy as policy_module

    assert not any(path[0] == "privacy"
                   for path, _ in policy_module.ENV_OVERRIDES.values())


# -- sealing ---------------------------------------------------------------------


def test_a_sealed_value_opens_to_the_value():
    token = _sealer().seal(FAKE_AWS_KEY, "regex:aws-access-key")
    assert SEALED.fullmatch(token)
    assert FAKE_AWS_KEY not in token
    assert _opened(token, "regex:aws-access-key") == (FAKE_AWS_KEY, False)


def test_sealing_is_randomised():
    sealer = _sealer()
    assert sealer.seal("v", "d") != sealer.seal("v", "d")


def test_a_sealed_value_opens_only_for_its_own_detector():
    token = _sealer().seal(FAKE_AWS_KEY, "regex:aws-access-key")
    with pytest.raises(ValueError, match="does not open"):
        _opened(token, "regex:github-pat")


def test_a_flipped_truncation_flag_does_not_open():
    token = _sealer().seal("value", "d")
    parts = token.split(".")
    parts[2] = "t"
    with pytest.raises(ValueError):
        _opened(".".join(parts), "d")


def test_a_long_value_is_cut_to_max_chars_and_says_so():
    token = _sealer(max_chars=8).seal("0123456789abcdef", "d")
    assert _opened(token, "d") == ("01234567", True)


@pytest.mark.parametrize("bits", [3072, 4096])
def test_the_largest_sealed_value_fits_the_shape(bits):
    private = KEY if bits == 3072 else rsa.generate_private_key(public_exponent=65537,
                                                                key_size=4096)
    token = _sealer(private, max_chars=sealing.MAX_CHARS_LIMIT).seal(
        "\U0001F511" * sealing.MAX_CHARS_LIMIT, "d")
    assert SEALED.fullmatch(token) and len(token) <= sealing.SEALED_MAX_CHARS
    assert SEALED.fullmatch(_sealer(private).seal("", "d"))


# -- the scan core ---------------------------------------------------------------


def test_scan_seals_each_matched_value_and_returns_none_in_the_clear():
    result = scan(_aws_unit(), _detectors(), sealer=_sealer())
    (finding,) = [f for f in result.findings if f.detector == "regex:aws-access-key"]
    assert finding.matched is None
    assert _opened(finding.sealed, finding.detector) == (FAKE_AWS_KEY, False)
    assert all(f.matched is None for f in result.findings)


def test_scan_without_a_sealer_drops_the_value():
    result = scan(_aws_unit(), _detectors())
    assert result.findings
    assert all(f.matched is None and f.sealed is None for f in result.findings)


def test_a_seal_that_raises_keeps_the_finding_unsealed(caplog):
    class Broken:
        def seal(self, value, detector):
            raise RuntimeError(f"cannot seal {value}")

    result = scan(_aws_unit(), _detectors(), sealer=Broken())
    assert result.findings and all(f.sealed is None and f.matched is None
                                   for f in result.findings)
    assert FAKE_AWS_KEY not in caplog.text


@pytest.mark.parametrize("text, detector, value", [
    (f"export AWS_KEY={FAKE_AWS_KEY}", "regex:aws-access-key", FAKE_AWS_KEY),
    ("card 4539578763621486 thanks", "regex:pan", "4539578763621486"),
])
def test_built_in_detectors_report_the_value_they_matched(text, detector, value):
    result = scan(_aws_unit(text), _detectors(), sealer=_sealer())
    found = {f.detector: f for f in result.findings}
    assert detector in found, sorted(found)
    assert _opened(found[detector].sealed, detector)[0] == value


def test_the_session_cache_holds_no_value_in_the_clear():
    from forgd_verdict.budget import Budget
    from forgd_verdict.cache import InMemoryLRUCache
    from forgd_verdict.core import scan_frame
    from forgd_verdict.extract import frame_units

    cache = InMemoryLRUCache()
    messages = [text_msg(f"key {FAKE_AWS_KEY}")]
    scan_frame(messages, frame_units, _detectors(), Budget(1000), cache, ("t", "s"),
               sealer=_sealer())
    state = cache.get(("t", "s"))
    assert state.findings and all(f.matched is None and f.sealed for f in state.findings
                                  if f.detector == "regex:aws-access-key")


def test_matched_and_sealed_are_kept_out_of_repr_and_equality():
    a = Finding("d", "warn", "l", "h", matched=FAKE_AWS_KEY, sealed="x")
    assert FAKE_AWS_KEY not in repr(a)
    assert a == Finding("d", "warn", "l", "h")


# -- the stored row --------------------------------------------------------------


def test_a_row_without_a_sealed_value_is_written_as_before():
    record = VerdictRecord(source="inference_hook",
                           findings=[FindingRow("d", "warn", "l", "h", "Bash")])
    assert json.loads(record.to_json())["findings"] == [
        {"detector": "d", "severity": "warn", "locator": "l", "excerpt_hash": "h",
         "tool_name": "Bash"}]


def test_a_sealed_value_survives_the_round_trip():
    token = _sealer().seal("v", "d")
    record = VerdictRecord(source="inference_hook",
                           findings=[FindingRow("d", "warn", "l", "h", None, token)])
    (row,) = VerdictRecord.from_json(record.to_json(), strict=True).findings
    assert row.sealed == token


@pytest.mark.parametrize("strict", [True, False])
def test_a_stored_sealed_field_that_is_not_a_sealed_value_is_dropped(strict):
    line = json.dumps({"source": "inference_hook", "findings": [
        {"detector": "d", "severity": "warn", "locator": "l", "excerpt_hash": "h",
         "sealed": FAKE_AWS_KEY}]})
    (row,) = VerdictRecord.from_json(line, strict=strict).findings
    assert row.sealed is None


# -- adapter 1 -------------------------------------------------------------------


def _server_policy(**sealing_over) -> Policy:
    return make_policy(
        privacy={"hash_salt": SALT, "sealing": _config(**sealing_over)},
        detectors={"gitleaks": {"enabled": False, "severity": "block"}},
        server={"mode": "observe", "secrets": [WHSEC]})


async def _post(server, webhook_id="msg_seal", **over) -> None:
    raw = json.dumps({**frame([text_msg(f"my key is {FAKE_AWS_KEY}")]), **over}).encode()
    status, _ = await ASGIClient(server).post("/hook", raw, sign(raw, webhook_id=webhook_id))
    assert status == 200


def _stored_findings(store) -> list[FindingRow]:
    return [f for r in store.read_verdicts() for f in r.findings
            if f.detector == "regex:aws-access-key"]


async def test_the_verdict_server_stores_the_sealed_value_and_never_the_value(tmp_path):
    from forgd_verdict.server.app import VerdictServer

    store = LocalFileStore(tmp_path / "store", instance="t")
    server = VerdictServer(_server_policy(), store=store)
    try:
        await _post(server)
    finally:
        server.close()
    (row,) = _stored_findings(store)
    assert _opened(row.sealed, row.detector) == (FAKE_AWS_KEY, False)
    stored = "".join(p.read_text() for p in (tmp_path / "store").rglob("*") if p.is_file())
    assert FAKE_AWS_KEY not in stored and FAKE_AWS_KEY[-8:] not in stored


async def test_an_org_with_its_own_key_is_sealed_to_it(tmp_path):
    from forgd_verdict.server.app import VerdictServer

    store = LocalFileStore(tmp_path / "store", instance="t")
    server = VerdictServer(_server_policy(orgs={ORG_UUID: _key(ORG_KEY)}), store=store)
    try:
        await _post(server, tenant_id=ORG_UUID)
        await _post(server, webhook_id="msg_seal_other", request_id="req_other")
    finally:
        server.close()
    by_org = {r.tenant_hash: r.findings for r in store.read_verdicts()}
    (own,) = [f for f in by_org[pseudonym(ORG_UUID, SALT, "org")]
              if f.detector == "regex:aws-access-key"]
    assert _opened(own.sealed, own.detector, ORG_KEY)[0] == FAKE_AWS_KEY
    with pytest.raises(ValueError):
        _opened(own.sealed, own.detector, KEY)
    others = [f for org, fs in by_org.items() if org != pseudonym(ORG_UUID, SALT, "org")
              for f in fs if f.detector == "regex:aws-access-key"]
    assert others and _opened(others[0].sealed, others[0].detector)[0] == FAKE_AWS_KEY


async def test_with_sealing_off_the_server_writes_no_sealed_field(tmp_path):
    from forgd_verdict.server.app import VerdictServer

    store = LocalFileStore(tmp_path / "store", instance="t")
    policy = make_policy(privacy={"hash_salt": SALT},
                         detectors={"gitleaks": {"enabled": False, "severity": "block"}},
                         server={"mode": "observe", "secrets": [WHSEC]})
    server = VerdictServer(policy, store=store)
    try:
        await _post(server)
    finally:
        server.close()
    stored = "".join(p.read_text() for p in (tmp_path / "store").rglob("*.jsonl"))
    assert '"excerpt_hash"' in stored and '"sealed"' not in stored


# -- adapter 2: the intake -------------------------------------------------------

INTAKE_TOKEN = "intake-token-for-sealing-0123456789abcdef"


def _intake_policy(sealed: bool) -> Policy:
    privacy = {"hash_salt": SALT, **({"sealing": _config()} if sealed else {})}
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"clients": [{"name": "laptop", "token": INTAKE_TOKEN}]},
        "privacy": privacy}))


def _ship(tmp_path, policy: Policy, sealed: str) -> FindingRow:
    from forgd_verdict.intake.app import Intake

    record = VerdictRecord(
        source=SOURCE_CODE_HOOK, action="deny", findings_count=1,
        findings=[FindingRow("regex:aws-access-key", "block", "tool_input.command",
                             "a" * 64, None, sealed)])
    intake = Intake(policy, store=LocalFileStore(tmp_path, instance="t"))
    try:
        status, _ = asyncio.run(ASGIClient(intake).post(
            "/intake", (record.to_json() + "\n").encode(),
            {"authorization": f"Bearer {INTAKE_TOKEN}",
             "content-type": "application/x-ndjson"}))
        assert status == 200
        intake.flush()
        ((row,),) = [r.findings for r in intake.store.read_verdicts()]
        return row
    finally:
        intake.close()


def test_the_intake_keeps_a_shipped_sealed_value_under_its_own_key(tmp_path):
    token = _sealer().seal(FAKE_AWS_KEY, "regex:aws-access-key")
    assert _ship(tmp_path, _intake_policy(True), token).sealed == token


def test_the_intake_drops_a_sealed_value_under_a_key_it_does_not_know(tmp_path):
    token = _sealer(ORG_KEY).seal(FAKE_AWS_KEY, "regex:aws-access-key")
    assert _ship(tmp_path, _intake_policy(True), token).sealed is None


def test_the_intake_drops_a_sealed_value_under_a_retired_key(tmp_path):
    token = _sealer(ORG_KEY).seal(FAKE_AWS_KEY, "regex:aws-access-key")
    policy = _intake_policy(True)
    policy.raw["privacy"]["sealing"]["retired"] = [_key(ORG_KEY)]
    assert _ship(tmp_path, policy, token).sealed is None


def test_the_intake_with_sealing_off_drops_every_sealed_value(tmp_path):
    token = _sealer().seal(FAKE_AWS_KEY, "regex:aws-access-key")
    assert _ship(tmp_path, _intake_policy(False), token).sealed is None


def test_the_intake_seals_to_the_key_of_the_credentials_org(monkeypatch):
    policy = Policy(raw=_deep_merge(DEFAULT_POLICY, {"privacy": {
        "hash_salt": SALT, "sealing": _config(orgs={ORG_UUID: _key(ORG_KEY)})}}))
    own = policy.sealer_for_pseudonym(pseudonym(ORG_UUID, SALT, "org"))
    assert own.key.fingerprint == sealing.fingerprint(ORG_KEY.public_key())
    assert policy.sealer_for_pseudonym("org_unattributed") is policy.sealing.default


# -- adapter 2: the hook ---------------------------------------------------------


def test_the_hooks_local_scan_seals(tmp_path):
    from forgd_verdict.hook import cli as hook_cli

    policy = make_policy(privacy={"sealing": _config()},
                         detectors={"gitleaks": {"enabled": False, "severity": "block"}})
    _, _, spool = hook_cli.evaluate(
        {"hook_event_name": "UserPromptSubmit", "prompt": f"key {FAKE_AWS_KEY}",
         "session_id": "s", "cwd": str(tmp_path)}, policy)
    result = spool.args[4]
    (finding,) = [f for f in result.findings if f.detector == "regex:aws-access-key"]
    assert _opened(finding.sealed, finding.detector)[0] == FAKE_AWS_KEY


# -- unseal ----------------------------------------------------------------------


@pytest.fixture
def fake_kms(monkeypatch):
    calls = []

    def unwrapper(kind):
        def make(key_id):
            calls.append((kind, key_id))
            private = {"https://vault.example/keys/findings/v1": KEY,
                       "https://vault.example/keys/old/v1": ORG_KEY}[key_id]
            return lambda wrapped: private.decrypt(wrapped, OAEP)
        return make

    monkeypatch.setattr(unseal, "UNWRAPPERS", {k: unwrapper(k) for k in sealing.KMS_KINDS})
    return calls


def _policy_file(tmp_path, **over) -> str:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"privacy": {"allow_unsalted": True,
                                            "sealing": _config(**over)}}))
    return str(path)


def test_unseal_masks_by_default(tmp_path, fake_kms, capsys):
    token = _sealer().seal(FAKE_AWS_KEY, "regex:aws-access-key")
    code = cli.main(["--policy", _policy_file(tmp_path), "unseal",
                     "regex:aws-access-key", token])
    out, err = capsys.readouterr()
    assert code == 0
    assert FAKE_AWS_KEY not in out and out.startswith(FAKE_AWS_KEY[:2])
    assert "--reveal" in err
    assert fake_kms == [("azure", "https://vault.example/keys/findings/v1")]


def test_unseal_reveal_prints_the_value(tmp_path, fake_kms, capsys):
    token = _sealer(max_chars=4).seal(FAKE_AWS_KEY, "regex:aws-access-key")
    code = cli.main(["--policy", _policy_file(tmp_path), "unseal",
                     "regex:aws-access-key", token, "--reveal"])
    out, err = capsys.readouterr()
    assert code == 0 and out.strip() == FAKE_AWS_KEY[:4]
    assert "cut short" in err


def test_unseal_finds_a_retired_key_by_fingerprint(tmp_path, fake_kms, capsys):
    token = _sealer(ORG_KEY).seal("old value", "d")
    path = _policy_file(tmp_path, retired=[_key(ORG_KEY, key_id="https://vault.example/keys/old/v1")])
    assert cli.main(["--policy", path, "unseal", "d", token, "--reveal"]) == 0
    assert capsys.readouterr().out.strip() == "old value"


def test_unseal_names_the_problem_for_an_unknown_key(tmp_path, fake_kms, capsys):
    token = _sealer(ORG_KEY).seal("v", "d")
    assert cli.main(["--policy", _policy_file(tmp_path), "unseal", "d", token]) == 2
    assert "no key in privacy.sealing" in capsys.readouterr().err
    assert fake_kms == []


def test_unseal_with_the_wrong_detector_fails(tmp_path, fake_kms, capsys):
    token = _sealer().seal("v", "regex:aws-access-key")
    assert cli.main(["--policy", _policy_file(tmp_path), "unseal", "regex:other", token]) == 1
    assert "detector" in capsys.readouterr().err


def test_unseal_takes_a_key_by_name_without_a_policy(fake_kms, capsys):
    token = _sealer().seal("v", "d")
    assert cli.main(["unseal", "d", token, "--reveal", "--kms", "azure",
                     "--key-id", "https://vault.example/keys/findings/v1"]) == 0
    assert capsys.readouterr().out.strip() == "v"


def test_unseal_refuses_something_that_is_not_a_sealed_value(fake_kms, capsys):
    assert cli.main(["unseal", "d", FAKE_AWS_KEY, "--kms", "aws", "--key-id", "k"]) == 2
    assert "not a sealed value" in capsys.readouterr().err


def test_unseal_reads_the_aws_region_from_the_key_arn(monkeypatch):
    import sys
    import types

    made = {}
    fake = types.ModuleType("boto3")
    fake.client = lambda service, **kw: made.update(service=service, **kw) or object()
    monkeypatch.setitem(sys.modules, "boto3", fake)
    unseal._aws("arn:aws:kms:eu-west-2:111122223333:key/abc")
    assert made == {"service": "kms", "region_name": "eu-west-2"}


def test_sealing_key_fingerprint_is_the_spki_digest():
    import hashlib

    der = KEY.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    assert SealingKey.parse(_key(), "k").fingerprint == hashlib.sha256(der).hexdigest()[:16]
    assert dataclasses.is_dataclass(SealingKey)


# -- adapters 3 and 4, and the dashboard -----------------------------------------


def test_the_collector_seals_to_the_key_of_the_tokens_org():
    from forgd_verdict.detectors.t0_regex import T0RegexDetector
    from forgd_verdict.otel.collect import collect
    from forgd_verdict.otel.payload import OtelRecord

    policy = make_policy(privacy={"sealing": _config(orgs={ORG_UUID: _key(ORG_KEY)})})
    rec = OtelRecord(kind="log", name="claude_code.api_request_body",
                     attributes={"body": f"pay with {FAKE_AWS_KEY}", "session.id": "s",
                                 "prompt.id": "p"})
    out, _ = collect([rec], [T0RegexDetector()], budget_ms=5000, org_id=ORG_UUID,
                     policy=policy)
    (row,) = [f for r in out for f in r.findings if f.detector == "regex:aws-access-key"]
    assert _opened(row.sealed, row.detector, ORG_KEY)[0] == FAKE_AWS_KEY


def _calls(source: str, name: str) -> list[str]:
    """The text of each call to `name` in `source`, by balanced parentheses."""
    import re

    out = []
    for m in re.finditer(rf"(?<!def )(?<![\w.]){name}\(", source):
        depth, i = 0, m.end() - 1
        for i in range(m.end() - 1, len(source)):
            depth += {"(": 1, ")": -1}.get(source[i], 0)
            if depth == 0:
                break
        out.append(source[m.start():i + 1])
    return out


@pytest.mark.parametrize("module", ["compliance.scanner", "managed.scanner"])
def test_the_scanners_pass_a_sealer(module):
    """Each of the post-hoc scanners' scan calls names the policy's sealer."""
    import importlib
    import inspect

    calls = _calls(inspect.getsource(importlib.import_module(f"forgd_verdict.{module}")),
                   "scan")
    assert calls and all("sealer(" in c for c in calls), calls


def test_the_events_page_shows_each_sealed_value_as_its_unseal_command():
    from forgd_verdict.dashboard.render import render_events

    token = _sealer().seal(FAKE_AWS_KEY, "regex:aws-access-key")
    sealed = VerdictRecord(source="inference_hook", request_id="req_a", action="deny",
                           findings=[FindingRow("regex:aws-access-key", "block", "l", "h",
                                                None, token)] * 2, findings_count=2)
    plain = VerdictRecord(source="inference_hook", request_id="req_b", action="deny",
                          findings=[FindingRow("regex:aws-access-key", "block", "l", "h")],
                          findings_count=1)
    html = render_events([sealed, plain])
    assert html.count(f"forgd-verdict unseal regex:aws-access-key {token}") == 1
    assert "1 sealed" in html
    assert FAKE_AWS_KEY not in html
    assert "sealed" not in render_events([plain]).split("<tbody>")[1]


def test_every_built_in_detector_finding_carries_its_matched_value():
    """Each `Finding(...)` a detector builds from a digest of a value names
    that value as `matched`, except LLM Guard's risk score, which reports
    no value."""
    import pathlib

    root = pathlib.Path(sealing.__file__).parent / "detectors"
    checked = 0
    for path in sorted(root.glob("*.py")):
        for call in _calls(path.read_text(encoding="utf-8"), "Finding"):
            if "excerpt_hash=digest(" not in call or "llmguard-risk" in call:
                continue
            checked += 1
            assert "matched=" in call, f"{path.name}: {call[:120]}"
    assert checked >= 7
