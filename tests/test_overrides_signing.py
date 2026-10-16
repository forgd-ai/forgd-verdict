"""Ed25519 signing for runtime-override records: keys, signatures, keygen."""

from __future__ import annotations

import base64
import json
import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from forgd_verdict import overrides_signing as sig
from forgd_verdict.cli import main
from forgd_verdict.policy import ENV_OVERRIDES, SECRET_PATHS, Policy, load_policy, redacted
from forgd_verdict.store.base import AUDIT_PREFIX


def _pair() -> sig.KeyPair:
    return sig.generate()


def _record() -> dict:
    return {"action": "override.set", "key": "server.mode", "new_value": "enforce",
            "revision": 3, "principal": {"name": "ada", "groups": ["admins"]},
            "note": "naïve – non-ASCII"}


# -- key parsing -----------------------------------------------------------


def test_generated_keys_parse_and_round_trip():
    pair = _pair()
    private = sig.parse_signing_key(pair.private)
    public = sig.parse_verify_key(pair.public)
    assert sig.key_id(private.public_key()) == sig.key_id(public) == pair.kid
    assert len(pair.private) == len(pair.public) == 43
    assert "=" not in pair.private + pair.public


@pytest.mark.parametrize("text", [
    "",
    "not base64 at all!",
    # Standard alphabet, not URL-safe.
    base64.b64encode(b"\xfb" * 32).decode().rstrip("="),
    # Padded.
    base64.urlsafe_b64encode(b"\x01" * 32).decode(),
    # Wrong length.
    sig.encode(b"\x01" * 31),
    sig.encode(b"\x01" * 33),
    sig.encode(b"\x01" * 64),
])
def test_malformed_keys_are_refused(text):
    with pytest.raises(sig.KeyConfigError):
        sig.parse_signing_key(text)
    with pytest.raises(sig.KeyConfigError):
        sig.parse_verify_key(text)


def test_a_non_canonical_encoding_is_refused():
    good = _pair().public
    # 32 bytes in 43 characters leaves two unused bits in the last one;
    # setting them decodes to the same bytes.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(good[-1])
    bad = good[:-1] + alphabet[last ^ 1]
    assert base64.urlsafe_b64decode(bad + "=") == base64.urlsafe_b64decode(good + "=")
    with pytest.raises(sig.KeyConfigError, match="canonical"):
        sig.parse_verify_key(bad)


def test_errors_never_contain_the_key():
    private = _pair().private
    for bad in (private + "A", private[:-1] + "!", private + "=="):
        with pytest.raises(sig.KeyConfigError) as err:
            sig.parse_signing_key(bad)
        assert private[:20] not in str(err.value)


def test_verify_keys_are_comma_separated():
    a, b = _pair(), _pair()
    keys = sig.parse_verify_keys(f"{a.public}, {b.public}")
    assert [sig.key_id(k) for k in keys] == [a.kid, b.kid]
    assert sig.parse_verify_keys("") == ()
    assert sig.parse_verify_keys(None) == ()
    assert len(sig.parse_verify_keys([a.public])) == 1


@pytest.mark.parametrize("shape", ["{a},", ",{a}", "{a},,{b}", "{a},{a}"])
def test_empty_or_repeated_verify_entries_are_refused(shape):
    a, b = _pair(), _pair()
    with pytest.raises(sig.KeyConfigError):
        sig.parse_verify_keys(shape.format(a=a.public, b=b.public))


# -- environment and policy ------------------------------------------------


def test_env_places_the_keys_under_overrides(monkeypatch, tmp_path):
    a, b = _pair(), _pair()
    monkeypatch.setenv("FORGD_OVERRIDES_SIGNING_KEY", a.private)
    monkeypatch.setenv("FORGD_OVERRIDES_VERIFY_KEY", f"{a.public},{b.public}")
    path = tmp_path / "policy.yaml"
    path.write_text("{}\n")
    policy = load_policy(path)
    cfg = sig.from_policy(policy.raw)
    assert cfg.signing_key is not None
    assert sig.key_id(cfg.signing_key.public_key()) == a.kid
    assert cfg.key_ids == (a.kid, b.kid)


def test_env_names_and_paths():
    assert "FORGD_OVERRIDES_SIGNING_KEY" not in ENV_OVERRIDES
    assert ENV_OVERRIDES["FORGD_OVERRIDES_VERIFY_KEY"][0] == ("overrides", "verify_keys")
    assert ("overrides", "signing_key") in SECRET_PATHS
    assert ("overrides", "verify_keys") not in SECRET_PATHS


def test_no_keys_configured_is_empty():
    cfg = sig.from_policy({})
    assert cfg.signing_key is None and cfg.verify_keys == ()


def test_a_signing_key_its_verify_keys_do_not_list_is_refused(monkeypatch):
    """Mutation: drop the key-id check in from_policy."""
    a, b = _pair(), _pair()
    monkeypatch.setenv(sig.ENV_SIGNING_KEY, a.private)
    with pytest.raises(sig.KeyConfigError, match=a.kid):
        sig.from_policy({"overrides": {"verify_keys": [b.public]}})


def test_a_signing_key_with_no_verify_keys_is_refused(monkeypatch):
    """Mutation: check the key id only when verify keys are listed."""
    monkeypatch.setenv(sig.ENV_SIGNING_KEY, _pair().private)
    with pytest.raises(sig.KeyConfigError, match="lists no key"):
        sig.from_policy({})


@pytest.mark.parametrize("value", ["literal", "PRIVATE", "$", "$1X", " $X", 7])
def test_a_signing_key_that_is_not_a_reference_is_refused(monkeypatch, value):
    """A private key pasted into policy.yaml refuses to start, whatever the
    environment holds. Mutation: resolve the value as env_or_literal did."""
    a = _pair()
    monkeypatch.setenv(sig.ENV_SIGNING_KEY, a.private)
    literal = a.private if value == "literal" else value
    with pytest.raises(sig.KeyConfigError, match=r"must be a \$NAME environment reference"):
        sig.from_policy({"overrides": {"signing_key": literal, "verify_keys": [a.public]}})


def test_the_signing_key_defaults_to_its_variable(monkeypatch):
    """Mutation: read only a signing key the policy names."""
    a = _pair()
    monkeypatch.setenv(sig.ENV_SIGNING_KEY, a.private)
    cfg = sig.from_policy({"overrides": {"verify_keys": [a.public]}})
    assert sig.key_id(cfg.signing_key.public_key()) == a.kid
    monkeypatch.delenv(sig.ENV_SIGNING_KEY)
    assert sig.from_policy({"overrides": {"verify_keys": [a.public]}}).signing_key is None


def test_load_policy_leaves_the_private_key_out_of_the_policy(tmp_path, monkeypatch):
    """Mutation: put FORGD_OVERRIDES_SIGNING_KEY back in ENV_OVERRIDES."""
    a = _pair()
    monkeypatch.setenv(sig.ENV_SIGNING_KEY, a.private)
    path = tmp_path / "policy.yaml"
    path.write_text("{}\n")
    raw = load_policy(path).raw
    assert a.private not in json.dumps(raw)
    assert "signing_key" not in (raw.get("overrides") or {})


def test_policy_values_may_name_an_env_var(monkeypatch):
    a = _pair()
    monkeypatch.setenv("SIGN_HERE", a.private)
    monkeypatch.setenv("VERIFY_HERE", a.public)
    cfg = sig.from_policy({"overrides": {"signing_key": "$SIGN_HERE",
                                         "verify_keys": "$VERIFY_HERE"}})
    assert cfg.key_ids == (a.kid,)


def test_the_private_key_is_redacted_and_the_public_keys_are_not():
    a = _pair()
    policy = Policy(raw={"overrides": {"signing_key": a.private, "verify_keys": [a.public]}})
    shown = redacted(policy)
    blob = json.dumps(shown)
    assert a.private not in blob
    assert shown["overrides"]["signing_key"] == "<redacted>"
    assert shown["overrides"]["verify_keys"] == [a.public]


# -- signing ---------------------------------------------------------------


def test_sign_then_verify_round_trips():
    a = _pair()
    key = sig.parse_signing_key(a.private)
    signed = sig.sign(_record(), key)
    assert signed[sig.SIGNATURE_FIELD]["alg"] == "Ed25519"
    assert signed[sig.SIGNATURE_FIELD]["kid"] == a.kid
    assert sig.verify(signed, [sig.parse_verify_key(a.public)]) == a.kid


def test_the_signature_ignores_key_order_and_itself():
    key = Ed25519PrivateKey.generate()
    signed = sig.sign(_record(), key)
    reordered = dict(reversed(list(signed.items())))
    assert sig.verify(reordered, [key.public_key()])
    # Re-signing a signed record replaces the signature rather than covering it.
    assert sig.canonical(sig.sign(signed, key)) == sig.canonical(_record())


def test_any_listed_key_verifies_and_an_unlisted_one_does_not():
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    signed = sig.sign(_record(), old)
    assert sig.verify(signed, [new.public_key(), old.public_key()])
    with pytest.raises(sig.SignatureError, match="not a configured verify key"):
        sig.verify(signed, [new.public_key()])


def test_tampering_is_detected():
    key = Ed25519PrivateKey.generate()
    signed = sig.sign(_record(), key)
    for field, value in (("new_value", "observe"), ("revision", 4), ("extra", True)):
        with pytest.raises(sig.SignatureError, match="does not verify"):
            sig.verify({**signed, field: value}, [key.public_key()])
    nested = json.loads(json.dumps(signed))
    nested["principal"]["groups"].append("root")
    with pytest.raises(sig.SignatureError):
        sig.verify(nested, [key.public_key()])


def test_a_forged_kid_does_not_help():
    real, forger = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    forged = sig.sign(_record(), forger)
    forged[sig.SIGNATURE_FIELD]["kid"] = sig.key_id(real.public_key())
    with pytest.raises(sig.SignatureError, match="does not verify"):
        sig.verify(forged, [real.public_key()])


@pytest.mark.parametrize("field", [
    None,
    "a string",
    {"alg": "HS256", "kid": "x", "sig": "x"},
    {"alg": "Ed25519", "kid": None, "sig": "x"},
])
def test_missing_or_malformed_signatures_are_refused(field):
    key = Ed25519PrivateKey.generate()
    record = dict(_record())
    if field is not None:
        record[sig.SIGNATURE_FIELD] = field
    with pytest.raises(sig.SignatureError):
        sig.verify(record, [key.public_key()])


@pytest.mark.parametrize("value", ["", "!!", sig.encode(b"\x00" * 63), 7])
def test_a_malformed_signature_value_is_refused(value):
    key = Ed25519PrivateKey.generate()
    signed = sig.sign(_record(), key)
    signed[sig.SIGNATURE_FIELD]["sig"] = value
    with pytest.raises(sig.SignatureError):
        sig.verify(signed, [key.public_key()])


def test_values_json_cannot_hold_natively_are_refused():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):
        sig.sign({"x": float("nan")}, key)
    with pytest.raises(TypeError):
        sig.sign({"x": object()}, key)


# -- keygen ----------------------------------------------------------------


def test_keygen_requires_a_private_key_destination(capsys):
    with pytest.raises(SystemExit) as exit_:
        main(["overrides", "keygen"])
    assert exit_.value.code == 2
    assert "--private-key-stdout" in capsys.readouterr().err


def test_keygen_refuses_both_destinations(tmp_path, capsys):
    with pytest.raises(SystemExit):
        main(["overrides", "keygen", "--private-key-stdout",
              "--private-key-file", str(tmp_path / "k")])
    assert not (tmp_path / "k").exists()


def test_keygen_to_stdout_prints_a_working_pair(capsys):
    assert main(["overrides", "keygen", "--private-key-stdout"]) == 0
    out = json.loads(capsys.readouterr().out)
    private = sig.parse_signing_key(out["private_key"])
    public = sig.parse_verify_key(out["public_key"])
    assert sig.key_id(public) == sig.key_id(private.public_key()) == out["key_id"]
    assert sig.verify(sig.sign(_record(), private), [public]) == out["key_id"]


def test_keygen_to_a_file_writes_0600_and_prints_only_the_public_key(tmp_path, capsys):
    path = tmp_path / "overrides.key"
    old = os.umask(0)
    try:
        assert main(["overrides", "keygen", "--private-key-file", str(path)]) == 0
    finally:
        os.umask(old)
    captured = capsys.readouterr()
    out = json.loads(captured.out)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    private_text = path.read_text().strip()
    private = sig.parse_signing_key(private_text)
    assert "private_key" not in out
    assert private_text not in captured.out + captured.err
    assert out["private_key_file"] == str(path)
    assert sig.key_id(private.public_key()) == out["key_id"]
    assert sig.parse_verify_key(out["public_key"])


def test_keygen_never_overwrites_a_file(tmp_path, capsys):
    path = tmp_path / "overrides.key"
    path.write_text("existing\n")
    assert main(["overrides", "keygen", "--private-key-file", str(path)]) == 2
    assert path.read_text() == "existing\n"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "exists" in captured.err


def test_keygen_needs_no_store_or_policy(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORGD_VERDICT_STORE", raising=False)
    assert main(["overrides", "keygen", "--private-key-stdout"]) == 0


# -- request records, writer side -----------------------------------------


def _signed_requests(store):
    import hashlib

    from forgd_verdict import overrides as ov

    out = {}
    for name in store.list_audit():
        if not name.endswith("-request.json"):
            continue
        blob = store.get_audit(name)
        out[json.loads(blob)["id"]] = (json.loads(blob), hashlib.sha256(blob).hexdigest())
    assert out
    state = ov.parse_state(store.read_control().body)
    return out, state


def test_init_change_and_checkpoint_records_are_signed_and_the_object_names_the_signed_bytes(
        tmp_path, monkeypatch):
    from conftest import DETECTORS

    from forgd_verdict import overrides as ov
    from forgd_verdict.store import LocalFileStore

    monkeypatch.setattr(ov, "CHECKPOINT_EVERY", 2)
    store = LocalFileStore(tmp_path / "store", instance="t")
    key = Ed25519PrivateKey.generate()
    actor = {"issuer": "https://idp.example/", "subject": "s", "name": "a.person",
             "via_group": "ops", "verified": True}
    ov.apply_change(store, actor, ov.Change(ov.ACTION_INIT), detectors=DETECTORS,
                    signing_key=key)
    for i in range(4):
        ov.apply_change(store, actor, ov.Change(ov.ACTION_EXCLUDE, value=f"req_{i}"),
                        detectors=DETECTORS, signing_key=key)

    records, state = _signed_requests(store)
    actions = {r["action"] for r, _ in records.values()}
    assert {ov.ACTION_INIT, ov.ACTION_EXCLUDE, ov.ACTION_CHECKPOINT} <= actions
    for record, _ in records.values():
        assert sig.verify(record, [key.public_key()]) == sig.key_id(key.public_key())
    # The object's hash is of the stored, signed bytes.
    head, digest = records[state.audit_id]
    assert sig.SIGNATURE_FIELD in head and state.audit_hash == digest
    # Each link names its parent's signed bytes too.
    for record, _ in records.values():
        if record.get("base_audit_id") in records:
            assert record["base_hash"] == records[record["base_audit_id"]][1]
    # The unchanged readers still accept the signed chain.
    assert ov.verify_head(store, state)["id"] == state.audit_id


def test_without_a_key_records_are_written_unsigned(tmp_path):
    from conftest import DETECTORS

    from forgd_verdict import overrides as ov
    from forgd_verdict.store import LocalFileStore

    store = LocalFileStore(tmp_path / "store", instance="t")
    ov.apply_change(store, {"name": "cli"}, ov.Change(ov.ACTION_INIT), detectors=DETECTORS)
    records, _ = _signed_requests(store)
    assert all(sig.SIGNATURE_FIELD not in r for r, _ in records.values())


# -- request records, reader side -----------------------------------------

_ACTOR = {"issuer": "https://idp.example/", "subject": "s", "name": "a.person",
          "via_group": "ops", "verified": True}


def _chain_store(tmp_path):
    from forgd_verdict.store import LocalFileStore

    return LocalFileStore(tmp_path / "store", instance="t")


def _apply(store, change, key):
    from conftest import DETECTORS

    from forgd_verdict import overrides as ov

    return ov.apply_change(store, _ACTOR, change, detectors=DETECTORS, signing_key=key)


def _reader(store, keys):
    from forgd_verdict import overrides as ov

    return ov.RuntimeOverrides(store, "test", baseline={ov.KEY_MODE: "observe"},
                               clock=lambda: 1000.0, verify_keys=keys)


def _mode(value):
    from forgd_verdict import overrides as ov

    return ov.Change(ov.ACTION_SET, ov.KEY_MODE, value)


def test_a_signed_chain_is_adopted(tmp_path):
    from forgd_verdict import overrides as ov

    good = Ed25519PrivateKey.generate()
    store = _chain_store(tmp_path)
    _apply(store, ov.Change(ov.ACTION_INIT), good)
    _apply(store, _mode("enforce"), good)
    snap = _reader(store, [good.public_key()]).refresh()
    assert (snap.source, snap.status, snap.ready) == ("object", "ok", True)
    assert snap.state.overrides[ov.KEY_MODE].value == "enforce"


@pytest.mark.parametrize("forger", ["unsigned", "unlisted"])
def test_a_forged_head_with_a_correct_hash_is_refused(tmp_path, forger):
    """The forger writes a well-formed record and an object whose audit_hash
    is that record's SHA-256, as anyone with write access to the store can."""
    from forgd_verdict import overrides as ov

    good = Ed25519PrivateKey.generate()
    rogue = None if forger == "unsigned" else Ed25519PrivateKey.generate()
    store = _chain_store(tmp_path)
    _apply(store, ov.Change(ov.ACTION_INIT), good)
    _apply(store, _mode("observe"), good)
    warm = _reader(store, [good.public_key()])
    assert warm.refresh().status == "ok"

    _apply(store, _mode("enforce"), rogue)
    # The hashes are consistent: only the signature is wrong.
    assert ov.verify_head(store, ov.parse_state(store.read_control().body))

    snap = warm.refresh()
    assert (snap.source, snap.status) == ("last_known_good", "invalid")
    assert snap.error == "chain_signature_invalid"
    assert snap.state.overrides[ov.KEY_MODE].value == "observe"
    cold = _reader(store, [good.public_key()]).refresh()
    assert (cold.source, cold.status, cold.ready) == ("baseline", "invalid", False)
    assert cold.error == "chain_signature_invalid"


def test_a_forged_ancestor_is_refused(tmp_path):
    """A signed head does not vouch for the chain behind it."""
    from forgd_verdict import overrides as ov

    good, rogue = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    store = _chain_store(tmp_path)
    _apply(store, ov.Change(ov.ACTION_INIT), rogue)
    _apply(store, _mode("enforce"), good)
    _apply(store, _mode("observe"), good)
    state = ov.parse_state(store.read_control().body)
    assert ov.verify_head(store, state, [good.public_key()])
    cold = _reader(store, [good.public_key()]).refresh()
    assert (cold.status, cold.ready, cold.error) == ("invalid", False, "chain_signature_invalid")


def test_any_listed_signer_is_accepted_and_an_unlisted_one_is_not(tmp_path):
    from forgd_verdict import overrides as ov

    a, b, other = (Ed25519PrivateKey.generate() for _ in range(3))
    store = _chain_store(tmp_path)
    _apply(store, ov.Change(ov.ACTION_INIT), a)
    _apply(store, _mode("enforce"), b)
    assert _reader(store, [a.public_key(), b.public_key()]).refresh().status == "ok"
    assert _reader(store, [b.public_key(), other.public_key()]).refresh().error == (
        "chain_signature_invalid")
    assert _reader(store, []).refresh().error == "chain_signature_invalid"


def test_without_verify_keys_the_reader_is_unchanged(tmp_path):
    from forgd_verdict import overrides as ov

    store = _chain_store(tmp_path)
    _apply(store, ov.Change(ov.ACTION_INIT), None)
    _apply(store, _mode("enforce"), None)
    assert _reader(store, None).refresh().status == "ok"


# -- production readers: reader_for ---------------------------------------

_ON = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}}}


class _NoReads:
    """A store that fails the test if anything reads it."""

    def __getattr__(self, name):
        if name in ("read_control", "get_audit", "list_audit", "audit_days", "put_audit",
                    "write_control",
                    "put_lockout_probe", "get_lockout", "list_lockout"):
            def boom(*a, **k):
                raise AssertionError(f"the store was touched: {name}")
            return boom
        raise AttributeError(name)


def _signed_store(tmp_path, key):
    from forgd_verdict import overrides as ov

    store = _chain_store(tmp_path)
    _apply(store, ov.Change(ov.ACTION_INIT), key)
    _apply(store, _mode("enforce"), key)
    return store


def test_feature_off_readers_are_unchanged(tmp_path, control_identity, monkeypatch):
    from forgd_verdict import overrides as ov

    monkeypatch.delenv(sig.ENV_VERIFY_KEY)
    reader = ov.reader_for({}, _NoReads(), "verdict")
    assert reader.store is None and reader.verify_keys is None and reader.key_error is None
    assert reader.refresh() == ov.BASELINE_ONLY


@pytest.mark.parametrize("verify", [None, "", "not-a-key", "AAAA,"])
def test_a_cold_reader_without_a_valid_verify_key_is_not_ready_and_reads_nothing(
        control_identity, caplog, verify):
    import logging

    from forgd_verdict import overrides as ov

    raw = dict(_ON)
    if verify is not None:
        raw["overrides"] = {"verify_keys": verify}
    with caplog.at_level(logging.ERROR):
        reader = ov.reader_for(raw, _NoReads(), "verdict", lockout=None, fleet=None)
        snap = reader.refresh()
    assert (snap.source, snap.status, snap.ready) == ("baseline", "disabled", False)
    assert snap.error == ov.ERROR_VERIFY_KEY
    assert snap.in_error
    assert ov.readiness(reader)[0] == 503
    assert any(getattr(r, "fields", {}).get("error") == ov.ERROR_VERIFY_KEY
               for r in caplog.records if r.levelno == logging.ERROR)


def test_the_reader_log_never_holds_key_material(control_identity, caplog):
    import logging

    from forgd_verdict import overrides as ov

    pair = _pair()
    # A private key where the public one belongs, and a truncated public key.
    for bad in (pair.private + "x", pair.public[:-2]):
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            ov.reader_for({**_ON, "overrides": {"verify_keys": [bad]}}, _NoReads(), "verdict",
                          lockout=None, fleet=None).refresh()
        blob = json.dumps([[r.getMessage(), getattr(r, "fields", None)] for r in caplog.records],
                          default=str)
        assert pair.private[:12] not in blob and pair.public[:12] not in blob


def test_a_valid_verify_key_adopts_a_signed_chain(tmp_path, control_identity):
    from forgd_verdict import overrides as ov

    key = Ed25519PrivateKey.generate()
    store = _signed_store(tmp_path, key)
    public = sig.encode(key.public_key().public_bytes(sig.Encoding.Raw, sig.PublicFormat.Raw))
    reader = ov.reader_for({**_ON, "overrides": {"verify_keys": [public]}}, store, "verdict",
                           lockout=None, fleet=None)
    snap = reader.refresh()
    assert (snap.source, snap.status, snap.ready) == ("object", "ok", True)
    assert reader.key_error is None and len(reader.verify_keys) == 1


def test_a_warm_reader_keeps_its_last_known_good_when_its_keys_go_bad(tmp_path, control_identity):
    from forgd_verdict import overrides as ov

    key = Ed25519PrivateKey.generate()
    store = _signed_store(tmp_path, key)
    reader = _reader(store, [key.public_key()])
    assert reader.refresh().source == "object"
    reader.set_verify_keys((), error=ov.ERROR_VERIFY_KEY)
    snap = reader.refresh()
    assert (snap.source, snap.status, snap.ready) == ("last_known_good", "disabled", True)
    assert snap.error == ov.ERROR_VERIFY_KEY
    assert snap.state.overrides[ov.KEY_MODE].value == "enforce"


# -- production writers ----------------------------------------------------


def _cli(tmp_path, *argv):
    policy = tmp_path / "admins.json"
    policy.write_text(json.dumps(_ON))
    return main(["--policy", str(policy), "overrides", "--store", str(tmp_path / "s"), *argv])


def test_the_cli_signs_every_record_with_the_configured_key(tmp_path, control_identity,
                                                           signing_env, capsys):
    from conftest import OVERRIDES_KEY_TEXT, OVERRIDES_PUBLIC

    from forgd_verdict.store import LocalFileStore

    assert _cli(tmp_path, "init") == 0
    assert _cli(tmp_path, "set", "server.mode", "enforce") == 0
    store = LocalFileStore(tmp_path / "s")
    records = [json.loads(store.get_audit(n)) for n in store.list_audit()
               if n.endswith("-request.json")]
    assert len(records) == 2
    for record in records:
        assert sig.verify(record, [OVERRIDES_PUBLIC])
    for name in store.list_audit():
        assert OVERRIDES_KEY_TEXT not in store.get_audit(name).decode()
    assert OVERRIDES_KEY_TEXT not in "".join(capsys.readouterr())


@pytest.mark.parametrize("value", [None, "not-a-key"])
def test_the_cli_refuses_to_write_without_a_valid_signing_key(tmp_path, control_identity,
                                                              monkeypatch, capsys, value):
    if value is None:
        monkeypatch.delenv(sig.ENV_SIGNING_KEY, raising=False)
    else:
        monkeypatch.setenv(sig.ENV_SIGNING_KEY, value)
    assert _cli(tmp_path, "init") == 2
    err = capsys.readouterr().err
    assert sig.ENV_SIGNING_KEY in err
    assert not (tmp_path / "s").exists() or not any((tmp_path / "s").rglob("*-request.json"))


def test_the_dashboard_does_not_start_without_a_signing_key(control_identity, monkeypatch):
    from conftest import OVERRIDES_KEY_TEXT, OVERRIDES_PUBLIC_TEXT

    from forgd_verdict.dashboard.app import _require_signing_key

    raw = {**_ON, "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}
    with pytest.raises(ValueError, match=sig.ENV_SIGNING_KEY):
        _require_signing_key(raw)
    with pytest.raises(sig.KeyConfigError):
        _require_signing_key({**raw, "overrides": {**raw["overrides"], "signing_key": "x"}})
    with pytest.raises(sig.KeyConfigError):
        _require_signing_key({**raw, "overrides": {**raw["overrides"],
                                                   "signing_key": OVERRIDES_KEY_TEXT}})
    monkeypatch.setenv(sig.ENV_SIGNING_KEY, OVERRIDES_KEY_TEXT)
    _require_signing_key(raw)


def test_create_app_refuses_without_a_signing_key(tmp_path, control_identity, monkeypatch):
    from conftest import OVERRIDES_PUBLIC_TEXT

    from forgd_verdict.dashboard.app import create_app

    monkeypatch.delenv(sig.ENV_SIGNING_KEY, raising=False)
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({
        "dashboard": {
            "auth": {"mode": "oidc_jwt", "header": "authorization",
                     "jwks_url": "https://example.invalid/keys",
                     "issuer": "https://login.example/v2.0", "audience": "api://dash"},
            "admins": {"groups": [{"group": "ops"}],
                       "allowed_origins": ["https://dash.example.com"],
                       "form_key": "k" * 40}},
        "overrides": {"verify_keys": [OVERRIDES_PUBLIC_TEXT]}}))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))
    with pytest.raises(ValueError, match=sig.ENV_SIGNING_KEY):
        create_app(str(tmp_path / "s"))


# -- writers, recovery and history verify too -----------------------------


def _apply_v(store, change, key, verify, **kw):
    from conftest import DETECTORS

    from forgd_verdict import overrides as ov

    return ov.apply_change(store, _ACTOR, change, detectors=DETECTORS, signing_key=key,
                           verify_keys=verify, **kw)


def test_a_writer_does_not_build_on_a_forged_head(tmp_path):
    """Re-signing a forged head would launder it."""
    from forgd_verdict import overrides as ov

    good, rogue = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    listed = [good.public_key()]
    store = _chain_store(tmp_path)
    _apply_v(store, ov.Change(ov.ACTION_INIT), good, listed)
    _apply(store, _mode("enforce"), rogue)
    before = sorted(store.list_audit())
    with pytest.raises(ov.InvalidState) as err:
        _apply_v(store, _mode("observe"), good, listed)
    assert err.value.code == "chain_signature_invalid"
    assert sorted(store.list_audit()) == before


def test_recover_keeps_the_newest_signed_chain_not_a_forged_one(tmp_path):
    from forgd_verdict import overrides as ov

    good, rogue = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    listed = [good.public_key()]
    store = _chain_store(tmp_path)
    _apply_v(store, ov.Change(ov.ACTION_INIT), good, listed)
    _apply_v(store, _mode("enforce"), good, listed)
    _apply(store, _mode("observe"), rogue)
    _apply_v(store, ov.Change(ov.ACTION_RECOVER), good, listed)
    snap = _reader(store, listed).refresh()
    assert (snap.status, snap.ready) == ("ok", True)
    assert snap.state.overrides[ov.KEY_MODE].value == "enforce"


def test_history_marks_an_unsigned_link_tampered(tmp_path):
    from forgd_verdict import overrides as ov

    good = Ed25519PrivateKey.generate()
    store = _chain_store(tmp_path)
    _apply(store, ov.Change(ov.ACTION_INIT), None)
    applied = _apply(store, _mode("enforce"), good)
    shown = ov.history(store, applied.state, verify_keys=[good.public_key()])
    init_id = [r["id"] for r in shown.applied if r["action"] == ov.ACTION_INIT]
    assert shown.tampered == frozenset(init_id)
    assert ov.history(store, applied.state).tampered == frozenset()



# -- rotation ---------------------------------------------------------------


def _kids(store):
    from forgd_verdict import overrides as ov

    out = []
    for name in sorted(store.list_audit()):
        if name.endswith("-request.json"):
            r = json.loads(store.get_audit(name))
            out.append((r["action"], r.get(sig.SIGNATURE_FIELD, {}).get("kid")))
    return out, ov


def test_rotation_writes_a_checkpoint_under_the_new_key_then_the_old_key_can_go(tmp_path):
    """The chain was signed by `old`, is retired by a migration `old` signed,
    and carries an override. After one change under `new`, a reader listing
    only `new` adopts it all."""
    from forgd_verdict import overrides as ov

    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    both = [old.public_key(), new.public_key()]
    store = _chain_store(tmp_path)
    _apply_v(store, ov.Change(ov.ACTION_INIT), old, [old.public_key()])
    _apply_v(store, ov.Change(ov.ACTION_MIGRATE), old, [old.public_key()],
             migrate=(None, frozenset({"req_legacy"})))
    _apply_v(store, _mode("enforce"), old, [old.public_key()])
    # Only `new` cannot read the chain yet.
    assert _reader(store, [new.public_key()]).refresh().error == "chain_signature_invalid"

    _apply_v(store, ov.Change(ov.ACTION_EXCLUDE, value="req_1"), new, both)
    records, _ = _kids(store)
    new_kid, old_kid = sig.key_id(new.public_key()), sig.key_id(old.public_key())
    assert sorted(a for a, k in records if k == new_kid) == sorted(
        [ov.ACTION_CHECKPOINT, ov.ACTION_EXCLUDE])

    snap = _reader(store, [new.public_key()]).refresh()
    assert (snap.status, snap.ready) == ("ok", True), snap.error
    assert snap.state.overrides[ov.KEY_MODE].value == "enforce"
    assert snap.state.legacy_markers_retired
    assert snap.state.excluded_requests == {"req_legacy", "req_1"}
    # A later change, a checkpoint included, needs only the new key.
    before = len(records)
    _apply_v(store, _mode("observe"), new, [new.public_key()])
    records, _ = _kids(store)
    assert len(records) == before + 1
    assert sum(k == new_kid for _, k in records) == 3
    assert old_kid in {k for _, k in records}


def test_rotation_checkpoints_again_under_a_later_checkpoint(tmp_path, monkeypatch):
    """A regular checkpoint after the old key is gone still carries the
    retirement: its migration is vouched for by the rotation checkpoint."""
    from forgd_verdict import overrides as ov

    monkeypatch.setattr(ov, "CHECKPOINT_EVERY", 2)
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    store = _chain_store(tmp_path)
    _apply_v(store, ov.Change(ov.ACTION_INIT), old, [old.public_key()])
    _apply_v(store, ov.Change(ov.ACTION_MIGRATE), old, [old.public_key()],
             migrate=(None, frozenset()))
    _apply_v(store, ov.Change(ov.ACTION_EXCLUDE, value="req_0"), new,
             [old.public_key(), new.public_key()])
    for i in range(1, 6):
        _apply_v(store, ov.Change(ov.ACTION_EXCLUDE, value=f"req_{i}"), new, [new.public_key()])
    snap = _reader(store, [new.public_key()]).refresh()
    assert (snap.status, snap.ready) == ("ok", True), snap.error
    assert snap.state.legacy_markers_retired
    assert snap.state.excluded_requests == {f"req_{i}" for i in range(6)}


def test_no_rotation_checkpoint_without_verify_keys(tmp_path):
    """An unverified head is never re-signed."""
    from forgd_verdict import overrides as ov

    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    store = _chain_store(tmp_path)
    _apply(store, ov.Change(ov.ACTION_INIT), old)
    _apply(store, _mode("enforce"), new)
    records, _ = _kids(store)
    assert ov.ACTION_CHECKPOINT not in {a for a, _ in records}


# -- outcome records decide nothing ---------------------------------------


def _timeout_after_commit(store, monkeypatch):
    """The object write commits, then the call raises as a timeout would."""
    real = store.write_control

    def commit_then_time_out(body, etag):
        real(body, etag)
        raise TimeoutError("the response was lost")

    monkeypatch.setattr(store, "write_control", commit_then_time_out)
    return lambda: monkeypatch.setattr(store, "write_control", real)


def _outcome_of(store, audit_id):
    from forgd_verdict import overrides as ov

    return json.loads(store.get_audit(ov.audit_name(audit_id, "outcome")))


def _newest_request(store, action):
    records = [json.loads(store.get_audit(n)) for n in store.list_audit()
               if n.endswith("-request.json")]
    return [r for r in records if r["action"] == action][-1]


def _break_object(store):
    from forgd_verdict import overrides as ov

    raw = json.loads(store.read_control().body)
    raw["version"] = 99
    (store.root / "state" / "runtime-overrides.json").write_text(json.dumps(raw))
    return ov


@pytest.mark.parametrize("damage", ["invalid", "deleted"])
def test_a_mode_change_that_timed_out_after_commit_is_kept_by_recover(
        tmp_path, monkeypatch, damage):
    """Mutation: skip a recover candidate whose outcome is not `applied`."""
    from forgd_verdict import overrides as ov

    key = Ed25519PrivateKey.generate()
    keys = [key.public_key()]
    store = _chain_store(tmp_path)
    _apply_v(store, ov.Change(ov.ACTION_INIT), key, keys)
    restore = _timeout_after_commit(store, monkeypatch)
    with pytest.raises(TimeoutError):
        _apply_v(store, _mode("enforce"), key, keys)
    restore()
    record = _newest_request(store, ov.ACTION_SET)
    outcome = _outcome_of(store, record["id"])
    assert outcome["result"] == "unknown"
    assert sig.verify(outcome, keys)
    assert _reader(store, keys).refresh().state.overrides[ov.KEY_MODE].value == "enforce"

    if damage == "invalid":
        _break_object(store)
    else:
        (store.root / "state" / "runtime-overrides.json").unlink()
    applied = _apply_v(store, ov.Change(ov.ACTION_RECOVER), key, keys)
    assert applied.state.overrides[ov.KEY_MODE].value == "enforce"


def test_a_migration_that_timed_out_after_commit_still_retires(tmp_path, monkeypatch):
    """A later checkpoint and a recover both carry the retirement.
    Mutation: refuse a migration whose outcome is not `applied`."""
    from forgd_verdict import overrides as ov

    monkeypatch.setattr(ov, "CHECKPOINT_EVERY", 2)
    key = Ed25519PrivateKey.generate()
    keys = [key.public_key()]
    store = _chain_store(tmp_path)
    _apply_v(store, ov.Change(ov.ACTION_INIT), key, keys)
    restore = _timeout_after_commit(store, monkeypatch)
    with pytest.raises(TimeoutError):
        _apply_v(store, ov.Change(ov.ACTION_MIGRATE), key, keys,
                 migrate=(None, frozenset({"req_legacy"})))
    restore()
    migration = _newest_request(store, ov.ACTION_MIGRATE)
    assert _outcome_of(store, migration["id"])["result"] == "unknown"
    for i in range(3):
        _apply_v(store, ov.Change(ov.ACTION_EXCLUDE, value=f"req_{i}"), key, keys)
    checkpoint = _newest_request(store, ov.ACTION_CHECKPOINT)
    assert checkpoint["retired_by"]["id"] == migration["id"]
    snap = _reader(store, keys).refresh()
    assert snap.status == "ok" and snap.state.legacy_markers_retired

    _break_object(store)
    applied = _apply_v(store, ov.Change(ov.ACTION_RECOVER), key, keys)
    assert applied.state.legacy_markers_retired
    assert applied.state.retired_by == migration["id"]


def test_a_refusal_before_commit_is_the_only_error_outcome(tmp_path, monkeypatch):
    """Mutation: write `error` for an unknown failure."""
    from forgd_verdict import overrides as ov

    key = Ed25519PrivateKey.generate()
    for exc, result in ((ov.StoreForbidden("denied"), "error"),
                        (ov.StoreConflict("raced"), "conflict"),
                        (OSError("503"), "unknown")):
        store = _chain_store(tmp_path / result)
        _apply_v(store, ov.Change(ov.ACTION_INIT), key, [key.public_key()])

        def fail(body, etag, exc=exc):
            raise exc

        before = set(store.list_audit())
        monkeypatch.setattr(store, "write_control", fail)
        with pytest.raises(type(exc)):
            _apply_v(store, _mode("enforce"), key, [key.public_key()])
        [name] = [n for n in set(store.list_audit()) - before if n.endswith("-request.json")]
        assert _outcome_of(store, json.loads(store.get_audit(name))["id"])["result"] == result
        monkeypatch.undo()


def test_recover_keeps_the_racing_record_whose_write_was_applied(tmp_path, monkeypatch):
    """Two records on the same base, the object deleted: neither is built on
    and the object is gone. Recover kept their base, losing the winner's
    change; the winner's signed `applied` outcome says which one committed.
    With that outcome lost too, recover refuses, and keeps the record left
    once the other is deleted."""
    from forgd_verdict import overrides as ov

    key = Ed25519PrivateKey.generate()
    keys = [key.public_key()]
    store = _chain_store(tmp_path)
    _apply_v(store, ov.Change(ov.ACTION_INIT), key, keys)
    _apply_v(store, _mode("observe"), key, keys)
    real_put = store.put_audit

    def racing(name, body):
        if name.endswith("-request.json"):
            monkeypatch.setattr(store, "put_audit", real_put)
            _apply_v(store, ov.Change(ov.ACTION_EXCLUDE, value="req_winner"), key, keys)
        return real_put(name, body)

    monkeypatch.setattr(store, "put_audit", racing)
    with pytest.raises(ov.StoreConflict):
        _apply_v(store, _mode("enforce"), key, keys)
    monkeypatch.undo()
    [loser] = [json.loads(store.get_audit(n)) for n in store.list_audit()
               if n.endswith("-request.json")
               and json.loads(store.get_audit(n))["new_value"] == "enforce"]
    store.root.joinpath(AUDIT_PREFIX, ov.audit_name(loser["id"], "outcome")).unlink()
    control = store.root / "state" / "runtime-overrides.json"
    winner = json.loads(control.read_bytes())["audit_id"]
    control.unlink()
    applied = _apply_v(store, ov.Change(ov.ACTION_RECOVER), key, keys)
    assert applied.state.overrides[ov.KEY_MODE].value == "observe"
    assert applied.state.excluded_requests == frozenset({"req_winner"})

    control.unlink()
    store.root.joinpath(AUDIT_PREFIX, ov.audit_name(applied.audit_id, "request")).unlink()
    store.root.joinpath(AUDIT_PREFIX, ov.audit_name(applied.audit_id, "outcome")).unlink()
    store.root.joinpath(AUDIT_PREFIX, ov.audit_name(winner, "outcome")).unlink()
    with pytest.raises(ov.Refused) as exc:
        _apply_v(store, ov.Change(ov.ACTION_RECOVER), key, keys)
    assert str(exc.value) == ov.REFUSED_HEAD_AMBIGUOUS
    store.root.joinpath(AUDIT_PREFIX, ov.audit_name(loser["id"], "request")).unlink()
    applied = _apply_v(store, ov.Change(ov.ACTION_RECOVER), key, keys)
    assert applied.state.excluded_requests == frozenset({"req_winner"})


def test_a_signed_record_built_on_an_unapplied_migration_does_not_retire_a_recovery(
        tmp_path, monkeypatch):
    """The migration conflicted; a signed record off the chain names it by
    hash as its base and says the markers are retired. Recover writes
    nothing: it cannot verify that retirement, and it does not drop one a
    signed record states. Mutations: count such a record as evidence the
    migration was applied; drop the retired-request check in _recovered."""
    from forgd_verdict import overrides as ov

    key = Ed25519PrivateKey.generate()
    keys = [key.public_key()]
    store = _chain_store(tmp_path)
    head = _apply_v(store, ov.Change(ov.ACTION_INIT), key, keys)
    monkeypatch.setattr(store, "write_control",
                        lambda body, etag: (_ for _ in ()).throw(ov.StoreConflict("raced")))
    with pytest.raises(ov.StoreConflict):
        _apply_v(store, ov.Change(ov.ACTION_MIGRATE), key, keys,
                 migrate=(None, frozenset({"req_legacy"})))
    monkeypatch.undo()
    migration = _newest_request(store, ov.ACTION_MIGRATE)
    stray = {k: v for k, v in migration.items() if k != "signature"}
    stray.update(id=migration["id"][:-12] + "f" * 12, action=ov.ACTION_EXCLUDE,
                 base_audit_id=migration["id"],
                 base_hash=ov._stored_hash(store, migration["id"]))
    store.put_audit(ov.audit_name(stray["id"], "request"),
                    ov._record_bytes(sig.sign(stray, key)))

    raw = json.loads(store.read_control().body)
    assert raw["audit_id"] == head.audit_id
    raw.update(version=99, **{ov.FIELD_RETIRED_BY: migration["id"]})
    (store.root / "state" / "runtime-overrides.json").write_text(json.dumps(raw))
    before = store.read_control().body, sorted(store.list_audit())
    with pytest.raises(ov.Refused) as exc:
        _apply_v(store, ov.Change(ov.ACTION_RECOVER), key, keys)
    assert str(exc.value) == ov.REFUSED_RETIREMENT_UNVERIFIED
    assert (store.read_control().body, sorted(store.list_audit())) == before
