"""Where the signing key may be, and the order a key rotation takes.

Only the dashboard (and the CLI run as the control identity) may hold
FORGD_OVERRIDES_SIGNING_KEY; every other role refuses to start with one.
The rotation order in docs/OVERRIDES.md, "Signing keys", is pinned step by
step: each step taken early leaves readers refusing. Each test names the
mutation that makes it fail.
"""

from __future__ import annotations

import json

import pytest
from conftest import DETECTORS, WHSEC, make_policy

from forgd_verdict import lockout
from forgd_verdict import overrides_signing as sig
from forgd_verdict.lockout import LockoutReports
from forgd_verdict.lockout_evidence import verifier
from forgd_verdict.overrides import (
    ACTION_INIT,
    ACTION_SET,
    KEY_MODE,
    Change,
    RuntimeOverrides,
    anchor_of,
    apply_change,
    reader_for,
    trusted_head,
    unanchored_head,
)
from forgd_verdict.store import LocalFileStore

ADMINS = {"dashboard": {"admins": {"groups": [{"group": "ops"}]}}}
ADMIN = {"issuer": "https://idp.example/", "subject": "sub-1", "name": "a.person",
         "via_group": "ops", "verified": True}
WRITER = "arn:aws:iam::111111111111:role/forgd-verdict-writer"
NOT_SIGNERS = ("verdict", "collector", "intake", "ingest", "connector")

pytestmark = pytest.mark.usefixtures("control_identity")


def _pair():
    return sig.generate()


# -- which roles may hold it ---------------------------------------------------


@pytest.mark.parametrize("role", NOT_SIGNERS)
def test_a_role_other_than_the_dashboard_refuses_a_signing_key_in_its_environment(
        tmp_path, monkeypatch, role):
    """Mutation: drop refuse_signing_key from reader_for."""
    monkeypatch.setenv(sig.ENV_SIGNING_KEY, _pair().private)
    with pytest.raises(RuntimeError, match=f"refusing to start the {role} role") as err:
        reader_for(ADMINS, LocalFileStore(tmp_path), role)
    assert sig.ENV_SIGNING_KEY in str(err.value)


@pytest.mark.parametrize("role", NOT_SIGNERS)
def test_it_refuses_one_with_runtime_overrides_off_too(tmp_path, monkeypatch, role):
    monkeypatch.setenv(sig.ENV_SIGNING_KEY, _pair().private)
    with pytest.raises(RuntimeError, match="refusing to start"):
        reader_for({}, LocalFileStore(tmp_path), role)


def test_it_refuses_one_the_policy_references(tmp_path, monkeypatch):
    """A shared policy.yaml may reference the variable: only a role that has
    it set refuses. Mutation: ignore the reference's variable."""
    raw = {**ADMINS, "overrides": {"signing_key": "$DASHBOARD_ONLY"}}
    reader_for(raw, LocalFileStore(tmp_path), "verdict")
    monkeypatch.setenv("DASHBOARD_ONLY", _pair().private)
    with pytest.raises(RuntimeError, match="refusing to start the verdict role"):
        reader_for(raw, LocalFileStore(tmp_path), "verdict")


def test_it_refuses_a_literal_in_the_policy(tmp_path):
    """Mutation: count only references as a configured key."""
    raw = {**ADMINS, "overrides": {"signing_key": _pair().private}}
    with pytest.raises(RuntimeError, match="refusing to start the collector role") as err:
        reader_for(raw, LocalFileStore(tmp_path), "collector")
    assert raw["overrides"]["signing_key"] not in str(err.value)


def test_the_dashboard_may_hold_it(tmp_path, monkeypatch):
    """Mutation: refuse every role."""
    monkeypatch.setenv(sig.ENV_SIGNING_KEY, _pair().private)
    reader_for(ADMINS, LocalFileStore(tmp_path), "dashboard")


def test_the_verdict_server_does_not_start_with_it(tmp_path, monkeypatch):
    from forgd_verdict.server.app import VerdictServer

    monkeypatch.setenv(sig.ENV_SIGNING_KEY, _pair().private)
    with pytest.raises(RuntimeError, match="refusing to start the verdict role"):
        VerdictServer(make_policy(
            detectors={"gitleaks": {"enabled": False, "severity": "block"}},
            server={"mode": "observe", "secrets": [WHSEC], "csv_path": None,
                    "store": str(tmp_path / "s"), "store_flush_s": 3600}, **ADMINS))


def test_the_connector_refuses_it_with_runtime_overrides_off(tmp_path, monkeypatch):
    """The connector builds no reader while overrides are off. Mutation:
    drop the connector's own check."""
    from forgd_verdict.connector.tools import reader_from_policy

    class Cfg:
        auth = None
        entitlements = None

    monkeypatch.setenv(sig.ENV_SIGNING_KEY, _pair().private)
    with pytest.raises(RuntimeError, match="refusing to start the connector role"):
        reader_from_policy(make_policy(), Cfg(), LocalFileStore(tmp_path))


def test_the_ingest_job_exits_2_with_it(tmp_path, monkeypatch, capsys):
    """Mutation: let the refusal raise out of the ingest command."""
    from forgd_verdict.cli import main

    monkeypatch.setenv(sig.ENV_SIGNING_KEY, _pair().private)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"compliance": {"api_key": ""}, **ADMINS}))
    assert main(["--policy", str(policy), "ingest", "--store", str(tmp_path / "s")]) == 2
    err = capsys.readouterr().err
    assert "refusing to start the ingest role" in err and "Traceback" not in err


# -- rotation ------------------------------------------------------------------


class Provable(LocalFileStore):
    lockout_provable = True


class Deployment:
    """One store, the dashboard's signing key and verify keys, and every
    other reader's verify keys, as the rotation changes them. The dashboard
    starts afresh for every change and every verification."""

    def __init__(self, root, old):
        self.store = Provable(root, instance="t")
        self.signing, self.dashboard_keys, self.reader_keys = old, [old], [old]
        self.verify()
        self.change(Change(ACTION_INIT))
        self.verify()

    def _keys(self, keys):
        return [sig.parse_verify_key(k.public) for k in keys]

    def _private(self):
        return sig.parse_signing_key(self.signing.private)

    def _dashboard(self):
        """The dashboard's verifier, over a reader that holds no state yet."""
        reader, keys = self.reader(self.dashboard_keys), self._keys(self.dashboard_keys)
        return verifier.Verifier(self.store, identities=(WRITER,),
                                 evaluate=lambda s, ids, **_: {WRITER: None},
                                 signing_key=self._private(),
                                 trusted=lambda: trusted_head(reader),
                                 unanchored=lambda: unanchored_head(self.store, keys),
                                 verify_keys=keys)

    def change(self, change):
        return apply_change(self.store, ADMIN, change, detectors=DETECTORS,
                            signing_key=self._private(),
                            verify_keys=self._keys(self.dashboard_keys),
                            after_write=self._dashboard().after_write)

    def verify(self):
        """One run of the dashboard's hourly verification."""
        return self._dashboard().once()

    def reader(self, keys=None):
        keys = self._keys(self.reader_keys if keys is None else keys)
        return RuntimeOverrides(self.store, "verdict", verify_keys=keys,
                                fleet=LockoutReports(self.store, ("verdict",), verify_keys=keys))


def _rotated(tmp_path, *, verifications=2, checkpoint=True):
    """A deployment taken through the rotation up to removing the old key:
    the new verify key added everywhere, the signing key switched, then
    `verifications` dashboard verifications and, with `checkpoint`, a change
    (which writes the new-key checkpoint first)."""
    old, new = _pair(), _pair()
    d = Deployment(tmp_path / "s", old)
    d.change(Change(ACTION_SET, KEY_MODE, "enforce"))
    d.verify()
    d.dashboard_keys = d.reader_keys = [old, new]
    d.signing = new
    if checkpoint:
        d.change(Change(ACTION_SET, KEY_MODE, "observe"))
    for _ in range(verifications):
        d.verify()
    return d, old, new


def test_the_rotation_order_ends_with_every_reader_on_the_new_key_alone(tmp_path):
    """Mutation: let the walk verify the head's ancestors past a checkpoint
    (readers would then need the old key forever)."""
    d, old, new = _rotated(tmp_path)
    d.dashboard_keys = d.reader_keys = [new]
    snap = d.reader().refresh()
    assert (snap.status, snap.ready) == ("ok", True)
    assert snap.state.value(KEY_MODE) == "observe"
    assert d.verify()["head"] == anchor_of(snap.state)
    assert d.reader().refresh().status == "ok"


def test_switching_the_signing_key_before_readers_have_it_is_refused(tmp_path):
    """Step 1 skipped: a reader holding only the old key refuses a record
    the new one signed."""
    old, new = _pair(), _pair()
    d = Deployment(tmp_path / "s", old)
    d.dashboard_keys, d.signing = [old, new], new
    d.change(Change(ACTION_SET, KEY_MODE, "enforce"))
    snap = d.reader([old]).refresh()
    assert snap.state is None and not snap.ready
    assert snap.writers == {"*": lockout.PROBLEM_VERIFY_SIGNATURE}


def test_the_dashboard_refuses_a_signing_key_its_verify_keys_lack(tmp_path, monkeypatch):
    """Steps 1 and 2 swapped on the dashboard itself."""
    old, new = _pair(), _pair()
    monkeypatch.setenv(sig.ENV_SIGNING_KEY, new.private)
    with pytest.raises(sig.KeyConfigError, match=new.kid):
        sig.from_policy({"overrides": {"verify_keys": [old.public]}})


def test_removing_the_old_key_before_the_new_key_checkpoint_is_refused(tmp_path):
    """Step 3's checkpoint not yet written: the head is still old-key
    signed."""
    d, old, new = _rotated(tmp_path, checkpoint=False)
    snap = d.reader([new]).refresh()
    assert (snap.status, snap.error) == ("invalid", "chain_signature_invalid")


def test_removing_the_old_key_after_one_new_key_verification_is_refused(tmp_path):
    """One new-key verification and no change since the switch: the newest
    record's base is old-key signed, so readers on the new key alone trust
    no verification. Mutation: stop checking the base record's signature."""
    d, old, new = _rotated(tmp_path, verifications=1, checkpoint=False)
    snap = d.reader([new]).refresh()
    assert snap.state is None and snap.writers == {"*": lockout.PROBLEM_VERIFY_SIGNATURE}
    d.change(Change(ACTION_SET, KEY_MODE, "observe"))
    assert d.reader([new]).refresh().status == "ok"


def test_the_checkpoint_change_alone_lets_readers_drop_the_old_key(tmp_path):
    """The checkpoint and the change after it each write a new-key record,
    the second based on the first, so no hourly verification is needed."""
    d, old, new = _rotated(tmp_path, verifications=0)
    snap = d.reader([new]).refresh()
    assert (snap.status, snap.state.value(KEY_MODE)) == ("ok", "observe")
