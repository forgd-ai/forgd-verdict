"""The control identity's verification run: which identities it checks,
how a failure to read the policy is recorded, and the dashboard thread."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from forgd_verdict import lockout
from forgd_verdict.lockout_evidence import EvidenceUnavailable, verifier
from forgd_verdict.store import LocalFileStore

WRITER = "arn:aws:iam::111111111111:role/forgd-verdict-writer"
OTHER = "arn:aws:iam::111111111111:role/forgd-other-writer"


class Cloud(LocalFileStore):
    lockout_provable = True

    def __init__(self, root, kind="s3"):
        super().__init__(root, instance="t")
        self.evidence_kind = kind


@pytest.fixture(autouse=True)
def provable_only(monkeypatch):
    monkeypatch.setattr(lockout, "_unprovable_allowed", False)


def test_writer_identities_are_read_trimmed_and_deduplicated():
    env = {verifier.ENV_WRITER_IDENTITIES: f" {WRITER}, ,{OTHER},{WRITER} "}
    assert verifier.writer_identities(env) == (WRITER, OTHER)
    assert verifier.writer_identities({}) == ()


def test_a_passing_evaluation_writes_a_record_readers_trust(tmp_path):
    store = Cloud(tmp_path)
    record = verifier.verify(store, (WRITER, OTHER),
                             evaluate=lambda s, ids, **_: {i: None for i in ids})
    assert record["ok"] and record["store"] == "s3"
    assert lockout.lockout_status(store, ("verdict",)).ok


def test_a_failing_identity_is_named_with_its_reason(tmp_path):
    store = Cloud(tmp_path)
    verifier.verify(store, (WRITER, OTHER),
                    evaluate=lambda s, ids, **_: {WRITER: None, OTHER: "no_deny_for_writer"})
    assert lockout.lockout_status(store, ("verdict",)).problems == {OTHER: "no_deny_for_writer"}


def test_an_evaluation_that_raises_verifies_nothing(tmp_path, caplog):
    """Mutation: write the identities as verified when the check raises."""
    store = Cloud(tmp_path)

    def boom(*a, **k):
        raise RuntimeError(f"denied for {WRITER}")

    record = verifier.verify(store, (WRITER,), evaluate=boom)
    assert record["identities"] == {WRITER: verifier.REASON_FAILED} and not record["ok"]
    assert not lockout.lockout_status(store, ("verdict",)).ok
    assert "denied for" not in caplog.text


def test_no_configured_identity_verifies_nothing(tmp_path):
    store = Cloud(tmp_path)
    verifier.verify(store, (), evaluate=lambda s, ids, **_: {})
    assert lockout.lockout_status(store, ("verdict",)).problems == {
        "*": "no writer identities verified"}


def test_a_policy_that_cannot_be_read_is_each_identitys_reason(tmp_path, monkeypatch):
    """Mutation: treat an unreadable policy as a pass."""
    from forgd_verdict.lockout_evidence import s3

    def denied(store):
        raise EvidenceUnavailable("permission_denied")

    monkeypatch.setattr(s3, "fetch", denied)
    monkeypatch.setattr(s3, "scope", lambda store: {"bucket": "b", "prefix": ""})
    assert verifier.evaluate_store(Cloud(tmp_path), (WRITER, OTHER)) == {
        WRITER: "permission_denied", OTHER: "permission_denied"}


def test_a_local_store_cannot_be_verified(tmp_path):
    assert verifier.evaluate_store(LocalFileStore(tmp_path), (WRITER,)) == {
        WRITER: verifier.REASON_UNSUPPORTED}


def test_azure_needs_the_storage_account_id(tmp_path):
    assert verifier.evaluate_store(Cloud(tmp_path, "azure"), ("0000-a",), account_id="") == {
        "0000-a": verifier.REASON_ACCOUNT_UNSET}


ACCOUNT_ID = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"
              "/providers/Microsoft.Storage/storageAccounts/acct")
STORE_URL = "https://acct.blob.core.windows.net"
OTHER_URL = "https://forgdfindings.blob.core.windows.net"


@pytest.mark.parametrize("account_id, account_url", [
    (ACCOUNT_ID.replace("/acct", "/other"), STORE_URL),
    (ACCOUNT_ID, OTHER_URL),
    (ACCOUNT_ID + "/blobServices/default", STORE_URL),
    ("acct", STORE_URL),
    (ACCOUNT_ID, "http://127.0.0.1:10000/acct"),
    (ACCOUNT_ID, ""),
], ids=["other-account-id", "other-store-host", "child-resource", "bare-name", "emulator", "no-url"])
def test_an_account_id_that_does_not_name_the_stores_account_verifies_nothing(
        tmp_path, monkeypatch, account_id, account_url):
    """A wrong id lists another account's role assignments, where the writer
    holds none, and would show it locked out. Mutation: drop the check."""
    from forgd_verdict.lockout_evidence import azure

    monkeypatch.setattr(azure, "fetch", lambda *a, **k: pytest.fail("fetched another account"))
    store = Cloud(tmp_path, "azure")
    store.account_url = account_url
    assert verifier.evaluate_store(store, ("0000-a",), account_id=account_id) == {
        "0000-a": verifier.REASON_ACCOUNT_MISMATCH}


@pytest.mark.parametrize("account_url", [
    STORE_URL, STORE_URL + ":443", STORE_URL + "/",
    "https://acct.privatelink.blob.core.windows.net",
    "https://acct.blob.core.usgovcloudapi.net",
], ids=["public", "port", "slash", "privatelink", "sovereign"])
def test_an_account_id_naming_the_stores_account_is_evaluated(tmp_path, monkeypatch, account_url):
    from forgd_verdict.lockout_evidence import azure

    store = Cloud(tmp_path, "azure")
    store.account_url = account_url
    store.prefix = ""
    monkeypatch.setattr(azure, "fetch", lambda s, account_id, writers: {"fetched": account_id})
    monkeypatch.setattr(azure, "evaluate", lambda doc, writers, **_: {w: doc["fetched"] for w in writers})
    account_id = ACCOUNT_ID.replace("/acct", "/ACCT") + "/"
    assert verifier.evaluate_store(store, ("0000-a",), account_id=account_id) == {"0000-a": account_id}


def test_the_cloud_stores_name_their_evidence():
    from forgd_verdict.store.blob import BlobStore
    from forgd_verdict.store.gcs import GCSStore
    from forgd_verdict.store.s3 import S3Store

    assert [verifier.store_kind(c) for c in (S3Store, GCSStore, BlobStore)] == [
        "s3", "gcs", "azure"]


def test_the_thread_verifies_at_start_and_survives_a_failure(tmp_path):
    runs = []

    def run(store):
        runs.append(store)
        raise RuntimeError("once")

    v = verifier.Verifier("store", interval_s=3600, run=run)
    assert v.interval_s == lockout.VERIFY_EVERY_S
    v.once()
    v.once()
    assert runs == ["store", "store"]


def test_a_record_older_than_two_hours_is_stale(tmp_path):
    store = Cloud(tmp_path)
    then = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
    verifier.verify(store, (WRITER,), evaluate=lambda s, ids, **_: {WRITER: None}, now=then)
    later = then.replace(hour=14, second=1)
    assert lockout.lockout_status(store, ("verdict",), later).problems == {
        "*": "verification stale"}
    [name] = [n for n in store.list_audit()]
    assert json.loads(store.get_audit(name))["at"] == "2026-09-28T12:00:00Z"


def test_the_dashboard_runs_the_verifier_only_with_admins_on(tmp_path, monkeypatch):
    import test_dashboard_admin as t

    from forgd_verdict.dashboard.app import Dashboard
    from forgd_verdict.overrides import ENV_ENABLED, RuntimeOverrides

    store = LocalFileStore(tmp_path)
    auth = t._auth() if hasattr(t, "_auth") else None
    overrides = RuntimeOverrides(store, "dashboard")
    monkeypatch.setenv(ENV_ENABLED, "true")
    on = Dashboard(store, auth=auth, admins=object(), overrides=overrides)
    assert on.verifier is not None and on.verifier.store is store
    monkeypatch.delenv(ENV_ENABLED)
    off = Dashboard(store, auth=auth, admins=object(), overrides=overrides)
    assert off.verifier is None
    assert Dashboard(store, auth=auth, overrides=overrides).verifier is None
