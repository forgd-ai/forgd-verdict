"""What the S3 backend does that the conformance suite cannot see.

The shared suite pins agreement with the other backends. These pin the
S3-specific parts: the conditional write that keeps records immutable, and
telling an absent object from a failed read.
"""

from __future__ import annotations

import logging

import pytest
from test_store_conformance import S3_URL, _install_fake_boto3, _S3Error, rec

from forgd_verdict.store import open_store
from forgd_verdict.store.s3 import S3Store


@pytest.fixture
def s3(monkeypatch):
    return _install_fake_boto3(monkeypatch)


def test_open_store_dispatches_s3(s3):
    store = open_store(S3_URL, instance="t")
    assert isinstance(store, S3Store)
    assert (store.bucket, store.prefix) == ("forgd-findings", "demo")


@pytest.mark.parametrize("url", ["s3://", "s3:///prefix", "gs://b/p"])
def test_a_malformed_spec_is_refused(url, s3):
    with pytest.raises(ValueError):
        S3Store(url)


def test_records_are_written_conditionally_and_state_is_not(s3):
    store = s3.make_store("t")
    store.write_verdicts([rec()])
    store.put_state("cursor.json", b"{}")
    store.set_reset_marker("2026-09-26T00:00:00Z")
    by_key = {p["Key"]: p["IfNoneMatch"] for p in s3.clients[-1].puts}
    records = [k for k in by_key if k.endswith(".jsonl")]
    assert records and all(by_key[k] == "*" for k in records)
    assert all(v is None for k, v in by_key.items() if not k.endswith(".jsonl"))


def test_two_writers_with_one_instance_id_fail_rather_than_overwrite(s3):
    """The immutability the conformance suite's concurrent-writer test relies
    on: without If-None-Match the second write silently replaces the first."""
    a, b = s3.make_store("same"), s3.make_store("same")
    a.write_verdicts([rec(request_id="first")])
    with pytest.raises(_S3Error, match="PreconditionFailed"):
        b.write_verdicts([rec(request_id="second")])
    assert [r.request_id for r in a.read_verdicts()] == ["first"]


def _lose_put_responses(store, monkeypatch):
    """Each conditional put commits, then the caller sees 412: what botocore's
    retry reports after S3 committed the first attempt and lost the reply."""
    real_put = store._client.put_object

    def put(**kw):
        real_put(**kw)
        if kw.get("IfNoneMatch") == "*":
            raise _S3Error("PreconditionFailed")

    monkeypatch.setattr(store._client, "put_object", put)


def test_a_lost_put_response_is_not_a_failed_write(s3, monkeypatch):
    """Raised, the 412 fails the batch and the caller writes it again under
    the next sequence number, counting every record twice."""
    store = s3.make_store("t")
    _lose_put_responses(store, monkeypatch)
    assert store.write_verdicts([rec(request_id="once")]) == 1
    assert [r.request_id for r in store.read_verdicts()] == ["once"]


def test_a_412_whose_object_cannot_be_read_stands(s3, monkeypatch):
    store = s3.make_store("t")
    _lose_put_responses(store, monkeypatch)
    monkeypatch.setattr(store._client, "get_object",
                        lambda **kw: (_ for _ in ()).throw(_S3Error("AccessDenied")))
    with pytest.raises(_S3Error, match="PreconditionFailed"):
        store.write_verdicts([rec()])


def test_an_absent_cursor_is_a_first_run(s3):
    assert s3.make_store("t").get_state("never-written.json") is None


def test_a_cursor_that_cannot_be_read_raises(s3, monkeypatch):
    """Read as a first run, an access-denied cursor rescans the whole window
    and reports success. The cursor exists, so the 403 is a real denial."""
    store = s3.make_store("t")
    store.put_state("cursor.json", b"{}")
    monkeypatch.setattr(store._client, "get_object",
                        lambda **kw: (_ for _ in ()).throw(_S3Error("AccessDenied")))
    with pytest.raises(_S3Error, match="AccessDenied"):
        store.get_state("cursor.json")


def test_an_unreadable_marker_is_logged_not_silent(s3, monkeypatch, caplog):
    store = s3.make_store("t")
    store.set_reset_marker("2026-09-26T00:00:00Z")
    store.set_excluded({"r1"})
    monkeypatch.setattr(store._client, "get_object",
                        lambda **kw: (_ for _ in ()).throw(_S3Error("AccessDenied")))
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.store.s3"):
        assert store.get_reset_marker() is None
        assert store.get_excluded() == set()
    assert len([r for r in caplog.records if "could not read" in r.getMessage()]) == 2


def test_an_absent_marker_is_not_logged(s3, caplog):
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.store.s3"):
        assert s3.make_store("t").get_reset_marker() is None
    assert not caplog.records


def test_reads_page_through_every_listing(s3):
    """The fake lists two keys a page; eleven single-record objects span six."""
    store = s3.make_store("t")
    for i in range(11):
        store.write_verdicts([rec(request_id=f"r{i}")])
    assert len(list(store.read_verdicts())) == 11


def test_the_client_is_bounded(s3):
    s3.make_store("t")
    config = s3.clients[-1].kwargs["config"]
    assert config.kwargs["connect_timeout"] and config.kwargs["read_timeout"]


def test_describe(s3):
    d = s3.make_store("t").describe()
    assert d["backend"] == "s3" and d["bucket"] == "forgd-findings" and d["prefix"] == "demo"


def _prefix_scoped(store, monkeypatch, list_allowed=True):
    """S3 with a ListBucket scoped by s3:prefix: a GetObject of a missing key
    is answered 403, since GetObject carries no prefix for the grant to match."""
    real_get = store._client.get_object

    def get_object(**kw):
        if kw["Key"] not in store._client.objects:
            raise _S3Error("AccessDenied")
        return real_get(**kw)

    monkeypatch.setattr(store._client, "get_object", get_object)
    if not list_allowed:
        monkeypatch.setattr(store._client, "list_objects_v2",
                            lambda **kw: (_ for _ in ()).throw(_S3Error("AccessDenied")))


def test_a_missing_cursor_under_a_prefix_scoped_grant_is_a_first_run(s3, monkeypatch):
    """The EKS example sets a key prefix, and the first ingest raised here."""
    store = s3.make_store("t")
    _prefix_scoped(store, monkeypatch)
    assert store.get_state("never-written.json") is None
    assert store.get_reset_marker() is None


def test_an_existing_cursor_denied_on_read_still_raises(s3, monkeypatch):
    """The list shows the key is there, so the 403 is a real denial."""
    store = s3.make_store("t")
    store.put_state("cursor.json", b"{}")
    monkeypatch.setattr(store._client, "get_object",
                        lambda **kw: (_ for _ in ()).throw(_S3Error("AccessDenied")))
    with pytest.raises(_S3Error):
        store.get_state("cursor.json")


def test_a_403_that_cannot_be_checked_stands(s3, monkeypatch):
    store = s3.make_store("t")
    _prefix_scoped(store, monkeypatch, list_allowed=False)
    with pytest.raises(_S3Error):
        store.get_state("never-written.json")


def test_a_similar_key_does_not_count_as_the_cursor(s3, monkeypatch):
    """The list is by prefix, so `cursor.json.bak` must not read as `cursor.json`."""
    store = s3.make_store("t")
    store.put_state("cursor.json.bak", b"{}")
    _prefix_scoped(store, monkeypatch)
    assert store.get_state("cursor.json") is None
