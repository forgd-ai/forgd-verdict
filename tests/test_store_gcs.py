"""What the GCS backend does that the conformance suite cannot see.

The shared suite pins agreement with the other backends. These pin the
GCS-specific parts: dispatch and spec parsing, the generation precondition
that keeps records immutable, telling an absent object from a denied read,
pagination, and the timeout and retry on every call.
"""

from __future__ import annotations

import logging
import subprocess
import sys

import pytest
from test_store_conformance import GCS_URL, _GCSError, _install_fake_gcs, rec

from forgd_verdict.store import open_store
from forgd_verdict.store.gcs import _RETRY_SECONDS, _TIMEOUT, GCSStore


@pytest.fixture
def gcs(monkeypatch):
    return _install_fake_gcs(monkeypatch)


def _deny_reads(store, monkeypatch, code: int = 403):
    """Every download answers `code`, whether or not the object exists."""
    bucket = store._bucket
    real_blob = bucket.blob

    def blob(name):
        b = real_blob(name)
        b.download_as_bytes = lambda **kw: (_ for _ in ()).throw(_GCSError(code))
        return b

    monkeypatch.setattr(bucket, "blob", blob)


# -- dispatch and spec -----------------------------------------------------


def test_open_store_dispatches_gs(gcs):
    store = open_store(GCS_URL, instance="t")
    assert isinstance(store, GCSStore)
    assert (store.bucket_name, store.prefix) == ("forgd-findings", "demo")


@pytest.mark.parametrize("url,prefix", [
    ("gs://b", ""),
    ("gs://b/", ""),
    ("gs://b/p/q/", "p/q"),
])
def test_the_prefix_is_parsed_without_stray_slashes(url, prefix, gcs):
    store = GCSStore(url, instance="t")
    assert (store.bucket_name, store.prefix) == ("b", prefix)


@pytest.mark.parametrize("url", ["gs://", "gs:///prefix", "s3://b/p", "gcs://b/p"])
def test_a_malformed_spec_is_refused(url, gcs):
    with pytest.raises(ValueError):
        GCSStore(url)


def test_the_client_uses_application_default_credentials(gcs):
    gcs.make_store("t")
    assert gcs.clients[-1].kwargs == {"project": None}


def test_importing_the_store_package_does_not_import_the_gcs_sdk():
    code = (
        "import sys, forgd_verdict.store as s; s.open_store('/tmp/x'); "
        "assert 'forgd_verdict.store.gcs' not in sys.modules; "
        "assert 'google.cloud.storage' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_a_missing_extra_names_it(monkeypatch):
    monkeypatch.setitem(sys.modules, "google.cloud.storage", None)
    monkeypatch.setitem(sys.modules, "google.cloud.storage.retry", None)
    with pytest.raises(RuntimeError, match=r"forgd-verdict\[gcp\]"):
        open_store(GCS_URL)


# -- preconditions ---------------------------------------------------------


def test_records_are_written_conditionally_and_markers_and_state_are_not(gcs):
    store = gcs.make_store("t")
    store.write_verdicts([rec()])
    store.write_denials([])
    store.put_state("cursor.json", b"{}")
    store.set_reset_marker("2026-09-26T00:00:00Z")
    store.set_excluded({"r1"})
    uploads = {k: kw["if_generation_match"]
               for op, k, kw in gcs.clients[-1].calls if op == "upload"}
    records = [k for k in uploads if k.endswith(".jsonl")]
    others = [k for k in uploads if not k.endswith(".jsonl")]
    assert records and all(uploads[k] == 0 for k in records)
    assert len(others) == 3 and all(uploads[k] is None for k in others)


def test_two_writers_with_one_instance_id_fail_rather_than_overwrite(gcs):
    a, b = gcs.make_store("same"), gcs.make_store("same")
    a.write_verdicts([rec(request_id="first")])
    with pytest.raises(_GCSError) as err:
        b.write_verdicts([rec(request_id="second")])
    assert err.value.code == 412
    assert [r.request_id for r in a.read_verdicts()] == ["first"]


def _lose_upload_responses(store, monkeypatch):
    """Each record upload commits, then the caller sees 412: what the SDK's
    retry reports after GCS committed the first attempt and lost the reply."""
    bucket = store._bucket
    real_blob = bucket.blob

    def blob(name):
        b = real_blob(name)
        real_upload = b.upload_from_string

        def upload(data, **kw):
            real_upload(data, **kw)
            if kw.get("if_generation_match") == 0:
                raise _GCSError(412)

        b.upload_from_string = upload
        return b

    monkeypatch.setattr(bucket, "blob", blob)


def test_a_lost_upload_response_is_not_a_failed_write(gcs, monkeypatch):
    """Raised, the 412 fails the batch and the caller writes it again under
    the next sequence number, counting every record twice."""
    store = gcs.make_store("t")
    _lose_upload_responses(store, monkeypatch)
    assert store.write_verdicts([rec(request_id="once")]) == 1
    assert [r.request_id for r in store.read_verdicts()] == ["once"]


def test_a_412_whose_object_cannot_be_read_stands(gcs, monkeypatch):
    store = gcs.make_store("t")
    _lose_upload_responses(store, monkeypatch)
    _deny_reads(store, monkeypatch)
    with pytest.raises(_GCSError) as err:
        store.write_verdicts([rec()])
    assert err.value.code == 412


def test_markers_and_state_are_overwritten(gcs):
    store = gcs.make_store("t")
    store.set_reset_marker("2026-09-25T00:00:00Z")
    store.set_reset_marker("2026-09-26T00:00:00Z")
    store.put_state("cursor.json", b"1")
    store.put_state("cursor.json", b"2")
    assert store.get_reset_marker() == "2026-09-26T00:00:00Z"
    assert store.get_state("cursor.json") == b"2"


# -- absence ---------------------------------------------------------------


def test_an_absent_cursor_is_a_first_run(gcs):
    assert gcs.make_store("t").get_state("never-written.json") is None


@pytest.mark.parametrize("exists", [True, False])
def test_a_cursor_denied_on_read_raises_whether_or_not_it_exists(gcs, monkeypatch, exists):
    """Only a 404 is absence. A 403 on a missing cursor raises too."""
    store = gcs.make_store("t")
    if exists:
        store.put_state("cursor.json", b"{}")
    _deny_reads(store, monkeypatch)
    with pytest.raises(_GCSError) as err:
        store.get_state("cursor.json")
    assert err.value.code == 403


def test_a_server_error_on_the_cursor_raises(gcs, monkeypatch):
    store = gcs.make_store("t")
    _deny_reads(store, monkeypatch, code=503)
    with pytest.raises(_GCSError):
        store.get_state("cursor.json")


def test_an_unreadable_marker_is_logged_not_silent(gcs, monkeypatch, caplog):
    store = gcs.make_store("t")
    store.set_reset_marker("2026-09-26T00:00:00Z")
    store.set_excluded({"r1"})
    _deny_reads(store, monkeypatch)
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.store.gcs"):
        assert store.get_reset_marker() is None
        assert store.get_excluded() == set()
    warned = [r for r in caplog.records if "could not read" in r.getMessage()]
    assert len(warned) == 2
    assert all(r.fields["code"] == 403 for r in warned)


def test_an_absent_marker_is_not_logged(gcs, caplog):
    store = gcs.make_store("t")
    with caplog.at_level(logging.WARNING, logger="forgd_verdict.store.gcs"):
        assert store.get_reset_marker() is None
        assert store.get_excluded() == set()
    assert not caplog.records


# -- listing ---------------------------------------------------------------


def test_reads_page_through_every_listing(gcs):
    """The fake lists two objects a page; eleven single-record objects span
    six, after one page each for the root's sources and the source's orgs."""
    store = gcs.make_store("t")
    for i in range(11):
        store.write_verdicts([rec(request_id=f"r{i}")])
    client = gcs.clients[-1]
    assert sorted(r.request_id for r in store.read_verdicts()) == sorted(
        f"r{i}" for i in range(11))
    assert client.pages_served == 1 + 1 + 6


def test_listing_uses_a_trailing_slash_prefix(gcs):
    store = gcs.make_store("t")
    list(store.read_verdicts())
    list(store.read_denials())
    prefixes = [k for op, k, _ in gcs.clients[-1].calls if op == "list"]
    assert prefixes == ["demo/verdicts/", "demo/denials/"]


# -- call bounds -----------------------------------------------------------


def test_every_call_carries_a_timeout_and_a_bounded_retry(gcs, caplog):
    store = gcs.make_store("t")
    store.write_verdicts([rec()])
    store.put_state("cursor.json", b"{}")
    store.set_reset_marker("2026-09-26T00:00:00Z")
    store.set_excluded({"r1"})
    list(store.read_verdicts())
    list(store.read_denials())
    store.get_state("cursor.json")
    store.get_state("absent.json")
    store.get_excluded()
    store.describe()

    calls = gcs.clients[-1].calls
    assert {op for op, _, _ in calls} == {"upload", "download", "list"}
    for op, key, kw in calls:
        assert kw.get("timeout") == _TIMEOUT, (op, key)
        retry = kw.get("retry")
        assert retry is not None and retry.timeout == _RETRY_SECONDS, (op, key)


def test_the_bounds_are_finite(gcs):
    connect, read = _TIMEOUT
    assert 0 < connect <= 30 and 0 < read <= 60
    assert 0 < _RETRY_SECONDS <= 120


def test_describe(gcs):
    d = gcs.make_store("t").describe()
    assert d["backend"] == "gcs"
    assert (d["bucket"], d["prefix"]) == ("forgd-findings", "demo")
