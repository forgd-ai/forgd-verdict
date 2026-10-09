"""The runtime overrides object and its audit records, on every backend.

`read_control` must tell an absent object from one it cannot read, because a
reader keeps its last-known-good through a failed read and a caller that
mistook a denial for "not there" would write over the object blind. The
local store's `get_state` returns None for both, and no backend's
`get_state` returns an etag, which is why these are separate operations.
"""

from __future__ import annotations

import pytest
import terraform_render
from test_store_conformance import backend  # noqa: F401 - the fixture

from forgd_verdict.models import CONTROL_STATE
from forgd_verdict.store.base import (
    AUDIT_PREFIX,
    STATE_PREFIX,
    StoreConflict,
    StoreForbidden,
    StoreReadError,
    safe_audit_name,
)

CONTROL = f"{STATE_PREFIX}/{CONTROL_STATE}"


def test_absent_is_absent(backend):  # noqa: F811
    assert backend.make_store("a").read_control().status == "absent"


def test_create_then_read_returns_bytes_and_an_etag(backend):  # noqa: F811
    store = backend.make_store("a")
    store.write_control(b'{"v":1}', None)
    found = store.read_control()
    assert (found.status, found.body) == ("ok", b'{"v":1}')
    assert found.etag
    assert backend.raw(CONTROL) == '{"v":1}'


def test_a_denied_read_raises_rather_than_reading_as_absent(backend):  # noqa: F811
    store = backend.make_store("a")
    store.write_control(b"{}", None)
    backend.deny(CONTROL)
    with pytest.raises(StoreReadError):
        store.read_control()


def test_create_only_refuses_an_existing_object(backend):  # noqa: F811
    store = backend.make_store("a")
    store.write_control(b"one", None)
    with pytest.raises(StoreConflict):
        store.write_control(b"two", None)
    assert backend.raw(CONTROL) == "one"


def test_replace_needs_the_current_etag(backend):  # noqa: F811
    store = backend.make_store("a")
    store.write_control(b"one", None)
    first = store.read_control().etag
    store.write_control(b"two", first)
    assert backend.raw(CONTROL) == "two"
    with pytest.raises(StoreConflict):
        store.write_control(b"three", first)
    assert backend.raw(CONTROL) == "two"


def test_replace_of_a_deleted_object_is_a_conflict(backend):  # noqa: F811
    store = backend.make_store("a")
    store.write_control(b"one", None)
    etag = store.read_control().etag
    if backend.name == "local":
        (backend.root / CONTROL).unlink()
    else:
        with backend._lock:
            del backend.blobs[backend._key(CONTROL)]
    with pytest.raises(StoreConflict):
        store.write_control(b"two", etag)


def test_audit_records_are_create_only(backend):  # noqa: F811
    store = backend.make_store("a")
    name = "2026-09-28/20260928T140311Z-0123456789ab-request.json"
    store.put_audit(name, b"first")
    with pytest.raises(StoreConflict):
        store.put_audit(name, b"second")
    assert backend.raw(f"{AUDIT_PREFIX}/{name}") == "first"
    assert store.get_audit(name) == b"first"
    assert store.list_audit() == [name]


def test_audit_reads_absent_as_none(backend):  # noqa: F811
    store = backend.make_store("a")
    assert store.get_audit("2026-09-28/nothing.json") is None
    assert store.list_audit() == []


def test_audit_records_are_not_read_as_records(backend):  # noqa: F811
    store = backend.make_store("a")
    store.put_audit("2026-09-28/x.json", b'{"kind":"request"}')
    store.write_control(b"{}", None)
    assert list(store.read_verdicts()) == []
    assert list(store.read_denials()) == []


@pytest.mark.parametrize("name", [
    "../state/runtime-overrides.json", "2026-09-28/../../x.json", "x.json",
    "2026-09-28/sub/x.json", "2026-09-28/.hidden.json", "2026-9-28/x.json",
])
def test_an_audit_name_cannot_leave_the_prefix(name):
    with pytest.raises(ValueError):
        safe_audit_name(name)


def test_a_denied_write_raises_store_forbidden(backend):  # noqa: F811
    """Mutation: let a 403 on either write escape as the provider's error."""
    if backend.name == "local":
        pytest.skip("a local store has no credentials to deny")
    store = backend.make_store("a")
    store.write_control(b"{}", None)
    etag = store.read_control().etag
    backend.deny_write(CONTROL)
    for if_etag in (etag, None):
        with pytest.raises(StoreForbidden):
            store.write_control(b"{}", if_etag)
    name = "2026-09-28/20260928T140311Z-0123456789ab-request.json"
    backend.deny_write(f"{AUDIT_PREFIX}/{name}")
    with pytest.raises(StoreForbidden):
        store.put_audit(name, b"{}")



# --- the store modules' pinned baseline ------------------------------------


@pytest.mark.parametrize("module", ["store-s3", "store-gcs", "store-azure"])
def test_the_pinned_baseline_is_each_store_module_before_control(module):
    """The feature-off renderings in the three module tests compare against
    these files. None of them mentions the control variables or the
    overrides."""
    pinned = terraform_render.BASELINE / module
    assert sorted(p.name for p in pinned.iterdir()) == ["main.tf", "outputs.tf", "variables.tf"]
    for f in pinned.iterdir():
        text = f.read_text(encoding="utf-8")
        assert "control_" not in text and "runtime-overrides" not in text, f


@pytest.mark.parametrize("module", sorted(terraform_render.APPS))
def test_the_pinned_baseline_is_each_app_module_before_dashboard_admins(module):
    """The feature-off renderings in the app module tests compare against
    these files. None of them mentions dashboard admins or the overrides."""
    pinned = terraform_render.baseline(module)
    assert sorted(p.name for p in pinned.iterdir()) == ["main.tf", "outputs.tf", "variables.tf"]
    for f in pinned.iterdir():
        text = f.read_text(encoding="utf-8")
        assert "dashboard_admins" not in text and "FORGD_OVERRIDES_ENABLED" not in text, f
        assert "FORGD_OVERRIDES_WRITER_ROLES" not in text, f
