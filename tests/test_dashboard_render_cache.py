"""The dashboard's render cache: bounded in entries and bytes, and keyed on
everything that changes what a cached page shows."""

from __future__ import annotations

import secrets

import pytest
from conftest import ASGIClient

from forgd_verdict.dashboard import app as dapp
from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.dashboard.auth import AuthConfig
from forgd_verdict.entitlements import MODE_TRUSTED_HEADER, Entitlements, Principal
from forgd_verdict.store.base import VerdictRecord, pseudonym
from forgd_verdict.store.local import LocalFileStore

SALT = "s"
A = pseudonym("org-a", SALT, "org")
B = pseudonym("org-b", SALT, "org")
C = pseudonym("org-c", SALT, "org")
TRUSTED = AuthConfig(mode=MODE_TRUSTED_HEADER, header="x-ms-client-principal-name")


def _store(tmp_path):
    store = LocalFileStore(tmp_path / "findings", instance="t")
    store.write_verdicts([
        VerdictRecord(source="otel_collect", tenant_hash=A, surface="surface-alpha"),
        VerdictRecord(source="otel_collect", tenant_hash=B, surface="surface-bravo"),
        VerdictRecord(source="otel_collect", tenant_hash=C, surface="surface-charlie"),
    ])
    return store


@pytest.fixture
def small_cache(monkeypatch):
    monkeypatch.setattr(dapp, "CACHE_MAX_ENTRIES", 8)
    monkeypatch.setattr(dapp, "CACHE_MAX_BYTES", 400_000)


def _org() -> str:
    return "org_" + secrets.token_hex(5)


async def test_distinct_org_values_do_not_grow_the_cache_past_its_entry_bound(
        tmp_path, small_cache):
    dash = Dashboard(_store(tmp_path))
    client = ASGIClient(dash)
    for _ in range(40):
        org = _org()
        assert (await client.get(f"/?org={org}"))[0] == 200
        assert (await client.get(f"/api/summary?org={org}"))[0] == 200
    assert len(dash._cache) <= 8


async def test_the_cache_holds_no_more_than_its_byte_bound(tmp_path, small_cache):
    dash = Dashboard(_store(tmp_path))
    client = ASGIClient(dash)
    for _ in range(40):
        await client.get(f"/?org={_org()}")
    assert dash._cache.bytes <= 400_000
    assert dash._cache.bytes == sum(size for _, _, size in dash._cache.entries())


async def test_a_page_larger_than_the_byte_bound_is_served_and_not_kept(
        tmp_path, monkeypatch):
    monkeypatch.setattr(dapp, "CACHE_MAX_BYTES", 1_000)
    dash = Dashboard(_store(tmp_path))
    status, body = await ASGIClient(dash).get("/")
    assert status == 200 and "<html" in body
    assert len(dash._cache) == 0 and dash._cache.bytes == 0


async def test_the_least_recently_used_entry_is_evicted_first(tmp_path, small_cache):
    dash = Dashboard(_store(tmp_path))
    client = ASGIClient(dash)
    await client.get("/?window=all")
    for _ in range(7):
        await client.get(f"/?org={_org()}")
        await client.get("/?window=all")
    await client.get(f"/?org={_org()}")
    assert any(k[0] == "page" and k[1] == "all" for k in dash._cache)


@pytest.mark.parametrize("org", [
    "x" * 8000,
    "a" * 65,
    "ORG_0123456789",
    "org_012345678%0a",
    "../../etc",
    "org_0123456789\x00",
    "org 0123456789",
    "%C3%A9org",
], ids=["long", "65", "upper", "newline", "traversal", "nul", "space", "non-ascii"])
async def test_a_malformed_org_is_refused_and_never_cached(tmp_path, org):
    dash = Dashboard(_store(tmp_path))
    client = ASGIClient(dash)
    for route in ("/", "/api/summary", "/events", "/policy"):
        status, body = await client.get(f"{route}?org={org}")
        assert status == 403 and body == {"error": "forbidden"}, route
    assert len(dash._cache) == 0


@pytest.mark.parametrize("org", [A, "workspace_0123456789", "developer", "otel-unknown",
                                 "org_aaaaaaaaaaaa", "a" * 64])
async def test_well_formed_partitions_are_still_served(tmp_path, org):
    status, _ = await ASGIClient(Dashboard(_store(tmp_path))).get(f"/?org={org}")
    assert status == 200


async def test_caller_chosen_viewer_names_do_not_grow_the_cache(tmp_path, small_cache):
    dash = Dashboard(_store(tmp_path), auth=TRUSTED)
    client = ASGIClient(dash)
    for i in range(40):
        status, _ = await client.get(
            "/", {"x-ms-client-principal-name": f"v{i}-" + "n" * 500 + "@example.com"})
        assert status == 200
    assert len(dash._cache) <= 8


async def test_two_viewers_with_one_name_and_different_entitlements_get_their_own_pages(
        tmp_path):
    """Two principals can share a display name. A page built for one
    viewer's entitlements must not be served to the other."""
    current = {"p": Principal("dana", ("g-ab",))}

    class FixedAuth(AuthConfig):
        def authenticate(self, headers):
            return current["p"]

    ent = Entitlements(by_group={"g-ab": frozenset({A, B}), "g-ac": frozenset({A, C})})
    dash = Dashboard(_store(tmp_path), auth=FixedAuth(mode=MODE_TRUSTED_HEADER),
                     entitlements=ent,
                     org_labels={A: "Label Alpha", B: "Label Bravo", C: "Label Charlie"})
    client = ASGIClient(dash)
    _, first = await client.get(f"/?org={A}")
    assert "Label Bravo" in first
    current["p"] = Principal("dana", ("g-ac",))
    _, second = await client.get(f"/?org={A}")
    assert "Label Charlie" in second
    assert "Label Bravo" not in second


async def test_the_selection_is_part_of_the_key(tmp_path):
    """`all` over one entitled org and that org selected read the same
    records; the pages still differ in which picker entry is current."""
    dash = Dashboard(_store(tmp_path))
    v_all = dapp.ViewScope(frozenset({A}), frozenset({A}), "all")
    v_one = dapp.ViewScope(frozenset({A}), frozenset({A}), A)
    dash._page("all", v_all, "")
    dash._page("all", v_one, "")
    assert len([k for k in dash._cache if k[0] == "page"]) == 2


def test_the_default_bounds_are_set():
    assert 0 < dapp.CACHE_MAX_ENTRIES <= 512
    assert 0 < dapp.CACHE_MAX_BYTES <= 64 * 1024 * 1024
