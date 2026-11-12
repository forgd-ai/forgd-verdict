"""Figures that open their records, the record page, and the colour theme."""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import parse_qsl, quote

import pytest
from conftest import ASGIClient

from forgd_verdict.dashboard.app import Dashboard, ViewScope
from forgd_verdict.dashboard.branding import LIGHT_TOKENS, Branding
from forgd_verdict.dashboard.render import render_events
from forgd_verdict.store import FindingRow, LocalFileStore, VerdictRecord
from forgd_verdict.store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
)

ORG_A, ORG_B = "org_aaaaaaaaaa", "org_bbbbbbbbbb"


def _rec(n: int, *, source=SOURCE_INFERENCE_HOOK, surface="claude-ai", action="allow",
         detector=None, org=None, reference=None, session=None) -> VerdictRecord:
    findings = [FindingRow(detector, "block", "messages[2]", f"sha256:{n:04d}")] if detector \
        else []
    return VerdictRecord(
        source=source, observed_at=f"2026-09-17T10:{n // 60:02d}:{n % 60:02d}Z",
        surface=surface, action=action,
        request_id=None if session else f"req{n:05d}", session_id=session,
        reference_id=reference, findings=findings, findings_count=len(findings),
        tenant_hash=org, build="1.2.7+abc")


def _store(tmp_path, records) -> LocalFileStore:
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts(records)
    return store


def _ids(html: str) -> list[str]:
    return re.findall(r">((?:req\d{5}|clls_\w+))</a>", html)


def _query(href: str) -> dict[str, str]:
    return dict(parse_qsl(unescape(href).split("?", 1)[1]))


async def test_every_matrix_count_opens_exactly_the_records_it_counts(tmp_path):
    store = _store(tmp_path, [
        *[_rec(n, surface="claude-ai") for n in range(3)],
        *[_rec(10 + n, surface="claude_code") for n in range(2)],
        *[_rec(20 + n, source=SOURCE_CODE_HOOK, surface="claude-code") for n in range(4)],
        _rec(30, source=SOURCE_COMPLIANCE_SCAN, surface="claude-ai", session="clls_30"),
    ])
    client = ASGIClient(Dashboard(store))
    _, html = await client.get("/coverage?window=all")
    cells = re.findall(r'<a class="mx-link [^"]+" href="([^"]+)">(\d+)</a>', html)
    assert len(cells) == 4
    for href, count in cells:
        _, page = await client.get(unescape(href))
        assert len(_ids(page)) == int(count), _query(href)


async def test_the_headline_tiles_open_the_records_they_count(tmp_path):
    store = _store(tmp_path, [_rec(1), _rec(2, action="deny", detector="regex:ssn")])
    _, html = await ASGIClient(Dashboard(store)).get("/?window=all")
    tiles = dict((label, href) for href, label in re.findall(
        r'<a class="stat-card" href="([^"]+)"><div class="stat-label">([^<]+)</div>', html))
    assert _query(tiles["Prompts evaluated live"]) == {"window": "all",
                                                       "source": "inference_hook"}
    assert _query(tiles["Would deny (inline)"]) == {"window": "all",
                                                    "source": "inference_hook",
                                                    "action": "deny"}
    # Nothing was audited, so that tile has nothing to open.
    assert "Sessions audited" not in tiles


async def test_the_surface_filter_narrows_and_a_hostile_value_is_dropped(tmp_path):
    store = _store(tmp_path, [_rec(1, surface="claude-ai"), _rec(2, surface="claude_code")])
    client = ASGIClient(Dashboard(store))
    _, html = await client.get("/events?window=all&surface=claude-code")
    assert _ids(html) == ["req00002"]
    assert "Surface: claude-code" in html
    hostile = quote('x"><h1>injected</h1>')
    status, html = await client.get(f"/events?window=all&surface={hostile}")
    assert status == 200 and "injected" not in html
    assert sorted(_ids(html)) == ["req00001", "req00002"]


async def test_the_record_page_finds_every_record_carrying_the_id(tmp_path):
    store = _store(tmp_path, [
        _rec(1, action="deny", detector="regex:aws-access-key", reference="fv_ref_1"),
        _rec(2, source=SOURCE_COMPLIANCE_SCAN, session="clls_2", reference="fv_ref_1",
             detector="regex:aws-access-key"),
        _rec(3),
    ])
    client = ASGIClient(Dashboard(store))
    _, log = await client.get("/events?window=all")
    href = re.search(r'href="(/events/detail\?[^"]+)"[^>]*>req00001<', log).group(1)
    assert _query(href) == {"window": "all", "id": "req00001"}
    status, html = await client.get(unescape(href))
    assert status == 200
    assert "1 record(s) carry this id" in html
    for fact in ("regex:aws-access-key", "messages[2]", "sha256:0001"[:12], "1.2.7+abc",
                 "fv_ref_1"):
        assert fact in html, fact
    # By reference id, both controls' records of the one request.
    _, html = await client.get("/events/detail?window=all&id=fv_ref_1")
    assert "2 record(s) carry this id" in html
    assert "compliance scan" in html and "inference hook" in html
    _, html = await client.get("/events/detail?window=all&id=req09999")
    assert "No record with this id in this window" in html


@pytest.mark.parametrize("bad", ["", "x" * 201, "a b", "../x", "<script>", "-lead"])
async def test_the_record_page_refuses_a_malformed_id(tmp_path, bad):
    status, body = await ASGIClient(Dashboard(_store(tmp_path, [_rec(1)]))).get(
        f"/events/detail?id={quote(bad)}")
    assert status == 404 and body == {"error": "not_found"}


async def test_the_record_page_reads_only_the_viewers_orgs(tmp_path):
    dash = Dashboard(_store(tmp_path, [_rec(1, org=ORG_A), _rec(2, org=ORG_B)]))
    scope = ViewScope(frozenset({ORG_A}), frozenset({ORG_A}), ORG_A)
    assert "1 record(s)" in dash._event_detail("all", "req00001", scope)
    other = dash._event_detail("all", "req00002", scope)
    assert "No record with this id" in other and "req00002</code></h1>" in other


def test_a_screened_id_is_not_linked():
    def screen(value):
        return "[withheld]" if value == "req00002" else value

    html = render_events([_rec(1), _rec(2)], id_screen=screen, window="all")
    assert "/events/detail?window=all&amp;id=req00001" in html
    assert "req00002" not in html


async def test_no_page_runs_script(tmp_path):
    client = ASGIClient(Dashboard(_store(tmp_path, [_rec(1, detector="regex:ssn")])))
    for path in ("/", "/coverage", "/detectors", "/delivery", "/events",
                 "/events/detail?id=req00001", "/policy"):
        _, html = await client.get(path)
        assert "<script" not in html.lower(), path


# -- the colour theme ------------------------------------------------------


async def test_the_theme_control_keeps_the_choice_and_returns_to_the_page(tmp_path):
    client = ASGIClient(Dashboard(_store(tmp_path, [_rec(1)])))
    status, _, headers = await client.request(
        "GET", "/theme?set=dark&next=" + quote("/coverage?window=30d"))
    assert status == 303
    assert headers["location"] == "/coverage?window=30d"
    assert headers["set-cookie"].startswith("fv_theme=dark; Path=/;")
    assert "HttpOnly" in headers["set-cookie"]
    _, _, headers = await client.request("GET", "/theme?set=auto&next=/")
    assert headers["set-cookie"].startswith("fv_theme=; ") and "Max-Age=0" in headers[
        "set-cookie"]


@pytest.mark.parametrize("target", ["//evil.example", "/\\evil.example",
                                    "https://evil.example", "evil", "/x\r\nSet-Cookie: a=b"])
async def test_the_theme_control_goes_back_only_to_this_dashboard(tmp_path, target):
    client = ASGIClient(Dashboard(_store(tmp_path, [_rec(1)])))
    _, _, headers = await client.request("GET", "/theme?set=light&next=" + quote(target))
    assert headers["location"] == "/"


async def test_the_chosen_theme_marks_the_page_without_splitting_the_cache(tmp_path):
    dash = Dashboard(_store(tmp_path, [_rec(1)]))
    client = ASGIClient(dash)
    _, dark = await client.get("/", {"cookie": "a=1; fv_theme=dark"})
    _, plain = await client.get("/")
    _, hostile = await client.get("/", {"cookie": 'fv_theme="><script>'})
    assert dark.startswith('<!DOCTYPE html>\n<html data-theme="dark" lang="en">')
    assert plain.startswith('<!DOCTYPE html>\n<html lang="en">')
    assert hostile == plain
    assert len([k for k in dash._cache if k[0] == "page"]) == 1


def test_each_mode_sets_which_scheme_a_viewer_sees_first():
    light = next(iter(LIGHT_TOKENS))
    auto = Branding().scheme_css
    assert "@media (prefers-color-scheme: light){:root:not([data-theme=dark])" in auto
    assert ":root[data-theme=light]{color-scheme:light;" in auto
    forced = Branding(mode="light").scheme_css
    assert "@media" not in forced and ":root:not([data-theme=dark]){" in forced
    dark = Branding(mode="dark").scheme_css
    assert ":root:not([data-theme=dark])" not in dark
    assert dark.count(f"{light}:") == 1           # only the viewer's choice
    # A theme is written for the dark scheme, so it makes dark the default.
    themed = Branding.from_policy({"theme": {"--bg-card": "#0C1F3A"}})
    assert themed.mode == "dark"
    assert Branding.from_policy({"theme": {"--bg-card": "#0C1F3A"},
                                 "mode": "auto"}).mode == "auto"


def test_markers_resolve_to_custom_properties_the_page_defines():
    branding = Branding()
    page = branding.fill("<@--warn-text@> <@--chart-ramp-3@> <@--chart-alert@>")
    assert page == "var(--warn-text) var(--chart-ramp-3) var(--chart-alert)"
    for name in ("--warn-text", "--chart-ramp-3", "--chart-alert"):
        assert f"{name}:" in branding.scheme_css
