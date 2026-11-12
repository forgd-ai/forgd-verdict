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
    EVENT_TOOL_CALL,
    SOURCE_CODE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
    SOURCE_MANAGED_SCAN,
)

ORG_A, ORG_B = "org_aaaaaaaaaa", "org_bbbbbbbbbb"
# A linked headline tile: its href, label and value.
TILE = (r'<a class="stat-card" href="(/events[^"]+)"><div class="stat-label">'
        r'(?:<svg[^>]*><path[^>]*/></svg>)?([^<]+)<span class="stat-go">[^<]*</span></div>'
        r'<div class="stat-value">([\d,]+)</div>')


def _rec(n: int, *, source=SOURCE_INFERENCE_HOOK, surface="claude-ai", action="allow",
         detector=None, org=None, reference=None, session=None, event=None, tally=None,
         request=True) -> VerdictRecord:
    findings = [FindingRow(detector, "block", "messages[2]", f"sha256:{n:04d}")] if detector \
        else []
    return VerdictRecord(
        source=source, observed_at=f"2026-09-17T10:{n // 60:02d}:{n % 60:02d}Z",
        surface=surface, action=action,
        request_id=None if session or not request else f"req{n:05d}", session_id=session,
        reference_id=reference, findings=findings, findings_count=len(findings),
        tenant_hash=org, build="1.2.7+abc", event=event, tally=tally)


def _store(tmp_path, records) -> LocalFileStore:
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts(records)
    return store


def _ids(html: str) -> list[str]:
    return re.findall(r">((?:req\d{5}|clls_\w+))</a>", html)


def _weight(html: str) -> int:
    """The records a log page stands for: one per row, and a Code hook tally
    row's allows."""
    rows = html.split("<tbody>")[1].split("</tbody>")[0].split("<tr>")[1:] \
        if "<tbody>" in html else []
    total = 0
    for row in rows:
        m = re.search(r"([\d,]+) allows?</span>", row)
        total += int(m.group(1).replace(",", "")) if m else 1
    return total


def _counted(n: int) -> list[VerdictRecord]:
    """A window that holds each kind of record a figure can miscount: tool
    call checks beside prompts, a Code hook tally, a managed scan, a
    warn-only scan, and an inline deny on the Code hook."""
    return [
        _rec(n, surface="claude-ai"),
        _rec(n + 1, surface="claude-ai", action="deny", detector="regex:ssn"),
        _rec(n + 2, surface="claude-ai", event=EVENT_TOOL_CALL, action="deny",
             detector="regex:ssn"),
        _rec(n + 3, source=SOURCE_CODE_HOOK, surface="claude-code", tally=50),
        _rec(n + 4, source=SOURCE_CODE_HOOK, surface="claude-code", action="deny",
             detector="regex:aws-access-key"),
        _rec(n + 5, source=SOURCE_COMPLIANCE_SCAN, surface="claude-ai", session="clls_a",
             detector="regex:ssn"),
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T11:00:00Z",
                      surface="claude-ai", session_id="clls_w",
                      findings=[FindingRow("presidio:person", "warn", "m", "sha256:w")],
                      findings_count=1),
        _rec(n + 6, source=SOURCE_MANAGED_SCAN, surface="claude-ai", session="clls_m",
             detector="regex:aws-access-key"),
        # Two managed scans against one warn-only compliance scan, so a link
        # that read the compliance scan's flagged rows in place of every
        # detection would open a different number of rows.
        _rec(n + 7, source=SOURCE_MANAGED_SCAN, surface="claude-ai", session="clls_n",
             detector="regex:aws-access-key"),
    ]


def _query(href: str) -> dict[str, str]:
    return dict(parse_qsl(unescape(href).split("?", 1)[1]))


async def test_every_coverage_count_opens_exactly_the_records_it_counts(tmp_path):
    store = _store(tmp_path, [*_counted(0), _rec(40, surface="claude_code"),
                              _rec(41, source=SOURCE_CODE_HOOK, surface="claude-code")])
    client = ASGIClient(Dashboard(store))
    _, html = await client.get("/coverage?window=all")
    links = re.findall(r'<a class="mx-link [^"]+" href="([^"]+)">(\d+)</a>', html)
    links += re.findall(r'<td class="num"><a href="([^"]+)">([\d,]+)</a></td>', html)
    assert len(links) >= 10
    for href, count in links:
        _, page = await client.get(unescape(href))
        assert _weight(page) == int(count.replace(",", "")), _query(href)


async def test_a_session_scanned_twice_is_one_count_and_two_rows_and_the_log_says_so(
        tmp_path):
    store = _store(tmp_path, [
        _rec(1, source=SOURCE_COMPLIANCE_SCAN, session="clls_x"),
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T12:00:00Z",
                      surface="claude-ai", session_id="clls_x"),
    ])
    client = ASGIClient(Dashboard(store))
    _, html = await client.get("/?window=all")
    href = next(h for h, label, _ in re.findall(TILE, html) if label == "Sessions audited")
    _, page = await client.get(unescape(href))
    assert _ids(page) == ["clls_x", "clls_x"]
    assert "counts once on the summary pages" in page
    _, inline = await client.get("/events?window=all&source=inference_hook")
    assert "counts once on the summary pages" not in inline


async def test_the_headline_tiles_open_exactly_the_records_they_count(tmp_path):
    client = ASGIClient(Dashboard(_store(tmp_path, _counted(0))))
    _, html = await client.get("/?window=all")
    tiles = re.findall(TILE, html)
    assert {label for _, label, _ in tiles} == {
        "Prompts evaluated live", "Sessions audited", "Would deny (inline)",
        "Detected in audit"}
    for href, label, count in tiles:
        _, page = await client.get(unescape(href))
        assert _weight(page) == int(count.replace(",", "")), label


async def test_a_tile_with_nothing_to_count_has_no_link(tmp_path):
    _, html = await ASGIClient(Dashboard(_store(tmp_path, [_rec(1)]))).get("/?window=all")
    assert [label for _, label, _ in re.findall(TILE, html)] == ["Prompts evaluated live"]


async def test_a_value_the_log_would_drop_is_not_linked(tmp_path):
    store = _store(tmp_path, [_rec(1, surface="agent:my bot", detector="custom:has space"),
                              _rec(2, request=False, reference="fv_ref_only")])
    client = ASGIClient(Dashboard(store))
    _, coverage = await client.get("/coverage?window=all")
    assert "agent:my bot" in coverage
    assert "surface=agent" not in coverage
    _, detectors = await client.get("/detectors?window=all")
    assert "custom:has space" in detectors and "has+space" not in detectors
    _, log = await client.get("/events?window=all")
    # A record known only by its reference id still opens.
    assert "/events?window=all&amp;open=fv_ref_only" in log
    _, sheet = await client.get("/events?window=all&open=fv_ref_only")
    assert "/events/detail?window=all&amp;id=fv_ref_only" in sheet


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
    opened = re.search(r'href="(/events\?[^"]+)"[^>]*>req00001<', log).group(1)
    _, sheet = await client.get(unescape(opened))
    href = re.search(r'href="(/events/detail\?[^"]+)">Every control', sheet).group(1)
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


async def test_the_record_page_says_when_there_are_more_than_it_shows(tmp_path):
    store = _store(tmp_path, [_rec(n, reference="fv_many") for n in range(21)])
    _, html = await ASGIClient(Dashboard(store)).get("/events/detail?window=all&id=fv_many")
    assert "The newest 20 records carrying this id are shown; there are more." in html
    assert html.count("<h2>Findings</h2>") == 20


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


async def test_a_record_opens_beside_the_log(tmp_path):
    store = _store(tmp_path, [_rec(1, action="deny", detector="regex:aws-access-key"),
                              _rec(2)])
    client = ASGIClient(Dashboard(store))
    _, html = await client.get("/events?window=all&open=req00001")
    sheet = html.split('<aside class="card sheet"', 1)[1]
    assert "regex:aws-access-key" in sheet and "req00002" not in sheet
    assert html.split("</style>", 1)[1].count("<tr aria-selected=true>") == 1
    assert 'href="/events?window=all" aria-label="Close"' in sheet
    _, plain = await client.get("/events?window=all")
    assert "sheet" not in plain.split("</style>", 1)[1]


async def test_an_open_id_not_on_the_page_or_malformed_opens_nothing(tmp_path):
    client = ASGIClient(Dashboard(_store(tmp_path, [_rec(1)])))
    for value in ("req09999", quote('x"><h1>injected</h1>')):
        status, html = await client.get(f"/events?window=all&open={value}")
        body = html.split("</style>", 1)[1]
        assert status == 200 and "<aside" not in body and "injected" not in body


def test_a_screened_id_opens_no_panel():
    def screen(value):
        return "[withheld]" if value == "req00002" else value

    html = render_events([_rec(2)], id_screen=screen, window="all", open_id="req00002")
    assert "<aside" not in html.split("</style>", 1)[1] and "req00002" not in html


def test_a_screened_id_is_not_linked():
    def screen(value):
        return "[withheld]" if value == "req00002" else value

    html = render_events([_rec(1), _rec(2)], id_screen=screen, window="all")
    assert "/events?window=all&amp;open=req00001" in html
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


def test_a_dark_theme_does_not_reach_the_light_scheme():
    css = Branding.from_policy({"mode": "light", "theme": {
        "--brand-accent-bg-strong": "#000000", "--warn-text": "#111111"}}).scheme_css
    light = css.split(":root:not([data-theme=dark]){")[1].split("}")[0]
    assert "--brand-accent-bg-strong:rgba(59, 130, 246, 0.18);" in light
    assert "--warn-text:#92400E;" in light
    assert "#000000" not in light and "#111111" not in light


def test_markers_resolve_to_custom_properties_the_page_defines():
    branding = Branding()
    page = branding.fill("<@--warn-text@> <@--chart-ramp-3@> <@--chart-alert@>")
    assert page == "var(--warn-text) var(--chart-ramp-3) var(--chart-alert)"
    for name in ("--warn-text", "--chart-ramp-3", "--chart-alert"):
        assert f"{name}:" in branding.scheme_css
