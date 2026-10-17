"""The Event Log at fleet scale: paging, the filter box, and code-hook allows."""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import parse_qsl, urlencode

from conftest import ASGIClient

from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.dashboard.render import render_events
from forgd_verdict.store import FindingRow, LocalFileStore, VerdictRecord
from forgd_verdict.store.base import SOURCE_CODE_HOOK, SOURCE_INFERENCE_HOOK

ORG_A, ORG_B = "org_aaaaaaaaaaaa", "org_bbbbbbbbbbbb"


def _rec(n: int, *, source=SOURCE_INFERENCE_HOOK, action="allow", day="2026-09-17",
         detector=None, device=None, org=None) -> VerdictRecord:
    findings = [FindingRow(detector, "block", "messages[0]", f"sha256:{n}")] if detector else []
    return VerdictRecord(
        source=source, observed_at=f"{day}T{n // 3600 % 24:02d}:{n // 60 % 60:02d}:{n % 60:02d}Z",
        surface="claude-ai", action=action, request_id=f"req{n:05d}", findings=findings,
        findings_count=len(findings), device=device, client="fleet" if device else None,
        tenant_hash=org)


def _ids(html: str) -> list[str]:
    return re.findall(r"req\d{5}", html)


def _older(html: str) -> str | None:
    m = re.search(r'href="(/events\?[^"]*before=[^"]*)"[^>]*>Older', html)
    return unescape(m.group(1)) if m else None


async def test_older_links_page_through_every_event_once(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([_rec(n, day=f"2026-09-{15 + n % 3}") for n in range(450)])
    client = ASGIClient(Dashboard(store))
    seen, path, pages = [], "/events?window=all", 0
    while path:
        status, html = await client.get(path)
        assert status == 200
        page = _ids(html)
        assert 0 < len(page) <= 200 or not page
        seen += page
        path = _older(html)
        pages += 1
        assert pages < 10
    assert pages == 3
    assert sorted(seen) == sorted(f"req{n:05d}" for n in range(450))
    assert len(seen) == len(set(seen))


async def test_a_later_page_links_back_to_the_newest(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([_rec(n) for n in range(250)])
    client = ASGIClient(Dashboard(store))
    _, html = await client.get("/events?window=all")
    assert 'href="/events?window=all"' not in html
    _, html = await client.get(_older(html))
    assert ">Newest</a>" in html


async def test_code_hook_allows_are_hidden_unless_asked_for(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([
        _rec(1, source=SOURCE_CODE_HOOK),
        _rec(2, source=SOURCE_CODE_HOOK, action="deny", detector="regex:aws-access-key"),
        _rec(3),
    ])
    client = ASGIClient(Dashboard(store))
    _, html = await client.get("/events?window=all")
    assert _ids(html) == ["req00003", "req00002"]
    assert "Code hook allows hidden" in html
    _, html = await client.get("/events?window=all&code_hook_allows=show")
    assert _ids(html) == ["req00003", "req00002", "req00001"]


async def test_the_filter_box_narrows_to_a_detector_and_a_device(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([
        _rec(1, detector="regex:aws-access-key"),
        # Only the intake writes a device, on the Code hook's records.
        _rec(2, detector="regex:ssn", device="d00000000000a", source=SOURCE_CODE_HOOK,
             action="deny"),
        _rec(3, device="d00000000000b", source=SOURCE_CODE_HOOK, action="deny"),
    ])
    client = ASGIClient(Dashboard(store))
    _, html = await client.get("/events?window=all")
    assert '<form method="get" action="/events"' in html
    assert 'name="detector"' in html and 'name="device"' in html
    _, html = await client.get("/events?window=all&detector=regex:ssn")
    assert _ids(html) == ["req00002"]
    _, html = await client.get("/events?window=all&device=d00000000000b")
    assert _ids(html) == ["req00003"]


async def test_hostile_filter_and_cursor_values_are_dropped_and_never_echoed(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([_rec(1, detector="regex:ssn")])
    client = ASGIClient(Dashboard(store))
    hostile = "x%22%3E%3Ch1%3Einjected%3C%2Fh1%3E"
    for param in ("detector", "device", "before", "code_hook_allows"):
        status, html = await client.get(f"/events?window=all&{param}={hostile}")
        assert status == 200
        assert "<h1>injected" not in html and "injected" not in html, param
        assert _ids(html) == ["req00001"], param


async def test_the_entitlement_applies_before_the_filter_box(tmp_path):
    """A device filter for another org's laptop shows nothing, not that
    laptop's rows."""
    from forgd_verdict.store.views import event_page

    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([_rec(1, device="d00000000000a", org=ORG_A,
                               source=SOURCE_CODE_HOOK, action="deny"),
                          _rec(2, device="d00000000000b", org=ORG_B,
                               source=SOURCE_CODE_HOOK, action="deny")])
    assert event_page(store, None, {ORG_A}, device="d00000000000b").records == []
    assert [r.request_id for r in event_page(store, None, {ORG_A},
                                             device="d00000000000a").records] == ["req00001"]


def test_the_deny_button_is_offered_only_for_a_valid_device_id():
    def deny(device):
        return f'<form data-device="{device}"></form>'

    records = [_rec(1, device="d00000000000a"), _rec(2, device="not-a-device"),
               _rec(3, device="D00000000000A")]
    html = render_events(records, deny_form=deny)
    assert html.count("<form data-device=") == 1
    assert 'data-device="d00000000000a"' in html
    assert "not-a-device" in html
    assert 'href="/events?device=not-a-device"' not in html


def _links(html: str) -> dict[str, dict[str, str]]:
    return {unescape(text): dict(parse_qsl(unescape(href).split("?", 1)[1]))
            for href, text in re.findall(r'<a href="(/events\?[^"]*)"[^>]*>([^<]*)</a>', html)}


def test_every_event_log_link_keeps_the_current_view_state():
    html = render_events([_rec(1, source=SOURCE_CODE_HOOK, action="deny",
                               detector="aws_key", device="d00000000000a")],
                         source=SOURCE_CODE_HOOK, action="deny", client="fleet",
                         detector="aws_key", window="30d", show_allows=True)
    links = _links(html)
    view = {"source": SOURCE_CODE_HOOK, "action": "deny", "client": "fleet",
            "detector": "aws_key", "window": "30d", "code_hook_allows": "show"}

    chips = {"All controls": "all", "Inference hook": "inference_hook",
             "Code hook": "code_hook", "Compliance scan": "compliance_scan",
             "OTel": "otel_collect", "Agent check": "agent_scan",
             "Managed scan": "managed_scan"}
    for name, value in chips.items():
        assert links[name] == {**view, "source": value}, name
    assert links["All verdicts"] == {**view, "action": "all"}
    assert links["Would deny only"] == view
    for key, value in (("client", "fleet"), ("detector", "aws_key")):
        label = f"{key.title()}: {value} ×"
        assert links[label] == {k: v for k, v in view.items() if k != key}, label
    assert links["d00000000000a"] == {**view, "device": "d00000000000a"}
    assert links["fleet"] == view


def _event_log_links(html: str) -> dict[str, dict[str, str]]:
    """Every /events link on the page except the org picker's own."""
    return _links(re.sub(r'<nav class="orgs">.*?</nav>', "", html, flags=re.S))


def _picked(html: str) -> str:
    m = re.search(r'<nav class="orgs">.*?<a href="([^"]*)" aria-current=true>', html, re.S)
    return dict(parse_qsl(unescape(m.group(1)).split("?", 1)[1]))["org"]


async def test_every_event_log_link_keeps_the_picked_org(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts(
        [_rec(n, source=SOURCE_CODE_HOOK, action="deny", detector="aws_key",
              device="d00000000000a", org=ORG_A) for n in range(250)]
        + [_rec(999, source=SOURCE_CODE_HOOK, action="deny", detector="aws_key",
                device="d00000000000b", org=ORG_B)])
    client = ASGIClient(Dashboard(store, org_labels={ORG_A: "Prod", ORG_B: "Dev"}))
    _, html = await client.get("/events")
    picker = unescape(re.search(r'<a href="([^"]*)"[^>]*>Prod<', html).group(1))
    assert dict(parse_qsl(picker.split("?", 1)[1])) == {"org": ORG_A}

    _, html = await client.get(picker + "&window=all&source=code_hook&action=deny"
                               "&client=fleet&code_hook_allows=show")
    assert _picked(html) == ORG_A
    assert "req00999" not in html
    links = _event_log_links(html)
    for name in ("All controls", "Code hook", "All verdicts", "Would deny only",
                 "Client: fleet ×", "d00000000000a", "fleet",
                 "Older events →", "Hide Code hook allows"):
        assert links[name]["org"] == ORG_A, name
    assert all(q.get("org") == ORG_A for q in links.values()), links
    assert f'<input type="hidden" name="org" value="{ORG_A}">' in html

    older = "/events?" + urlencode(links["Older events →"])
    _, html = await client.get(older)
    newest = _event_log_links(html)["Newest"]
    assert newest["org"] == ORG_A
    for query in (newest, links["All controls"], links["d00000000000a"]):
        _, html = await client.get("/events?" + urlencode(query))
        assert _picked(html) == ORG_A
        assert "req00999" not in html


def test_the_default_view_puts_no_org_in_its_links():
    html = render_events([_rec(1, device="d00000000000a")], window="all", selected="all")
    assert all("org" not in q for q in _links(html).values())
    assert 'name="org"' not in html


def test_a_tool_call_verdict_is_labelled_as_one():
    """A deny there stopped tool calls, not a prompt. Mutation: drop the
    label."""
    from forgd_verdict.store.base import EVENT_TOOL_CALL

    tool = _rec(1, action="deny", detector="regex:aws-access-key")
    tool.event = EVENT_TOOL_CALL
    html = render_events([tool, _rec(2, action="deny", detector="regex:aws-access-key")])
    assert html.count("(tool calls)") == 1
