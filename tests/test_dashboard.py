"""Dashboard rendering, the JSON API, and its security posture."""

from __future__ import annotations

import json
import re

from conftest import ASGIClient

from forgd_verdict.dashboard.app import Dashboard, window_to_since
from forgd_verdict.dashboard.auth import AuthConfig
from forgd_verdict.dashboard.branding import Asset, Branding
from forgd_verdict.dashboard.charts import _nice_ceiling, grouped_bars, hbar
from forgd_verdict.store import FindingRow, LocalFileStore, VerdictRecord
from forgd_verdict.store.base import (
    SOURCE_CODE_HOOK,
    SOURCE_COMPLIANCE_SCAN,
    SOURCE_INFERENCE_HOOK,
)

SECRET = "AKIAQYLPMN5HGZTHX4UQ"


TRUSTED_HEADER = AuthConfig.parse({"mode": "trusted_header",
                                   "header": "x-ms-client-principal-name",
                                   "stripped_by": "a proxy checked in this test"})


def seeded_store(tmp_path):
    store = LocalFileStore(tmp_path / "findings", instance="t")
    store.write_verdicts([
        VerdictRecord(
            source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:00:00Z",
            surface="claude-ai", action="allow", shadow_action="deny",
            total_ms=480.0, scan_ms=477.0, cache_hit=True, findings_count=1,
            reference_id="fv_awsaccesske_01ABC",
            findings=[FindingRow("regex:aws-access-key", "block",
                                 "msg[2].content[0]", "a" * 64)],
        ),
        VerdictRecord(
            source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:01:00Z",
            surface="claude-ai", action="allow", total_ms=470.0,
        ),
        VerdictRecord(
            source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T09:00:00Z",
            surface="claude_code", session_id="clls_01", action="deny",
            findings_count=1,
            findings=[FindingRow("regex:ssn", "block", "msg[1]", "b" * 64)],
        ),
    ])
    return store


async def test_page_renders_with_data(tmp_path):
    client = ASGIClient(Dashboard(seeded_store(tmp_path)))
    scope = {"type": "http", "method": "GET", "path": "/", "headers": [],
             "query_string": b"window=all"}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        sent.append(m)

    await client.app(scope, receive, send)
    status = sent[0]["status"]
    html = b"".join(m.get("body", b"") for m in sent[1:]).decode()
    assert status == 200
    assert "<!DOCTYPE html>" in html
    assert "<footer>" not in html          # unbranded: no footer
    assert "Findings" in html
    # Normalization guarantee: the adapter-3 underscore form never
    # reaches the page as a separate surface.
    assert "claude_code" not in html
    assert "claude-code" in html
    assert len(re.findall(r"<td><code>claude-[a-z]+</code></td>", html)) == 2
    assert "regex:aws-access-key" in html


async def test_page_renders_with_an_empty_store(tmp_path):
    """The dashboard ships before adapter 3 has ever run."""
    dash = Dashboard(LocalFileStore(tmp_path / "empty", instance="t"))
    html = dash._page("7d")
    assert "<!DOCTYPE html>" in html
    assert "Audit scan has not run" in html
    assert "No requests recorded" in html or "No data yet" in html


async def test_json_api(tmp_path):
    dash = Dashboard(seeded_store(tmp_path))
    payload = dash._summary_json("all")
    assert payload["total_requests"] == 3
    # Inline only: the compliance-scan session had a blocking finding, but a
    # post-hoc scan was never in a position to deny it.
    assert payload["would_deny"] == 1          # the shadow deny
    assert payload["enforced_deny"] == 0
    assert payload["detections"] == 1          # the post-hoc session
    assert payload["distinct_values"] == 2
    surfaces = {s["surface"]: s for s in payload["surfaces"]}
    assert set(surfaces) == {"claude-ai", "claude-code"}
    # null rather than 0 for a surface with no round trip
    assert surfaces["claude-code"]["p95_ms"] is None
    assert surfaces["claude-ai"]["p95_ms"] == 479.5  # p95 of [470, 480]
    assert surfaces["claude-ai"]["p50_ms"] == 475.0
    assert payload["reconciliation"]["values_missed_live"] == 1
    assert json.dumps(payload)  # must be serializable


async def test_no_secret_can_reach_the_page(tmp_path):
    """The store holds no content, so the page cannot render any."""
    store = LocalFileStore(tmp_path / "f", instance="t")
    store.write_verdicts([VerdictRecord(
        source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:00:00Z",
        surface="claude-ai", action="deny", findings_count=1,
        findings=[FindingRow("regex:aws-access-key", "block", "msg[0]", "c" * 64)],
    )])
    html = Dashboard(store)._page("all")
    assert SECRET not in html


async def test_trusted_header_refuses_unauthenticated_requests(tmp_path):
    """Guard against being deployed with public ingress and no auth provider."""
    dash = Dashboard(seeded_store(tmp_path), auth=TRUSTED_HEADER)
    client = ASGIClient(dash)
    status, body = await client.get("/")
    assert status == 401 and body["error"] == "authentication_required"

    # The platform injects this header once an auth provider is configured.
    status, _ = await client.get("/", {"x-ms-client-principal-name": "a@example.com"})
    assert status == 200


async def test_healthz_stays_open_for_probes(tmp_path):
    dash = Dashboard(seeded_store(tmp_path), auth=TRUSTED_HEADER)
    status, body = await ASGIClient(dash).get("/healthz")
    assert status == 200 and body["status"] == "ok"


async def test_security_headers_present(tmp_path):
    dash = Dashboard(seeded_store(tmp_path))
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        sent.append(m)

    await dash({"type": "http", "method": "GET", "path": "/", "headers": [],
                "query_string": b""}, receive, send)
    headers = {k.decode(): v.decode() for k, v in sent[0]["headers"]}
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in headers["content-security-policy"]


async def test_asset_path_traversal_is_refused(tmp_path):
    dash = Dashboard(seeded_store(tmp_path))
    client = ASGIClient(dash)
    for attempt in ("/assets/../../../../etc/passwd", "/assets/..%2f..%2fetc%2fpasswd"):
        status, _ = await client.get(attempt)
        assert status == 404, attempt


PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x20\x00\x00\x00\x10" + b"\x00" * 8
BRANDED = Branding(name="Acme", logo=Asset(PNG, "image/png", "logo.png"),
                   favicon=Asset(PNG, "image/png", "favicon.png"))


async def test_logo_asset_is_served(tmp_path):
    status, body = await ASGIClient(Dashboard(seeded_store(tmp_path), branding=BRANDED)).get(
        "/assets/brand/logo.png"
    )
    assert status == 200
    assert body == PNG


def test_window_parsing():
    assert window_to_since("all") is None
    assert window_to_since("7d") is not None
    assert window_to_since("nonsense") is None


# -- charts ----------------------------------------------------------------


def test_nice_ceiling_does_not_waste_the_plot():
    """A ceiling of 200 for a max of 129 flattens every bar."""
    assert _nice_ceiling(129) == 150
    assert _nice_ceiling(9) == 10
    assert _nice_ceiling(1) == 1
    assert _nice_ceiling(0) == 1
    assert _nice_ceiling(1_050) == 1200


def test_charts_handle_empty_input():
    assert "No data yet" in hbar([])
    assert "No data yet" in grouped_bars([])


def test_a_note_on_the_longest_bar_stays_inside_the_chart():
    rows = [("aws", 900), ("ssn", 10)]
    note = "900 per-laptop values"
    for width, label_width in ((640, 150), (1180, 190)):
        svg = hbar(rows, width=width, label_width=label_width, notes={"aws": note})
        x = float(re.search(r'<text x="([0-9.]+)"[^>]*class="c-value">900<', svg).group(1))
        assert x + 7 * len("900 \u00b7 " + note) <= width, (width, x)


def test_hbar_without_notes_is_unchanged_by_an_empty_notes_map():
    rows = [("claude-ai", 42), ("claude-code", 7)]
    assert hbar(rows, notes={}) == hbar(rows) == hbar(rows, notes=None)


def test_bars_carry_a_hover_title_and_a_direct_label():
    svg = hbar([("claude-ai", 42)])
    assert "<title>claude-ai: 42</title>" in svg
    assert ">42<" in svg  # direct label, not hover-only


def test_two_series_chart_always_has_a_legend():
    """Identity must never be colour-alone."""
    svg = grouped_bars([("2026-09-17", 10, 2)])
    assert 'class="legend"' in svg
    assert "Requests" in svg and "Would deny" in svg


def test_only_the_two_series_colours_are_used():
    """A third series colour needs the palette validator re-run, so the
    two-series chart uses exactly the two series colours."""
    colours = Branding().colours
    svg = Branding().fill(grouped_bars([("2026-09-17", 10, 2)]))
    used = set(re.findall(r"fill=\"(#[0-9A-Fa-f]{6})\"", svg))
    assert used == {colours["--chart-alert"], colours["--chart-primary"]}, used


async def test_page_makes_no_external_requests(tmp_path):
    """A findings page should not call out to a third party, and should
    render identically on an air-gapped network."""
    import re as _re

    html = Dashboard(seeded_store(tmp_path))._page("all")
    external = _re.findall(r"""(?:src|href)=["'](https?://[^"']+)""", html)
    assert external == [], external


async def test_headline_does_not_sum_requests_and_sessions(tmp_path):
    """A post-hoc session is not a request. Summing them produces a headline
    number with no meaning."""
    dash = Dashboard(seeded_store(tmp_path))
    p = dash._summary_json("all")
    assert p["total_requests"] == 3          # everything evaluated
    assert p["live_requests"] == 2
    assert p["scanned_sessions"] == 1
    s = __import__("forgd_verdict.store.query", fromlist=["build_summary"]).build_summary(
        list(dash.store.read_verdicts())
    )
    assert s.live_requests == 2
    assert s.scanned_sessions == 1
    html = dash._page("all")
    assert "Prompts evaluated live" in html
    assert "Sessions audited" in html


async def test_surface_table_shows_whether_an_inline_control_saw_it(tmp_path):
    """The coverage answer: a surface seen only post-hoc is one the
    inference hook never evaluated."""
    html = Dashboard(seeded_store(tmp_path))._page("all")
    assert ">Inline</th>" in html
    # The table pill, specifically: the coverage status line above the matrix
    # uses the same phrase, so count the pill rather than the string.
    assert html.count('<span class="pill cov-no">audit only</span>') == 1


def test_surface_row_tracks_each_control_point():
    from forgd_verdict.store.query import build_summary

    def r(src, surface):
        return VerdictRecord(source=src, observed_at="2026-09-17T10:00:00Z",
                             surface=surface, session_id=None)

    s = build_summary([
        r(SOURCE_INFERENCE_HOOK, "claude-ai"),
        r(SOURCE_COMPLIANCE_SCAN, "claude_code"),
        r(SOURCE_CODE_HOOK, "claude-code-local"),
    ])
    by = {x.surface: x for x in s.surfaces}
    assert by["claude-ai"].seen_by == ["inference hook"]
    assert by["claude-ai"].inline_coverage is True
    # One row, two controls: the local hook and the post-hoc scan both saw
    # Claude Code. Separate rows would read as though the code hook covered
    # a different product.
    assert by["claude-code"].seen_by == ["code hook", "compliance scan"]
    assert "claude-code-local" not in by
    # The code hook is an inline control -- it denies before the prompt
    # reaches inference -- so a surface it covers has inline coverage. Split
    # rows would hide that.
    assert by["claude-code"].inline_coverage is True


async def test_events_page_renders(tmp_path):
    dash = Dashboard(seeded_store(tmp_path))
    html = dash._events("all")
    assert "Every evaluated request" in html
    assert "Event log" in html
    # one row per evaluated request, newest first
    # The full timestamps: the page also prints the current time, and at
    # 20:10 UTC a bare "10:01" matched that first.
    assert html.index("2026-09-17 10:01:00") < html.index("2026-09-17 10:00:00")
    assert "regex:aws-access-key" in html
    assert "inference hook" in html and "compliance scan" in html


async def test_events_page_filters_by_control_point(tmp_path):
    dash = Dashboard(seeded_store(tmp_path))
    html = dash._events("all", source="compliance_scan")
    assert "regex:ssn" in html            # the compliance-scan finding
    assert "regex:aws-access-key" not in html   # the inference-hook one


async def test_events_page_filters_to_denials(tmp_path):
    dash = Dashboard(seeded_store(tmp_path))
    html = dash._events("all", action="deny")
    # 2 of the 3 seeded records reach a deny (one shadow, one real)
    assert html.count('class="act deny"') == 2
    assert "shadow" in html


INJECTED = "x%22%3E%3Ch1%3Einjected%3C%2Fh1%3E"


async def test_events_page_refuses_an_unknown_source(tmp_path):
    client = ASGIClient(Dashboard(seeded_store(tmp_path)))
    status, html = await client.get(f"/events?window=all&source={INJECTED}")
    assert status == 200
    assert "injected" not in html
    assert 'href="/events?window=all&amp;source=all" aria-current=true' in html
    assert "regex:ssn" in html and "regex:aws-access-key" in html


async def test_events_page_refuses_an_unknown_action(tmp_path):
    client = ASGIClient(Dashboard(seeded_store(tmp_path)))
    status, html = await client.get(f"/events?window=all&action={INJECTED}")
    assert status == 200
    assert "injected" not in html
    assert 'href="/events?window=all&amp;action=all" aria-current=true' in html


def test_event_filter_links_escape_their_values():
    from forgd_verdict.dashboard.render import render_events

    hostile = 'x"><h1>injected</h1>'
    html = render_events([], source=hostile, action=hostile)
    assert "<h1>injected" not in html
    assert 'href="/events?source=all&amp;action=x%22%3E%3Ch1%3Einjected%3C%2Fh1%3E"' in html
    assert 'href="/events?source=x%22%3E%3Ch1%3Einjected%3C%2Fh1%3E&amp;action=all"' in html


async def test_csp_restricts_forms_and_base_without_admins(tmp_path):
    dash = Dashboard(seeded_store(tmp_path))
    assert dash.admins is None
    _, _, headers = await ASGIClient(dash).request("GET", "/events")
    csp = headers["content-security-policy"]
    assert "form-action 'self'" in csp
    assert "base-uri 'none'" in csp


async def test_events_page_shows_no_prompt_content(tmp_path):
    html = Dashboard(seeded_store(tmp_path))._events("all")
    assert SECRET not in html
    assert "a" * 64 not in html  # nor the hashes: the page shows detector names


async def test_events_page_handles_an_empty_store(tmp_path):
    dash = Dashboard(LocalFileStore(tmp_path / "e", instance="t"))
    assert "No events in this window" in dash._events("7d")


async def test_nav_links_both_pages(tmp_path):
    dash = Dashboard(seeded_store(tmp_path))
    for html, current in ((dash._page("all"), "/"), (dash._events("all"), "/events")):
        assert 'href="/events"' in html and 'href="/"' in html
        assert f'href="{current}" aria-current=page' in html


async def test_coverage_matrix_names_surfaces_with_no_inline_check(tmp_path):
    """The headline finding, stated rather than left to be inferred."""
    html = Dashboard(seeded_store(tmp_path))._page("all")
    assert "<h2>Control points</h2>" in html
    # A status line, not a paragraph: the page states the gap without
    # explaining the product to the reader.
    assert 'class="status status-warn"' in html
    assert "audit only" in html
    assert "claude-code" in html


def test_matrix_renders_absence_differently_from_zero_magnitude():
    """'Never evaluated here' is categorically different from 'evaluated
    once', so it must not be the palest ramp step."""
    from forgd_verdict.dashboard.charts import SEQ, matrix, seq_step

    html = matrix(["claude-ai"], ["Inference hook", "Code hook"],
                  {("claude-ai", "Inference hook"): 12})
    assert "mx-none" in html            # the empty cell
    assert ">12<" in html
    assert seq_step(0, 10) == "none"
    assert seq_step(10, 10) in SEQ


def test_sequential_ramp_is_monotonic_in_lightness():
    """The check a sequential ramp must pass; the categorical validator
    does not apply to it."""
    from forgd_verdict.dashboard.charts import SEQ

    def lin(c):
        c /= 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    def L(h):
        r, g, b = (lin(int(h[i:i + 2], 16)) for i in (1, 3, 5))
        lp = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
        mp = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
        sp = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
        return 0.2104542553 * lp + 0.7936177850 * mp - 0.0040720468 * sp

    for ramp in ([Branding().fill(h) for h in SEQ], LAB_RAMP):
        ls = [L(h) for h in ramp]
        assert all(b > a for a, b in zip(ls, ls[1:], strict=False)), ls


LAB_RAMP = ("#1B2F48", "#24405C", "#2F5480", "#3C68A0", "#4A7AB5", "#6B95C6", "#8FB4DE")


async def test_slowest_frame_explains_itself(tmp_path):
    """A bare maximum invites someone to read it as a fault and ask for it
    to be reset. The worst frame is almost always a cold session start on a
    large transcript, so the tile carries the cause."""
    store = LocalFileStore(tmp_path / "f", instance="t")
    store.write_verdicts([
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:00:00Z",
                      surface="sheet_agent", total_ms=1250.0, body_bytes=158401,
                      messages_total=139, cache_hit=False),
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:01:00Z",
                      surface="sheet_agent", total_ms=470.0, body_bytes=569,
                      messages_total=140, cache_hit=True),
    ])
    dash = Dashboard(store)
    from forgd_verdict.store.query import build_summary

    s = build_summary(list(store.read_verdicts()))
    assert s.slowest["total_ms"] == 1250.0
    assert s.slowest["body_bytes"] == 158401
    assert s.slowest["cache_hit"] is False

    html = dash._page("all")
    assert "155 KB" in html          # 158401 bytes
    assert "139 msgs" in html
    assert "cold, full scan" in html
    assert "observed maximum" not in html   # the bare, uninterpretable label


def test_slowest_is_empty_without_timed_requests():
    from forgd_verdict.store.query import build_summary

    assert build_summary([]).slowest == {}


async def test_exactly_one_logo_and_one_meta_line(tmp_path):
    """The shared chrome renders the header. A duplicate was captured when
    the page body was extracted and rendered a second, unstyled logo at the
    PNG's natural size outside header.top."""
    for html in (
        Dashboard(seeded_store(tmp_path), branding=BRANDED)._page("all"),
        Dashboard(seeded_store(tmp_path), branding=BRANDED)._events("all"),
    ):
        # Exactly one logo <img>, in the header, and the favicon twice.
        assert html.count("/assets/brand/logo.png") == 1, "one header <img>"
        assert html.count("<img ") == 1, "no second logo in the body"
        assert html.count("/assets/brand/favicon.png") == 2, "icon + apple-touch-icon"
        assert 'sizes="32x16"' in html
        assert html.count('class="top-meta"') == 1
        assert html.count("</header>") == 1
        # Two wraps by design: one aligns the header, one the content.
        assert html.count('<div class="wrap">') == 2


async def test_ui_separates_prevention_from_detection(tmp_path):
    """A post-hoc scan cannot block. Presenting its findings in a shared
    allow/deny column implies it declined to."""
    dash = Dashboard(seeded_store(tmp_path))
    html = dash._page("all")
    assert "Would deny (inline)" in html
    assert "Detected in audit" in html
    assert "Live vs audit" in html
    # The distinction is carried by the column banding and the stat
    # sublabels, not by a paragraph explaining it.
    assert "Blocks before inference" in html
    assert "Detects after inference" in html
    assert "cannot block" in html

    events = dash._events("all")
    # The compliance-scan row reports a detection, not a denial.
    assert "detected" in events


def test_correlation_id_shows_the_distinguishing_end():
    """Compliance session ids are `clls_` plus a base64 payload whose
    leading characters are identical across sessions. Head-truncating made
    every row render the same string, defeating the column's only purpose."""
    from forgd_verdict.dashboard.render import _correlation

    a = "clls_eyJ2IjoxLCJvIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwicyI6IjAwMDAwMDAwMDAwMDAwMDEifQ"
    b = "clls_eyJ2IjoxLCJvIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwicyI6IjAwMDAwMDAwMDAwMDAwMDIifQ"
    assert _correlation(a) != _correlation(b), "ids must be distinguishable"
    assert _correlation("req_short") == "req_short"


async def test_findings_filter_includes_post_hoc_detections(tmp_path):
    """The filter used an inline-only concept, so it silently dropped every
    post-hoc detection."""
    store = LocalFileStore(tmp_path / "f", instance="t")
    store.write_verdicts([
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T10:00:00Z",
                      surface="claude_code", session_id="clls_1", findings_count=1,
                      findings=[FindingRow("regex:ssn", "block", "m", "h1")]),
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T10:01:00Z",
                      surface="claude_code", session_id="clls_2"),
    ])
    html = Dashboard(store)._events("all", source="compliance_scan", action="deny")
    assert "regex:ssn" in html
    assert html.count('class="act deny"') == 1   # the detection, not the clean one
    # And the chip is labelled for the control it filters.
    assert "With findings only" in html


async def test_post_hoc_rows_show_no_request_bytes(tmp_path):
    """A session has no request body; 0 reads as 'empty' rather than 'not
    applicable' -- the same error as reporting p95 of 0."""
    store = LocalFileStore(tmp_path / "f", instance="t")
    store.write_verdicts([
        VerdictRecord(source=SOURCE_COMPLIANCE_SCAN, observed_at="2026-09-17T10:00:00Z",
                      surface="claude_code", session_id="clls_1", messages_total=20),
    ])
    html = Dashboard(store)._events("all")
    assert ">&mdash;</td>" in html


async def test_detector_table_explains_what_each_detector_found(tmp_path):
    """`presidio:nrp` means nothing to a reader who has not seen Presidio's
    entity list, and the findings page is read by people who have not."""
    from forgd_verdict.dashboard.render import _detector_table
    from forgd_verdict.store.query import DetectorRow, Summary

    html = _detector_table(
        Summary(detectors=[
            DetectorRow(detector="presidio:nrp", severity="warn", count=3,
                        surfaces={"claude-ai"}, distinct_values={"a", "b"}),
        ])
    )
    assert "presidio:nrp" in html
    assert "nationality" in html


def test_finding_pills_collapse_repeats(tmp_path):
    """A pill per finding does not scale: one session can produce over a
    hundred presidio:person hits and render a table row thousands of
    pixels tall."""
    from forgd_verdict.dashboard.render import _finding_pills
    from forgd_verdict.store.base import FindingRow

    findings = [
        FindingRow("presidio:person", "warn", f"m[{i}]", f"h{i}")
        for i in range(120)
    ]
    html = _finding_pills(findings)
    assert html.count("presidio:person") == 1
    assert "<b>120</b>" in html


def test_finding_pills_lead_with_blocking_severity(tmp_path):
    """The row should lead with what someone has to act on, not with
    whichever detector happened to run first."""
    from forgd_verdict.dashboard.render import _finding_pills
    from forgd_verdict.store.base import FindingRow

    html = _finding_pills([
        FindingRow("presidio:person", "warn", "m", "h1"),
        FindingRow("presidio:person", "warn", "m", "h2"),
        FindingRow("regex:pan", "block", "m", "h3"),
    ])
    assert html.index("regex:pan") < html.index("presidio:person")


def test_finding_pills_cap_the_detector_count(tmp_path):
    from forgd_verdict.dashboard.render import _finding_pills
    from forgd_verdict.store.base import FindingRow

    html = _finding_pills(
        [FindingRow(f"regex:r{i}", "warn", "m", f"h{i}") for i in range(14)]
    )
    assert "+6 more" in html


def test_the_local_hook_shares_a_row_with_the_inference_hook():
    """Claude Code is one surface with two control points on it. Split across
    two rows, the coverage matrix reads as though the code hook covered a
    different product -- the same double-count the alias table exists to
    prevent. Which control saw it is carried by `source`, not by the row."""
    from forgd_verdict.store.query import normalize_surface

    assert normalize_surface("claude-code-local") == "claude-code"
    assert normalize_surface("claude_code") == "claude-code"


def test_detector_bars_are_coloured_by_severity():
    """Severity is a status the rows already carry, and encoding it changes
    what the chart says: a single hue made 201 low-precision NER locations
    look exactly as weighty as 47 checksum-validated NHS numbers."""
    from forgd_verdict.dashboard.render import render
    from forgd_verdict.store.query import DetectorRow, Summary

    summary = Summary(
        generated_at="2026-09-17T23:00:00Z",
        detectors=[
            DetectorRow("presidio:location", 971, "warn", {"cowork"},
                        {f"l{i}" for i in range(201)}),
            DetectorRow("checksum:nhs-number", 284, "block", {"claude-ai"},
                        {f"n{i}" for i in range(47)}),
        ],
    )
    html = render(summary)
    fills = set(re.findall(r'<path d="[^"]+" fill="(#[0-9A-Fa-f]{6})"', html))
    assert Branding().colours["--chart-alert"] in fills  # block
    assert Branding().colours["--chart-primary"] in fills  # warn
    # Status colour never travels alone.
    assert 'class="lg-dot"' in html


def test_the_strictest_severity_wins_within_a_family():
    """Families mix: `aws` is regex:aws-access-key at block while
    `access_key` is entropy:access_key at warn. A family carrying one
    block-severity value is a block finding."""
    from forgd_verdict.store.query import DetectorRow, Summary, family_severities

    sev = family_severities(Summary(detectors=[
        DetectorRow("regex:aws-access-key", 1, "block", set(), {"h1"}),
        DetectorRow("entropy:aws", 1, "warn", set(), {"h2"}),
    ]))
    assert sev["aws"] == "block"


def test_hbar_still_takes_a_single_hue():
    """The default stays one hue: the surfaces chart is magnitude across a
    category, where per-category colour would imply meaning that is not
    there."""
    from forgd_verdict.dashboard import charts

    html = Branding().fill(charts.hbar([("a", 3), ("b", 1)], charts.STEEL))
    assert set(re.findall(r'fill="(#[0-9A-Fa-f]{6})"', html)) == {
        Branding().colours["--chart-primary"]}


def test_the_matrix_says_which_controls_can_block():
    """The counts cannot carry this: 138 post-hoc sessions and 9 inline
    requests look like the same kind of number, and only one of them was a
    control that could have refused anything. Stated by position and label
    rather than colour, so it survives a printout."""
    from forgd_verdict.dashboard.render import render
    from forgd_verdict.store.query import Summary, SurfaceRow

    row = SurfaceRow("claude-ai", requests=147, live=9, post_hoc=138)
    html = render(Summary(surfaces=[row], generated_at="2026-09-17T23:00:00Z"))
    assert 'colspan="2">Blocks before inference' in html
    # Two of the four can only report: the compliance scan and OTel both
    # arrive after inference. Not a literal span -- see the test below,
    # which is what a hardcoded one broke.
    assert 'colspan="2">Detects after inference' in html


def test_every_control_point_column_sits_under_a_band():
    """Hardcoded spans meant adding the OTel column left it under no
    heading -- a detection-only control presented as if it were unclassified,
    which is the one thing this table exists to make unambiguous."""
    from forgd_verdict.dashboard.render import render
    from forgd_verdict.store.query import Summary, SurfaceRow

    row = SurfaceRow("claude-code", requests=1, otel=1)
    html = render(Summary(surfaces=[row], generated_at="2026-09-19T00:00:00Z"))
    spans = [int(n) for n in re.findall(r'colspan="(\d+)">(?:Blocks|Detects)', html)]
    assert sum(spans) == 4, spans


def test_the_matrix_divider_sits_only_at_the_group_boundary():
    """One rule between the inline columns and the post-hoc one, not a rule
    per column."""
    from forgd_verdict.dashboard import charts

    html = charts.matrix(
        ["s"], ["a", "b", "c"], {("s", "a"): 1, ("s", "b"): 2, ("s", "c"): 3},
        groups=[("inline", 2), ("post-hoc", 1)],
    )
    # One header cell plus one body cell carry the divider.
    assert html.count("mx-div") == 2


def test_the_matrix_still_renders_without_groups():
    from forgd_verdict.dashboard import charts

    html = charts.matrix(["s"], ["a"], {("s", "a"): 1})
    assert "mx-group" not in html
    assert "mx-div" not in html


def test_the_page_states_whether_verdicts_are_being_applied():
    """Every would-deny number on the page means something different
    depending on it, so it is stated for the whole page. Derived
    from the data: a record carries `shadow_action` only when the control
    decided one thing and did another."""
    from forgd_verdict.dashboard.render import render
    from forgd_verdict.store.query import Summary, SurfaceRow

    row = SurfaceRow("claude-ai", requests=9, live=9)
    shadow = render(Summary(surfaces=[row], live_requests=9, shadow_frames=3,
                            generated_at="2026-09-18T09:00:00Z"))
    assert "not blocking" in shadow

    live = render(Summary(surfaces=[row], live_requests=9, shadow_frames=0,
                          generated_at="2026-09-18T09:00:00Z"))
    assert '<span class="mode">enforcing</span>' in live
    assert "not blocking" not in live

    # With no inline traffic there is nothing to claim either way. Check for
    # the badge element, not the word: `.mode` is in the stylesheet always.
    none = render(Summary(generated_at="2026-09-18T09:00:00Z"))
    assert '<span class="mode' not in none


def test_the_page_does_not_explain_itself():
    """A vendor dashboard reports; it does not teach. These sentences all
    described how the product works rather than what it found."""
    from forgd_verdict.dashboard.render import render
    from forgd_verdict.store.query import Summary, SurfaceRow

    html = render(Summary(surfaces=[SurfaceRow("claude-ai", requests=9, live=9)],
                          live_requests=9, generated_at="2026-09-18T09:00:00Z"))
    for prose in (
        "Counted by distinct value",
        "In shadow mode a would-be denial still proceeds",
        "so they can block",
        "not a slow answer",
        "Which surface each control actually sees",
    ):
        assert prose not in html, prose


def _addressable_store(tmp_path):
    """A store whose frames carry request ids, which the shared seed does
    not. Exclusion is per request id, so the fixture has to have them."""
    from forgd_verdict.store.base import SOURCE_INFERENCE_HOOK, FindingRow, VerdictRecord
    from forgd_verdict.store.local import LocalFileStore

    store = LocalFileStore(tmp_path / "addr", instance="t")
    clean = VerdictRecord(source=SOURCE_INFERENCE_HOOK,
                          observed_at="2026-09-18T10:00:00Z",
                          surface="claude-ai", action="allow",
                          request_id="req-clean")
    bait = VerdictRecord(source=SOURCE_INFERENCE_HOOK,
                         observed_at="2026-09-18T10:01:00Z",
                         surface="claude-ai", action="deny",
                         request_id="req-bait", findings_count=1,
                         findings=[FindingRow("regex:aws-access-key", "block",
                                              "m", "h1")])
    store.write_verdicts([clean, bait])
    return store


async def test_the_page_says_when_frames_are_excluded(tmp_path):
    """A statistic that quietly omits records is worse than a noisy one, so
    the count is on the page whenever it is non-zero."""
    store = _addressable_store(tmp_path)
    assert "excluded from these rates" not in Dashboard(store)._page("all")

    store.set_excluded(["req-bait"])
    html = Dashboard(store)._page("all")
    assert "1 frame(s) excluded from these rates" in html
    assert "still in the event log" in html


async def test_excluded_frames_still_appear_in_the_event_log(tmp_path):
    """The record is omitted from the rates, not hidden. Someone auditing
    what happened must still be able to see it."""
    store = _addressable_store(tmp_path)
    store.set_excluded(["req-bait"])
    events = Dashboard(store)._events("all")
    assert "regex:aws-access-key" in events


async def test_exclusions_are_read_per_render(tmp_path):
    """Marking a frame takes effect on the next page load, not on a
    redeploy, so the marker is read per render rather than cached."""
    store = seeded_store(tmp_path)
    dash = Dashboard(store)
    assert dash._excluded() == set()
    store.set_excluded(["req-x"])
    assert dash._excluded() == {"req-x"}


# -- the policy tab ------------------------------------------------------
#
# The page exists because several tiles are uninterpretable without the
# config that produced them: "coverage lost to budget" needs the budget,
# "202 locations" needs to know LOCATION is an enabled entity, an empty
# code-hook column needs ship_mode. The tests that matter are the two that
# would be a security bug: secrets must not render, and the tab must sit
# behind the same gate as every other page.


async def test_the_policy_tab_renders_yaml(tmp_path):
    dash = Dashboard(LocalFileStore(tmp_path / "p", instance="t"))
    html = dash._policy()
    assert 'class="yaml"' in html
    # Content, not headings: the copy is not the contract. Keys arrive
    # wrapped by the highlighter, so match what it emits.
    assert '<span class="k">detectors</span>:' in html
    assert '<span class="k">t0_regex</span>:' in html
    # The nav gains a third entry and the other pages keep it.
    assert html.count(">Policy</a>") == 1
    assert ">Policy</a>" in dash._page("all")


async def test_the_policy_tab_never_renders_a_secret(tmp_path, monkeypatch):
    """The one way this page can be a security bug."""
    monkeypatch.setenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", "sk-ant-api01-SUPERSECRET")
    monkeypatch.setenv("FORGD_METRICS_TOKEN", "metrics-token-SUPERSECRET")
    monkeypatch.setenv("FORGD_HASH_SALT", "salt-SUPERSECRET")

    html = Dashboard(LocalFileStore(tmp_path / "p", instance="t"))._policy()
    assert "SUPERSECRET" not in html
    # Redacted rather than dropped: "no value" and "a value you cannot see"
    # are different facts when debugging a 401.
    assert "redacted" in html or "&lt;set&gt;" in html


async def test_a_policy_that_will_not_load_still_renders(tmp_path, monkeypatch):
    """A broken policy is exactly what someone opens this tab to find, so a
    blank page or a 500 is the worst possible response."""
    bad = tmp_path / "broken.yaml"
    bad.write_text("server: [this is not a mapping\n")
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(bad))

    html = Dashboard(LocalFileStore(tmp_path / "p", instance="t"))._policy()
    assert "could not be loaded" in html


async def test_the_policy_tab_is_behind_the_same_gate(tmp_path):
    """It shows configuration. It must not be the one unauthenticated page."""
    dash = Dashboard(LocalFileStore(tmp_path / "p", instance="t"), auth=TRUSTED_HEADER)
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    await dash({"type": "http", "method": "GET", "path": "/policy",
                "query_string": b"", "headers": []}, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    assert status == 401


# -- who the page was built for ------------------------------------------


async def test_the_page_names_the_signed_in_viewer(tmp_path):
    """"Is this actually authenticating?" should be answerable by looking.

    With a proxy in front, a misconfiguration that lets everyone through
    looks exactly like one that works -- the page renders either way. The
    only other way to tell is reading pod logs.
    """
    dash = Dashboard(seeded_store(tmp_path), auth=TRUSTED_HEADER)
    client = ASGIClient(dash)
    status, body = await client.get("/", {"x-ms-client-principal-name": "a@example.com"})
    assert status == 200
    assert "signed in as a@example.com" in body


async def test_an_unauthenticated_deployment_names_nobody(tmp_path):
    """Mode `none` identifies no one, so claiming a viewer would be a lie."""
    dash = Dashboard(seeded_store(tmp_path))
    status, body = await ASGIClient(dash).get("/")
    assert status == 200
    assert "signed in as" not in body


async def test_the_cache_never_serves_one_viewer_another_name(tmp_path):
    """The page is cached, and the key had to grow to carry the viewer.

    A cache keyed on the window alone serves a restricted viewer a page
    built for an unrestricted one. With the viewer named on a cached page,
    the same class of bug leaks an identity as well as data.
    """
    dash = Dashboard(seeded_store(tmp_path), auth=TRUSTED_HEADER)
    client = ASGIClient(dash)

    _, first = await client.get("/", {"x-ms-client-principal-name": "a@example.com"})
    _, second = await client.get("/", {"x-ms-client-principal-name": "b@example.com"})

    assert "signed in as a@example.com" in first
    assert "signed in as b@example.com" in second, (
        "the second viewer was served the first viewer's cached page"
    )
    assert "a@example.com" not in second


async def test_a_viewer_name_is_escaped(tmp_path):
    """It comes from a token claim, so it is attacker-influenced text."""
    dash = Dashboard(seeded_store(tmp_path), auth=TRUSTED_HEADER)
    status, body = await ASGIClient(dash).get(
        "/", {"x-ms-client-principal-name": "<script>alert(1)</script>"}
    )
    assert status == 200
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


async def test_the_policy_tab_does_not_claim_the_salt_is_unset(tmp_path, monkeypatch):
    """End to end, because the unit test passes whatever app.py calls.

    policy.py has the distinction, but no unit test fails if the dashboard
    calls redacted() without it -- removing `hashes_here=False` from app.py
    is caught only here. The dashboard is deliberately not given the salt, so UNSET
    there reads as a deployment hashing unsalted, and the obvious remedy is
    to hand it the salt.
    """
    monkeypatch.delenv("FORGD_HASH_SALT", raising=False)
    monkeypatch.delenv("FORGD_VERDICT_POLICY", raising=False)
    html = Dashboard(LocalFileStore(tmp_path / "p", instance="t"))._policy()
    assert "UNSET" not in html, "the Policy tab told an operator to add the salt here"
    assert "not given the salt" in html


# -- responsive layout ----------------------------------------------------
#
# These read the stylesheet rather than a rendered page, because the suite
# is offline and has no browser. Each one pins a specific way the page was
# 669px wide inside a 390px phone; a browser is what FOUND them, and this is
# what keeps them found.


def test_every_auto_fit_minimum_can_shrink_below_itself():
    """`minmax(200px,1fr)` does not shrink below 200px.

    auto-fit removes EMPTY tracks; it does not shrink a populated one below
    its stated minimum. So a `minmax(380px,1fr)` card grid held 380px on a
    350px content column and pushed the whole page wider than the screen --
    which reads as every section being too wide rather than as one grid
    rule. `min(380px,100%)` is the floor that yields.
    """
    from forgd_verdict.dashboard.render import PAGE_CSS

    # Comments stripped first. The rule above this one explains the bug by
    # quoting `minmax(200px,1fr)`, and scanning the raw stylesheet flagged
    # the explanation as the defect.
    declarations = re.sub(r"/\*.*?\*/", "", PAGE_CSS, flags=re.S)
    bare = re.findall(r"minmax\(\s*(\d+)px\s*,", declarations)
    assert not bare, (
        f"minmax() with a bare px minimum: {bare}. Use minmax(min(Npx,100%),1fr) "
        "so the track can shrink below its preferred width."
    )


def test_the_collapsed_section_row_track_can_shrink():
    """`1fr` is `minmax(auto,1fr)`, and that `auto` is MIN-CONTENT.

    The coverage matrix has fixed 104px cells, so its min-content is about
    580px -- which held the collapsed single-column track at 629px on a
    390px screen. Every sibling section inherited the width. `minmax(0,1fr)`
    is the track that is allowed to be narrower than its contents.
    """
    from forgd_verdict.dashboard.render import PAGE_CSS

    collapsed = PAGE_CSS.split("@media (max-width:1100px)")[1].split("}}")[0]
    assert "minmax(0,1fr)" in collapsed, collapsed
    assert "grid-template-columns:1fr" not in collapsed, collapsed


def test_the_stacked_breakpoint_releases_the_placed_sections():
    """Explicit placement survives the collapse unless it is undone.

    The wide layout pins the reconciliation figures to row 2 of the
    matrix's track and the round-trip column to a second track. At
    1100px there is only one track, and a section still asking for
    `grid-column:2` lands in an implicit column beside the page rather
    than under it.
    """
    from forgd_verdict.dashboard.render import PAGE_CSS

    wide = PAGE_CSS.split("@media (max-width:1100px)")[0]
    placed = {n for n in (2, 3) if f".section-row > section:nth-child({n})" in wide}
    assert placed == {2, 3}, f"placement changed; this test is checking {placed}"

    collapsed = PAGE_CSS.split("@media (max-width:1100px)")[1].split("}}")[0]
    for n in sorted(placed):
        assert f"section:nth-child({n})" in collapsed, (
            f"section {n} is placed explicitly in the wide layout and never "
            "released, so the single-column stack will not hold it"
        )
    assert "grid-column:auto" in collapsed and "grid-row:auto" in collapsed


def test_a_card_holding_a_table_scrolls_and_one_holding_a_chart_does_not():
    """Scoped with :has(table) on purpose.

    `.chart` sets `overflow:visible` so its value labels can sit outside the
    SVG box. Making every card a scroll container clips exactly those, so
    the rule names the cards that need it.
    """
    from forgd_verdict.dashboard.render import PAGE_CSS

    assert ".card:has(table){overflow-x:auto}" in PAGE_CSS
    # Not the unscoped version, which is the clipping bug.
    assert "\n.card{overflow-x:auto}" not in PAGE_CSS
    assert " .card{overflow-x:auto}" not in PAGE_CSS


def test_the_matrix_scrolls_at_full_size_rather_than_being_squeezed():
    """`width:104px` on a cell is a preference, not a floor.

    Inside a scrolling card the table shrank to fit and the columns came out
    at 84px and 43px -- which misaligns the one figure the grid exists to
    let you read across. `min-width:max-content` makes it scroll instead.
    """
    from forgd_verdict.dashboard.render import PAGE_CSS

    matrix = PAGE_CSS.split("table.matrix{")[1].split("}")[0]
    assert "min-width:max-content" in matrix, matrix


def test_the_rows_that_list_things_wrap():
    """Both are flex containers whose contents grow with the deployment.

    `.status` lists a surface name per uncovered surface and `.filters` is
    two groups on the event log. Neither wrapped, so both ran off the edge
    while their first item stayed put.
    """
    from forgd_verdict.dashboard.render import PAGE_CSS

    # Anchored to the start of a line: `.status{` also appears inside
    # `.aside .status{`, which is a different rule and matched first.
    for selector in ("\n.status{", "\n.filters{"):
        rule = PAGE_CSS.split(selector)[1].split("}")[0]
        assert "flex-wrap:wrap" in rule, (selector, rule)


def test_the_header_stops_being_one_fixed_row_on_a_phone():
    """Logo, tabs, org picker and the build block on one 68px flex row.

    It could not wrap, so it ran to 670px on a 390px screen and dragged the
    page with it. It also stops being sticky there: three stacked rows
    pinned to the top of a phone is most of the screen.
    """
    from forgd_verdict.dashboard.render import PAGE_CSS

    mobile = PAGE_CSS.split("@media(max-width:720px){")[1]
    assert "header.top .wrap{flex-wrap:wrap" in mobile, mobile[:400]
    assert "header.top{position:static}" in mobile, mobile[:400]


def test_a_heading_carrying_a_path_can_break():
    """The policy tab titles its source with the path it loaded.

    A path offers no break opportunity to the default `overflow-wrap`, so
    `/run/forgd/policy/policy.yaml` ran 29px past a 280px column. Not scoped
    to a breakpoint: a long path overflows a narrow column at any width.
    """
    from forgd_verdict.dashboard.render import PAGE_CSS

    h2 = PAGE_CSS.split("\nh2{")[1].split("}")[0]
    assert "overflow-wrap:anywhere" in h2, h2


def test_the_page_declares_a_viewport():
    """Without it a phone lays the page out at 980px and scales it down, so
    every fix above would be invisible -- the page would merely be small."""
    from forgd_verdict.dashboard.render import render
    from forgd_verdict.store.query import Summary

    html = render(Summary(generated_at="2026-09-20T00:00:00Z"))
    assert '<meta name="viewport" content="width=device-width,initial-scale=1">' in html


# -- the dashboard makes no external request -----------------------------


def test_tokens_css_imports_nothing():
    """`render.py` claimed there were no external requests at all, and
    `tokens.css` opened with an `@import` from fonts.googleapis.com --
    so the dashboard fetched from Google on every load, and the CSP had
    been widened to permit it.

    On an egress-filtered network the import failed silently and the page
    rendered differently there than here, which is the failure the claim
    was meant to rule out.
    """
    from forgd_verdict.dashboard.app import ASSETS

    css = (ASSETS / "tokens.css").read_text()
    # Comments stripped first. The file quotes the old `@import` line to
    # say what it replaced, and a line-prefix filter does not catch a
    # quoted example indented inside a block comment.
    code = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    assert "@import" not in code, code[:200]
    assert "fonts.googleapis.com" not in code
    assert "url('/assets/fonts/" in code


def test_the_csp_names_no_third_party_origin():
    import tempfile

    from forgd_verdict.store.local import LocalFileStore

    with tempfile.TemporaryDirectory() as tmp:
        dash = Dashboard(LocalFileStore(tmp, instance="t"))
        # Reach the header the same way a response does.
        sent = []

        async def send(msg):
            sent.append(msg)

        import asyncio

        asyncio.run(dash._send(send, 200, b"x", "text/plain"))
    headers = dict(sent[0]["headers"])
    csp = headers[b"content-security-policy"].decode()
    assert "fonts.googleapis.com" not in csp
    assert "fonts.gstatic.com" not in csp
    assert "font-src 'self'" in csp
    assert "default-src 'none'" in csp


def test_the_fonts_ship_in_the_package():
    """A single `*` in the package-data glob does not recurse, so
    `assets/fonts/` was absent from the wheel -- present from a source
    checkout and missing from the image, where the page falls back to
    system fonts silently."""
    from forgd_verdict.dashboard.app import ASSETS

    for name in ("inter-latin-var.woff2", "roboto-mono-latin-var.woff2"):
        f = ASSETS / "fonts" / name
        assert f.exists() and f.stat().st_size > 10_000, name
    # And the licences, because redistributing them is what the OFL is for.
    assert (ASSETS / "fonts" / "OFL-Inter.txt").exists()
    assert (ASSETS / "fonts" / "OFL-RobotoMono.txt").exists()


def test_the_agent_check_column_appears_only_when_there_are_agent_checks():
    """Most deployments build no agents of their own, and an always-present
    column would be empty on all of them."""
    from forgd_verdict.dashboard.render import render
    from forgd_verdict.store.query import Summary, SurfaceRow

    without = render(Summary(surfaces=[SurfaceRow("claude-ai", requests=9, live=9)],
                             generated_at="2026-09-23T00:00:00Z"))
    assert "Agent check" not in without.split('<div class="eyebrow">Coverage</div>')[1][:4000]
    with_agent = render(Summary(
        surfaces=[SurfaceRow("claude-ai", requests=9, live=9),
                  SurfaceRow("agent:support-bot", requests=4, agent=4)],
        generated_at="2026-09-23T00:00:00Z"))
    matrix = with_agent.split('<div class="eyebrow">Coverage</div>')[1][:6000]
    assert "Agent check" in matrix and "agent:support-bot" in matrix


class _WriteTrap:
    """A store whose write and marker methods fail the test if called."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        if name.startswith(("write_", "set_", "put_")):
            def trap(*args, **kwargs):
                raise AssertionError(f"the dashboard called store.{name}")
            return trap
        return getattr(self._inner, name)


async def _status(app, method: str, path: str, body: bytes = b"") -> tuple[int, dict]:
    scope = {"type": "http", "method": method, "path": path, "headers": [],
             "query_string": b""}
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(m):
        sent.append(m)

    await app(scope, receive, send)
    return sent[0]["status"], dict(sent[0]["headers"])


async def test_the_dashboard_answers_only_get_and_head(tmp_path):
    """Read-only by construction: no route acts on a POST, PUT, PATCH
    or DELETE, so none can edit policy or records."""
    app = Dashboard(_WriteTrap(seeded_store(tmp_path)))
    for path in ("/", "/policy", "/events", "/api/summary", "/healthz", "/assets/x"):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            status, headers = await _status(app, method, path, b"detectors=off")
            assert status == 405, (method, path, status)
            assert headers[b"allow"] == b"GET, HEAD"
        assert (await _status(app, "GET", path))[0] != 405, path


async def test_a_stored_record_with_wrong_types_still_renders(tmp_path):
    """The store is append-only, so a record written before intake checked
    types is read for as long as it is retained."""
    store = LocalFileStore(tmp_path / "findings", instance="t")
    store.write_verdicts([
        VerdictRecord(
            source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:00:00Z",
            surface=7, action="deny", scan_ms="boom", total_ms="slow",
            messages_scanned="<script>x</script>", messages_total=True,
            body_bytes="<b>big</b>", cache_hit="yes", session_updated_at=5,
            tiers_dropped="<i>ner</i>", findings_count="1",
            findings=[FindingRow("regex:aws-access-key", "block",
                                 "msg[2].content[0]", "a" * 64)],
        ),
    ])
    client = ASGIClient(Dashboard(store))
    for path in ("/events?window=all", "/?window=all", "/api/summary?window=all"):
        status, body = await client.get(path)
        assert status == 200, path
    _, html = await client.get("/events?window=all")
    assert "regex:aws-access-key" in html, "the record was dropped, not repaired"
    for markup in ("<script>x</script>", "<b>big</b>", "<i>ner</i>"):
        assert markup not in html


def test_an_event_page_that_stopped_early_says_older_events_are_not_shown():
    from forgd_verdict.dashboard.render import render_events
    from forgd_verdict.store.views import EventCursor

    html = render_events([], older=EventCursor.done("2026-09-16").encode(),
                         older_label="2026-09-16 00:00:00 UTC")
    assert "Older events" in html
    assert "reads back to 2026-09-16 00:00:00 UTC" in html
    assert "No events in this window" not in html
    assert "reads back" not in render_events([])
    assert "<script>" not in render_events([], older="<script>", older_label="<script>")


class _CountingStore:
    """A store that counts verdict reads."""

    def __init__(self, store):
        self._store = store
        self.reads = 0

    def read_verdicts(self, *a, **kw):
        self.reads += 1
        return self._store.read_verdicts(*a, **kw)

    def __getattr__(self, name):
        return getattr(self._store, name)


async def test_back_to_back_summary_api_calls_read_the_store_once(tmp_path):
    store = _CountingStore(seeded_store(tmp_path))
    client = ASGIClient(Dashboard(store))
    _, first = await client.get("/api/summary?window=all")
    _, second = await client.get("/api/summary?window=all")
    assert first == second
    assert store.reads == 1
    await client.get("/api/summary?window=7d")
    assert store.reads == 2


def test_the_summary_api_cache_keeps_scopes_and_the_html_page_apart(tmp_path):
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:00:00Z",
                      tenant_hash="org_aaa"),
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:00:00Z",
                      tenant_hash="org_bbb"),
        VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:00:00Z",
                      tenant_hash="org_bbb"),
    ])
    dash = Dashboard(store)
    assert dash._summary_json("all", frozenset({"org_aaa"}))["total_requests"] == 1
    assert dash._summary_json("all", frozenset({"org_bbb"}))["total_requests"] == 2
    assert dash._summary_json("all", None)["total_requests"] == 3
    assert dash._summary_json("all", frozenset())["total_requests"] == 0
    html = dash._page("all")
    assert isinstance(html, str) and "<html" in html
    assert isinstance(dash._summary_json("all", None), dict)
    assert {k[0] for k in dash._cache} == {"page", "api-summary"}
    assert len([k for k in dash._cache if k[0] == "api-summary"]) == 4


def test_an_admin_action_clears_the_summary_api_cache(tmp_path):
    store = _CountingStore(seeded_store(tmp_path))
    dash = Dashboard(store)
    dash._summary_json("all")
    dash._summary_json("all")
    assert store.reads == 1
    dash._cache.clear()
    dash._summary_json("all")
    assert store.reads == 2


def test_a_family_only_the_code_hook_saw_shows_its_per_laptop_values_beside_the_bar():
    from forgd_verdict.dashboard.render import render
    from forgd_verdict.store.query import build_summary

    def finding(detector, digest):
        return [FindingRow(detector, "block", "tool_input", digest)]

    records = [VerdictRecord(source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-17T10:00:00Z",
                             surface="claude-ai", action="deny", findings_count=1,
                             findings=finding("regex:aws-access-key", "sha256:server"))]
    records += [VerdictRecord(source=SOURCE_CODE_HOOK, observed_at="2026-09-17T10:00:00Z",
                              surface="claude-code", action="deny", findings_count=1,
                              salt_namespace=f"fleet:dev{n}",
                              findings=finding("regex:us-ssn", f"sha256:dev{n}"))
                for n in range(3)]
    html = render(build_summary(records, []))
    section = html[html.index("<h2>Detectors</h2>"):]
    section = section[:section.index("</section>")]
    chart = section[section.index("<svg"):section.index("</svg>")]
    values = dict(re.findall(r'class="c-label">([^<]+)</text>.*?class="c-value">(.*?)</text>',
                             chart, re.S))
    assert set(values) == {"aws", "ssn"}
    assert values["aws"] == "1"
    assert re.fullmatch(r'0<tspan class="c-note"> · 3 per-laptop values</tspan>',
                        values["ssn"])
    assert "Per-laptop values" in section
    assert re.search(r"ssn: 0</title>", chart) is None, "a zero bar draws no path"
    unit = re.search(r'<p class="unit">(.*?)</p>', section, re.S).group(1)
    assert "deployment salt only" in unit and "per-laptop values" in unit
