"""The dashboard with no `dashboard.branding`: neutral, and serving brand assets
only when they are configured."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
from test_dashboard_views_pinned import (  # noqa: F401
    PAGES,
    _admin,
    _get,
    _get_typed,
    _open,
    _topology,
    fixed_policy,
    frozen,
    frozen_time,
)

from forgd_verdict.dashboard.app import Dashboard
from forgd_verdict.dashboard.branding import Asset, Branding
from forgd_verdict.store import LocalFileStore, VerdictRecord
from forgd_verdict.store.base import SOURCE_INFERENCE_HOOK

REPO = Path(__file__).parents[1]

# Every colour the dashboard used before branding was configuration, as RGB
# with alpha ignored: the `:root` colours of the old tokens.css and the
# literals of render.py, controls.py and charts.py. White and black are
# excluded.
FORBIDDEN = frozenset({
    "#040C18", "#050F1E", "#07152A", "#0A1828", "#0C1F3A", "#0F2540", "#142E4D",
    "#1B2F48", "#22E06A", "#24405C", "#2F5480", "#2F9E63", "#333B4A", "#3C68A0",
    "#4A6078", "#4A7AB5", "#506880", "#5A7EC7", "#5A9E6F", "#5B9A6F", "#6B8A7A",
    "#6B95C6", "#8899AA", "#8B6F47", "#8FB4DE", "#A0B4C8", "#A85A3F", "#B03A2E",
    "#B4714E", "#B85C5C", "#C75B3A", "#D0DCE8", "#D97757", "#E0A090", "#E6E9EF",
    "#E89578", "#E8EEF5", "#EAF3FF", "#F0F4F8", "#FF4D3D", "#FF9A5A",
})

_HEX = re.compile(r"(?<![&\w])#([0-9A-Fa-f]{8}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{3,4})\b")
_RGB = re.compile(r"rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)")


def _colours(text: str) -> set[str]:
    """Every hex and rgb()/rgba() colour in `text`, as #RRGGBB."""
    out = set()
    for h in _HEX.findall(text):
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        out.add("#" + h[:6].upper())
    for r, g, b in _RGB.findall(text):
        out.add("#" + "".join(f"{int(float(c)):02X}" for c in (r, g, b)))
    return out


@pytest.fixture
async def neutral(tmp_path, frozen, fixed_policy, frozen_time,  # noqa: F811
                  control_identity, signing_env):
    """Every page in PAGES and tokens.css, unbranded."""
    apps = {"open": _open(tmp_path / "open"), "topology": _topology(tmp_path / "topo"),
            "admin": _admin(tmp_path / "admin")}
    out = {}
    for name, which, path in PAGES:
        status, body = await _get(apps[which], path)
        assert status == 200, name
        # The tmp path carries the test's name.
        out[name] = body.decode().replace(str(tmp_path), "<tmp>")
    status, ctype, body = await _get_typed(apps["open"], "/assets/tokens.css")
    assert status == 200 and ctype == "text/css"
    out["tokens.css"] = body.decode()
    return out


async def test_no_forgd_word_unbranded(neutral):
    for name, text in neutral.items():
        # `forgd-verdict` names the product; /run/forgd/ is where the chart
        # mounts the policy, quoted in a page CSS comment.
        rest = text.replace("forgd-verdict", "").replace("/run/forgd/", "")
        assert "forgd" not in rest.lower(), (name, rest[rest.lower().index("forgd") - 80:][:160])


async def test_no_colour_from_before_unbranded(neutral):
    for name, text in neutral.items():
        assert not _colours(text) & FORBIDDEN, (name, sorted(_colours(text) & FORBIDDEN))


async def test_unbranded_pages_carry_no_logo_favicon_footer_or_marker(neutral):
    for name, text in neutral.items():
        assert "<@" not in text, name
        if name.endswith(".html"):
            assert "<img " not in text and 'rel="icon"' not in text, name
            assert "<footer>" not in text, name
            assert "/assets/brand/" not in text, name
            assert ">verdict</span>" in text, name


def test_no_brand_files_ship_in_the_package():
    listed = subprocess.run(["git", "ls-files", "src/forgd_verdict/dashboard/assets"],
                            cwd=REPO, capture_output=True, text=True, check=False)
    if listed.returncode == 0:
        files = listed.stdout
    else:
        # Not a git checkout, as in an exported tree: every file present ships.
        assets = REPO / "src" / "forgd_verdict" / "dashboard" / "assets"
        files = "\n".join(str(p.relative_to(REPO)) for p in assets.rglob("*") if p.is_file())
    assert files.strip()
    assert not [f for f in files.split() if Path(f).name.startswith("forgd-")], files


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"/>'


@pytest.mark.parametrize("path", ["/assets/brand/logo.png", "/assets/brand/favicon.png",
                                  "/assets/brand/logo.svg", "/assets/forgd-white-logo.png",
                                  "/assets/forgd-mark.png"])
async def test_brand_assets_are_404_unset(tmp_path, path):
    status, _, _ = await _get_typed(Dashboard(LocalFileStore(tmp_path / "s", instance="t")),
                                    path)
    assert status == 404


async def _headers(app, path):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app({"type": "http", "method": "GET", "path": path, "query_string": b"",
               "headers": []}, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"], start["headers"], b"".join(m.get("body", b"") for m in sent[1:])


async def test_brand_assets_are_served_with_their_type(tmp_path):
    app = Dashboard(LocalFileStore(tmp_path / "s", instance="t"), branding=Branding(
        logo=Asset(SVG, "image/svg+xml", "logo.svg"),
        favicon=Asset(PNG, "image/png", "favicon.png")))
    status, headers, body = await _headers(app, "/assets/brand/logo.svg")
    assert (status, body) == (200, SVG)
    assert (b"content-type", b"image/svg+xml") in headers
    csps = [v for k, v in headers if k == b"content-security-policy"]
    assert b"default-src 'none'; script-src 'none'; style-src 'unsafe-inline'" in csps
    status, headers, body = await _headers(app, "/assets/brand/favicon.png")
    assert (status, body) == (200, PNG)
    assert (b"content-type", b"image/png") in headers
    assert len([k for k, _ in headers if k == b"content-security-policy"]) == 1
    for wrong in ("/assets/brand/logo.png", "/assets/brand/favicon.svg",
                  "/assets/brand/../tokens.css"):
        assert (await _headers(app, wrong))[0] == 404, wrong


async def test_a_theme_reaches_the_served_tokens_css(tmp_path):
    app = Dashboard(LocalFileStore(tmp_path / "s", instance="t"),
                    branding=Branding.from_policy({"theme": {"--bg-card": "#123456"}}))
    _, _, body = await _headers(app, "/assets/tokens.css")
    assert "  --bg-card: #123456;\n" in body.decode()


async def test_rendered_data_cannot_carry_a_colour_marker(tmp_path):
    """A marker in stored data is escaped like any other markup, so
    `Branding.fill` never sees it."""
    store = LocalFileStore(tmp_path / "s", instance="t")
    store.write_verdicts([VerdictRecord(
        source=SOURCE_INFERENCE_HOOK, observed_at="2026-09-20T10:00:00Z",
        request_id="<@--bg-card@>", surface="<@--warn-text@>", action="allow")])
    html = Dashboard(store)._events("all")
    assert "&lt;@--bg-card@&gt;" in html and "&lt;@--warn-text@&gt;" in html
