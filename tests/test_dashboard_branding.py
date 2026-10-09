"""`dashboard.branding`: the neutral default, what it accepts, and every refusal.

Each refusal is a BrandingError naming the dotted key, and none quotes the
value, the file or the `data:` payload that was refused.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from forgd_verdict.dashboard import branding as b
from forgd_verdict.dashboard.app import Dashboard, create_app
from forgd_verdict.dashboard.branding import (
    MAX_IMAGE_BYTES,
    Branding,
    BrandingError,
)
from forgd_verdict.policy import ENV_OVERRIDES
from forgd_verdict.store import LocalFileStore

TOKENS_CSS = Path(b.__file__).with_name("assets") / "tokens.css"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 16
SVG = (b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" '
       b'xmlns:xlink="http://www.w3.org/1999/xlink"><defs><path id="p" d="M0 0"/></defs>'
       b'<use xlink:href="#p"/></svg>')
MARKER = "PAYLOAD7Q"


def _uri(mime: str, data: bytes) -> str:
    return f"data:{mime};base64,{base64.b64encode(data).decode()}"


def test_unset_is_neutral():
    for neutral in (Branding.from_policy(None), Branding()):
        assert neutral.name == "verdict"
        assert neutral.logo is None and neutral.favicon is None
        assert neutral.mode == "dark" and dict(neutral.theme) == {}
        assert neutral.footer is None and neutral.chart_palette is None
    assert "forgd" not in Branding().name.lower()


def test_the_dashboard_defaults_to_neutral(tmp_path):
    assert Dashboard(LocalFileStore(tmp_path / "s", instance="t")).branding == Branding()


def test_every_field_parses(tmp_path):
    logo = tmp_path / "logo.bin"
    logo.write_bytes(PNG)
    got = Branding.from_policy({
        "name": "Acme", "logo": str(logo), "favicon": _uri("image/svg+xml", SVG),
        "mode": "dark", "theme": {"--bg-card": "#0C1F3A",
                                  "--brand-accent-bg": "rgba(217, 119, 87, 0.10)",
                                  "--text-dim": "hsl(210, 24%, 38%)"},
        "footer": {"text": "Acme", "link": "https://acme.example/x"},
        "chart_palette": ["#abc", "#AABBCCDD"],
    })
    assert got.name == "Acme"
    assert (got.logo.content_type, got.logo.filename, got.logo.data) == ("image/png",
                                                                          "logo.png", PNG)
    assert (got.favicon.content_type, got.favicon.filename) == ("image/svg+xml",
                                                                 "favicon.svg")
    assert got.theme["--brand-accent-bg"] == "rgba(217, 119, 87, 0.10)"
    assert got.footer == b.Footer("Acme", "https://acme.example/x")
    assert got.chart_palette == ("#abc", "#AABBCCDD")
    assert Branding.from_policy({"logo": _uri("image/webp", WEBP)}).logo.content_type \
        == "image/webp"
    assert Branding.from_policy({"footer": False}).footer is None
    assert Branding.from_policy({"footer": {"text": "Acme"}}).footer == b.Footer("Acme")


@pytest.mark.parametrize("raw, key", [
    ({"theme": {"--bg-card": "red"}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--bg-card": "#12345"}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--bg-card": "rgb(1, 2, var(--x))"}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--bg-card": "#fff\n"}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--bg-card": 123}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--bg-card": "red; background:url(x)"}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--bg-card": "#fff;}"}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--bg-card": "#fff</style>"}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--bg-card": "</style><script>"}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--bg-card": "#fff/**/"}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--bg-card": "url(https://x.example/a)"}}, "dashboard.branding.theme.--bg-card"),
    ({"theme": {"--forgd-orange": "#fff"}}, "dashboard.branding.theme.--forgd-orange"),
    ({"theme": {"--radius-sm": "#fff"}}, "dashboard.branding.theme.--radius-sm"),
    ({"theme": {"--made-up": "#fff"}}, "dashboard.branding.theme.--made-up"),
    ({"theme": ["#fff"]}, "dashboard.branding.theme"),
    ({"colour": "#fff"}, "dashboard.branding.colour"),
    ({"footer": {"text": "a", "href": "https://x"}}, "dashboard.branding.footer.href"),
    ({"footer": {"text": "a", "link": "http://x.example"}}, "dashboard.branding.footer.link"),
    ({"footer": {"text": "a", "link": "javascript:alert(1)"}}, "dashboard.branding.footer.link"),
    ({"footer": {"text": "a", "link": "https://x\"onmouseover=1"}},
     "dashboard.branding.footer.link"),
    ({"footer": {"link": "https://x"}}, "dashboard.branding.footer.text"),
    ({"footer": "Acme"}, "dashboard.branding.footer"),
    ({"mode": "light"}, "dashboard.branding.mode"),
    ({"name": ""}, "dashboard.branding.name"),
    ({"name": "a\nb"}, "dashboard.branding.name"),
    ({"name": "x" * 33}, "dashboard.branding.name"),
    ({"chart_palette": []}, "dashboard.branding.chart_palette"),
    ({"chart_palette": ["#fff", "blue"]}, "dashboard.branding.chart_palette[1]"),
], ids=lambda v: v if isinstance(v, str) else None)
def test_refusals_name_their_key(raw, key):
    with pytest.raises(BrandingError) as err:
        Branding.from_policy(raw)
    assert err.value.key == key
    assert str(err.value).startswith(key + ": ")


def test_a_non_mapping_is_refused():
    with pytest.raises(BrandingError, match=r"^dashboard\.branding: "):
        Branding.from_policy(["Acme"])


def _svg(body: str) -> bytes:
    return f'<svg xmlns="http://www.w3.org/2000/svg">{body}<!-- {MARKER} --></svg>'.encode()


IMAGE_REFUSALS = [
    ("oversized-data", _uri("image/png", PNG + MARKER.encode() * (MAX_IMAGE_BYTES // 9))),
    ("svg-script", _uri("image/svg+xml", _svg("<script>alert(1)</script>"))),
    ("svg-script-upper", _uri("image/svg+xml", _svg("<SCRIPT>alert(1)</SCRIPT>"))),
    ("svg-onload", _uri("image/svg+xml", _svg('<rect onload="alert(1)"/>'))),
    ("svg-onload-root", _uri("image/svg+xml",
                             f'<svg onload="alert(1)"><!-- {MARKER} --></svg>'.encode())),
    ("svg-javascript", _uri("image/svg+xml", _svg('<a href="javascript:alert(1)"/>'))),
    ("svg-foreign", _uri("image/svg+xml", _svg("<foreignObject/>"))),
    ("svg-external-href", _uri("image/svg+xml", _svg('<image href="https://x.example/a"/>'))),
    ("svg-xlink-external", _uri("image/svg+xml",
                                _svg("<use xlink:href='other.svg#a'/>"))),
    ("svg-unquoted-href", _uri("image/svg+xml", _svg("<use href=x.svg/>"))),
    ("svg-charref", _uri("image/svg+xml", _svg('<a href="&#106;avascript:x"/>'))),
    ("svg-import", _uri("image/svg+xml",
                        _svg("<style>@import url(https://e.x/a.css);</style>"))),
    ("svg-import-bare", _uri("image/svg+xml", _svg('<style>@IMPORT "https://e.x/a.css";</style>'))),
    ("svg-fill-url", _uri("image/svg+xml", _svg('<rect fill="url(https://e.x/p.svg#g)"/>'))),
    ("svg-style-url", _uri("image/svg+xml",
                           _svg("<rect style=\"background:url('//e.x/a')\"/>"))),
    ("svg-url-spaced", _uri("image/svg+xml", _svg('<rect fill="URL(  \'data:x\')"/>'))),
    ("svg-css-escape", _uri("image/svg+xml", _svg('<rect style="fill:u\\72l(//e.x)"/>'))),
    ("svg-doctype", _uri("image/svg+xml", f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "'
                         f'{MARKER}">]><svg/>'.encode())),
    ("data-html", _uri("text/html", f"<p>{MARKER}</p>".encode())),
    ("data-html-plain", f"data:text/html,<p>{MARKER}</p>"),
    ("png-declared-not-png", _uri("image/png", f"GIF89a{MARKER}".encode())),
    ("png-declared-svg-bytes", _uri("image/png", _svg(""))),
    ("svg-declared-png-bytes", _uri("image/svg+xml", PNG + MARKER.encode())),
    ("not-an-image", _uri("image/png", f"GIF89a{MARKER}".encode())),
    ("bad-base64", f"data:image/png;base64,{MARKER}!!"),
    ("no-comma", f"data:image/png;base64{MARKER}"),
]


@pytest.mark.parametrize("field", ["logo", "favicon"])
@pytest.mark.parametrize("name, value", IMAGE_REFUSALS, ids=[n for n, _ in IMAGE_REFUSALS])
def test_image_refusals_name_the_key_and_quote_nothing(field, name, value):
    with pytest.raises(BrandingError) as err:
        Branding.from_policy({field: value})
    msg = str(err.value)
    assert err.value.key == f"dashboard.branding.{field}", msg
    assert MARKER not in msg and "base64," not in msg, msg


def test_a_path_is_sniffed_capped_and_quoted_nowhere(tmp_path):
    secret = tmp_path / "id_rsa.png"
    secret.write_text("-----BEGIN " + f"PRIVATE KEY----- {MARKER}")
    big = tmp_path / "big.png"
    big.write_bytes(PNG + b"\x00" * MAX_IMAGE_BYTES)
    script = tmp_path / "mark.svg"
    script.write_bytes(_svg("<script/>"))
    for path, reason in ((secret, "not a PNG"), (big, "over 256 KB"),
                         (script, "<script"), (tmp_path / "absent.png", "cannot be read"),
                         (tmp_path, "cannot be read")):
        with pytest.raises(BrandingError) as err:
            Branding.from_policy({"logo": str(path)})
        msg = str(err.value)
        assert msg.startswith("dashboard.branding.logo: ") and reason in msg, msg
        assert MARKER not in msg and "PRIVATE" not in msg, msg


def test_an_image_at_the_cap_is_accepted():
    data = PNG + b"\x00" * (MAX_IMAGE_BYTES - len(PNG))
    assert Branding.from_policy({"logo": _uri("image/png", data)}).logo.data == data


def test_a_fragment_only_svg_is_accepted():
    assert Branding.from_policy({"logo": _uri("image/svg+xml", SVG)}).logo.data == SVG


@pytest.mark.parametrize("ref", ['fill="url(#grad)"', "fill=\"url( '#grad' )\"",
                                 'style="fill:URL(#grad)"'])
def test_an_svg_url_to_a_fragment_is_accepted(ref):
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="grad"/>'
           b"</defs><rect " + ref.encode() + b"/></svg>")
    assert Branding.from_policy({"logo": _uri("image/svg+xml", svg)}).logo.data == svg


def test_branding_is_not_environment_tunable():
    assert not [n for n, (path, _) in ENV_OVERRIDES.items()
                if path[:2] == ("dashboard", "branding")]


def test_create_app_passes_branding(tmp_path, monkeypatch):
    policy = tmp_path / "policy.yaml"
    policy.write_text(json.dumps({"dashboard": {"branding": {
        "name": "Acme", "theme": {"--bg-card": "#000"}}}}))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))
    app = create_app(str(tmp_path / "s"))
    assert app.branding.name == "Acme" and dict(app.branding.theme) == {"--bg-card": "#000"}


def test_create_app_refuses_bad_branding(tmp_path, monkeypatch):
    policy = tmp_path / "policy.yaml"
    policy.write_text(json.dumps({"dashboard": {"branding": {
        "theme": {"--bg-card": "red; background:url(x)"}}}}))
    monkeypatch.setenv("FORGD_VERDICT_POLICY", str(policy))
    with pytest.raises(BrandingError, match=r"dashboard\.branding\.theme\.--bg-card"):
        create_app(str(tmp_path / "s"))


NAME_32 = "Acme Corporation & Partners Ltd."


def test_a_long_name_is_shown_in_full_except_in_the_topology_core():
    """The core box fits 12 characters; the header and footer take all 32."""
    from types import SimpleNamespace

    from forgd_verdict.dashboard import render
    from forgd_verdict.store.query import Summary

    assert len(NAME_32) == 32
    branding = Branding.from_policy({"name": NAME_32, "footer": {"text": "acme.example"}})
    surface = SimpleNamespace(state="live", label="claude.ai", detail="ok", icon="chat",
                              requests=3, periodic=False)
    svg = render._topology([], [surface], name=branding.name)
    assert ('class="tpx-core-t"><title>Acme Corporation &amp; Partners Ltd.</title>'
            "Acme Corpor…</text>") in svg
    page = render.render(Summary(generated_at="2026-09-20T12:00:00Z"), branding=branding)
    assert ">Acme Corporation &amp; Partners Ltd.</span>" in page
    assert "<footer><b>Acme Corporation &amp; Partners Ltd.</b>" in page
    short = render._topology([], [surface], name="Acme Corp 12")
    assert 'class="tpx-core-t">Acme Corp 12</text>' in short and "<title>" not in short


@pytest.mark.parametrize("field", ["logo", "favicon"])
@pytest.mark.parametrize("path", ["logo.png", "./assets/logo.png", "../etc/mark.svg", "~/logo.png"])
def test_an_image_path_must_be_absolute(field, path, tmp_path, monkeypatch):
    """A relative path would resolve against the process's working directory."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logo.png").write_bytes(PNG)
    with pytest.raises(BrandingError) as err:
        Branding.from_policy({field: path})
    assert err.value.key == f"dashboard.branding.{field}"
    assert "absolute path" in str(err.value)


def test_redacted_summarises_branding_images(tmp_path):
    """`forgd-verdict policy` and the Policy tab share `redacted`."""
    from forgd_verdict.policy import Policy, image_summary, redacted

    logo = tmp_path / "logo.png"
    logo.write_bytes(PNG)
    out = redacted(Policy(raw={"dashboard": {"branding": {
        "logo": _uri("image/png", PNG + MARKER.encode()),
        "favicon": str(logo)}}}))["dashboard"]["branding"]
    assert out == {"logo": f"<image/png, {len(PNG) + len(MARKER):,} bytes>",
                   "favicon": f"<image/png, {len(PNG)} bytes, mounted file>"}
    assert image_summary(str(tmp_path / "absent.png")) == "<a mounted file not readable here>"
    assert image_summary(f"data:text/html,<p>{MARKER}</p>") == f"<not an image, {len(f'<p>{MARKER}</p>')} bytes>"
    assert image_summary(f"data:image/png;base64,{MARKER}!") == \
        "<a data: URI that does not decode>"
    assert image_summary(None) == "<not an image reference>"


def test_the_image_summary_never_names_a_path_and_reads_at_most_the_cap(tmp_path):
    """The policy can change after startup, so the Policy tab must not read
    an arbitrary path unbounded or say what is mounted where."""
    import os

    from forgd_verdict.policy import IMAGE_SUMMARY_MAX_BYTES, image_summary

    assert IMAGE_SUMMARY_MAX_BYTES == MAX_IMAGE_BYTES
    secret_dir = tmp_path / "customer-a"
    secret_dir.mkdir()
    text = secret_dir / "passwd"
    text.write_text("root:x:0:0:root:/root:/bin/sh\n")
    big = secret_dir / "big.png"
    big.write_bytes(PNG + b"\0" * (MAX_IMAGE_BYTES + 1))
    fifo = secret_dir / "pipe"
    os.mkfifo(fifo)
    shown = {
        "text": image_summary(str(text)),
        "big": image_summary(str(big)),
        "dir": image_summary(str(secret_dir)),
        "fifo": image_summary(str(fifo)),
    }
    assert shown["text"] == f"<not an image, {text.stat().st_size} bytes, mounted file>"
    assert shown["big"] == f"<a mounted file over {MAX_IMAGE_BYTES // 1024} KB>"
    assert shown["dir"] == shown["fifo"] == "<a mounted path that is not a regular file>"
    for s in shown.values():
        assert "customer-a" not in s and str(tmp_path) not in s


@pytest.mark.parametrize("colour", [
    "rgb(1deg,2,3)", "hsl(1,2,3)", "hsla(1deg,2%,3%,4deg)", "rgb(1,2)", "hsl(10%,50%,50%)",
    "rgb(10%,20,30%)", "rgba(1,2%,3,0.5)",
])
def test_a_malformed_colour_function_is_refused(colour):
    with pytest.raises(BrandingError):
        Branding.from_policy({"theme": {"--accent-blue": colour}})


@pytest.mark.parametrize("colour", [
    "rgb(1,2,3)", "rgb(10%,20%,30%)", "rgba(1,2,3,0.5)", "hsl(210,50%,40%)",
    "hsl(210deg,50%,40%)", "hsla(210,50%,40%,50%)", "#abc", "#a1b2c3", "#a1b2c3d4",
])
def test_a_well_formed_colour_is_accepted(colour):
    Branding.from_policy({"theme": {"--accent-blue": colour}})


def test_the_image_summary_reads_past_a_short_read(tmp_path, monkeypatch):
    """os.read may return fewer bytes than asked, even for a regular file."""
    import os

    from forgd_verdict import policy as policy_mod

    logo = tmp_path / "logo.png"
    logo.write_bytes(PNG + b"\0" * 4000)
    real = os.read
    monkeypatch.setattr(policy_mod.os, "read", lambda fd, n: real(fd, min(n, 7)))
    assert policy_mod.image_summary(str(logo)) == \
        f"<image/png, {len(PNG) + 4000:,} bytes, mounted file>"
