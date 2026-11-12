"""`dashboard.branding`: the dashboard's name, logo, favicon, colours and footer.

Unset, the dashboard is neutral: a generic name, no logo or favicon, the
default token set and no footer. Every value is validated when the dashboard
starts and any error stops it, as a BrandingError naming the dotted key.
Errors never quote a value, a file's contents or a `data:` payload.

    dashboard:
      branding:
        name: Acme
        logo: data:image/png;base64,...      # or an absolute path; PNG, SVG or WebP
        favicon: /etc/acme/mark.svg
        mode: auto                           # auto, light or dark
        theme:                               # any of THEME_TOKENS
          --bg-card: "#0C1F3A"
          --warn-text: "#E0A090"
        footer: {text: Acme, link: https://acme.example}
        chart_palette: ["#C75B3A", "#4A7AB5"]  # alert series, primary series

Colours are hex (#rgb, #rrggbb, #rrggbbaa) or rgb()/rgba()/hsl()/hsla() with
numeric arguments, and are emitted exactly as written. Images are sniffed by
their bytes, not their extension or declared type, and an SVG is refused if it
can run script or load anything outside itself.

The theme covers two kinds of token. A `:root` token of tokens.css is
rewritten in place in that block, in the copy inlined into every page and the
one served at /assets/tokens.css. A slot (SLOT_DEFAULTS) is a colour the page
CSS, the admin controls and the charts use directly: templates carry it as a
`<@--name@>` marker and `Branding.fill` writes `var(--name)` in its place,
which `Branding.scheme_css` defines. A marker starts with `<`, which
`html.escape` always encodes, so rendered data can never contain one.

`mode` picks the colour scheme a viewer sees until they choose one with the
theme control. `dark` is the token set above; `light` is
LIGHT_TOKENS over it; `auto` is dark, and light under the viewer's
`prefers-color-scheme: light`. A `theme` applies to the dark scheme, so with
a theme set and no `mode` the mode is `dark`; without either it is `auto`.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import unquote_to_bytes

from ..policy import IMAGE_PNG, IMAGE_SVG, IMAGE_WEBP, PNG_MAGIC, sniff_image

ROOT_KEY = "dashboard.branding"
DEFAULT_NAME = "verdict"
MAX_NAME_CHARS = 32
MAX_FOOTER_TEXT_CHARS = 200
MAX_LINK_CHARS = 2048
MAX_IMAGE_BYTES = 256 * 1024
MODES = ("auto", "light", "dark")
CHART_PALETTE_SIZE = 2

TOKENS_CSS = (Path(__file__).with_name("assets") / "tokens.css").read_text(encoding="utf-8")

# The nine `--forgd-*` tokens of tokens.css and their neutral names.
THEME_RENAMES: Mapping[str, str] = MappingProxyType({
    "--forgd-navy": "--brand-dark",
    "--forgd-white": "--brand-light",
    "--forgd-slate": "--brand-muted",
    "--forgd-orange": "--brand-accent",
    "--forgd-orange-light": "--brand-accent-light",
    "--forgd-orange-dim": "--brand-accent-dim",
    "--forgd-orange-bg": "--brand-accent-bg",
    "--forgd-orange-bg-strong": "--brand-accent-bg-strong",
    "--forgd-orange-glow": "--brand-accent-glow",
})

# The colour-valued tokens of the tokens.css `:root` block, under their
# neutral names. Radii, shadows, transitions and font stacks are not colours
# and are not themeable.
THEME_TOKENS: frozenset[str] = frozenset({
    *THEME_RENAMES.values(),
    "--border-orange",
    "--bg-deep", "--bg-primary", "--bg-card", "--bg-card-hover", "--bg-elevated",
    "--accent-primary", "--accent-primary-light", "--accent-primary-dim",
    "--accent-primary-glow", "--accent-primary-glow-strong",
    "--text-primary", "--text-secondary", "--text-dim", "--text-body-print",
    "--accent-green", "--accent-green-bg", "--accent-red", "--accent-red-bg",
    "--accent-blue", "--accent-blue-bg",
    "--cat-terracotta", "--cat-sage", "--cat-steel", "--cat-brown", "--cat-moss",
    "--cat-terracotta-bg", "--cat-sage-bg", "--cat-steel-bg", "--cat-brown-bg",
    "--cat-moss-bg",
    "--cat-terracotta-subtle", "--cat-sage-subtle", "--cat-steel-subtle",
    "--cat-brown-subtle", "--cat-moss-subtle",
    "--comp-pill-bg", "--comp-tag-bg", "--comp-arrow-color", "--comp-progress-bg",
    "--comp-progress-border",
    "--border-subtle", "--border-medium", "--border-strong",
}) | frozenset({
    # Colours outside `:root`, used directly by the page CSS, the admin
    # controls and the charts. Neutral defaults.
    "--warn-text", "--warn-mark", "--warn-wire", "--warn-edge",
    "--ok-text", "--ok-wire", "--ok-edge", "--ok-edge-strong",
    "--core-glow", "--core-ok", "--core-warn", "--core-alert",
    "--halo-ok", "--halo-warn", "--halo-alert",
    "--matrix-ink-on-dark", "--matrix-ink-on-light",
    *(f"--chart-ramp-{i}" for i in range(7)),
})

SLOT_DEFAULTS: Mapping[str, str] = MappingProxyType({
    "--warn-text": "#FBBF24",
    "--warn-mark": "#D97706",
    "--warn-wire": "rgba(217,119,6,.55)",
    "--warn-edge": "rgba(217,119,6,.5)",
    "--ok-text": "#93C5FD",
    "--ok-wire": "rgba(147,197,253,.5)",
    "--ok-edge": "rgba(147,197,253,.45)",
    "--ok-edge-strong": "rgba(59,130,246,.5)",
    "--core-glow": "#EFF6FF",
    "--core-ok": "#16A34A",
    "--core-warn": "#CA8A04",
    "--core-alert": "#DC2626",
    "--halo-ok": "#4ADE80",
    "--halo-warn": "#FB923C",
    "--halo-alert": "#F87171",
    "--matrix-ink-on-dark": "#F3F4F6",
    "--matrix-ink-on-light": "#0B0D11",
    # One hue, dark to light, lightness monotonic.
    "--chart-ramp-0": "#1E2533",
    "--chart-ramp-1": "#283244",
    "--chart-ramp-2": "#344158",
    "--chart-ramp-3": "#43546F",
    "--chart-ramp-4": "#566A88",
    "--chart-ramp-5": "#7A8CA6",
    "--chart-ramp-6": "#A3B1C6",
})

# The light scheme: `:root` tokens and slots that differ from the dark set.
# The ramp runs light to dark, so a matrix cell's ink flips with it:
# `--matrix-ink-on-dark` is the ink for ramp steps 0-2 in both schemes.
LIGHT_TOKENS: Mapping[str, str] = MappingProxyType({
    "--bg-deep": "#F5F6F8",
    "--bg-primary": "#FFFFFF",
    "--bg-card": "#FFFFFF",
    "--bg-card-hover": "#F7F8FA",
    "--bg-elevated": "#EEF0F4",
    "--accent-primary": "#4B5563",
    "--accent-primary-light": "#1D4ED8",
    "--accent-primary-dim": "#6B7280",
    "--accent-primary-glow": "rgba(75, 85, 99, 0.06)",
    "--accent-primary-glow-strong": "rgba(75, 85, 99, 0.12)",
    "--text-primary": "#111827",
    "--text-secondary": "#4B5563",
    "--text-dim": "#6B7280",
    "--border-subtle": "rgba(17, 24, 39, 0.08)",
    "--border-medium": "rgba(17, 24, 39, 0.14)",
    "--border-strong": "rgba(17, 24, 39, 0.26)",
    "--border-orange": "rgba(180, 83, 9, 0.45)",
    "--cat-terracotta": "#C2410C",
    "--cat-steel": "#2563EB",
    "--comp-pill-bg": "rgba(17, 24, 39, 0.05)",
    "--warn-text": "#92400E",
    "--warn-mark": "#D97706",
    "--warn-wire": "rgba(217,119,6,.6)",
    "--warn-edge": "rgba(217,119,6,.55)",
    "--ok-text": "#1D4ED8",
    "--ok-wire": "rgba(37,99,235,.45)",
    "--ok-edge": "rgba(37,99,235,.4)",
    "--ok-edge-strong": "rgba(37,99,235,.5)",
    "--core-glow": "#2563EB",
    "--halo-ok": "#22C55E",
    "--halo-warn": "#F97316",
    "--halo-alert": "#EF4444",
    "--matrix-ink-on-dark": "#111827",
    "--matrix-ink-on-light": "#FFFFFF",
    "--chart-ramp-0": "#E6ECF4",
    "--chart-ramp-1": "#D0DAE7",
    "--chart-ramp-2": "#B3C2D6",
    "--chart-ramp-3": "#5D7698",
    "--chart-ramp-4": "#4C6588",
    "--chart-ramp-5": "#3C5476",
    "--chart-ramp-6": "#2C4262",
})
LIGHT_SHADOW = "0 1px 2px rgba(16,24,40,.05), 0 1px 3px rgba(16,24,40,.07)"

# The two chart series. Set by `chart_palette`; without it, these `:root`
# tokens.
CHART_SERIES = ("--chart-alert", "--chart-primary")
CHART_SERIES_DEFAULTS = ("--cat-terracotta", "--cat-steel")

_KEYS = frozenset({"name", "logo", "favicon", "mode", "theme", "footer", "chart_palette"})
_FOOTER_KEYS = frozenset({"text", "link"})

# Per-function channel grammar, so a value the browser would discard is
# refused at load: rgb channels are numbers or percentages, an hsl hue is a
# number or degrees and its saturation and lightness are percentages. The
# comma syntax takes rgb channels as all numbers or all percentages, never
# mixed.
_N = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)"
_RGB_NUMS = rf"{_N}\s*,\s*{_N}\s*,\s*{_N}"
_RGB_PCTS = rf"{_N}%\s*,\s*{_N}%\s*,\s*{_N}%"
_HUE = rf"{_N}(?:deg)?"
_PCT = rf"{_N}%"
_ALPHA = rf"(?:\s*,\s*{_N}%?)?"
_COLOUR = re.compile(
    r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})"
    rf"|rgba?\(\s*(?:{_RGB_NUMS}|{_RGB_PCTS}){_ALPHA}\s*\)"
    rf"|hsla?\(\s*{_HUE}\s*,\s*{_PCT}\s*,\s*{_PCT}{_ALPHA}\s*\)",
    re.ASCII,
)
_MARKER = re.compile(r"<@(--[a-z0-9-]+)@>")
_ROOT_BLOCK = re.compile(r":root\s*\{[^}]*\}")
_ROOT_DECL = re.compile(r"(--[\w-]+)(\s*:\s*)([^;]*)(;)")
_PRINTABLE_KEY = re.compile(r"[-\w.]{1,64}", re.ASCII)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_LINK = re.compile(r"https://[^\s<>\"'`\\]+", re.ASCII)

PNG, SVG, WEBP = IMAGE_PNG, IMAGE_SVG, IMAGE_WEBP
_EXT = {PNG: ".png", SVG: ".svg", WEBP: ".webp"}
# Each pattern is a way for an SVG to run script or reach outside itself.
# `&#` and a backslash are refused because a character reference or a CSS
# escape can spell any of the others.
_SVG_REFUSED = (
    ("contains <script", re.compile(r"<script", re.IGNORECASE)),
    ("has an on* event attribute", re.compile(r"[\s\"'/]on[a-z]+\s*=", re.IGNORECASE)),
    ("contains javascript:", re.compile(r"javascript:", re.IGNORECASE)),
    ("contains <foreignObject", re.compile(r"<foreignobject", re.IGNORECASE)),
    ("contains a DOCTYPE or entity", re.compile(r"<!(?:doctype|entity)", re.IGNORECASE)),
    ("contains a character reference", re.compile(r"&#")),
    ("contains @import", re.compile(r"@import", re.IGNORECASE)),
    ("contains a backslash escape", re.compile(r"\\")),
    ("has a url() that is not a #fragment",
     re.compile(r"url\(\s*+[\"']?+\s*+(?!#)", re.IGNORECASE)),
)
_HREF = re.compile(r"\bhref\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]*))", re.IGNORECASE)


class BrandingError(ValueError):
    """`dashboard.branding` is invalid. The message names the dotted key."""

    def __init__(self, key: str, reason: str):
        super().__init__(f"{key}: {reason}")
        self.key = key


@dataclass(frozen=True)
class Asset:
    """An image, validated, and the name it is served under."""

    data: bytes = field(repr=False)
    content_type: str
    filename: str


@dataclass(frozen=True)
class Footer:
    text: str
    link: str | None = None


@dataclass(frozen=True)
class Branding:
    name: str = DEFAULT_NAME
    logo: Asset | None = None
    favicon: Asset | None = None
    mode: str = "auto"
    theme: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    footer: Footer | None = None
    chart_palette: tuple[str, ...] | None = None

    @cached_property
    def colours(self) -> Mapping[str, str]:
        """Every marker name and its value: the `:root` tokens and slots with
        the theme applied, and the two chart series."""
        out = {**root_tokens(TOKENS_CSS), **SLOT_DEFAULTS, **self.theme}
        series = self.chart_palette or tuple(out[k] for k in CHART_SERIES_DEFAULTS)
        out.update(zip(CHART_SERIES, series, strict=True))
        return MappingProxyType(out)

    @cached_property
    def tokens_css(self) -> str:
        """tokens.css with the theme's `:root` values written in place."""
        def declaration(m: re.Match[str]) -> str:
            value = self.theme.get(m[1])
            return m[0] if value is None else f"{m[1]}{m[2]}{value}{m[4]}"

        return _ROOT_BLOCK.sub(lambda block: _ROOT_DECL.sub(declaration, block[0]),
                               TOKENS_CSS, count=1)

    @cached_property
    def scheme_css(self) -> str:
        """The slots and chart series as custom properties, and the light
        scheme's values when `mode` uses it."""
        dark = {**SLOT_DEFAULTS, **{k: v for k, v in self.theme.items()
                                    if k in SLOT_DEFAULTS}}
        series = self.chart_palette or tuple(f"var({k})" for k in CHART_SERIES_DEFAULTS)
        dark.update(zip(CHART_SERIES, series, strict=True))

        def block(values: Mapping[str, str], scheme: str, shadow: str = "") -> str:
            decls = "".join(f"{k}:{v};" for k, v in values.items())
            return f":root{{color-scheme:{scheme};{decls}{shadow}}}"

        def block_for(selector: str, values: Mapping[str, str], scheme: str,
                      shadow: str = "") -> str:
            return block(values, scheme, shadow).replace(":root", selector, 1)

        light_shadow = f"--shadow-card:{LIGHT_SHADOW};"
        css = block(dark, "dark")
        # The viewer's choice (THEME_COOKIE), as `data-theme` on <html>,
        # overrides the mode.
        unchosen = ":root:not([data-theme=dark])"
        if self.mode == "light":
            css += block_for(unchosen, LIGHT_TOKENS, "light", light_shadow)
        elif self.mode == "auto":
            css += ("@media (prefers-color-scheme: light){"
                    + block_for(unchosen, LIGHT_TOKENS, "light", light_shadow) + "}")
        css += block_for(":root[data-theme=light]", LIGHT_TOKENS, "light", light_shadow)
        return css

    def fill(self, html: str) -> str:
        """`html` with every `<@--name@>` marker replaced by `var(--name)`."""
        return _MARKER.sub(lambda m: f"var({m[1]})", html)

    @classmethod
    def from_policy(cls, raw: Mapping[str, Any] | None) -> Branding:
        """`dashboard.branding`, validated. The neutral default when unset."""
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            raise BrandingError(ROOT_KEY, "must be a mapping")
        _known(raw, _KEYS, ROOT_KEY)
        theme = _theme(raw.get("theme"), f"{ROOT_KEY}.theme")
        return cls(
            name=_name(raw.get("name"), f"{ROOT_KEY}.name"),
            logo=_image(raw.get("logo"), f"{ROOT_KEY}.logo", "logo"),
            favicon=_image(raw.get("favicon"), f"{ROOT_KEY}.favicon", "favicon"),
            mode=_mode(raw.get("mode"), f"{ROOT_KEY}.mode", themed=bool(theme)),
            theme=theme,
            footer=_footer(raw.get("footer"), f"{ROOT_KEY}.footer"),
            chart_palette=_palette(raw.get("chart_palette"), f"{ROOT_KEY}.chart_palette"),
        )


def marker(name: str) -> str:
    """The placeholder a template writes for colour `name`."""
    return f"<@{name}@>"


def root_tokens(css: str) -> dict[str, str]:
    """The declarations of the first `:root` block in `css`, name to value."""
    block = _ROOT_BLOCK.search(css)
    if block is None:
        return {}
    text = re.sub(r"/\*.*?\*/", "", block[0], flags=re.DOTALL)
    return {m[1]: m[3].strip() for m in _ROOT_DECL.finditer(text)}


def png_size(data: bytes) -> tuple[int, int] | None:
    """Width and height from a PNG's IHDR chunk."""
    if len(data) < 24 or not data.startswith(PNG_MAGIC) or data[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", data[16:24])


def is_colour(value: Any) -> bool:
    return isinstance(value, str) and _COLOUR.fullmatch(value) is not None


def _label(key: Any) -> str:
    return key if isinstance(key, str) and _PRINTABLE_KEY.fullmatch(key) else "<unprintable>"


def _known(raw: Mapping[Any, Any], allowed: frozenset[str], where: str) -> None:
    for key in raw:
        if key not in allowed:
            raise BrandingError(f"{where}.{_label(key)}", "unknown key")


def _name(value: Any, key: str) -> str:
    if value is None:
        return DEFAULT_NAME
    if not isinstance(value, str) or not value.strip():
        raise BrandingError(key, "must be a non-empty string")
    if len(value) > MAX_NAME_CHARS or _CONTROL.search(value):
        raise BrandingError(key, f"must be at most {MAX_NAME_CHARS} printable characters")
    return value


def _mode(value: Any, key: str, themed: bool = False) -> str:
    if value is None:
        return "dark" if themed else "auto"
    if value not in MODES:
        raise BrandingError(key, f"must be one of {', '.join(MODES)}")
    return value


def _theme(value: Any, key: str) -> Mapping[str, str]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise BrandingError(key, "must be a mapping of token name to colour")
    out: dict[str, str] = {}
    for token, colour in value.items():
        where = f"{key}.{_label(token)}"
        if token not in THEME_TOKENS:
            raise BrandingError(where, "is not a themeable token")
        if not is_colour(colour):
            raise BrandingError(where, "must be a hex, rgb(), rgba(), hsl() or hsla() colour")
        out[token] = colour
    return MappingProxyType(out)


def _footer(value: Any, key: str) -> Footer | None:
    if value is None or value is False:
        return None
    if not isinstance(value, Mapping):
        raise BrandingError(key, "must be a mapping with `text` and optional `link`, or false")
    _known(value, _FOOTER_KEYS, key)
    text = value.get("text")
    if not isinstance(text, str) or not text.strip():
        raise BrandingError(f"{key}.text", "must be a non-empty string")
    if len(text) > MAX_FOOTER_TEXT_CHARS or _CONTROL.search(text):
        raise BrandingError(f"{key}.text",
                            f"must be at most {MAX_FOOTER_TEXT_CHARS} printable characters")
    link = value.get("link")
    if link is not None and not (isinstance(link, str) and len(link) <= MAX_LINK_CHARS
                                 and _LINK.fullmatch(link)):
        raise BrandingError(f"{key}.link", "must be an https: URL")
    return Footer(text=text, link=link)


def _palette(value: Any, key: str) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list | tuple) or len(value) != CHART_PALETTE_SIZE:
        raise BrandingError(key, f"must be a list of {CHART_PALETTE_SIZE} colours: "
                                 "the alert series, then the primary series")
    for i, colour in enumerate(value):
        if not is_colour(colour):
            raise BrandingError(f"{key}[{i}]",
                                "must be a hex, rgb(), rgba(), hsl() or hsla() colour")
    return tuple(value)


def _image(value: Any, key: str, stem: str) -> Asset | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise BrandingError(key, "must be a path or a data: URI")
    if value[:5].lower() == "data:":
        declared, data = _data_uri(value, key)
    else:
        if not Path(value).is_absolute():
            raise BrandingError(key, "must be an absolute path or a data: URI")
        declared, data = None, _read(value, key)
    sniffed = sniff_image(data)
    if sniffed is None:
        raise BrandingError(key, "is not a PNG, SVG or WebP image")
    if declared is not None and declared != sniffed:
        raise BrandingError(key, f"is declared {declared} but its bytes are not")
    if sniffed == SVG:
        _safe_svg(data, key)
    return Asset(data=data, content_type=sniffed, filename=stem + _EXT[sniffed])


def _data_uri(value: str, key: str) -> tuple[str, bytes]:
    # Base64 is 4/3 the decoded size; the slack covers the header.
    if len(value) > MAX_IMAGE_BYTES * 4 // 3 + 256:
        raise BrandingError(key, f"is over {MAX_IMAGE_BYTES // 1024} KB")
    header, sep, payload = value[5:].partition(",")
    if not sep:
        raise BrandingError(key, "is not a valid data: URI")
    params = [p.strip().lower() for p in header.split(";")]
    declared, is_b64 = params[0], "base64" in params[1:]
    if declared not in _EXT:
        raise BrandingError(key, "must be image/png, image/svg+xml or image/webp")
    try:
        data = (base64.b64decode(payload, validate=True) if is_b64
                else unquote_to_bytes(payload))
    except (binascii.Error, ValueError):
        raise BrandingError(key, "has a payload that is not valid base64") from None
    _cap(data, key)
    return declared, data


def _read(value: str, key: str) -> bytes:
    path = Path(value)
    try:
        if path.stat().st_size > MAX_IMAGE_BYTES:
            raise BrandingError(key, f"is over {MAX_IMAGE_BYTES // 1024} KB")
        with path.open("rb") as fh:
            data = fh.read(MAX_IMAGE_BYTES + 1)
    except OSError as exc:
        raise BrandingError(key, f"cannot be read: {exc.strerror or type(exc).__name__}") \
            from None
    _cap(data, key)
    return data


def _cap(data: bytes, key: str) -> None:
    if len(data) > MAX_IMAGE_BYTES:
        raise BrandingError(key, f"is over {MAX_IMAGE_BYTES // 1024} KB")


def _safe_svg(data: bytes, key: str) -> None:
    text = data.decode("utf-8")
    for reason, pattern in _SVG_REFUSED:
        if pattern.search(text):
            raise BrandingError(key, f"is an SVG that {reason}")
    for match in _HREF.finditer(text):
        target = next(g for g in match.groups() if g is not None)
        if not target.startswith("#"):
            raise BrandingError(key, "is an SVG with an href that is not a #fragment")
