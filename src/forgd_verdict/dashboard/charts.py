"""Inline SVG chart primitives.

No JS charting library and no build step: the dashboard is one Python
container serving server-rendered HTML, so charts are SVG emitted directly.

Colours come from the dashboard's branding (see branding.py): every colour
here is a `<@--name@>` marker that `Branding.fill` replaces when the page is
rendered. There are two series colours, `--chart-alert` and `--chart-primary`,
from `dashboard.branding.chart_palette` or else the `--cat-terracotta` and
`--cat-steel` tokens, and a seven-step sequential ramp, `--chart-ramp-0` to
`--chart-ramp-6`, dark to light.

So: one hue for magnitude-by-category (bars do not need distinct hues), and
the pair for the one genuinely two-series view. A verdict is never encoded
green-vs-red anywhere here; that pair fails for deuteranopia.

Mark specs follow the dataviz reference: thin marks, 4px rounded data-ends
anchored to the baseline, a 2px surface gap between adjacent fills,
recessive grid and axes, selective direct labels rather than a number on
every mark, and a native per-mark hover tooltip via <title>.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from html import escape

from .branding import marker

# The two series.
STEEL = marker("--chart-primary")
TERRACOTTA = marker("--chart-alert")

GRID = marker("--border-medium")

BAR_THICKNESS = 14
BAR_GAP = 12
RADIUS = 4


def _fmt(n: float) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}k"
    if isinstance(n, float) and not n.is_integer():
        return f"{n:.1f}"
    return f"{int(n)}"


def _hbar_path(x: float, y: float, w: float, h: float, r: float = RADIUS) -> str:
    """Horizontal bar with only the data end rounded.

    The baseline end stays square so the bar reads as anchored rather than
    floating -- rounding both ends detaches it from the axis.
    """
    r = max(0.0, min(r, w, h / 2))
    if w <= 0:
        return ""
    return (
        f"M{x},{y} H{x + w - r} A{r},{r} 0 0 1 {x + w},{y + r} "
        f"V{y + h - r} A{r},{r} 0 0 1 {x + w - r},{y + h} H{x} Z"
    )


def _vbar_path(x: float, y: float, w: float, h: float, r: float = RADIUS) -> str:
    """Vertical bar rounded at the top (the data end) only."""
    r = max(0.0, min(r, h, w / 2))
    if h <= 0:
        return ""
    return (
        f"M{x},{y + h} V{y + r} A{r},{r} 0 0 1 {x + r},{y} "
        f"H{x + w - r} A{r},{r} 0 0 1 {x + w},{y + r} V{y + h} Z"
    )


def _nice_ceiling(value: float) -> float:
    """Round the axis top up to a readable number.

    Without this the midpoint gridline reads 64.5, which is noise -- axis
    labels are for orientation, not precision.
    """
    if value <= 0:
        return 1.0
    import math

    magnitude = 10 ** math.floor(math.log10(value))
    # Fine-grained steps: a ceiling of 200 for a max of 129 wastes a
    # third of the plot height and flattens the bars.
    for step in (1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10):
        candidate = step * magnitude
        if candidate >= value:
            return float(candidate)
    return float(10 * magnitude)


def empty(message: str, height: int = 120) -> str:
    return (
        f'<div class="chart-empty" style="height:{height}px">'
        f'<span>{escape(message)}</span></div>'
    )


def hbar(
    rows: Sequence[tuple[str, float]],
    hue: str | Mapping[str, str] = STEEL,
    label_width: int = 150,
    width: int = 640,
    value_suffix: str = "",
    empty_message: str = "No data yet",
    notes: Mapping[str, str] | None = None,
) -> str:
    """Horizontal bars: magnitude across a category.

    `notes` maps a row label to text shown after that row's value, outside
    the bar; it does not change the bar's length.

    One hue for every bar by default. Categorical colour would imply the
    categories carry meaning beyond identity; identity comes from the row
    label.

    `hue` may instead be a mapping from row label to colour, for the one job
    that is not categorical: encoding a **status** the rows already have.
    Severity is such a status, and it changes what the chart says -- the
    longest bars here are warn-tier NER while the checksum-validated
    findings are short, which a single hue hides. A status encoding needs a
    legend; `severity_legend` is the one for this pair.
    """
    rows = [(k, v) for k, v in rows if v is not None]
    if not rows:
        return empty(empty_message)

    top = max((v for _, v in rows), default=0) or 1
    plot_w = width - label_width - 60
    if notes:
        # A note is 13px monospace, about 8px a character, after " \u00b7 ".
        plot_w -= 8 * max(len(n) + 3 for n in notes.values())
    height = len(rows) * (BAR_THICKNESS + BAR_GAP) + 8
    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'preserveAspectRatio="xMinYMin meet" role="img" class="chart" '
        f'style="height:auto;max-height:{height}px">'
    ]
    for i, (label, value) in enumerate(rows):
        y = i * (BAR_THICKNESS + BAR_GAP) + 4
        w = (value / top) * plot_w
        shown = f"{_fmt(value)}{value_suffix}"
        parts.append(
            f'<text x="{label_width - 10}" y="{y + BAR_THICKNESS - 2}" '
            f'text-anchor="end" class="c-label">{escape(str(label))}</text>'
        )
        # Track: shows the category exists even at a zero value.
        parts.append(
            f'<rect x="{label_width}" y="{y}" width="{plot_w}" height="{BAR_THICKNESS}" '
            f'rx="{RADIUS}" fill="{GRID}" opacity="0.35"/>'
        )
        if w > 0:
            fill = hue if isinstance(hue, str) else hue.get(str(label), STEEL)
            parts.append(
                f'<path d="{_hbar_path(label_width, y, w, BAR_THICKNESS)}" fill="{fill}">'
                f"<title>{escape(str(label))}: {escape(shown)}</title></path>"
            )
        note = (notes or {}).get(str(label))
        note = f'<tspan class="c-note"> \u00b7 {escape(note)}</tspan>' if note else ""
        parts.append(
            f'<text x="{label_width + max(w, 0) + 8}" y="{y + BAR_THICKNESS - 2}" '
            f'class="c-value">{escape(shown)}{note}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def severity_legend() -> str:
    """Block/warn legend for a severity-coloured chart.

    Status colour ships with a label, never colour alone: the pair passes
    CVD separation (ΔE 18.1 protan) but a reader in forced-colours mode or
    on a printout gets nothing from hue.
    """
    items = (("block", TERRACOTTA), ("warn", STEEL))
    swatches = "".join(
        f'<span class="lg-item"><span class="lg-dot" '
        f'style="background:{colour}"></span>{label}</span>'
        for label, colour in items
    )
    return f'<div class="lg">{swatches}</div>'


def grouped_bars(
    days: Sequence[tuple[str, float, float]],
    series_labels: tuple[str, str] = ("Requests", "Would deny"),
    width: int = 640,
    height: int = 200,
    empty_message: str = "No data yet",
) -> str:
    """Two series over time.

    The only two-series view here, so it gets the validated warm/cool pair.
    A legend is always rendered (identity is never colour-alone) and both
    series are direct-labelled at their final value.

    Grouped bars rather than lines: with a handful of days a line implies a
    continuity the data does not have. Per-bar <title> gives native hover.
    """
    days = list(days)
    if not days:
        return empty(empty_message, height=height)

    pad_l, pad_r, pad_t, pad_b = 44, 56, 12, 28
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    raw_top = max((max(a, b) for _, a, b in days), default=0) or 1
    top = _nice_ceiling(raw_top)

    slot = plot_w / len(days)
    bar_w = min(16.0, max(4.0, (slot - 10) / 2))
    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'preserveAspectRatio="xMinYMin meet" role="img" class="chart" '
        f'style="height:auto;max-height:{height}px">'
    ]
    # Recessive gridlines with axis values; no chart junk.
    for frac in (0, 0.5, 1.0):
        y = pad_t + plot_h - frac * plot_h
        parts.append(
            f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" '
            f'stroke="{GRID}" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{pad_l - 8}" y="{y + 4:.1f}" text-anchor="end" '
            f'class="c-axis">{_fmt(top * frac)}</text>'
        )

    for i, (day, a, b) in enumerate(days):
        x0 = pad_l + i * slot + (slot - (bar_w * 2 + 2)) / 2
        for j, (value, hue) in enumerate(((a, STEEL), (b, TERRACOTTA))):
            h = (value / top) * plot_h
            x = x0 + j * (bar_w + 2)  # 2px surface gap between adjacent fills
            if h > 0:
                parts.append(
                    f'<path d="{_vbar_path(x, pad_t + plot_h - h, bar_w, h)}" fill="{hue}">'
                    f"<title>{escape(day)} — {escape(series_labels[j])}: {_fmt(value)}"
                    f"</title></path>"
                )
        if len(days) <= 10 or i % max(1, len(days) // 6) == 0:
            parts.append(
                f'<text x="{x0 + bar_w:.1f}" y="{height - 8}" text-anchor="middle" '
                f'class="c-axis">{escape(day[5:])}</text>'
            )

    # Direct labels on the final values, so the legend is not the only key.
    last_day, last_a, last_b = days[-1]
    for value, hue, dy in ((last_a, STEEL, -4), (last_b, TERRACOTTA, 12)):
        y = pad_t + plot_h - (value / top) * plot_h
        parts.append(
            f'<text x="{width - pad_r + 6}" y="{max(pad_t + 8, y + dy):.1f}" '
            f'class="c-value" fill="{hue}">{_fmt(value)}</text>'
        )
    parts.append("</svg>")

    legend = "".join(
        f'<span class="legend-item"><span class="swatch" style="background:{hue}"></span>'
        f"{escape(label)}</span>"
        for label, hue in zip(series_labels, (STEEL, TERRACOTTA), strict=True)
    )
    return f'{"".join(parts)}<div class="legend">{legend}</div>'


def meter(numerator: int, denominator: int, hue: str = TERRACOTTA) -> str:
    """A single proportion. One bar, labelled; no pie, no donut."""
    pct = (numerator / denominator * 100) if denominator else 0.0
    return (
        f'<div class="meter" role="img" aria-label="{numerator} of {denominator}">'
        f'<div class="meter-fill" style="width:{min(100.0, pct):.1f}%;background:{hue}"></div>'
        f"</div>"
        f'<div class="meter-caption">{_fmt(numerator)} of {_fmt(denominator)} '
        f"({pct:.1f}%)</div>"
    )


__all__ = ["STEEL", "TERRACOTTA", "empty", "grouped_bars", "hbar", "meter"]


# Sequential ramp for magnitude, dark to light. A ramp's lightness has to be
# monotonic; the categorical validator does not apply to it.
SEQ = tuple(marker(f"--chart-ramp-{i}") for i in range(7))


def seq_step(value: float, top: float) -> str:
    """Pick a ramp step for a magnitude. Zero is never a ramp colour --
    absence is a different thing from a small value and gets its own
    treatment."""
    if value <= 0 or top <= 0:
        return "none"
    frac = min(1.0, value / top)
    idx = min(len(SEQ) - 1, max(0, int(round(frac * (len(SEQ) - 1)))))
    return SEQ[idx]


def matrix(
    rows: Sequence[str],
    cols: Sequence[str],
    cells: dict[tuple[str, str], int],
    empty_message: str = "No data yet",
    groups: Sequence[tuple[str, int]] | None = None,
) -> str:
    """Surfaces x control points.

    Two categorical dimensions and one measure, which is what a heatmap is
    for, so it takes the sequential ramp rather than categorical hues. A
    zero cell is rendered as an outlined dash instead of the lightest step:
    "never evaluated here" is categorically different from "evaluated once",
    and a pale colour would read as the latter.

    `groups` spans a banded header over consecutive columns, as
    `[(label, span), ...]`. It carries the distinction the numbers cannot:
    the first two controls run before inference and can refuse a request,
    the third reads transcripts afterwards and can only report. Position and
    a label rather than colour, so it survives a printout.
    """
    if not rows:
        return empty(empty_message)
    top = max(cells.values(), default=0)
    group_row = ""
    boundary = set()
    if groups:
        cells_html, at = [], 0
        for label, span in groups:
            at += span
            # Mark the first column of each group after the first, so the
            # body can draw the divider on the same edge.
            if at < len(cols):
                boundary.add(at)
            cells_html.append(
                f'<th class="mx-group" colspan="{span}">{escape(label)}</th>'
            )
        group_row = f'<tr><th></th>{"".join(cells_html)}</tr>'
    head = "".join(
        f'<th class="mx-col{" mx-div" if i in boundary else ""}">{escape(c)}</th>'
        for i, c in enumerate(cols)
    )
    body = []
    for r in rows:
        tds = []
        for i, c in enumerate(cols):
            n = cells.get((r, c), 0)
            div = " mx-div" if i in boundary else ""
            if n <= 0:
                tds.append(
                    f'<td class="mx-cell mx-none{div}" title="'
                    f'{escape(r)} — not seen by {escape(c)}">&mdash;</td>'
                )
            else:
                fill = seq_step(n, top)
                dark = fill in SEQ[:3]
                tds.append(
                    f'<td class="mx-cell{div}" style="background:{fill}" '
                    f'title="{escape(r)} — {escape(c)}: {n}">'
                    f'<span class="{"mx-on-dark" if dark else "mx-on-light"}">{n}</span>'
                    "</td>"
                )
        body.append(f'<tr><th class="mx-row">{escape(r)}</th>{"".join(tds)}</tr>')
    return (
        f'<table class="matrix"><thead>{group_row}<tr><th></th>'
        f'{head}</tr></thead><tbody>{"".join(body)}</tbody></table>'
    )
