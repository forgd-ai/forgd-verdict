"""Server-rendered dashboard HTML.

Self-contained: tokens.css and the two webfonts ship inside the package, and
a logo and favicon come from `dashboard.branding`, so the CSP is
`default-src 'none'` with no third-party origins. See
`assets/fonts/README.md` for the fonts.

Unbranded, the page is neutral: the name "verdict" as text in the header, no
favicon, the default token set and no footer. `dashboard.branding` (see
branding.py) sets the name, logo, favicon, footer and colours. Every colour
outside tokens.css is a `<@--name@>` marker that `Branding.fill` replaces in
the finished page.

Charts live in charts.py.
"""

from __future__ import annotations

import math
import re
from html import escape
from pathlib import Path
from urllib.parse import urlencode

from ..models import DEVICE_ID, NO_CONTENT_READ
from ..orgregistry import KIND_WORKSPACE, partition_kind
from ..store.base import EVENT_TOOL_CALL, WRITER_INTAKE_TOKEN, is_fleet_partition, writer_class
from ..store.query import Summary, families, family_device_values, family_severities
from ..store.tally import weight
from . import charts
from .branding import DEFAULT_NAME, Branding, marker, png_size
from .topology import core_health

ASSETS = Path(__file__).with_name("assets")

PAGE_CSS = """
*{box-sizing:border-box}
body{margin:0;background:var(--bg-deep);color:var(--text-primary);
 font-family:var(--font-body);-webkit-font-smoothing:antialiased;
 scroll-behavior:smooth}
a{color:var(--accent-primary-light);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1180px;margin:0 auto;padding:0 32px}
header.top{border-bottom:1px solid var(--border-subtle);background:var(--bg-primary);
 position:sticky;top:0;z-index:10}
header.top .bar{display:flex;align-items:center;gap:20px;height:60px;padding:0 24px}
/* The rail: one destination per question the dashboard answers. */
/* The rail's surface is painted on the shell, so it runs the full height
   of a page longer than the viewport. */
.shell{display:grid;grid-template-columns:208px minmax(0,1fr);
 min-height:calc(100vh - 61px);
 background:linear-gradient(90deg,var(--bg-primary) 0 207px,
  var(--border-subtle) 207px 208px,transparent 208px)}
nav.rail{position:sticky;top:61px;align-self:start;height:calc(100vh - 61px);
 padding:16px 12px;display:flex;flex-direction:column;gap:2px}
nav.rail a{display:flex;align-items:center;gap:10px;padding:8px 12px;
 border-radius:var(--radius-md);color:var(--text-secondary);font-size:14px;
 font-weight:500;transition:background var(--transition-snap),color var(--transition-snap)}
nav.rail a:hover{background:var(--bg-card-hover);color:var(--text-primary);
 text-decoration:none}
nav.rail a[aria-current=page]{background:var(--brand-accent-bg-strong);
 color:var(--text-primary)}
nav.rail svg{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;
 stroke-width:1.4;stroke-linecap:round;stroke-linejoin:round}
/* The time window, beside the brand: it applies to every page that reads
   records. */
nav.range{display:flex;gap:2px;padding:3px;border:1px solid var(--border-subtle);
 border-radius:var(--radius-md);background:var(--bg-deep)}
nav.range a{font-size:13px;font-weight:500;color:var(--text-secondary);
 padding:4px 10px;border-radius:var(--radius-sm)}
nav.range a:hover{color:var(--text-primary);text-decoration:none}
/* The theme control. Which choice is current is read from `data-theme` on
   <html>, set per request after the page cache, so a cached page serves
   every viewer. */
nav.theme{display:flex;gap:2px;padding:3px;border:1px solid var(--border-subtle);
 border-radius:var(--radius-md);background:var(--bg-deep)}
nav.theme a{font-size:12px;font-weight:500;color:var(--text-dim);padding:3px 9px;
 border-radius:var(--radius-sm)}
nav.theme a:hover{color:var(--text-primary);text-decoration:none}
:root:not([data-theme]) nav.theme a.t-auto,
:root[data-theme=light] nav.theme a.t-light,
:root[data-theme=dark] nav.theme a.t-dark{background:var(--bg-card);
 color:var(--text-primary);box-shadow:var(--shadow-card)}
nav.range a[aria-current=true]{background:var(--bg-card);color:var(--text-primary);
 box-shadow:var(--shadow-card)}
/* The org picker. Visually subordinate to the tabs: the tabs change what
   you are looking at, this changes whose data it is, and confusing the two
   is how someone reads one org's numbers as another's. */
nav.orgs{display:flex;gap:2px;padding-left:16px;
 border-left:1px solid var(--border-subtle)}
nav.orgs a{font-size:13px;color:var(--text-dim);
 padding:6px 10px;border-radius:var(--radius-sm);border:1px solid transparent;
 transition:color var(--transition-smooth),border-color var(--transition-smooth)}
nav.orgs a:hover{color:var(--text-secondary);text-decoration:none;
 border-color:var(--border-subtle)}
nav.orgs a[aria-current=true]{color:var(--text-primary);
 background:var(--bg-elevated);border-color:var(--border-medium)}
header.top img{height:26px;width:auto;display:block}
.top-meta{margin-left:auto;font-size:12px;
 color:var(--text-dim);text-align:right;line-height:1.5}
.eyebrow{font-size:13px;font-weight:600;color:var(--text-dim);margin-bottom:6px}
h1{font-size:30px;font-weight:800;letter-spacing:-.02em;margin:0 0 12px;
 display:flex;align-items:center;gap:12px;flex-wrap:wrap}
/* overflow-wrap:anywhere because these headings carry VALUES, not prose:
   the policy tab titles its source with the path it loaded
   (/run/forgd/policy/policy.yaml) and a path offers no break opportunity,
   so it ran 29px past a 280px column. Not scoped to a breakpoint -- a long
   path overflows a narrow column at any viewport width. */
h2{font-size:22px;font-weight:700;letter-spacing:-.01em;margin:0 0 8px;
 overflow-wrap:anywhere}
p.lede{color:var(--text-secondary);font-size:15px;line-height:1.65;max-width:72ch;margin:0}
section{padding:40px 0;border-top:1px solid var(--border-subtle)}
section:first-of-type{border-top:none}
.hero{padding:36px 0 28px}
/* min() on every auto-fit minimum. `minmax(200px,1fr)` does NOT shrink
   below 200px -- auto-fit removes empty tracks, it does not shrink a
   populated one -- so on a narrow screen the track keeps its floor and the
   grid pushes the page wider than the viewport instead of wrapping. */
.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr));
 gap:16px;margin:28px 0 0}
.stat-card{background:var(--bg-card);border:1px solid var(--border-subtle);
 border-radius:var(--radius-lg);padding:20px 22px;box-shadow:var(--shadow-card);
 transition:border-color var(--transition-smooth),background var(--transition-smooth)}
.stat-card:hover{border-color:var(--border-medium);background:var(--bg-card-hover)}
a.stat-card{display:block;color:inherit}
a.stat-card:hover{text-decoration:none;border-color:var(--border-strong)}
.stat-go{margin-top:12px;font-size:12px;font-weight:500;color:var(--accent-primary-light)}
.stat-label{font-size:13px;font-weight:500;color:var(--text-secondary);margin-bottom:10px}
.stat-value{font-size:32px;font-weight:800;letter-spacing:-.02em;line-height:1}
.stat-sub{margin-top:8px;font-size:12px;color:var(--text-secondary)}
.card{background:var(--bg-card);border:1px solid var(--border-subtle);
 border-radius:var(--radius-lg);padding:24px;box-shadow:var(--shadow-card)}
/* Only cards that HOLD A TABLE scroll. Applying overflow-x to every card
   would make each one a scroll container, and `.chart` sets
   `overflow:visible` on purpose so its value labels can sit outside the SVG
   box -- a scrolling card clips exactly those.
   Not scoped to a breakpoint. The column between the 720px and 1100px
   rules is a single stacked column at desktop width, so the surface table
   was still wider than its card at 1024px with no mobile rule in reach. */
.card:has(table){overflow-x:auto}
.card-grid{display:grid;gap:16px;margin-top:24px}
/* A card that hugs its content, for the matrix: the table is
   width:auto with fixed cells, so a full-width card left most of
   the row empty.
   `overflow-x:auto` is the other half of that. The cells are a fixed
   104px, so below about 700px the matrix is wider than the card and
   `max-width:100%` capped the CARD while the table kept going -- the page
   scrolled sideways and every section inherited the width. Scrolling the
   matrix is the honest failure: squashing it would misalign a grid whose
   whole job is to line detectors up against surfaces. */
.card.fit{width:max-content;max-width:100%;overflow-x:auto}
/* Matrix beside its reconciliation figures. The matrix is a fixed
   width, so the aside takes whatever is left. */
/* Peer sections laid out in a row. The rule and the padding move to the
   wrapper so the three read as siblings rather than as one section that
   swallowed two others.
   Two tracks, not three. The matrix is short and wide -- 629x371 at
   1920 -- and the stat columns are tall and narrow, so three tracks put
   475px of nothing under the matrix and squeezed each aside to 211px,
   which is narrower than one card. The reconciliation figures take the
   second row of the matrix's own track instead, where they have its
   full width to flow across, and the round-trip column takes both rows
   of the other track. */
.section-row{display:grid;align-items:start;
 grid-template-columns:max-content minmax(0,1fr);
 gap:40px 32px;padding:40px 0;border-top:1px solid var(--border-subtle)}
.section-row > section{padding:0;border-top:none}
.section-row > section:nth-child(2){grid-row:2}
.section-row > section:nth-child(3){grid-column:2;grid-row:1/span 2}
.section-row.pair > section:nth-child(2){grid-column:2;grid-row:1}
.section-row.pair .aside{grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr))}
/* minmax(0,1fr), never a bare 1fr. `1fr` is `minmax(auto,1fr)`, and that
   `auto` minimum is the item's MIN-CONTENT -- so the fixed-width coverage
   matrix held this track at 629px on a 390px screen and every sibling
   section inherited the width. The single-column stack could not shrink,
   which reads as "the page is too wide" rather than as a grid problem. */
@media (max-width:1100px){.section-row{grid-template-columns:minmax(0,1fr);gap:32px 0}
 .section-row.pair > section:nth-child(2),
 .section-row > section:nth-child(2),
 .section-row > section:nth-child(3){grid-column:auto;grid-row:auto}}
.aside{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(190px,100%),1fr));
 gap:12px;align-content:start}
/* The asides keep the page's heading scale rather than shrinking to a
   label: they are sections that happen to sit in a column. */
.aside{margin-top:24px}
.aside .status{grid-column:1/-1;margin:2px 0 0}
.card-grid.cols-2{grid-template-columns:repeat(auto-fit,minmax(min(380px,100%),1fr));
 align-items:start}
/* A table of identifiers needs more room than a bar chart of the same
   data. auto-fit cannot express that, so this pair is explicit and
   collapses to one column when there is not room for both. */
.card-grid.wide-first{grid-template-columns:minmax(0,1.7fr) minmax(0,1fr);
 align-items:start}
@media (max-width:1000px){.card-grid.wide-first{grid-template-columns:1fr}}
/* --- the delivery diagram ---------------------------------------- */
/* Products down the left, one wire each into the scan core, one out to
   the sink when adapter 5 is configured. State is never colour alone:
   every node carries a label and a relative time, and the heading names
   any late surface in words. */
.topology{margin:20px 0 6px}
.tp-head{font-size:13px;font-weight:500;color:var(--text-secondary);margin-bottom:10px}
.tp-head-warn{color:<@--warn-text@>}
/* The phone rendering, hidden until the diagram stops being legible. */
.tpc{list-style:none;margin:0;padding:12px 14px;
 background:var(--bg-card);border:1px solid var(--border-subtle);
 border-radius:var(--radius-lg);box-shadow:var(--shadow-card)}
.tpc-row{display:flex;align-items:center;gap:9px;padding:5px 0}
.tpc-dot{width:8px;height:8px;border-radius:50%;flex:none;
 background:var(--text-dim)}
.tpc-row.tpx-live .tpc-dot{background:<@--ok-text@>}
.tpc-row.tpx-idle .tpc-dot{background:var(--accent-primary-dim)}
.tpc-row.tpx-late .tpc-dot{background:<@--warn-mark@>}
.tpc-row.tpx-off,.tpc-row.tpx-na{opacity:.5}
.tpc-name{font-size:12.5px;color:var(--text-secondary)}
.tpc-detail{margin-left:auto;font-size:12px;
 color:var(--text-dim);white-space:nowrap}
.tpc-row.tpx-late .tpc-detail{color:<@--warn-text@>}
.tpc-out{border-top:1px solid var(--border-subtle);margin-top:5px;
 padding-top:9px}
.tpc-out .tpc-name{color:var(--accent-primary)}
/* The list is the default and the diagram is the enhancement, so the
   switch is min-width. Written the other way round it silently became
   the only rule in the 720px block and wiped every mobile fix
   -- the header stacking, the scrolling tables, all of it.
   1080px, not 720px: the SVG scales with its column, so at 721px the
   1120-unit drawing renders at 0.64x and the labels land at 5.6px.
   Legible is the breakpoint, not "is it a phone". */
.tpx-wrap{display:none;background:var(--bg-card);
 border:1px solid var(--border-subtle);
 border-radius:var(--radius-lg);padding:8px 14px;box-shadow:var(--shadow-card)}
@media(min-width:1080px){
 .tpx-wrap{display:block}
 .tpc{display:none}
}
/* Scales with the column and keeps its aspect, so there is no width at
   which the wires and the labels disagree about where they are. */
.tpx{display:block;width:100%;height:auto;overflow:visible}
.tpx-wire{stroke:var(--border-medium);stroke-width:1.5;fill:none}
.tpx-wire.tpx-live{stroke:<@--ok-wire@>}
.tpx-wire.tpx-late{stroke:<@--warn-wire@>}
.tpx-wire.tpx-idle{stroke:var(--border-subtle)}
.tpx-wire.tpx-off,.tpx-wire.tpx-na{stroke:var(--border-subtle);stroke-dasharray:3 4;opacity:.5}
.tpx-wire.tpx-periodic{stroke-dasharray:5 5}
/* The pulsar. `offset-path` walks the same cubic the wire draws, so the
   dot is on the wire by construction rather than by two coordinate
   systems agreeing. */
/* A ball of light: bright core, falloff to nothing. The radius is
   larger than the old hard dot because most of it is glow -- the part
   that reads as "the pulse" is the inner third. */
.tpx-pulse{fill:url(#tpxGlow);
 offset-rotate:0deg;
 animation:tpx-run var(--tpx-dur,2s) linear infinite;
 animation-delay:var(--tpx-delay,0s)}
@keyframes tpx-run{from{offset-distance:0%}to{offset-distance:100%}}
.tpxg-core{stop-color:<@--core-glow@>;stop-opacity:.95}
.tpxg-mid{stop-color:var(--accent-primary);stop-opacity:.55}
.tpxg-edge{stop-color:var(--accent-primary);stop-opacity:0}
.tpx-node rect{fill:var(--bg-elevated);stroke:var(--border-subtle);
 stroke-width:1}
.tpx-node.tpx-live rect{stroke:<@--ok-edge@>}
.tpx-node.tpx-late rect{stroke:<@--warn-edge@>}
.tpx-node.tpx-off,.tpx-node.tpx-na{opacity:.45}
.tpx-glyph{fill:none;stroke:var(--accent-primary);stroke-width:1.3;
 stroke-linecap:round;stroke-linejoin:round}
.tpx-node.tpx-late .tpx-glyph{stroke:<@--warn-text@>}
.tpx-node.tpx-off .tpx-glyph,.tpx-node.tpx-na .tpx-glyph{stroke:var(--text-dim)}
.tpx-label{fill:var(--text-primary);font:500 12.5px var(--font-body)}
.tpx-sub{fill:var(--text-dim);font:400 10px var(--font-mono)}
.tpx-late .tpx-sub{fill:<@--warn-text@>}
.tpx-halo{fill:none;stroke-width:3;filter:url(#tpxHaloBlur);pointer-events:none}
.tpx-core rect{fill:var(--bg-elevated);stroke:var(--border-strong);
 stroke-width:1.5}
/* The border carries the same signal. It is not decoration: the box's
   default stroke is a light blue-grey sitting directly on top of the halo,
   and at this size it dominated the colour underneath -- a green rim read
   as a white one. All three states tint it. */
.tpx-core-ok rect{stroke:<@--core-ok@>}
.tpx-core-warn rect{stroke:<@--core-warn@>}
.tpx-core-alert rect{stroke:<@--core-alert@>}
.tpx-core .tpx-glyph{stroke:var(--accent-primary)}
.tpx-core-t{fill:var(--accent-primary);font:500 10px var(--font-mono);
 letter-spacing:.08em;text-transform:uppercase}
/* The stylesheet had no reduced-motion rule at all before this. */
@media(prefers-reduced-motion:reduce){
 .tpx-pulse{animation:none;offset-distance:60%;opacity:.55}
}
.chart{display:block;overflow:visible;margin-top:8px}
.chart-empty{display:flex;align-items:center;justify-content:center;
 border:1px dashed var(--border-medium);border-radius:var(--radius-md);
 color:var(--text-dim);font-size:13px}
text.c-label{fill:var(--text-secondary);font:500 13px var(--font-body)}
text.c-value{fill:var(--text-primary);font:600 13px var(--font-mono)}
tspan.c-note{fill:var(--text-dim);font-weight:400}
text.c-axis{fill:var(--text-dim);font:400 10px var(--font-mono)}
.legend{display:flex;gap:18px;margin-top:14px;font-size:12px;
 color:var(--text-secondary)}
.legend-item{display:flex;align-items:center;gap:7px}
.swatch{width:10px;height:10px;border-radius:2px;display:inline-block}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
th{text-align:left;font-size:12px;font-weight:600;color:var(--text-secondary);
 padding:8px 10px;border-bottom:1px solid var(--border-medium);white-space:nowrap}
th.num{text-align:right}
td{padding:9px 10px;border-bottom:1px solid var(--border-subtle);
 color:var(--text-secondary)}
tbody tr{height:40px}
tbody tr:hover td{background:var(--bg-card-hover)}
td.num{font-family:var(--font-mono);color:var(--text-primary);text-align:right;
 font-variant-numeric:tabular-nums;white-space:nowrap}
td.num a{color:inherit;text-decoration:underline dotted var(--border-strong);
 text-underline-offset:3px}
td.num a:hover{color:var(--accent-primary-light)}
td code,td.mono{white-space:nowrap}
td.mono{font-family:var(--font-mono);font-size:11px;color:var(--text-dim)}
.det-what{display:block;margin-top:3px;font-size:11px;color:var(--text-dim)}
code,.mono{font-family:var(--font-mono);font-size:12px}
/* Status is an icon and a word, never colour alone. */
.pill{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:500;
 padding:2px 9px 2px 6px;border-radius:999px;border:1px solid var(--border-medium);
 white-space:nowrap}
.pill::before,.status::before{content:"!";display:inline-grid;place-items:center;
 width:14px;height:14px;border-radius:50%;border:1.5px solid currentColor;
 font:700 9px/1 var(--font-body);flex:none;box-sizing:border-box}
.pill.block::before{content:"\\00d7";font-size:11px}
.pill.cov-yes::before{content:"\\2713"}
.pill.block{color:<@--warn-text@>;border-color:var(--border-orange)}
.pill.warn{color:var(--accent-primary);border-color:var(--border-medium)}
/* min-width:max-content so the matrix SCROLLS at its natural size inside
   .card.fit rather than being squeezed into it. Without it the fixed 104px
   cells are only a preference -- the table shrank to the card and the
   columns came out at 84px and 43px, which misaligns the one figure the
   grid exists to let you read across. */
table.matrix{width:auto;min-width:max-content;border-collapse:separate;
 border-spacing:2px;margin-top:6px}
table.matrix th.mx-group{font-size:12px;padding:0 0 8px 0;
 color:var(--text-dim);font-weight:600;text-align:center;
 border-bottom:1px solid var(--border-subtle)}
table.matrix .mx-div{border-left:1px solid var(--border-medium)}
table.matrix th.mx-col{font-size:12px;color:var(--text-secondary);
 font-weight:600;padding:0 8px 8px;text-align:center;border:none;white-space:normal}
table.matrix th.mx-row{text-align:right;padding:0 14px 0 0;font-size:13px;
 font-weight:500;color:var(--text-secondary);border:none;white-space:nowrap}
table.matrix td.mx-cell{width:104px;height:40px;text-align:center;
 border-radius:var(--radius-sm);font-family:var(--font-mono);font-size:13px;
 border:none;padding:0}
table.matrix td.mx-none{background:transparent;
 border:1px dashed var(--border-medium);color:var(--text-dim)}
table.matrix tr:hover td{background-clip:padding-box}
table.matrix tbody tr{height:auto}
.mx-link{display:block;line-height:40px;border-radius:var(--radius-sm)}
.mx-link:hover{text-decoration:underline;outline:2px solid var(--border-strong)}
.mx-on-dark{color:<@--matrix-ink-on-dark@>;font-weight:600}
.mx-on-light{color:<@--matrix-ink-on-light@>;font-weight:600}
.pill.cov-yes{color:<@--ok-text@>;border-color:<@--ok-edge-strong@>}
.lg{display:flex;gap:16px;margin-top:10px;font-size:12px;color:var(--text-secondary)}
.lg-item{display:inline-flex;align-items:center;gap:6px}
.lg-dot{width:8px;height:8px;border-radius:2px;display:inline-block}
.unit{font-size:13px;color:var(--text-dim);margin:-2px 0 0}
/* flex-wrap, because this line lists surface names and the list grows with
   the deployment. It is a flex container only to hang the status dot off
   ::before, and each <code> is a flex item -- so without wrapping, four
   surfaces ran past the edge on a narrow screen while the dot stayed put. */
.status{font-size:13px;font-weight:500;
 margin:10px 0 18px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.status-ok{color:var(--text-secondary)}
.status-ok::before{content:"\\2713";color:<@--ok-text@>}
.status-warn{color:<@--warn-text@>}
.status-warn::before{color:<@--warn-mark@>}
td .status{margin:0;display:inline-flex}
.mode{font-size:12px;font-weight:600;padding:4px 10px;border-radius:999px;align-self:center;
 border:1px solid var(--border-medium);color:var(--accent-primary);
 font-weight:400;line-height:1;white-space:nowrap}
.mode.shadow{border-color:var(--border-orange);color:<@--warn-text@>}
.pill.cov-no{color:<@--warn-text@>;border-color:<@--warn-edge@>}
table.log{font-size:12px}
table.log td{padding:7px 9px;vertical-align:middle}
table.log td.ts{font-family:var(--font-mono);color:var(--text-dim);white-space:nowrap}
.det{display:inline-block;font-family:var(--font-mono);font-size:10px;
 padding:2px 6px;margin:1px 3px 1px 0;border-radius:var(--radius-sm);
 border:1px solid var(--border-medium);color:var(--accent-primary-light)}
.det.block{border-color:var(--border-orange);color:<@--warn-text@>}
.act{font-size:12px;font-weight:600}
.act.deny{color:<@--warn-text@>}
.act.allow{color:var(--text-dim)}
.act.flag{color:<@--ok-text@>}
.act.shadow{color:<@--ok-text@>}
.empty-log{padding:36px;text-align:center;color:var(--text-dim);font-size:13px}
.meter{height:10px;background:var(--border-subtle);border-radius:var(--radius-sm);
 overflow:hidden;margin-top:14px}
.meter-fill{height:100%;border-radius:var(--radius-sm)}
.meter-caption{margin-top:8px;font-family:var(--font-mono);font-size:12px;
 color:var(--text-secondary)}
.yaml{font-family:var(--font-mono);font-size:12px;line-height:1.65;
 color:var(--text-secondary);white-space:pre;overflow-x:auto;margin:0;
 tab-size:2}
.yaml .k{color:var(--accent-primary)}
.yaml .c{color:var(--accent-primary-dim)}
.yaml .v{color:var(--text-primary)}
.note{margin-top:16px;font-size:13px;color:var(--text-dim);line-height:1.6;
 max-width:70ch}
/* flex-wrap for the same reason as .status: the event log's filter row is
   two groups (source, action) rather than the overview's one, so it is the
   page where a fixed row runs off first. */
.filters{display:flex;gap:10px;align-items:center;margin-top:20px;flex-wrap:wrap}
.filters a{font-size:13px;font-weight:500;padding:5px 12px;border-radius:999px;
 border:1px solid var(--border-subtle);color:var(--text-secondary);
 transition:border-color var(--transition-smooth)}
.filters a:hover{border-color:var(--border-medium);text-decoration:none}
.filters input,.filters button{font:500 13px var(--font-body);padding:6px 12px;
 border:1px solid var(--border-medium);border-radius:var(--radius-md);
 background:var(--bg-card);color:var(--text-primary)}
.filters input::placeholder{color:var(--text-dim)}
.filters button{cursor:pointer;background:var(--bg-elevated)}
.filters button:hover{border-color:var(--border-strong)}
.filters a[aria-current=true]{border-color:var(--border-strong);
 color:var(--text-primary);background:var(--bg-elevated)}
/* The event detail page. */
dl.kv{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:10px 28px;
 margin:0;font-size:13px}
dl.kv dt{color:var(--text-dim)}
dl.kv dd{margin:0;color:var(--text-primary);overflow-wrap:anywhere}
.crumbs{font-size:13px;color:var(--text-dim);margin-bottom:8px}
.see-all{display:inline-block;margin-top:14px;font-size:13px;font-weight:500}
footer{border-top:1px solid var(--border-subtle);margin-top:48px;padding:28px 0 40px;
 font-size:13px;color:var(--accent-primary)}
footer b{color:var(--text-primary);font-weight:700}
@media(max-width:900px){
 .shell{grid-template-columns:minmax(0,1fr);background:none}
 nav.rail{position:static;height:auto;flex-direction:row;flex-wrap:wrap;
  background:var(--bg-primary);border-bottom:1px solid var(--border-subtle);
  padding:8px 12px}
}
@media(max-width:720px){
 .wrap{padding:0 20px}
 h1{font-size:26px}
 /* The header was one 68px flex row that could not wrap: logo, tabs, org
    picker and the build/generated-at block. On a phone it ran to 670px and
    dragged the page with it. Let it become as many rows as it needs. */
 header.top{position:static}
 header.top .bar{flex-wrap:wrap;height:auto;gap:10px 14px;padding:14px 20px}
 nav.range{flex-wrap:wrap}
 nav.orgs{margin-left:0;padding-left:0;border-left:none;flex-wrap:wrap}
 .top-meta{margin-left:0;text-align:left;width:100%}
 /* Wide tables scroll within their card rather than widening the page.
    The card scroll itself is not here -- see `.card:has(table)` above,
    which is unconditional. This is only the part that is specific to a
    narrow screen: a timestamp is the one nowrap cell that reads fine
    broken across two lines, and unwrapping it buys back a column. */
 table.log td.ts{white-space:normal}
}
"""

RANGES = (
    ("24h", "Last 24 hours"),
    ("7d", "Last 7 days"),
    ("30d", "Last 30 days"),
    ("all", "All time"),
)


def _stat(label: str, value: str, sub: str = "", href: str | None = None,
          go: str = "View records") -> str:
    """A figure. With `href` (escaped) the tile links to what it counts."""
    sub_html = f'<div class="stat-sub">{sub}</div>' if sub else ""
    inner = (f'<div class="stat-label">{escape(label)}</div>'
             f'<div class="stat-value">{value}</div>{sub_html}')
    if href is None:
        return f'<div class="stat-card">{inner}</div>'
    return (f'<a class="stat-card" href="{href}">{inner}'
            f'<div class="stat-go">{escape(go)} &rarr;</div></a>')


def _surfaces_cell(surfaces: set[str], limit: int = 2) -> str:
    """Two surface names plus a count. The full list wrapped over four lines
    and pushed the numeric columns out of alignment."""
    ordered = sorted(surfaces)
    if len(ordered) <= limit:
        return escape(", ".join(ordered))
    shown = ", ".join(ordered[:limit])
    return (
        f'<span title="{escape(", ".join(ordered))}">{escape(shown)} '
        f'+{len(ordered) - limit}</span>'
    )


_STATE_CLASS = {"ok": "status-ok", "warn": "status-warn", "bad": "status-warn",
                "unknown": "status-warn"}
_STATE_WORD = {"ok": "ok", "warn": "watch", "bad": "broken", "unknown": "unknown"}


def _state_cell(state: str, detail: str = "") -> str:
    word = escape(_STATE_WORD.get(state, state))
    note = f' <span class="det-what">{escape(detail)}</span>' if detail else ""
    return f'<span class="status {_STATE_CLASS.get(state, "status-warn")}">{word}</span>{note}'


def _minutes(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value / 60:.1f} h" if value >= 120 else f"{value:.0f} min"


def _pipeline_section(pipe) -> str:
    """Delivery lag, join rate, cursor health, per-detector silence and
    daily delivery per source: the pipeline's own health, apart from what
    it found (store/pipeline.py)."""
    if pipe is None:
        return ""
    lag = "".join(
        f"<tr><td><code>{escape(r.source)}</code></td><td class='num'>{r.samples or '—'}</td>"
        f"<td class='num'>{_minutes(r.p50_min)}</td><td class='num'>{_minutes(r.p95_min)}</td>"
        f"<td class='num'>{_minutes(r.max_min)}</td><td>{_state_cell(r.state, r.detail)}</td></tr>"
        for r in pipe.lag)
    joins = "".join(
        f"<tr><td>{escape(j.name)}</td><td class='num'>{j.matched:,} of {j.total:,}</td>"
        f"<td class='num'>{'—' if j.rate is None else f'{j.rate * 100:.0f}%'}</td>"
        f"<td>{_state_cell(j.state, j.detail)}</td></tr>" for j in pipe.joins)
    cursors = "".join(
        f"<tr><td><code>{escape(c.reader)}</code> {escape(c.name)}</td>"
        f"<td class='num'>{'—' if c.age_hours is None else f'{c.age_hours:,.1f} h ago'}</td>"
        f"<td class='num'>{'—' if c.limit_days is None else f'{c.limit_days} d'}</td>"
        f"<td>{_state_cell(c.state, c.detail)}</td></tr>" for c in pipe.cursors
    ) or "<tr><td colspan='4'>No pulling reader is configured</td></tr>"
    if pipe.silent:
        silent = "".join(
            f"<tr><td><code>{escape(s.detector)}</code></td><td>{escape(s.last_fired)}</td>"
            f"<td class='num'>{s.active_days} of {s.baseline_days} days</td></tr>"
            for s in pipe.silent)
        silence = (f"<p>{_state_cell(pipe.silence_state)}</p><table><thead><tr>"
                   "<th>Detector</th><th>Last fired</th><th class='num'>Fired on</th></tr></thead>"
                   f"<tbody>{silent}</tbody></table>")
    else:
        silence = f"<p>{_state_cell(pipe.silence_state, pipe.silence_detail)}</p>"
    sources = sorted({s for _, per in pipe.daily for s in per})
    dropped = set(pipe.dropped)
    days = "".join(
        f"<tr><td>{escape(day)}</td>" + "".join(
            f"<td class='num'>{per.get(s, 0):,}"
            + (" <span class='status status-warn'>stopped</span>" if (day, s) in dropped
               else "") + "</td>" for s in sources) + "</tr>"
        for day, per in pipe.daily[:7])
    daily = ("<table><thead><tr><th>Day</th>"
             + "".join(f"<th class='num'><code>{escape(s)}</code></th>" for s in sources)
             + f"</tr></thead><tbody>{days}</tbody></table>") if sources else charts.empty(
        "No records in this window")
    return f"""  <section>
    <h2>Pipeline health</h2>
    <p class="unit">Whether each reader is still delivering, apart from what it found</p>
    <div class="card-grid cols-2">
      <div class="card"><h3>Delivery lag</h3><table><thead><tr><th>Source</th>
        <th class="num">Records</th><th class="num">p50</th><th class="num">p95</th>
        <th class="num">Max</th><th>State</th></tr></thead>
        <tbody>{lag}</tbody></table></div>
      <div class="card"><h3>Join rate</h3><table><thead><tr><th>Join</th>
        <th class="num">Matched</th><th class="num">Rate</th><th>State</th></tr></thead>
        <tbody>{joins}</tbody></table></div>
      <div class="card"><h3>Cursor health</h3><table><thead><tr><th>Reader</th>
        <th class="num">Last pass</th><th class="num">Limit</th><th>State</th></tr></thead>
        <tbody>{cursors}</tbody></table></div>
      <div class="card"><h3>Silent detectors</h3>{silence}</div>
    </div>
    <div class="card" style="overflow-x:auto;margin-top:16px"><h3>Records per source per
      day</h3>{daily}</div>
  </section>
"""


def _detector_table(summary: Summary, link=None, limit: int = 24,
                    compact: bool = False) -> str:
    """The detectors, most values first. `compact` keeps the name, severity
    and distinct values."""
    if not summary.detectors:
        return charts.empty("No findings recorded")
    from ..core import DESCRIPTIONS

    rows = []
    for det in summary.detectors[:limit]:
        pill = "block" if det.severity == "block" else "warn"
        # The detector name is the stable identifier and stays; the plain
        # description sits under it. `presidio:nrp` is not self-explanatory
        # to anyone who has not read Presidio's entity list.
        what = DESCRIPTIONS.get(det.detector, "")
        label = f"<code>{escape(det.detector)}</code>"
        href = link(detector=det.detector) if link is not None else None
        if href:
            label = f'<a href="{href}">{label}</a>'
        if what:
            label += f'<span class="det-what">{escape(what)}</span>'
        rows.append(
            f"<tr><td>{label}</td>"
            f'<td><span class="pill {pill}">{escape(det.severity)}</span></td>'
            f'<td class="num">{_linked(det.unique, href)}</td>'
            + ("</tr>" if compact else
               f'<td class="num">{det.device_salted or "—"}</td>'
               f'<td class="num">{_linked(det.count, href)}</td>'
               f'<td class="mono">{_surfaces_cell(det.surfaces)}</td></tr>')
        )
    if compact:
        return ("<table><thead><tr><th>Detector</th><th>Severity</th>"
                "<th class='num'>Distinct values</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody></table>")
    return (
        "<table><thead><tr><th>Detector</th><th>Severity</th>"
        "<th class='num'>Distinct values</th>"
        '<th class="num" title="Hashed with each laptop\'s own salt, so one value on '
        'several laptops counts once per laptop">Per-laptop values</th>'
        "<th class='num'>Occurrences</th><th>Surfaces</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


# Icon glyphs, drawn at 16x16 and referenced by <use>. Inline because the
# CSP is `default-src 'none'` -- an icon font or a sprite file is a
# request this page does not make.
_ICONS = {
    "chat": "M2 3h12v8H7l-3 3v-3H2z",
    "terminal": "M2 3h12v10H2zM4 6l2.5 2L4 10M8.5 10.5H12",
    "docs": "M4 2h5l3 3v9H4zM9 2v3h3",
    "grid": "M2 2h5v5H2zM9 2h5v5H9zM2 9h5v5H2zM9 9h5v5H9z",
    "clock": "M8 2a6 6 0 100 12A6 6 0 008 2zM8 5v3.5l2.5 1.5",
    "core": "M3 4h10v8H3zM6 7h4M6 9h4",
    "sink": "M8 2v7M5 6l3 3 3-3M3 12h10",
    "shield": "M8 2l5 2v4c0 3-2.2 5.2-5 6-2.8-.8-5-3-5-6V4z",
    "search": "M7 3a4 4 0 100 8 4 4 0 000-8zM10 10l4 4",
    "pulse": "M2 8h3l2-4 2 8 2-4h3",
    "list": "M5 4h9M5 8h9M5 12h9M2 4h.5M2 8h.5M2 12h.5",
}


# Seconds for one pulse to travel an inbound wire, by volume.
#
# Slow on purpose. The first pass ran 1.4-3.4s and the panel read as
# busy rather than alive -- five wires blinking above the numbers people
# actually came for. At this pace a pulse is something you notice when
# you look at it, not something competing for attention while you read
# the stat row.
#
# The ORDERING still carries the information: claude.ai at 1,840
# requests stays visibly quicker than Cowork at 95. Only the tempo moved.
#
# The outbound arm is deliberately NOT in here. It is a short straight
# line rather than a long curve, so the same duration reads faster on
# it, and at 1.8s it was already right.
PULSE_SECONDS = ((10, 7.5), (200, 6.0), (2000, 4.8))
PULSE_SECONDS_FAST = 4.0


def _pulse_seconds(requests: int) -> float:
    for threshold, seconds in PULSE_SECONDS:
        if requests < threshold:
            return seconds
    return PULSE_SECONDS_FAST


# Behind the core box, not on it. A border colour on a 126px rect reads
# as a status chip; what was asked for is the box looking like it is
# sitting on something. Three gradients rather than one recoloured by
# CSS, because an SVG gradient cannot inherit a colour from the element
# referencing it, and three static defs cost less than a filter.
# Not one opacity for all three. Green at .22 on this navy is nearly
# invisible while red at .22 is loud, so the three would read as
# "nothing, something, SOMETHING" rather than as three states.
# Centre opacity is tuned per colour to land them in the same place.
# Stroke colour and opacity per state. Green needs more of both: at a
# given opacity on this navy it reads far fainter than red.
_HALO = {
    "ok": (marker("--halo-ok"), ".95"),
    "warn": (marker("--halo-warn"), ".85"),
    "alert": (marker("--halo-alert"), ".85"),
}


# The core box fits 12 characters of its label: the text starts 38 units into
# a 126-unit box, and a character of 10px uppercase monospace with .08em
# letter-spacing takes 6.8.
CORE_LABEL_CHARS = 12


def _core_label(name: str) -> str:
    """`name` escaped, or its first 11 characters and an ellipsis with the
    full name as a tooltip when it does not fit the core box."""
    if len(name) <= CORE_LABEL_CHARS:
        return escape(name)
    return f"<title>{escape(name)}</title>{escape(name[:CORE_LABEL_CHARS - 1])}…"


def _topology(points, surfaces=None, sink=None, health="ok",
              empty_store: bool = False, name: str = DEFAULT_NAME) -> str:
    """The delivery diagram: what is reaching us, and what leaves.

    Products down the left -- claude.ai, Claude Code, Cowork, the office
    agents, the Compliance scan -- each on its own wire into the scan
    core, and one wire out to the sink when adapter 5 is configured.

    Shows PRODUCTS rather than adapters, because that is the question
    someone glancing at it has: is Cowork still reaching us, not is
    adapter 4. A product seen by several control points is as fresh as
    its freshest feed.

    NO JAVASCRIPT EXISTS HERE. The CSP is `default-src 'none'` with no
    `script-src`, so the travelling pulse is a CSS keyframe driving
    `offset-path` along the same path the wire draws, with values baked
    in at render time. The diagram is a snapshot that updates on refresh.

    A pulse runs only where something is actually flowing, at a speed
    that follows real volume. An animation on a dead wire is a lie that
    looks like health, which is the failure this exists to catch.
    """
    if not surfaces:
        return ""

    rows = [s for s in surfaces if s.state != "off"] or list(surfaces)
    n = len(rows)
    row_h, pad_t = 44, 22
    height = pad_t * 2 + row_h * n
    core_y = height / 2
    # The viewBox is sized to what a full-width column actually is, so
    # the SVG renders about 1:1. Drawn at 760 it scaled to 1.43x and
    # every label came out oversized -- the geometry was right and the
    # type was the wrong size for the page it sits on.
    x_icon, x_label, x_wire0, x_wire1, x_core = 22, 54, 300, 690, 720
    width = 1120 if sink else 900

    # One gradient, referenced by every pulse. A flat-filled circle
    # read as a hard dot sliding along a line; the falloff is what makes
    # it a ball of light instead. Defined in the SVG rather than as a CSS
    # filter because a blur() on five animated nodes is a repaint per
    # frame, and this is a decoration on a page people leave open.
    defs = ['<radialGradient id="tpxGlow">'
            '<stop class="tpxg-core" offset="0%"/>'
            '<stop class="tpxg-mid" offset="38%"/>'
            '<stop class="tpxg-edge" offset="100%"/>'
            "</radialGradient>"]
    halo_c, halo_o = _HALO.get(health, _HALO["ok"])
    # A blurred OUTLINE, not a radial fill. A radial gradient is round and
    # the core is a rounded rectangle, so sizing it to clear the corners
    # left a wash across a quarter of the panel. Blurring a stroke of the
    # same shape keeps the light within a few pixels of the edge.
    #
    # A filter here is affordable where it was not for the pulses: one
    # static element rasterises once, five animated ones repaint per frame.
    defs.append(
        '<filter id="tpxHaloBlur" x="-60%" y="-160%" '
        'width="220%" height="420%">'
        '<feGaussianBlur stdDeviation="2.4"/>'
        "</filter>"
    )
    wires, pulses, nodes = [], [], []
    for i, srf in enumerate(rows):
        y = pad_t + row_h * i + row_h / 2
        # A cubic that leaves the node flat and arrives at the core flat,
        # so four wires converge instead of four lines pointing at a box.
        d = (f"M{x_wire0} {y} C{x_wire0 + 110} {y} {x_wire1 - 110} {core_y} "
             f"{x_wire1} {core_y}")
        pid = f"tpw{i}"
        defs.append(f'<path id="{pid}" d="{d}" fill="none"/>')
        periodic = " tpx-periodic" if getattr(srf, "periodic", False) else ""
        wires.append(
            f'<use href="#{pid}" class="tpx-wire tpx-{srf.state}{periodic}"/>'
        )
        if srf.state == "live" and srf.requests:
            # A scheduled pull is not a stream. Its pulse crosses slowly,
            # so "running, every few hours" reads differently at a glance
            # from "delivering continuously" -- without either looking
            # broken.
            dur = 14.0 if periodic else _pulse_seconds(srf.requests)
            pulses.append(
                f'<circle r="9" class="tpx-pulse" '
                f'style="offset-path:path(\'{d}\');--tpx-dur:{dur}s;'
                f'--tpx-delay:{i * 0.55:.2f}s"/>'
            )
        nodes.append(
            f'<g class="tpx-node tpx-{srf.state}">'
            f'<rect x="{x_icon - 7}" y="{y - 13}" width="26" height="26" rx="7"/>'
            f'<path class="tpx-glyph" transform="translate({x_icon - 3},{y - 8})" '
            f'd="{_ICONS.get(srf.icon, _ICONS["chat"])}"/>'
            f'<text x="{x_label}" y="{y - 1}" class="tpx-label">'
            f"{escape(srf.label)}</text>"
            f'<text x="{x_label}" y="{y + 12}" class="tpx-sub">'
            f"{escape(srf.detail)}</text>"
            f"</g>"
        )

    out_svg = ""
    if sink:
        d_out = f"M{x_core + 134} {core_y} L{width - 180} {core_y}"
        defs.append(f'<path id="tpwout" d="{d_out}" fill="none"/>')
        out_svg = (
            f'<use href="#tpwout" class="tpx-wire tpx-live"/>'
            f'<circle r="9" class="tpx-pulse" style="offset-path:path('
            f"'{d_out}');--tpx-dur:1.8s;--tpx-delay:0s\"/>"
            f'<g class="tpx-node tpx-live">'
            f'<rect x="{width - 172}" y="{core_y - 22}" width="156" height="44" rx="9"/>'
            f'<path class="tpx-glyph" transform="translate({width - 158},{core_y - 8})" '
            f'd="{_ICONS["sink"]}"/>'
            f'<text x="{width - 132}" y="{core_y + 4}" class="tpx-label">'
            f"{escape(sink)}</text></g>"
        )

    core = (
        # The halo is inside the same group and drawn FIRST, so it sits
        # under the rect rather than washing over the text.
        f'<g class="tpx-core tpx-core-{health}">'
        f'<rect class="tpx-halo" x="{x_core - 2}" y="{core_y - 28}" '
        f'width="130" height="56" rx="13" '
        f'stroke="{halo_c}" stroke-opacity="{halo_o}"/>'
        f'<rect x="{x_core}" y="{core_y - 26}" width="126" height="52" rx="11"/>'
        f'<path class="tpx-glyph" transform="translate({x_core + 12},{core_y - 8})" '
        f'd="{_ICONS["core"]}"/>'
        + (f'<text x="{x_core + 38}" y="{core_y + 4}" class="tpx-core-t">verdict</text>'
           if name == DEFAULT_NAME else
           f'<text x="{x_core + 38}" y="{core_y - 1}" class="tpx-core-t">{_core_label(name)}</text>'
           f'<text x="{x_core + 38}" y="{core_y + 12}" class="tpx-core-t">verdict</text>')
        + "</g>"
    )

    late = [s for s in surfaces if s.state == "late"]
    if empty_store:
        # A mistyped store path produces a WORKING store with no
        # partitions, and this page then renders healthy and blank -- the
        # dashboard's own version of a clean scan. The signal existed in
        # `describe()` and appeared only on the Policy tab.
        head = "The store has no partitions — check the store path"
        head_cls = "tp-head tp-head-warn"
    elif late:
        head = "Late: " + ", ".join(s.label for s in late)
        head_cls = "tp-head tp-head-warn"
    else:
        head = "All active surfaces delivering"
        head_cls = "tp-head"
    # BOTH renderings, and CSS shows one.
    #
    # The SVG scales with its column, which is right down to about 720px
    # and wrong below it: at 390px the whole 1120-unit diagram squeezes
    # into ~326px and the labels land at roughly 4px. Scaling a
    # convergence diagram into a phone does not produce a small diagram,
    # it produces an unreadable one.
    #
    # The list is not a second source of truth -- both are built from
    # the same `surfaces`, in the same order, from the same states. The
    # hidden one is `display:none`, so it is out of the accessibility
    # tree too and a screen reader is not read the same five nodes
    # twice.
    compact = "".join(
        f'<li class="tpc-row tpx-{srf.state}">'
        f'<span class="tpc-dot"></span>'
        f'<span class="tpc-name">{escape(srf.label)}</span>'
        f'<span class="tpc-detail">{escape(srf.detail)}</span>'
        "</li>"
        for srf in rows
    )
    sink_row = (
        f'<li class="tpc-row tpx-live tpc-out">'
        f'<span class="tpc-dot"></span>'
        f'<span class="tpc-name">&rarr; {escape(sink)}</span>'
        f'<span class="tpc-detail">forwarding</span></li>'
    ) if sink else ""
    return (
        '<div class="topology">'
        f'<div class="{head_cls}">{escape(head)}</div>'
        f'<div class="tpx-wrap"><svg class="tpx" viewBox="0 0 {width} {height}" '
        f'role="img" aria-label="{escape(head)}">'
        f'<defs>{"".join(defs)}</defs>'
        f'{"".join(wires)}{out_svg}{core}{"".join(nodes)}{"".join(pulses)}'
        "</svg></div>"
        f'<ul class="tpc">{compact}{sink_row}</ul>'
        "</div>"
    )


PAGES = {
    "overview": ("/", "overview"),
    "coverage": ("/coverage", "coverage"),
    "detectors": ("/detectors", "detectors"),
    "delivery": ("/delivery", "delivery"),
}


def render(summary: Summary, window: str = "7d", store_desc: dict | None = None,
           orgs: dict[str, str] | None = None, selected: str = "",
           viewer: str = "", points=None, surfaces=None, sink=None,
           empty_store: bool = False, banners: str = "",
           branding: Branding | None = None, page: str = "overview") -> str:
    """One of the summary pages, `page` a key of PAGES."""
    branding = branding or Branding()
    path, title = PAGES[page]

    def link(**filters: str) -> str:
        return events_link(window, selected, **filters)

    body = {"overview": _overview_body, "coverage": _coverage_body,
            "detectors": _detectors_body, "delivery": _delivery_body}[page](
        summary, link, points=points, surfaces=surfaces, sink=sink,
        empty_store=empty_store, branding=branding, window=window, selected=selected)
    backend = str((store_desc or {}).get("backend", "—"))
    return _chrome(title, path, summary.generated_at, backend, body,
                   orgs, selected, viewer, banners, branding, window=window)


def _overview_body(summary: Summary, link, *, points, surfaces, sink, empty_store,
                   branding, window, selected) -> str:
    stats = "".join([
        _stat("Prompts evaluated live", f"{summary.live_requests:,}",
              "Inference hooks"
              + (f" &middot; {summary.tool_call_checks:,} tool call checks, "
                 f"{summary.tool_call_would_deny:,} would deny"
                 if summary.tool_call_checks else ""),
              href=link(source="inference_hook", kind="prompt")
              if summary.live_requests else None),
        _stat("Sessions audited",
              f"{summary.scanned_sessions + summary.managed_sessions:,}",
              "Compliance API" + (f" &middot; {summary.managed_sessions:,} managed agents"
                                  if summary.managed_sessions else ""),
              href=link(kind="audit")
              if summary.scanned_sessions + summary.managed_sessions else None),
        # The can/cannot-block wording sits on the headline tiles rather
        # than in a duplicate tile further down: it is the distinction the
        # two numbers turn on, and it belongs where they are read.
        _would_deny_tile(summary, link),
        _stat("Detected in audit", f"{summary.detections:,}",
              f"{summary.detection_rate * 100:.1f}% of scanned sessions "
              "&middot; cannot block",
              href=link(kind="detected") if summary.detections else None),
        _stat("Distinct values found", f"{summary.distinct_values:,}",
              f"{summary.total_findings:,} occurrences"
              + (f" &middot; {summary.device_salted_values:,} more from laptops, counted "
                 "once per laptop" if summary.device_salted_values else ""),
              href=_href("/detectors", _state(window, selected)), go="By detector"),
        _stat("Round trip p95", f"{summary.latency.get('p95', 0):.0f}<span "
              f'style="font-size:16px;color:var(--text-dim)"> ms</span>',
              f"p50 {summary.latency.get('p50', 0):.0f} ms · "
              f"p99 {summary.latency.get('p99', 0):.0f} ms",
              href=_href("/delivery", _state(window, selected)), go="Delivery"),
    ])
    topology = _topology(points or [], surfaces, sink,
                         core_health(points or []), empty_store=empty_store,
                         name=branding.name)
    gaps = [r.surface for r in summary.surfaces if not r.inline_coverage]
    coverage = (
        f'<p class="status status-warn">{len(gaps)} surface(s) audit only &mdash; '
        + ", ".join(_maybe_link(f"<code>{escape(g)}</code>", link(surface=g)) for g in gaps)
        + "</p>" if gaps else
        '<p class="status status-ok">Inline coverage complete</p>' if summary.surfaces
        else '<p class="status status-warn">No traffic recorded yet</p>')
    return f"""
  <div class="hero">
    <h1>Overview {_mode_badge(summary)}</h1>
    {topology}
    <div class="stat-row">{stats}</div>
    {_excluded_note(summary)}
  </div>
  <section>
    <div class="card-grid cols-2" style="margin-top:0">
      <div class="card"><h2>Coverage</h2>{coverage}
        {charts.hbar([(r.surface, r.requests) for r in summary.surfaces], charts.STEEL,
                     empty_message="No requests recorded yet")}
        <a class="see-all" href="{_href('/coverage', _state(window, selected))}">Control
          points by surface &rarr;</a></div>
      <div class="card"><h2>Top detectors</h2>
        {_detector_table(summary, link, limit=5, compact=True)}
        <a class="see-all" href="{_href('/detectors', _state(window, selected))}">All
          detectors &rarr;</a></div>
    </div>
  </section>
  <section>
    <h2>Per day</h2>
    <div class="card">{charts.grouped_bars(summary.daily,
        empty_message="Not enough history yet")}</div>
  </section>
"""


def _coverage_body(summary: Summary, link, **_) -> str:
    return f"""
  <div class="hero">
    <h1>Coverage {_mode_badge(summary)}</h1>
    <p class="lede">Which controls saw each product surface in this window, and
    whether anything checked a surface before it reached the model.</p>
  </div>
{_coverage_matrix(summary, _reconciliation_aside(summary.reconciliation),
                    "", link=link)}
  <section>
    <h2>Surfaces</h2>
    <div class="card" style="margin-top:16px">{_surface_table(summary, link)}</div>
  </section>
"""


def _detectors_body(summary: Summary, link, **_) -> str:
    family_rows = families(summary)
    family_notes = {family: f"{n:,} per-laptop value{'s' if n != 1 else ''}"
                    for family, n in family_device_values(summary).items()}
    # Severity is a status the rows already carry, so it is the one
    # legitimate colour job here. A single hue made 201 low-precision NER
    # locations look exactly as weighty as 47 checksum-validated NHS
    # numbers.
    severity = family_severities(summary)
    family_hues = {
        family: charts.TERRACOTTA if severity.get(family) == "block"
        else charts.STEEL
        for family, _ in family_rows
    }
    return f"""
  <div class="hero">
    <h1>Detectors</h1>
    <p class="lede">What was found, by detector. Select a detector or a count to see
    the records; the store holds detector names and positions, never the matched
    text.</p>
  </div>
  <section>
    <h2>By family</h2>
    <p class="unit">Distinct values, deployment salt only{
        " &middot; per-laptop values beside the bar, counted once per laptop"
        if family_notes else ""}</p>
    <div class="card">{charts.hbar(family_rows, family_hues, width=1180,
        label_width=190, empty_message="No findings recorded yet",
        notes=family_notes)}
        {charts.severity_legend()}</div>
    <div class="card" style="overflow-x:auto;margin-top:16px">
      {_detector_table(summary, link)}</div>
  </section>
"""


def _delivery_body(summary: Summary, link, **_) -> str:
    return f"""
  <div class="hero">
    <h1>Delivery</h1>
    <p class="lede">What inspection costs on the request path, and whether each
    reader is still delivering.</p>
  </div>
  <section>
    {_round_trip_aside(summary)}
  </section>
{_pipeline_section(summary.pipeline)}
"""


def _maybe_link(inner: str, href: str | None) -> str:
    return f'<a href="{href}">{inner}</a>' if href else inner


def _linked(n: int, href: str | None) -> str:
    """`n`, linked to the records it counts when it is not zero."""
    return f'<a href="{href}">{n:,}</a>' if n and href else f"{n:,}"


LIVE, AUDIT = "inference_hook", "compliance_scan"


def _surface_table(summary: Summary, link=None) -> str:
    if not summary.surfaces:
        return charts.empty("No requests recorded")

    def to(**filters):
        return link(**filters) if link is not None else None

    def name(surface):
        return _maybe_link(f"<code>{escape(surface)}</code>", to(surface=surface))

    rows = "".join(
        f"<tr><td>{name(r.surface)}</td>"
        f'<td class="num">'
        f'{_linked(r.live, to(surface=r.surface, source=LIVE, kind="prompt"))}</td>'
        f'<td class="num">{_linked(r.post_hoc, to(surface=r.surface, source=AUDIT))}</td>'
        f"<td>{_coverage_pill(r)}</td>"
        f'<td class="num">'
        f'{_linked(r.would_deny, to(surface=r.surface, kind="inline", action="deny"))}</td>'
        f'<td class="num">{_linked(r.detections, to(surface=r.surface, kind="detected"))}</td>'
        f'<td class="num">{_latency_cell(r)}</td></tr>'
        for r in summary.surfaces
    )
    return (
        "<table><thead><tr><th>Surface</th><th class='num'>Live</th>"
        "<th class='num'>Audited</th><th>Inline</th><th class='num'>Would deny</th>"
        "<th class='num'>Detected</th><th class='num'>p95 ms</th>"
        "</tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _slowest_note(summary: Summary) -> str:
    """Explain the maximum rather than just state it.

    The worst frame is almost always a cold session start on a large
    transcript, which is expected. A bare number invites someone to read it
    as a problem and ask for it to be reset; the cause makes it
    interpretable, and p99 gives it scale.
    """
    s = summary.slowest
    p99 = summary.latency.get("p99", 0)
    if not s:
        return "no timed requests yet"
    kb = s["body_bytes"] / 1024
    cause = "cache hit" if s["cache_hit"] else "cold, full scan"
    return (
        f"{kb:,.0f} KB &middot; {s['messages']} msgs &middot; {cause}"
        f"<br>p99 {p99:.0f} ms"
    )


def _latency_cell(row) -> str:
    return f"{row.p95:.0f}" if row.has_latency else "&mdash;"


def _recon_note(recon) -> str:
    """Status of the post-hoc join, or nothing.

    Says nothing when there is nothing to report. "All denial records
    joined" against 0 of 0 would claim success for work that never ran.
    """
    if not recon.scanned_sessions:
        return '<p class="status status-warn">Audit scan has not run</p>'
    if recon.denials_unmatched:
        return (
            f'<p class="status status-warn">{recon.denials_unmatched} '
            "denial record(s) match no verdict here, by request id or reference id</p>"
        )
    if recon.denial_activities:
        return (
            f'<p class="status status-ok">{recon.denial_activities} denial '
            "record(s) joined</p>"
        )
    return ""


__all__ = ["render"]


NAV = (
    ("/", "Overview", "grid"),
    ("/coverage", "Coverage", "shield"),
    ("/detectors", "Detectors", "search"),
    ("/delivery", "Delivery", "pulse"),
    ("/events", "Events", "list"),
    ("/policy", "Policy", "docs"),
)


# What the event log's filters and the record page accept. A link is built
# only for a value that passes, so a link never opens a filter the route
# drops.
DETECTOR_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}")
SURFACE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:\-]{0,63}")
RECORD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:\-]{0,199}")

# The event log's `kind` filter: which records a summary figure counts, where
# a control point alone does not say. `prompt` is the inference hook's
# prompts, without its tool-call checks; `inline` every inline evaluation but
# those; `audit` the scanned sessions; `detected` the post-hoc records with a
# blocking-severity finding.
KINDS = {
    "prompt": "Prompts",
    "inline": "Inline evaluations",
    "audit": "Audited sessions",
    "detected": "Detected in audit",
}


def _of_kind(r, kind: str) -> bool:
    if kind == "prompt":
        return r.source == "inference_hook" and r.event != EVENT_TOOL_CALL
    if kind == "inline":
        return r.is_inline and r.event != EVENT_TOOL_CALL
    if kind == "audit":
        return r.source in ("compliance_scan", "managed_scan")
    if kind == "detected":
        return not r.is_inline and r.detected
    return True


def event_match(surface: str = "", kind: str = ""):
    """The event log's `match` for a surface and a kind; None for neither."""
    if not surface and not kind:
        return None
    from ..store.query import normalize_surface

    return lambda r: ((not surface or normalize_surface(r.surface) == surface)
                      and _of_kind(r, kind))


def _state(window: str | None, selected: str) -> dict[str, str]:
    """The query that carries the window and the selected org to another
    page."""
    return {**({"window": window} if window and window != "7d" else {}),
            **({"org": selected} if selected and selected != "all" else {})}


def _href(path: str, query: dict[str, str]) -> str:
    """`path` with `query`, escaped for an attribute."""
    return escape(path + ("?" + urlencode(query) if query else ""), quote=True)


def events_link(window: str | None, selected: str = "", **filters: str) -> str | None:
    """The event log filtered to `filters`, in this window and org, or None
    when the log would drop a surface or detector filter given."""
    for key, valid in (("surface", SURFACE_NAME), ("detector", DETECTOR_NAME)):
        if filters.get(key) and not valid.fullmatch(filters[key]):
            return None
    return _href("/events", {**_state(window, selected),
                             **{k: v for k, v in filters.items() if v}})


def _kind_suffix(key: str) -> str:
    """' (workspace)' for a Managed Agents workspace's partition, else ''."""
    return " (workspace)" if partition_kind(key) == KIND_WORKSPACE else ""


def _org_picker(orgs: dict[str, str], selected: str, path: str,
                window: str | None = None) -> str:
    """The org selector, shown only when there is a choice to make.

    Deliberately not a control: it narrows a view, and the authorization is
    the 403 on the route behind it. A viewer sees only the orgs they may
    read, so this lists what is already permitted rather than deciding it.

    One org means no picker. Most deployments serve one customer with one
    org, and a dropdown with a single entry is furniture.
    """
    if len(orgs) < 2:
        return ""
    items = [("all", "All orgs"), *sorted(orgs.items(), key=lambda kv: kv[1].lower())]
    links = "".join(
        f'<a href="{_href(path, {**_state(window, ""), "org": key})}"'
        f'{" aria-current=true" if key == (selected or "all") else ""}>'
        f"{escape(label)}{_kind_suffix(key)}</a>"
        for key, label in items
    )
    return f'<nav class="orgs">{links}</nav>'


def _favicon(branding: Branding) -> str:
    icon = branding.favicon
    if icon is None:
        return ""
    href = f"/assets/brand/{icon.filename}"
    size = png_size(icon.data) if icon.content_type == "image/png" else None
    sizes = f' sizes="{size[0]}x{size[1]}"' if size else ""
    return (f'<link rel="icon" type="{icon.content_type}"{sizes} href="{href}">\n'
            f'<link rel="apple-touch-icon" href="{href}">\n')


def _brand_mark(branding: Branding) -> str:
    if branding.logo is not None:
        return (f'<img src="/assets/brand/{branding.logo.filename}" '
                f'alt="{escape(branding.name)}">')
    return ('<span style="font-family:var(--font-mono);font-size:14px;font-weight:500;'
            f'letter-spacing:.06em;color:var(--text-primary)">{escape(branding.name)}</span>')


def _footer(branding: Branding) -> str:
    footer = branding.footer
    if footer is None:
        return ""
    text = escape(footer.text)
    if footer.link:
        text = f'<a href="{escape(footer.link)}">{text}</a>'
    return (f"  <footer><b>{escape(branding.name)}</b>&nbsp;&nbsp;|&nbsp;&nbsp;"
            f"{text}</footer>\n")


THEMES = (("auto", "Auto"), ("light", "Light"), ("dark", "Dark"))


def _range_picker(path: str, window: str, selected: str) -> str:
    links = "".join(
        f'<a href="{_href(path, {**_state(key, selected)})}"'
        f'{" aria-current=true" if key == window else ""}>{escape(label)}</a>'
        for key, label in RANGES)
    return f'<nav class="range" aria-label="Time window">{links}</nav>'


def _chrome(title: str, path: str, meta: str, backend: str, body: str,
            orgs: dict[str, str] | None = None, selected: str = "",
            viewer: str = "", banners: str = "",
            branding: Branding | None = None, window: str | None = None) -> str:
    """Shared shell for every page, so nav and branding cannot drift.
    `window` is the time window of a page that reads records; a page
    without one has no window picker."""
    branding = branding or Branding()
    state = _state(window, selected)
    rail = "".join(
        f'<a href="{_href(href, state)}"'
        f'{" aria-current=page" if href == path else ""}>'
        f'<svg viewBox="0 0 16 16" aria-hidden="true"><path d="{_ICONS[icon]}"/></svg>'
        f"{escape(label)}</a>"
        for href, label, icon in NAV
    )
    picker = _org_picker(orgs or {}, selected, path, window)
    ranges = _range_picker(path, window, selected) if window else ""
    palette = ",".join(branding.colours[k] for k in ("--chart-alert", "--chart-primary"))
    here = path + ("?" + urlencode(state) if state else "")
    themes = "".join(
        f'<a class="t-{key}" href="{_href("/theme", {"set": key, "next": here})}">{label}</a>'
        for key, label in THEMES)
    return branding.fill(
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<meta name="robots" content="noindex,nofollow">\n'
        + _favicon(branding)
        + f"<title>forgd-verdict &mdash; {escape(title)}</title>\n"
        f"<style>{branding.tokens_css}\n{branding.scheme_css}\n{PAGE_CSS}</style></head>\n"
        f'<body data-palette="{escape(palette, quote=True)}">\n'
        '<header class="top"><div class="bar">\n'
        f"  {_brand_mark(branding)}\n"
        f"  {ranges}\n"
        f"  {picker}\n"
        # Who the page was built for. Not decoration: with auth in front,
        # "is this actually authenticating?" is otherwise only answerable
        # by reading pod logs, and a misconfigured proxy that lets everyone
        # through looks exactly like one that works.
        f'  <span class="top-meta">'
        + (f"signed in as {escape(viewer)}<br>" if viewer else "")
        + f"generated {escape(meta)} &middot; store: {escape(backend)}"
        + "</span>\n"
        f'  <nav class="theme" aria-label="Colour theme">{themes}</nav>\n'
        "</div></header>\n"
        f'<div class="shell"><nav class="rail" aria-label="Pages">{rail}</nav>\n'
        f'<main><div class="wrap">{banners}{body}\n'
        + _footer(branding)
        + "</div></main></div></body></html>"
    )


def _coverage_pill(row) -> str:
    """Whether any inline control evaluated this surface.

    The most consequential cell in the view: a surface seen only by the
    post-hoc scan reached the model with nothing checking it first. Carries
    a word as well as a colour.
    """
    if row.inline_coverage:
        return '<span class="pill cov-yes">yes</span>'
    return '<span class="pill cov-no">audit only</span>'


def _excluded_note(summary: Summary) -> str:
    """Say so when frames are being left out of the rates.

    A statistic that quietly omits records is worse than a noisy one, so the
    count is always on the page when it is non-zero.
    """
    if not summary.excluded_frames:
        return ""
    n = summary.excluded_frames
    return (
        f'<p class="status status-ok">{n:,} frame(s) excluded from these '
        "rates &mdash; still in the event log</p>"
    )


def _would_deny_tile(summary: Summary, link=None) -> str:
    """The inference hook's would-deny count and rate, or "no adapter data"
    when it evaluated nothing, then the intake token's, labelled."""
    token = (f"via intake token: {summary.token_would_deny:,} of "
             f"{summary.token_decisions:,} ({summary.token_deny_rate * 100:.1f}%)"
             if summary.token_deny_rate is not None else "")
    if summary.deny_rate is None:
        return _stat("Would deny (inline)", "&mdash;",
                     "no adapter data" + (f" &middot; {token}" if token else ""))
    return _stat("Would deny (inline)", f"{summary.adapter_would_deny:,}",
                 f"{summary.deny_rate * 100:.1f}% of live evaluations &middot; can block"
                 + (f" &middot; {token}" if token else ""),
                 href=link(source="inference_hook", kind="prompt", action="deny")
                 if link is not None and summary.adapter_would_deny else None)


def _mode_badge(summary: Summary) -> str:
    """Whether the inline controls are applying their verdicts.

    Derived from the data rather than read from config: a record carries
    `shadow_action` only when the control decided one thing and did another.
    A badge rather than a footnote, because every would-deny number on the
    page means something different depending on it.
    """
    if not summary.live_requests:
        return ""
    if summary.shadow_frames:
        return '<span class="mode shadow">shadow &middot; not blocking</span>'
    return '<span class="mode">enforcing</span>'


def _reconciliation_aside(recon) -> str:
    """The reconciliation figures, beside the matrix rather than below it.

    They answer the same question the matrix does -- which control saw
    what -- and the matrix card hugs its table, so there is room.
    """
    return (
        "<section>"
        '<h2>Live vs audit</h2>'
        '<div class="aside">'
        + _stat("Code hook decisions", f"{recon.code_hook_decisions:,}",
                f"{recon.code_hook_denied:,} blocked before running"
                + (f" · {recon.code_hook_withheld:,} output withheld after"
                   if recon.code_hook_withheld else ""))
        + _stat("Values missed live", f"{recon.missed_count:,}",
                "not seen inline")
        + _stat("Denials joined",
                f"{recon.joined_by_request_id + recon.joined_by_reference:,}",
                f"of {recon.denial_activities:,} activity records"
                + (f" · {recon.denials_tool_call:,} of tool calls"
                   if recon.denials_tool_call else ""))
        + _recon_note(recon)
        + "</div></section>"
    )


def _round_trip_aside(summary: Summary) -> str:
    """Cost of inspection, in a column beside the coverage matrix.

    Its own full-width row held four tiles and a lot of nothing. The matrix
    is a fixed width, so the space beside it is where these fit.
    """
    return (
        "<section>"
        '<h2>Cost of inspection</h2>'
        '<div class="aside">'
        + _stat("Session cache hit rate", f"{summary.cache_hit_rate * 100:.0f}%",
                f"{summary.cache_hits:,} hits &middot; {summary.cache_misses:,} misses")
        + _stat("Coverage lost to budget", f"{summary.tiers_dropped:,}",
                "a tier was dropped")
        + _stat("Over the scan size limit", f"{summary.oversize_unscanned:,}",
                "part of a value was not scanned")
        + _stat("Artifacts not scanned", f"{summary.artifacts_unscanned:,}",
                "a chat artifact could not be fetched")
        + _stat("Deleted before read", f"{summary.deleted_unread:,}",
                "a chat was deleted before its messages were read")
        + _stat("Histories read in part", f"{summary.history_partial:,}",
                "a managed session's history could not be paged to its end")
        + _stat("Scan budget exceeded", f"{summary.budget_exceeded:,}",
                "over the scan budget")
        + _stat("Slowest round trip", f"{summary.latency.get('max', 0):.0f}"
                '<span style="font-size:16px;color:var(--text-dim)"> ms</span>',
                _slowest_note(summary))
        + _post_hoc_stat(summary)
        + "</div></section>"
    )


def _post_hoc_stat(summary: Summary) -> str:
    """The audit scan's own duration, in its own box.

    Deliberately NOT folded into "round trip". Adapter 3 runs on a cron
    and nothing times out on it, so a slow pass costs money rather than
    failing a request. Averaged together, a regression on the path that
    does have a 5,000 ms deadline would disappear into it.
    """
    stats = summary.post_hoc_latency or {}
    if not stats.get("n"):
        return ""
    return _stat(
        "Slowest audit scan", f"{stats.get('max', 0):.0f}"
        '<span style="font-size:16px;color:var(--text-dim)"> ms</span>',
        f"{stats['n']:,} sessions &middot; p95 {stats.get('p95', 0):.0f} ms"
        f"<br>p99 {stats.get('p99', 0):.0f} ms",
    )


MATRIX_SOURCES = {
    "Inference hook": "inference_hook",
    "Agent check": "agent_scan",
    "Code hook": "code_hook",
    "Compliance scan": "compliance_scan",
    "Managed scan": "managed_scan",
    "OTel": "otel_collect",
}


def _coverage_matrix(summary: Summary, aside: str = "", trailing: str = "",
                     link=None) -> str:
    """Surfaces x control points, directly under the headline.

    This is the question the project exists to answer, so it gets a section
    of its own rather than a column in a table.
    """
    # Column order is prevention first, detection last, left to right.
    # "Agent check" only when some surface has one: it exists for agents a
    # customer builds on the Developer Platform, and most deployments
    # would otherwise carry an empty column.
    agent = any(getattr(r, "agent", 0) for r in summary.surfaces)
    # Likewise "Managed scan", for deployments that read Managed Agents.
    managed = any(getattr(r, "managed", 0) for r in summary.surfaces)
    cols = ("Inference hook", *(("Agent check",) if agent else ()),
            "Code hook", "Compliance scan", *(("Managed scan",) if managed else ()),
            "OTel")
    rows = [r.surface for r in summary.surfaces]
    cells = {}
    for r in summary.surfaces:
        cells[(r.surface, "Inference hook")] = r.live
        cells[(r.surface, "Agent check")] = getattr(r, "agent", 0)
        cells[(r.surface, "Code hook")] = r.code_hook
        cells[(r.surface, "Compliance scan")] = r.post_hoc
        cells[(r.surface, "OTel")] = r.otel
        cells[(r.surface, "Managed scan")] = getattr(r, "managed", 0)

    gaps = [r.surface for r in summary.surfaces if not r.inline_coverage]
    if gaps:
        names = ", ".join(f"<code>{escape(g)}</code>" for g in gaps)
        callout = (
            f'<p class="status status-warn">{len(gaps)} surface(s) '
            f"audit only &mdash; {names}</p>"
        )
    elif rows:
        callout = '<p class="status status-ok">Inline coverage complete</p>'
    else:
        callout = ""

    # The banded header carries what the numbers cannot: two of these
    # controls can refuse a request and two can only report on one. Stated
    # by position and label rather than colour, so it survives a printout.
    #
    # The spans are counted from `cols` rather than written as literals, so
    # a column added to `cols` lands inside a band. With literals it would
    # sit under no heading at all, which is precisely the claim this table
    # exists to make unambiguous.
    blocking = sum(1 for c in cols if c in ("Inference hook", "Agent check", "Code hook"))

    def cell_href(surface: str, col: str) -> str:
        # The Code hook count includes its allows, which the log hides by
        # default.
        extra = ({"code_hook_allows": "show"} if col == "Code hook"
                 else {"kind": "prompt"} if col == "Inference hook" else {})
        return link(surface=surface, source=MATRIX_SOURCES[col], **extra)

    table = charts.matrix(
        rows, cols, cells,
        empty_message="No traffic recorded yet",
        groups=[
            ("Blocks before inference", blocking),
            ("Detects after inference", len(cols) - blocking),
        ],
        href=cell_href if link is not None else None,
    )
    return (
        f'  <div class="section-row{"" if trailing else " pair"}">\n'
        "    <section>\n"
        "      <h2>Control points</h2>\n"
        '      <p class="unit">Records per surface and control. Select a count to see '
        "them.</p>\n"
        f"      {callout}\n"
        f'      <div class="card fit" style="overflow-x:auto">{table}</div>\n'
        "    </section>\n"
        f"    {aside}\n"
        f"    {trailing}\n"
        "  </div>\n"
    )


def _bytes_cell(value) -> str:
    """A post-hoc session has no request body. 0 reads as "empty"
    rather than "not applicable" -- the same error as reporting a p95 of
    zero for a control that never made a round trip."""
    if isinstance(value, bool) or not isinstance(value, int) or not value:
        return "&mdash;"
    return f"{value:,}"


def _count_cell(value) -> str:
    """A whole number for a finite int or float, and 0 for anything else."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "0"
    if isinstance(value, float) and not math.isfinite(value):
        return "0"
    return f"{value:.0f}"


def _correlation(value: str) -> str:
    """Show the distinguishing end of an identifier, not the shared start.

    Compliance session ids are `clls_` plus a base64 payload whose leading
    characters are identical across sessions, so a head-truncated column
    rendered every row the same and defeated the column's only purpose:
    telling rows apart."""
    if len(value) <= 24:
        return value
    return f"{value[:9]}\u2026{value[-12:]}"


def _source_label(source: str) -> str:
    return {
        "inference_hook": "inference hook",
        "code_hook": "code hook",
        "compliance_scan": "compliance scan",
        "otel_collect": "otel",
        "agent_scan": "agent check",
        "managed_scan": "managed scan",
    }.get(source, source)


def _finding_pills(findings, limit: int = 8) -> str:
    """One pill per distinct detector, with a count, capped.

    A pill per finding does not scale: a single session can produce over a
    hundred `presidio:person` hits and render a table row several thousand
    pixels tall, which pushes every other row off the page.
    The count is the information; the repetition never was.
    """
    if not findings:
        return '<span style="color:var(--text-dim)">&mdash;</span>'
    tally: dict[str, list] = {}
    for f in findings:
        seen, hashes = tally.setdefault(f.detector, [f.severity, set()])
        hashes.add(f.excerpt_hash)
    # Blocking severity first, then by weight: the row should lead with the
    # finding someone has to act on, not with whichever detector ran first.
    ordered = sorted(
        tally.items(),
        key=lambda kv: (kv[1][0] != "block", -len(kv[1][1]), kv[0]),
    )
    pills = []
    for detector, (severity, hashes) in ordered[:limit]:
        cls = "block" if severity == "block" else ""
        n = len(hashes)
        # Distinct values, not occurrences: "3" here and "3" in the detector
        # table must mean the same thing.
        count = f' <b>{n}</b>' if n > 1 else ""
        pills.append(f'<span class="det {cls}">{escape(detector)}{count}</span>')
    if len(ordered) > limit:
        pills.append(
            f'<span class="det">+{len(ordered) - limit} more</span>'
        )
    return "".join(pills)


SEALED_SHOWN = 20


def _sealed_commands(findings) -> str:
    """A collapsed list of the `forgd-verdict unseal` command for each
    distinct sealed value among `findings`, at most SEALED_SHOWN; empty when
    none is sealed. The values are ciphertext: the dashboard cannot open
    them, and the command runs under the reader's own cloud login."""
    seen = list(dict.fromkeys((f.detector, f.sealed) for f in findings
                              if getattr(f, "sealed", None)))
    if not seen:
        return ""
    lines = "".join(
        f'<code style="display:block;font-size:10px;word-break:break-all;'
        f'margin-top:4px">forgd-verdict unseal {escape(d)} {escape(s)}</code>'
        for d, s in seen[:SEALED_SHOWN])
    more = (f'<div style="color:var(--text-dim);font-size:10px">'
            f'+{len(seen) - SEALED_SHOWN} more</div>' if len(seen) > SEALED_SHOWN else "")
    return (f'<details style="margin-top:4px"><summary style="font-size:10px;'
            f'color:var(--text-dim);cursor:pointer">{len(seen)} sealed</summary>'
            f'{lines}{more}</details>')


def render_events(records, source: str = "all", action: str = "all",
                 limit: int = 200, store_desc: dict | None = None,
                 client: str = "", device: str = "",
                 generated_at: str = "",
                 orgs: dict[str, str] | None = None, selected: str = "",
                 viewer: str = "", banners: str = "", exclude_form=None,
                 id_screen=None, branding: Branding | None = None,
                 deny_form=None, older: str | None = None, window: str = "",
                 detector: str = "", paged: bool = False,
                 show_allows: bool = False, older_label: str = "",
                 approximate: str | None = None, surface: str = "",
                 kind: str = "") -> str:
    """One row per evaluated request. `older` is the cursor for the next
    page when the window holds older events than this one shows, and
    `older_label` where this page reads back to, `approximate` the day
    whose rows on this page are in storage order rather than time order,
    `paged`
    whether this is a later page, and `show_allows` whether the Code hook's
    allow rows are shown.

    The overview answers "how much". This answers "what happened at 20:44".
    Findings appear as detector pills. A matched value appears only sealed,
    with `privacy.sealing` on, as the `unseal` command that opens it.

    Each request or session id is shown through `id_screen`
    (overrides.OrgScreen) when one is given. A row whose id the screen
    changes gets no Exclude form, whose value would carry the id.
    """
    backend = str((store_desc or {}).get("backend", "—"))
    narrowed = {k: v for k, v in (("kind", kind), ("surface", surface), ("client", client),
                                  ("device", device), ("detector", detector)) if v}
    state = {**({"org": selected} if selected and selected != "all" else {}),
             **({"window": window} if window else {}),
             **{k: v for k, v in (("source", source), ("action", action)) if v != "all"},
             **narrowed, **({"code_hook_allows": "show"} if show_allows else {})}

    def events_href(**changes) -> str:
        query = {k: v for k, v in {**state, **changes}.items() if v is not None}
        return escape("/events?" + urlencode(query), quote=True)

    rows = []
    for r in records[:limit]:
        # Each control reports in its own terms. An inline control allowed or
        # blocked; a post-hoc scan found something or did not. One shared
        # allow/deny column would imply the scan declined to block.
        act = r.disposition
        cls = {"deny": "deny", "detected": "deny",
               "flagged": "flag", "deleted": "flag"}.get(act, "allow")
        shadow = (
            ' <span class="act shadow">(shadow)</span>'
            if r.shadow_action and r.shadow_action != r.action
            else ""
        )
        if r.deleted_at and act != "deleted":
            shadow += ' <span class="act shadow">(deleted)</span>'
        if r.event == EVENT_TOOL_CALL:
            # The verdict covered the tool calls in a model response, not a
            # prompt.
            shadow += ' <span class="act shadow">(tool calls)</span>'
        msgs = ("not read" if any(m in r.tiers_dropped for m in NO_CONTENT_READ)
                else f"{_count_cell(r.messages_scanned)}/{_count_cell(r.messages_total)}")
        n = weight(r)
        if n > 1 or r.tally:
            # A tally row: clean allows counted since the intake's last flush.
            shadow += (f' <span style="color:var(--text-dim);font-size:10px">'
                       f'{n:,} allow{"" if n == 1 else "s"}</span>')
        dets = _finding_pills(r.findings) + _sealed_commands(r.findings)
        ts = escape((r.observed_at or "").replace("T", " ").rstrip("Z"))
        # For a post-hoc scan, when the session actually happened is the more
        # useful fact; observed_at is just when the job last ran.
        if r.session_updated_at and r.session_updated_at != r.observed_at:
            ts += (
                '<br><span style="color:var(--text-dim);font-size:10px">session '
                + escape(r.session_updated_at[:16].replace("T", " "))
                + "</span>"
            )
        raw = r.request_id or r.session_id or r.reference_id or ""
        shown = id_screen(raw) if id_screen is not None else raw
        corr = escape(_correlation(shown))
        if raw and shown == raw and RECORD_ID.fullmatch(raw):
            # A screened id is not linked: the link would carry it.
            corr = (f'<a href="{_href("/events/detail", {**_state(window, selected), "id": raw})}"'
                    f' title="Open this record">{corr}</a>')
        if exclude_form is not None and r.request_id and r.findings and shown == raw:
            corr += exclude_form(r.request_id)
        rows.append(
            f'<tr><td class="ts">{ts}</td>'
            f"<td><code>{escape(_source_label(r.source))}</code></td>"
            f"<td><code>{escape(r.surface or '-')}</code>"
            f"{_writer_cell(r, deny_form, events_href)}</td>"
            f'<td class="num">{_bytes_cell(r.body_bytes)}</td>'
            f'<td class="num">{msgs}</td>'
            f'<td class="num">{_count_cell(r.scan_ms)}</td>'
            f'<td><span class="act {cls}">{escape(act)}</span>{shadow}</td>'
            f"<td>{dets}</td>"
            f'<td><code style="font-size:11px">{corr}</code></td>'
            "</tr>"
        )
    table = (
        '<table class="log"><thead><tr><th>Time (UTC)</th><th>Control</th>'
        "<th>Surface</th><th class='num'>Bytes</th><th class='num'>Msgs</th>"
        "<th class='num'>Scan ms</th><th>Verdict</th><th>Detectors</th><th>Record</th>"
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
    ) if rows else ('<div class="empty-log">No events in this window.</div>' if not older
                    else '<div class="empty-log">No events found on this page.</div>')

    # The verdict filter has to describe both kinds of control: an inline
    # control denies, a post-hoc scan detects. 'Would deny only' is wrong
    # for the latter and reads as if it had a choice.
    verdict_label = {
        "compliance_scan": "With findings only",
        "otel_collect": "With findings only",
        "inference_hook": "Would deny only",
        "code_hook": "Would deny only",
    }.get(source, "Denied or detected")

    paging = []
    if paged:
        paging.append(f'<a href="{events_href()}">Newest</a>')
    if older:
        paging.append(f'<a href="{events_href(before=older)}">Older events &rarr;</a>'
                      + (f'<span class="note"> this page reads back to '
                         f"{escape(older_label)}</span>" if older_label else ""))
    nav = f'<div class="filters">{"".join(paging)}</div>' if paging else ""
    if any(not r.is_inline for r in records[:limit]):
        nav = ('<p class="note">A session scanned more than once has a row for each scan '
               "here and counts once on the summary pages.</p>" + nav)
    if approximate:
        nav = (f'<p class="note">{escape(approximate)} holds more records than one page '
               f"reads, so the order within {escape(approximate)} is approximate on this "
               "page.</p>" + nav)
    allows = (f'<a href="{events_href(code_hook_allows=None)}">Hide Code hook allows</a>'
              if show_allows else
              f'Code hook allows hidden &middot; <a href="{events_href(code_hook_allows="show")}">'
              "Show them</a>")
    hidden = "".join(
        f'<input type="hidden" name="{escape(k, quote=True)}" value="{escape(v, quote=True)}">'
        for k, v in state.items() if k not in ("device", "detector"))
    box = (
        '<form method="get" action="/events" class="filters">'
        f"{hidden}"
        '<input name="device" placeholder="device id" size="16" maxlength="13" '
        f'value="{escape(device, quote=True)}">'
        '<input name="detector" placeholder="detector name" size="32" '
        f'maxlength="128" value="{escape(detector, quote=True)}">'
        '<button type="submit">Filter</button></form>'
    )

    def chip(name, key, value, current):
        sel = " aria-current=true" if value == current else ""
        href = events_href(**{key: value})
        return f'<a href="{href}"{sel}>{escape(name)}</a>'

    def clear(key):
        value = KINDS.get(narrowed[key], narrowed[key]) if key == "kind" else narrowed[key]
        label = "Only" if key == "kind" else key.title()
        return (f'<a href="{events_href(**{key: None})}" aria-current=true>'
                f"{escape(label)}: {escape(value)} &times;</a>")

    controls = (
        '<div class="filters">'
        + chip("All controls", "source", "all", source)
        + chip("Inference hook", "source", "inference_hook", source)
        + chip("Code hook", "source", "code_hook", source)
        + chip("Compliance scan", "source", "compliance_scan", source)
        + chip("OTel", "source", "otel_collect", source)
        + chip("Agent check", "source", "agent_scan", source)
        + chip("Managed scan", "source", "managed_scan", source)
        + '</div><div class="filters">'
        + chip("All verdicts", "action", "all", action)
        + chip(verdict_label, "action", "deny", action)
        + "</div>"
        + ('<div class="filters">' + "".join(clear(k) for k in narrowed) + "</div>"
           if narrowed else "")
    )

    body = (
        '\n  <div class="hero">\n'
        "    <h1>Events</h1>\n"
        f'    <p class="note">{len(rows):,} events on this page, '
        "newest first. Select a record id to open it. Detector names and positions "
        f"only &mdash; the store holds no prompt content. {allows}</p>\n"
        f"    {controls}\n"
        f"    {box}\n"
        "  </div>\n"
        f'  <section><div class="card" style="overflow-x:auto">{table}</div>{nav}</section>\n'
    )
    return _chrome("events", "/events", generated_at, backend, body,
                   orgs, selected, viewer, banners, branding, window=window or "7d")


def _when(ts: str | None) -> str:
    return escape((ts or "").replace("T", " ").rstrip("Z")) or "&mdash;"


def _record_card(r, id_screen=None) -> str:
    """One record: what the control saw and decided, and every finding with
    its detector, position and value hash."""
    from ..core import DESCRIPTIONS

    def screened(value):
        if not value:
            return "&mdash;"
        shown = id_screen(value) if id_screen is not None else value
        return f"<code>{escape(shown)}</code>"

    shadow = (f" (shadow: decided {escape(r.shadow_action)})"
              if r.shadow_action and r.shadow_action != r.action else "")
    msgs = ("not read" if any(m in r.tiers_dropped for m in NO_CONTENT_READ)
            else f"{_count_cell(r.messages_scanned)} of {_count_cell(r.messages_total)}")
    facts = [
        ("Observed", _when(r.observed_at)),
        ("Session updated", _when(r.session_updated_at)) if r.session_updated_at else None,
        ("Control", escape(_source_label(r.source))),
        ("Surface", f"<code>{escape(r.surface or '-')}</code>"),
        ("Verdict", f'<span class="act">{escape(r.disposition)}</span>{shadow}'),
        ("Event", escape(r.event)) if r.event else None,
        ("Request id", screened(r.request_id)),
        ("Session id", screened(r.session_id)) if r.session_id else None,
        ("Reference id", screened(r.reference_id)) if r.reference_id else None,
        ("Client", escape(r.client)) if r.client else None,
        ("Device", escape(r.device)) if r.device else None,
        ("Model", escape(r.model)) if r.model else None,
        ("Request body", f"{_bytes_cell(r.body_bytes)} bytes") if r.body_bytes else None,
        ("Messages scanned", msgs),
        ("Scan time", f"{_count_cell(r.scan_ms)} ms") if r.scan_ms is not None else None,
        ("Round trip", f"{_count_cell(r.total_ms)} ms") if r.total_ms is not None else None,
        ("Session cache", "hit" if r.cache_hit else "miss") if r.cache_hit is not None
        else None,
        ("Coverage dropped", escape(", ".join(r.tiers_dropped))) if r.tiers_dropped else None,
        ("Deleted", _when(r.deleted_at)) if r.deleted_at else None,
        ("Build", f"<code>{escape(r.build)}</code>") if r.build else None,
    ]
    kv = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in filter(None, facts))
    if r.findings:
        rows = "".join(
            f"<tr><td><code>{escape(f.detector)}</code>"
            + (f'<span class="det-what">{escape(DESCRIPTIONS[f.detector])}</span>'
               if f.detector in DESCRIPTIONS else "")
            + f'</td><td><span class="pill {"block" if f.severity == "block" else "warn"}">'
            f"{escape(f.severity)}</span></td>"
            f"<td><code>{escape(f.locator)}</code>"
            + (f'<span class="det-what">tool {escape(f.tool_name)}</span>'
               if f.tool_name else "")
            + f'</td><td class="mono" title="{escape(f.excerpt_hash, quote=True)}">'
            f"{escape(f.excerpt_hash[:12])}</td>"
            f"<td>{_sealed_commands([f]) or '&mdash;'}</td></tr>"
            for f in r.findings)
        findings = ("<table><thead><tr><th>Detector</th><th>Severity</th><th>Position</th>"
                    "<th>Value hash</th><th>Sealed value</th></tr></thead>"
                    f"<tbody>{rows}</tbody></table>")
    else:
        findings = '<p class="status status-ok">No findings</p>'
    return (f'<div class="card-grid wide-first" style="margin-top:16px">'
            f'<div class="card"><h2>Findings</h2>{findings}</div>'
            f'<div class="card"><h2>Record</h2><dl class="kv">{kv}</dl></div></div>')


def render_event_detail(records, record_id: str, window: str = "7d",
                        store_desc: dict | None = None, generated_at: str = "",
                        orgs: dict[str, str] | None = None, selected: str = "",
                        viewer: str = "", banners: str = "", id_screen=None,
                        branding: Branding | None = None, more: bool = False,
                        read_to: str = "") -> str:
    """Every record carrying `record_id` as its request, session or
    reference id in the window, newest first: one request as each control
    saw it. `more` says there are more than `records`; `read_to` is where
    the read stopped when it did not reach the start of the window."""
    backend = str((store_desc or {}).get("backend", "—"))
    back = _href("/events", _state(window, selected))
    shown = id_screen(record_id) if id_screen is not None else record_id
    if records:
        cards = "".join(
            (f'<section><h2>{escape(_source_label(r.source))} &middot; '
             f"{_when(r.observed_at)}</h2>{_record_card(r, id_screen)}</section>")
            for r in records)
        count = (f"The newest {len(records)} records carrying this id are shown; there are "
                 "more." if more else f"{len(records)} record(s) carry this id in this window.")
        lede = (f"{count} A matched value is never stored; a sealed one opens only with "
                "<code>forgd-verdict unseal</code> under your own cloud login.")
    else:
        cards = ('<section><div class="card"><div class="empty-log">No record with this id '
                 "in this window. Try a longer window.</div></div></section>")
        lede = ""
    if read_to and not more:
        lede += (f" This page read back to {escape(read_to)}; an older record in the window "
                 "may also carry this id.")
    body = (
        '\n  <div class="hero">\n'
        f'    <div class="crumbs"><a href="{back}">Events</a> &rsaquo; record</div>\n'
        f"    <h1><code style=\"font-size:22px\">{escape(_correlation(shown))}</code></h1>\n"
        f'    <p class="lede">{lede}</p>\n'
        "  </div>\n" + cards)
    return _chrome("event", "/events", generated_at, backend, body,
                   orgs, selected, viewer, banners, branding, window=window)



def _writer_cell(r, deny=None, href=None) -> str:
    """The intake client and device under a row's surface, each a link
    that filters the log to it, and for an admin a form denying the
    device. `href(**changes)` builds a link's escaped href from the
    current view; without it a link carries only its own filter. Empty
    for records no intake wrote. A record still in a multi-org fleet's
    partition is marked org pending."""
    parts = []
    if writer_class(getattr(r, "source", None)) == WRITER_INTAKE_TOKEN:
        parts.append('<span title="shipped with an intake token, which anyone holding '
                     'it can do">via token</span>')
    for key in ("client", "device"):
        value = getattr(r, key, None)
        if not value:
            continue
        if key == "device" and not DEVICE_ID.fullmatch(value):
            parts.append(escape(value))
            continue
        link = (href(**{key: value}) if href
                else escape("/events?" + urlencode({key: value}), quote=True))
        parts.append(f'<a href="{link}">{escape(value)}</a>')
    device = getattr(r, "device", None)
    if deny is not None and device and DEVICE_ID.fullmatch(device):
        parts[-1] += deny(device)
    if is_fleet_partition(getattr(r, "tenant_hash", None)):
        parts.append('<span title="no OTel export has attributed this session to one '
                     'of the fleet\'s orgs yet">org pending</span>')
    if not parts:
        return ""
    return ('<br><span style="color:var(--text-dim);font-size:10px">'
            + " &middot; ".join(parts) + "</span>")


def _highlight(line: str) -> str:
    """Comment, key and value, coloured. Deliberately not a YAML parser --
    this renders text the operator already recognises, and a parser would
    reformat it into something they might not."""
    stripped = line.lstrip()
    indent = line[: len(line) - len(stripped)]
    if stripped.startswith("#"):
        return f'{indent}<span class="c">{escape(stripped)}</span>'
    if ":" in stripped and not stripped.startswith("- "):
        key, _, rest = stripped.partition(":")
        value = f'<span class="v">{escape(rest)}</span>' if rest.strip() else escape(rest)
        return f'{indent}<span class="k">{escape(key)}</span>:{value}'
    return indent + escape(stripped)


def render_policy(policy_yaml: str, source: str, detectors: list[str],
                  store_desc: dict | None = None, generated_at: str = "",
                  orgs: dict[str, str] | None = None, selected: str = "",
                  viewer: str = "", banners: str = "", panel: str = "",
                  branding: Branding | None = None) -> str:
    """The effective policy, as the process rendering this page resolved it.

    YAML rather than a table of controls: it is the same text an operator
    edits, so there is nothing to translate and no risk of the page and the
    file disagreeing about what a setting is called.
    """
    backend = str((store_desc or {}).get("backend", "\u2014"))
    # Built before the f-string: a backslash inside an f-string expression
    # is a syntax error until 3.12 and this project supports 3.11.
    highlighted = "\n".join(_highlight(ln) for ln in policy_yaml.splitlines())
    body = f"""
  <div class="hero">
    <div class="eyebrow">Configuration</div>
    <h1>Policy</h1>
  </div>
{panel}
  <section>
    <div class="eyebrow">Effective</div>
    <h2>{escape(source)}</h2>
    <p class="status status-ok">Detectors built:
    {escape(", ".join(detectors)) or "none"}</p>
    <div class="card" style="overflow-x:auto"><pre class="yaml">{highlighted}</pre></div>
  </section>
"""
    return _chrome("policy", "/policy", generated_at, backend, body,
                   orgs, selected, viewer, banners, branding)
