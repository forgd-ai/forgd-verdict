# Vendored webfonts

Inter and Roboto Mono, latin subset, variable weight, woff2. 80 KB total.

They are here rather than on a CDN because `render.py` says the
dashboard makes no external requests and the CSP is `default-src
'none'`. An `@import` from `fonts.googleapis.com` would need the CSP
widened to permit it.

A security tool should not fetch from a third party on every dashboard
load, and on an egress-filtered network such an import fails silently,
so the page renders differently there.

Both families are SIL Open Font License 1.1; the licences are beside
them. Redistribution inside this package is what the OFL is for, and the
files are unmodified subsets as served by Google Fonts.

To refresh, take the `latin` block only from:

    https://fonts.googleapis.com/css2?family=Inter:wght@300..900&family=Roboto+Mono:wght@400..500&display=swap

The other twelve unicode-range subsets (cyrillic, greek, vietnamese and
the rest) are not shipped. The dashboard's own text is
English, and a finding's content is never rendered.
