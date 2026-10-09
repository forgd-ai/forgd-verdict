"""Adapter 2's receiving end: a write-only findings intake.

A laptop running the Claude Code hook that ships with
FORGD_VERDICT_SHIP_STORE needs data-plane WRITE access to the findings
container, because that is a blob URL and hook/ship.py writes to it
directly. Storage Blob Data Contributor includes DELETE, so such a developer
machine can not merely add findings but alter or remove them -- in a tool
whose output is evidence. One compromised laptop is enough, and the
credential is as durable as their Azure session.

A bearer token can only append. A fleet's token is shared by its laptops,
each of which names its device, and one device is denied through the
runtime overrides without touching the rest.

SEPARATE FROM THE VERDICT SERVER AND THE DASHBOARD, on purpose:

  * the verdict server must never grow a second auth scheme -- it
    authenticates Anthropic by signature, and a service with two ways in
    has two ways to get wrong;
  * the dashboard must stay read-only, so the one thing humans sign into
    holds no write credential.

WRITE-ONLY. There is no read path at all, so a stolen token cannot be used
to enumerate findings -- only to add them, which is the smallest useful
capability for the job.
"""

from __future__ import annotations

ROLE = "intake"
# NOT under /v1. The collector's ingress rule is `/v1` as a PREFIX, so
# /v1/findings would be matched by it and routed to the collector -- which
# would answer 404 for a path it does not serve, and a hook shipping there
# would park every batch forever against an endpoint that exists.
#
# Longest-prefix matching would in fact pick the more specific rule, but
# that is a property of the ingress controller rather than of this service.
# A path that cannot collide does not depend on it.
PATH_INTAKE = "/intake"
# The scan route. Adapter 2 posts a Claude Code hook payload and gets a
# verdict back, so the laptop runs no detectors and installs no gitleaks.
#
# ITS OWN ROUTE, so it can have its own credential. The verdict server's
# /hook authenticates Anthropic by signature, and that signing secret must
# never reach a laptop -- which is why adapter 2 cannot simply call it.
# Here the caller is a developer machine holding its fleet's bearer, or an
# agent holding its own, and a denied device is refused.
#
# Still no read path: this scans what it is given. A stolen token buys a
# scan, not the findings of anyone else.
PATH_SCAN = "/scan"
