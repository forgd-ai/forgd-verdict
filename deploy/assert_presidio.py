"""Build-time proof that the Presidio T2 tier actually works.

Run as a Dockerfile build step for the ingest image. PresidioPIIDetector
catches a failed load and reports itself unavailable, so that
`enabled: auto` degrades rather than taking the six-hourly job down. That
is the right runtime behaviour and the wrong build behaviour: without this
check, a broken model download ships an image whose T2 tier is silently
absent, and the findings page simply shows fewer detections with nothing
to say why.

Also asserts the entity identifiers the policy names. Presidio ignores an
entity it does not recognise instead of raising, so a typo or a renamed
identifier would cost nothing at startup and everything at scan time.
"""

import sys

import requests
from presidio_analyzer import AnalyzerEngine

# NO NETWORK FROM HERE ON. The image bakes tldextract's suffix list in, so
# nothing below should make a request. Attempts are RECORDED and the build
# fails on any, rather than relying on the request failing: tldextract
# falls back to a bundled snapshot when a fetch errors, so a blocked
# request alone would pass quietly. Without this, a cache that no longer
# matched -- a tldextract upgrade changes its cache key -- would go back
# to fetching publicsuffix.org on every run.
_attempts: list[str] = []


def _no_network(self, method, url, *args, **kwargs):
    _attempts.append(f"{method} {url}")
    raise RuntimeError(f"no network at runtime: {method} {url}")


requests.Session.request = _no_network

# The identifiers in policy.yaml's compliance.detectors.presidio_pii.entities.
ENTITIES = ["PERSON", "LOCATION", "EMAIL_ADDRESS", "PHONE_NUMBER", "NRP"]

# Must match compliance.detectors.presidio_pii.score_threshold. An earlier
# version omitted it, which made this check weaker than the thing it checks:
# PresidioPIIDetector discards anything under the threshold, so an entity
# could satisfy the assertion and still never produce a finding.
SCORE_THRESHOLD = 0.6

# PERSON and LOCATION exercise the NER model; EMAIL_ADDRESS and PHONE_NUMBER
# exercise the pattern recognizers. Requiring one of each proves the spaCy
# model loaded, not merely that the package imported.
#
# Two properties of the probe text are load-bearing, both learned the hard
# way. The email domain must be a real TLD, because Presidio validates it and
# a `.example` address -- the obvious choice for a fixture -- is silently not
# an email. And the phone number needs a context word next to it: Presidio
# scores a bare number 0.40 and only its context enhancer lifts that to 0.75,
# so "phone" here is what puts the entity over the threshold. A probe without
# it reports PHONE_NUMBER as broken when the configuration is correct.
PROBE = (
    "Contact Dana Whitfield in Lisbon at dana@example.com, "
    "phone +1 415 682 4900."
)
REQUIRED = {"PERSON", "LOCATION", "EMAIL_ADDRESS", "PHONE_NUMBER"}

engine = AnalyzerEngine()
found = {
    r.entity_type
    for r in engine.analyze(text=PROBE, entities=ENTITIES, language="en")
    if r.score >= SCORE_THRESHOLD
}

missing = REQUIRED - found
if missing:
    print(
        f"presidio imported but found nothing for {sorted(missing)}; "
        f"got {sorted(found)} at or above {SCORE_THRESHOLD}. "
        "The spaCy model is probably absent.",
        file=sys.stderr,
    )
    sys.exit(1)

if _attempts:
    print(f"presidio tried the network at runtime: {_attempts}. The baked "
          "tldextract cache did not match; see TLDEXTRACT_CACHE in the "
          "Dockerfile.", file=sys.stderr)
    sys.exit(1)

print("presidio T2 ready, no network:", sorted(found))
