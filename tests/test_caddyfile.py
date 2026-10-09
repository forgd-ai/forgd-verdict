"""deploy/Caddyfile and the chart's diagnostics ingress take one position on
the diagnostic paths.

/healthz is public: scripts/verify_deployment.sh reads it from outside to
tell the new revision from the old, and it carries no findings. /metrics is
token-gated by the app and answers 404 without a token, so publishing the
path is acceptable; a proxy may still keep it off the public listener.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CADDYFILE = ROOT / "deploy" / "Caddyfile"
INGRESS = ROOT / "deploy" / "helm" / "forgd-verdict" / "templates" / "ingress.yaml"


def _public_site() -> str:
    text = CADDYFILE.read_text(encoding="utf-8")
    start = text.index("verdict.example.com {")
    return text[start:text.index("\n}\n", start)]


def _blocked(site: str) -> set[str]:
    out: set[str] = set()
    for name, paths in re.findall(r"^\s*@(\w+) path ([^\n]+)$", site, re.M):
        if re.search(rf"^\s*respond @{name} 404\s*$", site, re.M):
            out |= set(paths.split())
    return out


def test_the_public_site_serves_healthz():
    assert "/healthz" not in _blocked(_public_site())


def test_the_public_site_keeps_metrics_off_it():
    assert "/metrics" in _blocked(_public_site())


def test_both_files_state_the_same_position():
    caddy = " ".join(CADDYFILE.read_text(encoding="utf-8").split())
    chart = " ".join(INGRESS.read_text(encoding="utf-8").split())
    assert "should not be reachable from the internet" not in caddy
    for text in (caddy, chart):
        assert "verify_deployment.sh" in text
        assert "404 without" in text
