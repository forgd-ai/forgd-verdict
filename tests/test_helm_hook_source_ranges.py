"""`ingress.hook.sourceRanges`: an optional source allowlist on /hook alone."""

from __future__ import annotations

import pytest
import test_helm_gke as gke_mode
from test_helm_chart import by_kind, render, requires_helm

pytestmark = requires_helm

FULL = "rel-forgd-verdict"
RANGE = ("--set", "ingress.hook.sourceRanges={192.0.2.0/24}")
ALLOW = "nginx.ingress.kubernetes.io/whitelist-source-range"


def _paths(ingress) -> list[tuple[str, str]]:
    return [(p["path"], p["backend"]["service"]["name"])
            for r in ingress["spec"]["rules"] for p in r["http"]["paths"]]


@pytest.fixture(scope="module")
def ranged():
    return by_kind(render(*RANGE), "Ingress")


def test_off_by_default_hook_stays_on_the_public_object():
    ingresses = by_kind(render(), "Ingress")
    assert f"{FULL}-hook" not in ingresses
    assert ("/hook", f"{FULL}-verdict") in _paths(ingresses[f"{FULL}-public"])
    assert not [n for n, i in ingresses.items() if ALLOW in i["metadata"].get("annotations", {})]


def test_set_hook_moves_to_its_own_object_with_the_allowlist(ranged):
    hook = ranged[f"{FULL}-hook"]
    ann = hook["metadata"]["annotations"]
    assert ann[ALLOW] == "192.0.2.0/24"
    assert ann["nginx.ingress.kubernetes.io/enable-global-auth"] == "false"
    assert ann["nginx.ingress.kubernetes.io/enable-modsecurity"] == "false"
    assert ann["nginx.ingress.kubernetes.io/proxy-body-size"] == "64m"
    assert {p for p, _ in _paths(hook)} == {"/hook"}
    assert "tls" not in hook["spec"]


def test_set_no_other_object_routes_hook_or_carries_the_allowlist(ranged):
    for name, ing in ranged.items():
        if name == f"{FULL}-hook":
            continue
        assert "/hook" not in {p for p, _ in _paths(ing)}, name
        assert ALLOW not in ing["metadata"].get("annotations", {}), name
    assert ("/v1", f"{FULL}-collector") in _paths(ranged[f"{FULL}-public"])


def test_the_public_annotations_reach_the_hook_object():
    docs = render(*RANGE, "--set-string",
                  "ingress.annotations.nginx\\.ingress\\.kubernetes\\.io/proxy-read-timeout=30")
    ann = by_kind(docs, "Ingress")[f"{FULL}-hook"]["metadata"]["annotations"]
    assert ann["nginx.ingress.kubernetes.io/proxy-read-timeout"] == "30"


def test_gke_mode_refuses_it():
    assert "ingress.hook.sourceRanges does not apply with ingress.className gce" in \
        gke_mode.render_error(*gke_mode.GKE_MODE, *RANGE)
