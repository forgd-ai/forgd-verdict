"""Scoping a viewer to a subset of the customer's orgs.

Multi-org here is ONE customer with several organizations, so this is an
internal segregation control they turn on, not a boundary that must exist
before anyone is onboarded. That decides the default, and the default is
the thing most likely to be got wrong in either direction:

  * fail-closed would lock out every deployment that has not set a map
  * fail-open once a map IS configured would silently entitle everyone

Both are pinned below.
"""

from __future__ import annotations

import pytest
from conftest import ASGIClient

from forgd_verdict.dashboard.app import Dashboard, ViewScope
from forgd_verdict.dashboard.auth import AuthConfig
from forgd_verdict.entitlements import (
    MODE_NONE,
    MODE_OIDC_JWT,
    MODE_TRUSTED_HEADER,
    Entitlements,
    Forbidden,
    Principal,
)
from forgd_verdict.policy import Policy
from forgd_verdict.store.base import VerdictRecord, pseudonym
from forgd_verdict.store.local import LocalFileStore

SALT = "s"
A = pseudonym("org-a", SALT, "org")
B = pseudonym("org-b", SALT, "org")


def policy_with_map(entries, mode=MODE_OIDC_JWT):
    auth = {"mode": mode}
    if mode == MODE_OIDC_JWT:
        auth.update({"jwks_url": "https://x/keys", "issuer": "https://x",
                     "audience": "aud"})
    return Policy(raw={
        "privacy": {"hash_salt": SALT},
        "dashboard": {"auth": auth, "entitlements": {"map": entries}},
    })


# --- resolution ----------------------------------------------------------


def test_no_map_configured_means_no_restriction():
    """One customer is entitled to all of their own orgs, so fail-closed
    here would lock out every deployment without a map to protect against
    a risk they do not have."""
    ent = Policy(raw={"dashboard": {}}).entitlements()
    assert ent.enabled is False
    assert ent.allowed(Principal("someone")) is None
    assert ent.allowed(None) is None


def test_a_configured_map_resolves_org_ids_to_pseudonyms():
    """Config names orgs by id because that is what an operator knows; the
    store holds pseudonyms."""
    ent = policy_with_map([{"group": "g-eu", "orgs": ["org-a"]}]).entitlements()
    assert ent.enabled is True
    assert ent.allowed(Principal("dana", ("g-eu",))) == frozenset({A})


def test_a_viewer_matching_no_group_gets_nothing_not_everything():
    """Once an operator has configured the map, an unmatched viewer is
    someone they did not list."""
    ent = policy_with_map([{"group": "g-eu", "orgs": ["org-a"]}]).entitlements()
    assert ent.allowed(Principal("stranger", ("g-other",))) == frozenset()
    assert ent.allowed(Principal("no-groups")) == frozenset()


def test_membership_of_several_groups_unions_their_orgs():
    ent = policy_with_map([
        {"group": "g-eu", "orgs": ["org-a"]},
        {"group": "g-us", "orgs": ["org-b"]},
    ]).entitlements()
    assert ent.allowed(Principal("dana", ("g-eu", "g-us"))) == frozenset({A, B})


@pytest.mark.parametrize("mode", [MODE_NONE, MODE_TRUSTED_HEADER])
def test_entitlements_are_refused_under_an_unverified_auth_mode(mode):
    """A group membership we cannot verify is one the caller can choose.

    Refused at load time: serving a control that looks enforced and is not
    is worse than having no control.
    """
    with pytest.raises(ValueError, match="oidc_jwt"):
        policy_with_map([{"group": "g", "orgs": ["org-a"]}], mode=mode).entitlements()


def test_check_raises_only_for_an_org_outside_the_allowance():
    ent = policy_with_map([{"group": "g-eu", "orgs": ["org-a"]}]).entitlements()
    dana = Principal("dana", ("g-eu",))
    ent.check(dana, A)                      # allowed
    ent.check(dana, None)                   # nothing asked for
    with pytest.raises(Forbidden):
        ent.check(dana, B)
    # Unrestricted callers are never refused.
    Entitlements().check(Principal("x"), B)


# --- enforcement on the routes -------------------------------------------


def make_dashboard(tmp_path, entitlements, principal):
    """A dashboard whose auth returns a fixed principal, so the routes can
    be exercised without minting tokens (that is test_dashboard_auth's job)."""
    store = LocalFileStore(tmp_path, instance="t")
    store.write_verdicts([
        VerdictRecord(source="otel_collect", session_id="a1", tenant_hash=A,
                      surface="surface-alpha"),
        VerdictRecord(source="otel_collect", session_id="b1", tenant_hash=B,
                      surface="surface-bravo"),
    ])

    class FixedAuth(AuthConfig):
        def authenticate(self, headers):
            return principal

    return Dashboard(store, auth=FixedAuth(mode=MODE_TRUSTED_HEADER),
                     entitlements=entitlements)


ROUTES = ["/", "/events", "/api/summary"]


@pytest.mark.parametrize("route", ROUTES)
async def test_a_restricted_viewer_never_sees_another_orgs_records(tmp_path, route):
    """Enforcement is on every route that reads records, not on the
    selector. A dropdown that narrows a view is not a control."""
    ent = policy_with_map([{"group": "g-eu", "orgs": ["org-a"]}]).entitlements()
    dash = make_dashboard(tmp_path, ent, Principal("dana", ("g-eu",)))
    status, body = await ASGIClient(dash).get(route)
    assert status == 200
    blob = body if isinstance(body, str) else str(body)
    # Surfaces show on the overview, session ids on the event log; the
    # JSON summary carries counts. Whichever it is, org B must be absent.
    assert "surface-bravo" not in blob
    assert "b1" not in blob
    if route == "/api/summary":
        assert body["total_requests"] == 1


@pytest.mark.parametrize("route", ROUTES)
async def test_asking_for_an_unentitled_org_is_403_not_an_empty_page(tmp_path, route):
    """An empty page is indistinguishable from a clean week, which is the
    wrong thing to show someone who asked for an org they cannot see."""
    ent = policy_with_map([{"group": "g-eu", "orgs": ["org-a"]}]).entitlements()
    dash = make_dashboard(tmp_path, ent, Principal("dana", ("g-eu",)))
    status, body = await ASGIClient(dash).get(f"{route}?org={B}")
    assert status == 403
    assert body == {"error": "forbidden"}


@pytest.mark.parametrize("route", ROUTES)
async def test_with_no_map_every_viewer_sees_every_org(tmp_path, route):
    dash = make_dashboard(tmp_path, Entitlements(), Principal("anyone"))
    status, body = await ASGIClient(dash).get(route)
    assert status == 200
    if route == "/api/summary":
        assert body["total_requests"] == 2
    else:
        blob = body if isinstance(body, str) else str(body)
        assert "surface-alpha" in blob or "a1" in blob
        assert "surface-bravo" in blob or "b1" in blob


async def test_the_page_cache_does_not_leak_across_the_boundary(tmp_path):
    """The cache was keyed on the window alone. An unrestricted viewer
    warming it would then have served a restricted viewer the full page --
    a cache that leaks across an authorization boundary, which is worse
    than no cache.
    """
    ent = policy_with_map([{"group": "g-eu", "orgs": ["org-a"]}]).entitlements()

    store = LocalFileStore(tmp_path, instance="t")
    store.write_verdicts([
        VerdictRecord(source="otel_collect", tenant_hash=A, surface="surface-alpha"),
        VerdictRecord(source="otel_collect", tenant_hash=B, surface="surface-bravo"),
    ])

    unrestricted = Dashboard(store, entitlements=Entitlements())
    wide = unrestricted._page("7d", ViewScope(None, None, "all"))
    assert "surface-alpha" in wide and "surface-bravo" in wide

    # Same instance, same window, a viewer who may only see org A. Served
    # from the cache before the key carried the scope.
    narrow = unrestricted._page("7d", ViewScope(frozenset({A}), frozenset({A}), A))
    assert "surface-alpha" in narrow
    assert "surface-bravo" not in narrow
    assert ent.enabled


async def test_healthz_stays_reachable_without_an_identity(tmp_path):
    ent = policy_with_map([{"group": "g-eu", "orgs": ["org-a"]}]).entitlements()
    dash = make_dashboard(tmp_path, ent, Principal("dana", ("g-eu",)))
    status, body = await ASGIClient(dash).get("/healthz")
    assert status == 200 and body["status"] == "ok"


# --- the selector --------------------------------------------------------


def dash_with_labels(tmp_path, labels, entitlements=None, principal=None):
    store = LocalFileStore(tmp_path, instance="t")
    store.write_verdicts([
        VerdictRecord(source="otel_collect", tenant_hash=A, surface="surface-alpha"),
        VerdictRecord(source="otel_collect", tenant_hash=B, surface="surface-bravo"),
    ])

    class FixedAuth(AuthConfig):
        def authenticate(self, headers):
            return principal

    return Dashboard(store, auth=FixedAuth(mode=MODE_TRUSTED_HEADER),
                     entitlements=entitlements or Entitlements(),
                     org_labels=labels)


async def test_one_org_shows_no_picker(tmp_path):
    """A dropdown with a single entry is furniture. Most deployments serve
    one customer with one org."""
    dash = dash_with_labels(tmp_path, {A: "Prod EU"}, principal=Principal("x"))
    _, body = await ASGIClient(dash).get("/")
    assert 'class="orgs"' not in body


async def test_several_orgs_show_a_picker_with_their_labels(tmp_path):
    dash = dash_with_labels(tmp_path, {A: "Prod EU", B: "Sandbox"},
                            principal=Principal("x"))
    _, body = await ASGIClient(dash).get("/")
    assert 'class="orgs"' in body
    assert "Prod EU" in body and "Sandbox" in body
    assert "All orgs" in body


async def test_the_picker_lists_only_orgs_the_viewer_may_read(tmp_path):
    """Built from the entitlement scope, not from the data. Otherwise the
    picker advertises an org that 403s when clicked -- and tells the viewer
    that org exists, which is the thing being withheld."""
    c = pseudonym("org-c", SALT, "org")
    ent = policy_with_map(
        [{"group": "g-eu", "orgs": ["org-a", "org-b"]}]
    ).entitlements()
    dash = dash_with_labels(tmp_path, {A: "Prod EU", B: "Sandbox", c: "Secret Project"},
                            entitlements=ent,
                            principal=Principal("dana", ("g-eu",)))
    _, body = await ASGIClient(dash).get("/")
    assert "Prod EU" in body and "Sandbox" in body
    assert "Secret Project" not in body
    assert c not in body


async def test_a_viewer_entitled_to_one_org_gets_no_picker(tmp_path):
    """Nothing to choose between, and a picker would only advertise that
    other orgs exist."""
    ent = policy_with_map([{"group": "g-eu", "orgs": ["org-a"]}]).entitlements()
    dash = dash_with_labels(tmp_path, {A: "Prod EU", B: "Sandbox"},
                            entitlements=ent,
                            principal=Principal("dana", ("g-eu",)))
    _, body = await ASGIClient(dash).get("/")
    assert 'class="orgs"' not in body
    # A bare substring check against the whole page, so the label has to be
    # a string that cannot occur in markup. "Dev" was, and SVG's
    # `stdDeviation` started matching it.
    assert "Sandbox" not in body


async def test_an_unlabelled_org_is_not_offered(tmp_path):
    """An unlabelled pseudonym is not something a human can choose
    between."""
    dash = dash_with_labels(tmp_path, {A: "Prod EU"}, principal=Principal("x"))
    _, body = await ASGIClient(dash).get("/")
    assert B not in body


async def test_the_picker_appears_on_every_page(tmp_path):
    dash = dash_with_labels(tmp_path, {A: "Prod EU", B: "Sandbox"},
                            principal=Principal("x"))
    for route in ("/", "/events", "/policy"):
        _, body = await ASGIClient(dash).get(route)
        assert 'class="orgs"' in body, route


async def test_selecting_an_org_marks_it_current_and_narrows_the_page(tmp_path):
    dash = dash_with_labels(tmp_path, {A: "Prod EU", B: "Sandbox"},
                            principal=Principal("x"))
    _, body = await ASGIClient(dash).get(f"/?org={A}")
    assert f'?org={A}" aria-current=true' in body
    assert "surface-alpha" in body
    assert "surface-bravo" not in body


# --- IAP -------------------------------------------------------------------


@pytest.mark.parametrize("platform", ["iap", "$FORGD_TEST_PLATFORM"])
def test_a_map_under_iap_refuses_to_start(platform, monkeypatch):
    """The map matches groups only, and an IAP token carries none."""
    monkeypatch.setenv("FORGD_TEST_PLATFORM", "iap")
    p = policy_with_map([{"group": "g1", "orgs": ["org-a"]}])
    p.raw["dashboard"]["auth"]["platform"] = platform
    with pytest.raises(ValueError, match=r"entitlements\.map.*platform is iap"):
        p.entitlements()


def test_iap_without_a_map_starts():
    p = Policy(raw={"dashboard": {"auth": {"mode": MODE_OIDC_JWT, "platform": "iap"}}})
    assert p.entitlements().enabled is False


def test_a_map_under_another_platform_still_loads():
    p = policy_with_map([{"group": "g1", "orgs": ["org-a"]}])
    p.raw["dashboard"]["auth"]["platform"] = "oauth2_proxy"
    assert p.entitlements().enabled
