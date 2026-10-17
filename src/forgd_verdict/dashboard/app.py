"""Dashboard ASGI app.

Reads the findings store and nothing else. It holds no Compliance Access Key
and no webhook signing secret -- that separation is the reason ingest and
presentation are different services. The worst a compromise of this app
yields is the findings themselves, which carry no prompt content.

Authentication is delegated to the platform. On Container Apps, enable the
built-in Entra provider and the app receives X-MS-CLIENT-PRINCIPAL-NAME on
every request; there is no login code here and no session to steal. Run it
behind something that authenticates, or on a trusted network -- it does not
authenticate on its own, and says so at startup.

NEVER enable platform auth on the verdict server. Anthropic authenticates
with a webhook signature, and an auth redirect would turn every governed
prompt into a webhook failure.
"""

from __future__ import annotations

import asyncio
import json
import logging
import mimetypes
import os
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, NamedTuple

from .. import build_id
from ..applog import exc_fields
from ..entitlements import (
    MODE_NONE,
    MODE_OIDC_JWT,
    MODE_TRUSTED_HEADER,
    Entitlements,
    Forbidden,
    GroupsUnavailable,
)
from ..intake.verify import DEVICE_ID
from ..overrides_signing import ENV_SIGNING_KEY, from_policy
from ..plugins import describe_for_log, loaded_distributions
from ..policy import INTAKE_CLIENT_NAME, policy_error
from ..store.attribution import Fleets, attributed, policy_fleets, warn_unresolved_fleets
from ..store.base import visible
from ..store.query import effective_since
from ..store.views import (
    EVENT_ACTIONS,
    EVENT_SOURCES,
    WINDOWS,
    EventCursor,
    event_page,
    excluded_requests,
    read_summary,
    summary_payload,
    window_to_since,
)
from . import controls, render
from .admin import MAX_BODY_BYTES, PATH_ACTIONS, AdminConfig, TokenRefused
from .auth import AuthConfig, AuthError, refuse_require_principal
from .branding import Branding

ASSETS = Path(__file__).with_name("assets")
CACHE_TTL_S = 20.0
# Bounds on the render cache. Its keys carry caller-chosen values (the org,
# the viewer's name), so every distinct value is a new entry.
CACHE_MAX_ENTRIES = 128
CACHE_MAX_BYTES = 8 * 1024 * 1024
# Threads token verification runs on under oidc_jwt, so a key fetch never
# runs on the event loop.
AUTH_WORKERS = 8

log = logging.getLogger("forgd_verdict.dashboard")
# The shape of an Origin header: scheme, host and optional port.
_ORIGIN = re.compile(r"https?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?")

ORG_PSEUDONYM = re.compile(r"(org|workspace)_[0-9a-f]{10}")
PARTITION_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}")


class RenderCache:
    """Rendered pages and summary payloads, least recently used first out.

    Bounded by `CACHE_MAX_ENTRIES` and `CACHE_MAX_BYTES`, read on every
    insert, and by `CACHE_TTL_S` on every read. A value larger than the byte
    bound is not kept.
    """

    def __init__(self) -> None:
        self._entries: OrderedDict[Hashable, tuple[float, Any, int]] = OrderedDict()
        self._lock = threading.Lock()
        self.bytes = 0

    def get(self, key: Hashable, now: float) -> Any | None:
        with self._lock:
            hit = self._entries.get(key)
            if hit is None:
                return None
            if now - hit[0] >= CACHE_TTL_S:
                self._drop(key)
                return None
            self._entries.move_to_end(key)
            return hit[1]

    def put(self, key: Hashable, now: float, value: Any) -> None:
        size = _cached_size(value)
        with self._lock:
            if key in self._entries:
                self._drop(key)
            if size > CACHE_MAX_BYTES:
                return
            self._entries[key] = (now, value, size)
            self.bytes += size
            while self._entries and (len(self._entries) > CACHE_MAX_ENTRIES
                                     or self.bytes > CACHE_MAX_BYTES):
                self._drop(next(iter(self._entries)))

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self.bytes = 0

    def keys(self) -> list[Hashable]:
        with self._lock:
            return list(self._entries)

    def entries(self) -> list[tuple[Hashable, Any, int]]:
        with self._lock:
            return [(k, v, size) for k, (_, v, size) in self._entries.items()]

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[Hashable]:
        return iter(self.keys())

    def _drop(self, key: Hashable) -> None:
        _, _, size = self._entries.pop(key)
        self.bytes -= size


def _cached_size(value: Any) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8", "surrogatepass"))
    return len(json.dumps(value, default=str).encode("utf-8", "surrogatepass"))


def _partition_well_formed(org: str) -> bool:
    """Lowercase ASCII letters, digits, `_` and `-`, at most 64 characters:
    the shape of every partition name a writer produces."""
    return bool(PARTITION_NAME.fullmatch(org))


# How far back `Dashboard._action_scope` looks for the records carrying a
# request id or device.
ACTION_SCOPE_WINDOW = "30d"


class ViewScope(NamedTuple):
    """What a viewer may read, what they asked for, and which is current.

    `allowed` is the entitlement and drives the picker; `scoped` is the
    selection and drives every read. They are different sets and keeping
    them apart is the whole reason this type exists.
    """

    allowed: frozenset[str] | None
    scoped: frozenset[str] | None
    selected: str


class Dashboard:
    def __init__(self, store: Any, require_principal: bool = False,
                 auth: AuthConfig | None = None,
                 entitlements: Entitlements | None = None,
                 org_labels: Mapping[str, str] | None = None,
                 configured: dict[str, bool] | None = None,
                 sink_name: str | None = None,
                 scan_state_keys: list[str] | None = None,
                 watch=None, admins: AdminConfig | None = None,
                 overrides=None, baseline_mode: str = "observe",
                 baseline_source: str = "policy.yaml", lockout=None,
                 signing_key=None, branding: Branding | None = None,
                 compliance=None, fleets: Fleets = None, cursor_readers=None):
        from ..lockout import LockoutReports, expected_roles
        from ..overrides import OverlaidStore, deployment_enabled

        if overrides is not None:
            store = OverlaidStore(store, overrides)
        self.store = store
        self.overrides = overrides
        self.branding = branding or Branding()
        # The writers' lockout reports. Admin actions are refused and no
        # forms render until every expected writer role has a fresh denial.
        if lockout is None and admins is not None and overrides is not None:
            lockout = getattr(overrides, "fleet", None) or LockoutReports(
                store, expected_roles(), verify_keys=getattr(overrides, "verify_keys", None))
        self.lockout = lockout
        # Off unless dashboard.admins lists groups: no controls render, and
        # every method but GET and HEAD is refused.
        self.admins = admins
        # Admins parsed but the deployment has not enabled the control
        # identity: no controls render and every admin action is refused.
        self.controls_off = admins is not None and not deployment_enabled()
        # The control identity verifies every writer identity's lockout from
        # the cloud's IAM policy, hourly and after every change it writes,
        # for readers to trust.
        self.verifier = None
        if (admins is not None and not self.controls_off and overrides is not None
                and getattr(overrides, "store", None) is not None):
            from ..lockout import WRITTEN_BY_DASHBOARD
            from ..lockout_evidence.verifier import Verifier
            from ..overrides import trusted_head, unanchored_head

            verify_keys = getattr(overrides, "verify_keys", None)
            self.verifier = Verifier(
                overrides.store, signing_key=signing_key,
                trusted=lambda: trusted_head(overrides),
                unanchored=lambda: unanchored_head(overrides.store, verify_keys),
                verify_keys=verify_keys, written_by=WRITTEN_BY_DASHBOARD)
        self.baseline_mode = baseline_mode
        self.baseline_source = baseline_source
        # Where adapter 3 records that it ran. Read per render so the
        # panel can tell a scan that found nothing from one that did not
        # happen; empty means no compliance scan is configured, or the
        # policy could not be loaded, and the panel falls back to
        # inferring liveness from the records as it did before.
        self.scan_state_keys = list(scan_state_keys or [])
        # Adapter 3's orgs and their partitions (topology.CompliancePlan).
        # When set, the scan's state is decided per view from it, and
        # scan_state_keys is not read.
        self.compliance = compliance
        # The pulling readers whose cursors the pipeline panel judges
        # (topology.cursor_readers).
        self.cursor_readers = list(cursor_readers or [])
        # The fleet partitions and their orgs. With none, a scoped viewer's
        # reads read no fleet partition.
        self.fleets = fleets
        # When traffic is expected, for the delivery diagram. Defaults to
        # 07:00-20:00 UTC, which is a guess about the customer's working
        # day -- so the diagram names the window it is judging against.
        from .topology import Watch

        self.watch = watch or Watch()
        # Adapter 5's destination, for the outbound arm of the delivery
        # diagram. None when no sink is configured, and then the arm is
        # not drawn at all -- forwarding is optional and a diagram that
        # implies it is happening would be worse than no diagram.
        self.sink_name = sink_name
        # Which control points this deployment RUNS, for the delivery
        # strip. From the policy via the factory, because the store
        # cannot tell "never configured" from "configured and silent" --
        # both have written nothing, and only the second is an alert.
        # None falls back to inferring from the data, which can never
        # invent an alert for an adapter nobody set up.
        self.configured = configured
        if require_principal:
            refuse_require_principal()
        self.auth = auth or AuthConfig(mode=MODE_NONE)
        self.require_principal = self.auth.mode != MODE_NONE
        # Off unless configured: one customer is entitled to all of their
        # own orgs, so restricting is a preference a customer turns on.
        self.entitlements = entitlements or Entitlements()
        self.org_labels = org_labels if org_labels is not None else {}
        self._cache = RenderCache()
        self._auth_pool: ThreadPoolExecutor | None = None
        self._started = time.time()
        log.info(
            "dashboard ready",
            extra={"fields": {
                "store": describe_for_log(store),
                "auth": self.auth.describe(),
                **({"build": build_id()} if loaded_distributions() else {}),
            }},
        )
        if self.auth.mode == MODE_NONE:
            log.warning(
                "dashboard does not authenticate requests; put it behind a "
                "platform auth provider or a trusted network",
                extra={"fields": {"remediation": "set dashboard.auth.mode"}},
            )
        elif self.auth.mode == MODE_TRUSTED_HEADER:
            # Worth saying out loud on every start. The mode is only an
            # authentication check where the platform's proxy strips inbound
            # copies of the header; anywhere the container is directly
            # reachable, the caller sets it themselves.
            log.warning(
                "dashboard trusts an unverified header; this is only safe "
                "behind a proxy that strips it from inbound requests",
                extra={"fields": {
                    "header": self.auth.header,
                    "remediation": "dashboard.auth.mode: oidc_jwt",
                }},
            )

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    if self.overrides is not None:
                        self.overrides.start()
                    if self.verifier is not None:
                        self.verifier.start()
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    if self.verifier is not None:
                        self.verifier.stop()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":  # pragma: no cover
            return

        path = scope.get("path", "/").rstrip("/") or "/"
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in (scope.get("headers") or [])
        }
        method = scope.get("method", "GET")
        if method == "POST" and path == PATH_ACTIONS and self.admins is not None:
            await self._admin_post(receive, send, headers)
            return
        if method not in ("GET", "HEAD"):
            await self._send(send, 405, b'{"error": "method_not_allowed"}', "application/json",
                             [(b"allow", b"GET, HEAD")])
            return

        # Probes stay unauthenticated so the platform can reach them.
        if path == "/healthz":
            await self._json(send, 200, {"status": "ok",
                                         "uptime_s": round(time.time() - self._started, 1)})
            return
        if path == "/readyz":
            from ..overrides import readiness

            await self._json(send, *readiness(self.overrides))
            return

        try:
            principal = await self._authenticate(headers)
        except AuthError as exc:
            # The reason is logged, not returned: a verification oracle tells
            # a forger which part to fix.
            log.info("dashboard request rejected",
                     extra={"fields": {"reason": str(exc)}})
            await self._json(send, 401, {"error": "authentication_required"})
            return

        if path.startswith("/assets/"):
            await self._asset(send, path[len("/assets/"):])
            return

        qs = scope.get("query_string", b"")
        window = _query_param(qs, "window", "7d")
        if window not in {*WINDOWS, "all"}:
            window = "7d"

        # Which orgs this caller may read, and which they asked for.
        # Resolved once, here, and passed down -- not re-derived per route,
        # because a route that forgot to would serve everything.
        try:
            view = self._scope_for(principal, _query_param(qs, "org", ""))
        except GroupsUnavailable:
            # Said, to the viewer and in the log. Refusing is right -- which
            # orgs they may read cannot be decided -- but a refusal with no
            # reason reads as a bug, and it lands on the people in the most
            # groups.
            log.warning("dashboard viewer's token omitted their groups", extra={
                "fields": {**_screened_who(getattr(principal, "name", None), _org_screen()),
                           "claim": self.auth.groups_claim}})
            detail = (
                "Identity-Aware Proxy does not put group memberships in its sign-in "
                "token, so which organizations you may read cannot be decided. Ask "
                "the operator to turn off dashboard.entitlements, or to sign in "
                "through an identity provider whose token carries groups."
                if self.auth.platform == "iap" else
                "Your sign-in token left out your group memberships, so which "
                "organizations you may read cannot be decided. Entra ID does this for "
                "users in more groups than a token holds. Ask the operator to emit "
                "only the groups assigned to this application, or to use app roles.")
            await self._json(send, 403, {"error": "groups_unavailable", "detail": detail})
            return
        except Forbidden as exc:
            # 403 and not an empty page. An empty page is indistinguishable
            # from a clean week, which is the wrong thing to show someone
            # who has asked for an org they cannot see.
            log.info("dashboard org refused", extra={"fields": {
                **_screened_who(getattr(principal, "name", None), _org_screen()),
                "org_well_formed": bool(ORG_PSEUDONYM.fullmatch(str(exc)))}})
            await self._json(send, 403, {"error": "forbidden"})
            return

        if path == "/api/summary":
            await self._json(send, 200, self._summary_json(window, view.scoped))
            return
        who = getattr(principal, "name", "") or ""
        who = _org_screen()(who) if who else ""
        if path == "/":
            await self._html(send, self._page(window, view, who), headers)
            return
        if path == "/policy":
            await self._html(send, self._policy(view, who, principal,
                                                _query_param(qs, "result", "")), headers)
            return
        if path == "/events":
            source = _query_param(qs, "source", "all")
            if source not in EVENT_SOURCES:
                source = "all"
            action = _query_param(qs, "action", "all")
            if action not in EVENT_ACTIONS:
                action = "all"
            client = _query_param(qs, "client", "")
            if not INTAKE_CLIENT_NAME.fullmatch(client):
                client = ""
            device = _query_param(qs, "device", "")
            if not DEVICE_ID.fullmatch(device):
                device = ""
            detector = _query_param(qs, "detector", "")
            if not _DETECTOR_NAME.fullmatch(detector):
                detector = ""
            before = EventCursor.decode(_query_param(qs, "before", ""))
            show_allows = _query_param(qs, "code_hook_allows", "") == "show"
            await self._html(
                send,
                self._events(
                    window,
                    source,
                    action,
                    view,
                    who,
                    principal,
                    client=client,
                    device=device,
                    detector=detector,
                    before=before,
                    show_allows=show_allows,
                ),
                headers,
            )
            return
        await self._json(send, 404, {"error": "not_found"})

    async def _authenticate(self, headers: dict[str, str]):
        """`self.auth.authenticate`, on a worker thread under oidc_jwt."""
        if self.auth.mode != MODE_OIDC_JWT:
            return self.auth.authenticate(headers)
        if self._auth_pool is None:
            self._auth_pool = ThreadPoolExecutor(max_workers=AUTH_WORKERS,
                                                 thread_name_prefix="dashboard-auth")
        return await asyncio.get_running_loop().run_in_executor(
            self._auth_pool, self.auth.authenticate, headers)

    def _scope_for(self, principal, requested: str) -> ViewScope:
        """What the viewer may read, and what they asked to read.

        Two different things. A picker built from the narrowed selection
        leaves one entry after an org is chosen, and no way back to the
        others.

        `allowed` drives the picker. `scoped` drives every read.
        """
        allowed = self.entitlements.allowed(principal)
        if not requested or requested == "all":
            return ViewScope(allowed, allowed, "all")
        if not _partition_well_formed(requested):
            raise Forbidden(requested)
        self.entitlements.check(principal, requested)
        return ViewScope(allowed, frozenset({requested}), requested)

    # -- rendering --------------------------------------------------------

    def _page(self, window: str, view: ViewScope | None = None,
              viewer: str = "") -> str:
        view = view or ViewScope(None, None, "all")
        scoped = view.scoped
        now = time.monotonic()
        # The cache key carries the scope AND the viewer. Keyed on the
        # window alone, a restricted viewer would be served a page built for
        # an unrestricted one -- a cache that leaks across an authorization
        # boundary, which is a worse bug than no cache at all. The page now
        # also names who it was built for, so without the viewer in the key
        # it would show one person's name to another.
        key = ("page", window, _key_set(scoped), _key_set(view.allowed),
               view.selected, viewer)
        hit = self._cache.get(key, now)
        if hit is not None:
            return hit
        # A reset marker moves the floor for every statistic, so a window
        # that predates the reset still starts at it.
        desc = self.store.describe()
        since = effective_since(window_to_since(window), desc.get("reset_at"))
        summary = read_summary(self.store, since, scoped, fleets=self.fleets)
        # Which adapters this deployment RUNS comes from the policy, not
        # the store: a surface nobody configured has written nothing,
        # which is indistinguishable from one that broke before it ever
        # wrote. Only the third of those is worth a colour.
        from ..store.base import SOURCE_COMPLIANCE_SCAN
        from .topology import compliance_view, control_points, infer_configured, surface_states

        configured = self.configured
        if self.compliance is not None:
            reason, beats, intervals = compliance_view(self.compliance, self.store, scoped)
            configured = {**(configured if configured is not None
                             else infer_configured(summary)),
                          SOURCE_COMPLIANCE_SCAN: reason}
        else:
            beats, intervals = self._heartbeats()
        points = control_points(summary, configured, watch=self.watch,
                                heartbeats=beats, intervals=intervals)
        surfaces = surface_states(summary, configured, watch=self.watch,
                                  heartbeats=beats, intervals=intervals)
        if summary.pipeline is not None:
            from ..store.pipeline import cursor_health

            readers = [r for r in self.cursor_readers
                       if scoped is None or r.partition in scoped]
            summary.pipeline.cursors = cursor_health(
                self.store, [(r.reader, r.name, r.state_key, r.limit_days) for r in readers])
        from ..store import store_is_empty

        html = render.render(summary, window, desc,
                             self._visible_orgs(view.allowed), view.selected,
                             viewer, points=points, surfaces=surfaces,
                             sink=self.sink_name,
                             empty_store=store_is_empty(self.store),
                             banners=self._banners(), branding=self.branding)
        self._cache.put(key, now, html)
        return html

    def _heartbeats(self) -> tuple[dict[str, str], dict[str, float]]:
        from .topology import heartbeats

        return heartbeats(self.store, self.scan_state_keys)

    def _visible_orgs(self, allowed: frozenset[str] | None) -> dict[str, str]:
        """Labelled orgs this caller is ENTITLED to -- not the ones they
        currently have selected.

        Built from the entitlement and not from the store, so the picker
        cannot list an org the viewer would be refused. An org with no
        configured label is not shown: an unlabelled pseudonym is not
        something a human can choose between.
        """
        labels = dict(self.org_labels)
        if allowed is None:
            return labels
        return {k: v for k, v in labels.items() if k in allowed}

    def _excluded(self) -> set[str]:
        """Request ids kept out of the statistics.

        Read per render rather than cached at startup, so marking a frame
        takes effect on the next page load instead of a redeploy.
        """
        return excluded_requests(self.store)

    def _policy(self, view: ViewScope | None = None, viewer: str = "",
                principal=None, result: str = "") -> str:
        view = view or ViewScope(None, None, "all")
        """The effective policy, redacted, as YAML.

        Rendered per request: an operator opening this page is usually
        checking whether a change took effect. `POLICY_CACHE` reloads the
        policy whenever the file, an `ENV_OVERRIDES` variable or a `$NAME`
        it references changes.
        """
        import yaml

        from ..policy import redacted
        from ..store.base import utcnow

        source = os.environ.get("FORGD_VERDICT_POLICY") or "policy.yaml"
        try:
            # Built first: `redacted` shows a plugin's `public_keys` only
            # once this policy has built the plugin.
            policy, built = POLICY_CACHE.detectors()
            detectors = [d.name for d in built]
            # hashes_here=False: this process is deliberately not given
            # the salt, so it cannot tell "unset" from "set somewhere I
            # cannot see" -- and reporting UNSET would send an operator to
            # fix it by handing the dashboard the salt.
            effective = redacted(policy, hashes_here=False)
        except Exception as exc:  # noqa: BLE001 - a bad policy must still render
            # Showing the error beats a blank page: a policy that will not
            # load is exactly what someone opens this tab to discover.
            #
            # `policy_error`, never `str(exc)`. A PyYAML error quotes the
            # offending source line, so an unterminated quote on the
            # `hash_salt:` line printed the salt onto this tab.
            return render.render_policy(
                f"# policy could not be loaded:\n# {policy_error(exc)}\n",
                source, [], self.store.describe(), utcnow(),
                self._visible_orgs(view.allowed), view.selected, viewer,
                banners=self._banners(), panel=self._panel(principal, result),
                branding=self.branding,
            )
        text = yaml.safe_dump(effective, sort_keys=False, default_flow_style=False,
                              allow_unicode=True, width=100)
        state = self.overrides.current().state if self.overrides is not None else None
        if state is not None and state.overrides:
            text = "".join(
                f"# runtime override in force: {key} = {entry.value} "
                "(the value below is the policy's)\n"
                for key, entry in sorted(state.overrides.items())) + text
        return render.render_policy(text, source, detectors,
                                    self.store.describe(), utcnow(),
                                    self._visible_orgs(view.allowed),
                                    view.selected, viewer,
                                    banners=self._banners(),
                                    panel=self._panel(principal, result),
                                    branding=self.branding)

    def _events(self, window: str, source: str = "all", action: str = "all",
                view: ViewScope | None = None, viewer: str = "",
                principal=None, *, client: str = "", device: str = "",
                detector: str = "", before: EventCursor | None = None,
                show_allows: bool = False) -> str:
        view = view or ViewScope(None, None, "all")
        scoped = view.scoped
        """Newest-first event list, filtered by control point and verdict.

        Not cached: the point of a log is that it is current, and a viewer
        looking at it is usually looking for something that just happened.
        """
        desc = self.store.describe()
        since = effective_since(window_to_since(window), desc.get("reset_at"))
        page = event_page(self.store, since, scoped, source, action,
                          client=client, device=device, detector=detector, before=before,
                          hide_code_hook_allows=not show_allows, fleets=self.fleets)
        scope = None
        if self._admin_group(principal) is not None:
            scope = self._action_scope(principal, {
                "request_id": {r.request_id for r in page.records if r.request_id},
                "device": {r.device for r in page.records if r.device}})
        exclude = self._exclude_form(principal, scope)
        deny = self._deny_form(principal, scope) if exclude is not None else None
        from ..store.base import utcnow

        return render.render_events(
            page.records,
            older=page.before.encode() if page.before else None,
            older_label=page.before.label if page.before else "",
            approximate=page.approximate,
            window=window,
            detector=detector,
            paged=before is not None,
            show_allows=show_allows,
            source=source,
            action=action,
            client=client,
            device=device,
            orgs=self._visible_orgs(view.allowed),
            selected=view.selected,
            store_desc=desc,
            generated_at=utcnow(),
            viewer=viewer,
            banners=self._banners() + (controls.STYLE if exclude is not None else ""),
            exclude_form=exclude,
            deny_form=deny,
            id_screen=_org_screen(),
            branding=self.branding,
        )

    def _summary_json(self, window: str,
                      scoped: frozenset[str] | None = None) -> dict[str, Any]:
        """The summary payload, cached as `_page` is, under its own key
        namespace and keyed by window and scope. It names no viewer."""
        now = time.monotonic()
        key = ("api-summary", window, _key_set(scoped))
        hit = self._cache.get(key, now)
        if hit is not None:
            return hit
        since = effective_since(
            window_to_since(window), self.store.describe().get("reset_at")
        )
        payload = summary_payload(
            read_summary(self.store, since, scoped, fleets=self.fleets), window)
        self._cache.put(key, now, payload)
        return payload

    # -- runtime overrides ------------------------------------------------

    def _banners(self) -> str:
        if self.overrides is None:
            return ""
        lockout = (controls.lockout_banner(self.lockout.current())
                   if self.lockout is not None and not self.controls_off else "")
        return lockout + controls.banners(self.overrides.current(), self.baseline_mode,
                                          _org_screen())

    def _locked_out(self, refresh: bool = False) -> bool:
        """Whether admin actions are refused because a writer lockout is not
        proven. True without a lockout view."""
        if self.lockout is None:
            return True
        return not (self.lockout.refresh() if refresh else self.lockout.current()).ok

    def _admin_group(self, principal) -> str | None:
        if self.admins is None or self.controls_off or principal is None:
            return None
        if not getattr(principal, "subject", "") or getattr(principal, "groups_incomplete", False):
            return None
        return self.admins.match(principal)

    def _form_maker(self, principal, revision: int, scope=None):
        """A form per control, each with a token bound to the principal, the
        control and `revision`. None for a viewer who is not an admin. A
        control `_may` refuses under `scope` renders as nothing."""
        if self._admin_group(principal) is None or self._locked_out():
            return None
        admins = self.admins
        issued = int(time.time())

        def form(action: str, key: str, value: str, label: str, danger: bool) -> str:
            from html import escape

            if not self._may(principal, action, value, scope):
                return ""
            token = admins.mint(principal, action, key, value, revision, issued)
            return (f'<form method="post" action="{PATH_ACTIONS}">'
                    f'<input type="hidden" name="action" value="{escape(action)}">'
                    f'<input type="hidden" name="key" value="{escape(key)}">'
                    f'<input type="hidden" name="value" value="{escape(value)}">'
                    f'<input type="hidden" name="token" value="{escape(token)}">'
                    f'<button type="submit"{" class=danger" if danger else ""}>'
                    f"{escape(label)}</button></form>")
        return form

    def _store_revision(self) -> int:
        """The revision a write would be conditional on: the stored object's,
        or 0 when there is none to parse."""
        snap = self.overrides.refresh()
        if snap.status == "ok" and snap.state is not None:
            return snap.state.revision
        return 0

    def _panel(self, principal, result: str) -> str:
        """Shown to admins, and to everyone once an overrides object exists
        or cannot be read. Otherwise the Policy tab is as it was."""
        if self.overrides is None:
            return ""
        from ..overrides import history

        snap = self.overrides.current()
        if (self.admins is None and snap.state is None
                and snap.status in ("absent", "disabled")):
            return ""
        snap = self.overrides.current()
        state = snap.state
        legacy = self.store.get_legacy_excluded()
        values = {"request_id": (set(state.excluded_requests) if state else set()) | legacy,
                  "device": set(state.denied_devices) if state else set()}
        scope = self._action_scope(principal, values)
        form = None
        if self._admin_group(principal) is not None:
            form = self._form_maker(principal, self._store_revision(), scope)
        try:
            recent = history(self.store, snap.state,
                             verify_keys=getattr(self.overrides, "verify_keys", None))
        except Exception as exc:  # noqa: BLE001 - the history must not take the page down
            log.warning("could not read the runtime overrides history",
                        extra={"fields": exc_fields(exc)})
            recent = None
        return controls.panel(controls.Panel(
            snapshot=snap, baseline_mode=self.baseline_mode,
            baseline_source=self.baseline_source,
            legacy_reset=self.store.describe().get("legacy_reset_at"),
            legacy_excluded=legacy,
            history=recent, form=form, result=result or None,
            legacy_label=_exclusion_labeler(), org_screen=_org_screen(),
            shown_requests=None if scope is None else scope["request_id"],
            shown_devices=None if scope is None else scope["device"]))

    def _action_scope(self, principal, values: Mapping[str, set[str]]
                      ) -> dict[str, set[str]] | None:
        """None when `principal` may read every org: with no entitlement
        map, or entitled to every partition the map grants and every
        labelled org. Otherwise, for each record field in `values`, the
        values of it every record carrying it is visible to them on, among
        records in the last `ACTION_SCOPE_WINDOW` that carry it at all. A
        value no such record carries is left out."""
        try:
            allowed = self.entitlements.allowed(principal)
        except (GroupsUnavailable, Forbidden):
            allowed = frozenset()
        every = self.entitlements.partitions() | set(self.org_labels)
        if allowed is None or (every and allowed >= every):
            return None
        wanted = {f: set(v) for f, v in values.items() if v}
        seen: dict[str, set[str]] = {f: set() for f in values}
        hidden: dict[str, set[str]] = {f: set() for f in values}
        if wanted:
            since = window_to_since(ACTION_SCOPE_WINDOW)
            for r in attributed(self.store, self.fleets).read_verdicts(since, None):
                ok = visible(r, allowed)
                for f, vs in wanted.items():
                    v = getattr(r, f, None)
                    if v in vs:
                        (seen if ok else hidden)[f].add(v)
        return {f: seen[f] - hidden[f] for f in values}

    def _may(self, principal, action: str, value: str,
             scope: Mapping[str, set[str]] | None) -> bool:
        """Whether `principal` may apply `action` to `value`, given
        `_action_scope` for it: a deployment-wide action needs every org, a
        request or device action every org that value's records are in."""
        from ..overrides import SCOPED_ACTIONS

        if scope is None:
            return True
        field = SCOPED_ACTIONS.get(action)
        return field is not None and value in scope.get(field, ())

    def _exclude_form(self, principal, scope=None):
        """An Exclude button for each event row the admin can see and `_may`
        allows under `scope`."""
        if self.overrides is None or self._admin_group(principal) is None:
            return None
        from ..overrides import ACTION_EXCLUDE

        form = self._form_maker(principal, self._store_revision(), scope)
        if form is None:
            return None
        excluded = self.store.get_excluded()

        def exclude(request_id: str) -> str:
            if request_id in excluded:
                return ' <span class="note">excluded</span>'
            return " " + form(ACTION_EXCLUDE, "excluded_requests", request_id,
                              "exclude", False).replace("<form ", '<form class="xform" ', 1)
        return exclude

    def _deny_form(self, principal, scope=None):
        """A Deny button for each event row's intake device the admin can see
        and `_may` allows under `scope`."""
        if self.overrides is None or self._admin_group(principal) is None:
            return None
        from ..overrides import ACTION_DENY_DEVICE

        form = self._form_maker(principal, self._store_revision(), scope)
        if form is None:
            return None
        denied = self.overrides.denied_devices()

        def deny(device: str) -> str:
            if device in denied:
                return ' <span class="note">denied</span>'
            return " " + form(ACTION_DENY_DEVICE, "denied_devices", device,
                              "deny device", True).replace("<form ", '<form class="xform" ', 1)
        return deny

    async def _admin_post(self, receive: Callable, send: Callable,
                          headers: dict[str, str]) -> None:
        """POST /admin/actions: Origin, identity, admin group, then the body,
        form token and the change. Every refusal is logged with its reason and answered
        without one."""
        from urllib.parse import parse_qs

        from ..overrides import (
            ACTION_RECOVER,
            CONTROL_IDENTITY_OFF,
            DASHBOARD_ACTIONS,
            KEY_MODE,
            Change,
            InvalidState,
            NoChange,
            Refused,
            StoreConflict,
            StoreForbidden,
            StoreReadError,
            apply_change,
            org_ids_of,
            org_screen_of,
        )

        def refuse(reason: str, **fields) -> None:
            org = _org_screen()
            who = _screened_who(fields.pop("who"), org) if "who" in fields else {}
            log.warning("dashboard admin action refused",
                        extra={"fields": {"reason": reason, **org(fields), **who}})

        if not headers.get("content-type", "").startswith(
                "application/x-www-form-urlencoded"):
            refuse("content_type")
            await self._json(send, 415, {"error": "unsupported_media_type"})
            return
        origin = headers.get("origin")
        if not origin or origin.rstrip("/") not in self.admins.allowed_origins:
            refuse("origin", origin=origin if origin and _ORIGIN.fullmatch(origin)
                   else "malformed" if origin else None)
            await self._json(send, 403, {"error": "forbidden"})
            return
        fetch_site = headers.get("sec-fetch-site")
        if fetch_site is not None and fetch_site != "same-origin":
            refuse("sec_fetch_site", sec_fetch_site=fetch_site
                   if fetch_site in ("same-site", "cross-site", "none") else "other")
            await self._json(send, 403, {"error": "forbidden"})
            return
        try:
            principal = await self._authenticate(headers)
        except AuthError as exc:
            refuse("authentication", detail=str(exc))
            await self._json(send, 401, {"error": "authentication_required"})
            return
        who = getattr(principal, "name", None)
        if principal is None or not getattr(principal, "subject", ""):
            refuse("no_subject", who=who)
            await self._json(send, 403, {"error": "forbidden"})
            return
        if getattr(principal, "groups_incomplete", False):
            refuse("groups_incomplete", who=who)
            await self._json(send, 403, {"error": "forbidden"})
            return
        group = self.admins.match(principal)
        if group is None:
            refuse("not_admin", who=who)
            await self._json(send, 403, {"error": "forbidden"})
            return
        if self.controls_off:
            refuse("control_identity_off", who=who, detail=CONTROL_IDENTITY_OFF)
            await self._json(send, 403, {"error": "forbidden"})
            return
        if self._locked_out(refresh=True):
            refuse("writer_lockout", who=who,
                   problems=dict(self.lockout.current().problems) if self.lockout else None)
            await self._json(send, 403, {"error": "forbidden"})
            return
        body, oversized = await _read_body(receive, MAX_BODY_BYTES)
        if oversized:
            refuse("body_too_large", who=who)
            await self._json(send, 413, {"error": "payload_too_large"})
            return
        form = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        fields = {}
        for name in ("action", "key", "value", "token"):
            values = form.get(name, [])
            if len(values) != 1:
                refuse("form", who=who, field=name)
                await self._json(send, 400, {"error": "bad_request"})
                return
            fields[name] = values[0]
        action, key, value = fields["action"], fields["key"], fields["value"]
        if action not in DASHBOARD_ACTIONS:
            refuse("action", who=who)
            await self._json(send, 400, {"error": "bad_request"})
            return
        try:
            revision = self.admins.verify(fields["token"], principal, action, key, value,
                                          int(time.time()))
        except TokenRefused as exc:
            refuse("token", who=who, detail=str(exc))
            await self._json(send, 403, {"error": "forbidden"})
            return
        from ..overrides import SCOPED_ACTIONS

        field = SCOPED_ACTIONS.get(action)
        scope = await asyncio.to_thread(
            self._action_scope, principal, {field: {value}} if field and value else {})
        if not self._may(principal, action, value, scope):
            refuse("out_of_scope", who=who)
            await self._json(send, 403, {"error": "forbidden"})
            return
        actor = {"issuer": principal.issuer, "subject": principal.subject,
                 "name": principal.name, "via_group": group, "verified": True}
        change = Change(action, key or None, value or None)
        recover_mode = value if action == ACTION_RECOVER and key == KEY_MODE else None
        try:
            policy, detectors = POLICY_CACHE.detectors()
            org_ids = org_ids_of(policy)
            org = org_screen_of(policy)
            keys = from_policy(policy.raw)
            signing_key = keys.signing_key
            if signing_key is None:
                raise RuntimeError(f"{ENV_SIGNING_KEY} is not set")
        except Exception as exc:  # noqa: BLE001 - no scan, no change
            refuse("detectors", who=who, detail=str(exc) if isinstance(exc, RuntimeError)
                   else policy_error(exc))
            await self._send(send, 303, b"", "text/plain",
                             [(b"location", b"/policy?result=refused")])
            return
        try:
            applied = apply_change(self.store, actor, change, detectors=detectors,
                                   org_ids=org_ids, salt=policy.hash_salt,
                                   expect_revision=revision, recover_mode=recover_mode,
                                   signing_key=signing_key, verify_keys=keys.verify_keys,
                                   after_write=self.verifier.after_write
                                   if self.verifier is not None else None)
            result = "applied"
            log.info("dashboard admin action applied", extra={"fields": {
                **_screened_who(who, org), "action": action, "key": org(key or None),
                "audit_id": applied.audit_id, "revision": applied.state.revision}})
        except NoChange:
            result = "nochange"
        except StoreConflict:
            result = "conflict"
        except InvalidState:
            result = "invalid"
        except Refused as exc:
            refuse("refused", who=who, detail=str(exc))
            result = "refused"
        except StoreReadError as exc:
            log.error("dashboard admin action: the store could not be read",
                      extra={"fields": exc_fields(exc)})
            result = "unreadable"
        except StoreForbidden as exc:
            log.error("dashboard admin action: the dashboard's identity may not write "
                      "the runtime overrides; admins need the control identity",
                      extra={"fields": {"denied": str(exc)}})
            result = "error"
        except Exception as exc:  # noqa: BLE001 - reported on the page and in the log
            log.error("dashboard admin action failed", extra={"fields": exc_fields(exc)})
            result = "error"
        self.overrides.refresh()
        self._cache.clear()
        await self._send(send, 303, b"", "text/plain",
                         [(b"location", f"/policy?result={result}".encode("ascii"))])

    # -- transport --------------------------------------------------------

    async def _asset(self, send: Callable, name: str) -> None:
        cache = (b"cache-control", b"public, max-age=86400")
        if name.startswith("brand/"):
            asset = next((a for a in (self.branding.logo, self.branding.favicon)
                          if a is not None and name == f"brand/{a.filename}"), None)
            if asset is None:
                await self._json(send, 404, {"error": "not_found"})
                return
            extra = [cache]
            if asset.content_type == "image/svg+xml":
                extra.append((b"content-security-policy",
                              b"default-src 'none'; script-src 'none'; "
                              b"style-src 'unsafe-inline'"))
            await self._send(send, 200, asset.data, asset.content_type, extra=extra)
            return
        if name == "tokens.css":
            await self._send(send, 200, self.branding.tokens_css.encode("utf-8"),
                             "text/css", extra=[cache])
            return
        # Resolve inside ASSETS and refuse anything that escapes it.
        try:
            target = (ASSETS / name).resolve()
            target.relative_to(ASSETS.resolve())
            body = target.read_bytes()
        except (OSError, ValueError):
            await self._json(send, 404, {"error": "not_found"})
            return
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        await self._send(send, 200, body, ctype, extra=[cache])

    async def _html(self, send: Callable, html: str, headers: dict[str, str]) -> None:
        await self._send(send, 200, html.encode("utf-8"), "text/html; charset=utf-8")

    async def _json(self, send: Callable, status: int, payload: dict) -> None:
        await self._send(send, status, json.dumps(payload).encode("utf-8"),
                         "application/json")

    async def _send(self, send: Callable, status: int, body: bytes, ctype: str,
                    extra: list[tuple[bytes, bytes]] | None = None) -> None:
        headers = [
            (b"content-type", ctype.encode("ascii")),
            (b"content-length", str(len(body)).encode("ascii")),
            # Findings are security data; keep them out of caches and frames.
            (b"referrer-policy", b"no-referrer"),
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            # No third-party origin. The two that were here --
            # fonts.googleapis.com for the stylesheet and fonts.gstatic.com
            # for the files -- were added to permit an `@import` in
            # tokens.css, while the renderer's docstring claimed there
            # were no external requests at all. The fonts ship in the
            # package now, so `self` covers them.
            (b"content-security-policy",
             b"default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; "
             b"font-src 'self'; form-action 'self'; base-uri 'none'"),
        ]
        headers.extend(extra or [])
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


class _PolicyCache:
    """The policy the dashboard's request paths read, and its `dashboard`
    detectors, reloaded only when `load_identity()` or the value of a
    `$NAME` the policy references changes.

    A failed load clears the entry. A failed detector build is not kept, so
    the next caller builds again.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key: tuple[Any, ...] | None = None
        self._refs: tuple[str, ...] = ()
        self._policy: Any = None
        self._detectors: list[Any] | None = None

    def policy(self) -> Any:
        from ..policy import env_references, load_identity, load_policy

        identity = load_identity()
        with self._lock:
            if self._key is not None and self._key == (identity, _env_values(self._refs)):
                return self._policy
            self._key, self._refs, self._policy, self._detectors = None, (), None, None
            policy = load_policy()
            refs = env_references(policy.raw)
            self._key, self._refs, self._policy = (identity, _env_values(refs)), refs, policy
            return policy

    def detectors(self) -> tuple[Any, list[Any]]:
        """The policy and its detectors built for the `dashboard` profile."""
        policy = self.policy()
        with self._lock:
            if self._policy is policy and self._detectors is not None:
                return policy, self._detectors
            detectors = policy.build_detectors(profile="dashboard")
            if self._policy is policy:
                self._detectors = detectors
            return policy, detectors

    def clear(self) -> None:
        with self._lock:
            self._key, self._refs, self._policy, self._detectors = None, (), None, None


def _env_values(names: tuple[str, ...]) -> tuple[str | None, ...]:
    return tuple(os.environ.get(n) for n in names)


POLICY_CACHE = _PolicyCache()


def _exclusion_labeler() -> Callable[[str], str]:
    """overrides.exclusion_label with the policy's detectors and org ids;
    with neither when the policy or its detectors cannot be loaded."""
    from ..overrides import exclusion_label, org_ids_of

    try:
        policy, detectors = POLICY_CACHE.detectors()
        org_ids = org_ids_of(policy)
    except Exception:  # noqa: BLE001 - no scan, no value
        log.warning("legacy exclusions are withheld: the policy's detectors could not be built")
        detectors, org_ids = None, frozenset()
    return lambda value: exclusion_label(value, detectors, org_ids)


def _org_screen():
    """overrides.OrgScreen for the policy; one that withholds every value
    when the policy cannot be loaded."""
    from ..overrides import ORG_SCREEN_UNAVAILABLE, org_screen_of

    try:
        return org_screen_of(POLICY_CACHE.policy())
    except Exception:  # noqa: BLE001 - no org ids, no value
        log.warning("runtime overrides values are withheld: the policy could not be loaded")
        return ORG_SCREEN_UNAVAILABLE


def _screened_who(who: object, org: Callable[[object], object]) -> dict[str, object]:
    """`who` as a log line carries it: org ids replaced by `org`, then
    screened with the policy's detectors, and withheld when they cannot be
    built."""
    from ..overrides import WITHHELD, screened_identity

    if not isinstance(who, str) or not who:
        return {"who": who}
    who = org(who)
    try:
        policy, detectors = POLICY_CACHE.detectors()
    except Exception:  # noqa: BLE001 - no scan, no name
        return {"who": WITHHELD, "who_unscanned": True}
    return screened_identity(who, detectors, policy.hash_salt)


async def _read_body(receive: Callable, max_bytes: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > max_bytes:
            return b"", True
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks), False


# The Event Log's detector filter.
_DETECTOR_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}")


def _key_set(orgs: frozenset[str] | None) -> tuple[str, ...] | None:
    return None if orgs is None else tuple(sorted(orgs))


def _query_param(query: bytes, key: str, default: str) -> str:
    from urllib.parse import parse_qs

    values = parse_qs(query.decode("latin-1")).get(key)
    return values[0] if values else default


def _require_signing_key(raw: dict) -> None:
    """ValueError unless the policy holds a valid signing key its verify keys list."""
    if from_policy(raw).signing_key is None:
        raise ValueError(
            f"dashboard.admins lists groups but {ENV_SIGNING_KEY} is not set: every admin "
            "action is a signed record, so the dashboard does not start without the key. "
            "Generate one with `forgd-verdict overrides keygen`")


def create_app(store_spec: str | None = None, require_principal: bool | None = None):
    from ..policy import load_policy
    from ..store import open_store

    spec = store_spec or os.environ.get("FORGD_VERDICT_STORE") or "./findings"

    # `dashboard.auth`, parsed at startup so a mode missing its audience
    # fails here rather than on the first request.
    raw_auth: dict | None = None
    entitlements = None
    labels: dict[str, str] = {}
    # NOT wrapped in a try. A file named by FORGD_VERDICT_POLICY that does
    # not exist raises PolicyNotFound, and with none named `load_policy`
    # returns the built-in defaults. A swallow here once caught a policy
    # that existed and would not parse, and that left `policy = None`,
    # which skipped `dashboard.auth` entirely and served every route
    # unauthenticated.
    #
    # Same reasoning as `policy.entitlements()` below, which was already
    # deliberately outside a try.
    policy = load_policy()
    # The policy key also carries FORGD_DASHBOARD_REQUIRE_PRINCIPAL, through
    # ENV_OVERRIDES.
    if require_principal or (policy.raw.get("dashboard") or {}).get("require_principal"):
        refuse_require_principal()
    configured = None
    sink_name = None
    watch = None
    scan_state_keys: list[str] = []
    if policy is not None:
        raw_auth = (policy.raw.get("dashboard") or {}).get("auth")
        # Deliberately NOT inside a try. An entitlement map configured under
        # an unverified auth mode must fail startup, not be swallowed --
        # swallowing it serves a control that looks enforced and is not,
        # which is worse than having no control at all.
        entitlements = policy.entitlements()
        labels = policy.partition_labels()
        from ..store.base import SOURCE_COMPLIANCE_SCAN
        from .topology import configured_from_policy, watch_from_policy

        configured = configured_from_policy(policy)
        sinks = policy.sinks
        sink_name = str(sinks[0].get("name") or "") if sinks else None
        watch = watch_from_policy(policy)
        # Only when the scan is actually configured. Otherwise the
        # dashboard would GET a cursor blob per render for a job nobody
        # runs, and the panel already reports that adapter as off.
        if configured.get(SOURCE_COMPLIANCE_SCAN):
            scan_state_keys = policy.compliance_state_keys()
    auth = AuthConfig.parse(raw_auth) if raw_auth else None
    # Not inside a try: an AdminConfig that does not parse stops the
    # dashboard from starting.
    admins = AdminConfig.parse((policy.raw.get("dashboard") or {}).get("admins"),
                               auth or AuthConfig(mode=MODE_NONE))
    # Not inside a try: a BrandingError stops the dashboard from starting.
    branding = Branding.from_policy((policy.raw.get("dashboard") or {}).get("branding"))
    store = open_store(spec, plugins=policy.plugin_allow if policy is not None else (),
                       profile="dashboard")
    compliance = None
    if policy is not None:
        policy.use_org_registry(store)
        from .topology import compliance_plan

        compliance = compliance_plan(policy)

    from ..overrides import KEY_MODE, honoured_in, reader_for

    baseline_mode = str((policy.raw.get("server") or {}).get("mode", "observe"))
    baseline_source = "FORGD_VERDICT_MODE" if os.environ.get("FORGD_VERDICT_MODE") \
        else "policy.yaml"
    overrides = None
    if honoured_in(policy.raw, "dashboard", log):
        if admins is not None:
            _require_signing_key(policy.raw)
        overrides = reader_for(policy.raw, store, "dashboard", baseline={KEY_MODE: baseline_mode})
        overrides.refresh()
    if admins is not None and overrides is not None:
        log.info("dashboard admin controls enabled", extra={"fields": admins.describe()})
    extra = {"admins": admins, "overrides": overrides, "baseline_mode": baseline_mode,
             "baseline_source": baseline_source, "branding": branding,
             "signing_key": from_policy(policy.raw).signing_key if overrides is not None
             else None, "compliance": compliance}

    fleets = None
    if policy is not None:
        fleets = policy_fleets(policy)
        warn_unresolved_fleets(policy, "dashboard")
    readers = None
    if policy is not None and compliance is not None:
        from .topology import cursor_readers

        readers = cursor_readers(policy, compliance, labels or {})
    return Dashboard(store, auth=auth, fleets=fleets,
                     entitlements=entitlements, org_labels=labels,
                     configured=configured, sink_name=sink_name,
                     scan_state_keys=scan_state_keys, watch=watch,
                     cursor_readers=readers, **extra)
