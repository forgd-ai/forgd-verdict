"""Adapter 4: the OTLP collector.

A pure-ASGI application, like the verdict server, for the same reason: the
hot path stays stdlib and this container's dependency list is its attack
surface.

It runs as its OWN service rather than another route on the verdict server.
The verdict server answers inside the org's 5,000 ms verdict timeout with a
circuit breaker behind it; a telemetry firehose sharing that event loop
turns a slow scan of a 60 KB API body into a webhook failure, which fails
the user's request rather than merely missing a finding.

PRIVACY, and this is the strictest instance of it in the project: every
other adapter sees content that is already governed, while this one
receives raw prompt text, tool parameters and file paths for surfaces where
Anthropic redacts nothing by default. The body is scanned in memory and
dropped. It is never written to disk, never logged at any level -- including
on the error path, which is where this normally leaks -- and never stored.
Findings only: detector, locator, one-way digest.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import time
from collections.abc import Callable

from .. import build_id
from ..applog import configure_logging, exc_fields, warn_if_unsalted
from ..core import UNSCANNED, UNSCANNED_CAPPED, left_out_tiers
from ..detectors.gitleaks import HEALTHZ_TIMEOUT_S, daemon_state, livez
from ..metadata import MetadataGuard
from ..models import env_or_literal, pseudonym
from ..orgregistry import publish_registry
from ..overrides import cold, reader_for, readiness
from ..plugins import loaded_distributions
from ..policy import Policy, load_policy, warn_unset_credentials
from .collect import collect
from .extract import agent_services
from .payload import (
    ENCODINGS,
    MAX_RECORDS,
    SIGNAL_LOGS,
    SIGNAL_TRACES,
    DecodedTooLarge,
    DecodeError,
    InflatedTooLarge,
    TooManyRecords,
    decode,
    inflate,
    metric_names,
)

# OTLP's own paths. The collector endpoint an admin configures is a base
# URL; the exporter appends these.
PATH_LOGS = "/v1/logs"
PATH_TRACES = "/v1/traces"
# Accepted, not scanned -- see _ingest_metrics. An OTLP exporter sends every
# enabled signal to the same base endpoint, so this arrives whether or not
# anyone asked for it, and a 404 is a delivery failure it retries forever.
PATH_METRICS = "/v1/metrics"
INGEST_PATHS = (PATH_LOGS, PATH_TRACES, PATH_METRICS)

# Distinct names held by each diagnostic table on /stats: refused origins,
# metric names, unrecognised attributes. A new name past this is counted in
# `<table>_overflow` and not kept.
MAX_DIAGNOSTIC_KEYS = 500
# Exports decoded and scanned at once, by default (`otel.export_workers`).
EXPORT_WORKERS = 4
# How long an export holding a slot may take to send its body.
BODY_READ_TIMEOUT_S = 30.0

# CORS, and why it is permissive.
#
# Office add-ins run as HTML/JS in an embedded WebView -- inside desktop
# Excel, Word and PowerPoint, not a browser tab -- and a WebView enforces
# CORS exactly like one. So their exporter sends `OPTIONS /v1/traces`
# first, and this service answered 405 to everything that was not a POST.
# The preflight failed, the WebView never sent the POST, and the collector
# saw nothing at all: 29 preflights, zero exports, counters at zero,
# indistinguishable from a surface that was never configured. Cowork's
# exporter is server-side, sends no preflight, and worked throughout --
# which is what made this look like an office-agent problem rather than a
# CORS one.
#
# `*` by default, deliberately. CORS protects a browser user from a page
# acting with their ambient credentials; there are none here. The bearer
# token is a header the caller must supply, and a page that does not have
# it gets 401 whatever the origin says. Narrowing the default would buy
# nothing a token does not already buy, and getting it wrong costs total
# silent telemetry loss -- which is the failure this whole comment is
# about. Narrow it with `otel.cors_origins` if a deployment wants to.
DEFAULT_CORS_ORIGINS = ("*",)


class Collector:
    def __init__(
        self,
        policy: Policy | None = None,
        *,
        logger=None,
        detectors=None,
        store=None,
        late_detectors=None,
    ):
        self.policy = (policy or load_policy()).for_profile("otel")
        self.log = logger or configure_logging(
            str(self.policy.server.get("log_level", "INFO"))
        )
        self.detectors = (
            detectors if detectors is not None else self.policy.build_detectors(profile="collector")
        )
        # `collect` reports the tier dropped on every record; this logs it once.
        left_out_tiers(self.policy, self.detectors, "collector")
        self.gitleaks_sockets = [s for s in [self.policy.gitleaks_daemon()] if s]
        self.config = self.policy.otel
        # Adapter 5, top-level rather than under `otel`: a sink is a
        # destination for this deployment and not a property of the OTLP
        # receiver. When a second control point learns to forward, it
        # reads the same list.
        self.sinks_config = self.policy.sinks
        self.tokens = _token_map(self.config)
        self.agents = agent_services(self.config)
        self.max_body = int(self.config.get("max_body_bytes", 8 * 1024 * 1024))
        workers = int(self.config.get("export_workers", EXPORT_WORKERS))
        if workers < 1:
            raise ValueError(f"otel.export_workers is {workers}; it must be at least 1")
        self._exporting = asyncio.Semaphore(workers)
        self.budget_ms = float(
            (self.policy.raw.get("otel", {}).get("scan", {}) or {}).get(
                "budget_ms", self.policy.budget_ms
            )
        )
        self.salt = self.policy.hash_salt
        self.meta = MetadataGuard(self.detectors, self.salt, allow_subprocess=True)
        self.metrics_token = self.policy.metrics_token
        origins = self.config.get("cors_origins")
        self.cors_origins = tuple(
            str(o) for o in origins
        ) if isinstance(origins, list) and origins else DEFAULT_CORS_ORIGINS

        if store is None:
            spec = self.config.get("store") or self.policy.server.get("store")
            if spec:
                from ..store import open_store

                store = open_store(str(spec), plugins=self.policy.plugin_allow,
                                   profile="collector")
        from ..store.sink import StoreSink

        self.policy.refuse_unsalted("collector")
        self.sink = StoreSink(
            store,
            salt=self.salt,
            batch_size=int(self.config.get("store_batch_size", 50)),
            flush_interval_s=float(self.config.get("store_flush_s", 30)),
            max_queue=2 * MAX_RECORDS,
            hold_failed=True,
        )
        # Adapter 5. Empty unless `sinks:` is configured, and nothing is
        # built or run when it is absent. Built BEFORE serving starts so a
        # sink that names a redaction tier this deployment does not run
        # stops the process here rather than forwarding uncensored.
        from ..sink.factory import (
            build_forwarders,
            emitted_ids,
            sinks_may_need_late,
        )

        if late_detectors is None:
            late_detectors = (
                self._late_detectors()
                if sinks_may_need_late(self.sinks_config) else []
            )
        self.forwarders = build_forwarders(
            self.sinks_config, emitted_ids(self.detectors),
            cheap_detectors=self.detectors, late_detectors=late_detectors,
            org_labels=[str(o.get("label") or "unnamed")
                        for o in (self.config.get("orgs") or [])
                        if isinstance(o, dict)],
            org_ids=_ids_by_label(self.config.get("orgs") or []),
            plugins=self.policy.plugin_allow, profile="collector",
        )

        self._started = time.time()
        # A session's findings are recorded once, however many cumulative
        # request bodies re-send them.
        from .collect import SeenFindings

        self._seen = SeenFindings()
        self._unrecognised: dict[str, int] = {}
        self._counts: dict[str, int] = {}
        # Origins whose preflight was refused, and metric names seen.
        # Both are names, never content -- and both answer a question
        # that is otherwise only visible in a WebView's own console.
        self._origins: dict[str, int] = {}
        self._metrics_seen: dict[str, int] = {}

        self.log.info(
            "otel collector ready",
            extra={
                "fields": {
                    "detectors": [d.name for d in self.detectors],
                    "orgs_configured": len(self.tokens),
                    "agents": sorted(self.agents),
                    "budget_ms": self.budget_ms,
                    "store": "enabled" if self.sink.enabled else "disabled",
                    "sinks": [f.config.name for f in self.forwarders],
                    **({"build": build_id()} if loaded_distributions() else {}),
                }
            },
        )
        warn_if_unsalted(self.log, self.policy)
        warn_unset_credentials(self.log, self.policy, "collector")
        if self.sink.store is not None:
            publish_registry(self.sink.store, self.policy, "collector", self.log)
        # Read for its status only: no allowlisted key applies to the collector.
        self.overrides = reader_for(self.policy.raw, self.sink.store, "collector",
                                    log=self.log)
        self.overrides.refresh()
        if not self.tokens:
            # Fail closed and say so. With no token configured there is no
            # org to attribute anything to, so every export is refused --
            # which is correct, and completely opaque unless it is stated.
            self.log.error(
                "no org tokens configured; every export will be refused with 401",
                extra={"fields": {"remediation": "set otel.orgs[].token"}},
            )

    # -- ASGI ------------------------------------------------------------

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":  # pragma: no cover - websockets not served
            return
        method = scope.get("method", "GET")
        path = (scope.get("path") or "/").rstrip("/") or "/"

        if method == "GET" and path == "/stats":
            # The question this exists to answer: did anything arrive, and on
            # which signal. Without it, "office agents are not sending" and
            # "they are sending and we reject it" look identical -- successful
            # exports are not logged, deliberately, because logging this
            # service's request bodies is how prompt text escapes.
            #
            # Fail closed like the verdict server's /metrics: with no token
            # configured the endpoint does not exist. It reports volumes and
            # attribute NAMES, never content, but a deny rate is still not
            # something to publish by default.
            status = self._stats_authorized(_lower_headers(scope.get("headers") or []))
            if status != 200:
                error = "unauthorized" if status == 401 else "not_found"
                await self._json(send, status, {"error": error})
                return
            await self._json(send, 200, await asyncio.to_thread(self.stats))
            return
        if method == "GET" and path in ("/healthz", "/health"):
            await self._json(
                send,
                200,
                {
                    "status": "ok",
                    "build": build_id(),
                    "orgs_configured": len(self.tokens),
                    "agents": sorted(self.agents),
                    "gitleaksd": await daemon_state(self.gitleaks_sockets,
                                                    HEALTHZ_TIMEOUT_S),
                    "uptime_s": round(time.time() - self._started, 1),
                },
            )
            return
        if method == "GET" and path == "/readyz":
            await self._json(send, *readiness(self.overrides))
            return
        if method == "GET" and path == "/livez":
            await self._json(send, *await livez(self.gitleaks_sockets))
            return
        # The preflight, BEFORE the method check, which would answer 405.
        #
        # A WebView will not send the POST unless this succeeds, so a 405
        # here is total silent telemetry loss for every add-in surface --
        # and it looks exactly like a surface nobody configured.
        if method == "OPTIONS" and path in INGEST_PATHS:
            headers = _lower_headers(scope.get("headers") or [])
            self.bump("preflight")
            await self._no_content(send, self._cors(headers.get("origin", ""), True))
            return
        if method != "POST":
            await self._json(send, 405, {"error": "method_not_allowed"})
            return
        if path == PATH_LOGS:
            await self._ingest(scope, receive, send, SIGNAL_LOGS)
            return
        if path == PATH_TRACES:
            await self._ingest(scope, receive, send, SIGNAL_TRACES)
            return
        if path == PATH_METRICS:
            await self._ingest_metrics(scope, receive, send)
            return
        await self._json(send, 404, {"error": "not_found"})

    # -- CORS --------------------------------------------------------------

    def _cors(self, origin: str, preflight: bool = False) -> list[tuple[bytes, bytes]]:
        """Headers for a cross-origin caller, or none if it is not allowed."""
        allowed = "*" in self.cors_origins
        if not allowed and origin and origin in self.cors_origins:
            allowed = True
        if not allowed:
            # Recorded, because a rejected origin is invisible otherwise:
            # the WebView reports a CORS error to its own console and we
            # see a preflight that went nowhere. The ORIGIN only, which is
            # a scheme and host, never a body.
            if origin:
                # Cleaned when /stats is read, off the event loop. This
                # runs before the request is authenticated.
                origin = self.meta.bounded(origin)
                self._tally(self._origins, origin, "refused_origins_overflow")
            return []
        value = "*" if "*" in self.cors_origins else origin
        out = [(b"access-control-allow-origin", value.encode())]
        if preflight:
            out += [
                (b"access-control-allow-methods", b"POST, OPTIONS"),
                # The exporter sends both. Listing them is required: a
                # preflight that omits `authorization` fails for a request
                # that carries one, which is every request here.
                (b"access-control-allow-headers", b"authorization, content-type"),
                # Without this a WebView preflights every single export.
                (b"access-control-max-age", b"600"),
            ]
        return out

    async def _no_content(self, send: Callable, headers: list) -> None:
        await send({"type": "http.response.start", "status": 204,
                    "headers": [(b"content-length", b"0"), *headers]})
        await send({"type": "http.response.body", "body": b""})

    async def _ingest_metrics(self, scope: dict, receive: Callable, send: Callable) -> None:
        """Accept OTLP metrics. Never scanned, never stored.

        A metric carries measurements and attribute keys, not message
        content, so there is nothing for a detector to find. But an
        exporter sends every enabled signal to the same base endpoint, so
        this arrives regardless -- and answering 404, as this did, is a
        delivery failure it retries forever while an operator reads it as
        the collector being broken.

        The NAMES are recorded so /stats can say what is being sent. That
        is what a metrics view would be built from, and it is the
        difference between "nothing arrives" and "something does and we
        drop it".
        """
        headers = _lower_headers(scope.get("headers") or [])
        org = self._authorize(headers)
        if org is None:
            self.bump("unauthorized")
            await self._json(send, 401, {"error": "unauthorized"},
                             self._cors(headers.get("origin", "")))
            return
        if not await self._encoding_supported(headers, send):
            return
        if not await self._export_slot(headers, send):
            return
        async with self._exporting:
            await self._read_metrics(headers, receive, send)

    async def _read_metrics(self, headers: dict[str, str], receive: Callable,
                            send: Callable) -> None:
        """The rest of `_ingest_metrics`, holding an export slot."""
        body, oversized = await self._read_body(receive, headers, send)
        if body is None:
            return
        if not oversized:
            try:
                body = await asyncio.to_thread(
                    inflate, body, headers.get("content-encoding", ""), self.max_body)
            except InflatedTooLarge:
                oversized = True
            except DecodeError:
                body = b""
        if oversized:
            await self._json(send, 413, {"error": "payload_too_large"},
                             self._cors(headers.get("origin", "")))
            return
        names = await asyncio.to_thread(metric_names, body, headers.get("content-type", ""))
        for name in (self.meta.bounded(n) for n in names):
            self._tally(self._metrics_seen, name, "metrics_names_overflow")
        self.bump("metrics_accepted")
        await self._json(send, 200, {"partialSuccess": {}},
                         self._cors(headers.get("origin", "")))

    async def _export_slot(self, headers: dict[str, str], send: Callable) -> bool:
        """Whether an export slot is free; if not, answers 503 busy with
        Retry-After, before the body is read."""
        if not self._exporting.locked():
            return True
        self.bump("busy")
        await self._json(send, 503, {"error": "busy"},
                         extra_headers=[(b"retry-after", b"5"),
                                        *self._cors(headers.get("origin", ""))])
        return False

    async def _read_body(self, receive: Callable, headers: dict[str, str],
                         send: Callable) -> tuple[bytes | None, bool]:
        """`_read_body` within BODY_READ_TIMEOUT_S. Past it, answers 503
        with Retry-After and returns (None, False)."""
        try:
            return await asyncio.wait_for(_read_body(receive, self.max_body),
                                          BODY_READ_TIMEOUT_S)
        except TimeoutError:
            self.bump("body_timeout")
            await self._json(send, 503, {"error": "body_timeout"},
                             extra_headers=[(b"retry-after", b"5"),
                                            *self._cors(headers.get("origin", ""))])
            return None, False

    def _export_slots_free(self) -> int:
        """Export slots not held."""
        return self._exporting._value

    async def _encoding_supported(self, headers: dict[str, str], send: Callable) -> bool:
        """Whether `inflate` reads the request's Content-Encoding; if not,
        answers 415 naming the ones it reads."""
        encoding = headers.get("content-encoding", "").strip().lower()
        if encoding in ("", *ENCODINGS):
            return True
        self.bump("unsupported_encoding")
        await self._json(send, 415, {"error": "unsupported_content_encoding",
                                     "supported": list(ENCODINGS)},
                         self._cors(headers.get("origin", "")))
        return False

    async def _lifespan(self, receive: Callable, send: Callable) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                self.overrides.start()
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                self.close()
                await send({"type": "lifespan.shutdown.complete"})
                return

    # -- ingest ----------------------------------------------------------

    async def _ingest(
        self, scope: dict, receive: Callable, send: Callable, signal: str
    ) -> None:
        headers = _lower_headers(scope.get("headers") or [])

        # Authenticate BEFORE reading the body. An unauthenticated sender
        # should not be able to make this process hold 8 MB of prompt text
        # in memory, nor to probe decoding behaviour.
        org = self._authorize(headers)
        if org is None:
            self.bump("unauthorized")
            await self._json(send, 401, {"error": "unauthorized"},
                             self._cors(headers.get("origin", "")))
            return

        reason = cold(self.overrides)
        if reason is not None:
            self.bump("overrides_not_ready")
            self.log.error("runtime overrides not ready; refusing the export",
                           extra={"fields": {"reason": reason, "org": self._org_ref(org)}})
            await self._json(send, 503, {"error": "not_ready", "reason": reason},
                             self._cors(headers.get("origin", "")))
            return

        if self.sink.degraded:
            await self._store_unavailable(headers, send)
            return
        if not await self._encoding_supported(headers, send):
            return
        if not await self._export_slot(headers, send):
            return
        async with self._exporting:
            await self._read_export(headers, receive, send, signal, org)

    async def _read_export(self, headers: dict[str, str], receive: Callable,
                           send: Callable, signal: str, org: dict) -> None:
        """The rest of `_ingest`, holding an export slot."""
        body, oversized = await self._read_body(receive, headers, send)
        if body is None:
            return
        undecodable = None
        if not oversized:
            try:
                body = await asyncio.to_thread(
                    inflate, body, headers.get("content-encoding", ""), self.max_body)
            except InflatedTooLarge:
                oversized = True
            except DecodeError as exc:
                undecodable = exc
        if oversized:
            self.bump("oversized")
            self.log.warning(
                "export body exceeded max_body_bytes",
                extra={"fields": {"max_body_bytes": self.max_body,
                                  "org": self._org_ref(org)}},
            )
            await self._json(send, 413, {"error": "payload_too_large"},
                             self._cors(headers.get("origin", "")))
            return

        try:
            if undecodable is not None:
                raise undecodable
            records = await asyncio.to_thread(
                decode, body, headers.get("content-type", ""), signal)
        except TooManyRecords:
            # Refused whole: nothing in the body is scanned or stored, and a
            # 503 tells the exporter to retry.
            self.bump("too_many_records")
            self.log.warning(
                "export carried more records than one batch may; refusing it whole",
                extra={"fields": {"signal": signal, "org": self._org_ref(org),
                                  "max_records": MAX_RECORDS}},
            )
            await self._json(
                send, 503,
                {"error": "too_many_records",
                 "detail": f"an export may carry at most {MAX_RECORDS} records; "
                           "nothing in this one was scanned or stored. "
                           "Send smaller batches."},
                extra_headers=[(b"retry-after", b"30"),
                               *self._cors(headers.get("origin", ""))],
            )
            return
        except DecodedTooLarge:
            # Refused whole, as TooManyRecords.
            self.bump("decoded_too_large")
            self.log.warning(
                "export values rendered past the decode budget; refusing it whole",
                extra={"fields": {"signal": signal, "org": self._org_ref(org)}},
            )
            await self._json(
                send, 503,
                {"error": "decoded_too_large",
                 "detail": "the attribute values in this export render to more text "
                           "than one batch may; nothing in it was scanned or stored. "
                           "Send smaller batches or flatter values."},
                extra_headers=[(b"retry-after", b"30"),
                               *self._cors(headers.get("origin", ""))],
            )
            return
        except DecodeError as exc:
            # Deliberately not the exception's message verbatim in the log:
            # a decoder error can quote the bytes it choked on, and those
            # bytes are someone's prompt.
            self.bump("undecodable")
            self.log.warning(
                "undecodable export body",
                extra={"fields": {"signal": signal, "org": self._org_ref(org),
                                  "reason": type(exc).__name__}},
            )
            # 400 is right here and only here: a body we cannot parse will
            # not parse on retry either, so asking the exporter to send it
            # again wastes both sides. Transient failures below return 503.
            await self._json(send, 400, {"error": "undecodable"},
                             self._cors(headers.get("origin", "")))
            return
        finally:
            del body

        # EVERY distinct claim, not the first non-empty one. `next(...)`
        # stopped at the first, so a batch whose first resource matched
        # and whose second claimed another org was accepted whole:
        #
        #   mixed batch, first matches, second evil  -> 200
        #   single mismatched claim (control)        -> 403
        #
        # Both records landed under the TOKEN's org, so it is a bypass of
        # the check rather than tenant selection -- the sender defeats the
        # refusal but cannot choose where records go.
        # From the attributes and the resource both: `OtelRecord.get` returns
        # the first non-empty one and never shows the other.
        claims = {c for r in records for where in (r.attributes, r.resource)
                  if (c := where.get("organization.id"))}
        if "ids" in org:
            refusal = self._fleet_refusal(org, records, claims)
            if refusal is not None:
                await self._json(send, 403, {"error": refusal},
                                 self._cors(headers.get("origin", "")))
                return
            if not records:
                # No record, so no org to file under and nothing to scan.
                self.bump("accepted")
                await self._json(send, 200, {"partialSuccess": {}},
                                 self._cors(headers.get("origin", "")))
                return
            org = {"id": next(iter(claims)), "label": org["label"]}
        mismatched = sorted(c for c in claims if c != org["id"])
        if mismatched and org["id"]:
            claimed = ", ".join(pseudonym(c, self.salt, "org") for c in mismatched)
            # The token is what we issued; the attribute is what the sender
            # says. Trusting the attribute would let one org's export file
            # findings under another org's name.
            self.bump("org_mismatch")
            self.log.warning(
                "organization.id does not match the token's org; refusing",
                extra={"fields": {"token_org": self._org_ref(org), "claimed": claimed}},
            )
            await self._json(send, 403, {"error": "organization_mismatch"},
                             self._cors(headers.get("origin", "")))
            return

        seen_added: list = []
        forward = (self._forward_group(org["id"])
                   if self.forwarders else None)
        try:
            # In a worker thread. A batch is many groups at up to the scan
            # budget each, and run on the event loop it held /livez and
            # /health for the whole batch: long enough for the liveness
            # probe to restart the collector mid-export.
            verdicts, unknown = await asyncio.to_thread(
                collect,
                records,
                self.detectors,
                budget_ms=self.budget_ms,
                salt=self.salt,
                org_id=org["id"],
                on_group=forward,
                on_done=forward.finish if forward is not None else None,
                seen=self._seen,
                seen_added=seen_added,
                agents=self.agents,
                meta=self.meta,
                policy=self.policy,
            )
            accepted = self.sink.submit_records(verdicts)
        except Exception as exc:
            self._seen.forget(seen_added)
            # An exporter drops a batch on 4xx and retries on 5xx, so a
            # transient failure must be a 5xx. A 400 here would discard
            # findings and look like success to the sender.
            self.bump("scan_failed")
            self.log.error("failed to scan or record an export",
                           extra={"fields": exc_fields(exc)})
            await self._json(
                send, 503, {"error": "unavailable"},
                extra_headers=[(b"retry-after", b"5"),
                               *self._cors(headers.get("origin", ""))],
            )
            return
        if not accepted:
            # The sender retries this batch, so its findings must not count
            # as recorded.
            self._seen.forget(seen_added)
            if self.sink.degraded:
                await self._store_unavailable(headers, send)
                return
            # Backpressure rather than silence: the writer is behind, and
            # the exporter holding the batch is a better buffer than this
            # process pretending it stored something.
            self.bump("queue_full")
            await self._json(
                send, 503, {"error": "busy"},
                extra_headers=[(b"retry-after", b"10"),
                               *self._cors(headers.get("origin", ""))],
            )
            return

        for key in unknown:
            self._tally(self._unrecognised, self.meta.bounded(key),
                        "unrecognised_attributes_overflow")
        self.bump("accepted")
        self.bump(f"records_{signal}", len(records))
        self.bump("findings", sum(v.findings_count for v in verdicts))
        self.bump("tiers_dropped", sum(1 for v in verdicts if v.tiers_dropped))
        self.bump("oversize_unscanned",
                  sum(1 for v in verdicts if UNSCANNED in v.tiers_dropped
                      or UNSCANNED_CAPPED in v.tiers_dropped))
        await self._json(send, 200, {"partialSuccess": {}},
                         self._cors(headers.get("origin", "")))

    async def _store_unavailable(self, headers: dict[str, str], send: Callable) -> None:
        """503 `store_unavailable`: the store writer holds a batch it could
        not write, and takes nothing more until it has written it."""
        self.bump("store_unavailable")
        await self._json(
            send, 503, {"error": "store_unavailable"},
            extra_headers=[(b"retry-after", b"15"),
                           *self._cors(headers.get("origin", ""))],
        )

    def _fleet_refusal(self, org: dict, records: list, claims: set[str]) -> str | None:
        """Why a batch on a fleet token cannot be filed under one org of its
        set, counted and logged, or None when it can."""
        if any(not (r.attributes.get("organization.id") or r.resource.get("organization.id"))
               for r in records):
            error, counter, message = ("organization_missing", "org_missing",
                                       "a record on a fleet token claims no organization.id")
        elif claims - org["ids"]:
            error, counter, message = ("organization_mismatch", "org_mismatch",
                                       "organization.id is not in the fleet token's orgs")
        elif len(claims) > 1:
            error, counter, message = ("organization_mixed", "org_mixed",
                                       "a batch on a fleet token claims more than one org")
        else:
            return None
        self.bump(counter)
        self.log.warning(f"{message}; refusing", extra={"fields": {
            "token": org["label"],
            "claimed": ", ".join(sorted(pseudonym(c, self.salt, "org") for c in claims))}})
        return error

    def _org_ref(self, org: dict) -> str | None:
        """The org as a log line names it: its store pseudonym."""
        return pseudonym(org["id"], self.salt, "org")

    def _authorize(self, headers: dict[str, str]) -> dict | None:
        supplied = ""
        auth = headers.get("authorization", "")
        if auth.startswith("Bearer "):
            supplied = auth[len("Bearer "):]
        elif auth:
            supplied = auth
        else:
            # Anthropic's console takes OTLP headers as `key=value` pairs,
            # so an operator may configure a bare header rather than
            # Authorization. Accept both rather than make the difference a
            # silent 401.
            supplied = headers.get("x-forgd-token", "")
        if not supplied:
            return None
        for token, org in self.tokens.items():
            if _equal(supplied, token):
                return org
        return None

    def _stats_authorized(self, headers: dict[str, str]) -> int:
        """200 to serve, 404 when disabled, 401 on a bad token."""
        token = self.metrics_token
        if not token:
            return 404
        supplied = headers.get("authorization", "")
        prefix = "Bearer "
        if not supplied.startswith(prefix):
            return 401
        return 200 if _equal(supplied[len(prefix):], token) else 401

    def bump(self, key: str, n: int = 1) -> None:
        self._counts[key] = self._counts.get(key, 0) + n

    def _tally(self, table: dict[str, int], key: str, overflow: str) -> None:
        """Count `key` in `table`, or bump `overflow` if `key` is new and
        `table` already holds MAX_DIAGNOSTIC_KEYS names."""
        if key in table or len(table) < MAX_DIAGNOSTIC_KEYS:
            table[key] = table.get(key, 0) + 1
        else:
            self.bump(overflow)

    def _late_detectors(self) -> list:
        """Tiers built for redaction only, from `otel.sink_detectors`.

        Merged over the top-level `detectors:` like a profile, and only
        tiers at T2 and above are kept: the cheap ones already run inline.
        Built only when a sink is configured, because loading Presidio and
        its spaCy model costs seconds and about a gigabyte.
        """
        from ..detectors.base import TIER_T2
        from ..policy import _deep_merge

        extra = (self.policy.raw.get("otel") or {}).get("sink_detectors") or {}
        if not extra:
            return []
        pol = self.policy.derive(_deep_merge(self.policy.raw, {"detectors": extra}))
        return [d for d in pol.build_detectors(salt=self.salt, profile="collector")
                if getattr(d, "tier", 0) >= TIER_T2]

    def _forward_group(self, org_id: str) -> _ExportForwarder:
        """The adapter-5 hook for one export, handed to `collect`."""
        return _ExportForwarder(self, org_id)

    def stats(self) -> dict:
        counts = dict(self._counts)
        return {
            "uptime_s": round(time.time() - self._started, 1),
            "orgs_configured": len(self.tokens),
            # Split out because it is the first question asked of this
            # service: traces are the office agents, logs are Cowork and
            # Claude Code. A zero here is the difference between "not
            # configured" and "configured and failing".
            "metrics_names": self.meta.clean_keys(dict(self._metrics_seen),
                                                  where="otel:metric-name"),
            # Origins whose preflight was REFUSED. Empty is the healthy
            # state; a name here is a surface being silently blocked.
            "refused_origins": self.meta.clean_keys(dict(self._origins),
                                                    where="otel:origin"),
            # Adapter 5, absent when no sink is configured. `dropped` is
            # the number that matters: a sink drops rather than blocking
            # ingest, so a downstream outage is invisible upstream and
            # this counter is the only place it shows.
            "sinks": [f.stats() for f in self.forwarders],
            # `held` is the failed batch the writer is retrying; while it is
            # non-zero, exports are answered 503 `store_unavailable`.
            "store": {"written": self.sink.written, "dropped": self.sink.dropped,
                      "errors": self.sink.errors, "held": self.sink.stats()["held"]},
            "records_logs": counts.get("records_logs", 0),
            "records_traces": counts.get("records_traces", 0),
            "counts": {**counts, "metadata_redacted": self.meta.redacted},
            # A rename upstream shows up as this rising, rather than
            # as findings quietly going to zero.
            "unrecognised_attributes": dict(self._unrecognised),
            "runtime_overrides": self.overrides.current().fields(),
        }

    def close(self) -> None:
        self.overrides.stop()
        self.sink.close()
        for fwd in self.forwarders:
            fwd.close()

    # -- responses -------------------------------------------------------

    async def _json(
        self, send: Callable, status: int, payload: dict, extra_headers=None
    ) -> None:
        body = json.dumps(payload).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        headers.extend(extra_headers or [])
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


class _ExportForwarder:
    """One export's groups, on their way to every configured sink.

    Calling it queues a group: the RAW records with the in-memory findings,
    which still carry spans. `finish` redacts every queued group, per sink,
    in one `redact_groups` call and offers the result once; a sink with a
    late stage is offered one `LateJob` holding them all. Detection has
    already happened by this point and is unaffected by what any sink
    censors.
    """

    def __init__(self, collector: Collector, org_id: str) -> None:
        self._collector = collector
        self._org_id = org_id
        self._groups: list[tuple[list, list, str, tuple[str, ...]]] = []

    def __call__(self, members, findings, surface, skipped=()) -> None:
        self._groups.append((list(members), list(findings), surface, tuple(skipped)))

    def finish(self) -> None:
        from ..sink.late import LateGroup, LateJob
        from ..sink.redact import RedactGroup, index_findings, redact_groups
        from ..store.base import utcnow

        groups, self._groups = self._groups, []
        if not groups:
            return
        now = utcnow()
        for fwd in self._collector.forwarders:
            try:
                if not fwd.accepts(self._org_id):
                    fwd.out_of_scope += sum(len(g[0]) for g in groups)
                    continue
                if fwd.late is not None:
                    # Slow tiers run in the sink's own worker, after the
                    # 200. The ingest path only queues.
                    fwd.late.offer(LateJob(
                        [LateGroup(m, f, s, sk) for m, f, s, sk in groups],
                        self._org_id, now))
                    continue
                events = redact_groups(
                    [RedactGroup(m, index_findings(f), s, sk) for m, f, s, sk in groups],
                    fwd.plan, fwd.config, org=self._org_id, observed_at=now,
                    detectors=self._collector.detectors)
                fwd.pipeline.offer(events)
            except Exception as exc:
                self._collector.log.warning(
                    "sink hook failed",
                    extra={"fields": {"sink": fwd.config.name, **exc_fields(exc)}})


def _token_map(config: dict) -> dict[str, dict]:
    from ..models import require_strong_token, usable_secret

    out: dict[str, dict] = {}
    first_index: dict[str, int] = {}
    for index, org in enumerate(config.get("orgs") or []):
        if not isinstance(org, dict):
            continue
        # usable_secret, not env_or_literal: a placeholder is non-empty and
        # a bearer token has no format to fail, so the public placeholder
        # would otherwise be a working credential for anyone who read the
        # repository. An org with no real token is simply not configured.
        label = str(org.get("label") or "unnamed")
        fleet = org.get("ids") is not None
        if fleet:
            if org.get("id") is not None:
                raise ValueError(
                    f"otel.orgs entry {label!r} sets both id and ids; set id for "
                    "one org's token or ids for a fleet token valid for several")
            if not isinstance(org["ids"], list) or not org["ids"]:
                raise ValueError(
                    f"otel.orgs entry {label!r}: ids must be a non-empty list of "
                    "org ids, each a $FORGD_ORG_ID_<NAME> reference")
        token = usable_secret(env_or_literal(org.get("token")))
        if not token:
            continue
        require_strong_token(f"otel.orgs[{label!r}].token", token)
        token = str(token)
        if token in out:
            raise ValueError(
                f"otel.orgs[{first_index[token]}] ({out[token]['label']!r}) and "
                f"otel.orgs[{index}] ({label!r}) have the same token; each entry needs "
                "its own, or one entry's exports are attributed to the other")
        first_index[token] = index
        if fleet:
            out[token] = {"ids": _fleet_ids(label, org["ids"]), "label": label}
            continue
        org_id = str(env_or_literal(org.get("id")) or "")
        if not org_id:
            # A token with no org id disables the cross-check against the
            # payload's `organization.id`, so any org's batch is accepted
            # on a valid token. CLAUDE.md names this as load-bearing.
            #
            # Refused, not warned. The Helm chart refuses an `orgIds` value
            # that is empty or not a UUID, and a `secrets.otelTokens` entry
            # with no `orgIds` entry; the Terraform modules refuse the same
            # for `org_ids` and their token maps. A deployment through
            # neither had nothing stopping it, and the only other startup
            # diagnostic fires when there are NO tokens at all -- so this
            # org looked identical to a correct one in the log.
            raise ValueError(
                f"otel.orgs entry {label!r} has a token but no id. With the "
                "id empty the cross-check against the payload's "
                "organization.id cannot run and any org's batch is accepted "
                "on this token. Set it, or remove the entry."
            )
        out[token] = {"id": org_id, "label": label}
    return out


def _ids_by_label(orgs: list) -> dict[str, set[str]]:
    """`{label: org ids}` over `otel.orgs`: each entry's `id`, or each of its
    `ids`, resolved. An id that resolves to nothing is left out."""
    out: dict[str, set[str]] = {}
    for org in orgs:
        if not isinstance(org, dict):
            continue
        ids = org["ids"] if isinstance(org.get("ids"), list) else [org.get("id")]
        resolved = {str(v) for i in ids if isinstance(i, str) and (v := env_or_literal(i))}
        out.setdefault(str(org.get("label") or "unnamed"), set()).update(resolved)
    return out


def _fleet_ids(label: str, raw: list) -> frozenset[str]:
    """Each element of an entry's `ids`, resolved. Raises ValueError on one
    that resolves to nothing or repeats another."""
    ids: list[str] = []
    for i, element in enumerate(raw):
        org_id = str(env_or_literal(element) or "") if isinstance(element, str) else ""
        if not org_id:
            raise ValueError(
                f"otel.orgs entry {label!r}: ids[{i}] resolves to nothing. Set the "
                "variable, or remove the element.")
        if org_id in ids:
            raise ValueError(
                f"otel.orgs entry {label!r}: ids[{i}] repeats ids[{ids.index(org_id)}]")
        ids.append(org_id)
    return frozenset(ids)


def _equal(a: str, b: str) -> bool:
    """Constant-time comparison of two tokens as UTF-8 bytes."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _lower_headers(raw) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in raw}


async def _read_body(receive: Callable, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunk = message.get("body") or b""
        total += len(chunk)
        if total > limit:
            return b"".join(chunks), True
        chunks.append(chunk)
        if not message.get("more_body"):
            break
    return b"".join(chunks), False


def create_app(policy: Policy | None = None, **kwargs) -> Collector:
    return Collector(policy, **kwargs)
