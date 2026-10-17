"""Adapter 1: the Inference hooks verdict server.

A pure-ASGI application (no web framework) so the hot path stays stdlib.
Run it with uvicorn behind a TLS-terminating reverse proxy.

Protocol contract implemented here, verified 2026-09-17 against
platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint:

  * POST to any path -- the whole configured URL is the endpoint.
  * Respond HTTP 200 + JSON for BOTH allow and deny. A non-200 is a webhook
    failure, not a deny, and sustained failures trip the circuit breaker.
  * Unknown top-level `type` -> allow, never an error status.
  * Unknown block types and unknown fields -> read what you know, reject
    nothing.
  * `source.application == "config-test"` is the connection test and the
    circuit-breaker recovery probe. Answer it normally.
  * Dedupe on `webhook-id`; the single connection-failure retry reuses it.
  * Bodies up to 64 MiB; responses read to 64 KiB, uncompressed, no redirects.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

from .. import build_id
from ..applog import TimingCSV, configure_logging, exc_fields, warn_if_unsalted
from ..budget import Budget
from ..cache import InMemoryLRUCache
from ..core import (
    UNSCANNED,
    UNSCANNED_CAPPED,
    _scrub,
    decide,
    left_out_tiers,
    scan,
    scan_frame,
    with_left_out,
)
from ..detectors.gitleaks import HEALTHZ_TIMEOUT_S, daemon_state, livez
from ..extract import frame_units, unknown_frame_units
from ..metadata import MetadataGuard
from ..models import ACTION_ALLOW, ACTION_DENY, Verdict, dedupe_findings, load_json, pseudonym
from ..orgregistry import publish_registry
from ..overrides import KEY_MODE, cold, reader_for, readiness
from ..plugins import loaded_distributions
from ..policy import Policy, load_policy, warn_unset_credentials
from ..store.base import EVENT_OTHER, EVENT_TOOL_CALL
from ..store.sink import StoreSink
from .archive import FrameArchive
from .idempotency import VerdictStore
from .metrics import UNKNOWN_SOURCE, Metrics
from .preauth import Hold, PreAuthBudget
from .signature import SignatureResult, precheck, usable_secrets, verify

ALLOW_BODY = b'{"action": "allow"}'
# The frame `type` Anthropic sends for the tool calls in a model response,
# with Validate tool calls on (docs/PROTOCOL.md).
FRAME_TOOL_CALL = "tool_call"


class VerdictServer:
    def __init__(
        self,
        policy: Policy | None = None,
        *,
        logger=None,
        cache=None,
        metrics: Metrics | None = None,
        csv: TimingCSV | None = None,
        archive: FrameArchive | None = None,
        detectors=None,
        store=None,
    ):
        # The server profile, for the same reason adapter 3 has one: the
        # adapters share a policy file but not a latency budget. Here it is
        # gitleaks -- the daemon is required on this path and optional
        # everywhere else.
        self.policy = (policy or load_policy()).for_profile("server")
        self.log = logger or configure_logging(
            str(self.policy.server.get("log_level", "INFO"))
        )
        self.detectors = (
            detectors if detectors is not None else self.policy.build_detectors(profile="server")
        )
        self.left_out = left_out_tiers(self.policy, self.detectors, "server")
        self.gitleaks_sockets = [s for s in [self.policy.gitleaks_daemon()] if s]
        self.meta = MetadataGuard(self.detectors, self.policy.hash_salt,
                                  allow_subprocess=True)
        self.provenance = self._build_provenance()
        self.cache = cache if cache is not None else InMemoryLRUCache(
            max_sessions=self.policy.cache_max_sessions, ttl_s=self.policy.cache_ttl_s
        )
        self.metrics = metrics or Metrics()
        self.csv = csv if csv is not None else TimingCSV(
            self.policy.server.get("csv_path")
        )
        self.verdicts = VerdictStore(
            ttl_s=float(self.policy.server.get("idempotency_ttl_s", 900)),
            max_entries=int(self.policy.server.get("idempotency_max", 10000)),
        )
        self.baseline_mode = self.policy.mode
        self.archive = archive if archive is not None else FrameArchive(
            self.policy.server.get("archive_dir") if self.baseline_mode == "archive" else None
        )
        # Durable findings sink. Without it, verdict history dies with the
        # replica -- the CSV is on ephemeral disk and /metrics is in-process.
        if store is None and self.policy.server.get("store"):
            from ..store import open_store

            store = open_store(str(self.policy.server["store"]),
                               plugins=self.policy.plugin_allow, profile="server")
        self.policy.refuse_unsalted("verdict server")
        self.required_headers = self.policy.required_headers
        self.sink = StoreSink(
            store,
            salt=self.policy.hash_salt,
            batch_size=int(self.policy.server.get("store_batch_size", 50)),
            flush_interval_s=float(self.policy.server.get("store_flush_s", 60)),
        )
        self.max_body = self.policy.max_body_bytes
        self.preauth = PreAuthBudget(self.policy.preauth_body_budget_bytes)
        self.body_read_timeout_s = self.policy.body_read_timeout_s
        self._started = time.time()
        from ..behaviour.flags import reader_from_policy

        self.flags = reader_from_policy(self.policy, self.sink.store)
        self.overrides = reader_for(self.policy.raw, self.sink.store, "verdict",
                                    baseline={KEY_MODE: self.baseline_mode}, log=self.log)
        self.overrides.refresh()

        self.log.info(
            "verdict server ready",
            extra={
                "fields": {
                    "mode": self.mode,
                    "detectors": [d.name for d in self.detectors],
                    "behaviour": (
                        (["provenance"] if self.provenance and self.provenance.provenance
                         else [])
                        + (["taint"] if self.provenance and self.provenance.taint_severity
                           else [])),
                    "require_signature": self.policy.require_signature,
                    "secrets_configured": len(self.policy.secrets),
                    # Configured != usable. A placeholder value counts as
                    # configured, so reporting only the count made the
                    # first-deploy failure mode opaque: every hook request
                    # 401s while the startup log looks healthy.
                    "secrets_usable": usable_secrets(self.policy.secrets),
                    "budget_ms": self.policy.budget_ms,
                    "max_body_bytes": self.max_body,
                    "preauth_body_budget_bytes": self.preauth.limit,
                    "metrics_endpoint": "enabled" if self.policy.metrics_token else "disabled",
                    "store": "enabled" if self.sink.enabled else "disabled",
                    "runtime_overrides": self.overrides.current().fields(),
                    **({"build": build_id()} if loaded_distributions() else {}),
                }
            },
        )
        warn_if_unsalted(self.log, self.policy)
        warn_unset_credentials(self.log, self.policy, "verdict")
        if self.sink.store is not None:
            publish_registry(self.sink.store, self.policy, "verdict", self.log)
        if not self.policy.require_signature:
            self.log.error(
                "server.require_signature is false: any caller that can reach this "
                "endpoint can submit hook requests without a signature, and their "
                "frames are scanned and answered as if Anthropic sent them",
                extra={"fields": {"remediation": "set server.require_signature: true "
                                                 "and configure server.secrets"}},
            )
        elif not self.policy.secrets:
            self.log.error(
                "require_signature is true but no signing secret is configured; "
                "hook requests will be refused with 503 until one is set",
                extra={"fields": {"remediation": "set server.secrets in policy.yaml"}},
            )
        elif not usable_secrets(self.policy.secrets):
            # The placeholder case. Say it at startup rather than leaving the
            # operator to infer it from a stream of 401s.
            self.log.error(
                "a signing secret is configured but none of them decode to a key; "
                "every hook request will be refused with 401. Expected a value like "
                "whsec_<standard-base64>; check for a placeholder or a truncated paste",
                extra={"fields": {"secrets_configured": len(self.policy.secrets)}},
            )

    # -- ASGI ------------------------------------------------------------

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":  # pragma: no cover - websockets not served
            return
        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        if method == "GET" and path.rstrip("/") == "/metrics":
            # Platforms with all-or-nothing ingress expose this to the
            # internet. deploy/Caddyfile 404s it at the proxy; Container
            # Apps and friends have no equivalent, so the app enforces it.
            status = self._metrics_authorized(_lower_headers(scope.get("headers") or []))
            if status != 200:
                error = "unauthorized" if status == 401 else "not_found"
                await self._json(send, status, {"error": error})
                return
            await self._json(send, 200, self._metrics_body())
            return
        if method == "GET" and path.rstrip("/") in ("/healthz", "/health"):
            await self._json(
                send,
                200,
                {
                    "status": "ok",
                    "mode": self.mode,
                    # Which build is answering. Without this, "the endpoint is
                    # healthy" says nothing about which rule set it holds.
                    "build": build_id(),
                    "gitleaksd": await daemon_state(self.gitleaks_sockets,
                                                    HEALTHZ_TIMEOUT_S),
                    "uptime_s": round(time.time() - self._started, 1),
                },
            )
            return
        if method == "GET" and path.rstrip("/") == "/readyz":
            await self._json(send, *readiness(self.overrides))
            return
        if method == "GET" and path.rstrip("/") == "/livez":
            await self._json(send, *await livez(self.gitleaks_sockets))
            return
        if method != "POST":
            await self._json(send, 405, {"error": "method_not_allowed"})
            return
        await self._handle_hook(scope, receive, send)

    def _metrics_authorized(self, headers: dict[str, str]) -> int:
        """200 to serve, 404 when disabled, 401 on a bad token.

        Fail closed: with no token configured the endpoint does not exist.
        An operator who wants metrics says so explicitly, which is the right
        default when the alternative is publishing your org's deny rate.
        """
        token = self.policy.metrics_token
        if not token:
            return 404
        supplied = headers.get("authorization", "")
        prefix = "Bearer "
        if not supplied.startswith(prefix):
            return 401
        return 200 if _equal(supplied[len(prefix):], token) else 401

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

    # -- hook path --------------------------------------------------------

    async def _handle_hook(self, scope: dict, receive: Callable, send: Callable) -> None:
        t_start = time.perf_counter()
        headers = _lower_headers(scope.get("headers") or [])

        received = await self._receive_verified(headers, receive, send)
        if received is None:
            return
        body, t_recv, sig_reason, webhook_id = received
        t_verify = time.perf_counter()

        # 2. Optional second factor: the static custom request headers the
        #    admin configured on the Anthropic side (up to 16 are supported).
        for name, expected in self.required_headers.items():
            if not _equal(headers.get(name, ""), expected):
                self.metrics.bump("required_header_mismatch")
                self.log.warning(
                    "required request header missing or wrong",
                    extra={"fields": {"header": name,
                                      "request_id": self.meta.opaque(webhook_id)}},
                )
                await self._json(send, 401, {"error": "missing_required_header"})
                return

        # 3. While the overrides reader is cold, answer as an internal error
        #    in enforce would, whatever the mode. Nothing is scanned or
        #    recorded.
        reason = cold(self.overrides)
        if reason is not None:
            self.metrics.bump("overrides_not_ready")
            self.log.error(
                "runtime overrides not ready; answering as an internal error",
                extra={"fields": {"reason": reason,
                                  "request_id": self.meta.opaque(webhook_id)}},
            )
            if self.policy.server.get("on_internal_error", "fail") != "allow":
                await self._json(send, 500, {"error": "scan_failed"})
                return
            await self._json(send, 200, Verdict(action=ACTION_ALLOW).to_wire())
            return

        # 4. Idempotency: replay the recorded verdict for a repeated delivery.
        replay = self.verdicts.get(webhook_id)
        if replay is not None:
            self.metrics.bump("dedupe_hits")
            await self._json(send, 200, replay)
            await asyncio.to_thread(
                self._record_row,
                headers, {}, replay, t_start, t_recv, t_verify, t_verify, t_verify,
                len(body), None, dedupe_hit=True,
            )
            return

        # 5. Parse.
        try:
            frame = load_json(body) if body else {}
            if not isinstance(frame, dict):
                raise ValueError("frame must be a JSON object")
        except (ValueError, RecursionError) as exc:
            self.metrics.bump("unparseable_body")
            self.log.warning(
                "could not parse request body", extra={"fields": {"error": type(exc).__name__}}
            )
            await self._json(send, 400, {"error": "invalid_json"})
            return
        t_parse = time.perf_counter()

        source_app = _source_application(frame)
        frame_type = frame.get("type")

        # 6. A tool call frame, and an unrecognized event type, is scanned
        #    whole and decided like a prompt. A tool call frame holds only the
        #    assistant message with the calls, so the session cache and the
        #    transcript checks, which read a transcript, do not apply.
        whole = frame_type != "prompt"
        unknown = whole and frame_type != FRAME_TOOL_CALL
        if frame_type == FRAME_TOOL_CALL:
            self.metrics.bump("tool_call_frames")
        elif unknown:
            self.metrics.bump("unknown_frame_type")

        # 7. Scan + decide, off the event loop so a gitleaks subprocess or a
        #    multi-megabyte regex pass doesn't stall concurrent verdicts.
        budget = Budget(self.policy.budget_ms)
        mode = self.mode
        try:
            result = await asyncio.to_thread(
                self._scan_flagged, self._scan_whole if whole else self._scan,
                frame, budget)
            result.detectors_skipped = with_left_out(result.detectors_skipped, self.left_out)
            verdict = decide(result.findings, self.policy,
                             dropped=result.detectors_skipped)
        except Exception as exc:
            self.metrics.bump("scan_error")
            try:
                fields = await asyncio.to_thread(
                    self.meta.clean,
                    {"request_id": webhook_id, "source_application": source_app},
                    where="server:log")
            except Exception:  # noqa: BLE001 - opaque() runs no detector
                fields = {"request_id": self.meta.opaque(webhook_id)}
            self.log.error("scan failed", extra={"fields": {**fields, **exc_fields(exc)}})
            # In observe/archive the server is not the gate, so allow. In
            # enforce, `on_internal_error` decides: `fail` returns a non-200
            # so the org's own failure handling applies (fail-open or
            # fail-closed, their choice) rather than us silently allowing.
            on_error = self.policy.server.get("on_internal_error", "fail")
            if mode == "enforce" and on_error == "fail":
                await self._json(send, 500, {"error": "scan_failed"})
                return
            verdict = Verdict(action=ACTION_ALLOW)
            result = None
        t_scan = time.perf_counter()

        shadow_action = verdict.action
        if mode in ("observe", "archive") and verdict.action == ACTION_DENY:
            # Server-side shadow: scan and log, never block. Independent of
            # the org's own Shadow mode setting.
            #
            # The reference_id is deliberately carried onto the collapsed
            # verdict. to_wire() only emits it when action is deny, so it
            # never reaches Anthropic -- but it does reach our log, which
            # means a shadow deny is identified in the same namespace as an
            # enforced one. Without it, findings gathered during a shadow run
            # cannot be compared against Activity Feed denials after the
            # switch to enforcing, which is the whole point of shadowing
            # first.
            verdict = Verdict(
                action=ACTION_ALLOW,
                reference_id=verdict.reference_id,
                findings=verdict.findings,
                findings_count=verdict.findings_count,
            )

        verdict_body = verdict.to_wire()
        t_decide = time.perf_counter()

        self.verdicts.put(webhook_id, verdict_body)
        await self._json(send, 200, verdict_body)

        # 8. Everything after the response is off the user's critical path.
        if unknown:
            # After the response, so the guard's detectors are off the
            # request's budget.
            try:
                fields = await asyncio.to_thread(
                    self.meta.clean, {"type": frame_type, "request_id": webhook_id},
                    where="server:log")
            except Exception:  # noqa: BLE001 - opaque() runs no detector
                fields = {"request_id": self.meta.opaque(webhook_id)}
            self.log.info("unrecognized frame type; scanned every field",
                          extra={"fields": fields})
        if self.baseline_mode == "archive":
            self.archive.submit(frame)

        await asyncio.to_thread(
            self._record_row,
            headers, frame, verdict_body, t_start, t_recv, t_verify, t_parse,
            t_scan, len(body), result, shadow_action=shadow_action,
            decide_end=t_decide, sig_reason=sig_reason, verdict=verdict,
        )

    async def _receive_verified(
        self, headers: dict[str, str], receive: Callable, send: Callable,
    ) -> tuple[bytes, float, str, str | None] | None:
        """Steps 0 and 1: read the body under the pre-auth budget and verify
        its signature. Returns (body, t_recv, signature reason, webhook-id),
        or None once a refusal has been sent. The request's share of the
        budget is released on every exit."""
        # 0. The signature checks that need no body, so a request that will
        #    be refused never has its body read.
        if self.policy.require_signature:
            if not self.policy.secrets:
                self.metrics.bump("misconfigured")
                await self._json(send, 503, {"error": "no_signing_secret_configured"})
                return None
            pre = precheck(headers)
            if not pre.ok:
                await self._refuse_signature(send, pre, headers.get("webhook-id"))
                return None

        declared = _content_length(headers)
        if declared is not None and declared > self.max_body:
            await self._refuse_oversized(send, declared)
            return None
        if not self.preauth.fits(max(declared or 0, 1)):
            await self._refuse_busy(send, declared)
            return None

        hold = self.preauth.hold()
        try:
            try:
                body, read, refusal = await asyncio.wait_for(
                    _read_body(receive, self.max_body, hold), self.body_read_timeout_s)
            except TimeoutError:
                self.metrics.bump("body_timeout")
                await self._json(send, 503, {"error": "body_timeout"},
                                 headers=[(b"retry-after", b"1")])
                return None
            t_recv = time.perf_counter()
            if refusal == "oversized":
                await self._refuse_oversized(send, read)
                return None
            if refusal == "budget":
                await self._refuse_busy(send, declared)
                return None

            # 1. Signature, over the raw bytes, before any parsing.
            sig_reason = "skipped"
            webhook_id = headers.get("webhook-id")
            if self.policy.require_signature:
                result = verify(self.policy.secrets, headers, body)
                sig_reason = result.reason
                webhook_id = result.webhook_id or webhook_id
                if not result.ok:
                    await self._refuse_signature(send, result, webhook_id)
                    return None
            return body, t_recv, sig_reason, webhook_id
        finally:
            hold.release()

    async def _refuse_oversized(self, send: Callable, read_bytes: int) -> None:
        # An oversized body is a webhook failure on Anthropic's side too;
        # make it visible rather than silently scanning a truncated frame.
        self.metrics.bump("oversized_body")
        self.log.warning(
            "request body exceeded max_body_bytes",
            extra={"fields": {"max_body_bytes": self.max_body, "read_bytes": read_bytes}},
        )
        await self._json(send, 413, {"error": "payload_too_large"})

    async def _refuse_busy(self, send: Callable, declared: int | None) -> None:
        """503 with Retry-After: the pre-auth budget has no room for this body."""
        self.metrics.bump("preauth_budget_exhausted")
        self.log.warning(
            "pre-auth body budget exhausted; refusing a hook request with 503",
            extra={"fields": {"declared_bytes": declared, **self.preauth.stats()}},
        )
        await self._json(send, 503, {"error": "busy"}, headers=[(b"retry-after", b"1")])

    async def _refuse_signature(self, send: Callable, result: SignatureResult,
                                webhook_id: str | None) -> None:
        self.metrics.bump(f"sig_{result.reason}")
        self.log.warning(
            "signature verification failed",
            extra={"fields": {"reason": result.reason,
                              "request_id": self.meta.opaque(webhook_id)}},
        )
        await self._json(send, 401, {"error": "invalid_signature"})

    @staticmethod
    def _key_part(value: Any) -> str:
        return value if isinstance(value, str) else ""

    def _scan_whole(self, frame: dict, budget: Budget):
        """A tool call frame or a frame of an unrecognized type, scanned
        whole without the session cache or the behavioural checks, which
        assume a transcript."""
        result = scan(unknown_frame_units(frame), self.detectors, budget)
        messages = frame.get("messages")
        result.messages_total = result.messages_scanned = (
            len(messages) if isinstance(messages, list) else 0)
        return result

    def _scan(self, frame: dict, budget: Budget):
        messages = frame.get("messages")
        if not isinstance(messages, list):
            messages = []
        # Coerced, because both halves come straight out of the request
        # body and neither was validated. A list `session_id` made
        # `InMemoryLRUCache.get` raise `unhashable type: 'list'` before
        # anything was scanned -- an allow in observe, and in enforce with
        # `on_internal_error: fail` a 500 per request, which trips
        # Anthropic's circuit breaker and bypasses the hook entirely.
        key = (self._key_part(frame.get("tenant_id")),
               self._key_part(frame.get("session_id")))
        result = scan_frame(
            messages, frame_units, self.detectors, budget, self.cache, key
        )
        if self.provenance is not None:
            # Over the whole transcript on every frame. It needs the order
            # of blocks and who wrote each, which the per-unit scan does not
            # carry.
            #
            # Within what is left of the scan budget, and at most the pass's
            # own limit. A pass that raised or was cut short names its checks
            # in `detectors_skipped`, so `on_tier_dropped` applies to them
            # and the stored row records them.
            from ..behaviour.provenance import request_time_budget, run

            actor = frame.get("actor") if isinstance(frame.get("actor"), dict) else {}
            actors = [v for v in (actor.get("id"), actor.get("email_address"))
                      if isinstance(v, str) and v]
            outcome = run(self.provenance, messages, session=key, findings=result.findings,
                          context=(_source_application(frame), actors),
                          time_budget_s=request_time_budget(budget))
            if outcome.error is not None:
                self.metrics.bump("provenance_error")
                self.log.warning("provenance check failed",
                                 extra={"fields": exc_fields(outcome.error)})
            elif outcome.dropped:
                self.metrics.bump("provenance_cut_short")
                self.log.warning("behavioural checks stopped at their time budget",
                                 extra={"fields": {"checks": outcome.dropped}})
            extra = outcome.findings
            # The same scrub the scan core applies to its own findings:
            # a locator or tool name that is itself a credential is
            # replaced. Structural locators already keep destinations
            # out; this keeps a key-shaped tool name out as well.
            extra = _scrub(extra, self.detectors)
            if extra:
                result.findings = dedupe_findings([*result.findings, *extra])
            result.detectors_skipped = with_left_out(result.detectors_skipped, outcome.dropped)
        return result

    def _scan_flagged(self, scan, frame: dict, budget: Budget):
        """`scan`, plus the finding for a session a post-hoc check flagged
        (behaviour/flags.py), for every frame type. A failed read flags
        nothing."""
        result = scan(frame, budget)
        if self.flags is not None:
            flagged = self.flags.finding(frame.get("session_id"))
            if flagged is not None:
                result.findings = dedupe_findings([*result.findings, flagged])
        return result

    def _build_provenance(self):
        """Provenance and taint, sharing one pass. None when both are off."""
        from ..behaviour.provenance import from_policy

        return from_policy(self.policy)

    # -- reporting --------------------------------------------------------

    def _record_row(
        self,
        headers: dict[str, str],
        frame: dict,
        verdict_body: dict,
        t_start: float,
        t_recv: float,
        t_verify: float,
        t_parse: float,
        t_scan: float,
        body_bytes: int,
        result,
        *,
        shadow_action: str | None = None,
        decide_end: float | None = None,
        dedupe_hit: bool = False,
        sig_reason: str = "",
        verdict: Verdict | None = None,
    ) -> None:
        end = decide_end or time.perf_counter()
        ms = lambda a, b: round((b - a) * 1000.0, 3)  # noqa: E731
        meta = self.meta.clean({
            "request_id": frame.get("request_id") or headers.get("webhook-id") or "",
            "source_application": _source_application(frame),
            "tenant_id": frame.get("tenant_id") or "",
            "model": frame.get("model") or "",
        }, where="server:row")
        source_app = meta["source_application"]
        action = verdict_body.get("action", ACTION_ALLOW)
        findings_count = int(verdict_body.get("findings_count", 0) or 0)
        scan_ms = ms(t_parse, t_scan)
        total_ms = ms(t_start, end)

        row = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "request_id": meta["request_id"],
            "source_application": source_app,
            # The store pseudonym, the same value as the record's tenant_hash.
            "tenant_id": pseudonym(meta["tenant_id"], self.policy.hash_salt, "org") or "",
            "model": meta["model"],
            "body_bytes": body_bytes,
            "messages_total": getattr(result, "messages_total", 0),
            "messages_scanned": getattr(result, "messages_scanned", 0),
            "cache_hit": int(bool(getattr(result, "cache_hit", False))),
            "recv_ms": ms(t_start, t_recv),
            "verify_ms": ms(t_recv, t_verify),
            "parse_ms": ms(t_verify, t_parse),
            "scan_ms": scan_ms,
            "decide_ms": ms(t_scan, end),
            "total_ms": total_ms,
            "action": action,
            "findings_count": findings_count,
            "budget_exceeded": int(bool(getattr(result, "budget_exceeded", False))),
            "mode": self.mode,
            "dedupe_hit": int(dedupe_hit),
        }
        self.csv.write(row)
        row_for_store = dict(row)
        row_for_store["tenant_id"] = meta["tenant_id"]
        row_for_store["build"] = build_id()
        # Store only, not the CSV: a list column would break a flat CSV, and
        # this is the coverage signal the findings page needs.
        dropped = list(getattr(result, "detectors_skipped", []) or [])
        if dropped:
            row_for_store["tiers_dropped"] = dropped
        if shadow_action and shadow_action != action:
            row_for_store["shadow_action"] = shadow_action
        if verdict is not None and verdict.reference_id:
            row_for_store["reference_id"] = verdict.reference_id
        frame_type = frame.get("type")
        if frame_type != "prompt":
            row_for_store["event"] = (EVENT_TOOL_CALL if frame_type == EVENT_TOOL_CALL
                                      else EVENT_OTHER)
        self.sink.submit(row_for_store, list(verdict.findings) if verdict else [])
        self.metrics.record(
            source_app,
            total_ms,
            scan_ms,
            body_bytes,
            action,
            cache_hit=bool(getattr(result, "cache_hit", False)),
            budget_exceeded=bool(getattr(result, "budget_exceeded", False)),
            findings=findings_count,
            tiers_dropped=bool(dropped),
            oversize_unscanned=UNSCANNED in dropped or UNSCANNED_CAPPED in dropped,
        )

        fields: dict[str, Any] = dict(row)
        fields["signature"] = sig_reason
        if shadow_action and shadow_action != action:
            fields["shadow_action"] = shadow_action
        if verdict is not None and verdict.findings:
            # Detector names, locators and hashes only -- never the match.
            fields["findings"] = [f.to_log() for f in verdict.findings]
            if verdict.reference_id:
                fields["reference_id"] = verdict.reference_id
        self.log.info("verdict", extra={"fields": fields})

    def _metrics_body(self) -> dict[str, Any]:
        snap = self.metrics.snapshot()
        snap["mode"] = self.mode
        snap["uptime_s"] = round(time.time() - self._started, 1)
        snap["detectors"] = [d.name for d in self.detectors]
        snap["session_cache"] = self.cache.stats()
        snap["idempotency_entries"] = len(self.verdicts)
        snap["archive"] = {"written": self.archive.written, "dropped": self.archive.dropped}
        snap["csv_rows_dropped"] = self.csv.dropped
        snap["counters"]["metadata_redacted"] = self.meta.redacted
        snap["store"] = self.sink.stats()
        snap["runtime_overrides"] = self.overrides.current().fields()
        snap["preauth_body"] = self.preauth.stats()
        return snap

    async def _json(self, send: Callable, status: int, payload: dict,
                    headers: list[tuple[bytes, bytes]] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    *(headers or []),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    @property
    def mode(self) -> str:
        """The policy's mode, or a runtime override of it."""
        return self.overrides.mode(self.baseline_mode)

    def close(self) -> None:
        self.overrides.stop()
        self.csv.close()
        self.archive.close()
        self.sink.close()


# -- helpers ---------------------------------------------------------------


def _equal(a: str, b: str) -> bool:
    """Constant-time comparison of two tokens as UTF-8 bytes."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _lower_headers(raw: list[tuple[bytes, bytes]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in raw:
        key = name.decode("latin-1").lower()
        if key not in out:
            out[key] = value.decode("latin-1")
    return out


def _source_application(frame: dict) -> str:
    source = frame.get("source")
    if isinstance(source, dict):
        app = source.get("application")
        if isinstance(app, str) and app:
            return app
    return UNKNOWN_SOURCE


def _content_length(headers: dict[str, str]) -> int | None:
    """The request's declared `content-length`, or None when it is absent
    or not a non-negative integer."""
    value = headers.get("content-length", "").strip()
    return int(value) if _DIGITS.match(value) else None


_DIGITS = re.compile(r"^[0-9]{1,18}\Z")


async def _read_body(receive: Callable[[], Awaitable[dict]], max_bytes: int,
                     hold: Hold) -> tuple[bytes, int, str]:
    """(body, bytes read, refusal). Each chunk is added to `hold` before it
    is kept. refusal is "" for a whole body, "oversized" past `max_bytes`
    and "budget" when the pre-auth budget has no room for the next chunk;
    with a refusal the body is empty and the rest is not read."""
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        if chunk:
            total += len(chunk)
            if total > max_bytes:
                return b"", total, "oversized"
            if not hold.take(len(chunk)):
                return b"", total, "budget"
            chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks), total, ""


def create_app(policy_path: str | None = None) -> VerdictServer:
    return VerdictServer(load_policy(policy_path))
