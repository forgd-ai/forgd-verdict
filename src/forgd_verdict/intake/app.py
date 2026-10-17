"""The intake ASGI app. See the package docstring for why it exists."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from functools import partial

from .. import build_id
from ..applog import exc_fields
from ..budget import Budget
from ..core import (
    _scrub,
    decide,
    gitleaks_left_out,
    scan,
    scan_frame,
    t1_dropped,
    t1_unchecked,
    with_left_out,
)
from ..detectors.gitleaks import HEALTHZ_TIMEOUT_S, daemon_state, livez
from ..extract import frame_units, hook_units, is_hook_locator, unknown_frame_units
from ..metadata import MetadataGuard
from ..models import (
    ACTION_ALLOW,
    ACTION_DENY,
    Verdict,
    digest,
    load_json,
    pseudonym,
    ulid,
)
from ..orgregistry import publish_registry, unresolved_org_references
from ..overrides import KEY_MODE, cold, reader_for, readiness
from ..plugins import loaded_distributions
from ..policy import Policy, load_policy, warn_unset_credentials
from ..sealing import SEALED
from ..store.base import (
    ORG_UNATTRIBUTED,
    SOURCE_AGENT_SCAN,
    SOURCE_CODE_HOOK,
    FindingRow,
    VerdictRecord,
    utcnow,
)
from ..store.tally import Tally, is_clean_allow, tallied, weight
from . import PATH_INTAKE, PATH_SCAN
from .devicecert import SCHEME as DEVICE_SCHEME
from .devicecert import body_digest
from .verify import ON_ERROR_HEADER, ROUTES, Caller, _equal, verifiers, verify

__all__ = ["ROUTES", "Intake", "create_app"]

_log = logging.getLogger("forgd_verdict")

# One batch is one drained spool. A laptop offline for a week ships more
# than one online for an hour, so this is generous -- but not unbounded,
# because the body is read into memory before it is parsed.
DEFAULT_MAX_BODY = 8 * 1024 * 1024
# The largest /scan body. A scan holds the GIL through each regex pass over
# its text, so while a 4 MiB body was scanned a small /scan on another
# thread took about 1 s, the hook's remote timeout; at 2 MiB, about 0.3 s.
DEFAULT_SCAN_MAX_BODY = 2 * 1024 * 1024
MAX_DEVICES_TRACKED = 100_000
# /intake store writes run on their own pool of this many threads, so a
# store that stops answering holds these and not the default executor
# that /scan runs on. A request that finds every thread busy is refused.
WRITE_WORKERS = 4
# How long /intake waits for a write before answering 503. Below the
# shipper's 20 s client timeout, so the hook reads the 503 instead of
# timing out with the write still running.
WRITE_TIMEOUT_S = 10.0
# Non-empty lines one /intake request may carry. The hook ships one spool
# file per request, and a spool file holds fewer than this.
MAX_RECORDS = 5000
# Shipped bodies parsed at once; another gets 503 busy and is retried.
PARSE_WORKERS = 2
# Batches written by this process, remembered so a retry is answered with
# the first write's result instead of being written again.
WRITTEN_BATCHES_MAX = 4096
# /scan runs on two lanes of its own threads. A body over SCAN_LARGE_BYTES
# takes the large lane, which runs SCAN_LARGE_WORKERS at once and refuses
# the next with 503 rather than queueing it. Every other body takes the
# small lane: SCAN_WORKERS at once, up to SCAN_MAX_WAITING more waiting at
# most SCAN_WAIT_S for a thread, and 503 past either. The hook scans
# locally on a 503, as on any answer that is not a verdict.
SCAN_LARGE_BYTES = 256 * 1024
SCAN_LARGE_WORKERS = 1
SCAN_WORKERS = 4
SCAN_WAIT_S = 0.25
SCAN_MAX_WAITING = 64
SCAN_RETRY_AFTER = b"1"
# How often clean allows counted since the last flush are written as tally
# rows (store/tally.py), unless `intake.tally_flush_s` says otherwise.
TALLY_FLUSH_S = 600.0


def _left_out(profile: Policy, detectors, route: str) -> list[str]:
    """`["gitleaks"]`, logged, when `profile` enables gitleaks and `detectors`
    does not hold it; otherwise empty."""
    if not gitleaks_left_out(profile, detectors):
        return []
    _log.warning("gitleaks (T1) is enabled but was not built: its binary was not "
                 "found. Every %s /scan verdict reports it in tiers_dropped", route,
                 extra={"fields": {"detector": "gitleaks", "route": route}})
    return ["gitleaks"]


def _lower_headers(raw) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in raw}


class BatchWrites:
    """The intake's store writes: a bounded pool and a per-process dedupe.

    A batch is keyed by a digest of the credential, the device and the
    request body, which a spooled batch repeats exactly on retry. While its
    write runs, a retry is refused as busy; once it has landed, a retry is
    answered with its counts and not written again.

    Delivery is at-least-once. The map lives in this process and holds the
    last `WRITTEN_BATCHES_MAX` batches, so a retry that reaches another
    replica, arrives after a restart, or follows an evicted entry is
    written a second time.
    """

    def __init__(self, workers: int = WRITE_WORKERS):
        self.workers = workers
        self._pool = ThreadPoolExecutor(max_workers=workers,
                                        thread_name_prefix="intake-write")
        self._lock = threading.Lock()
        self._inflight: dict[str, Future] = {}
        self._written: OrderedDict[str, tuple[int, int]] = OrderedDict()

    @staticmethod
    def key(caller: Caller, body: bytes) -> str:
        h = hashlib.sha256()
        for part in (caller.name, caller.device or ""):
            h.update(part.encode("utf-8") + b"\0")
        h.update(body)
        return h.hexdigest()

    def written(self, key: str) -> tuple[int, int] | None:
        """(accepted, rejected) when this batch has landed, else None."""
        with self._lock:
            return self._written.get(key)

    def submit(self, key: str, write: Callable, records, rejected: int
               ) -> Future | str:
        """The running write, or why none was started: "landed" when this
        batch has been written since `written` was checked, "in_flight" when
        it is being written, "busy" when the pool is full."""
        with self._lock:
            if key in self._written:
                return "landed"
            if key in self._inflight:
                return "in_flight"
            if len(self._inflight) >= self.workers:
                return "busy"
            future = self._pool.submit(write, records)
            self._inflight[key] = future

        def settled(done: Future) -> None:
            with self._lock:
                self._inflight.pop(key, None)
                if done.cancelled() or done.exception() is not None:
                    return
                self._written[key] = (done.result(), rejected)
                self._written.move_to_end(key)
                while len(self._written) > WRITTEN_BATCHES_MAX:
                    self._written.popitem(last=False)

        future.add_done_callback(settled)
        return future

    def inflight(self) -> int:
        with self._lock:
            return len(self._inflight)

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


class ScanLane:
    """A bounded set of /scan threads.

    `run` returns the call's result, or BUSY when no thread came free:
    at once when `wait_s` is 0, else within `wait_s`, and at once when
    `max_waiting` callers are already waiting. A thread's slot is released
    when its call returns, not when the request that started it ends, so a
    client that disconnects mid-scan does not free a slot that is still
    scanning.
    """

    BUSY = object()

    def __init__(self, name: str, workers: int, wait_s: float, max_waiting: int):
        self.name = name
        self.workers = workers
        self.wait_s = wait_s
        self.max_waiting = max_waiting
        self._pool = ThreadPoolExecutor(max_workers=workers,
                                        thread_name_prefix=f"intake-scan-{name}")
        self._sem: asyncio.Semaphore | None = None
        self.waiting = 0
        self.running = 0

    def _semaphore(self) -> asyncio.Semaphore:
        if self._sem is None:
            self._sem = asyncio.Semaphore(self.workers)
        return self._sem

    def full(self) -> bool:
        """No thread free, and no room to wait for one."""
        sem = self._semaphore()
        return sem.locked() and (self.wait_s <= 0 or self.waiting >= self.max_waiting)

    async def run(self, fn: Callable, *args):
        sem = self._semaphore()
        if self.full():
            return self.BUSY
        if sem.locked():
            self.waiting += 1
            try:
                await asyncio.wait_for(sem.acquire(), self.wait_s)
            except TimeoutError:
                return self.BUSY
            finally:
                self.waiting -= 1
        else:
            await sem.acquire()
        self.running += 1
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(self._pool, fn, *args)
        except BaseException:
            self.running -= 1
            sem.release()
            raise

        def released(_done) -> None:
            self.running -= 1
            sem.release()

        future.add_done_callback(released)
        return await asyncio.shield(future)

    def stats(self) -> dict[str, int]:
        return {"workers": self.workers, "running": self.running,
                "waiting": self.waiting}

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


class Intake:
    """Accepts NDJSON VerdictRecords from adapter 2. Nothing else."""

    def __init__(self, policy: Policy | None = None, store=None,
                 policy_path: str | None = None):
        self.policy = policy if policy is not None else load_policy(policy_path)
        self.config = self.policy.raw.get("intake") or {}
        self.verifiers = verifiers(self.policy)
        sealing = self.policy.sealing
        self._sealing_keys = (frozenset(k.fingerprint for k in sealing.current_keys())
                              if sealing is not None else frozenset())
        self.max_body = int(self.config.get("max_body_bytes", DEFAULT_MAX_BODY))
        # Read once: a placeholder or a token under 24 characters stops the
        # intake here, as it stops the verdict server and the collector.
        self._metrics_token = self.policy.metrics_token
        self.scan_max_body = int(self.config.get("scan_max_body_bytes",
                                                 DEFAULT_SCAN_MAX_BODY))
        # Parsing a shipped body holds up to MAX_RECORDS records in memory.
        self._parsing = asyncio.Semaphore(PARSE_WORKERS)
        self.scan_lanes = {
            "small": ScanLane("small", SCAN_WORKERS, SCAN_WAIT_S, SCAN_MAX_WAITING),
            "large": ScanLane("large", SCAN_LARGE_WORKERS, 0.0, 0),
        }
        self._started = time.time()
        # /scan runs the hook profile and posted frames the server profile.
        self.gitleaks_sockets = [
            s for s in (self.policy.for_profile(p).gitleaks_daemon()
                        for p in ("hook", "server")) if s]
        self._counts: dict[str, int] = {}
        # Which client sent what. A name, never a token: a shared token that
        # nobody can attribute is a token nobody will rotate.
        self._by_client: dict[str, int] = {}
        # Device ids seen by this process, for `device_first_seen`. Per
        # replica and bounded, so a count and not an inventory.
        self._devices_seen: set[str] = set()

        # Built once, lazily. The hook profile, because this is adapter 2's
        # scan wherever it runs -- one definition of a violation, not two.
        self._detector_cache = None
        self._left_out: list[str] = []
        # Held while a lazily built detector set or guard is built, so scan
        # threads arriving together build it once.
        self._build_lock = threading.RLock()
        self._meta = None
        # Frames an agent posts itself get the inference hook's
        # treatment: the server profile's detectors, a session cache so a
        # cumulative transcript is not rescanned whole each call, and the
        # behavioural checks. Built on first use; most deployments send none.
        self._frame_detector_cache = None
        self._frame_left_out: list[str] = []
        self._frame_cache = None
        self._behaviour = None
        self._behaviour_built = False
        self._budget_ms = int(
            (self.policy.raw.get("hook") or {}).get("budget_ms", 200))

        if store is None:
            # .raw.get, not .server: a hand-built Policy need not carry
            # every section, and a KeyError here would take the process
            # down at startup over a default.
            server = self.policy.raw.get("server") or {}
            spec = self.config.get("store") or server.get("store")
            if spec:
                from ..store import open_store

                store = open_store(str(spec), plugins=self.policy.plugin_allow,
                                   profile="intake")
        self.policy.refuse_unsalted("intake")
        self.store = store
        from ..store.sink import StoreSink

        batch_size = int(self.config.get("store_batch_size", 500))
        # /scan and posted frames write through this batching writer; /intake
        # writes each shipped batch directly. A store object per /scan call
        # is one per prompt per laptop.
        self.sink = StoreSink(
            store,
            salt=self.policy.hash_salt,
            batch_size=batch_size,
            flush_interval_s=float(self.config.get("store_flush_s", 60)),
            max_queue=int(self.config.get("store_max_queue", max(5000, 4 * batch_size))),
        )
        self.writes = BatchWrites()
        # Clean /scan allows, counted and written as tally rows every
        # `tally_flush_s`, sooner when the tally holds TALLY_MAX_KEYS rows,
        # and on close.
        self.tally = Tally()
        self.tally_flush_s = float(self.config.get("tally_flush_s", TALLY_FLUSH_S))
        if not 1 <= self.tally_flush_s <= 86_400:
            raise ValueError("intake.tally_flush_s must be from 1 to 86400 seconds")
        self._tally_lock = threading.Lock()
        self._tally_due = threading.Event()
        self._tally_stop = threading.Event()
        self._tally_thread: threading.Thread | None = None
        if store is not None:
            self._tally_thread = threading.Thread(target=self._tally_loop,
                                                  name="intake-tally", daemon=True)
            self._tally_thread.start()
        if store is not None:
            publish_registry(store, self.policy, "intake", _log)
        self.overrides = reader_for(
            self.policy.raw, store, "intake",
            baseline={KEY_MODE: (self.policy.raw.get("server") or {}).get("mode", "observe")})
        self.overrides.refresh()
        self._warn_credentials()
        warn_unset_credentials(_log, self.policy, "intake")
        self._warn_no_denylist()
        if not self.configured():
            _log.warning(
                "no intake tokens configured; every submission will be refused",
                extra={"fields": {"remediation": "set intake.fleet[].tokens"}},
            )
        _log.info(
            "findings intake ready",
            extra={"fields": {
                "clients_configured": self.configured(),
                "store": "enabled" if self.store is not None else "disabled",
                "runtime_overrides": self.overrides.current().fields(),
                **({"build": build_id()} if loaded_distributions() else {}),
            }},
        )

    def _warn_credentials(self) -> None:
        creds = [c for v in self.verifiers for c in v.credentials()]
        laptops = sorted(c.name for c in creds if not c.fleet and not c.agent)
        if laptops:
            _log.warning(
                "intake.clients holds per-laptop tokens; a managed fleet uses one "
                "intake.fleet token, with each device named in the request",
                extra={"fields": {"per_laptop_clients": len(laptops),
                                  "remediation": "move laptops to intake.fleet"}},
            )
        unbound = sorted(c.name for c in creds if c.org == ORG_UNATTRIBUTED)
        unset = unresolved_org_references(self.policy)
        if unbound and unset:
            _log.warning(
                "an org reference in the policy resolves to nothing, so intake "
                "credentials with no org file their records as unattributed rather "
                "than under the only org left; set the variable, or set `org` on "
                "each credential",
                extra={"fields": {"unset": unset, "credentials": unbound}},
            )
        elif unbound:
            _log.warning(
                "intake credentials with no org file their records as unattributed; "
                "set `org` on each, or configure exactly one org",
                extra={"fields": {"credentials": unbound}},
            )

    def _warn_no_denylist(self) -> None:
        fleets = sorted(c.name for v in self.verifiers for c in v.credentials() if c.fleet)
        if fleets and not self.overrides.enabled:
            _log.warning(
                "intake.fleet is configured and runtime overrides are off, so one "
                "device cannot be denied: revoking a lost or compromised laptop means "
                "rotating its fleet's token on every laptop",
                extra={"fields": {"fleets": fleets,
                                  "remediation": "enable runtime overrides "
                                                 "(docs/OVERRIDES.md) to use "
                                                 "`forgd-verdict overrides deny-device`"}},
            )

    def _note_device(self, caller: Caller) -> None:
        if caller.device is None:
            if caller.fleet:
                self.bump("device_missing")
            return
        if (caller.device not in self._devices_seen
                and len(self._devices_seen) < MAX_DEVICES_TRACKED):
            self._devices_seen.add(caller.device)
            self.bump("device_first_seen")

    def configured(self) -> int:
        """How many credentials have a usable token."""
        return sum(len(v.credentials()) for v in self.verifiers)

    def bump(self, key: str, n: int = 1) -> None:
        self._counts[key] = self._counts.get(key, 0) + n

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":  # pragma: no cover
            return
        method = scope.get("method", "GET")
        path = (scope.get("path") or "/").rstrip("/") or "/"

        if method == "GET" and path == "/stats":
            # Behind `server.metrics_token`, as the collector's /stats: with
            # no token configured the route does not exist.
            status = self._stats_authorized(_lower_headers(scope.get("headers") or []))
            if status != 200:
                await self._json(send, status, {
                    "error": "unauthorized" if status == 401 else "not_found"})
                return
            await self._json(send, 200, self.stats())
            return
        if method == "GET" and path in ("/healthz", "/health"):
            await self._json(send, 200, {
                "status": "ok",
                "build": build_id(),
                "clients_configured": self.configured(),
                "gitleaksd": await daemon_state(self.gitleaks_sockets,
                                                HEALTHZ_TIMEOUT_S),
                "uptime_s": round(time.time() - self._started, 1),
            })
            return
        if method == "GET" and path == "/readyz":
            await self._json(send, *readiness(self.overrides))
            return
        if method == "GET" and path == "/livez":
            await self._json(send, *await livez(self.gitleaks_sockets))
            return
        if method == "POST" and path == PATH_INTAKE:
            await self._accept(scope, receive, send)
            return
        if method == "POST" and path == PATH_SCAN:
            await self._scan(scope, receive, send)
            return
        # No read path, and no hint of one. Everything else is 404, so a
        # stolen token cannot probe for an endpoint that lists findings --
        # there is none to find.
        await self._json(send, 404, {"error": "not_found"})

    async def _lifespan(self, receive: Callable, send: Callable) -> None:
        """Its own method, like the collector's.

        Inline, the loop's only exit was the inner return on shutdown, so
        the statement after it was unreachable -- and reading it as an exit
        path is how the `close()` below came to be missing: the collector
        closes its store on shutdown and this did not, so the client was
        never released.
        """
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                self.overrides.start()
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                self.close()
                await send({"type": "lifespan.shutdown.complete"})
                return

    def _detectors(self):
        """Adapter 2's detector set, built where the tiers are installed.

        `include_local_only` matches what the laptop would have built, so
        a deployment that moves the scan here does not quietly change
        which rules apply -- only where they run. The salt is the
        deployment's, because the record is written here and the laptop's
        per-device salt exists precisely so the deployment secret never
        reaches it.
        """
        if self._detector_cache is None:
            with self._build_lock:
                if self._detector_cache is None:
                    hook = self.policy.for_profile("hook")
                    built = hook.build_detectors(include_local_only=True, profile="intake")
                    # Set before the cache, which other scan threads read
                    # without the lock.
                    self._left_out = _left_out(hook, built, "hook")
                    self._detector_cache = built
        return self._detector_cache

    def _guard_shipped(self, records: list[VerdictRecord]) -> list[VerdictRecord]:
        return self._guard().records(records, untrusted=True)

    def _guard(self) -> MetadataGuard:
        """The metadata boundary over adapter 2's detectors, gitleaks
        included when it runs as a subprocess. Called off the event loop."""
        if self._meta is None:
            with self._build_lock:
                if self._meta is None:
                    self._meta = MetadataGuard(self._detectors(), self.policy.hash_salt,
                                               allow_subprocess=True)
        return self._meta

    async def _scan(self, scope: dict, receive: Callable, send: Callable) -> None:
        """Scan a Claude Code hook payload and return a verdict.

        The same policy, the same detectors and the same `decide()` the
        other adapters use, so "what is a violation" has one
        implementation. A detector set built on the laptop from its own
        profile could drift from it, and would need a gitleaks binary for
        T1 at all.

        Here the laptop needs neither. It also gets tiers it cannot
        practically install: Presidio wants spaCy and about 500 MB.
        """
        headers = _lower_headers(scope.get("headers") or [])
        conf = await self._authorized(headers, "scan", send)
        if conf is None or await self._refused_cold(send, "scan"):
            return
        client = conf.name

        # Refused before the body is read when its declared length already
        # names a lane with no room.
        declared = _content_length(headers)
        if declared is not None and declared > self.scan_max_body:
            self.bump("scan_too_large")
            await self._json(send, 413, {"error": "payload_too_large"})
            return
        if declared is not None and self._lane(declared).full():
            await self._scan_busy(send, self._lane(declared))
            return

        body, oversized = await _read_body(receive, self.scan_max_body)
        if oversized:
            self.bump("scan_too_large")
            await self._json(send, 413, {"error": "payload_too_large"})
            return
        if not await self._body_signed(conf, body, send):
            return
        lane = self._lane(len(body))

        try:
            payload = load_json(body or b"{}")
        except (ValueError, RecursionError):
            self.bump("scan_undecodable")
            await self._json(send, 400, {"error": "undecodable"})
            return
        if not isinstance(payload, dict):
            self.bump("scan_undecodable")
            await self._json(send, 400, {"error": "undecodable"})
            return

        if "hook_event_name" not in payload:
            await self._scan_frame(payload, conf, send, lane)
            return

        # Off the event loop, like a frame. PostToolUse brings whole tool
        # responses here -- a file read, a web fetch -- and a laptop's hook
        # waiting behind one scan would time out and fall back.
        body = await lane.run(self._hook_verdict, payload, conf,
                              headers.get(ON_ERROR_HEADER) == "block")
        if body is ScanLane.BUSY:
            await self._scan_busy(send, lane)
            return
        self.bump("scanned")
        self._by_client[client] = self._by_client.get(client, 0) + 1
        await self._json(send, 200, body)

    def _lane(self, size: int) -> ScanLane:
        return self.scan_lanes["large" if size > SCAN_LARGE_BYTES else "small"]

    async def _scan_busy(self, send: Callable, lane: ScanLane) -> None:
        self.bump("scan_busy")
        self.bump(f"scan_busy_{lane.name}")
        await self._json(send, 503, {"error": "busy"},
                         [(b"retry-after", SCAN_RETRY_AFTER)])

    def _hook_verdict(self, payload: dict, conf: Caller, blocks: bool = False) -> dict:
        """The wire verdict for `payload`, recorded. `blocks` is a hook whose
        `hook.on_error` is `block`: a T1 that did not run is then the deny
        that hook will enforce, recorded and returned as such."""
        event = payload.get("hook_event_name")
        units = hook_units(payload)
        result = scan(units, self._detectors(), Budget(self._budget_ms),
                      self.policy.sealer_for_pseudonym(conf.org))
        dropped = with_left_out(result.detectors_skipped, self._left_out)
        verdict = decide(result.findings, self.policy, dropped=dropped)
        if blocks and verdict.action != ACTION_DENY and t1_dropped(dropped):
            verdict = t1_unchecked(self.policy, verdict.findings)

        # Recorded here, not shipped back for the laptop to spool. The
        # round trip already happened, the store is right here, and the
        # spool existed only because the hook had nowhere to put a finding
        # synchronously.
        if self.store is not None and units:
            record = _bind_to_writer(VerdictRecord(
                source=SOURCE_CODE_HOOK,
                session_id=_hook_session(payload.get("session_id"),
                                         self.policy.hash_salt),
                surface=_writer_surface(conf),
                # The event leads, as on a laptop's spooled record, so the
                # dashboard can tell a PostToolUse deny from a block. It is
                # a name hook_units recognised, or there would be no units
                # and no record.
                request_id=f"{event}:{ulid()}",
                action=verdict.action,
                reference_id=verdict.reference_id,
                findings_count=len(result.findings),
                findings=[FindingRow.from_finding(f) for f in result.findings],
                tiers_dropped=list(dropped),
                scan_ms=round(result.elapsed_ms, 2)
                if hasattr(result, "elapsed_ms") else None,
            ), conf, hashed_here=True)
            if is_clean_allow(record):
                # Guarded when its tally row is flushed.
                if self.tally.add(record):
                    self._tally_due.set()
            else:
                record = self._guard().record(record)
                # Queued, never waited on: the laptop is inside a 200 ms
                # budget. A full queue or a failed write is counted in the
                # sink's `dropped` and `errors`, in /stats.
                self.sink.submit_record(record)

        return {
            **verdict.to_wire(),
            # What the laptop needs to render a message and nothing more.
            # No locators, no excerpt hashes: the hook has the content
            # already and the store has the evidence.
            "detectors": sorted({f.detector for f in result.findings}),
            "tiers_dropped": dropped,
        }

    def _tally_loop(self) -> None:
        while not self._tally_stop.is_set():
            self._tally_due.wait(self.tally_flush_s)
            self._tally_due.clear()
            if self._tally_stop.is_set():
                return
            try:
                self._flush_tally()
            except Exception as exc:  # noqa: BLE001 - the loop must keep running
                _log.warning("tally flush failed", extra={"fields": exc_fields(exc)})

    def _flush_tally(self) -> None:
        """Queue every tally row counted so far on the sink. When the guard
        or the sink raises, or the sink refuses the rows, the drained rows
        are counted back in, for the next flush, and an exception is
        raised again."""
        with self._tally_lock:
            drained = self.tally.drain()
            if not drained:
                return
            try:
                rows = self._guard().records(drained)
                accepted = self.sink.submit_records(rows)
            except BaseException:
                self.tally.merge(drained)
                self.bump("tally_requeued")
                raise
            if not accepted:
                self.tally.merge(drained)
                self.bump("tally_requeued")
                return
            self.bump("tally_rows", len(rows))

    def _frame_detectors(self):
        """The inference hook's detector set: the server profile."""
        if self._frame_detector_cache is None:
            with self._build_lock:
                if self._frame_detector_cache is None:
                    server = self.policy.for_profile("server")
                    built = server.build_detectors(profile="intake")
                    self._frame_left_out = _left_out(server, built, "agent")
                    self._frame_detector_cache = built
        return self._frame_detector_cache

    async def _scan_frame(self, frame: dict, conf: Caller, send: Callable,
                          lane: ScanLane) -> None:
        """Scan a messages array an agent's own code posted before calling the model.

        For agents on the Developer Platform, which Anthropic's inference
        hooks do not cover: the builder owns the loop, so the builder runs
        the check. The shape is the inference hook's frame, so the
        same parser, detectors and behavioural checks apply, and a verdict
        reads the same as one from adapter 1.

        What the frame says about itself is kept in the caller's own name:
        the surface is `agent:<client>`, with `source.application` as a label
        beneath it only when the client's configuration lists that label, and
        the session is keyed by client and stored as a digest. A frame cannot
        claim to be an Anthropic surface, share another client's cache, or
        put its own strings in the record.

        Scanning runs on a worker thread. The service is shared with laptop
        hooks waiting inside a 200 ms budget, and an 8 MiB frame scanned on
        the event loop stalled every request behind it.
        """
        body = await lane.run(self._frame_verdict, frame, conf)
        if body is ScanLane.BUSY:
            await self._scan_busy(send, lane)
            return
        self.bump("scanned_frames")
        self._by_client[conf.name] = self._by_client.get(conf.name, 0) + 1
        await self._json(send, 200, body)

    def _frame_verdict(self, frame: dict, conf: Caller) -> dict:
        from ..behaviour.provenance import from_policy, request_time_budget
        from ..behaviour.provenance import run as run_behaviour
        from ..cache import InMemoryLRUCache

        server = self.policy.for_profile("server")
        with self._build_lock:
            if self._frame_cache is None:
                self._frame_cache = InMemoryLRUCache(
                    max_sessions=server.cache_max_sessions, ttl_s=server.cache_ttl_s)
            if not self._behaviour_built:
                self._behaviour = from_policy(server)
                self._behaviour_built = True

        client, labels = conf.name, conf.labels
        messages = frame.get("messages")
        session = str(frame.get("session_id") or "")
        key = (client, session)
        prompt = _is_frame(frame)
        if prompt:
            # Not cached past a size. The cache is bounded in sessions, and
            # each entry keeps a shape per block, so many sessions of many
            # tiny blocks made its real footprint far larger than the body
            # limit suggests.
            cache = self._frame_cache if _blocks(messages) <= MAX_CACHED_BLOCKS else None
            budget = Budget(server.budget_ms)
            result = scan_frame(messages, frame_units, self._frame_detectors(),
                                budget, cache, key,
                                sealer=self.policy.sealer_for_pseudonym(conf.org))
        else:
            # Any other frame is scanned whole, without the session cache or
            # the behavioural checks, which assume a prompt transcript.
            self.bump("unknown_frame_type")
            result = scan(unknown_frame_units(frame), self._frame_detectors(),
                          Budget(server.budget_ms),
                          self.policy.sealer_for_pseudonym(conf.org))
            result.messages_total = result.messages_scanned = (
                len(messages) if isinstance(messages, list) else 0)
        findings = list(result.findings)
        if prompt and self._behaviour is not None:
            actor = frame.get("actor") if isinstance(frame.get("actor"), dict) else {}
            actors = [v for v in (actor.get("id"), actor.get("email_address"))
                      if isinstance(v, str) and v]
            outcome = run_behaviour(self._behaviour, messages, session=key, findings=findings,
                                    time_budget_s=request_time_budget(budget),
                                    context=(f"agent:{client}", actors))
            if outcome.error is not None:
                self.bump("behaviour_error")
                _log.warning("behavioural check failed",
                             extra={"fields": exc_fields(outcome.error)})
            elif outcome.dropped:
                self.bump("behaviour_cut_short")
                _log.warning("behavioural checks stopped at their time budget",
                             extra={"fields": {"checks": outcome.dropped}})
            findings += _scrub(outcome.findings, self._frame_detectors())
            result.detectors_skipped = with_left_out(result.detectors_skipped, outcome.dropped)
        dropped = with_left_out(result.detectors_skipped, self._frame_left_out)
        verdict = decide(findings, server, dropped=dropped)
        # The deployment's mode, as adapter 1 applies it. In observe or
        # archive a deny is recorded and returned as `shadow_action`, and the
        # action is allow -- the operator chose to measure before enforcing,
        # and a builder's agent is one more thing being measured.
        shadow = verdict.action
        if (self.overrides.mode(self.policy.mode) in ("observe", "archive")
                and verdict.action == ACTION_DENY):
            verdict = Verdict(action=ACTION_ALLOW, reference_id=verdict.reference_id,
                              findings=verdict.findings,
                              findings_count=verdict.findings_count)

        if self.store is not None:
            record = _bind_to_writer(VerdictRecord(
                source=SOURCE_AGENT_SCAN,
                session_id=_session_digest(session, self.policy.hash_salt),
                surface=_agent_surface(client, frame, labels),
                action=verdict.action,
                shadow_action=shadow,
                reference_id=verdict.reference_id,
                findings_count=len(findings),
                findings=[FindingRow.from_finding(f) for f in findings],
                tiers_dropped=list(dropped),
                messages_total=getattr(result, "messages_total", None),
                messages_scanned=getattr(result, "messages_scanned", None),
                scan_ms=round(result.elapsed_ms, 2)
                if hasattr(result, "elapsed_ms") else None,
            ), conf, hashed_here=True)
            record = self._guard().record(record)
            self.sink.submit_record(record)

        return {
            **verdict.to_wire(),
            "shadow_action": shadow,
            "detectors": sorted({f.detector for f in findings}),
            "tiers_dropped": dropped,
        }

    async def _accept(self, scope: dict, receive: Callable, send: Callable) -> None:
        headers = _lower_headers(scope.get("headers") or [])
        conf = await self._authorized(headers, "intake", send)
        if conf is None or await self._refused_cold(send, "intake"):
            return
        client = conf.name

        body, oversized = await _read_body(receive, self.max_body)
        if not oversized and not await self._body_signed(conf, body, send):
            return
        if oversized:
            self.bump("too_large")
            await self._json(send, 413, {"error": "payload_too_large"})
            return

        key, landed = await asyncio.to_thread(self._landed, conf, body)
        if landed is not None:
            self.bump("duplicate_batch")
            await self._json(send, 200, {"accepted": landed[0], "rejected": landed[1]})
            return

        if self._parsing.locked():
            self.bump("parse_busy")
            await self._json(send, 503, {"error": "busy"}, [(b"retry-after", b"5")])
            return
        async with self._parsing:
            parsed = await asyncio.to_thread(self._parse_shipped, body, conf)
        if parsed is None:
            # No retry of this request can fit, so 413 rather than the 503
            # a laptop parks and sends again.
            self.bump("too_many_records")
            await self._json(send, 413, {"error": "too_many_records",
                                         "max_records": MAX_RECORDS})
            return
        records, rejected = parsed

        if rejected:
            self.bump("rejected_records", rejected)
            _log.warning(
                "refused records in an intake batch",
                extra={"fields": {"client": client, "rejected": rejected,
                                  "accepted": len(records)}},
            )

        if not records:
            # 400, not 200: a batch that produced nothing storable is a
            # sender problem, and the hook parks a batch it could not ship
            # rather than dropping it.
            await self._json(send, 400, {"error": "no_usable_records",
                                         "rejected": rejected})
            return

        if self.store is None:
            self.bump("store_disabled")
            await self._json(send, 503, {"error": "store_unavailable"},
                             [(b"retry-after", b"30")])
            return
        # Written before the answer, not queued: the hook deletes its spool
        # file on a 2xx.
        future = self.writes.submit(key, partial(_write_all, self.store), records, rejected)
        if future == "landed":
            accepted, rejected = self.writes.written(key) or (0, rejected)
            self.bump("duplicate_batch")
            await self._json(send, 200, {"accepted": accepted, "rejected": rejected})
            return
        if isinstance(future, str):
            self.bump("write_" + future)
            await self._json(send, 503, {"error": "unavailable", "reason": future},
                             [(b"retry-after", b"30")])
            return
        try:
            written = await asyncio.wait_for(
                asyncio.shield(asyncio.wrap_future(future)), WRITE_TIMEOUT_S)
        except TimeoutError:
            # The write keeps its thread and may still land; a retry of
            # this batch then finds it in `writes` and is not written again.
            self.bump("store_timeout")
            future.add_done_callback(self._count_late(asyncio.get_running_loop(), client))
            _log.error("intake store write timed out",
                       extra={"fields": {"timeout_s": WRITE_TIMEOUT_S}})
            await self._json(send, 503, {"error": "unavailable", "reason": "timeout"},
                             [(b"retry-after", b"30")])
            return
        except Exception as exc:
            # 5xx so the hook parks the batch and retries. A 4xx here would
            # make it discard findings it had already scanned.
            self.bump("store_error")
            _log.error("intake could not write a batch", extra={"fields": exc_fields(exc)})
            await self._json(send, 503, {"error": "unavailable"},
                             [(b"retry-after", b"30")])
            return

        self.bump("accepted")
        self.bump("records", written)
        self._by_client[client] = self._by_client.get(client, 0) + written
        await self._json(send, 200, {"accepted": written, "rejected": rejected})

    def _landed(self, conf: Caller, body: bytes) -> tuple[str, tuple[int, int] | None]:
        """The batch's dedupe key, and its counts if it has already landed.
        Called off the event loop: the body can be `max_body_bytes`."""
        key = BatchWrites.key(conf, body)
        return key, self.writes.written(key)

    def _parse_shipped(self, body: bytes, conf: Caller
                       ) -> tuple[list[VerdictRecord], int] | None:
        """(records, rejected) for a shipped body, bound to `conf` and
        guarded; None when it has more than `MAX_RECORDS` non-empty lines,
        which are counted before any is parsed. Called off the event loop."""
        lines = _nonempty_lines(body, MAX_RECORDS)
        if lines is None:
            return None
        records: list[VerdictRecord] = []
        rejected = 0
        for line in lines:
            try:
                record = VerdictRecord.from_json(line, strict=True)
            except Exception:  # noqa: BLE001 - one bad line is not a bad batch
                rejected += 1
                continue
            # A laptop token may write adapter-2 records and nothing else.
            #
            # Otherwise it can forge inference-hook rows and move the
            # numbers this whole project is about -- coverage, would-deny
            # rates, the reconciliation between live and post-hoc. The
            # source is asserted by the sender, so it is checked rather
            # than trusted.
            if record.source != SOURCE_CODE_HOOK or record.action not in _ACTIONS:
                rejected += 1
                continue
            salt = self.policy.hash_salt
            records.append(_bind_to_writer(_clamp_shipped(record, salt, self._sealing_keys),
                                           conf, salt=salt))
        if records:
            records = tallied(self._guard_shipped(records))
        return records, rejected

    def _count_late(self, loop: asyncio.AbstractEventLoop, client: str) -> Callable:
        """A done-callback that counts a timed-out write if it lands.

        It runs on the write's thread, so the counting is handed to the
        loop, which owns `_counts` and `_by_client`.
        """
        def landed(done: Future) -> None:
            if done.cancelled() or done.exception() is not None:
                return
            # RuntimeError when the loop has closed.
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(self._landed_late, client, done.result())
        return landed

    def _landed_late(self, client: str, written: int) -> None:
        self.bump("late_landed")
        self.bump("records", written)
        self._by_client[client] = self._by_client.get(client, 0) + written

    async def _authorized(self, headers: dict[str, str], route: str,
                          send: Callable) -> Caller | None:
        """The client if its token may use `route`; else answer and None.

        403 for a valid token on a route it is not scoped to, or from a
        device the runtime overrides deny; 401 for everything else. The
        distinction does tell a caller its token is real, but it only helps
        someone who already holds it, and an
        operator reading a 401 would go looking for a wrong token rather
        than a missing scope.
        """
        if headers.get("authorization", "").startswith(DEVICE_SCHEME + " "):
            # A certificate chain's verification is CPU work an unauthenticated
            # caller chooses, so it runs off the event loop.
            client = await asyncio.to_thread(verify, self.verifiers, headers)
        else:
            client = verify(self.verifiers, headers)
        if client is None or (client.route is not None and client.route != route):
            # A device-signed request names its route, so one signed for
            # /scan cannot be replayed to /intake.
            self.bump("unauthorized")
            await self._json(send, 401, {"error": "unauthorized"})
            return None
        if route not in client.routes:
            self.bump("forbidden_route")
            await self._json(send, 403, {"error": "forbidden",
                                         "route": route})
            return None
        if client.device is not None and client.device in self.overrides.denied_devices():
            self.bump("device_denied")
            await self._json(send, 403, {"error": "device_denied"})
            return None
        if client.device is None and client.fleet and client.credential.require_device:
            # The hook always sends one, so a fleet request without it is
            # not the managed hook.
            self.bump("device_missing")
            await self._json(send, 403, {"error": "device_required"})
            return None
        self._note_device(client)
        return client

    async def _body_signed(self, client: Caller, body: bytes, send: Callable) -> bool:
        """Whether a device-signed request's body is the one it signed; a
        bearer-token request always is. Answers 401 when it is not."""
        if client.body_sha256 is None:
            return True
        if _equal(body_digest(body), client.body_sha256):
            return True
        self.bump("unauthorized")
        self.bump("device_body_mismatch")
        await self._json(send, 401, {"error": "unauthorized"})
        return False

    def _stats_authorized(self, headers: dict[str, str]) -> int:
        """200 to serve, 404 when disabled, 401 on a bad token."""
        token = self._metrics_token
        if not token:
            return 404
        supplied = headers.get("authorization", "")
        prefix = "Bearer "
        if not supplied.startswith(prefix):
            return 401
        return 200 if _equal(supplied[len(prefix):], token) else 401

    def stats(self) -> dict:
        return {
            "uptime_s": round(time.time() - self._started, 1),
            "clients_configured": self.configured(),
            "counts": {**self._counts,
                       "metadata_redacted": self._meta.redacted if self._meta else 0},
            "by_client": dict(sorted(self._by_client.items())),
            "store": self.sink.stats(),
            "intake_writes": {"inflight": self.writes.inflight(),
                              "workers": self.writes.workers},
            "scan_lanes": {name: lane.stats() for name, lane in self.scan_lanes.items()},
            "tally": dict(zip(("rows", "allows"), self.tally.pending(), strict=True),
                          dropped=self.tally.dropped),
            "runtime_overrides": self.overrides.current().fields(),
        }

    def flush(self, timeout_s: float | None = None) -> bool:
        """Write every record queued and every allow counted so far; see
        `StoreSink.flush`."""
        self._flush_tally()
        return self.sink.flush(timeout_s)

    def close(self) -> None:
        self.overrides.stop()
        self.writes.close()
        for lane in self.scan_lanes.values():
            lane.close()
        self._tally_stop.set()
        self._tally_due.set()
        if self._tally_thread is not None:
            self._tally_thread.join(timeout=5)
        try:
            self._flush_tally()
        except Exception as exc:  # noqa: BLE001 - close must still close the sink
            _log.warning("tally flush at close failed", extra={"fields": exc_fields(exc)})
        self.sink.close()
        closer = getattr(self.store, "close", None)
        if callable(closer):
            closer()

    async def _refused_cold(self, send: Callable, route: str) -> bool:
        """Answer 503 and return True while the overrides reader is cold."""
        reason = cold(self.overrides)
        if reason is None:
            return False
        self.bump("overrides_not_ready")
        _log.error("runtime overrides not ready; refusing the request",
                   extra={"fields": {"reason": reason, "route": route}})
        await self._json(send, 503, {"error": "not_ready", "reason": reason})
        return True

    async def _json(self, send: Callable, status: int, payload: dict,
                    extra_headers=None) -> None:
        body = json.dumps(payload).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        headers.extend(extra_headers or [])
        await send({"type": "http.response.start", "status": status,
                    "headers": headers})
        await send({"type": "http.response.body", "body": body})


def _is_frame(payload: dict) -> bool:
    """A prompt frame: `type: "prompt"` with a messages list, and no hook
    event name.

    `/scan` sends any other payload without `hook_event_name` through
    `unknown_frame_units`, as the verdict server does a frame of another
    type.
    """
    return (payload.get("type") == "prompt"
            and isinstance(payload.get("messages"), list)
            and "hook_event_name" not in payload)


# Frames with more blocks than this are scanned but not cached.
MAX_CACHED_BLOCKS = 2_000


def _agent_surface(client: str, frame: dict, labels: frozenset[str] = frozenset()) -> str:
    """`agent:<client>`, plus `/<label>` only for a label the client is configured with.

    The client is what the token proved. The frame's `source.application`
    is sender data, and a character filter is no secret check once the
    value is lowercased, since the credential detectors are case-sensitive.
    So it is used only to pick one of the client's configured `labels`, and
    otherwise ignored.
    """
    source = frame.get("source")
    app = source.get("application") if isinstance(source, dict) else None
    return f"agent:{client}/{app}" if isinstance(app, str) and app in labels \
        else f"agent:{client}"


def _session_digest(session: str, salt: str) -> str | None:
    """A frame's session id as a stable digest, never as sent.

    It groups one agent session's records, which a digest does as well as
    the original, and it is sender data: a secret copied into it would
    otherwise reach the store verbatim.
    """
    return f"sess_{digest(session, salt)[:16]}" if session else None


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def _hook_session(session, salt: str) -> str | None:
    """A hook payload's session id: kept if it is Claude Code's, else a digest.

    Claude Code's own ids are UUIDs and are kept, because the same id is
    `session.id` on OTel exports and joins the two. An Agent SDK callback
    posts whatever it likes here, so anything else is sender data and is
    stored the way a frame's session is.
    """
    session = str(session or "")
    return session if _UUID.match(session) else _session_digest(session, salt)


def _blocks(messages) -> int:
    n = 0
    for m in messages or []:
        content = m.get("content") if isinstance(m, dict) else None
        n += len(content) if isinstance(content, list) else 1
    return n


def _writer_surface(caller: Caller) -> str:
    """`agent:<name>` for an agent credential, else `claude-code-local`."""
    return f"agent:{caller.name}" if caller.agent else "claude-code-local"


# What `hook/cli.py` `_spool` sends: `pseudonym(user, device_salt, "user")`.
_HOOK_ACTOR = re.compile(r"^user_[0-9a-f]{10}\Z")
# The prefix of a shipped actor once rebound. No server-side writer uses
# it, so a rebound value cannot equal one of theirs.
SHIPPED_ACTOR_PREFIX = "hookuser"

_SHIPPED_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*\Z")
_SHIPPED_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]*\Z")
# `models.make_reference_id`: `fv_`, a short name, `_` and a ULID.
_SHIPPED_REFERENCE_ID = re.compile(r"^fv_[A-Za-z0-9._:/\-]{1,12}_[0-9A-HJKMNP-TV-Z]{26}\Z")
_SHIPPED_DIGEST = re.compile(r"^[0-9a-f]{64}\Z")
_SHIPPED_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/\-]*\Z")
_SHIPPED_BUILD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+=\-]*\Z")
# `(pattern, cap)` for each identifier a shipped record may carry. A value
# that fails is dropped.
_SHIPPED_IDS = {
    "session_id": (_SHIPPED_SESSION_ID, 64),
    "request_id": (_SHIPPED_REQUEST_ID, 200),
    "model": (_SHIPPED_MODEL, 100),
    "build": (_SHIPPED_BUILD, 256),
}
# Fields a shipped record never sets: only another adapter writes them, or
# `hook/cli.py` `_spool` leaves them unset.
_NOT_SHIPPED = ("reported_as", "session_started_at", "session_updated_at", "deleted_at",
                "shadow_action", "cache_hit", "budget_exceeded", "scan_ms", "total_ms",
                "body_bytes", "messages_total", "messages_scanned", "event")

_ACTIONS = (ACTION_ALLOW, ACTION_DENY)
# `hook/device.py` `salt_namespace`.
_SALT_NAMESPACE = re.compile(r"^d[0-9a-f]{12}\Z")
# A detector or tier name, as the dashboard's detector filter accepts one.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]*\Z")
_TIER_MAX_CHARS = 64
_TIERS_MAX = 32
_DETECTOR_MAX_CHARS = 128
_TOOL_MAX_CHARS = 128


def _shipped_locator(locator: str, salt: str) -> str:
    """`locator` when `extract.is_hook_locator` accepts it, else
    `<shipped:` and 12 hex characters of its salted digest `>`."""
    if not locator or is_hook_locator(locator):
        return locator
    return f"<shipped:{digest(locator, salt)[:12]}>"


def _shipped_digest(value: str, salt: str) -> str:
    """`value` when it is a sha256 hex digest, as `models.digest` writes, else
    the salted digest of `value`."""
    return value if _SHIPPED_DIGEST.match(value) else digest(value, salt)


def _clamp_shipped(record: VerdictRecord, salt: str = "",
                   sealing_keys: frozenset[str] = frozenset()) -> VerdictRecord:
    """`record` with each enum, id and finding field held to the form
    `hook/cli.py` `_spool` writes. A value outside it is dropped or replaced,
    and `findings_count` is the number of findings kept. The fields `_spool`
    never writes are dropped by `_bind_to_writer` (`_NOT_SHIPPED`). The
    caller has already refused an action other than allow or deny.

    A finding's `sealed` is kept only when it is a sealed value under one
    of `sealing_keys`, the fingerprints of this intake's own current
    `privacy.sealing` keys, never a retired one. The intake cannot open it, so that is all it can
    check; with sealing off nothing is kept."""
    from ..core import MAX_SCAN_FINDINGS
    from ..models import REFERENCE_ID_MAX, SEVERITY_BLOCK, SEVERITY_WARN

    ref = record.reference_id
    if ref is not None and not (len(ref) <= REFERENCE_ID_MAX
                                and _SHIPPED_REFERENCE_ID.match(ref)):
        ref = None
    namespace = record.salt_namespace
    if namespace and not _SALT_NAMESPACE.match(namespace):
        namespace = None
    tiers: list[str] = []
    for tier in record.tiers_dropped:
        if (len(tier) <= _TIER_MAX_CHARS and _NAME.match(tier) and tier not in tiers
                and len(tiers) < _TIERS_MAX):
            tiers.append(tier)
    findings = [
        FindingRow(
            detector=f.detector if (len(f.detector) <= _DETECTOR_MAX_CHARS
                                    and _NAME.match(f.detector)) else "unknown",
            severity=f.severity if f.severity in (SEVERITY_BLOCK, SEVERITY_WARN)
            else SEVERITY_WARN,
            locator=_shipped_locator(f.locator, salt),
            excerpt_hash=_shipped_digest(f.excerpt_hash, salt),
            tool_name=f.tool_name if (f.tool_name is not None
                                      and len(f.tool_name) <= _TOOL_MAX_CHARS
                                      and _NAME.match(f.tool_name)) else None,
            sealed=f.sealed if (f.sealed is not None and SEALED.fullmatch(f.sealed)
                                and f.sealed.split(".")[1] in sealing_keys) else None,
        )
        for f in record.findings[:MAX_SCAN_FINDINGS]
    ]
    return replace(
        record,
        tally=None,
        reference_id=ref,
        salt_namespace=namespace,
        tiers_dropped=tiers,
        findings=findings,
        findings_count=len(findings),
    )


def _write_all(store, records: list[VerdictRecord]) -> int:
    """Write `records` and return how many verdicts they hold: a tally row
    counts as its `tally`, so the hook is told every record it sent."""
    written = store.write_verdicts(records)
    return sum(weight(r) for r in records) if written == len(records) else written




def _shipped_actor(sent: object, caller: Caller, salt: str) -> str | None:
    """`sent` rebound to the writer: a digest of the credential's name and
    `sent`, under the deployment salt, with SHIPPED_ACTOR_PREFIX. None when
    `sent` is not the hook's pseudonym shape."""
    if not isinstance(sent, str) or not _HOOK_ACTOR.match(sent):
        return None
    return pseudonym(f"{caller.name}\x00{sent}", salt, SHIPPED_ACTOR_PREFIX)


def _shipped_id(field: str, value: object) -> str | None:
    """`value` when it matches `field`'s pattern within its cap, else None."""
    pattern, cap = _SHIPPED_IDS[field]
    if isinstance(value, str) and len(value) <= cap and pattern.match(value):
        return value
    return None


def _bind_to_writer(record: VerdictRecord, caller: Caller, *,
                    hashed_here: bool = False, salt: str = "") -> VerdictRecord:
    """Overwrite the fields the writer must not choose.

    The token authenticated the writer and nothing bound the RECORD to
    them. `VerdictRecord.from_json` accepts every dataclass field off the
    wire, and the store partitions by `tenant_hash` and `observed_at`, so
    one POST with a valid token wrote:

        verdicts/source=code_hook/org=MADE-UP-ORG/date=1999-01-01/...
          {"tenant_hash": "MADE-UP-ORG", "actor_hash": "ceo@victim.example",
           "salt_namespace": "attacker-salt", ...}

    -- an invented org as a real partition on disk, and a chosen time
    window for the evidence.

    Bounded before and after: intake refuses any source but `code_hook`,
    and `latest_per_session` collapses only compliance records, so a
    writer can ADD evidence and cannot hide a real record. This stops the
    adding from being attributable to anyone else.

    `observed_at` becomes receipt time. The hook's own clock is not
    authority over which window evidence lands in, and a spooled batch
    shipped late is still received when it is received.

    `hashed_here` is the /scan case, where nothing arrived hashed: this
    process matched the content and used the deployment salt, so the
    namespace must stay empty. Namespacing it anyway said the hashes were
    incomparable with every other server-side writer's when they are the
    same salt, which a reader takes literally -- it would count one
    leaked key as two.
    """
    namespace = (
        record.salt_namespace if hashed_here
        else f"{caller.name}:{record.salt_namespace or 'device'}"
    )
    if not hashed_here:
        # A shipped record. Its surface is the credential's, its actor is
        # rebound to the credential under `salt`, and its identifiers are
        # kept only within their pattern and cap.
        record = replace(
            record,
            surface=_writer_surface(caller),
            actor_hash=_shipped_actor(record.actor_hash, caller, salt),
            **{f: _shipped_id(f, getattr(record, f)) for f in _SHIPPED_IDS},
            **dict.fromkeys(_NOT_SHIPPED),
        )
        record = replace(record, build=record.build or "")
    return replace(
        record,
        observed_at=utcnow(),
        tenant_hash=caller.org,
        fleet_orgs=list(caller.credential.fleet_orgs) or None,
        client=caller.name,
        device=caller.device,
        # The laptop's per-device salt namespace is real and useful -- it
        # says these hashes are not comparable with the server's -- but it
        # is the writer's to assert only within their own name.
        salt_namespace=namespace,
    )


def _content_length(headers: dict[str, str]) -> int | None:
    """The request's declared `content-length`, or None when it is absent
    or not a non-negative integer."""
    value = headers.get("content-length", "").strip()
    return int(value) if _DIGITS.match(value) else None


_DIGITS = re.compile(r"^[0-9]{1,18}\Z")


async def _read_body(receive: Callable, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunks.append(message.get("body", b""))
        total += len(chunks[-1])
        if total > limit:
            return b"", True
        if not message.get("more_body"):
            break
    return b"".join(chunks), False


def create_app() -> Intake:
    """Built from FORGD_VERDICT_POLICY, because uvicorn imports by string."""
    return Intake()


def _nonempty_lines(body: bytes, limit: int) -> list[bytes] | None:
    """The non-empty lines of `body`, or None as soon as there are more than
    `limit`. Scans without splitting the whole body, so a body of millions of
    short or blank lines costs a scan, not a list of millions of objects."""
    out: list[bytes] = []
    start, end = 0, len(body)
    while start < end:
        stop = body.find(b"\n", start)
        if stop == -1:
            stop = end
        line = body[start:stop]
        if line.strip():
            if len(out) == limit:
                return None
            out.append(line)
        start = stop + 1
    return out
