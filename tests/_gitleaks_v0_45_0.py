# FROZEN: src/forgd_verdict/detectors/gitleaks.py as released in v0.45.0, the
# reference for test_collector_gitleaks_groups.py. Only the relative imports
# are rewritten as absolute ones. Do not edit, format or lint it.
# ruff: noqa
"""T1: gitleaks subprocess detector.

CLI contract verified against gitleaks master on 2026-09-17:
  * `gitleaks stdin` is the current streaming mode. The `detect`/`protect`
    commands and their `--no-git` / `--pipe` flags were deprecated in v8.19.0
    and are not used here.
  * JSON report fields are the Go struct's exported names: `RuleID`,
    `StartLine`, `EndLine`, `Secret`, `Match`, `Description`, `Entropy`.
    `Line` carries `json:"-"` and is never serialized.
  * `--exit-code 0` stops a leak from looking like a crash (default is 1).
  * `StartLine` is 1-based in stdin mode.
  * `--config` is passed ALWAYS. This is a security requirement, not tuning:
    gitleaks otherwise picks up `<target path>/.gitleaks.toml`, plus the
    `GITLEAKS_CONFIG` and `GITLEAKS_CONFIG_TOML` environment variables. Any
    of the three lets the scanned context disable its own scanning, which for
    adapter 2 -- running inside a developer's working directory -- is a
    one-file DLP bypass. Verified against 8.30.1: a `.gitleaks.toml` holding
    an allowlist of `.*` in the working directory takes detections from 1 to
    0. We therefore pin the config, scrub both env vars, and run from a
    neutral directory.

Note gitleaks' default config allowlists well-known documentation keys
(`AKIAIOSFODNN7EXAMPLE` among them). T0 flags those and T1 does not,
which is why both tiers are worth running.

All ScanUnits are concatenated into one stream so gitleaks is spawned once per
frame rather than once per block; a line map converts the reported line number
back to the originating unit.

Two transports, same rules and same findings:

  * `daemon` -- POST the stream to `sidecar/gitleaksd` over a Unix socket.
    The CLI recompiles ~220 regexes on every exec, a fixed 477 ms on an Azure
    Container Apps vCPU that no body size, core count or cache can reduce.
    The daemon compiles once. Measured 0.08 ms empty and 0.81 ms at 200 KB.
  * subprocess -- `gitleaks stdin`, for laptops and anywhere without a
    sidecar.

A configured daemon that cannot be reached is an ERROR, never a silent
fallback. `enabled: auto` exists so a missing binary degrades gracefully; a
missing daemon on the inline path means the tier is not running, and a
tier that falls back quietly fails open with nothing to show for it.
"""

from __future__ import annotations

import asyncio
import bisect
import concurrent.futures
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path

from forgd_verdict.models import Finding, ScanUnit, digest
from forgd_verdict.detectors.base import TIER_T1, DetectorFailed

# gitleaks is fed the joined transcript. A frame can legally be 64 MiB; piping
# that through a subprocess on the hot path is not worth it, so cap and log.
DEFAULT_MAX_BYTES = 8 * 1024 * 1024

# Shipped alongside this module; see the file for why it is mandatory.
BASELINE_CONFIG = Path(__file__).with_name("gitleaks-baseline.toml")

# The config the running daemon loaded, exported by deploy/entrypoint.sh.
GITLEAKS_CONFIG_ENV = "FORGD_GITLEAKS_CONFIG"

# Config-injection vectors that outrank `<target>/.gitleaks.toml`.
CONFIG_ENV_VARS = ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")


def _resolve_binary(binary: str | None) -> str | None:
    """Resolve to an executable path, or None.

    An explicitly configured path still has to exist: otherwise `enabled:
    auto` would silently treat a typo as "present" and every scan would
    return zero findings.
    """
    if binary:
        return shutil.which(binary) or (
            binary if os.path.isfile(binary) and os.access(binary, os.X_OK) else None
        )
    return shutil.which("gitleaks")


class GitleaksDetector:
    name = "gitleaks"
    tier = TIER_T1

    def __init__(
        self,
        severity: str = "block",
        salt: str = "",
        binary: str | None = None,
        timeout_s: float = 2.0,
        config: str | None = None,
        redact: bool = False,
        max_bytes: int = DEFAULT_MAX_BYTES,
        daemon: str | None = None,
    ):
        self.severity = severity
        self._salt = salt
        self._binary = _resolve_binary(binary)
        self._timeout_s = timeout_s
        self._config = config
        self._redact = redact
        self._max_bytes = max_bytes
        self._daemon = daemon or None
        # Configuring a daemon is a statement that this tier must run here.
        # The policy layer reads this and refuses to build a detector set
        # with an unreachable daemon, so `enabled: auto` cannot quietly drop
        # the tier on the one latency-critical path. Without a daemon the
        # detector stays optional, which keeps `serve` working on a machine
        # that has no gitleaks binary.
        self.required = bool(self._daemon)
        self.truncated = False

    @property
    def uses_daemon(self) -> bool:
        """True when this detector scans through gitleaksd, not a subprocess."""
        return bool(self._daemon)

    @property
    def max_bytes(self) -> int:
        """The most UTF-8 bytes of unit text one `scan` reads; past it the
        scan raises `DetectorFailed`."""
        return self._max_bytes

    def available(self) -> bool:
        """A daemon is checked by connecting, not by looking for a binary.

        Deliberately does not fall back to the binary when a daemon is
        configured: `auto` would then report available and quietly run a
        900x slower path, or none at all.
        """
        if self._daemon:
            return _daemon_alive(self._daemon, self._timeout_s)
        return bool(self._binary)

    def scan(self, units: Iterable[ScanUnit]) -> list[Finding]:
        # A configured daemon deliberately skips the availability gate. That
        # gate means "this tier is optional, carry on without it", which is
        # right for a missing binary and wrong for a daemon that was
        # reachable at startup and has since died: the scan would return an
        # empty list, which reads as a clean frame. Let DaemonUnavailable
        # propagate instead. Startup validation is the policy layer's job --
        # `enabled: true` raises there if the daemon is not up.
        if not self._daemon and not self.available():
            return []
        units = [u for u in units if u.text]
        if not units:
            return []

        stream, line_map = _join(units, self._max_bytes)
        self.truncated = line_map.pop("__truncated__", False)  # type: ignore[arg-type]
        if not stream:
            if self.truncated:
                # `_join` skips a whole unit rather than cutting inside
                # one, so a single oversized unit leaves NOTHING to scan
                # and this returned clean without the CLI ever running.
                raise DetectorFailed(
                    f"every unit exceeded max_bytes ({self._max_bytes}); "
                    "gitleaks scanned nothing"
                )
            return []

        report = self._run(stream)
        findings: list[Finding] = []
        for item in report:
            # StartLine is 1-based in `stdin` mode (verified against
            # gitleaks 8.30.1: a finding on the third line reports 3).
            start = int(item.get("StartLine", 1))
            unit = _lookup(line_map, start)
            if unit is None:
                continue
            secret = item.get("Secret") or item.get("Match") or ""
            rule = item.get("RuleID") or "unknown"
            findings.append(
                Finding(
                    detector=f"gitleaks:{rule}",
                    severity=self.severity,
                    locator=unit.locator,
                    excerpt_hash=digest(secret, self._salt),
                    tool_name=unit.tool_name,
                )
            )
        if self.truncated and not findings:
            # `_join` stops at max_bytes and sets this flag, which nothing
            # read -- `grep -rn "\.truncated" src/ tests/` found the write
            # and no reader. 8 MiB of padding followed by a GitLab PAT
            # returned [] and was recorded as a clean T1 run.
            #
            # Only when there are NO findings. A truncated scan that DID
            # match already denies, and discarding those to report a
            # failure would trade a real finding for a warning.
            raise DetectorFailed(
                f"gitleaks saw only the first {self._max_bytes} bytes and "
                "found nothing; the rest was not scanned"
            )
        return findings

    def _run(self, stream: str) -> list[dict]:
        if self._daemon:
            return _run_daemon(self._daemon, stream, self._timeout_s)
        return self._run_subprocess(stream)

    def _run_subprocess(self, stream: str) -> list[dict]:
        # `--report-path -` writes the JSON report to stdout, so the
        # plaintext secrets in it stay in this process's memory and never
        # reach disk. `redact: true` masks them in the report as well, at
        # the cost of excerpt_hash fidelity: it then hashes the mask.
        # Always pin the config. An operator-supplied path is a deliberate
        # administrative act; absent one, use the packaged baseline. Never
        # let gitleaks resolve a config from the scanned context.
        config = self._config or str(BASELINE_CONFIG)
        cmd = [
            self._binary,  # type: ignore[list-item]
            "stdin",
            "--no-banner",
            "--no-color",
            "--exit-code", "0",
            "--log-level", "error",
            "--report-format", "json",
            "--report-path", "-",
            "--config", config,
            # A repo can also disable rules with `gitleaks:allow` comments.
            # Honouring those in a DLP scan would let the scanned content
            # opt itself out, one line at a time.
            "--ignore-gitleaks-allow",
        ]
        if self._redact:
            cmd += ["--redact=100"]

        # Strip the config env vars, which outrank --config's neighbours in
        # the precedence chain and would otherwise be an injection point.
        env = {k: v for k, v in os.environ.items() if k not in CONFIG_ENV_VARS}
        try:
            # A fresh empty directory as both the working directory and the
            # `.gitleaksignore` location. gitleaks reads `.gitleaksignore`
            # from its working directory, and `tempfile.gettempdir()` follows
            # TMPDIR, which a project's settings can point at the repository.
            with tempfile.TemporaryDirectory(prefix="forgd-gitleaks-") as neutral:
                proc = subprocess.run(
                    [*cmd, "--gitleaks-ignore-path", neutral],
                    input=stream.encode("utf-8", "replace"),
                    capture_output=True,
                    timeout=self._timeout_s,
                    check=False,
                    env=env,
                    cwd=neutral,
                )
        except subprocess.TimeoutExpired as exc:
            raise DetectorFailed(
                f"gitleaks timed out after {self._timeout_s}s"
            ) from exc
        except OSError as exc:
            raise DetectorFailed(f"gitleaks could not run: {exc}") from exc
        raw = proc.stdout
        if not raw.strip():
            # A clean run prints `[]`, so empty stdout means gitleaks never
            # wrote a report, whatever the exit code. Measured against
            # gitleaks 8.30.1:
            #
            #   clean          exit 0, stdout "[]"
            #   bad --config   exit 1, stdout empty
            #
            # A binary that does not support `--report-path -` writes a file
            # named `-` and prints nothing, which would otherwise read as a
            # clean scan.
            #
            # stderr is NOT quoted: gitleaks logs finding summaries there,
            # and a matched value must not reach a log.
            raise DetectorFailed(
                f"gitleaks exited {proc.returncode} and wrote no report"
                + (f"; --config {self._config}" if self._config else "")
            )
        # `--exit-code 0` makes a leak exit 0, so any other code is gitleaks
        # failing, whatever it printed.
        if proc.returncode != 0:
            raise DetectorFailed(f"gitleaks exited {proc.returncode}")
        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise DetectorFailed("gitleaks report did not parse") from exc
        if not isinstance(parsed, list):
            raise DetectorFailed("gitleaks report is not a list")
        return parsed


class DaemonUnavailable(RuntimeError):
    """A configured gitleaksd could not be reached.

    Raised rather than returning no findings: an empty result is
    indistinguishable from a clean scan, which is how a dead tier hides.
    """


def _connect(socket_path: str, timeout_s: float):
    import http.client
    import socket as _socket

    class _UDSConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            sock.settimeout(timeout_s)
            sock.connect(socket_path)
            self.sock = sock

    conn = _UDSConnection("localhost", timeout=timeout_s)
    return conn


def _daemon_alive(socket_path: str, timeout_s: float) -> bool:
    try:
        conn = _connect(socket_path, timeout_s)
        try:
            conn.request("GET", "/healthz")
            return conn.getresponse().status == 200
        finally:
            conn.close()
    except OSError:
        return False


# How long /livez and /healthz wait for the daemon.
LIVEZ_TIMEOUT_S = 1.0
HEALTHZ_TIMEOUT_S = 0.5

# Pings run on their own small pool, not asyncio's default one. The apps
# run full scans on the default pool, and with enough concurrent large
# scans queued there a ping could not start inside its timeout: /livez
# reported a healthy daemon down and the orchestrator restarted the pod
# under exactly the load it was serving.
_PING_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="gitleaksd-ping")


async def daemon_state(sockets: Iterable[str], timeout_s: float) -> str:
    """`not_configured`, `ok`, or `down` if any socket fails to answer.

    Each ping runs in a worker thread and the wait is bounded as a whole,
    so a daemon that accepts and never replies holds a thread for at most
    about `timeout_s` per socket operation and never holds the event loop.
    """
    sockets = sorted(set(sockets))
    if not sockets:
        return "not_configured"
    try:
        alive = await asyncio.wait_for(
            asyncio.gather(*(asyncio.get_running_loop().run_in_executor(
                _PING_POOL, _daemon_alive, s, timeout_s) for s in sockets)),
            timeout_s,
        )
    except TimeoutError:
        return "down"
    return "ok" if all(alive) else "down"


async def livez(sockets: Iterable[str]) -> tuple[int, dict]:
    """Status and body for `GET /livez`: 503 only when a daemon is down."""
    state = await daemon_state(sockets, LIVEZ_TIMEOUT_S)
    down = state == "down"
    return 503 if down else 200, {"status": "down" if down else "ok", "gitleaksd": state}


def _run_daemon(socket_path: str, stream: str, timeout_s: float) -> list[dict]:
    try:
        conn = _connect(socket_path, timeout_s)
        try:
            conn.request("POST", "/scan", body=stream.encode("utf-8", "replace"),
                         headers={"content-type": "application/octet-stream"})
            response = conn.getresponse()
            body = response.read()
            if response.status != 200:
                raise DaemonUnavailable(
                    f"gitleaksd returned {response.status}"
                )
        finally:
            conn.close()
    except OSError as exc:
        raise DaemonUnavailable(f"gitleaksd at {socket_path}: {exc}") from exc
    try:
        report = json.loads(body.decode("utf-8")) or []
    except ValueError as exc:
        raise DetectorFailed("gitleaksd report did not parse") from exc
    if not isinstance(report, list) or not all(isinstance(i, dict) for i in report):
        raise DetectorFailed("gitleaksd report is not a list of findings")
    return report


def _join(units: list[ScanUnit], max_bytes: int) -> tuple[str, dict]:
    """Concatenate units into one stream, recording a line -> unit map."""
    chunks: list[str] = []
    bounds: list[tuple[int, int, ScanUnit]] = []
    line = 1
    total = 0
    truncated = False
    for unit in units:
        encoded = unit.text
        size = len(encoded.encode("utf-8", "replace"))
        if total + size > max_bytes:
            truncated = True
            break
        total += size
        n_lines = encoded.count("\n") + 1
        bounds.append((line, line + n_lines - 1, unit))
        chunks.append(encoded)
        line += n_lines
    return "\n".join(chunks), {"bounds": bounds, "starts": [b[0] for b in bounds],
                               "__truncated__": truncated}


def _lookup(line_map: dict, line: int) -> ScanUnit | None:
    """The unit whose lines include `line`, by bisecting the ascending
    start lines; None for a line outside every unit."""
    k = bisect.bisect_right(line_map.get("starts", []), line) - 1
    if k < 0:
        return None
    start, end, unit = line_map["bounds"][k]
    return unit if start <= line <= end else None
