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
  * `StartColumn` and `EndColumn` are UTF-8 byte offsets into the line. On
    the stream's first line the match is bytes `StartColumn-1` to
    `EndColumn`; on every later line both count the newline before it, so
    it is `StartColumn-2` to `EndColumn-1`. Verified against 8.30.1 and
    the gitleaksd library build.
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

from ..models import Finding, ScanUnit, digest
from .base import TIER_T1, DetectorFailed, ScanTruncated

# gitleaks is fed the joined transcript. A frame can legally be 64 MiB; piping
# that through a subprocess on the hot path is not worth it, so cap and log.
DEFAULT_MAX_BYTES = 8 * 1024 * 1024

# Shipped alongside this module; see the file for why it is mandatory.
BASELINE_CONFIG = Path(__file__).with_name("gitleaks-baseline.toml")

# The config the running daemon loaded, exported by deploy/entrypoint.sh.
GITLEAKS_CONFIG_ENV = "FORGD_GITLEAKS_CONFIG"

# Config-injection vectors that outrank `<target>/.gitleaks.toml`.
CONFIG_ENV_VARS = ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")

# The only variables the subprocess is given. gitleaks reads its config from
# `--config` and its input from stdin; Go on Windows needs SYSTEMROOT.
SUBPROCESS_ENV = ("SYSTEMROOT",)

# gitleaks' stdin source reads whatever the pipe holds, then reads on to the
# next blank line for at most 25,000 bytes and cuts there or mid-line; a
# match across a cut is in neither fragment. A longer stream is fed as
# windows of at most `PIPE_WINDOW` bytes, each overlapping the one before
# by `PIPE_OVERLAP`, with a blank line between them.
PIPE_WINDOW = 24_000
PIPE_OVERLAP = 8_192
# gitleaks skips the whole stream when its first chunk has the magic bytes
# of a binary type, so the stream opens with this line.
PIPE_PREFIX = b"\n"


def _resolve_binary(binary: str | None) -> str | None:
    """Resolve to an executable path, or None.

    An explicitly configured path still has to exist: otherwise `enabled:
    auto` would silently treat a typo as "present" and every scan would
    return zero findings.

    Absolute, because the scan runs gitleaks from a temporary directory, so
    a relative path that resolved here would name nothing there.
    """
    if binary:
        found = shutil.which(binary) or (
            binary if os.path.isfile(binary) and os.access(binary, os.X_OK) else None
        )
    else:
        found = shutil.which("gitleaks")
    return os.path.abspath(found) if found else None


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
        # Against this process's working directory, for the same reason as
        # the binary: under `hook.project_overrides` the policy leaves a
        # relative config relative so that it names a file in the project.
        self._config = os.path.abspath(config) if config else config
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

    @property
    def uses_daemon(self) -> bool:
        """True when this detector scans through gitleaksd, not a subprocess."""
        return bool(self._daemon)

    @property
    def max_bytes(self) -> int:
        """The most UTF-8 bytes of unit text one `scan` reads. Past it the
        scan reads the newest units that fit and raises `ScanTruncated`."""
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
        scanned = len(line_map["bounds"])
        truncated = scanned < len(units)
        report = self._run(stream) if stream else []
        findings: list[Finding] = []
        for item in report:
            # StartLine is 1-based in `stdin` mode (verified against
            # gitleaks 8.30.1: a finding on the third line reports 3).
            start = int(item.get("StartLine", 1))
            bound = _bound(line_map, start)
            if bound is None:
                continue
            first_line, unit = bound
            span_start, span_end = _span(item, unit.text, start - first_line)
            secret = item.get("Secret") or item.get("Match") or ""
            rule = item.get("RuleID") or "unknown"
            findings.append(
                Finding(
                    detector=f"gitleaks:{rule}",
                    severity=self.severity,
                    locator=unit.locator,
                    excerpt_hash=digest(secret, self._salt),
                    matched=secret or None,
                    tool_name=unit.tool_name,
                    start=span_start,
                    end=span_end,
                )
            )
        if truncated:
            # Raised whether or not the scanned units produced findings.
            raise ScanTruncated(
                f"gitleaks scanned the last {scanned} of {len(units)} units; "
                f"the earlier ones were past max_bytes ({self._max_bytes})",
                findings, scanned)
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

        # SUBPROCESS_ENV only. CONFIG_ENV_VARS outrank --config's neighbours
        # in the precedence chain, and the rest of the environment can come
        # from the project the hook runs in.
        env = {k: os.environ[k] for k in SUBPROCESS_ENV if k in os.environ}
        try:
            # A fresh empty directory as both the working directory and the
            # `.gitleaksignore` location. gitleaks reads `.gitleaksignore`
            # from its working directory, and `tempfile.gettempdir()` follows
            # TMPDIR, which a project's settings can point at the repository.
            with tempfile.TemporaryDirectory(prefix="forgd-gitleaks-") as neutral:
                source = stream.encode("utf-8", "replace")
                piped, windows = _pipe_stream(source)
                proc = subprocess.run(
                    [*cmd, "--gitleaks-ignore-path", neutral],
                    input=piped,
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
        except (ValueError, RecursionError) as exc:
            raise DetectorFailed("gitleaks report did not parse") from exc
        if not isinstance(parsed, list):
            raise DetectorFailed("gitleaks report is not a list")
        return _unpipe(parsed, piped, source, windows)


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
    except (ValueError, RecursionError) as exc:
        raise DetectorFailed("gitleaksd report did not parse") from exc
    if not isinstance(report, list) or not all(isinstance(i, dict) for i in report):
        raise DetectorFailed("gitleaksd report is not a list of findings")
    return report


def _pipe_stream(source: bytes) -> tuple[bytes, list[tuple[int, int, int]]]:
    """`source` as fed to the gitleaks subprocess, and its windows as
    `(offset in the piped bytes, start, end in source)`."""
    windows: list[tuple[int, int, int]] = []
    out = bytearray(PIPE_PREFIX)
    start = 0
    while True:
        end = min(start + PIPE_WINDOW, len(source))
        while 0 < end < len(source) and source[end] & 0xC0 == 0x80:
            end -= 1  # not inside a UTF-8 sequence
        if windows:
            out += b"\n\n"
        windows.append((len(out), start, end))
        out += source[start:end]
        if end >= len(source):
            return bytes(out), windows
        start = end - PIPE_OVERLAP
        while source[start] & 0xC0 == 0x80:
            start -= 1


def _line_starts(data: bytes) -> list[int]:
    starts = [0]
    i = data.find(b"\n")
    while i != -1:
        starts.append(i + 1)
        i = data.find(b"\n", i + 1)
    return starts


def _unpipe(report: list, piped: bytes, source: bytes,
            windows: list[tuple[int, int, int]]) -> list:
    """`report` with each finding's lines and columns moved from the piped
    bytes to `source`, and the copies an overlap produced dropped.

    gitleaks counts columns from 1 on a fragment's first line and from 2 on
    later ones, so a finding's columns are taken from whichever reading puts
    its `Match` at that place. One that neither does keeps only its line."""
    piped_lines, source_lines = _line_starts(piped), _line_starts(source)
    offsets = [w[0] for w in windows]

    def to_source(at: int) -> int | None:
        k = bisect.bisect_right(offsets, at) - 1
        if k < 0:
            return None
        base, start, end = windows[k]
        pos = start + at - base
        return pos if pos <= end else None

    def line_col(pos: int) -> tuple[int, int]:
        line = bisect.bisect_right(source_lines, pos)
        return line, pos - source_lines[line - 1] + (1 if line == 1 else 2)

    out, seen = [], set()
    for item in report:
        if not isinstance(item, dict):
            out.append(item)
            continue
        item = dict(item)
        try:
            line, end_line = int(item["StartLine"]), int(item["EndLine"])
            first, last = int(item["StartColumn"]), int(item["EndColumn"])
        except (KeyError, TypeError, ValueError):
            line = end_line = first = last = None
        match = item.get("Match")
        begin = stop = None
        if (line is not None and isinstance(match, str) and match
                and 1 <= line <= end_line <= len(piped_lines)):
            want = match.encode("utf-8", "replace")
            for shift in (1, 2):
                b = piped_lines[line - 1] + first - shift
                e = piped_lines[end_line - 1] + last - shift + 1
                if 0 <= b < e <= len(piped) and piped[b:e] == want:
                    begin, stop = b, e
                    break
        start = to_source(begin) if begin is not None else None
        end = to_source(stop) if stop is not None else None
        if start is not None and end is not None and end > start \
                and source[start:end] == piped[begin:stop]:
            item["StartLine"], item["StartColumn"] = line_col(start)
            end_line, end_col = line_col(end - 1)
            item["EndLine"], item["EndColumn"] = end_line, end_col
        else:
            for k in ("StartColumn", "EndColumn", "EndLine"):
                item.pop(k, None)
            at = piped_lines[line - 1] if line and line <= len(piped_lines) else None
            pos = to_source(at) if at is not None else None
            if pos is None:
                item.pop("StartLine", None)
            else:
                item["StartLine"] = bisect.bisect_right(source_lines, pos)
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _join(units: list[ScanUnit], max_bytes: int) -> tuple[str, dict]:
    """Concatenate the longest run of trailing units whose joined UTF-8 size
    is at most `max_bytes`, in their original order, recording a line ->
    unit map. Units before that run are left out."""
    first = len(units)
    total = 0
    while first > 0:
        size = len(units[first - 1].text.encode("utf-8", "replace"))
        if first < len(units):
            size += 1  # the "\n" joining it to the next unit
        if total + size > max_bytes:
            break
        total += size
        first -= 1
    chunks: list[str] = []
    bounds: list[tuple[int, int, ScanUnit]] = []
    line = 1
    for unit in units[first:]:
        n_lines = unit.text.count("\n") + 1
        bounds.append((line, line + n_lines - 1, unit))
        chunks.append(unit.text)
        line += n_lines
    return "\n".join(chunks), {"bounds": bounds, "starts": [b[0] for b in bounds]}


def _lookup(line_map: dict, line: int) -> ScanUnit | None:
    """The unit whose lines include `line`, by bisecting the ascending
    start lines; None for a line outside every unit."""
    bound = _bound(line_map, line)
    return bound[1] if bound else None


def _bound(line_map: dict, line: int) -> tuple[int, ScanUnit] | None:
    """(first line, unit) of the unit whose lines include `line`."""
    k = bisect.bisect_right(line_map.get("starts", []), line) - 1
    if k < 0:
        return None
    start, end, unit = line_map["bounds"][k]
    return (start, unit) if start <= line <= end else None


def _span(item: dict, text: str, line_in_unit: int) -> tuple[int | None, int | None]:
    """The character offsets in `text` of the match gitleaks reported on its
    `line_in_unit`th line, or (None, None) unless the report's columns
    locate its `Match` there on one line."""
    try:
        line = int(item["StartLine"])
        first, last = int(item["StartColumn"]), int(item["EndColumn"])
        one_line = int(item["EndLine"]) == line
    except (KeyError, TypeError, ValueError):
        return None, None
    match = item.get("Match")
    lines = text.split("\n")
    if not (one_line and isinstance(match, str) and match
            and 0 <= line_in_unit < len(lines)):
        return None, None
    shift = 1 if line == 1 else 2
    begin, stop = first - shift, last - shift + 1
    raw = lines[line_in_unit].encode("utf-8", "replace")
    if not 0 <= begin < stop <= len(raw):
        return None, None
    try:
        prefix = raw[:begin].decode("utf-8")
        body = raw[begin:stop].decode("utf-8")
    except UnicodeDecodeError:
        return None, None
    start = sum(len(t) + 1 for t in lines[:line_in_unit]) + len(prefix)
    end = start + len(body)
    if text[start:end] != match:
        return None, None
    return start, end
