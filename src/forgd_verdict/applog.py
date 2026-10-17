"""Structured JSON logging and the timing CSV.

Both sinks are written off the hot path by a background writer, so a slow
disk does not delay the caller. Neither sink may ever receive matched
content -- see tests/test_privacy.py.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import queue
import sys
import threading
import traceback
from typing import Any

from .fsmode import open_private

CSV_COLUMNS = [
    "ts",
    "request_id",
    "source_application",
    "tenant_id",
    "model",
    "body_bytes",
    "messages_total",
    "messages_scanned",
    "cache_hit",
    "recv_ms",
    "verify_ms",
    "parse_ms",
    "scan_ms",
    "decide_ms",
    "total_ms",
    "action",
    "findings_count",
    "budget_exceeded",
    "mode",
    "dedupe_hit",
]


def exc_fields(exc: BaseException) -> dict[str, str]:
    """`error`, the exception's type, and `at`, the file and line that
    raised it, for a log line's fields. Never the message or a traceback:
    either can quote a request body or an upstream response."""
    out = {"error": type(exc).__name__}
    frames = traceback.extract_tb(exc.__traceback__)
    if frames:
        out["at"] = f"{os.path.basename(frames[-1].filename)}:{frames[-1].lineno}"
    return out


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", stream=None) -> logging.Logger:
    """Install the JSON handler on the `forgd_verdict` logger, replacing the
    one an earlier call installed and leaving any other handler in place."""
    logger = logging.getLogger("forgd_verdict")
    for old in [h for h in logger.handlers if getattr(h, "_forgd_json", False)]:
        logger.removeHandler(old)
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler._forgd_json = True
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    return logger


class TimingCSV:
    """Append-only CSV writer on a background thread."""

    _SENTINEL = object()

    def __init__(self, path: str | None):
        self.path = path
        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self._thread: threading.Thread | None = None
        self.dropped = 0
        if path:
            self._start()

    def _start(self) -> None:
        assert self.path
        needs_header = not os.path.exists(self.path) or os.path.getsize(self.path) == 0
        self._fh = os.fdopen(open_private(os.path.abspath(self.path),
                                          os.O_WRONLY | os.O_APPEND),
                             "a", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(self._fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        if needs_header:
            self._writer.writeheader()
            self._fh.flush()
        self._thread = threading.Thread(target=self._run, name="forgd-csv", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is self._SENTINEL:
                break
            try:
                self._writer.writerow(item)
                if self._queue.empty():
                    self._fh.flush()
            except Exception:  # pragma: no cover - disk failure must not kill serving
                pass
        try:
            self._fh.flush()
            self._fh.close()
        except Exception:  # pragma: no cover
            pass

    def write(self, row: dict[str, Any]) -> None:
        if not self.path:
            return
        try:
            self._queue.put_nowait(row)
        except queue.Full:
            # Never block the verdict path on the metrics sink.
            self.dropped += 1

    def close(self) -> None:
        if self._thread is None:
            return
        self._queue.put(self._SENTINEL)
        self._thread.join(timeout=5)


def warn_if_unsalted(log, policy) -> bool:
    """Say so, loudly, when findings are being hashed with no salt.

    `excerpt_hash` is sha256(salt + matched_text). With an empty salt a
    findings export can be brute-forced back to the value for anything
    low-entropy -- an SSN has ~1e9 possibilities, a PAN fewer once Luhn is
    applied -- so the store's "findings, never content in the clear" claim
    stops being true for exactly the values that matter most.

    A service that logs or records findings refuses to start without a
    salt (`Policy.refuse_unsalted`), so this is logged only by one whose
    policy file sets `privacy.allow_unsalted: true`.
    """
    if policy.hash_salt:
        return False
    log.warning(
        "privacy.hash_salt is empty and privacy.allow_unsalted is set; findings "
        "are hashed with a bare sha256 and a low-entropy value (an SSN, a card "
        "number) can be recovered from a log or an export by brute force",
        extra={"fields": {"remediation": "set privacy.hash_salt to a deployment secret"}},
    )
    return True
