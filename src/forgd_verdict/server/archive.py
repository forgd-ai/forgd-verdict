"""Archive mode: persist prompt frames AFTER responding.

A push alternative to polling the Compliance API. The response must never
wait on persistence, so frames go to a bounded queue drained by a background
thread; if the queue fills, frames are dropped and counted rather than
back-pressuring the verdict path.

The archive holds full transcripts. It is the one sink in this project that
deliberately contains sensitive content -- store it accordingly (encrypted
volume, restricted ACL, its own retention clock). The privacy invariant
covers logs, CSV, metrics and verdicts, not this.
"""

from __future__ import annotations

import gzip
import json
import os
import queue
import secrets
import threading
import time
from typing import Any

from ..fsmode import open_private, private_dir


class FrameArchive:
    _SENTINEL = object()

    def __init__(self, directory: str | None, max_queue: int = 1000):
        self.directory = directory
        self.dropped = 0
        self.written = 0
        # Each writer appends to its own file: one per uvicorn worker, and
        # one per replica sharing a volume.
        self.instance = f"{os.getpid()}-{secrets.token_hex(4)}"
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        if directory:
            private_dir(directory)
            self._thread = threading.Thread(target=self._run, name="forgd-archive", daemon=True)
            self._thread.start()

    def submit(self, frame: dict[str, Any]) -> None:
        if not self.directory:
            return
        try:
            self._queue.put_nowait(frame)
        except queue.Full:
            self.dropped += 1

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is self._SENTINEL:
                break
            try:
                self._write(item)
                self.written += 1
            except Exception:  # pragma: no cover - disk failure must not kill serving
                self.dropped += 1

    def _write(self, frame: dict[str, Any]) -> None:
        assert self.directory
        day = time.strftime("%Y-%m-%d", time.gmtime())
        path = os.path.join(self.directory, f"frames-{day}-{self.instance}.jsonl.gz")
        line = json.dumps(frame, default=str).encode("utf-8") + b"\n"
        # 0600: transcripts, not logs.
        fd = open_private(path, os.O_WRONLY | os.O_APPEND)
        with os.fdopen(fd, "ab") as fh, gzip.GzipFile(fileobj=fh, mode="ab") as gz:
            gz.write(line)

    def close(self) -> None:
        if self._thread is None:
            return
        self._queue.put(self._SENTINEL)
        self._thread.join(timeout=5)
