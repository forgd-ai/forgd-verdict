"""Shared by the intake hung-store and record-cap tests."""

from __future__ import annotations

import threading

from forgd_verdict.policy import DEFAULT_POLICY, Policy, _deep_merge
from forgd_verdict.store import LocalFileStore

TOKEN = "intake-token-for-hung-store-0123456789"
PROBE = "probe:"


class HangingStore(LocalFileStore):
    """Blocks every write of a probe batch until `release` is set.

    Only probe batches block: the sink behind `/scan` writes through the
    same store from its own thread, and its records carry no probe id.
    """

    def __init__(self, root):
        super().__init__(root, instance="t")
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.entered = 0
        self.landed: list[str] = []

    def write_verdicts(self, records):
        records = list(records)
        ids = [r.request_id or "" for r in records]
        if any(i.startswith(PROBE) for i in ids):
            with self.lock:
                self.entered += 1
            self.release.wait(30)
            with self.lock:
                self.landed.extend(ids)
        return super().write_verdicts(records)


def policy() -> Policy:
    return Policy(raw=_deep_merge(DEFAULT_POLICY, {
        "intake": {"clients": [{"name": "alice-laptop", "token": TOKEN}]},
        "privacy": {"hash_salt": "s"}}))


def auth() -> dict:
    return {"authorization": f"Bearer {TOKEN}",
            "content-type": "application/x-ndjson"}
