#!/usr/bin/env python3
"""Latency harness for the Inference hooks verdict server.

Generates correctly signed prompt frames at a target size, fires them
concurrently, and reports percentiles. Two shapes matter:

  * allow-path: clean transcripts, measures pure round-trip overhead.
  * scan-path:  transcripts carrying a secret, measures full detection cost.

The org verdict timeout (1-10,000ms, 5,000ms default) covers connection, TLS,
upload, processing and response, so the number that matters is total round
trip at realistic body sizes, not scan time in isolation.

Usage:
  python loadtest.py --url https://verdict.example.com --secret whsec_... \\
      --size-kb 100 --requests 500 --concurrency 16
  python loadtest.py --url http://127.0.0.1:8000 --no-sign --shape scan \\
      --size-kb 1024 --requests 50
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

FILLER = "the quick brown fox jumps over the lazy dog " * 16  # ~700 B
# Structurally valid, not a real credential, and outside gitleaks' allowlist.
PLANTED_SECRET = "AKIAQYLPMN5HGZTHX4UQ"


def build_frame(size_kb: int, shape: str, session_id: str | None, turns: int) -> dict:
    target = size_kb * 1024
    per_turn = max(1, target // max(1, turns))
    messages = []
    for i in range(turns):
        text = (FILLER * (per_turn // len(FILLER) + 1))[:per_turn]
        if shape == "scan" and i == turns - 1:
            text += f" AWS_ACCESS_KEY_ID={PLANTED_SECRET}"
        messages.append(
            {"role": "user" if i % 2 == 0 else "assistant",
             "content": [{"type": "text", "text": f"turn {i} {text}"}]}
        )
    return {
        "type": "prompt",
        "request_id": f"req_{uuid.uuid4().hex[:16]}",
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "actor": {"type": "user", "id": "user_loadtest", "email_address": None},
        "source": {"application": "claude-code"},
        "session_id": session_id,
        "model": "claude-opus-5",
        "messages": messages,
        "metadata": {},
    }


def sign(secret: str, webhook_id: str, body: bytes) -> dict[str, str]:
    ts = str(int(time.time()))
    key = base64.b64decode(secret.removeprefix("whsec_"))
    mac = hmac.new(key, f"{webhook_id}.{ts}.".encode() + body, hashlib.sha256)
    return {
        "webhook-id": webhook_id,
        "webhook-timestamp": ts,
        "webhook-signature": "v1," + base64.b64encode(mac.digest()).decode(),
    }


class Results:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.latencies: list[float] = []
        self.actions: dict[str, int] = {}
        self.errors: dict[str, int] = {}
        self.bytes_sent = 0

    def ok(self, ms: float, action: str, nbytes: int) -> None:
        with self.lock:
            self.latencies.append(ms)
            self.actions[action] = self.actions.get(action, 0) + 1
            self.bytes_sent += nbytes

    def fail(self, reason: str) -> None:
        with self.lock:
            self.errors[reason] = self.errors.get(reason, 0) + 1


def fire(args, results: Results, index: int) -> None:
    session_id = None if args.no_session else f"loadtest-{index % max(1, args.sessions)}"
    frame = build_frame(args.size_kb, args.shape, session_id, args.turns)
    body = json.dumps(frame).encode()
    headers = {"content-type": "application/json", "user-agent": "anthropic-dlp/1",
               "accept-encoding": "identity"}
    if not args.no_sign:
        if not args.secret:
            raise SystemExit("--secret is required unless --no-sign is passed")
        headers.update(sign(args.secret, frame["request_id"], body))

    request = urllib.request.Request(args.url, data=body, headers=headers, method="POST")
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            payload = json.loads(response.read().decode())
        elapsed = (time.perf_counter() - start) * 1000.0
        results.ok(elapsed, payload.get("action", "?"), len(body))
    except urllib.error.HTTPError as exc:
        results.fail(f"http_{exc.code}")
    except Exception as exc:  # noqa: BLE001 - report, don't stop the run
        results.fail(type(exc).__name__)


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo) if lo != hi else ordered[lo]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True)
    parser.add_argument("--secret", default=None, help="whsec_... signing secret")
    parser.add_argument("--no-sign", action="store_true", help="skip signing (dev only)")
    parser.add_argument("--size-kb", type=int, default=100)
    parser.add_argument("--turns", type=int, default=8)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--shape", choices=["allow", "scan"], default="allow")
    parser.add_argument("--sessions", type=int, default=1,
                        help="distinct session_ids, to exercise the incremental cache")
    parser.add_argument("--no-session", action="store_true",
                        help="send session_id=null, defeating the cache")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args(argv)

    warm = Results()
    for i in range(args.warmup):
        fire(args, warm, i)

    results = Results()
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        list(pool.map(lambda i: fire(args, results, i), range(args.requests)))
    wall = time.perf_counter() - started

    summary = {
        "url": args.url,
        "shape": args.shape,
        "size_kb": args.size_kb,
        "turns": args.turns,
        "requests": args.requests,
        "concurrency": args.concurrency,
        "sessions": 0 if args.no_session else args.sessions,
        "completed": len(results.latencies),
        "errors": results.errors,
        "actions": results.actions,
        "wall_s": round(wall, 3),
        "rps": round(len(results.latencies) / wall, 1) if wall else 0,
        "mb_sent": round(results.bytes_sent / 1_048_576, 2),
        "latency_ms": {
            "min": round(min(results.latencies), 2) if results.latencies else 0,
            "p50": round(pct(results.latencies, 50), 2),
            "p95": round(pct(results.latencies, 95), 2),
            "p99": round(pct(results.latencies, 99), 2),
            "max": round(max(results.latencies), 2) if results.latencies else 0,
            "mean": round(statistics.fmean(results.latencies), 2) if results.latencies else 0,
        },
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        lat = summary["latency_ms"]
        print(f"{args.shape}-path  {args.size_kb} KB x {args.turns} turns  "
              f"n={summary['completed']}/{args.requests}  c={args.concurrency}")
        print(f"  p50 {lat['p50']:>8.2f} ms   p95 {lat['p95']:>8.2f} ms   "
              f"p99 {lat['p99']:>8.2f} ms   max {lat['max']:>8.2f} ms")
        print(f"  {summary['rps']} req/s   {summary['mb_sent']} MB sent   "
              f"actions={summary['actions']}")
        if results.errors:
            print(f"  ERRORS: {results.errors}", file=sys.stderr)
    return 1 if results.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
