"""`python -m forgd_verdict.server` -- run the verdict server with uvicorn."""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="forgd-verdict serve")
    parser.add_argument("--policy", default=None, help="path to policy.yaml")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    # uvicorn imports the factory by string, and the factory builds the app
    # from `load_policy()` with no argument. So `--policy` has to reach it
    # through the environment or it silently affects only host and port --
    # the process runs on ./policy.yaml while the operator believes
    # otherwise. It works in the container only because the image sets this.
    if args.policy:
        os.environ["FORGD_VERDICT_POLICY"] = str(args.policy)

    from ..policy import PolicyNotFound, Unsalted, load_policy

    try:
        policy = load_policy(args.policy)
    except PolicyNotFound as exc:
        print(f"refusing to start the verdict server: {exc}", file=sys.stderr)
        return 2
    try:
        policy.refuse_unsalted("verdict server")
        limit_concurrency = policy.limit_concurrency
        _ = policy.preauth_body_budget_bytes, policy.body_read_timeout_s
    except (Unsalted, ValueError) as exc:
        print(f"refusing to start the verdict server: {exc}", file=sys.stderr)
        return 2
    host = args.host or policy.server.get("host", "0.0.0.0")
    port = args.port or int(policy.server.get("port", 8000))

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn is not installed. Install with: pip install 'forgd-verdict[server]'",
            file=sys.stderr,
        )
        return 2

    if args.workers > 1:
        # Session cache and idempotency store are per-process. With >1 worker
        # a retry can land on a different process and rescan, and incremental
        # scanning degrades to per-worker. Correct, just less efficient --
        # swap InMemoryLRUCache for a shared store before scaling out.
        print(
            f"warning: {args.workers} workers; session cache and dedupe are per-process",
            file=sys.stderr,
        )
    uvicorn.run(
        "forgd_verdict.server.factory:app",
        host=host,
        port=port,
        workers=args.workers,
        log_level=args.log_level,
        # Transcripts are large and the org timeout covers upload.
        # Keep-alive matters: Anthropic reuses connections.
        timeout_keep_alive=75,
        # Connections and in-flight requests past this are answered 503 by
        # uvicorn before the app sees them.
        limit_concurrency=limit_concurrency,
        factory=False,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
