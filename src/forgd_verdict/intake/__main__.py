"""`forgd-verdict intake` -- adapter 2's receiving end."""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="forgd-verdict intake")
    parser.add_argument("--policy", default=None, help="path to policy.yaml")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    # uvicorn imports the factory by string and the factory calls
    # load_policy() with no argument, so --policy has to reach it through
    # the environment or it silently affects only host and port. Same trap
    # the collector and the verdict server hit.
    if args.policy:
        os.environ["FORGD_VERDICT_POLICY"] = str(args.policy)

    from ..policy import PolicyNotFound, Unsalted, load_policy

    try:
        policy = load_policy(args.policy)
    except PolicyNotFound as exc:
        print(f"refusing to start intake: {exc}", file=sys.stderr)
        return 2
    config = policy.raw.get("intake") or {}
    try:
        policy.refuse_unsalted("intake")
    except Unsalted as exc:
        print(f"refusing to start intake: {exc}", file=sys.stderr)
        return 2
    host = args.host or config.get("host", "0.0.0.0")
    port = args.port or int(config.get("port", 8200))

    from .verify import verifiers

    try:
        usable = sum(len(v.credentials()) for v in verifiers(policy))
    except ValueError as exc:
        print(f"refusing to start intake: {exc}", file=sys.stderr)
        return 2
    if not usable:
        # Not fatal, for the same reason the collector is not: a deployment
        # can start before anyone is onboarded, and crash-looping would turn
        # that into an alert. It refuses every submission and says so.
        print(
            "warning: no intake.fleet or intake.clients entry has a usable "
            "token; every submission will be refused with 401",
            file=sys.stderr,
        )

    import uvicorn

    uvicorn.run(
        "forgd_verdict.intake.factory:app",
        host=host,
        port=port,
        # One worker: the counters are per-process, and a second would
        # split the by-client attribution across two sets of numbers.
        workers=1,
        log_level=args.log_level,
        timeout_keep_alive=75,
        factory=False,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
