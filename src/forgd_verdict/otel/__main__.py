"""`python -m forgd_verdict.otel` -- run the OTLP collector with uvicorn."""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="forgd-verdict collect")
    parser.add_argument("--policy", default=None, help="path to policy.yaml")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
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
        print(f"refusing to start the collector: {exc}", file=sys.stderr)
        return 2
    config = policy.otel
    try:
        policy.refuse_unsalted("collector")
    except Unsalted as exc:
        print(f"refusing to start the collector: {exc}", file=sys.stderr)
        return 2
    host = args.host or config.get("host", "0.0.0.0")
    port = args.port or int(config.get("port", 8100))

    if not (config.get("orgs") or []):
        # Not fatal: a deployment can legitimately start before an org is
        # onboarded, and crash-looping would turn that into an alert. The
        # collector says the same thing at startup and refuses every export.
        print(
            "warning: otel.orgs is empty; every export will be refused with 401",
            file=sys.stderr,
        )

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn is not installed. Install with: pip install 'forgd-verdict[server]'",
            file=sys.stderr,
        )
        return 2

    uvicorn.run(
        "forgd_verdict.otel.factory:app",
        host=host,
        port=port,
        # One worker. The store sink and its queue are per-process, so a
        # second worker would halve the effective queue and flush twice as
        # often for no gain -- the same reason the verdict server warns.
        workers=1,
        log_level=args.log_level,
        timeout_keep_alive=75,
        factory=False,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
