"""`python -m forgd_verdict.connector` -- serve the findings connector.

Exits 2 without binding anything when the connector is disabled, when its
configuration does not validate, or when the `connector` extra is missing.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="forgd-verdict connector")
    parser.add_argument("--policy", default=None, help="policy file (default: "
                        "$FORGD_VERDICT_POLICY or policy.yaml)")
    parser.add_argument("--store", default=None, help="store spec (path or blob URL); "
                        "default $FORGD_VERDICT_STORE")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    from ..policy import load_policy, policy_error
    from . import config

    try:
        policy = load_policy(args.policy)
    except Exception as exc:  # noqa: BLE001 - YAML, JSON and OS errors alike
        print(f"refusing to start the connector: {policy_error(exc)}", file=sys.stderr)
        return 2
    try:
        cfg = config.load(policy)
    except ValueError as exc:
        print(f"refusing to start the connector: {exc}", file=sys.stderr)
        return 2
    if cfg is None:
        print("refusing to start the connector: connector.enabled is not true. Set "
              "connector.enabled (or FORGD_CONNECTOR_ENABLED) with connector.resource "
              "and connector.auth; see docs/CONNECTOR.md.", file=sys.stderr)
        return 2

    try:
        import mcp  # noqa: F401
        import uvicorn
    except ImportError:
        print("the connector needs its extra: pip install 'forgd-verdict[connector]'",
              file=sys.stderr)
        return 2

    import os

    spec = args.store or os.environ.get("FORGD_VERDICT_STORE")
    if not spec:
        print("refusing to start the connector: no findings store. Pass --store or set "
              "FORGD_VERDICT_STORE to the store the dashboard reads.", file=sys.stderr)
        return 2

    from ..store import open_store
    from .app import create_app
    from .tools import reader_from_policy

    reader = reader_from_policy(
        policy, cfg, open_store(spec, plugins=policy.plugin_allow, profile="connector"))
    if reader.overrides is not None:
        reader.overrides.start()
    uvicorn.run(create_app(cfg, reader), host=args.host, port=args.port, log_level="info",
                access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
