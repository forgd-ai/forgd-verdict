"""`python -m forgd_verdict.dashboard` -- serve the findings dashboard."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="forgd-verdict dashboard")
    parser.add_argument("--store", default=None, help="store spec (path or blob URL)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--require-principal",
        action="store_true",
        help="refused at startup; configure dashboard.auth in policy.yaml instead",
    )
    parser.add_argument(
        "--serve-open", action="store_true",
        help="bind a public interface with auth.mode none. The network in "
             "front of the dashboard is then the only control.")
    parser.add_argument("--render", metavar="PATH",
                        help="write a static HTML snapshot and exit")
    parser.add_argument("--window", default="7d", choices=["24h", "7d", "30d", "all"])
    args = parser.parse_args(argv)

    from ..entitlements import MODE_NONE
    from ..policy import PolicyNotFound
    from .app import create_app

    try:
        app = create_app(args.store, args.require_principal or None)
    except PolicyNotFound as exc:
        print(f"refusing to start the dashboard: {exc}", file=sys.stderr)
        return 2

    # An open dashboard must not bind a public interface by accident.
    #
    # DEFAULT_POLICY has no `dashboard.auth` key, so a deployment with no
    # policy file resolves to mode `none` -- and this entrypoint defaults
    # to 0.0.0.0. Every route then serves every finding to anyone who can
    # reach the port. It warns, but a warning does not stop the bind.
    #
    # Loopback is exempt: `--host 127.0.0.1` for a local look is the
    # reason the mode exists at all.
    if (not args.render and app.auth.mode == MODE_NONE
            and args.host not in ("127.0.0.1", "localhost", "::1")
            and not args.serve_open):
        print(
            f"refusing to bind {args.host}: dashboard.auth.mode is 'none', so "
            "every route would serve every finding to anyone who can reach "
            "the port.\n"
            "  set dashboard.auth in policy.yaml, or bind 127.0.0.1, or pass "
            "--serve-open if the network in front of this is the control.",
            file=sys.stderr,
        )
        return 2

    if args.render:
        # A shareable snapshot with no server and no credentials in it.
        html = app._page(args.window)
        with open(args.render, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"wrote {args.render} ({len(html):,} bytes)")
        return 0

    try:
        import uvicorn
    except ImportError:
        print("uvicorn is not installed: pip install 'forgd-verdict[server]'",
              file=sys.stderr)
        return 2
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
