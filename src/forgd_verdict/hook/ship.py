"""Drain the adapter 2 spool.

Two triggers, one command:

  * `SessionEnd` with `async: true` in the hook settings. Costs the blocking
    path nothing, because the session is already over. The default.
  * A detached grandchild spawned by the hook itself, for near-real-time
    freshness, at the cost of one fork+exec (~5-15ms) on every hook call.

Two destinations:

  * A Store, which works today and is what the tests exercise.
  * An HTTP ingest endpoint, for the Azure service. Write-only and separate
    from both the verdict server and the dashboard on purpose: the verdict
    server must never grow a second auth scheme, and the dashboard must stay
    read-only so the thing users sign into holds no write credentials.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path

from .._hookenv import MARKER
from ..intake.verify import DEVICE_HEADER
from ..store.base import VerdictRecord
from ..store.spool import ShipResult, Spool, drain
from .device import hook_device_id
from .endpoint import destination, open_url, refusal
from .trust import overrides
from .trust import spool_root as trusted_spool_root

USER_AGENT = "forgd-verdict-hook/0.1"

# Answers to a batch that a retry would get again: 400, nothing in it was
# storable; 413, it is over the endpoint's size or record limit.
PERMANENT_REFUSALS = frozenset({400, 413})


def ship_to_store(store) -> callable:
    def _ship(records: Sequence[VerdictRecord]) -> bool:
        return store.write_verdicts(list(records)) == len(records)

    return _ship


def _warn_direct_store(spec: str) -> None:
    """Say it once, on stderr, where a hook's output is already read."""
    remote = "://" in spec and not spec.startswith("file://")
    if not remote:
        return  # a local file store is the development path, not a policy
    print(
        "forgd-verdict: hook.ship_store writes DIRECTLY to a remote store. "
        "This needs store credentials on every laptop and makes each one an "
        "unvalidated writer. Prefer hook.ship_endpoint with the fleet's intake "
        "token (hook.ship_token) -- see docs/PLATFORM.md, adapter 2.",
        file=sys.stderr,
    )


def ship_to_endpoint(url: str, token: str | None, timeout_s: float = 20.0,
                     ca_file: str | None = None, device: str | None = None,
                     signer=None) -> callable:
    def _ship(records: Sequence[VerdictRecord]) -> bool:
        refused = refusal(url)
        if refused:
            print(f"forgd-verdict: not shipping to hook.ship_endpoint: {refused}",
                  file=sys.stderr)
            return ShipResult(ok=False)
        body = ("\n".join(r.to_json() for r in records) + "\n").encode("utf-8")
        headers = {
            "content-type": "application/x-ndjson",
            "user-agent": USER_AGENT,
        }
        if signer is not None:
            # The certificate names the device; DEVICE_HEADER is not read.
            headers["authorization"] = signer(body, "intake")
        elif token:
            headers["authorization"] = f"Bearer {token}"
        if device:
            headers[DEVICE_HEADER] = device
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with open_url(request, timeout_s, ca_file) as response:
                if not 200 <= response.status < 300:
                    return ShipResult(ok=False,
                                      refused=response.status in PERMANENT_REFUSALS)
                payload = response.read()
        except urllib.error.HTTPError as exc:
            return ShipResult(ok=False, refused=exc.code in PERMANENT_REFUSALS)
        except (urllib.error.URLError, OSError, ValueError):
            # Offline, asleep, VPN down. The batch is parked and retried.
            return ShipResult(ok=False)

        # A 2xx is not "all of it landed". `/intake` returns 200 with
        # {"accepted": 7, "rejected": 3} for a batch it partly refused, so
        # the body is read before any of the spool file is deleted.
        total = len(records)
        try:
            reported = json.loads(payload or b"{}")
            accepted = int(reported["accepted"])
            refused = int(reported.get("rejected", 0))
        except (ValueError, TypeError, KeyError, RecursionError):
            # An endpoint that does not report counts. Trust the 2xx --
            # this has to keep working against a plain collector.
            return ShipResult(ok=True, accepted=total)
        return ShipResult(ok=True, accepted=accepted, rejected=refused)

    return _ship


def run_ship(
    policy,
    *,
    store_spec: str | None = None,
    endpoint: str | None = None,
    token: str | None = None,
    spool_root: str | None = None,
) -> dict[str, object]:
    """Drain the spool to `endpoint` or `store_spec`, else to the policy's
    `hook.ship_endpoint` or `hook.ship_store`.

    `store_spec` is the command line's `--store`. A remote store from the
    policy, which includes one the environment supplies through a
    placeholder or FORGD_VERDICT_SHIP_STORE, is opened only with
    `hook.project_overrides: true`, and so is a remote `--store` in a
    Windows hook process.
    """
    hook_cfg = policy.hook if policy is not None else {}
    endpoint = endpoint or destination(hook_cfg, "ship_endpoint")
    token = token or destination(hook_cfg, "ship_token")
    from_argv = bool(store_spec)
    store_spec = store_spec or destination(hook_cfg, "ship_store")

    spool = Spool(spool_root or trusted_spool_root(policy))

    if endpoint:
        from .devicesign import device_signer

        signer = device_signer(hook_cfg)
        if not token and signer is None:
            print("forgd-verdict: hook.ship_endpoint is set but hook.ship_token resolves to "
                  "nothing; the intake refuses an unauthenticated batch and the records "
                  "stay spooled", file=sys.stderr)
        root = Path(spool_root).parent if spool_root else None
        ship = ship_to_endpoint(endpoint, token, ca_file=hook_cfg.get("ca_file") or None,
                                device=hook_device_id(policy, root), signer=signer)
        target = {"endpoint": endpoint, "authenticated": bool(token) or signer is not None}
    elif (store_spec and (not from_argv or _windows_hook())
          and _remote_store(str(store_spec), policy) and not overrides(policy)):
        # Remote store SDKs take credentials, endpoints, CA bundles and
        # proxies from the environment, and so from the project's.
        if from_argv:
            why = "a Windows hook opens a remote store"
            skipped = "remote --store from a Windows hook needs hook.project_overrides: true"
        else:
            why = "a remote store is opened"
            skipped = "remote hook.ship_store needs hook.project_overrides: true"
        source = "--store" if from_argv else "hook.ship_store"
        print(f"forgd-verdict: not shipping to {source}: {why} only with "
              "hook.project_overrides: true; use hook.ship_endpoint", file=sys.stderr)
        return {
            "shipped": 0,
            "failed": 0,
            "batches": 0,
            "skipped": skipped,
            "spool": spool.describe(),
        }
    elif store_spec:
        # DIRECT TO THE STORE, with a warning.
        #
        # `ship_endpoint` is the supported path. Writing at the container
        # from a laptop means every laptop holds store credentials, every
        # laptop is an unvalidated writer of a schema nothing enforces,
        # and revoking one developer means rotating what all of them
        # hold. /intake exists so none of that is necessary: a per-
        # developer bearer token, a write-only endpoint, and the store
        # credential stays on the cluster.
        #
        # Left working rather than removed -- a fork with no cluster is a
        # real deployment, and a local file store is how the hook is
        # developed against. Loud, because the way this goes wrong is
        # that nobody decided it: a settings.json copied between projects
        # keeps pointing at a store that has since been deleted, and the
        # findings go nowhere with nothing to say so.
        _warn_direct_store(str(store_spec))
        from ..store import open_store

        ship = ship_to_store(open_store(
            str(store_spec), plugins=policy.plugin_allow if policy is not None else (),
            profile="hook"))
        target = {"store": str(store_spec), "direct": True}
    else:
        return {
            "shipped": 0,
            "failed": 0,
            "batches": 0,
            "skipped": "no destination configured",
            "spool": spool.describe(),
        }

    result = drain(spool, ship)
    result.update(target)
    result["spool"] = spool.describe()
    return result


def _windows() -> bool:
    return os.name == "nt"


def _windows_hook() -> bool:
    """True on Windows in a process started with `-X forgd_verdict_hook`,
    whose environment is the project's: POSIX starts the hook under
    `env -i`, Windows cannot."""
    return _windows() and MARKER in sys._xoptions


def _remote_store(spec: str, policy) -> bool:
    """True when `spec` opens a cloud store or a `stores` plugin."""
    if spec.startswith(("https://", "http://", "s3://", "gs://")):
        return True
    from ..plugins import find_entry, store_scheme

    scheme = store_scheme(spec)
    allow = policy.plugin_allow if policy is not None else ()
    return scheme is not None and find_entry(allow, "stores", scheme) is not None


def spawn_detached(policy_path: str | None = None, spool: str | None = None) -> bool:
    """Fire the drain in a grandchild that outlives this process.

    The exit code is part of the hook contract, so Claude Code waits for the
    hook to exit -- doing the upload inline would keep the developer's action
    blocked for the duration. A detached child lets the exit code land
    immediately.
    """
    argv = [sys.executable, "-I", "-X", "forgd_verdict_hook", "-m", "forgd_verdict.cli",
            "hook-ship"]
    if policy_path:
        argv += ["--policy", policy_path]
    if spool:
        argv += ["--spool", spool]
    try:
        subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # survives the hook's exit
            close_fds=True,
        )
        return True
    except OSError:
        return False


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="forgd-verdict hook-ship")
    parser.add_argument("--policy", default=None)
    parser.add_argument("--store", default=None, help="drain into a store")
    parser.add_argument("--endpoint", default=None, help="POST ndjson to a URL")
    parser.add_argument("--token", default=None, help="bearer token for --endpoint")
    parser.add_argument("--spool", default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    from ..policy import PolicyNotFound, default_policy, load_policy, policy_error

    # Without `--policy`, neither `$FORGD_VERDICT_POLICY` nor `./policy.yaml`
    # is read, as for the hook: both come from the project's environment.
    try:
        try:
            if args.policy is None:
                policy = default_policy(for_hook=True)
            else:
                policy = load_policy(args.policy, for_hook=True, drop_unknown_events=True)
        except PolicyNotFound:
            policy = default_policy(for_hook=True)
    except Exception as exc:  # noqa: BLE001 - never wedge a session
        print(f"forgd-verdict: could not load policy: {policy_error(exc)}", file=sys.stderr)
        return 1

    result = run_ship(
        policy,
        store_spec=args.store,
        endpoint=args.endpoint,
        token=args.token,
        spool_root=args.spool,
    )
    if not args.quiet:
        print(json.dumps(result, indent=2, default=str))
    return 0
