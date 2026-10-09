"""`forgd-verdict` entry point.

    forgd-verdict serve       run the Inference hooks verdict server (adapter 1)
    forgd-verdict hook        Claude Code hook, payload on stdin (adapter 2)
    forgd-verdict compliance  post-hoc Compliance API scanner (adapter 3)
    forgd-verdict hook-ship   drain the local hook spool to a store/endpoint
    forgd-verdict ingest      one Compliance API ingest pass into the store
    forgd-verdict dashboard   serve (or render) the findings dashboard
    forgd-verdict reset-stats move the dashboard floor to now (keeps records)
    forgd-verdict overrides   show or change the runtime overrides (audited)
    forgd-verdict scan        scan a file or stdin with the same core; exits 1
                              on a deny, 3 when a blocking tier did not run
    forgd-verdict policy      show the effective merged policy
    forgd-verdict gitleaks-config --role ROLE
                              print the config ROLE's gitleaks daemon must load
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

EXIT_INCOMPLETE = 3


def _cmd_scan(args: argparse.Namespace) -> int:
    """1 on a deny; EXIT_INCOMPLETE on an allow when a blocking detector did
    not run, including a gitleaks left out at build; else 0."""
    from .budget import Budget
    from .core import (
        ScanResult,
        _blocking_tiers,
        decide,
        gitleaks_left_out,
        scan,
        with_left_out,
    )
    from .models import ScanUnit
    from .policy import load_policy

    policy = load_policy(args.policy)
    if args.path == "-":
        text = sys.stdin.read()
        locator = "stdin"
    else:
        with open(args.path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        locator = args.path

    salt = policy.hash_salt
    if not salt:
        import secrets

        salt = secrets.token_hex(16)
        print("privacy.hash_salt is empty; hashing with a random key that lives only "
              "in this process, so these digests match no other run",
              file=sys.stderr)
    detectors = policy.build_detectors(include_local_only=args.local_detectors,
                                       salt=salt, profile="compliance")
    budget = Budget(args.budget_ms or policy.budget_ms)
    result: ScanResult = scan([ScanUnit(locator, None, text)], detectors, budget)
    dropped = with_left_out(result.detectors_skipped,
                            ["gitleaks"] if gitleaks_left_out(policy, detectors) else [])
    verdict = decide(result.findings, policy, dropped=dropped)
    print(
        json.dumps(
            {
                "action": verdict.action,
                "deny_reason": verdict.deny_reason,
                "reference_id": verdict.reference_id,
                "findings": [f.to_log() for f in result.findings],
                "detectors_run": result.detectors_run,
                "detectors_skipped": result.detectors_skipped,
                "tiers_dropped": dropped,
                "budget_exceeded": result.budget_exceeded,
            },
            indent=2,
        )
    )
    if verdict.action == "deny":
        return 1
    unscanned = sorted(_blocking_tiers(policy, dropped))
    if unscanned:
        print(f"forgd-verdict scan: {', '.join(unscanned)} did not run, so this is "
              f"not a complete scan; exiting {EXIT_INCOMPLETE}", file=sys.stderr)
        return EXIT_INCOMPLETE
    return 0


def _cmd_policy(args: argparse.Namespace) -> int:
    from .policy import PolicyInvalid, load_policy, redacted

    try:
        policy = load_policy(args.policy)
    except PolicyInvalid as exc:
        print(f"forgd-verdict policy: {exc}", file=sys.stderr)
        return 2
    effective = redacted(policy)
    effective["_detectors_enabled"] = [
        d.name for d in policy.build_detectors(include_local_only=True, profile="dashboard")
    ]
    print(json.dumps(effective, indent=2))
    return 0


def _cmd_gitleaks_config(args: argparse.Namespace) -> int:
    from .policy import gitleaks_daemon_config, load_policy, policy_error

    try:
        policy = load_policy(args.policy)
    except Exception as exc:  # noqa: BLE001 - YAML, JSON and OS errors alike
        print(f"FATAL: the policy could not be loaded ({policy_error(exc)})",
              file=sys.stderr)
        return 2
    try:
        print(gitleaks_daemon_config(policy, args.role))
    except ValueError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2
    return 0


def _cmd_spotcheck(args: argparse.Namespace) -> int:
    """Judge a detector's precision against the content that produced it.

    Prints to the terminal and nowhere else: no store, no spool, no CSV, no
    log sink. The store deliberately keeps only hashes, which is why this
    has to re-fetch rather than read back.
    """
    from .compliance.client import ComplianceError
    from .compliance.scanner import ComplianceScanner
    from .policy import load_policy
    from .spotcheck import load_env_file, sample_chats, sample_sessions

    # Read the file before the policy, so `api_key: $ENV` resolves against it.
    if args.env_file:
        names = load_env_file(args.env_file)
        print(f"loaded {len(names)} name(s) from {args.env_file}: "
              f"{', '.join(names) or 'none new'}", file=sys.stderr)

    policy = load_policy(args.policy)
    _orgs = policy.compliance_orgs()
    try:
        scanner = ComplianceScanner(policy, org=_orgs[0] if _orgs else None)
    except ValueError:
        # The client refuses to construct without a key, which is the right
        # behaviour; this turns it into a usable instruction rather than a
        # traceback.
        print(
            "No Compliance Access Key. It is deliberately not stored in this "
            "repo. Either export ANTHROPIC_COMPLIANCE_ACCESS_KEY in your own "
            "shell, or put it in a gitignored .env and pass --env-file .env.",
            file=sys.stderr,
        )
        return 2

    ids = list(args.session or [])
    if args.from_store:
        from .store import open_store

        store = open_store(args.from_store, plugins=policy.plugin_allow,
                           profile="compliance")
        seen: list[str] = []
        from .store.base import SOURCE_COMPLIANCE_SCAN

        for rec in store.read_verdicts():
            # Session ids of the Compliance scan's own records only: a
            # Code hook record's session id is what a laptop sent.
            if (rec.source != SOURCE_COMPLIANCE_SCAN or not rec.session_id
                    or rec.session_id in seen):
                continue
            if any(
                f.detector == args.detector or f.detector.startswith(args.detector)
                for f in rec.findings
            ):
                seen.append(rec.session_id)
        ids.extend(seen)
        print(f"store names {len(seen)} session(s) carrying {args.detector}",
              file=sys.stderr)

    try:
        if ids:
            from .spotcheck import sample_named

            sample = sample_named(scanner, args.detector, ids, family=args.family)
            where = f"named session(s) [{len(ids)}]"
        elif args.chats:
            sample = sample_chats(scanner, args.detector,
                                  max_sources=args.max_sources)
            where = "claude.ai chats"
        else:
            sample = sample_sessions(
                scanner, args.detector, family=args.family, since=args.since,
                max_sources=args.max_sources,
            )
            where = f"{args.family} sessions"
    except ComplianceError as exc:
        hint = ""
        if exc.status == 401:
            hint = "  The key was rejected. Check it is the Compliance Access Key."
        elif exc.status == 403:
            hint = ("  Authenticated but not authorised. The key needs "
                    "read:compliance_activities and read:compliance_user_data.")
        print(f"Compliance API returned {exc.status}.{hint}", file=sys.stderr)
        return 1
    except OSError as exc:
        # No network, DNS, TLS. Not worth a traceback.
        print(f"Compliance API unreachable: {exc}", file=sys.stderr)
        return 1

    rows = sample.rows(args.limit, args.reveal)
    print(f"{args.detector} over {sample.sources_scanned} {where} "
          f"({sample.units_scanned} units)")
    print(f"{len(sample.values)} distinct values, showing {len(rows)}"
          + ("" if args.reveal else "  [masked; --reveal for full]"))
    if not rows:
        print("  nothing matched. Either the detector is disabled for this "
              "profile or the sample is too small.")
        return 0
    width = max((len(v) for v, _ in rows), default=8)
    for value, n in rows:
        print(f"  {value:<{width}}  x{n}")
    print("\nJudge precision from this, then discard the output. Nothing here "
          "was written to disk.")
    return 0


def _control_store(args: argparse.Namespace, fallback: str | None = None):
    """The store the runtime overrides live in, or None with a message."""
    import os

    from .policy import load_policy
    from .store import open_store

    policy = load_policy(args.policy)
    spec = (args.store or policy.server.get("store")
            or os.environ.get("FORGD_VERDICT_STORE") or fallback)
    if not spec:
        print("no store configured: pass --store, set server.store, or export "
              "FORGD_VERDICT_STORE", file=sys.stderr)
        return None
    return open_store(str(spec), plugins=policy.plugin_allow, profile="dashboard")


def _anchorer(store, signing_key, verify_keys):
    """A Verifier that writes a lockout verification record naming each head
    a change writes, on a store that can prove a lockout, or None. The
    writer identities come from FORGD_OVERRIDES_WRITER_IDENTITIES, as on the
    dashboard."""
    from .lockout import WRITTEN_BY_CLI, provable
    from .lockout_evidence.verifier import Verifier

    if not provable(store):
        return None
    return Verifier(store, signing_key=signing_key, verify_keys=verify_keys,
                    written_by=WRITTEN_BY_CLI)


def _anchored(anchorer, records) -> None:
    """Warn when the record naming the last head written is missing or does
    not show every writer identity locked out."""
    from .lockout_evidence import verifier

    if anchorer is None or not records:
        return
    if anchorer.pending is not None or records[-1] is None:
        print("warning: the change is applied, but the lockout verification naming its "
              "head could not be written; readers that hold no verified state adopt it "
              "once the dashboard writes one", file=sys.stderr)
    elif not records[-1]["ok"]:
        print("warning: the lockout verification naming this head does not show every "
              f"writer identity locked out (is {verifier.ENV_WRITER_IDENTITIES} set?); "
              "readers adopt it once the dashboard's next verification passes",
              file=sys.stderr)


def _change(args, store, change, **kwargs) -> tuple[int, object | None]:
    """Apply one audited change as the CLI. (exit code, Applied or None)."""
    from .overrides import (
        InvalidState,
        NoChange,
        Refused,
        StoreConflict,
        StoreForbidden,
        StoreReadError,
        apply_change,
        cli_actor,
        org_ids_of,
        org_screen_of,
    )
    from .policy import load_policy, policy_error

    try:
        policy = load_policy(args.policy)
    except Exception as exc:  # noqa: BLE001 - no scan, no change
        print(f"refused: the policy could not be loaded ({policy_error(exc)})",
              file=sys.stderr)
        return 2, None
    try:
        detectors = policy.build_detectors(profile="dashboard")
        org = org_screen_of(policy)
    except RuntimeError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2, None
    keys = _signing_keys(policy)
    if keys is None:
        return 2, None
    signing_key, verify_keys = keys
    anchorer = _anchorer(store, signing_key, verify_keys)
    records: list = []
    try:
        applied = apply_change(store, cli_actor(), change, detectors=detectors,
                               org_ids=org_ids_of(policy), salt=policy.hash_salt,
                               signing_key=signing_key, verify_keys=verify_keys,
                               after_write=(lambda state: records.append(
                                   anchorer.after_write(state)))
                               if anchorer is not None else None, **kwargs)
        _anchored(anchorer, records)
        return 0, applied
    except NoChange as exc:
        print(f"nothing to do: {org(str(exc))}", file=sys.stderr)
        return 0, None
    except InvalidState as exc:
        print(f"the runtime overrides object is invalid ({exc.code}); run "
              "`forgd-verdict overrides recover`", file=sys.stderr)
        return 1, None
    except Refused as exc:
        print(f"refused: {org(str(exc))}", file=sys.stderr)
        return 2, None
    except StoreForbidden as exc:
        print(f"refused: these credentials may not write {org(str(exc))}. Changing runtime "
              "overrides needs the control identity, not the writer identity the "
              "services run as; see \"Running the CLI as the control identity\" "
              "in docs/OVERRIDES.md", file=sys.stderr)
        return 2, None
    except StoreConflict:
        print("the runtime overrides object changed while this ran; run it again",
              file=sys.stderr)
        return 1, None
    except StoreReadError as exc:
        print(f"the store could not be read ({org(str(exc))}); nothing was changed",
              file=sys.stderr)
        return 1, None


def _show_keys(args):
    """(verify keys, key error) for `overrides show`, from the policy."""
    from .overrides import verify_keys_for
    from .policy import load_policy

    try:
        raw = load_policy(args.policy).raw
    except Exception:  # noqa: BLE001 - reported as a key error, and nothing is read
        raw = {}
    return verify_keys_for(raw, "cli", None)


def _cli_reader(args, store):
    """A RuntimeOverrides for the CLI that verifies records as `overrides
    show` does (_show_keys)."""
    from .overrides import RuntimeOverrides

    keys, key_error = _show_keys(args)
    return RuntimeOverrides(store, "cli", verify_keys=keys, key_error=key_error)


def _cold_refusal(store, state, keys) -> str | None:
    """The anchor error a cold reader would refuse `state` with
    (overrides.cold_refusal), printed to stderr as a warning; None when it
    would adopt it or there is no state."""
    from .overrides import ERROR_BEHIND_REQUEST, cold_refusal

    code = cold_refusal(store, state, keys) if state is not None else None
    if code is not None:
        why = ("a signed change request names a later revision" if code == ERROR_BEHIND_REQUEST
               else "it is not the head the newest signed lockout verification record names")
        print(f"warning: a service starting now would refuse this object ({code}): {why}; "
              "see Recovery in docs/OVERRIDES.md", file=sys.stderr)
    return code


def _signing_keys(policy):
    """(signing key, verify keys), or None after printing why there are none."""
    from .overrides_signing import ENV_SIGNING_KEY, KeyConfigError, from_policy

    try:
        cfg = from_policy(policy.raw)
    except KeyConfigError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return None
    if cfg.signing_key is None:
        print(f"refused: {ENV_SIGNING_KEY} is not set. Every runtime-override record is "
              "signed, so a change needs the control identity's signing key; see "
              "\"Signing keys\" in docs/OVERRIDES.md", file=sys.stderr)
        return None
    return cfg.signing_key, cfg.verify_keys


def _overrides_on(args: argparse.Namespace) -> bool:
    from .overrides import enabled_in
    from .policy import load_policy

    return enabled_in(load_policy(args.policy).raw)


def _excluded_labeler(args: argparse.Namespace):
    """overrides.exclusion_label with the policy's detectors and org ids;
    with neither when they cannot be built, so every value is withheld."""
    from .overrides import exclusion_label, org_ids_of
    from .policy import load_policy

    try:
        policy = load_policy(args.policy)
        detectors, org_ids = policy.build_detectors(profile="dashboard"), org_ids_of(policy)
    except Exception:  # noqa: BLE001 - no scan, no value
        print("warning: excluded request ids are withheld: the policy's detectors could "
              "not be built", file=sys.stderr)
        detectors, org_ids = None, frozenset()
    return lambda value: exclusion_label(value, detectors, org_ids)


def _org_screen(args: argparse.Namespace):
    """overrides.OrgScreen for the policy; one that withholds every value,
    with a warning on stderr, when the policy cannot be loaded."""
    from .overrides import ORG_SCREEN_UNAVAILABLE, org_screen_of
    from .policy import load_policy

    try:
        return org_screen_of(load_policy(args.policy))
    except Exception:  # noqa: BLE001 - no org ids, no value
        print("warning: values are withheld: the policy could not be loaded", file=sys.stderr)
        return ORG_SCREEN_UNAVAILABLE


def _print_frames(args: argparse.Namespace, store, excluded: set[str]) -> None:
    """The frames with findings, each excluded one's id through the labeler
    and every other id through the org screen."""
    rows = []
    for rec in store.read_verdicts():
        if not rec.findings or not rec.request_id:
            continue
        dets = sorted({f.detector for f in rec.findings})
        rows.append((rec.observed_at or "", rec.request_id,
                     rec.surface or "-", ",".join(dets)))
    rows.sort()
    print(f"{len(rows)} frame(s) with findings; {len(excluded)} excluded\n")
    label = _excluded_labeler(args) if any(r[1] in excluded for r in rows) else None
    org = _org_screen(args) if any(r[1] not in excluded for r in rows) else None
    for ts, rid, surf, dets in rows:
        shown = label(rid) if rid in excluded else org(rid)
        mark = "EXCLUDED" if rid in excluded else "        "
        print(f"  {mark}  {ts}  {surf:16} {dets[:46]:46} {shown}")
    if rows:
        print("\nExclude with: forgd-verdict exclude --request-id <ID>")


def _legacy_exclude(args: argparse.Namespace) -> int:
    """`exclude` with runtime overrides off: the markers/excluded_requests object."""
    from .policy import load_policy
    from .store import open_store

    policy = load_policy(args.policy)
    spec = args.store or policy.raw["server"].get("store") or "./findings"
    store = open_store(str(spec), plugins=policy.plugin_allow, profile="dashboard")

    if args.list:
        _print_frames(args, store, store.get_excluded())
        return 0

    if args.clear:
        store.set_excluded([])
        print("all exclusions removed")
        return 0

    if not args.request_id:
        print("nothing to do: pass --request-id, --list or --clear",
              file=sys.stderr)
        return 2

    current = store.get_excluded()
    merged = current | set(args.request_id)
    store.set_excluded(sorted(merged))
    added = len(merged) - len(current)
    print(f"{added} added, {len(merged)} excluded in total")
    return 0


def _legacy_reset_stats(args: argparse.Namespace) -> int:
    """`reset-stats` with runtime overrides off: the markers/stats_reset object."""
    import os

    from .policy import load_policy
    from .store import open_store
    from .store.base import utcnow

    policy = load_policy(args.policy)
    spec = args.store or policy.server.get("store") or os.environ.get(
        "FORGD_VERDICT_STORE"
    )
    if not spec:
        print("no store configured: pass --store or set server.store", file=sys.stderr)
        return 2
    store = open_store(str(spec), plugins=policy.plugin_allow, profile="dashboard")
    if args.clear:
        store.set_reset_marker("")
        print(json.dumps({"reset_at": None, "note": "marker cleared"}, indent=2))
        return 0
    when = args.at or utcnow()
    store.set_reset_marker(when)
    print(json.dumps({
        "reset_at": when,
        "note": "records are kept; the dashboard now starts from this point",
    }, indent=2))
    return 0


def _cmd_exclude(args: argparse.Namespace) -> int:
    """Manage exclusions: request ids kept out of the rates.

    A reset moves the floor and hides every record before it, real findings
    included. This omits named frames from the rates and leaves them in the
    store and the event log, which is what deliberate demo bait needs: it
    was a real evaluation, and it has no place in a deny rate someone reads
    as the organization's.
    """
    from .overrides import (
        ACTION_EXCLUDE,
        ACTION_EXCLUDE_CLEAR,
        Change,
        OverlaidStore,
    )

    if not _overrides_on(args):
        return _legacy_exclude(args)
    store = _control_store(args, fallback="./findings")
    if store is None:
        return 2

    if args.list:
        reader = _cli_reader(args, store)
        _cold_refusal(store, reader.refresh().state, reader.verify_keys)
        _print_frames(args, store, OverlaidStore(store, reader).get_excluded())
        return 0

    if args.clear:
        code, applied = _change(args, store, Change(ACTION_EXCLUDE_CLEAR))
        if code:
            return code
        if applied is not None:
            print("the object's exclusions are cleared")
        legacy = store.get_excluded()
        if legacy and not _cli_reader(args, store).legacy_retired():
            print(f"warning: {len(legacy)} exclusion(s) in the legacy "
                  "markers/excluded_requests object still apply until "
                  "`forgd-verdict overrides migrate-markers` runs", file=sys.stderr)
        return 0

    if not args.request_id:
        print("nothing to do: pass --request-id, --list or --clear",
              file=sys.stderr)
        return 2

    added = 0
    for rid in dict.fromkeys(args.request_id):
        code, applied = _change(args, store, Change(ACTION_EXCLUDE, value=rid))
        if code:
            return code
        added += applied is not None
    print(f"{added} added")
    return 0


def _cmd_reset_stats(args: argparse.Namespace) -> int:
    """Move the dashboard's floor without deleting anything.

    A period of testing pollutes every aggregate, and the honest fix is a
    clean slate rather than a caveat nobody reads. Records stay in the
    store, so the audit trail survives and the reset can be undone.
    """
    from .overrides import ACTION_RESET, ACTION_RESET_CLEAR, Change

    if not _overrides_on(args):
        return _legacy_reset_stats(args)
    store = _control_store(args)
    if store is None:
        return 2
    if args.clear:
        code, _ = _change(args, store, Change(ACTION_RESET_CLEAR))
        if code:
            return code
        legacy = store.get_reset_marker()
        if legacy and not _cli_reader(args, store).legacy_retired():
            print(json.dumps({"reset_at": legacy, "note": "the object's reset is cleared; "
                              "the legacy markers/stats_reset object still applies"},
                             indent=2))
            print("warning: the legacy markers/stats_reset object still applies until "
                  "`forgd-verdict overrides migrate-markers` runs", file=sys.stderr)
            return 0
        print(json.dumps({"reset_at": None, "note": "reset cleared"}, indent=2))
        return 0
    code, applied = _change(args, store, Change(ACTION_RESET, value=args.at))
    if code or applied is None:
        return code
    print(json.dumps({
        "reset_at": applied.state.stats_reset,
        "note": "records are kept; the dashboard now starts from this point",
    }, indent=2))
    return 0


def _cmd_overrides(args: argparse.Namespace) -> int:
    """Show or change the runtime overrides, audited as the CLI."""
    from .overrides import (
        ACTION_CLEAR,
        ACTION_CLEAR_ALL,
        ACTION_DENY_CLEAR,
        ACTION_DENY_DEVICE,
        ACTION_INIT,
        ACTION_RECOVER,
        ACTION_SET,
        ACTION_UNDENY_DEVICE,
        Change,
        RuntimeOverrides,
        history,
    )

    if args.what == "keygen":
        return _keygen(args)
    if args.what != "show" and not _overrides_on(args):
        print("refused: runtime overrides are off because dashboard.admins lists no "
              "groups, so no service would read this change; see \"Who may change "
              "it\" in docs/OVERRIDES.md", file=sys.stderr)
        return 2
    store = _control_store(args)
    if store is None:
        return 2
    if args.what == "show":
        keys, key_error = _show_keys(args)
        snap = RuntimeOverrides(store, "cli", verify_keys=keys, key_error=key_error).refresh()
        refusal = _cold_refusal(store, snap.state, keys)
        recent = (history(store, snap.state, verify_keys=keys)
                  if snap.state is not None else None)
        org = _org_screen(args)
        print(json.dumps({
            "runtime_overrides": snap.fields(),
            "cold_reader": {"adopts": refusal is None, "error": refusal}
            if snap.state is not None else None,
            "state": org(snap.state.to_json()) if snap.state is not None else None,
            "legacy": {"markers/stats_reset": store.get_reset_marker(),
                       "markers/excluded_requests": len(store.get_excluded()),
                       "retired": bool(snap.state and snap.state.legacy_markers_retired)},
            "recent_changes": [
                {k: r.get(k) for k in ("at", "action")}
                | org({k: r.get(k) for k in ("key", "old_value", "new_value")}
                      | {"by": (r.get("principal") or {}).get("name")})
                for r in (recent.applied if recent else [])],
        }, indent=2, default=str))
        return 0
    if args.what == "set":
        code, applied = _change(args, store, Change(ACTION_SET, args.key, args.value))
    elif args.what == "clear":
        code, applied = _change(args, store, Change(ACTION_CLEAR, args.key))
    elif args.what == "clear-all":
        code, applied = _change(args, store, Change(ACTION_CLEAR_ALL))
    elif args.what == "recover":
        code, applied = _change(args, store, Change(ACTION_RECOVER), recover_mode=args.mode)
    elif args.what == "init":
        code, applied = _change(args, store, Change(ACTION_INIT))
    elif args.what == "deny-device":
        code, applied = _change(args, store, Change(ACTION_DENY_DEVICE, value=args.device))
    elif args.what == "undeny-device":
        code, applied = _change(args, store, Change(ACTION_UNDENY_DEVICE, value=args.device))
    elif args.what == "clear-devices":
        code, applied = _change(args, store, Change(ACTION_DENY_CLEAR))
    else:
        return _migrate_markers(args, store)
    if applied is not None:
        print(json.dumps({"revision": applied.state.revision,
                          "audit_id": applied.audit_id}, indent=2))
    return code


def _keygen(args: argparse.Namespace) -> int:
    """Generate an Ed25519 key pair for signing runtime-override records."""
    from .overrides_signing import ENV_SIGNING_KEY, ENV_VERIFY_KEY, generate, write_private_key

    pair = generate()
    out: dict[str, str] = {"key_id": pair.kid, "public_key": pair.public}
    if args.private_key_file:
        try:
            write_private_key(args.private_key_file, pair.private)
        except FileExistsError:
            print(f"refused: {args.private_key_file} exists; keygen does not overwrite a key",
                  file=sys.stderr)
            return 2
        out["private_key_file"] = args.private_key_file
    else:
        out["private_key"] = pair.private
    out["signing_env"] = ENV_SIGNING_KEY
    out["verify_env"] = ENV_VERIFY_KEY
    print(json.dumps(out, indent=2))
    return 0


def _migrate_markers(args, store) -> int:
    """Fold the legacy markers/* objects into the object and retire them.

    One audited write folds both values in and sets legacy_markers_retired;
    readers holding that object ignore markers/* from then on. The legacy
    objects are read and never written. Idempotent: once retired, nothing
    is written, whatever the legacy objects hold.
    """
    from .overrides import ACTION_MIGRATE, Change

    legacy_reset = store.get_reset_marker()
    legacy_ids = frozenset(store.get_excluded())
    code, applied = _change(args, store, Change(ACTION_MIGRATE),
                            migrate=(legacy_reset, legacy_ids))
    if code or applied is None:
        return code
    print(json.dumps({"migrated": {"stats_reset": legacy_reset,
                                   "excluded_requests": len(legacy_ids)},
                      "legacy_markers_retired": True,
                      "revision": applied.state.revision}, indent=2))
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    import os

    from .compliance.ingest import run_ingest
    from .policy import load_policy
    from .store import open_store

    policy = load_policy(args.policy)
    spec = args.store or policy.server.get("store") or os.environ.get(
        "FORGD_VERDICT_STORE"
    )
    if not spec:
        print(
            "no store configured: pass --store, set server.store, or export "
            "FORGD_VERDICT_STORE",
            file=sys.stderr,
        )
        return 2
    # Read for its status only: no allowlisted key applies to the ingest jobs.
    from .lockout import LOCKOUT_MISSING
    from .overrides import ERROR_READER_TOO_OLD, ERROR_UNINITIALIZED, reader_for

    try:
        reader = reader_for(
            policy.raw,
            open_store(str(spec), plugins=policy.plugin_allow, profile="compliance"),
            "ingest")
    except RuntimeError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    snapshot = reader.refresh()
    overrides = snapshot.fields()
    if not snapshot.ready:
        print(json.dumps({"runtime_overrides": overrides}, indent=2, default=str))
        why = (snapshot.error if snapshot.error in (LOCKOUT_MISSING, ERROR_UNINITIALIZED)
               else "the runtime overrides need a newer forgd-verdict release"
               if snapshot.error == ERROR_READER_TOO_OLD
               else "the runtime overrides could not be confirmed")
        print(f"refusing to ingest: {why} (status {snapshot.status}); see "
              "docs/OVERRIDES.md", file=sys.stderr)
        return 1
    # A scheduled job must not crash-loop before the key exists. Exit
    # cleanly and say why, so a cron firing into an unconfigured deployment
    # is a log line rather than a failure alert.
    # Asked of the resolved org list, not of `compliance.api_key`: with
    # several orgs the top-level key is absent and checking it would skip a
    # correctly-configured multi-org deployment without saying why.
    from .managed.scanner import run_managed_ingest

    # Whether any is configured, not whether they are valid: a bad
    # managed_agents block is reported by run_managed_ingest and must not
    # stop the Compliance pass of a deployment configured for both.
    managed = bool((policy.raw.get("managed_agents") or {}).get("workspaces"))
    if not policy.compliance_orgs() and managed:
        # A Platform-only deployment: Managed Agents and no Enterprise org,
        # so no Compliance Access Key to hold. Said, so a Compliance key
        # lost from the vault of a deployment meant to have both is visible.
        from .applog import warn_if_unsalted

        warn_if_unsalted(logging.getLogger("forgd_verdict.ingest"), policy)
        summary = {
            "compliance": {"skipped": "no Compliance Access Key configured"},
            "managed_agents": run_managed_ingest(
                policy, open_store(str(spec), plugins=policy.plugin_allow, profile="managed"),
                max_sessions=args.max_sessions),
            "runtime_overrides": overrides}
        print(json.dumps(summary, indent=2, default=str))
        return 0
    if not policy.compliance_orgs():
        print(json.dumps({
            "skipped": "no Compliance Access Key configured",
            "remediation": (
                "create one in claude.ai > Organization settings > API with "
                "read:compliance_activities and read:compliance_user_data, "
                "then set it as the job's ANTHROPIC_COMPLIANCE_ACCESS_KEY secret"
            ),
            "runtime_overrides": overrides,
        }, indent=2))
        return 0

    summary = run_ingest(
        policy,
        open_store(str(spec), plugins=policy.plugin_allow, profile="compliance"),
        family=args.family,
        since=args.since,
        max_sessions=args.max_sessions,
        include_denials=not args.no_denials,
        include_chats=not args.no_chats,
    )
    if managed:
        summary["managed_agents"] = run_managed_ingest(
            policy, open_store(str(spec), plugins=policy.plugin_allow, profile="managed"),
            max_sessions=args.max_sessions)
    summary["runtime_overrides"] = overrides
    print(json.dumps(summary, indent=2, default=str))
    return 0


def _cmd_compliance(args: argparse.Namespace) -> int:
    from .compliance import ComplianceScanner
    from .policy import load_policy

    policy = load_policy(args.policy)
    if args.what != "denials":
        from .policy import Unsalted
        try:
            policy.refuse_unsalted("compliance sessions")
        except Unsalted as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 2
    # Interactive commands act on the first configured org. `ingest` is the
    # one that walks them all; this is for looking at something by hand.
    orgs = policy.compliance_orgs()
    scanner = ComplianceScanner(policy, org=orgs[0] if orgs else None)
    if len(orgs) > 1:
        print(f"note: {len(orgs)} orgs configured; showing {scanner.org_label}",
              file=sys.stderr)

    if args.what == "denials":
        activities = list(scanner.denials(since=args.since))
        for activity in activities:
            print(
                json.dumps(
                    {
                        "id": activity.get("id"),
                        "created_at": activity.get("created_at"),
                        "type": activity.get("type"),
                        "reference_id": scanner.extract_reference_id(activity),
                        "actor": (activity.get("actor") or {}).get("email_address"),
                    }
                )
            )
        print(
            json.dumps({"summary": {"denial_activities": len(activities)}}),
            file=sys.stderr,
        )
        return 0

    reports = []
    for report in scanner.scan_sessions(
        family=args.family, since=args.since, max_sessions=args.max_sessions
    ):
        reports.append(report)
        print(json.dumps(report.to_json()))
    if args.join:
        print(json.dumps({"join": scanner.join_denials(reports, since=args.since)}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="forgd-verdict", description=__doc__)
    parser.add_argument("--policy", default=None, help="path to policy.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("serve", help="run the Inference hooks verdict server", add_help=False)
    sub.add_parser("hook", help="Claude Code hook (payload on stdin)", add_help=False)
    sub.add_parser("dashboard", help="serve the findings dashboard", add_help=False)
    sub.add_parser("hook-ship", help="drain the local hook spool", add_help=False)
    sub.add_parser("collect", help="run the OTLP collector (adapter 4)", add_help=False)
    sub.add_parser(
        "intake",
        help="run the findings intake (adapter 2's receiving end)",
        add_help=False,
    )

    p_scan = sub.add_parser("scan", help="scan a file or stdin")
    p_scan.add_argument("path", nargs="?", default="-")
    p_scan.add_argument("--budget-ms", type=int, default=None)
    p_scan.add_argument(
        "--local-detectors",
        action="store_true",
        help="also run hook-only detectors (shell exfil)",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_policy = sub.add_parser("policy", help="print the effective merged policy")
    p_policy.set_defaults(func=_cmd_policy)

    p_glc = sub.add_parser("gitleaks-config",
                           help="print the config the gitleaks daemon must load")
    p_glc.add_argument("--role", required=True, choices=("collect", "intake", "server"),
                       help="the role whose daemon this is; only its profiles are compared")
    p_glc.set_defaults(func=_cmd_gitleaks_config)

    p_comp = sub.add_parser("compliance", help="post-hoc Compliance API scanner")
    p_comp.add_argument("what", choices=["sessions", "denials"], default="sessions", nargs="?")
    p_comp.add_argument("--family", choices=["local", "remote"], default="local")
    p_comp.add_argument("--since", default=None, help="RFC 3339, e.g. 2026-09-01T00:00:00Z")
    p_comp.add_argument("--max-sessions", type=int, default=None)
    p_comp.add_argument("--join", action="store_true", help="join against denial activities")
    p_comp.set_defaults(func=_cmd_compliance)

    p_ing = sub.add_parser("ingest", help="one Compliance API ingest pass")
    p_ing.add_argument("--store", default=None, help="store spec (path or blob URL)")
    p_ing.add_argument(
        "--family", default="local,remote",
        help="session families to scan, comma-separated. Both by default: "
             "they are different populations, and scanning only `local` "
             "never sees a remote session.")
    p_ing.add_argument("--since", default=None)
    p_ing.add_argument("--max-sessions", type=int, default=None)
    p_ing.add_argument("--no-denials", action="store_true")
    p_ing.add_argument(
        "--no-chats",
        action="store_true",
        help="skip claude.ai chats (they are a separate endpoint family)",
    )
    p_ing.set_defaults(func=_cmd_ingest)

    p_spot = sub.add_parser(
        "spotcheck",
        help="re-fetch and print the values behind one detector's findings",
    )
    p_spot.add_argument("detector", help="e.g. presidio:person, checksum:nhs-number")
    p_spot.add_argument(
        "--env-file",
        default=None,
        help="load KEY=value lines (e.g. .env) before running; not read unless named",
    )
    p_spot.add_argument("--family", choices=["local", "remote"], default="local")
    p_spot.add_argument("--chats", action="store_true", help="sample claude.ai chats")
    p_spot.add_argument(
        "--session",
        action="append",
        default=None,
        metavar="ID",
        help="check these session or chat ids only; repeatable. Ask the store "
             "which ones carried the finding -- blind sampling misses it.",
    )
    p_spot.add_argument(
        "--from-store",
        default=None,
        metavar="SPEC",
        help="read the session ids that carried this detector from a store",
    )
    p_spot.add_argument("--since", default=None)
    p_spot.add_argument("--max-sources", type=int, default=10)
    p_spot.add_argument("--limit", type=int, default=25, help="distinct values to show")
    p_spot.add_argument(
        "--reveal",
        action="store_true",
        help="print values in full instead of masked (they are PII; do not paste)",
    )
    p_spot.set_defaults(func=_cmd_spotcheck)

    p_exc = sub.add_parser(
        "exclude",
        help="keep named frames out of the dashboard's rates (records are kept)",
    )
    p_exc.add_argument("--store", default=None)
    p_exc.add_argument(
        "--request-id", action="append", default=None, metavar="ID",
        help="exclude this frame; repeatable",
    )
    p_exc.add_argument(
        "--list", action="store_true",
        help="list frames that carry findings, with their ids, and exit",
    )
    p_exc.add_argument(
        "--clear", action="store_true",
        help="remove every exclusion; with runtime overrides on, the object's "
             "only, never markers/*",
    )
    p_exc.set_defaults(func=_cmd_exclude)

    p_rst = sub.add_parser(
        "reset-stats",
        help="start the dashboard's numbers from now; records are kept",
    )
    p_rst.add_argument("--store", default=None)
    p_rst.add_argument("--at", default=None, help="RFC 3339; defaults to now")
    p_rst.add_argument("--clear", action="store_true",
                       help="remove the reset; with runtime overrides on, the object's "
                            "only, never markers/*")
    p_rst.set_defaults(func=_cmd_reset_stats)

    p_ovr = sub.add_parser(
        "overrides",
        help="show or change the runtime overrides (docs/OVERRIDES.md); audited",
    )
    p_ovr.add_argument("--store", default=None)
    ovr = p_ovr.add_subparsers(dest="what", required=True)
    ovr.add_parser("show", help="the object, what is in force, and recent changes")
    ovr.add_parser("init", help="write the genesis record and an empty object; every "
                                "service is not ready until it runs")
    p_set = ovr.add_parser("set", help="override an allowlisted key")
    p_set.add_argument("key", help="server.mode")
    p_set.add_argument("value", help="observe or enforce")
    p_clr = ovr.add_parser("clear", help="remove one override")
    p_clr.add_argument("key")
    ovr.add_parser("clear-all", help="remove every override; markers are kept")
    p_deny = ovr.add_parser("deny-device",
                            help="refuse an intake device id on every route, without a "
                                 "redeploy")
    p_deny.add_argument("device", help="the id in the X-Forgd-Device header")
    p_undeny = ovr.add_parser("undeny-device", help="accept a denied device id again")
    p_undeny.add_argument("device")
    ovr.add_parser("clear-devices", help="accept every denied device id again")
    ovr.add_parser("migrate-markers",
                   help="fold the legacy markers/* objects in and retire them; "
                        "run once, safe to repeat")
    p_rec = ovr.add_parser("recover",
                           help="write a valid object over a deleted or invalid one, keeping "
                                "the state of the newest audit chain that verifies")
    p_rec.add_argument("--mode", choices=("observe", "enforce"), default=None,
                       help="set this server.mode override over the kept state; default: "
                            "keep its mode, or none if no chain verifies")
    p_key = ovr.add_parser(
        "keygen", help="generate an Ed25519 key pair for signing override records; "
                       "the public key is always printed")
    dest = p_key.add_mutually_exclusive_group(required=True)
    dest.add_argument("--private-key-stdout", action="store_true",
                      help="print the private key with the public key")
    dest.add_argument("--private-key-file", metavar="PATH",
                      help="write the private key to a new file with mode 0600")
    for p in (p_ovr, *ovr.choices.values()):
        p.set_defaults(func=_cmd_overrides)

    # `serve` and `hook` own their own flags; hand the remainder straight
    # over. Walk only the leading global options, stepping over each one's
    # value, so `forgd-verdict --policy X serve --port 9000` reaches `serve`.
    argv = list(sys.argv[1:] if argv is None else argv)
    passthrough = {"serve": _run_serve, "hook": _run_hook,
                   "dashboard": _run_dashboard, "hook-ship": _run_hook_ship,
                   "collect": _run_collect,
                   "intake": _run_intake}
    takes_value = {"--policy"}
    i = 0
    while i < len(argv):
        token = argv[i]
        if token in passthrough:
            return passthrough[token](argv[i + 1 :], argv[:i])
        if token in takes_value:
            i += 2
            continue
        if token.startswith("--") and "=" in token:
            i += 1
            continue
        break

    args = parser.parse_args(argv)
    from .policy import PolicyInvalid, PolicyNotFound, Unsalted

    try:
        return args.func(args)
    except (PolicyInvalid, PolicyNotFound, Unsalted) as exc:
        print(f"forgd-verdict {args.command}: {exc}", file=sys.stderr)
        return 2


def _run_serve(rest: list[str], before: list[str]) -> int:
    from .server.__main__ import main as serve_main

    return serve_main(_merge_policy_flag(rest, before))


def _run_hook(rest: list[str], before: list[str]) -> int:
    from .hook.cli import main as hook_main

    return hook_main(_merge_policy_flag(rest, before))


def _run_hook_ship(rest: list[str], before: list[str]) -> int:
    from .hook.ship import main as ship_main

    return ship_main(_merge_policy_flag(rest, before))


def _run_intake(rest: list[str], before: list[str]) -> int:
    from .intake.__main__ import main as intake_main

    return intake_main(_merge_policy_flag(rest, before))


def _run_collect(rest: list[str], before: list[str]) -> int:
    from .otel.__main__ import main as collect_main

    return collect_main(_merge_policy_flag(rest, before))


def _run_dashboard(rest: list[str], before: list[str]) -> int:
    from .dashboard.__main__ import main as dash_main

    return dash_main(rest)


def _merge_policy_flag(rest: list[str], before: list[str]) -> list[str]:
    """Allow `forgd-verdict --policy X serve` as well as `serve --policy X`."""
    if "--policy" in before and "--policy" not in rest:
        idx = before.index("--policy")
        if idx + 1 < len(before):
            return ["--policy", before[idx + 1], *rest]
    return rest


if __name__ == "__main__":
    raise SystemExit(main())
