"""Adapter 2: the Claude Code hook CLI.

`forgd-verdict hook` reads the hook payload on stdin, runs the same scan core
as the verdict server, and answers in Claude Code's current hook output
contract.

Output contract verified against code.claude.com/docs/en/hooks on 2026-09-17
(note the page moved: docs.claude.com/en/docs/claude-code/hooks now 301s to
code.claude.com/docs/en/hooks):

  * On exit 0, stdout that starts with `{` and ends with `}` is parsed as the
    hook's JSON output. Everything else on stdout goes to the debug log --
    except on UserPromptSubmit, where it is injected as context.
  * A block is expressed DIFFERENTLY PER EVENT, and getting this wrong fails
    open silently -- the hook runs, reports success, and the prompt or call
    proceeds:
      - PreToolUse:       `{"hookSpecificOutput": {"hookEventName": ...,
                            "permissionDecision": "deny",
                            "permissionDecisionReason": ...}}`
      - UserPromptSubmit, UserPromptExpansion, PostToolUse:
                          `{"decision": "block", "reason": ...}` at the TOP
                            LEVEL. `permissionDecision` is a PreToolUse
                            concept; these events ignore it. Verified against
                            the "UserPromptSubmit decision control" section on
                            code.claude.com/docs/en/hooks. With the
                            PreToolUse shape and exit 0, a prompt carrying an
                            AWS key reaches the model.
      - Any other event has no shape here. In `hook.enabled_events` the
        hook's `load_policy` drops it with a warning, and every other
        caller refuses it.
  * `systemMessage` is a UNIVERSAL TOP-LEVEL field, not part of
    `hookSpecificOutput`. Nesting it there is the same class of silent
    failure: valid JSON, no warning, no message shown.
  * Exit 2 also blocks, taking the message from stderr. We use the JSON form:
    it carries a structured reason.

On allow we print NOTHING and exit 0. Emitting `permissionDecision: "allow"`
would be wrong: for PreToolUse that auto-approves the call and bypasses the
normal permission flow, turning a DLP scanner into a permission bypass.
Silence means "no decision; normal permission flow applies".
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import json
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any

from .. import build_id
from ..budget import Budget
from ..core import (
    ScanResult,
    decide,
    gitleaks_left_out,
    scan,
    t1_dropped,
    t1_unchecked,
    with_left_out,
)
from ..detectors.base import TIER_T0
from ..extract import artifact_units, hook_units
from ..intake.verify import DEVICE_HEADER, ON_ERROR_HEADER
from ..metadata import MetadataGuard, is_uuid, opaque_id
from ..models import (
    ACTION_ALLOW,
    ACTION_DENY,
    SEVERITY_WARN,
    Verdict,
    load_json,
    make_reference_id,
    ulid,
)
from ..policy import (
    DEFAULT_POLICY,
    HOOK_BLOCK_SHAPES,
    Policy,
    PolicyNotFound,
    default_policy,
    load_policy,
    parse_expansions,
    policy_error,
    policy_path,
)
from ..store.base import SOURCE_CODE_HOOK, FindingRow, VerdictRecord, pseudonym
from ..store.spool import Spool
from .device import hook_device_id, hook_salt, salt_namespace
from .endpoint import destination, open_url, refusal
from .ship import USER_AGENT
from .trust import spool_root, user_name

EXIT_OK = 0
EXIT_ERROR = 1

# Without `--policy` the hook reads neither `$FORGD_VERDICT_POLICY` nor
# `./policy.yaml`: both come from the project the hook runs in.
NO_POLICY = ("no policy file was given; the hook reads only --policy, not "
             "$FORGD_VERDICT_POLICY or ./policy.yaml")
NO_POLICY_PATH = "<no --policy>"

# The remote scan's own timeout, separate from `budget_ms`, which bounds
# the local scan. A cold call from a laptop can take over 200 ms, about
# half of it DNS, so a 200 ms timeout would send the first prompt of every
# session to the local fallback. Warm calls take about 100 ms.
REMOTE_TIMEOUT_MS = 1000
# Claude Code kills a hook that outlives its own `timeout` and lets the
# prompt through unscanned. Every shipped config sets that to 10 s, so
# the remote wait stops at half of it and leaves room for the fallback.
MAX_REMOTE_TIMEOUT_MS = 5000


def _block(event: str | None, reason: str) -> dict[str, Any]:
    """The block payload for `event`, in its HOOK_BLOCK_SHAPES shape.

    The wrong shape is not an error -- it is a silent allow. ValueError
    for an event with no documented shape; `load_policy` drops or refuses
    such an event in `hook.enabled_events`, so none reaches here.
    """
    shape = HOOK_BLOCK_SHAPES.get(event) if isinstance(event, str) else None
    if shape == "top":
        return {"decision": "block", "reason": reason}
    if shape == "tool":
        return {
            "hookSpecificOutput": {
                "hookEventName": event,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    raise ValueError(f"no documented block shape for hook event {event!r}")


# What a warning on each event calls the thing it matched.
_SUBJECTS = {
    "UserPromptSubmit": "prompt",
    "UserPromptExpansion": "command expansion",
    "PreToolUse": "tool call",
    "PostToolUse": "tool call",
}


def _subject(event: str | None) -> str:
    return _SUBJECTS.get(event, "request") if isinstance(event, str) else "request"


SpoolJob = Callable[[], None]


def run(payload: dict[str, Any], policy: Policy) -> tuple[int, str]:
    """Returns (exit_code, stdout), with the decision already spooled.
    Pure, so tests need no subprocess."""
    code, out, spool = evaluate(payload, policy)
    if spool is not None:
        spool()
    return code, out


def evaluate(payload: dict[str, Any], policy: Policy) -> tuple[int, str, SpoolJob | None]:
    """Returns (exit_code, stdout, spool). `spool` appends this decision to
    the local spool when called, and is None when there is nothing to
    spool. `main` calls it after the decision is on stdout."""
    event = payload.get("hook_event_name")
    enabled = policy.hook.get("enabled_events") or []

    # SessionEnd is the zero-cost shipping trigger: the session is over, so
    # draining the spool blocks nobody. Registered with async: true.
    if event == "SessionEnd":
        _drain_quietly(policy)
        return EXIT_OK, "", None

    if event not in enabled:
        return EXIT_OK, "", None

    if event == "UserPromptExpansion":
        refused = _refused_expansion(policy, payload)
        if refused is not None:
            return refused

    units = hook_units(payload)
    if not units:
        return EXIT_OK, "", None

    # A PER-DEVICE salt, not the deployment one and not empty.
    #
    # The deployment secret must never reach a laptop -- it leaks with the
    # first lost machine. But hashing with empty, which is what happened
    # before, made an export of adapter-2 rows brute-forceable back to the
    # matched secret: a bare sha256 of an SSN is about a billion guesses.
    # See hook/device.py.
    budget_ms = int(policy.hook.get("budget_ms", 200))

    # Remote first when configured, and the laptop then installs nothing.
    #
    # The point is one definition of a violation. Scanning locally meant
    # adapter 2 built its own detector set from its own profile, so the
    # same prompt could be judged differently here and on the server --
    # and getting T1 at all meant a gitleaks binary on every machine.
    remote = _remote_verdict(policy, payload, _remote_timeout_ms(policy))
    if remote is not None:
        return (*_respond(event, remote, policy), None)

    # LOCAL FALLBACK, and it has to exist. A hook that cannot reach the
    # service on a plane must still decide something, and the two honest
    # options are "scan with what is here" and "block everything". The
    # first keeps working; the second is a DLP control that turns into an
    # outage whenever the network does.
    #
    # It also means a deployment that configures no endpoint is unchanged.
    salt = hook_salt(policy)
    local, no_t1 = _without_path_gitleaks(_without_project_daemon(policy).for_profile("hook"))
    detectors = local.build_detectors(include_local_only=True, salt=salt, profile="hook")
    no_t1 = no_t1 or _missing_gitleaks(local, detectors)
    result: ScanResult = scan(units, detectors, Budget(budget_ms))
    dropped = with_left_out(result.detectors_skipped, ["gitleaks"] if no_t1 else [])
    verdict = decide(result.findings, policy, dropped=dropped)

    if no_t1:
        no_t1 += (", and without hook.project_overrides: true only an absolute path "
                  "is trusted")
    elif t1_dropped(result.detectors_skipped):
        no_t1 = "it failed during the scan"

    verdict, no_t1_message = _on_t1_not_run(policy, verdict, no_t1)

    spool = partial(_spool, policy, payload, event, verdict, result, salt, detectors,
                    dropped)

    if verdict.action == ACTION_DENY:
        return EXIT_OK, json.dumps(_block(event, verdict.deny_reason)), spool

    warnings = [f for f in result.findings if f.severity == SEVERITY_WARN]
    if warnings:
        detectors_seen: list[str] = []
        for f in warnings:
            if f.detector not in detectors_seen:
                detectors_seen.append(f.detector)
        from ..core import describe

        phrases = []
        for d in detectors_seen:
            phrase = describe(d, policy.plugin_phrases())
            if phrase not in phrases:
                phrases.append(phrase)
        # systemMessage is top-level. Nested inside hookSpecificOutput it is
        # valid JSON that nothing reads.
        out = json.dumps(
            {
                "systemMessage": (
                    f"forgd-verdict: this {_subject(event)} matched "
                    + ", ".join(phrases)
                    + " (warning only, not blocked)."
                )
            }
        )
        if no_t1_message:
            out = _with_system_message(out, no_t1_message)
        return EXIT_OK, out, spool

    # Allow: say nothing, decide nothing -- except that T1 did not run.
    if no_t1_message:
        return EXIT_OK, _with_system_message("", no_t1_message), spool
    return EXIT_OK, "", spool


def _expansion_matches(rule: dict[str, str], payload: dict[str, Any]) -> bool:
    return all(payload.get(key) == value for key, value in rule.items())


def _refused_expansion(policy: Policy, payload: dict[str, Any],
                       ) -> tuple[int, str, SpoolJob | None] | None:
    """The block for an expansion `hook.expansions` refuses, or None.

    A match in `deny` refuses, then a match in `allow` passes, then
    `default` decides. The reason names the command only.
    """
    rules = parse_expansions(policy.hook.get("expansions"))
    if any(_expansion_matches(r, payload) for r in rules["deny"]):
        refused = True
    elif any(_expansion_matches(r, payload) for r in rules["allow"]):
        refused = False
    else:
        refused = rules["default"] == "deny"
    if not refused:
        return None
    name = payload.get("command_name")
    name = "".join(c for c in name if c.isprintable())[:64] if isinstance(name, str) else ""
    reason = (f"forgd-verdict: /{name or 'command'} is not permitted by policy "
              "(expansion control)")
    verdict = Verdict(action=ACTION_DENY, deny_reason=reason,
                      reference_id=make_reference_id("expansion"))

    def spool() -> None:
        _spool(policy, payload, "UserPromptExpansion", verdict, ScanResult(),
               hook_salt(policy))

    return EXIT_OK, json.dumps(_block("UserPromptExpansion", reason)), spool


def _remote_timeout_ms(policy: Policy) -> int:
    """`hook.scan_timeout_ms`, capped below Claude Code's hook timeout.

    Capped rather than refused: a hook that errors on a bad value runs
    under `on_error`, which ships as `allow`. A value over the cap is
    clamped and said so on stderr.
    """
    raw = policy.hook.get("scan_timeout_ms", REMOTE_TIMEOUT_MS)
    try:
        ms = int(raw)
    except (TypeError, ValueError):
        print(f"forgd-verdict: hook.scan_timeout_ms {raw!r} is not a number; "
              f"using {REMOTE_TIMEOUT_MS} ms", file=sys.stderr)
        return REMOTE_TIMEOUT_MS
    if ms > MAX_REMOTE_TIMEOUT_MS:
        print(f"forgd-verdict: hook.scan_timeout_ms {ms} is over "
              f"{MAX_REMOTE_TIMEOUT_MS}; a hook that outlives Claude Code's "
              f"timeout lets the prompt through unscanned. Using "
              f"{MAX_REMOTE_TIMEOUT_MS} ms", file=sys.stderr)
        return MAX_REMOTE_TIMEOUT_MS
    return max(ms, 1)


def _remote_verdict(policy: Policy, payload: dict[str, Any],
                    timeout_ms: int) -> dict[str, Any] | None:
    """Ask the scan service. None means "could not", never "allow".

    Every failure returns None and the caller scans locally. That is the
    whole contract: a timeout, a 500, a DNS failure on a train, an
    unparseable body -- none of them is a decision, and treating any of
    them as one would be a control that silently stops.

    The timeout is `hook.scan_timeout_ms`, not `budget_ms`. It only costs
    anything when the service is slow or the network drops packets: a
    refused connection or a failed lookup returns at once. When it does
    expire, the local scan still runs after it, so the worst case per
    prompt is this timeout plus `budget_ms`.
    """
    endpoint = destination(policy.hook, "scan_endpoint")
    if not endpoint:
        return None
    refused = refusal(endpoint)
    if refused:
        print(f"forgd-verdict: not using hook.scan_endpoint: {refused}; "
              "scanning locally", file=sys.stderr)
        return None
    token = destination(policy.hook, "scan_token")
    from .devicesign import device_signer

    signer = device_signer(policy.hook)
    if not token and signer is None:
        print("forgd-verdict: hook.scan_endpoint is set but hook.scan_token resolves to "
              "nothing; the intake refuses an unauthenticated scan", file=sys.stderr)

    body = json.dumps(payload).encode("utf-8")
    headers = {"content-type": "application/json", "user-agent": USER_AGENT}
    if signer is not None:
        headers["authorization"] = signer(body, "scan")
    elif token:
        headers["authorization"] = f"Bearer {token}"
    device = hook_device_id(policy)
    if device:
        headers[DEVICE_HEADER] = device
    headers[ON_ERROR_HEADER] = str(policy.hook["on_error"])
    request = urllib.request.Request(endpoint, data=body, headers=headers,
                                     method="POST")
    try:
        with open_url(request, timeout_ms / 1000.0, policy.hook.get("ca_file") or None) as r:
            if not 200 <= getattr(r, "status", 200) < 300:
                return None
            out = json.loads(r.read())
    except urllib.error.HTTPError as exc:
        # Reached, and answered with an error. Named apart from
        # "unreachable" because the fix is different: 401 is a wrong
        # token, 403 a token not scoped to /scan, 5xx the service.
        print(f"forgd-verdict: scan service answered {exc.code}; "
              "scanning locally", file=sys.stderr)
        return None
    except Exception as exc:  # noqa: BLE001 - any failure is a fallback
        # stderr, not silence. A deployment that meant to scan remotely
        # and is quietly scanning locally has less coverage than it
        # thinks, and nothing else would say so.
        print(f"forgd-verdict: scan service unreachable ({type(exc).__name__}); "
              "scanning locally", file=sys.stderr)
        return None
    if (isinstance(out, dict) and out.get("action") in (ACTION_ALLOW, ACTION_DENY)
            and _is_names(out.get("tiers_dropped", []))):
        return out
    # A verdict the hook cannot read is a failed scan, not an allow: scan
    # locally as for an unreachable service.
    print("forgd-verdict: scan service answered with an unrecognised verdict; "
          "scanning locally", file=sys.stderr)
    return None


def _is_names(value: Any) -> bool:
    """Whether `value` is a list of strings."""
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _without_project_daemon(policy: Policy) -> Policy:
    """`policy` with a `$VAR` gitleaks daemon removed, unless project overrides are on.

    The shipped hook profile names `$FORGD_GITLEAKS_SOCKET` for the intake
    service's `/scan`. On a laptop that variable comes from the project's
    environment, and a socket answering `[]` would blind T1.
    """
    if policy.hook.get("project_overrides") is True:
        return policy
    raw = copy.deepcopy(policy.raw)
    sections = [raw.get("detectors"), (raw.get("hook") or {}).get("detectors")]
    for section in sections:
        gitleaks = (section or {}).get("gitleaks")
        if isinstance(gitleaks, dict) and str(gitleaks.get("daemon", "")).startswith("$"):
            del gitleaks["daemon"]
    return Policy(raw=raw)


def _binary_key(policy: Policy) -> str:
    """Where `binary` was set: the hook profile when it sets one."""
    hook_gitleaks = ((policy.hook.get("detectors") or {}).get("gitleaks") or {})
    if isinstance(hook_gitleaks, dict) and "binary" in hook_gitleaks:
        return "hook.detectors.gitleaks.binary"
    return "detectors.gitleaks.binary"


def _without_path_gitleaks(policy: Policy) -> tuple[Policy, str | None]:
    """`policy` with gitleaks disabled when it would run a binary found on
    PATH, and why; `policy` and None when project overrides are on.

    The project's environment sets PATH. A gitleaks it supplies would
    answer every scan with no findings. With no daemon, only an absolute
    `binary` is run. `policy` is the hook profile, from `for_profile("hook")`.
    """
    if policy.hook.get("project_overrides") is True:
        return policy, None
    gitleaks = (policy.raw.get("detectors") or {}).get("gitleaks")
    if (not isinstance(gitleaks, dict) or gitleaks.get("enabled", False) is False
            or gitleaks.get("daemon")):
        return policy, None
    binary = gitleaks.get("binary")
    if isinstance(binary, str) and os.path.isabs(binary):
        return policy, None
    raw = copy.deepcopy(policy.raw)
    raw["detectors"]["gitleaks"]["enabled"] = False
    why = ("detectors.gitleaks.binary is not set, here or as "
           "hook.detectors.gitleaks.binary" if not binary
           else f"{_binary_key(policy)} is not an absolute path")
    return policy.derive(raw), why


def _missing_gitleaks(policy: Policy, detectors) -> str | None:
    """Why T1 is not running, when `policy` configures gitleaks and none of
    `detectors` is it; None otherwise, and always None with project
    overrides on."""
    if policy.hook.get("project_overrides") is True:
        return None
    if not gitleaks_left_out(policy, detectors):
        return None
    return f"{_binary_key(policy)} does not exist or is not executable"


def _on_t1_not_run(policy: Policy, verdict: Verdict,
                   no_t1: str | None) -> tuple[Verdict, str]:
    """`verdict` under `hook.on_error` when gitleaks (T1) did not run for
    the reason `no_t1`, and the message said on stderr; `verdict` and ""
    when `no_t1` is empty or `verdict` already denies.

    Under `block` the verdict becomes a deny that says the content could
    not be checked. Under `allow` it stands.
    """
    if verdict.action == ACTION_DENY or not no_t1:
        return verdict, ""
    on_error = str(policy.hook["on_error"])
    message = (
        f"forgd-verdict: gitleaks (T1) did not run: {no_t1}. "
        f"hook.on_error is {on_error}, so this "
        + ("is blocked." if on_error == "block" else "is let through without T1."))
    print(message, file=sys.stderr)
    if on_error == "block":
        verdict = t1_unchecked(policy, verdict.findings)
    return verdict, message


def _respond(event: str | None, remote: dict[str, Any],
             policy: Policy) -> tuple[int, str]:
    """Turn a wire verdict into Claude Code's output contract.

    A `tiers_dropped` naming gitleaks follows `hook.on_error` as a local
    scan's does.
    """
    if remote.get("action") == ACTION_DENY:
        reason = remote.get("deny_reason") or "blocked by forgd-verdict"
        return EXIT_OK, json.dumps(_block(event, reason))
    no_t1 = ("the scan service reported it did not run"
             if t1_dropped(remote.get("tiers_dropped") or []) else None)
    verdict, no_t1_message = _on_t1_not_run(policy, Verdict(action=ACTION_ALLOW), no_t1)
    if verdict.action == ACTION_DENY:
        return EXIT_OK, json.dumps(_block(event, verdict.deny_reason))
    out = ""
    detectors = [d for d in (remote.get("detectors") or []) if d]
    if detectors:
        from ..core import describe

        phrases: list[str] = []
        for d in detectors:
            phrase = describe(d)
            if phrase not in phrases:
                phrases.append(phrase)
        out = json.dumps({
            "systemMessage": (
                f"forgd-verdict: this {_subject(event)} looks like it contains "
                + ", ".join(phrases) + "."),
        })
    if no_t1_message:
        out = _with_system_message(out, no_t1_message)
    return EXIT_OK, out


def _spool(policy: Policy, payload: dict[str, Any], event: str,
           verdict, result, salt: str = "", detectors=(), dropped=()) -> None:
    """Append this decision to the local spool.

    Local, with no network call: Claude Code waits for this process to exit,
    so anything here adds to the developer's wait. `main` runs it after the
    decision is on stdout. The tool name is checked by the metadata guard,
    which includes gitleaks as one subprocess call. Shipping happens
    elsewhere -- see hook/ship.py.

    Failure is swallowed. A spool problem must never stop a decision from
    being delivered.
    """
    if str(policy.hook.get("spool_enabled", True)).lower() in ("0", "false", "no"):
        return
    try:
        meta = MetadataGuard(detectors, salt, allow_subprocess=True)
        session = payload.get("session_id")
        session = str(session) if session else ""
        record = VerdictRecord(
            source=SOURCE_CODE_HOOK,
            # Claude Code's session ids are UUIDs and join with OTel's
            # `session.id`. Anything else is stored as a digest.
            session_id=(session if is_uuid(session) else opaque_id(session, salt, "sess"))
            if session else None,
            surface="claude-code-local",
            actor_hash=pseudonym(_local_user(), salt, "user"),
            # Which salt hashed the findings below, as a stable id and not
            # the salt. Without it a reader unions these with the server's
            # hashes and reports one leaked key as several.
            salt_namespace=salt_namespace(salt),
            action=verdict.action,
            # A hook deny IS enforced -- unlike the server's observe mode,
            # there is no shadow here. Recorded plainly.
            reference_id=verdict.reference_id,
            findings_count=len(result.findings),
            findings=[FindingRow.from_finding(f) for f in result.findings],
            tiers_dropped=list(dropped),
        )
        # `event` and the tool go in the locator space rather than new
        # columns, so the record shape stays shared with the other adapters.
        # Unique per decision, not per event type. One reference per event
        # type would make any per-frame operation hit every prompt at once
        # -- excluding one frame from the dashboard's rates would remove
        # every prompt decision recorded. Claude Code supplies `prompt_id` on
        # UserPromptSubmit and `tool_use_id` on PreToolUse; a ULID covers the
        # case where neither arrives.
        tool = payload.get("tool_name")
        kind = meta.one(str(tool), where="hook:tool_name") if tool else "prompt"
        unique = payload.get("tool_use_id") or payload.get("prompt_id")
        unique = opaque_id(str(unique), salt, "id") if unique else ulid()
        record.request_id = f"{event}:{kind}:{unique}"
        # FORGD_BUILD_COMMIT is set at image build, and on a laptop by the
        # project's environment if by anything.
        record.build = build_id(commit=False)
        Spool(spool_root(policy)).append(record)
    except Exception:  # noqa: BLE001 - never block a decision on telemetry
        pass


def _maybe_ship_detached(policy: Policy, policy_path: str | None,
                         spool: str | None = None) -> None:
    """Spawn the drain in a grandchild, if configured for freshness."""
    if str(policy.hook.get("ship_mode", "off")) != "detached":
        return
    try:
        from .ship import spawn_detached

        spawn_detached(policy_path, spool)
    except Exception:  # noqa: BLE001
        pass


def _drain_quietly(policy: Policy) -> None:
    if str(policy.hook.get("ship_mode", "off")) == "off":
        return
    try:
        from .ship import run_ship

        run_ship(policy)
    except Exception:  # noqa: BLE001 - SessionEnd must never error loudly
        pass


def _local_user() -> str:
    return user_name()


def _on_error_of(path) -> str:
    """`hook.on_error` from the file at `path` if it parses to a mapping that
    sets one, else DEFAULT_POLICY's."""
    default = str(DEFAULT_POLICY["hook"]["on_error"])
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            data = json.loads(text)
        else:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
    except Exception:  # noqa: BLE001 - an unreadable file has no on_error
        return default
    hook = data.get("hook") if isinstance(data, dict) else None
    value = hook.get("on_error") if isinstance(hook, dict) else None
    return str(value) if value is not None else default


def _no_policy_message(why: str, policy: Policy) -> str:
    on_error = str(policy.hook["on_error"])
    then = ("blocks it" if on_error == "block"
            else "lets the prompt or tool call through unscanned")
    return (f"forgd-verdict: {why}. The hook is scanning on its built-in defaults, "
            f"where hook.on_error is {on_error}, so a scan that fails {then}.")


def _with_system_message(out: str, message: str) -> str:
    """`out` (empty or one JSON object) with `message` as its top-level
    `systemMessage`, after any message it already carries."""
    body = json.loads(out) if out else {}
    if body.get("systemMessage"):
        message = f"{body['systemMessage']}\n{message}"
    body["systemMessage"] = message
    return json.dumps(body)


def _unparsed_deny_reason(raw: str | None, policy: Policy) -> str | None:
    """The deny reason when a T0 detector blocks on `raw`, stdin that did not
    parse, scanned as one unit; None when nothing blocks, when `raw` is None,
    or when the scan raises."""
    if not raw:
        return None
    try:
        detectors = [
            d for d in _without_project_daemon(policy).build_detectors(
                include_local_only=True, salt=hook_salt(policy),
                profile="hook")
            if getattr(d, "tier", 0) == TIER_T0]
        result = scan(artifact_units("stdin", raw), detectors,
                      Budget(int(policy.hook.get("budget_ms", 200))))
        verdict = decide(result.findings, policy)
    except Exception as exc:  # noqa: BLE001 - a failed scan falls back to on_error
        print(f"forgd-verdict: scan of the unparsed payload failed: {type(exc).__name__}",
              file=sys.stderr)
        return None
    return verdict.deny_reason if verdict.action == ACTION_DENY else None


def _parse_payload(raw: str | None) -> tuple[dict[str, Any] | None, str]:
    """The payload, or None and why it is unusable. The reason names the
    error and its position, never the text."""
    if raw is None:
        return None, "stdin is not valid UTF-8"
    if not raw.strip():
        return None, "stdin is empty"
    try:
        payload = load_json(raw)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON at line {exc.lineno} column {exc.colno}"
    except (RecursionError, ValueError):
        return None, "JSON nested too deeply"
    if not isinstance(payload, dict):
        return None, "it is not a JSON object"
    return payload, ""


class _Watchdog:
    """Ends the process with the `on_error` result if no decision is written
    within `hook.watchdog_ms` of `main` starting.

    The decision and the expiry write under one lock, so exactly one of them
    reaches stdout and stderr. Once a decision is written, expiry exits with
    its code, which stops a spool or detached spawn still running then.

    Where `signal.setitimer` exists and `main` runs on the main thread,
    expiry is a SIGALRM handler. Python runs it on the main thread between
    bytecodes and from C code that checks for signals, such as `_sre`
    matching, which holds the GIL throughout and so would keep a timer
    thread from running. Elsewhere expiry is a `threading.Timer`.
    """

    # When SIGALRM interrupts `deliver`, the main thread holds the lock, so
    # the handler re-arms this far ahead instead of waiting for it.
    _RETRY_S = 0.05

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = time.monotonic()
        self._timer: threading.Timer | None = None
        self._decided: int | None = None
        self._fired = False
        self.on_error = str(DEFAULT_POLICY["hook"]["on_error"])
        self.deadline_ms = int(DEFAULT_POLICY["hook"]["watchdog_ms"])
        self._alarm = (hasattr(signal, "setitimer")
                       and threading.current_thread() is threading.main_thread())
        self._previous: Any = None
        if self._alarm:
            self._previous = signal.signal(signal.SIGALRM, self._on_alarm)
        self.arm(self.deadline_ms)

    def arm(self, deadline_ms: int) -> None:
        """Expire `deadline_ms` after `main` started, replacing any earlier deadline."""
        with self._lock:
            self.deadline_ms = deadline_ms
            left = max(deadline_ms / 1000.0 - (time.monotonic() - self._started), 0.0)
            if self._alarm:
                # A zero interval disarms the timer, so a passed deadline is 1 us.
                signal.setitimer(signal.ITIMER_REAL, max(left, 1e-6))
                return
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(left, self._expire)
            self._timer.daemon = True
            self._timer.start()

    def deliver(self, code: int, out: str = "", err: str = "") -> int:
        """Write the decision and return `code`. Blocks for good if expiry
        got the lock first, since that ends the process."""
        with self._lock:
            if err:
                sys.stderr.write(err + "\n")
                sys.stderr.flush()
            if out:
                # No trailing newline: the contract keys on stdout ending with `}`.
                sys.stdout.write(out)
                sys.stdout.flush()
            self._decided = code
            return code

    def cancel(self) -> None:
        with self._lock:
            if self._alarm:
                signal.setitimer(signal.ITIMER_REAL, 0)
                # None is a handler installed from C, which cannot be restored.
                signal.signal(signal.SIGALRM,
                              signal.SIG_DFL if self._previous is None else self._previous)
            elif self._timer is not None:
                self._timer.cancel()

    def _on_alarm(self, signum: int, frame: Any) -> None:
        if not self._lock.acquire(blocking=False):
            signal.setitimer(signal.ITIMER_REAL, self._RETRY_S)
            return
        try:
            self._expire_locked()
        finally:
            self._lock.release()

    def _expire(self) -> None:
        with self._lock:
            self._expire_locked()

    def _expire_locked(self) -> None:
        if self._fired:
            return
        self._fired = True
        code = self._decided
        if code is None:
            message = (f"forgd-verdict: the scan did not finish within "
                       f"hook.watchdog_ms ({self.deadline_ms} ms); hook.on_error is "
                       f"{self.on_error}, so ")
            if self.on_error == "block":
                # Exit 2 blocks every blocking event and takes the message from stderr.
                _emit(sys.stderr, 2, message + "this is blocked.\n")
                code = 2
            else:
                message += "this went through unscanned."
                _emit(sys.stderr, 2, message + "\n")
                _emit(sys.stdout, 1, json.dumps({"systemMessage": message}))
                code = EXIT_OK
        with contextlib.suppress(Exception):
            sys.stdout.flush()
            sys.stderr.flush()
        os._exit(code)


def _emit(stream: Any, fd: int, text: str) -> None:
    """Write `text` to `stream`, or straight to `fd` when the stream raises.

    A signal handler that interrupts a write on the same buffered stream
    gets RuntimeError for the reentrant call.
    """
    try:
        stream.write(text)
        stream.flush()
    except Exception:  # noqa: BLE001 - the expiry message must reach the fd
        with contextlib.suppress(OSError):
            os.write(fd, text.encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    command = _subcommand(argv)
    if command is not None and argv[command] == "device-id":
        return _device_id_main(argv[:command] + argv[command + 1:])
    watchdog = _Watchdog()
    try:
        return _main(argv, watchdog)
    finally:
        watchdog.cancel()


def _subcommand(argv: list[str]) -> int | None:
    """The index of the first argument that is neither an option nor the
    value of `--policy` or `--spool`, or None."""
    i = 0
    while i < len(argv):
        if argv[i] in ("--policy", "--spool"):
            i += 2
        elif argv[i].startswith("-"):
            i += 1
        else:
            return i
    return None


def _device_id_main(argv: list[str]) -> int:
    """`forgd-verdict hook device-id`: print the device id the hook sends.

    For an MDM inventory script. 0 with the id on stdout; 1 when the hook
    would send none, with the reason on stderr; 2 when the policy file
    does not load.
    """
    parser = argparse.ArgumentParser(
        prog="forgd-verdict hook device-id",
        description="Print the device id this laptop's hook sends to the intake.")
    parser.add_argument("--policy", default=None, help="path to policy.yaml")
    args = parser.parse_args(argv)
    try:
        policy = (default_policy(for_hook=True) if args.policy is None
                  else load_policy(args.policy, for_hook=True))
    except Exception as exc:  # noqa: BLE001 - reported, never a traceback
        print(f"forgd-verdict hook device-id: {policy_error(exc)}", file=sys.stderr)
        return 2
    device = hook_device_id(policy)
    if not device:
        return 1
    print(device)
    return 0


def _main(argv: list[str] | None, watchdog: _Watchdog) -> int:
    parser = argparse.ArgumentParser(
        prog="forgd-verdict hook",
        description="Scan a Claude Code hook payload read from stdin.",
    )
    parser.add_argument("--policy", default=None, help="path to policy.yaml")
    parser.add_argument("--spool", default=None,
                        help="spool directory; the device salt goes in its parent")
    args = parser.parse_args(argv)

    # Bytes, decoded as UTF-8: the text layer of sys.stdin follows LC_ALL,
    # LC_CTYPE and LANG, which the project's environment sets.
    raw: str | None
    try:
        buffer = getattr(sys.stdin, "buffer", None)
        raw = buffer.read().decode("utf-8") if buffer is not None else sys.stdin.read()
    except UnicodeDecodeError:
        raw = None
    path = policy_path(args.policy) if args.policy is not None else Path(NO_POLICY_PATH)
    if args.policy is not None:
        watchdog.on_error = _on_error_of(path)
    no_policy: str | None = None
    try:
        try:
            if args.policy is None:
                no_policy = NO_POLICY
                policy = default_policy(for_hook=True)
            else:
                policy = load_policy(args.policy, for_hook=True)
        except PolicyNotFound as exc:
            no_policy = str(exc)
            policy = default_policy(for_hook=True)
    except Exception as exc:  # noqa: BLE001 - every load failure runs under on_error
        return watchdog.deliver(
            2 if _on_error_of(path) == "block" else EXIT_ERROR,
            err=f"forgd-verdict: could not load policy {path}: {policy_error(exc)}")
    watchdog.on_error = str(policy.hook["on_error"])
    watchdog.arm(int(policy.hook.get("watchdog_ms", watchdog.deadline_ms)))
    if no_policy is not None:
        print(_no_policy_message(no_policy, policy), file=sys.stderr)
    if args.spool:
        policy.raw.setdefault("hook", {})["spool"] = os.path.abspath(args.spool)

    # Empty stdin is malformed: Claude Code always sends a JSON object, so
    # nothing arriving means the payload was lost and the event is unknown.
    payload, problem = _parse_payload(raw)
    if payload is None:
        why = f"forgd-verdict: could not parse hook payload: {problem}"
        reason = _unparsed_deny_reason(raw, policy)
        if reason is not None:
            # Exit 2 blocks every blocking event and takes the message from stderr.
            return watchdog.deliver(2, err=f"{why}\n{reason}")
        return watchdog.deliver(2 if str(policy.hook["on_error"]) == "block" else EXIT_ERROR,
                                err=why)

    if payload.get("hook_event_name") == "SessionEnd":
        # No decision, and the drain runs under the async hook's own timeout.
        watchdog.cancel()

    try:
        code, out, spool = evaluate(payload, policy)
    except Exception as exc:
        on_error = str(policy.hook["on_error"])
        # Fail closed under `block`: exit 2 blocks and takes the message from stderr.
        return watchdog.deliver(2 if on_error == "block" else EXIT_ERROR,
                                err=f"forgd-verdict: scan failed: {type(exc).__name__}")

    if no_policy is not None:
        out = _with_system_message(out, _no_policy_message(no_policy, policy))

    watchdog.deliver(code, out=out)

    # The spool runs only once the decision is on stdout, and nothing it
    # raises reaches the exit code.
    if spool is not None:
        with contextlib.suppress(Exception):
            spool()

    # After the verdict is written, optionally hand shipping to a grandchild
    # that outlives this process. Cheap (one fork+exec) and off the decision.
    _maybe_ship_detached(policy, args.policy, args.spool and os.path.abspath(args.spool))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
