"""policy.yaml loading and the detector registry it drives.

One policy file feeds every adapter. Adapter-specific keys live in their
own sections, such as `server:`, `hook:`, `compliance:` and `otel:`;
everything under `detectors:`, `scan:`, `deny:`, and `privacy:` is shared,
which is the point of the design.

PyYAML is a base dependency: `load_policy` defaults to `policy.yaml`. A
`.json` policy loads without it.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import logging
import os
import re
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import unquote_to_bytes

from .detectors import (
    ChecksumDetector,
    EntropyDetector,
    GitleaksDetector,
    LLMGuardPIIDetector,
    PresidioPIIDetector,
    ShellExfilDetector,
    T0RegexDetector,
)
from .detectors.gitleaks import BASELINE_CONFIG, GITLEAKS_CONFIG_ENV
from .models import (
    ORG_UNATTRIBUTED,
    SEVERITIES,
    env_or_literal,
    hasher_for,
    require_strong_token,
    shown_text,
    shown_url,
    usable_secret,
)
from .plugins import (
    BUILTIN_DETECTORS,
    RESERVED_DETECTOR_NAMES,
    PluginAllow,
    PluginDetector,
    PluginRegistry,
    find_entry,
    load_plugins,
    parse_allow,
    store_scheme,
)

log = logging.getLogger("forgd_verdict.policy")


# Env values are strings; these are the only non-trivial coercions.
def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def json_list(value: str) -> list:
    """A JSON array, for the one setting a chart has to pass as a list."""
    parsed = json.loads(value)
    if not isinstance(parsed, list):
        raise ValueError("expected a JSON array")
    return parsed


def comma_list(value: str) -> list[str]:
    """Comma-separated values, each stripped; empty entries are kept."""
    return [part.strip() for part in value.split(",")]


# Settings that must be changeable without rebuilding the image.
# `mode` is the one that matters: flipping observe -> enforce is the
# riskiest operation in the whole system, and it has to be reversible in
# seconds from a deployment console, not via a rebuild-and-roll.
ENV_OVERRIDES: Mapping[str, tuple[tuple[str, ...], Any]] = MappingProxyType({
    "FORGD_VERDICT_MODE": (("server", "mode"), str),
    "FORGD_VERDICT_LOG_LEVEL": (("server", "log_level"), str),
    "FORGD_VERDICT_BUDGET_MS": (("scan", "budget_ms"), int),
    "FORGD_VERDICT_STORE": (("server", "store"), str),
    "FORGD_DASHBOARD_REQUIRE_PRINCIPAL": (("dashboard", "require_principal"), _truthy),
    # Per-project opt-in for shipping local hook decisions. `off` by default
    # and deliberately so: a central record of what developers typed and
    # which commands they tried is a different question from scanning
    # prompts in flight, and it should not be inherited from installing a
    # hook. With `hook.project_overrides: true` it can be turned on for one
    # project -- a Claude Code `env` block in .claude/settings.json --
    # without editing the policy everyone else shares.
    "FORGD_VERDICT_SHIP_MODE": (("hook", "ship_mode"), str),
    # The spool's destination. Separate from `server.store`, which is the
    # verdict server's own sink: the two adapters write to the same store in
    # production but are configured on different machines by different
    # people, and conflating them would mean a laptop inherited the server's
    # destination by accident.
    "FORGD_VERDICT_SHIP_STORE": (("hook", "ship_store"), str),
    # Every FORGD_VERDICT_SHIP_* and FORGD_VERDICT_SCAN_* override applies
    # only when the policy file sets `hook.project_overrides: true`
    # (PROJECT_OVERRIDE_ENV).
    "FORGD_VERDICT_SHIP_ENDPOINT": (("hook", "ship_endpoint"), str),
    "FORGD_VERDICT_SHIP_TOKEN": (("hook", "ship_token"), str),
    "FORGD_VERDICT_SCAN_ENDPOINT": (("hook", "scan_endpoint"), str),
    "FORGD_VERDICT_SCAN_TOKEN": (("hook", "scan_token"), str),
    "FORGD_VERDICT_SCAN_TIMEOUT_MS": (("hook", "scan_timeout_ms"), int),
    # Auth mode, so a local run can be opened in a browser and a deployment
    # can be tightened without a rebuild. It can only be changed to a mode
    # the policy already validates, and `none` is logged loudly on startup.
    "FORGD_DASHBOARD_AUTH_MODE": (("dashboard", "auth", "mode"), str),
    # The proxy that strips inbound copies of the trusted header. An
    # attestation, not a credential -- it names something an operator
    # has checked.
    "FORGD_DASHBOARD_STRIPPED_BY": (("dashboard", "auth", "stripped_by"), str),
    # Identity provider settings the Helm chart supplies. Not secrets: an
    # issuer URL and a claim name. The issuers list arrives as JSON because
    # an environment variable cannot carry a list.
    "FORGD_DASHBOARD_ISSUERS": (("dashboard", "auth", "issuers"), json_list),
    "FORGD_DASHBOARD_GROUPS_CLAIM": (("dashboard", "auth", "groups_claim"), str),
    "FORGD_DASHBOARD_PLATFORM": (("dashboard", "auth", "platform"), str),
    "FORGD_DASHBOARD_ALB_ARN": (("dashboard", "auth", "alb_arn"), str),
    # The findings connector. None of these is a secret.
    "FORGD_CONNECTOR_ENABLED": (("connector", "enabled"), _truthy),
    "FORGD_CONNECTOR_RESOURCE": (("connector", "resource"), str),
    "FORGD_CONNECTOR_SCOPES": (("connector", "scopes"), json_list),
    "FORGD_CONNECTOR_REQUIRED_SCOPE": (("connector", "required_scope"), str),
    "FORGD_CONNECTOR_ALLOWED_ORIGINS": (("connector", "allowed_origins"), json_list),
    "FORGD_CONNECTOR_AUTH_MODE": (("connector", "auth", "mode"), str),
    "FORGD_CONNECTOR_ISSUER": (("connector", "auth", "issuer"), str),
    "FORGD_CONNECTOR_JWKS_URL": (("connector", "auth", "jwks_url"), str),
    "FORGD_CONNECTOR_AUDIENCE": (("connector", "auth", "audience"), json_list),
    "FORGD_CONNECTOR_ISSUERS": (("connector", "auth", "issuers"), json_list),
    "FORGD_CONNECTOR_GROUPS_CLAIM": (("connector", "auth", "groups_claim"), str),
    # The public keys runtime-override records are verified with
    # (overrides_signing.py). The private key is read from the variable
    # overrides.signing_key names, not placed in the policy.
    "FORGD_OVERRIDES_VERIFY_KEY": (("overrides", "verify_keys"), comma_list),
})

# What `load_policy` and `load_identity` read: `ENV_OVERRIDES` as this
# module defined it, unaffected by a later rebind of the name or a change
# to the mapping behind the proxy.
_ENV_OVERRIDE_ITEMS = tuple(ENV_OVERRIDES.items())

DEFAULT_POLICY: dict[str, Any] = {
    "detectors": {
        "t0_regex": {"enabled": True, "severity": "block"},
        # Identifiers decided by arithmetic rather than by a pattern.
        "checksums": {"enabled": True, "severity": "block"},
        # Assigned values that look randomly generated. Heuristic, so
        # it warns rather than blocks until its FP rate is known.
        "entropy": {"enabled": True, "severity": "warn"},
        "gitleaks": {"enabled": "auto", "severity": "block"},
        "llmguard_pii": {"enabled": False, "severity": "warn"},
        "presidio_pii": {"enabled": False, "severity": "warn"},
        # Behavioural, adapter 1 only. Off unless a profile turns it on.
        "provenance": {"enabled": False, "severity": "warn"},
        "taint": {"enabled": False, "severity": "warn"},
        "shell_exfil": {"enabled": False, "severity": "warn"},
    },
    "scan": {
        "budget_ms": 1500,
        "session_cache": {"ttl_hours": 24, "max_sessions": 5000},
    },
    "privacy": {"hash_salt": ""},
    "deny": {"contact_line": ""},
    "server": {
        "mode": "observe",
        # Bearer token for GET /metrics. Unset means the endpoint is
        # disabled, because on a platform with all-or-nothing ingress
        # (Container Apps, App Runner, Cloud Run) an unauthenticated
        # /metrics is internet-readable -- and while it carries no matched
        # content, it does expose traffic volume, which Claude surfaces are
        # in use, and the deny rate.
        "metrics_token": "",
        "host": "0.0.0.0",
        "port": 8000,
        "secrets": [],
        "require_signature": True,
        "max_body_bytes": 64 * 1024 * 1024,
        # See Policy.preauth_body_budget_bytes, body_read_timeout_s and
        # limit_concurrency.
        "preauth_body_budget_bytes": 256 * 1024 * 1024,
        "body_read_timeout_s": 15,
        "limit_concurrency": 1024,
        "idempotency_ttl_s": 900,
        "idempotency_max": 10000,
        "archive_dir": "./archive",
        "csv_path": "./timings.csv",
        "required_headers": {},
        "on_internal_error": "fail",
        # What to do when a BLOCKING tier did not run -- dropped for
        # budget, or failed. `allow` is the shipped behaviour and is
        # right for the shipped policy, where no blocking detector sits
        # in T2. A deployment that puts one there and means it wants
        # `deny`: otherwise a caller can burn the budget with benign
        # filler and the tier that would have denied never runs.
        "on_tier_dropped": "allow",
        # Durable findings sink. Empty disables it. A local path or a
        # blob URL; see store.open_store. Findings only, never content.
        "store": "",
        # Batching for the findings sink. Larger batches mean fewer
        # objects, and the dashboard reads one object per HTTP request.
        "store_batch_size": 50,
        "store_flush_s": 60,
    },
    "hook": {
        "budget_ms": 200,
        "enabled_events": ["UserPromptSubmit", "UserPromptExpansion", "PreToolUse"],
        "on_error": "allow",
        "project_overrides": False,
        # See parse_watchdog_ms.
        "watchdog_ms": 8000,
        # Which `UserPromptExpansion` events may proceed to the scan, by
        # the command they name. See parse_expansions.
        "expansions": {"default": "allow", "deny": [], "allow": []},
    },
    "dashboard": {"require_principal": False},
    "compliance": {
        "base_url": "https://api.anthropic.com",
        "api_key": "$ANTHROPIC_COMPLIANCE_ACCESS_KEY",
        "anthropic_version": "2023-06-01",
        "state_path": "./compliance-state.json",
        "page_limit": 100,
        "lookback_minutes": 10,
    },
}


def _positive_server_int(section: Mapping[str, Any], key: str) -> int:
    """`section[key]` as an integer of at least 1, or ValueError naming
    `server.<key>`."""
    raw = section.get(key)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
        raise ValueError(f"server.{key} must be a positive integer, got {raw!r}")
    return raw


def _deep_merge(base: dict, override: dict) -> dict:
    """A new dict: `override` merged over `base`, sharing no nested dict with either.

    It copied the top level only, so a policy file that did not mention a
    section shared DEFAULT_POLICY's own dict for it -- and an environment
    override written into that section afterwards (FORGD_VERDICT_MODE into
    `server`) changed the module-wide default for every policy loaded
    after, in the same process.
    """
    out = {k: _deep_merge(v, {}) if isinstance(v, dict) else v for k, v in base.items()}
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


@dataclass
class DetectorConfig:
    enabled: bool | str
    severity: str

    @classmethod
    def parse(cls, name: str, raw: Any) -> DetectorConfig:
        if not isinstance(raw, dict):
            raise ValueError(f"detectors.{name} must be a mapping")
        severity = raw.get("severity", "block")
        if severity not in SEVERITIES:
            raise ValueError(
                f"detectors.{name}.severity must be one of {SEVERITIES}, got {severity!r}"
            )
        return cls(enabled=raw.get("enabled", False), severity=severity)


def state_key(state_path: str) -> str:
    """The store key adapter 3 keeps a cursor under: the state_path's file
    name, or `compliance-state.json` when it has none."""
    return os.path.basename(state_path) or "compliance-state.json"


@dataclass
class Policy:
    raw: dict[str, Any] = field(default_factory=dict)
    _org_resolver: Any = field(default=None, init=False, repr=False, compare=False)
    _plugins: PluginRegistry = field(default_factory=PluginRegistry, init=False,
                                     repr=False, compare=False)
    # Unknown, disabled detector names already warned about for this load.
    _warned: set[str] = field(default_factory=set, init=False, repr=False, compare=False)

    # --- shared ---------------------------------------------------------
    @property
    def hash_salt(self) -> str:
        return env_or_literal((self.raw.get("privacy") or {}).get("hash_salt", "")) or ""

    @property
    def allow_unsalted(self) -> bool:
        """`privacy.allow_unsalted`, true only when the policy file sets the
        boolean `true`. It is not resolved from the environment, and no
        `ENV_OVERRIDES` entry or runtime override reaches `privacy`."""
        return (self.raw.get("privacy") or {}).get("allow_unsalted") is True

    def refuse_unsalted(self, role: str) -> None:
        """Raise Unsalted when the salt is empty and the policy file does
        not set `privacy.allow_unsalted: true`."""
        if self.hash_salt or self.allow_unsalted:
            return
        raise Unsalted(
            f"{role}: refusing to start with an empty privacy.hash_salt. Findings "
            "are logged and stored with a digest of the matched value, and a bare "
            "sha256 of a low-entropy value can be reversed. Set privacy.hash_salt "
            "(FORGD_HASH_SALT in the shipped policy) to a deployment secret, or set "
            "privacy.allow_unsalted: true in the policy file to accept that.")

    @property
    def budget_ms(self) -> int:
        """Milliseconds for the whole scan.

        Floored at 1. Zero or negative means every tier past T0 is
        skipped on every frame, on every adapter, with no error -- and
        `FORGD_VERDICT_BUDGET_MS` reached it through a bare `int()` with
        nothing checking the result. `mode` is validated against an
        allowlist; this is the same kind of setting.
        """
        raw = self.raw["scan"]["budget_ms"]
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"scan.budget_ms must be a positive integer, got {raw!r}"
            ) from exc
        if value < 1:
            raise ValueError(
                f"scan.budget_ms must be at least 1 ms, got {value}. Zero or "
                "less silently drops every tier past T0 on every frame."
            )
        return value

    @property
    def cache_ttl_s(self) -> float:
        return float(self.raw["scan"]["session_cache"]["ttl_hours"]) * 3600.0

    @property
    def cache_max_sessions(self) -> int:
        return int(self.raw["scan"]["session_cache"]["max_sessions"])

    @property
    def contact_line(self) -> str:
        return str(self.raw["deny"].get("contact_line", "") or "")

    # --- adapter 1 ------------------------------------------------------
    @property
    def server(self) -> dict[str, Any]:
        return self.raw["server"]

    @property
    def mode(self) -> str:
        mode = self.server.get("mode", "observe")
        if mode not in ("observe", "enforce", "archive"):
            raise ValueError(f"server.mode must be observe|enforce|archive, got {mode!r}")
        return mode

    @property
    def secrets(self) -> list[str]:
        resolved = [env_or_literal(s) for s in self.server.get("secrets") or []]
        return [s for s in resolved if s]

    @property
    def on_tier_dropped(self) -> str:
        value = self.server.get("on_tier_dropped", "allow")
        if value not in ("allow", "deny"):
            raise ValueError(
                f"server.on_tier_dropped must be allow|deny, got {value!r}"
            )
        return value

    @property
    def require_signature(self) -> bool:
        """The only authentication the verdict server has.

        Validated rather than coerced. `bool()` turned every falsy YAML
        value into "off", and the dangerous one is a bare key -- a line
        reading `require_signature:` with nothing after it parses as None
        and disables signature checking while LOOKING present:

            require_signature:      raw=None   -> False
            require_signature: 0    raw=0      -> False
            require_signature: ""   raw=''     -> False

        Refused, the way `mode` already is. CLAUDE.md: prefer refusing to
        start over a quiet value that happens to work here.
        """
        raw = self.server.get("require_signature", True)
        if not isinstance(raw, bool):
            raise ValueError(
                "server.require_signature must be true or false, got "
                f"{raw!r}. A bare `require_signature:` with no value parses "
                "as null and would turn off the only authentication the "
                "verdict server has."
            )
        return raw

    @property
    def max_body_bytes(self) -> int:
        """The largest hook body the verdict server reads."""
        return _positive_server_int(self.server, "max_body_bytes")

    @property
    def preauth_body_budget_bytes(self) -> int:
        """Bytes of hook body the verdict server holds, across every request,
        before their signatures are verified.

        The signature covers the raw body, so the body has to be read before
        the caller is known; this bounds what unauthenticated callers can
        make the process hold. A request that would take it past the budget
        is answered 503 without its body being read. Below `max_body_bytes`
        a body at the protocol maximum could never be admitted, so that is
        refused.
        """
        budget = _positive_server_int(self.server, "preauth_body_budget_bytes")
        if budget < self.max_body_bytes:
            raise ValueError(
                f"server.preauth_body_budget_bytes ({budget}) is below "
                f"server.max_body_bytes ({self.max_body_bytes}): a frame at the "
                "body limit would be refused with 503 on every delivery"
            )
        return budget

    @property
    def body_read_timeout_s(self) -> float:
        """Seconds the verdict server waits for a whole hook body."""
        raw = self.server.get("body_read_timeout_s")
        try:
            value = float(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"server.body_read_timeout_s must be a positive number, got {raw!r}"
            ) from exc
        if not value > 0 or value == float("inf"):
            raise ValueError(
                f"server.body_read_timeout_s must be a positive number, got {raw!r}"
            )
        return value

    @property
    def limit_concurrency(self) -> int:
        """uvicorn's `limit_concurrency` for the verdict server: connections
        and in-flight requests past it are answered 503."""
        return _positive_server_int(self.server, "limit_concurrency")

    @property
    def metrics_token(self) -> str | None:
        """The bearer for `/metrics` and `/stats`, or None when unset or a
        placeholder. Raises ValueError when it is too short to be one."""
        server = self.raw.get("server") or {}
        token = usable_secret(env_or_literal(server.get("metrics_token", "")))
        return require_strong_token("server.metrics_token", token) if token else None

    @property
    def required_headers(self) -> dict[str, str]:
        """Static headers the admin configured on the Anthropic side (up to 16).

        A second factor alongside the signature, useful when the endpoint is
        shared. Never a substitute for signature verification. Raises
        PolicyInvalid when a value resolves to nothing.
        """
        out = {}
        for name, value in (self.server.get("required_headers") or {}).items():
            resolved = env_or_literal(value)
            if not resolved:
                shown = value if _unset(value) else "empty"
                raise PolicyInvalid(
                    f"server.required_headers.{name} is {shown}, which resolves to "
                    "nothing. The verdict server would stop checking that header. Set "
                    "the variable, or remove the header from the policy and from the "
                    "Anthropic side.")
            out[name.lower()] = resolved
        return out

    # --- adapter 2 ------------------------------------------------------
    @property
    def hook(self) -> dict[str, Any]:
        return self.raw["hook"]

    @property
    def dashboard(self) -> dict[str, Any]:
        return self.raw["dashboard"]

    # --- findings connector ---------------------------------------------
    @property
    def connector(self) -> dict[str, Any]:
        """`connector`, or `{}`. Validated by `connector.config`, not here."""
        raw = self.raw.get("connector")
        return raw if isinstance(raw, dict) else {}

    # --- adapter 3 ------------------------------------------------------
    @property
    def compliance(self) -> dict[str, Any]:
        return self.raw["compliance"]

    def entitlements(self, auth: dict[str, Any] | None = None,
                     auth_path: str = "dashboard.auth"):
        """`dashboard.entitlements` resolved to store partitions.

        Validated against `auth`, the block that will verify the callers,
        named `auth_path` in errors. `dashboard.auth` when not given; the
        connector passes `connector.auth`.

        Config names orgs by id under `orgs`, Managed Agents workspaces by
        key under `workspaces`, and intake clients by name under `clients`.
        Orgs and workspaces are resolved to their pseudonyms when a caller's
        access is checked. Intake records, a fleet's and an agent's alike,
        file under an org and are granted through `orgs`. A `clients` grant
        reads the partition a client, laptop or agent, wrote under its own
        name before records filed under orgs; the name is the partition. A
        value this deployment is not configured for resolves to a partition
        that holds no record, or to nothing, and grants no rows.

        Raises ValueError when an `orgs` value is a configured workspace's key
        or label, a `workspaces` value is a workspace's label and no
        workspace's key, or a `clients` value is not in intake's name form or
        not in `intake.clients`. The message names a workspace by label only.
        """
        from .entitlements import MODE_NONE, MODE_OIDC_JWT, Entitlements, scoped_group

        raw = (self.dashboard.get("entitlements") or {})
        entries = [e for e in (raw.get("map") or []) if isinstance(e, dict)]
        if not entries:
            return Entitlements()

        if auth is None:
            auth = self.dashboard.get("auth") or {}
        mode = str(auth.get("mode", MODE_NONE))
        if mode != MODE_OIDC_JWT:
            # A group membership we cannot verify is one the caller can
            # choose. Under `trusted_header` the header is the only claim
            # and there is no group in it; under `none` there is no identity
            # at all. Refusing at load time rather than serving a control
            # that looks enforced and is not.
            raise ValueError(
                f"dashboard.entitlements requires {auth_path}.mode "
                f"{MODE_OIDC_JWT!r}; got {mode!r}. Group membership from an "
                "unverified source is not an entitlement."
            )

        if env_or_literal(str(auth.get("platform") or "")) == "iap":
            # The map matches groups and nothing else, and an IAP token
            # carries none, so every viewer would be refused.
            raise ValueError(
                f"dashboard.entitlements.map is set but {auth_path}.platform is "
                "iap: Identity-Aware Proxy tokens carry no groups, so no entry can "
                "match and every viewer would be refused. Remove "
                "dashboard.entitlements.map, or sign in through an identity "
                "provider whose token carries groups.")
        issuers = len([i for i in (auth.get("issuers") or []) if isinstance(i, dict)]) + (
            1 if env_or_literal(auth.get("issuer")) else 0)
        by_group: dict[str, set[str]] = {}
        for entry in entries:
            group = str(env_or_literal(entry.get("group")) or "")
            if not group:
                continue
            issuer = str(env_or_literal(entry.get("issuer")) or "")
            if issuers > 1 and not issuer:
                # With two IdPs, a bare group name matches a group from
                # either, so an admin of one can create a group named after
                # an entry and read whatever it grants.
                raise ValueError(
                    "dashboard.entitlements.map: with more than one identity "
                    f"provider every entry needs `issuer`; {group!r} has none, "
                    "so a group of that name from any provider would match it")
            if issuer:
                group = scoped_group(issuer, group)
            for listed in ("orgs", "workspaces", "clients"):
                if not isinstance(entry.get(listed) or [], list):
                    raise ValueError(
                        f"dashboard.entitlements.map: group {group!r} gives `{listed}` as "
                        f"{type(entry.get(listed)).__name__}; it must be a list.")
            orgs = {str(o) for o in map(env_or_literal, entry.get("orgs") or []) if o}
            spaces = {str(w) for w in entry.get("workspaces") or [] if w}
            clients = {str(c) for c in entry.get("clients") or [] if c}
            _check_entitlement_names(group, orgs, spaces, _workspace_names(self))
            for name in sorted(clients):
                if not is_intake_client_name(name):
                    raise ValueError(
                        f"dashboard.entitlements.map: group {group!r} lists {name!r} under "
                        "`clients`; an intake client name is a lowercase letter followed "
                        "by up to 39 lowercase letters, digits or hyphens, and is not "
                        f"{ORG_UNATTRIBUTED!r}.")
            by_group.setdefault(group, set()).update(
                {("org", o) for o in orgs} | {("workspace", w) for w in spaces}
                | {("client", c) for c in clients})
        configured = self.intake_client_names()
        granted = {value for refs in by_group.values() for kind, value in refs
                   if kind == "client"}
        unknown = sorted(granted - set(configured))
        if unknown:
            raise ValueError(
                f"dashboard.entitlements.map grants {unknown[0]!r} under `clients`, which "
                "is not in intake.clients; a grant names a configured intake client.")
        return Entitlements(
            by_group={g: frozenset(v) for g, v in by_group.items() if v},
            resolve=self.partition_pseudonym,
        )



    # --- organizations --------------------------------------------------
    @property
    def orgs(self) -> list[dict[str, Any]]:
        """The org registry: `[{id, label}]`.

        Labels live here and not in the store, which is the whole point. The
        store keeps a pseudonym so it can be read by someone who should not
        learn which customers exist; the dashboard resolves a name at render
        time from configuration it already holds.
        """
        return [o for o in (self.raw.get("orgs") or []) if isinstance(o, dict)]

    def org_labels(self) -> Mapping[str, str]:
        """`{pseudonym: label}` for every configured org, resolved on each read.

        With a salt, computed from `orgs`. Without one, labels come from the
        org registry for every org the policy names. Either way an org with
        no configured label is left out, a label only resolves for an org
        this deployment is configured for, and an unknown pseudonym has no
        entry. Workspaces are in `workspace_labels`.
        """
        from .orgregistry import OrgLabels

        return OrgLabels(self._label_refs("org"), self._label_for)

    def workspace_labels(self) -> Mapping[str, str]:
        """`{pseudonym: label}` for every configured Managed Agents workspace,
        resolved on each read the way `org_labels` is."""
        from .orgregistry import OrgLabels

        return OrgLabels(self._label_refs("workspace"), self._label_for)

    def partition_labels(self) -> Mapping[str, str]:
        """`org_labels` and `workspace_labels`: the partitions a viewer picks
        between. An intake client is not one; its records file under an
        org."""
        from .orgregistry import OrgLabels

        return OrgLabels(self._label_refs("org") + self._label_refs("workspace"),
                         self._label_for)

    def _label_refs(self, kind: str) -> list[tuple[str, str]]:
        from .orgregistry import referenced_orgs, referenced_workspaces

        if kind == "workspace":
            return [("workspace", k) for k in sorted(referenced_workspaces(self))]
        if not self.hash_salt:
            return [("org", v) for v in sorted(referenced_orgs(self))]
        # `$ENV_VAR`, because an organization UUID names a customer and
        # does not belong in a config file that is committed.
        return [("org", str(env_or_literal(o.get("id")) or "")) for o in self.orgs
                if env_or_literal(o.get("id")) and o.get("label")]

    def _label_for(self, ref: tuple[str, str]) -> tuple[str, str] | None:
        """`(pseudonym, label)` for `(kind, value)`: from the registry without
        a salt, from this policy with one."""
        from .orgregistry import referenced_workspaces

        kind, value = ref
        if kind == "client":
            return (value, value)
        if not self.hash_salt:
            entry = self._resolver().lookup(ref)
            return (entry.pseudonym, entry.label) if entry and entry.label else None
        if kind == "workspace":
            label = referenced_workspaces(self).get(value)
        else:
            label = next((str(o.get("label")) for o in self.orgs
                          if str(env_or_literal(o.get("id")) or "") == value
                          and o.get("label")), None)
        key = self._resolver().resolve(ref)
        return (key, label) if key and label else None

    def use_org_registry(self, store: Any) -> None:
        """Resolve org ids through the registry in `store` when there is no salt.

        Entitlements and labels built before this call pick it up too: both
        consult the resolver at read time. With a salt, the registry is
        checked against it now, and again on lookups after each refresh.
        """
        from .orgregistry import OrgResolver

        self._org_resolver = OrgResolver(self.hash_salt, store)
        if self.hash_salt and store is not None:
            self._org_resolver.check_salt()

    def unresolved_fleet_orgs(self) -> list[str]:
        """The names of the `intake.fleet` entries with `orgs` holding an
        id that is unset or does not resolve to a pseudonym, in policy
        order. Names only, never an id."""
        return [name for name, ids in self.fleet_org_ids()
                if not all(i and self.org_pseudonym(i) for i in ids)]

    def fleet_org_ids(self) -> list[tuple[str, list[str]]]:
        """`(name, org ids, "" for one unset)` for each `intake.fleet` entry
        with an `orgs` list."""
        out = []
        for entry in (self.raw.get("intake") or {}).get("fleet") or []:
            if not isinstance(entry, dict) or not isinstance(entry.get("orgs"), list):
                continue
            name = entry.get("name")
            if isinstance(name, str) and name:
                out.append((name, [str(env_or_literal(v) or "") for v in entry["orgs"]]))
        return out

    def org_pseudonym(self, org_id: str) -> str | None:
        """The store pseudonym for `org_id`, or None when it cannot be resolved."""
        return self._resolver().pseudonym(org_id)

    def workspace_pseudonym(self, key: str) -> str | None:
        """The store pseudonym for workspace `key`, or None when it cannot be
        resolved."""
        return self._resolver().workspace_pseudonym(key)

    def partition_pseudonym(self, ref: tuple[str, str]) -> str | None:
        """The store partition for `("org", id)` or `("workspace", key)`, a
        pseudonym, or for `("client", name)`, the intake client's name."""
        if ref[0] == "client":
            return ref[1] if is_intake_client_name(ref[1]) else None
        return self._resolver().resolve(ref)

    def intake_client_names(self) -> tuple[str, ...]:
        """The `intake.clients` names in intake's name form, in order. Read
        from the policy alone: no client's token needs to be set."""
        clients = (self.raw.get("intake") or {}).get("clients") or []
        return tuple(str(c["name"]) for c in clients if isinstance(c, dict)
                     and is_intake_client_name(c.get("name")))

    def _resolver(self):
        if self._org_resolver is None:
            from .orgregistry import OrgResolver

            self._org_resolver = OrgResolver(self.hash_salt)
        return self._org_resolver

    # --- adapter 4 ------------------------------------------------------
    @property
    def otel(self) -> dict[str, Any]:
        return self.raw.get("otel") or {}

    @property
    def sinks(self) -> list[dict[str, Any]]:
        """Adapter 5 destinations. Absent or empty means no sink runs.

        A list, and each entry carries a `type`, so a second destination
        or a second type is another entry.
        """
        raw = self.raw.get("sinks")
        return list(raw) if isinstance(raw, list) else []

    def compliance_orgs(self) -> list[dict[str, Any]]:
        """One resolved entry per org adapter 3 scans.

        The Compliance Access Key *is* the organization -- it is minted
        inside one org and reads only that one -- so scanning N orgs is N
        keys, not one key with a parameter.

        The single-org form (`compliance.api_key` + `compliance.org_id`)
        is read as exactly one org.

        Raises on a configuration that would silently corrupt state; see
        `_state_path_for`. That includes a `compliance.orgs` entry with a key
        and an id that resolves to nothing, which would take the single-org
        cursor file.
        """
        from .models import env_or_literal, pseudonym, usable_secret

        cfg = self.compliance
        salt = self.hash_salt
        entries = [o for o in (cfg.get("orgs") or []) if isinstance(o, dict)]
        multi = bool(entries)
        if not entries:
            entries = [{
                "id": cfg.get("org_id"),
                "api_key": cfg.get("api_key"),
                "state_path": cfg.get("state_path"),
            }]

        labels = {}
        for org in self.orgs:
            org_id = str(env_or_literal(org.get("id")) or "")
            if org_id:
                labels[org_id] = str(org.get("label") or pseudonym(org_id, salt, "org"))

        out: list[dict[str, Any]] = []
        seen_state: dict[str, str] = {}
        for index, entry in enumerate(entries):
            org_id = str(env_or_literal(entry.get("id")) or "")
            # A placeholder key is not a key. Without this the job treats
            # itself as configured and makes failing API calls every six
            # hours instead of taking the clear "no key configured" path.
            api_key = usable_secret(env_or_literal(entry.get("api_key"))) or ""
            if not api_key:
                # No key means nothing to scan for this org. Skipped rather
                # than failed: a deployment that has onboarded one org of
                # three should still scan the one.
                continue
            if multi and not org_id:
                written = entry.get("id")
                named = (f" ({written} is unset)"
                         if isinstance(written, str) and written.startswith("$") else "")
                raise PolicyInvalid(
                    f"compliance.orgs entry {index} "
                    f"({str(entry.get('label') or 'unlabelled')!r}) has an api_key "
                    f"but no id{named}. Without it the entry takes the single-org "
                    "cursor file, which may be another org's. Set it, or remove "
                    "the entry's api_key.")
            state_path = self._state_path_for(entry, org_id)
            # Compared by the store key, the path's basename without case:
            # `./prod/cursor.json` and `./dev/cursor.json` are one object in
            # a store, and one file on a case-insensitive filesystem.
            shared = state_key(state_path).strip().lower()
            if shared in seen_state:
                # Two orgs sharing a cursor file is silent data loss: a pass
                # that fails midway advances `last_run_started_at` for an org
                # it never scanned, and those sessions are never looked at
                # again. Refuse rather than discover it months later.
                raise PolicyInvalid(
                    f"compliance.orgs: entries {seen_state[shared]} and "
                    f"{index} share state_path file name {state_key(state_path)!r}; "
                    "each org needs its own cursor file, and in a findings store "
                    "a cursor is named by the state_path's file name alone"
                )
            seen_state[shared] = str(index)
            out.append({
                "id": org_id,
                "label": labels.get(org_id) or entry.get("label")
                or pseudonym(org_id, salt, "org") or "unnamed",
                "api_key": api_key,
                "state_path": state_path,
            })
        return out

    @staticmethod
    def _state_path_for(entry: dict[str, Any], org_id: str) -> str:
        explicit = entry.get("state_path")
        if explicit:
            from .models import config_state_name

            key = os.path.basename(str(explicit))
            try:
                if key:
                    config_state_name(key)
            except ValueError as exc:
                raise PolicyInvalid(
                    f"compliance state_path {str(explicit)!r}: {exc}. Name another file; "
                    "its basename is the cursor's key in the findings store") from exc
            return str(explicit)
        if not org_id:
            # The single-org shape, where there is nothing to disambiguate.
            # Its state keeps this fixed name: a different name would look
            # like a first run and rescan everything.
            return "./compliance-state.json"
        from .models import digest

        return f"./compliance-state-{digest(org_id)[:10]}.json"

    def compliance_state_keys(self) -> list[str]:
        """The store keys adapter 3's cursors live under, one per org.

        Separate from `compliance_orgs()`, which resolves an API key per
        org and drops any org without one. The dashboard reads these to
        tell "the scan ran and found nothing" from "the scan did not
        run", and the dashboard is deliberately given no Compliance
        Access Key -- so it cannot reach them through that path.

        Shares `_state_path_for`, so a key derived here is the key the
        scanner writes. Two copies of that rule would drift into a
        dashboard reading a cursor nobody writes, which fails as the
        panel silently going back to guessing.
        """
        cfg = self.compliance
        entries = [o for o in (cfg.get("orgs") or []) if isinstance(o, dict)]
        if not entries:
            entries = [{"id": cfg.get("org_id"),
                        "state_path": cfg.get("state_path")}]
        out: list[str] = []
        for entry in entries:
            org_id = str(env_or_literal(entry.get("id")) or "")
            # Matches `State.key`, including its fallback: a state_path of
            # "" or "/" has no basename and the scanner still writes.
            key = state_key(self._state_path_for(entry, org_id))
            if key not in out:
                out.append(key)
        return out

    # --- plugins --------------------------------------------------------
    @property
    def plugin_allow(self) -> tuple[PluginAllow, ...]:
        """The `plugins.allow` entries; empty when the section is absent."""
        return parse_allow(self.raw.get("plugins"))

    # --- per-adapter profiles -------------------------------------------
    def for_profile(self, name: str) -> Policy:
        """Return this policy with `<name>.detectors` and `<name>.scan`
        merged over the top-level sections.

        One policy definition covers every control point, but they do not
        share a latency budget. The inference hook runs inside the org's
        verdict timeout, where a webhook failure is worse than a missed
        finding; the post-hoc scanner is a cron job with nobody waiting. A
        tier that is reckless on the first is free on the second, so the
        adapter -- not a separate file -- decides which tiers it can afford.

        Merging rather than replacing keeps the shared rules shared: an
        override adds or retunes a detector, it does not fork the policy.
        """
        section = self.raw.get(name) or {}
        overrides = {
            key: section[key] for key in ("detectors", "scan") if key in section
        }
        if not overrides:
            return self
        return self.derive(_deep_merge(self.raw, overrides))

    def derive(self, raw: dict[str, Any]) -> Policy:
        """A policy over `raw` that shares this one's plugin registry."""
        out = Policy(raw)
        out._plugins = self._plugins
        out._warned = self._warned
        return out

    def plugin_phrases(self) -> Mapping[str, str]:
        """Deny-reason phrases of the detector plugins this policy built."""
        return MappingProxyType(self._plugins.phrases)

    # --- detectors ------------------------------------------------------
    def detector_configs(self) -> dict[str, DetectorConfig]:
        return {
            name: DetectorConfig.parse(name, raw)
            for name, raw in self.raw["detectors"].items()
        }

    def gitleaks_daemon(self) -> str | None:
        """The gitleaksd socket this policy scans through, if any.

        None when `detectors.gitleaks` is disabled.
        """
        gl = (self.raw.get("detectors") or {}).get("gitleaks")
        if gl is None or DetectorConfig.parse("gitleaks", gl).enabled is False:
            return None
        return env_or_literal(gl.get("daemon", "")) or None

    def gitleaks_config(self) -> str | None:
        """`detectors.gitleaks.config` as written, or None when unset."""
        gl = (self.raw.get("detectors") or {}).get("gitleaks") or {}
        return gl.get("config") or None

    def _refuse_daemon_config_mismatch(self) -> None:
        """Raise when the daemon may not have loaded `detectors.gitleaks.config`.

        The daemon loads its config at startup and the entrypoint exports
        that path as `$FORGD_GITLEAKS_CONFIG`. With no config in the policy
        there is nothing to compare.
        """
        daemon, config = self.gitleaks_daemon(), self.gitleaks_config()
        if not daemon or not config:
            return
        wanted = os.path.realpath(config)
        loaded = os.environ.get(GITLEAKS_CONFIG_ENV)
        if not loaded:
            raise RuntimeError(
                f"detectors.gitleaks.config is {wanted}, but {GITLEAKS_CONFIG_ENV} "
                f"is unset, so nothing says which config the daemon at {daemon} "
                "loaded. Start the daemon through deploy/entrypoint.sh, or set "
                f"{GITLEAKS_CONFIG_ENV} to the config it was started with."
            )
        if os.path.realpath(loaded) != wanted:
            raise RuntimeError(
                f"detectors.gitleaks.config is {wanted}, but the daemon at "
                f"{daemon} loaded {os.path.realpath(loaded)} "
                f"({GITLEAKS_CONFIG_ENV})."
            )

    def build_detectors(self, *, include_local_only: bool = False,
                        salt: str | None = None,
                        profile: str | None = None) -> list[Any]:
        """Instantiate the enabled detectors, in tier order.

        `enabled: auto` means "on if the dependency is present". A detector
        configured `auto` that cannot load is skipped silently; one configured
        `true` that cannot load raises, because an operator who wrote `true`
        asked for a guarantee.

        Plugin detectors from `plugins.allow` are built after the built-ins,
        each wrapped in `PluginDetector`, and only when `profile` is given.
        With `profile=None` a configured plugin is skipped. A name under any
        `detectors:` section that is neither a built-in nor an allowlisted
        detector plugin raises, whatever the profile.
        """
        # `salt` overrides the policy's, for a caller whose salt is not a
        # deployment secret. The hook uses a per-device one: the deployment
        # salt must never reach a laptop, and hashing with EMPTY made an
        # export of adapter-2 rows brute-forceable back to the value.
        salt = self.hash_salt if salt is None else salt
        allow = {e.name: e for e in self.plugin_allow if e.group == "detectors"}
        self._refuse_unknown_detectors(allow)
        cfgs = self.detector_configs()
        built: list[Any] = []

        def add(name: str, factory) -> None:
            cfg = cfgs.get(name)
            if cfg is None or cfg.enabled is False:
                return
            detector = factory(cfg.severity, salt)
            if detector.available():
                built.append(detector)
            elif cfg.enabled is True or getattr(detector, "required", False):
                # `required` covers the case `auto` cannot: a detector
                # configured with a sidecar has been told it must run here,
                # so an unreachable sidecar is a startup failure rather than
                # a tier that quietly disappears.
                raise RuntimeError(
                    f"detectors.{name} is required here but unavailable "
                    f"(missing binary, optional dependency, or a configured "
                    f"daemon that is not reachable)."
                )

        add("t0_regex", lambda sev, salt: T0RegexDetector(sev, salt))
        chk = self.raw["detectors"].get("checksums") or {}
        add(
            "checksums",
            lambda sev, salt: ChecksumDetector(
                sev, salt, enabled=set(chk["ids"]) if chk.get("ids") else None
            ),
        )
        add("entropy", lambda sev, salt: EntropyDetector(sev, salt))
        if include_local_only:
            add("shell_exfil", lambda sev, salt: ShellExfilDetector(sev, salt))
        gl = self.raw["detectors"].get("gitleaks") or {}

        def gitleaks(sev: str, salt: str) -> GitleaksDetector:
            self._refuse_daemon_config_mismatch()
            return GitleaksDetector(
                sev,
                salt,
                binary=gl.get("binary"),
                timeout_s=float(gl.get("timeout_ms", 2000)) / 1000.0,
                config=gl.get("config"),
                redact=bool(gl.get("redact", False)),
                daemon=self.gitleaks_daemon(),
            )

        add("gitleaks", gitleaks)
        pres = self.raw["detectors"].get("presidio_pii") or {}
        add(
            "presidio_pii",
            lambda sev, salt: PresidioPIIDetector(
                sev,
                salt,
                entities=tuple(pres["entities"]) if pres.get("entities") else None,
                score_threshold=float(pres.get("score_threshold", 0.6)),
            ),
        )
        add("llmguard_pii", lambda sev, salt: LLMGuardPIIDetector(sev, salt))
        if profile is not None:
            built.extend(self._plugin_detectors(allow, cfgs, profile, salt,
                                                include_local_only, list(built)))
        built.sort(key=lambda d: d.tier)
        return built

    def _refuse_unknown_detectors(self, allow: Mapping[str, PluginAllow]) -> None:
        clash = sorted(set(allow) & RESERVED_DETECTOR_NAMES)
        if clash:
            raise RuntimeError(f"plugins.allow names built-in detectors {clash}; "
                               "a plugin cannot replace a built-in")
        known = BUILTIN_DETECTORS | set(allow)
        for path, node in _detector_sections(self.raw):
            for name, cfg in node.items():
                where = f"{'.'.join(path)}.{name}"
                if name not in known:
                    if isinstance(cfg, dict) and cfg.get("enabled", False) is False:
                        if name not in self._warned:
                            self._warned.add(name)
                            log.warning("unknown detector name, disabled and ignored",
                                        extra={"fields": {"detector": where}})
                        continue
                    raise RuntimeError(
                        f"{where} is enabled but is not a built-in detector or an "
                        "allowlisted detectors plugin; remove it, or install the "
                        "plugin and list it in plugins.allow"
                    )
                if name not in BUILTIN_DETECTORS:
                    ref = _env_reference(cfg, where)
                    if ref:
                        raise RuntimeError(
                            f"{ref} is a `$` reference; plugin config is not resolved "
                            "from the environment"
                        )

    def _plugin_detectors(self, allow: Mapping[str, PluginAllow],
                          cfgs: Mapping[str, DetectorConfig], profile: str, salt: str,
                          include_local_only: bool, builtins: list[Any]) -> list[Any]:
        wanted = [e for name, e in allow.items()
                  if name in cfgs and cfgs[name].enabled is not False]
        factories = load_plugins(wanted, "detectors", profile, set(RESERVED_DETECTOR_NAMES))
        if not factories:
            return []
        from .core import screen_phrases, scrub_plugin_label

        kept: list[PluginDetector] = []

        def scrub(text: str) -> str:
            return scrub_plugin_label(text, builtins, kept)

        hasher = hasher_for(salt)
        out: list[PluginDetector] = []
        prefixes: dict[str, str] = {}
        for name, factory in factories.items():
            cfg = cfgs[name]
            det = PluginDetector.build(
                name, factory, MappingProxyType(copy.deepcopy(self.raw["detectors"][name])),
                cfg.severity, hasher, scrub, allow[name])
            if det.finding_prefix in prefixes:
                raise RuntimeError(
                    f"detectors.{name} and detectors.{prefixes[det.finding_prefix]} "
                    f"share the finding prefix {det.finding_prefix!r}")
            prefixes[det.finding_prefix] = name
            if det.local_only and not include_local_only:
                continue
            if det.available():
                out.append(det)
            elif cfg.enabled is True:
                raise RuntimeError(
                    f"detectors.{name} is required here but unavailable "
                    f"(the plugin's available() returned false)."
                )
        screen_phrases(builtins, out)
        for det in out:
            self._plugins.register(det)
        kept.extend(out)
        return out


# The sections `for_profile` merges a `detectors:` block from, besides the
# top level.
_PROFILE_SECTIONS = ("server", "hook", "compliance", "otel")

# SinkConfig's fields; `redacted` shows only these on a plugin sink entry.
SINK_STANDARD_KEYS = frozenset({
    "name", "type", "endpoint", "token", "redact", "drop_events", "metadata",
    "max_queue", "orgs", "timeout_s", "options",
})
BUILTIN_SINK_TYPES = ("otlp", "azure-monitor")


def _detector_sections(raw: Mapping[str, Any]) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    """Every `detectors:` mapping in `raw`, with its path."""
    out = []
    for path in [("detectors",), *((s, "detectors") for s in _PROFILE_SECTIONS),
                 ("otel", "sink_detectors")]:
        node: Any = raw
        for part in path:
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, dict):
            out.append((path, node))
    return out


def _env_reference(value: Any, where: str) -> str | None:
    """The path of the first `$`-prefixed string under `value`, or None."""
    if isinstance(value, str):
        return where if value.startswith("$") else None
    if isinstance(value, dict):
        items = ((f"{where}.{k}", v) for k, v in value.items())
    elif isinstance(value, (list, tuple)):
        items = ((f"{where}[{i}]", v) for i, v in enumerate(value))
    else:
        return None
    for sub, v in items:
        found = _env_reference(v, sub)
        if found:
            return found
    return None


# The policy keys a store spec is read from.
STORE_SPEC_PATHS: tuple[tuple[str, ...], ...] = (
    ("server", "store"), ("otel", "store"), ("intake", "store"), ("hook", "ship_store"),
)


def _redact_plugin_config(effective: dict[str, Any], policy: Policy) -> None:
    """Show `enabled`, `severity` and declared `public_keys` of each plugin
    detector's config; of each sink only its SinkConfig fields, with every
    `options` value redacted; and a plugin store spec only by its scheme.

    Public keys come from `policy`'s own registry, for the distribution and
    version its `plugins.allow` entry names."""
    for _path, node in _detector_sections(effective):
        for name, cfg in node.items():
            if name in BUILTIN_DETECTORS or not isinstance(cfg, dict):
                continue
            entry = find_entry(policy.plugin_allow, "detectors", name)
            public = policy._plugins.public_keys_for(entry) if entry else frozenset()
            shown = {"enabled", "severity"} | public
            for key in cfg:
                if key not in shown:
                    cfg[key] = "<redacted>"
    for *parents, key in STORE_SPEC_PATHS:
        node: Any = effective
        for part in parents:
            node = node.get(part) if isinstance(node, dict) else None
        spec = node.get(key) if isinstance(node, dict) else None
        scheme = store_scheme(spec) if isinstance(spec, str) else None
        if scheme is not None and find_entry(policy.plugin_allow, "stores", scheme):
            node[key] = f"{scheme}:<redacted>"
    for entry in effective.get("sinks") or []:
        if not isinstance(entry, dict):
            continue
        for key in entry:
            if key not in SINK_STANDARD_KEYS:
                entry[key] = "<redacted>"
        options = entry.get("options")
        if isinstance(options, dict):
            entry["options"] = {k: "<redacted>" for k in options}
        elif "options" in entry:
            entry["options"] = "<redacted>"


# Keys whose resolved value must never be rendered anywhere. The metrics
# token is here for the same reason as the others: it is a bearer credential
# for an endpoint that reports traffic volumes.
SECRET_PATHS: tuple[tuple[str, ...], ...] = (
    # The single-org form. The shipped file uses `compliance.orgs`, whose
    # keys SECRET_LIST_PATHS covers below.
    ("compliance", "api_key"),
    ("server", "metrics_token"),
    ("privacy", "hash_salt"),
    # Adapter 2's outbound bearer. `ENV_OVERRIDES` resolves
    # FORGD_VERDICT_SHIP_TOKEN into the effective policy dict, so the
    # value is materialised into the structure `redacted` then prints.
    ("hook", "ship_token"),
    # Adapter 2's inbound bearer for /scan. Same developer, same laptop,
    # a different credential -- and the same reason it must not print.
    ("hook", "scan_token"),
    # The key the dashboard signs its admin form tokens with.
    ("dashboard", "admins", "form_key"),
    # The Ed25519 key runtime-override records are signed with.
    ("overrides", "signing_key"),
)

# Adapter 4's per-org bearer tokens live in a list, so they need walking
# rather than a fixed path. Kept separate from SECRET_PATHS so neither has
# to grow a special case for the other's shape.
SECRET_LIST_PATHS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("otel", "orgs"), "token"),
    # Adapter 5. A sink's credential is an OTLP bearer today and will be a
    # HEC token, a Datadog key or SigV4 material later -- all of them
    # secrets, and none of them belong on the dashboard's Policy tab.
    (("sinks",), "token"),
    # Adapter 2's intake. A bearer per client, and the Policy tab is
    # readable by anyone who can sign in to the dashboard -- which is a
    # wider set than the holders of these tokens.
    (("intake", "clients"), "token"),
    # The fleet's bearers: a list, so a rotation can hold two.
    (("intake", "fleet"), "tokens"),
    # Adapter 3, multi-org -- the form the shipped policy.yaml uses.
    (("compliance", "orgs"), "api_key"),
    # Adapter 6. A workspace API key, and no read-only scope is documented
    # for one: it can create and delete sessions as well as read them.
    (("managed_agents", "workspaces"), "api_key"),
)

# Maps whose values are credentials and whose keys are not: each literal
# value is redacted and each name kept. A `$NAME` reference is shown as
# written.
SECRET_MAP_PATHS: tuple[tuple[str, ...], ...] = (
    # Adapter 1's optional second factor: header name to expected value.
    ("server", "required_headers"),
)

_ENV_REFERENCE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")

# Credential paths a deployment may leave unset, each with the roles that
# read it and what an unset reference does there. `warn_unset_credentials`
# logs every unset reference a role reads at its start. Every other path in
# SECRET_PATHS, SECRET_LIST_PATHS and SECRET_MAP_PATHS refuses to start, or
# is reported where it is read, when its reference resolves to nothing.
OPTIONAL_WHEN_UNSET: Mapping[tuple[str, ...], tuple[frozenset[str], str]] = MappingProxyType({
    ("server", "metrics_token"): (
        frozenset({"verdict", "collector", "intake"}), "/metrics and /stats are not served"),
    ("otel", "orgs", "token"): (
        frozenset({"collector"}), "this entry's exports are refused with 401"),
    ("intake", "clients", "token"): (
        frozenset({"intake"}), "this client is refused with 401"),
    ("intake", "fleet", "tokens"): (
        frozenset({"intake"}), "this fleet is refused with 401"),
    ("compliance", "api_key"): (frozenset({"ingest"}), "this org is not scanned"),
    ("compliance", "orgs", "api_key"): (frozenset({"ingest"}), "this org is not scanned"),
})


def _unset(value: Any) -> str | None:
    """`value` when it is a `$NAME` reference that resolves to nothing."""
    if isinstance(value, str) and _ENV_REFERENCE.fullmatch(value) and not env_or_literal(value):
        return value
    return None


def unset_credentials(policy: Policy, path: tuple[str, ...]) -> list[tuple[str, str]]:
    """`(where, "$NAME")` for each reference at `path` that resolves to
    nothing. A list of references, such as a fleet's `tokens`, is reported
    only when every one of them is unset. A literal is never reported."""
    node: Any = policy.raw
    for part in path[:-1]:
        node = node.get(part) if isinstance(node, dict) else None
        if node is None:
            return []
    key = path[-1]
    entries = node if isinstance(node, list) else [node]
    where = ".".join(path[:-1])
    out = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        value = entry.get(key)
        refs = value if isinstance(value, list) else [value]
        unset = [r for r in map(_unset, refs) if r]
        if refs and len(unset) == len(refs):
            label = entry.get("name") or entry.get("label") if isinstance(node, list) else None
            at = f"{where}[{label or i}].{key}" if isinstance(node, list) else f"{where}.{key}"
            out.append((at, ", ".join(unset)))
    return out


def warn_unset_credentials(log: logging.Logger | logging.LoggerAdapter, policy: Policy,
                           role: str) -> list[tuple[str, str]]:
    """Log each unset reference in OPTIONAL_WHEN_UNSET that `role` reads,
    naming the path, the variable and its effect, and return them."""
    found = []
    for path, (roles, effect) in OPTIONAL_WHEN_UNSET.items():
        if role not in roles:
            continue
        for where, ref in unset_credentials(policy, path):
            log.warning(f"{where} is {ref}, which is not set: {effect}",
                        extra={"fields": {"path": where, "variable": ref}})
            found.append((where, ref))
    return found


def _workspace_names(policy: Policy) -> tuple[dict[str, str], dict[str, str]]:
    """`({key: label}, {label: label})` for configured workspaces."""
    from .orgregistry import configured_workspaces

    raw = (policy.raw.get("managed_agents") or {}).get("workspaces") or []
    labels = {str(w.get("label")): str(w.get("label"))
              for w in raw if isinstance(w, dict) and w.get("label")}
    return dict(configured_workspaces(policy)), labels


def _check_entitlement_names(group: str, orgs: set[str], spaces: set[str],
                             names: tuple[dict[str, str], dict[str, str]]) -> None:
    """Refuse an entitlement entry that names a workspace where an org id or
    a workspace key belongs. Names the workspace by label only."""
    keys, labels = names
    for value in sorted(orgs):
        label = keys.get(value) or labels.get(value)
        if label:
            raise ValueError(
                f"dashboard.entitlements.map: group {group!r} lists the "
                f"managed_agents workspace labelled {label!r} under `orgs`. Remove "
                "it from `orgs` and add that workspace's `key` to the same "
                "entry's `workspaces` list.")
    for value in sorted(spaces):
        if value not in keys and value in labels:
            raise ValueError(
                f"dashboard.entitlements.map: group {group!r} names the "
                f"managed_agents workspace labelled {labels[value]!r} by its label "
                "under `workspaces`. Replace it with that workspace's `key`.")


# An intake client's `name`, which is also its partition in the store.
INTAKE_CLIENT_NAME = re.compile(r"[a-z][a-z0-9-]{0,39}")


def is_intake_client_name(value: Any) -> bool:
    """`value` is in INTAKE_CLIENT_NAME's form and is not the shared
    unattributed partition."""
    return (isinstance(value, str) and value != ORG_UNATTRIBUTED
            and INTAKE_CLIENT_NAME.fullmatch(value) is not None)

WORKSPACE_KEY_PLACEHOLDER = "<workspace key>"


ORG_ID_REF = re.compile(r"\$FORGD_ORG_ID_[A-Za-z0-9_]+")
ORG_ID_PLACEHOLDER = "<org id>"


def _redact_org_id(value: Any) -> Any:
    """`value` if it is empty or an exact `$FORGD_ORG_ID_*` reference, else
    ORG_ID_PLACEHOLDER."""
    if not value or (isinstance(value, str) and ORG_ID_REF.fullmatch(value)):
        return value
    return ORG_ID_PLACEHOLDER


def _redact_org_ids(effective: dict[str, Any]) -> None:
    """Replace literal org ids in every place the policy takes one."""

    def items(node: Any) -> list[Any]:
        return [item for item in node if isinstance(item, dict)] \
            if isinstance(node, list) else []

    def section(name: str) -> dict[str, Any]:
        node = effective.get(name)
        return node if isinstance(node, dict) else {}

    for org in items(effective.get("orgs")):
        if "id" in org:
            org["id"] = _redact_org_id(org["id"])
    compliance = section("compliance")
    if "org_id" in compliance:
        compliance["org_id"] = _redact_org_id(compliance["org_id"])
    for org in items(compliance.get("orgs")) + items(section("otel").get("orgs")):
        if "id" in org:
            org["id"] = _redact_org_id(org["id"])
        if isinstance(org.get("ids"), list):
            org["ids"] = [_redact_org_id(v) for v in org["ids"]]
    entitlements = section("dashboard").get("entitlements")
    if isinstance(entitlements, dict):
        for entry in items(entitlements.get("map")):
            if isinstance(entry.get("orgs"), list):
                entry["orgs"] = [_redact_org_id(v) for v in entry["orgs"]]
            if isinstance(entry.get("workspaces"), list):
                entry["workspaces"] = [WORKSPACE_KEY_PLACEHOLDER for _ in entry["workspaces"]]
    intake = section("intake")
    for entry in items(intake.get("fleet")) + items(intake.get("clients")):
        if "org" in entry:
            entry["org"] = _redact_org_id(entry["org"])
        if isinstance(entry.get("orgs"), list):
            entry["orgs"] = [_redact_org_id(v) for v in entry["orgs"]]
    for ws in items(section("managed_agents").get("workspaces")):
        if ws.get("key") not in (None, ""):
            ws["key"] = WORKSPACE_KEY_PLACEHOLDER


def _secret_shown(value: Any) -> Any:
    """`value` as the Policy tab shows a secret."""
    if isinstance(value, list):
        return [_secret_shown(v) for v in value]
    if isinstance(value, str) and _ENV_REFERENCE.fullmatch(value) and not env_or_literal(value):
        return f"<unset: {value} empty>"
    return "<redacted>"


def redacted(policy: Policy, *, hashes_here: bool = True) -> dict[str, Any]:
    """The effective policy with every secret and literal org id removed.

    One implementation shared by `forgd-verdict policy` and the dashboard's
    Policy tab. A second copy would drift, and the failure mode of drift
    here is printing a credential.

    Reports whether a secret is set rather than dropping the key, because
    "no value" and "a value you cannot see" are different facts and an
    operator debugging a 401 needs to tell them apart. A secret written as
    a `$VAR` reference that resolves to nothing is shown as
    `<unset: $VAR empty>`; any other set secret as `<redacted>`, and a list
    of them item by item.

    `hashes_here` is False in a process that is DELIBERATELY not given the
    hash salt -- the dashboard. There, an unresolved salt is not evidence of
    anything, and saying UNSET is worse than saying nothing: it reads as a
    deployment hashing unsalted, and the obvious remedy is to hand the
    dashboard the salt. That is precisely what the separation forbids, since
    the dashboard reads every finding hash and the salt beside them is one
    compromise for both.
    """
    effective: dict[str, Any] = json.loads(json.dumps(policy.raw, default=str))

    server = effective.get("server") or {}
    if server.get("secrets"):
        n = len(policy.secrets)
        server["secrets"] = [f"<{n} resolved>" if n else "<none resolved>"]

    for *parents, key in SECRET_PATHS:
        node = effective
        for part in parents:
            node = node.get(part) or {}
        if not node.get(key):
            continue
        if key == "hash_salt":
            # RESOLVED, not the literal. `$FORGD_HASH_SALT` with nothing in
            # the environment is truthy as a string, so this reported
            # `<set>` on a deployment that was hashing unsalted -- an
            # indicator that lied in the one direction that matters.
            if policy.hash_salt:
                node[key] = "<set>"
            elif hashes_here:
                node[key] = "<UNSET: $env var is empty>"
            else:
                node[key] = "<not shown here: this service is not given the salt>"
        else:
            node[key] = _secret_shown(node[key])

    for path, key in SECRET_LIST_PATHS:
        parent: Any = effective
        for part in path[:-1]:
            parent = parent.get(part) if isinstance(parent, dict) else None
        cursor = parent.get(path[-1]) if isinstance(parent, dict) else None
        if cursor and not isinstance(cursor, list):
            # Written in a shape the loader refuses, such as a mapping: its
            # keys can be credentials too, so nothing under it is shown.
            parent[path[-1]] = f"<redacted: {'.'.join(path)} is not a list>"
            continue
        for i, item in enumerate(cursor or []):
            if isinstance(item, dict):
                if item.get(key):
                    item[key] = _secret_shown(item[key])
            elif item:
                cursor[i] = REDACTED

    for path in SECRET_MAP_PATHS:
        parent = effective
        for part in path[:-1]:
            parent = parent.get(part) if isinstance(parent, dict) else None
        mapping = parent.get(path[-1]) if isinstance(parent, dict) else None
        if mapping and not isinstance(mapping, dict):
            parent[path[-1]] = REDACTED
            continue
        if not isinstance(mapping, dict):
            continue
        for name, value in mapping.items():
            if value and not (isinstance(value, str) and _ENV_REFERENCE.fullmatch(value)):
                mapping[name] = "<redacted>"

    branding = (effective.get("dashboard") or {}).get("branding")
    if isinstance(branding, dict):
        for key in BRANDING_IMAGE_KEYS:
            if key in branding:
                branding[key] = image_summary(branding[key])

    _redact_plugin_config(effective, policy)
    _redact_org_ids(effective)
    skip = {id(node) for _, node in _detector_sections(effective)}
    _redact_shapes(effective, skip)
    return effective


REDACTED = "<redacted>"
# Keys whose value is a credential wherever they appear in a policy.
CREDENTIAL_KEY = re.compile(
    r"(?:^|_)(?:token|tokens|secret|secrets|password|passwd|api_key|apikey|private_key"
    r"|access_key|secret_key|signing_key|form_key|sas|sas_token|connection_string"
    r"|credential|credentials)\Z")
# Keys whose value is a URL, a store spec or a list of either.
URL_KEY = re.compile(r"(?:^|_)(?:endpoint|url|uri|issuer|issuers|store|origin|origins)\Z")
# What `redacted` itself writes in place of a secret.
_SHOWN_MARKER = re.compile(
    r"<(?:redacted|set|none resolved|\d+ resolved|unset: \$[A-Za-z_][A-Za-z0-9_]* empty"
    r"|UNSET: \$env var is empty|not shown here: this service is not given the salt)>")


def _redact_shapes(node: Any, skip: set[int]) -> None:
    """Redact credential-named keys and credentials in URLs anywhere under
    `node`, except inside the mappings whose ids are in `skip`."""
    if id(node) in skip:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            name = str(key)
            if name != "hash_salt" and CREDENTIAL_KEY.search(name):
                node[key] = _credential_shown(value)
            elif URL_KEY.search(name) and isinstance(value, str):
                node[key] = shown_url(value)
            elif URL_KEY.search(name) and isinstance(value, list):
                node[key] = [shown_url(v) if isinstance(v, str) else v for v in value]
                _redact_shapes(node[key], skip)
            elif isinstance(value, str):
                node[key] = shown_text(value)
            else:
                _redact_shapes(value, skip)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            if isinstance(value, str):
                node[i] = shown_text(value)
            else:
                _redact_shapes(value, skip)


def _credential_shown(value: Any) -> Any:
    if isinstance(value, str):
        return value if not value or _SHOWN_MARKER.fullmatch(value) else _secret_shown(value)
    if isinstance(value, list):
        return [_credential_shown(v) for v in value]
    if isinstance(value, dict):
        return REDACTED if value else value
    return value


IMAGE_PNG, IMAGE_SVG, IMAGE_WEBP = "image/png", "image/svg+xml", "image/webp"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_SVG_ROOT = re.compile(
    r"\A\ufeff?\s*(?:<\?xml[^>]*\?>\s*)?(?:<!--.*?-->\s*)*<svg[\s>/]",
    re.DOTALL | re.IGNORECASE,
)
# `dashboard.branding` keys holding an image, as a path or a `data:` URI.
BRANDING_IMAGE_KEYS = ("logo", "favicon")


def sniff_image(data: bytes) -> str | None:
    """PNG, SVG or WebP from the bytes themselves, else None."""
    if data.startswith(PNG_MAGIC):
        return IMAGE_PNG
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return IMAGE_WEBP
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return IMAGE_SVG if _SVG_ROOT.match(text) else None


# The same cap `dashboard.branding` enforces on a logo or favicon.
IMAGE_SUMMARY_MAX_BYTES = 256 * 1024


def image_summary(value: Any) -> str:
    """A branding image as `<type, N bytes>`. Never the image's bytes, its
    `data:` payload, or the path of a mounted file."""
    if not isinstance(value, str) or not value:
        return "<not an image reference>"
    if value[:5].lower() == "data:":
        header, _, payload = value[5:].partition(",")
        is_b64 = "base64" in [p.strip().lower() for p in header.split(";")[1:]]
        try:
            data = (base64.b64decode(payload, validate=True) if is_b64
                    else unquote_to_bytes(payload))
        except (binascii.Error, ValueError):
            return "<a data: URI that does not decode>"
        return f"<{sniff_image(data) or 'not an image'}, {len(data):,} bytes>"
    # A mounted file: read at most the branding cap, from a regular file only,
    # and never name the path, which can say what is mounted where.
    # Opened non-blocking and checked through the descriptor, so a FIFO
    # swapped in after any check by path cannot block the open or the read.
    try:
        fd = os.open(value, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return "<a mounted file not readable here>"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return "<a mounted path that is not a regular file>"
        if st.st_size > IMAGE_SUMMARY_MAX_BYTES:
            return f"<a mounted file over {IMAGE_SUMMARY_MAX_BYTES // 1024} KB>"
        # os.read may return fewer bytes than asked; read to EOF or the cap.
        chunks: list[bytes] = []
        got = 0
        while got <= IMAGE_SUMMARY_MAX_BYTES:
            chunk = os.read(fd, IMAGE_SUMMARY_MAX_BYTES + 1 - got)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
        data = b"".join(chunks)
    except OSError:
        return "<a mounted file not readable here>"
    finally:
        os.close(fd)
    if len(data) > IMAGE_SUMMARY_MAX_BYTES:
        return f"<a mounted file over {IMAGE_SUMMARY_MAX_BYTES // 1024} KB>"
    return f"<{sniff_image(data) or 'not an image'}, {len(data):,} bytes, mounted file>"


def policy_error(exc: BaseException) -> str:
    """Describe a policy load failure without quoting the policy.

    `str()` on a PyYAML error includes a snippet of the offending source
    with a caret under it, so an unterminated quote on the `hash_salt:`
    line renders the salt. Only the type and the position are safe, and
    the position is what an operator needs.
    """
    if isinstance(exc, PolicyNotFound):
        return str(exc)
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    where = ""
    if mark is not None:
        line = getattr(mark, "line", None)
        col = getattr(mark, "column", None)
        if line is not None:
            # PyYAML counts from zero; editors do not.
            where = f" at line {line + 1}"
            if col is not None:
                where += f", column {col + 1}"
    return (
        f"{type(exc).__name__}{where}. The text is withheld: a parser error "
        "quotes the line it failed on and a validation error the value it "
        "refused, and either may be a credential."
    )


class Unsalted(RuntimeError):
    """`privacy.hash_salt` is empty and the policy file does not set
    `privacy.allow_unsalted: true`."""


class PolicyInvalid(ValueError):
    """A policy setting that loads but is refused. The message names keys
    and values of the policy's own vocabulary, never file content, so it
    is safe to print whole."""


class PolicyNotFound(FileNotFoundError):
    """A policy file named by an argument or by `$FORGD_VERDICT_POLICY` does
    not exist. The message names the path and where it came from."""

    def __init__(self, path: Path, source: str) -> None:
        super().__init__(f"policy file {path} does not exist (named by {source})")
        self.path = path
        self.source = source


SOURCE_ARGUMENT = "--policy"
SOURCE_ENV = "FORGD_VERDICT_POLICY"


def _resolve(path: str | os.PathLike[str] | None) -> tuple[Path, str | None]:
    """(the file `load_policy(path)` reads, what named it): `path` is
    SOURCE_ARGUMENT, `$FORGD_VERDICT_POLICY` is SOURCE_ENV, and the
    `policy.yaml` fallback is None."""
    if path is not None:
        return Path(path), SOURCE_ARGUMENT
    env = os.environ.get("FORGD_VERDICT_POLICY")
    if env:
        return Path(env), SOURCE_ENV
    return Path("policy.yaml"), None


def policy_path(path: str | os.PathLike[str] | None = None) -> Path:
    """The file `load_policy(path)` reads: `path`, else `$FORGD_VERDICT_POLICY`,
    else `policy.yaml`."""
    return _resolve(path)[0]


def default_policy(*, for_hook: bool = False) -> Policy:
    """The built-in defaults with the `ENV_OVERRIDES` variables applied.
    `for_hook` applies them as `_apply_env_overrides` describes."""
    return Policy(raw=_apply_env_overrides(_deep_merge(DEFAULT_POLICY, {}),
                                           for_hook=for_hook))


GITLEAKS_ROLE_PROFILES: dict[str, tuple[str, ...]] = {
    "server": ("server",),
    "collect": ("otel",),
    "intake": ("server", "hook"),
}


def gitleaks_daemon_config(policy: Policy, role: str) -> str:
    """The one config path `role`'s gitleaks daemon should load for `policy`.

    Each role runs its own daemon, so only the profiles that role builds
    are compared (`GITLEAKS_ROLE_PROFILES`), and among them only those that
    scan through the daemon. A profile inherits the top-level
    `detectors.gitleaks.config`. A profile with no config asks for the
    daemon's default: `$FORGD_GITLEAKS_CONFIG` when set, else the packaged
    baseline. A set `$FORGD_GITLEAKS_CONFIG` must match every config those
    profiles name. Relative paths resolve against the working directory.
    Raises ValueError naming both settings and both paths on any
    disagreement, and for a role not in `GITLEAKS_ROLE_PROFILES`.
    """
    if role not in GITLEAKS_ROLE_PROFILES:
        raise ValueError(f"unknown role {role!r}; expected one of "
                         f"{', '.join(GITLEAKS_ROLE_PROFILES)}.")
    env = os.environ.get(GITLEAKS_CONFIG_ENV) or None
    default = os.path.realpath(env) if env else str(BASELINE_CONFIG)
    sections: list[tuple[str, str | None]] = []
    for name in GITLEAKS_ROLE_PROFILES[role]:
        derived = policy.for_profile(name)
        if derived.gitleaks_daemon():
            sections.append((f"detectors.gitleaks.config for the {name} profile",
                             derived.gitleaks_config()))

    named = [(label, os.path.realpath(c)) for label, c in sections if c]
    if env:
        for label, path in named:
            if path != default:
                raise ValueError(
                    f"{GITLEAKS_CONFIG_ENV} is {default}, but {label} is {path}.")
    effective = [(label, os.path.realpath(c) if c else default, bool(c))
                 for label, c in sections]

    def show(label: str, path: str, set_here: bool) -> str:
        return f"{label} is {path}" if set_here else f"{label} is unset, so {path}"

    for entry in effective[1:]:
        if entry[1] != effective[0][1]:
            raise ValueError(f"{show(*effective[0])}, but {show(*entry)}. "
                             "The daemon loads one config.")
    return effective[0][1] if effective else default


def load_identity(path: str | os.PathLike[str] | None = None) -> tuple[Any, ...]:
    """Everything `load_policy(path)` reads that can change its result: the
    resolved file path, a sha256 of its bytes (None for no file, which
    loads the defaults), and the value of each `ENV_OVERRIDES` variable.

    `$NAME` references are resolved later, when a value is read; see
    `env_references`."""
    p = policy_path(path).absolute()
    body = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
    return (str(p), body,
            tuple((name, os.environ.get(name)) for name, _spec in _ENV_OVERRIDE_ITEMS))


def env_references(raw: Any) -> tuple[str, ...]:
    """The variable names of every `$NAME` string anywhere in `raw`, sorted."""
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, str):
            if node.startswith("$"):
                found.add(node[1:])
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, (list, tuple)):
            for v in node:
                walk(v)

    walk(raw)
    return tuple(sorted(found))


# Where deploy/entrypoint.sh writes a policy that arrived in the environment.
INLINE_POLICY_DIR = "/run/forgd/policy"
INLINE_POLICY_ENV = ("FORGD_POLICY_INLINE", "FORGD_POLICY_INLINE_GZ")


def written_from_env(path: Path) -> bool:
    """Whether `path` is a policy the entrypoint wrote from FORGD_POLICY_INLINE
    or FORGD_POLICY_INLINE_GZ: one is set, or the file is in the directory it
    writes to."""
    if any(os.environ.get(name) for name in INLINE_POLICY_ENV):
        return True
    dirs = {INLINE_POLICY_DIR, os.environ.get("FORGD_POLICY_DIR") or INLINE_POLICY_DIR}
    return str(path.absolute().parent) in dirs


def anchor_gitleaks_paths(policy: Policy, base: Path, *, refuse: bool = False) -> Policy:
    """`policy` with relative gitleaks `config`, `binary` and `daemon` paths
    resolved against `base`, the policy file's directory, unless
    `hook.project_overrides` is on.

    A relative path would otherwise resolve against whatever directory
    the process started in: the project, for the hook. A bare `binary`
    name is left for a PATH lookup, and a `$VAR` reference as written.

    With `refuse`, a relative path raises ValueError instead: `base` is a
    directory the entrypoint wrote the policy to, and nothing else is there.
    """
    if (policy.raw.get("hook") or {}).get("project_overrides") is True:
        return policy
    raw = copy.deepcopy(policy.raw)
    for where, section in (("detectors", raw.get("detectors")),
                           ("hook.detectors", (raw.get("hook") or {}).get("detectors"))):
        gitleaks = (section or {}).get("gitleaks")
        if not isinstance(gitleaks, dict):
            continue
        for key in ("config", "binary", "daemon"):
            value = gitleaks.get(key)
            if not isinstance(value, str) or not value or value.startswith("$"):
                continue
            if os.path.isabs(value) or (key == "binary" and os.sep not in value):
                continue
            if refuse:
                raise ValueError(
                    f"{where}.gitleaks.{key} is {value!r}, a relative path, in a policy "
                    f"that arrived inline and was written to {base}, where nothing else "
                    "is; give an absolute path")
            gitleaks[key] = str(base / value)
    return Policy(raw=raw)


def load_policy(path: str | os.PathLike[str] | None = None, *,
                for_hook: bool = False, drop_unknown_events: bool | None = None) -> Policy:
    """Load policy from YAML or JSON, merged over the built-in defaults.

    A path named by `path` or `$FORGD_VERDICT_POLICY` that does not exist
    raises PolicyNotFound. With neither set and no `./policy.yaml`, this
    returns `default_policy()`.

    Workspace collisions are refused by the ingest job, and entitlement
    names by `Policy.entitlements()`, which only the dashboard and the
    connector call, so a mistake in either never stops the verdict server.

    `for_hook` applies the environment overrides as `_apply_env_overrides`
    describes. `drop_unknown_events`, which defaults to `for_hook`, drops an
    unknown event in `hook.enabled_events` with a warning instead of
    refusing the policy.
    """
    p, source = _resolve(path)
    if not p.exists():
        if source is not None:
            raise PolicyNotFound(p, source)
        return default_policy(for_hook=for_hook)

    text = p.read_text(encoding="utf-8")
    if p.suffix in (".json",):
        data = json.loads(text)
    else:
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                f"{p} is YAML but PyYAML is not installed. "
                "Install `PyYAML` or use a .json policy file."
            ) from exc
        data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{p} must contain a mapping at the top level")
    policy = anchor_gitleaks_paths(
        Policy(raw=_apply_env_overrides(_deep_merge(DEFAULT_POLICY, data), for_hook=for_hook)),
        p.absolute().parent, refuse=written_from_env(p))
    parse_allow(policy.raw.get("plugins"))
    refuse_unknown_compliance_keys(policy.raw.get("compliance"))
    hook = policy.raw.get("hook") or {}
    parse_expansions(hook.get("expansions"))
    parse_watchdog_ms(hook.get("watchdog_ms"))
    if drop_unknown_events is None:
        drop_unknown_events = for_hook
    if drop_unknown_events:
        events, unknown = split_enabled_events(hook.get("enabled_events"))
        if unknown:
            log.warning(f"hook.enabled_events has {', '.join(unknown)}, which the hook does "
                        "not handle; ignored. `forgd-verdict policy` refuses this file",
                        extra={"fields": {"events": unknown, "policy": str(p)}})
            policy.raw["hook"]["enabled_events"] = events
    else:
        events = parse_enabled_events(hook.get("enabled_events"))
    own_hook = data.get("hook")
    if (isinstance(own_hook, dict) and "expansions" in own_hook
            and "UserPromptExpansion" not in events):
        log.warning("hook.expansions is set but UserPromptExpansion is not in "
                    "hook.enabled_events, so no expansion is refused",
                    extra={"fields": {"policy": str(p)}})
    return policy


# The hook events the hook scans, and the shape each blocks in, per
# code.claude.com/docs/en/hooks: "top" is a top-level `decision` and
# `reason`, "tool" is `hookSpecificOutput.permissionDecision`.
HOOK_BLOCK_SHAPES = {
    "UserPromptSubmit": "top",
    "UserPromptExpansion": "top",
    "PreToolUse": "tool",
    "PostToolUse": "top",
}


# Events `hook.enabled_events` accepts that the hook handles before it
# reads that list.
HOOK_IGNORED_EVENTS = frozenset({"SessionEnd"})


def split_enabled_events(events: Any) -> tuple[list[str], list[str]]:
    """`hook.enabled_events` as (known, unknown): known events are in
    HOOK_BLOCK_SHAPES or HOOK_IGNORED_EVENTS. ValueError if it is not a list."""
    if events is None:
        return [], []
    if not isinstance(events, list):
        raise ValueError(f"hook.enabled_events must be a list, not {type(events).__name__}")
    known = [e for e in events if e in HOOK_BLOCK_SHAPES or e in HOOK_IGNORED_EVENTS]
    unknown = [str(e) for e in events if e not in known]
    return known, unknown


def parse_enabled_events(events: Any) -> list[str]:
    """`hook.enabled_events` validated by `split_enabled_events`; ValueError
    naming any unknown event."""
    known, unknown = split_enabled_events(events)
    if unknown:
        raise PolicyInvalid(f"hook.enabled_events has {', '.join(unknown)}; the hook "
                         f"scans and blocks only {', '.join(HOOK_BLOCK_SHAPES)}")
    return known


EXPANSION_KEYS = frozenset({"default", "deny", "allow"})
EXPANSION_RULE_KEYS = ("command_source", "expansion_type", "command_name")
EXPANSION_TYPES = frozenset({"slash_command", "mcp_prompt"})


# Claude Code's `timeout` for the scan hooks in every shipped managed
# settings fragment. A hook still running then is killed and the prompt or
# tool call goes through unscanned.
CLAUDE_CODE_HOOK_TIMEOUT_MS = 10_000


def parse_watchdog_ms(value: Any) -> int:
    """`hook.watchdog_ms`: an integer above 0 and below
    CLAUDE_CODE_HOOK_TIMEOUT_MS. PolicyInvalid on anything else."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PolicyInvalid(f"hook.watchdog_ms must be a whole number of milliseconds "
                            f"above 0, not {value!r}")
    if value >= CLAUDE_CODE_HOOK_TIMEOUT_MS:
        raise PolicyInvalid(
            f"hook.watchdog_ms is {value}, at or past Claude Code's "
            f"{CLAUDE_CODE_HOOK_TIMEOUT_MS} ms hook timeout in the shipped managed "
            "settings; Claude Code kills a hook still running then and the prompt "
            "goes through unscanned. Set it below that, with room for the decision "
            "to be written.")
    return value


def parse_expansions(section: Any) -> dict[str, Any]:
    """`hook.expansions` validated: `default` (`allow` | `deny`) and the
    `deny` and `allow` rule lists. ValueError on anything else.

    A rule is a mapping of one or more of EXPANSION_RULE_KEYS to strings,
    and matches a payload whose fields equal every value it sets.
    """
    if section is None:
        section = {}
    if not isinstance(section, dict):
        raise ValueError(f"hook.expansions must be a mapping, not {type(section).__name__}")
    unknown = sorted(str(k) for k in section if k not in EXPANSION_KEYS)
    if unknown:
        raise ValueError(f"hook.expansions has {', '.join(unknown)}; it takes "
                         f"{', '.join(sorted(EXPANSION_KEYS))}")
    default = section.get("default", "allow")
    if default not in ("allow", "deny"):
        raise ValueError(f"hook.expansions.default must be allow|deny, got {default!r}")
    out: dict[str, Any] = {"default": default}
    for kind in ("deny", "allow"):
        rules = section.get(kind) or []
        if not isinstance(rules, list):
            raise ValueError(f"hook.expansions.{kind} must be a list of rules, "
                             f"not {type(rules).__name__}")
        for i, rule in enumerate(rules):
            where = f"hook.expansions.{kind}[{i}]"
            if not isinstance(rule, dict):
                raise ValueError(f"{where} must be a mapping, not {type(rule).__name__}")
            bad = sorted(str(k) for k in rule if k not in EXPANSION_RULE_KEYS)
            if bad:
                raise ValueError(f"{where} has {', '.join(bad)}; a rule takes "
                                 f"{', '.join(EXPANSION_RULE_KEYS)}")
            if not rule:
                raise ValueError(f"{where} must set at least one of "
                                 f"{', '.join(EXPANSION_RULE_KEYS)}")
            for key, value in rule.items():
                if not isinstance(value, str):
                    raise ValueError(f"{where}.{key} must be a string, "
                                     f"not {type(value).__name__}")
            if rule.get("expansion_type", "slash_command") not in EXPANSION_TYPES:
                raise ValueError(f"{where}.expansion_type must be one of "
                                 f"{', '.join(sorted(EXPANSION_TYPES))}, "
                                 f"got {rule['expansion_type']!r}")
        out[kind] = [dict(rule) for rule in rules]
    return out


# What adapter 3 reads from `compliance:`: the scanner's connection and
# paging settings, the single-org form, `orgs`, and the profile overrides
# `for_profile("compliance")` merges.
COMPLIANCE_KEYS = frozenset({
    "anthropic_version", "api_key", "base_url", "detectors", "lookback_minutes",
    "org_id", "orgs", "page_limit", "scan", "state_path",
})


def refuse_unknown_compliance_keys(section: Any) -> None:
    """ValueError naming any key in `compliance:` that nothing reads."""
    if section is None:
        return
    if not isinstance(section, dict):
        raise ValueError(f"compliance must be a mapping, not {type(section).__name__}")
    unknown = sorted(str(k) for k in section if k not in COMPLIANCE_KEYS)
    if unknown:
        raise ValueError(
            f"compliance has {', '.join(unknown)}, which nothing reads; it takes "
            f"{', '.join(sorted(COMPLIANCE_KEYS))}. cors_origins belongs under otel.")


# The hook's destinations, credentials, timeout and shipping mode. A Claude
# Code project's `.claude/settings.json` `env` block reaches the hook's
# environment, so these are applied only when the policy file sets
# `hook.project_overrides: true`.
PROJECT_OVERRIDE_ENV = frozenset({
    "FORGD_VERDICT_SCAN_ENDPOINT",
    "FORGD_VERDICT_SCAN_TOKEN",
    "FORGD_VERDICT_SCAN_TIMEOUT_MS",
    "FORGD_VERDICT_SHIP_MODE",
    "FORGD_VERDICT_SHIP_ENDPOINT",
    "FORGD_VERDICT_SHIP_STORE",
    "FORGD_VERDICT_SHIP_TOKEN",
})


def _apply_env_overrides(raw: dict[str, Any], *, for_hook: bool = False) -> dict[str, Any]:
    """Let specific settings be overridden from the environment.

    Deliberately an allowlist rather than a generic FORGD_VERDICT_<PATH>
    scheme: the environment is where a deployment platform injects values,
    and a wildcard mechanism would let an env var silently weaken detector
    severities or disable a detector. Only the operational knobs are exposed.

    A value that fails its cast raises ValueError. With `for_hook`, only the
    overrides under `hook` apply, and one that fails its cast is skipped
    with a warning naming the variable but not its value.
    """
    project_overrides = (raw.get("hook") or {}).get("project_overrides") is True
    for name, (path, caster) in _ENV_OVERRIDE_ITEMS:
        if for_hook and path[0] != "hook":
            continue
        value = os.environ.get(name)
        if value is None or value == "":
            continue
        if name in PROJECT_OVERRIDE_ENV and not project_overrides:
            print(f"forgd-verdict: {name} ignored; the policy does not set "
                  "hook.project_overrides: true", file=sys.stderr)
            continue
        try:
            cast = caster(value)
        except (TypeError, ValueError) as exc:
            if for_hook:
                print(f"forgd-verdict: {name} ignored; it is not a valid "
                      f"{caster.__name__}", file=sys.stderr)
                continue
            raise ValueError(f"{name}={value!r} is not a valid {caster.__name__}") from exc
        # Paths are walked rather than destructured: `dashboard.auth.mode` is
        # three deep, and the two-element unpack this replaced would have
        # raised on it.
        target = raw
        for part in path[:-1]:
            nxt = target.setdefault(part, {})
            if not isinstance(nxt, dict):
                raise ValueError(f"{name} cannot override {'.'.join(path)}: "
                                 f"{part!r} is not a mapping")
            target = nxt
        target[path[-1]] = cast
    return raw
