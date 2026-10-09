"""Who may change runtime overrides from the dashboard, and the form tokens.

`dashboard.admins` is off when absent or when it lists no groups. With groups,
it needs `oidc_jwt`, an explicit `allowed_origins` list and a `form_key`; the
dashboard refuses to start without any of them. See docs/OVERRIDES.md.

A form token is an HMAC-SHA256, under `form_key`, over the principal, the
action, the key, the value, the object's revision and the time it was issued.
It is refused after TOKEN_TTL_S, and once any write moves the revision.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any

from ..entitlements import MODE_OIDC_JWT, Principal, scoped_group
from ..models import env_or_literal, shown_url

TOKEN_TTL_S = 300
MIN_FORM_KEY_BYTES = 32
MAX_BODY_BYTES = 4096
PATH_ACTIONS = "/admin/actions"

_ORIGIN = re.compile(r"https?://[^/\s?#@]+")


class TokenRefused(Exception):
    """A form token that does not verify. The reason is for the log only."""


@dataclass(frozen=True)
class AdminConfig:
    groups: frozenset[str]
    allowed_origins: frozenset[str]
    form_key: bytes

    @classmethod
    def parse(cls, raw: Any, auth: Any) -> AdminConfig | None:
        """`dashboard.admins` against the dashboard's AuthConfig, or None when off."""
        if not raw:
            return None
        if not isinstance(raw, dict):
            raise ValueError("dashboard.admins must be a mapping")
        entries = raw.get("groups") or []
        if not isinstance(entries, list):
            raise ValueError("dashboard.admins.groups must be a list")
        if not entries:
            return None
        mode = getattr(auth, "mode", "none")
        if mode != MODE_OIDC_JWT:
            raise ValueError(
                f"dashboard.admins requires dashboard.auth.mode {MODE_OIDC_JWT!r}; got "
                f"{mode!r}. An admin group from an unverified source is one the caller "
                "chooses.")
        if getattr(auth, "platform", "") == "iap":
            raise ValueError(
                "dashboard.admins is set but dashboard.auth.platform is iap: Identity-Aware "
                "Proxy tokens carry no groups, so no admin could match.")
        issuers = len(getattr(auth, "issuers", ()) or ())
        groups: set[str] = set()
        for n, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(f"dashboard.admins.groups[{n}] must be a mapping")
            group = str(env_or_literal(entry.get("group")) or "")
            issuer = str(env_or_literal(entry.get("issuer")) or "")
            if not group:
                raise ValueError(f"dashboard.admins.groups[{n}] has no group")
            if issuers > 1 and not issuer:
                raise ValueError(
                    "dashboard.admins.groups: with more than one identity provider every "
                    f"entry needs `issuer`; {group!r} has none, so a group of that name "
                    "from any provider would match it")
            groups.add(scoped_group(issuer, group) if issuer else group)
        origins = raw.get("allowed_origins") or []
        if not isinstance(origins, list) or not origins:
            raise ValueError(
                "dashboard.admins.allowed_origins must list the dashboard's origin, "
                "e.g. https://verdict-dashboard.example.com")
        for origin in origins:
            if not isinstance(origin, str) or not _ORIGIN.fullmatch(origin):
                raise ValueError(
                    "dashboard.admins.allowed_origins: "
                    f"{shown_url(origin) if isinstance(origin, str) else type(origin).__name__!r}"
                    " is not a scheme and "
                    "host with no path")
        key = str(env_or_literal(str(raw.get("form_key") or "")) or "")
        if len(key.encode("utf-8")) < MIN_FORM_KEY_BYTES:
            raise ValueError(
                "dashboard.admins.form_key is empty or shorter than "
                f"{MIN_FORM_KEY_BYTES} bytes; set FORGD_DASHBOARD_FORM_KEY on the dashboard "
                "from the secret store")
        return cls(frozenset(groups), frozenset(o.rstrip("/") for o in origins),
                   key.encode("utf-8"))

    def match(self, principal: Principal) -> str | None:
        """The admin group `principal` is in, or None."""
        for group in principal.groups:
            if group in self.groups or scoped_group(principal.issuer, group) in self.groups:
                return group
        return None

    def describe(self) -> dict[str, Any]:
        return {"groups": len(self.groups), "allowed_origins": sorted(self.allowed_origins)}

    # -- form tokens ----------------------------------------------------

    def _mac(self, payload: bytes) -> bytes:
        return hmac.new(self.form_key, payload, hashlib.sha256).digest()

    def mint(self, principal: Principal, action: str, key: str, value: str,
             revision: int, issued_at: int) -> str:
        payload = json.dumps([principal.issuer, principal.subject, action, key, value,
                              revision, issued_at], separators=(",", ":")).encode("utf-8")
        return f"{_b64(payload)}.{_b64(self._mac(payload))}"

    def verify(self, token: str, principal: Principal, action: str, key: str,
               value: str, now: int) -> int:
        """The revision `token` was minted against. TokenRefused otherwise."""
        try:
            body, mac = token.split(".", 1)
            payload = _unb64(body)
            supplied = _unb64(mac)
        except (ValueError, AttributeError) as exc:
            raise TokenRefused("malformed") from exc
        if not hmac.compare_digest(supplied, self._mac(payload)):
            raise TokenRefused("signature")
        try:
            issuer, subject, t_action, t_key, t_value, revision, issued_at = json.loads(payload)
        except (ValueError, TypeError, RecursionError) as exc:
            raise TokenRefused("malformed") from exc
        if (issuer, subject) != (principal.issuer, principal.subject):
            raise TokenRefused("principal")
        if (t_action, t_key, t_value) != (action, key, value):
            raise TokenRefused("action")
        if not isinstance(issued_at, int) or not 0 <= now - issued_at <= TOKEN_TTL_S:
            raise TokenRefused("expired")
        if not isinstance(revision, int):
            raise TokenRefused("malformed")
        return revision


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
