"""The connector's configuration, validated once at startup.

`load(policy)` returns None when the connector is disabled and a
`ConnectorConfig` when it is enabled and every check passes. Anything else
raises ValueError, and the server does not start. The messages name keys
and do not repeat the resource URL or any other value that could carry a
credential, so they can be printed as they are.

The connector is an OAuth resource server and nothing else. The one way in
is a JWT from a configured issuer, sent as `Authorization: Bearer` and
verified by the dashboard's `oidc_jwt` verifier. So the checks here refuse
every configuration that would admit a caller some other way: another auth
mode, a proxy platform, a trusted header, or a static credential. A static
key -- Claude's `static_headers` auth type -- is one bearer shared by every
member of a Claude organization, with no principal behind it for
entitlements to apply to.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..dashboard.auth import AuthConfig
from ..entitlements import MODE_OIDC_JWT, Entitlements
from ..models import env_or_literal

CONNECTOR_KEYS = frozenset({
    "enabled", "resource", "scopes", "required_scope", "allowed_origins", "auth",
})
AUTH_KEYS = frozenset({"mode", "issuer", "jwks_url", "audience", "groups_claim", "issuers"})
ISSUER_KEYS = frozenset({"issuer", "jwks_url", "audience", "groups_claim"})

# Keys that would configure a credential the connector checks by equality
# rather than by signature. Named so the refusal can say why.
STATIC_CREDENTIAL_KEYS = frozenset({
    "static_headers", "static_token", "static_tokens", "headers", "token",
    "tokens", "bearer", "bearer_token", "api_key", "api_keys", "secret",
    "client_secret", "shared_secret",
})

# The path the connector serves MCP on, and so the path of `resource`.
MCP_PATH = "/mcp"
# The header every token arrives in. Not configurable.
AUTH_HEADER = "authorization"
DEFAULT_ALLOWED_ORIGINS = ("https://claude.ai",)


@dataclass
class ConnectorConfig:
    resource: str
    scopes: tuple[str, ...]
    required_scope: str
    allowed_origins: tuple[str, ...]
    auth: AuthConfig
    entitlements: Entitlements = field(default_factory=Entitlements)
    # The policy this was loaded from, for screening what the log carries.
    policy: Any = field(default=None, repr=False, compare=False)


def load(policy: Any) -> ConnectorConfig | None:
    """Validate `policy.connector`. None when disabled; raises when invalid."""
    raw = policy.connector
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError("connector.enabled must be true or false, not a string or a "
                         "placeholder")
    if not enabled:
        return None
    _refuse_unknown(raw, CONNECTOR_KEYS, "connector")

    auth_raw = raw.get("auth")
    if not isinstance(auth_raw, dict) or not auth_raw:
        raise ValueError(
            "connector.enabled is true but connector.auth is not set. The "
            f"connector only accepts {MODE_OIDC_JWT} tokens from your identity "
            "provider; set connector.auth.mode, issuer, jwks_url and audience.")
    _refuse_unknown(auth_raw, AUTH_KEYS, "connector.auth")

    mode = str(auth_raw.get("mode") or "")
    if mode != MODE_OIDC_JWT:
        raise ValueError(
            f"connector.auth.mode must be {MODE_OIDC_JWT!r}"
            f"{'' if mode else ' and is unset'}. "
            "The connector has no unauthenticated or trusted-header mode: it is "
            "reached from Anthropic's cloud, where no proxy in front can vouch "
            "for a caller.")

    _check_issuers(auth_raw)
    resource = _canonical_resource(raw.get("resource"))

    parsed = dict(auth_raw, header=AUTH_HEADER)
    try:
        auth = AuthConfig.parse(parsed)
    except ValueError as exc:
        # AuthConfig names the block it was written for.
        raise ValueError(str(exc).replace("dashboard.auth", "connector.auth")) from exc

    required_scope = str(env_or_literal(str(raw.get("required_scope") or "")) or "")
    if not required_scope:
        raise ValueError(
            "connector.required_scope is empty. Without it any token whose audience "
            "matches is accepted, including an ID token or a token issued for the "
            "dashboard from the same app registration. Set it to the scope your "
            "identity provider issues for the connector, for example findings.read.")

    return ConnectorConfig(
        resource=resource,
        scopes=_strings(raw.get("scopes"), "connector.scopes"),
        required_scope=required_scope,
        allowed_origins=_strings(raw.get("allowed_origins"), "connector.allowed_origins")
        or DEFAULT_ALLOWED_ORIGINS,
        auth=auth,
        entitlements=policy.entitlements(auth=auth_raw, auth_path="connector.auth"),
        policy=policy,
    )


def _refuse_unknown(raw: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    for key in raw:
        if key in STATIC_CREDENTIAL_KEYS:
            raise ValueError(
                f"{where}.{key}: the connector does not accept a static credential. "
                "A key shared by a whole Claude organization has no user behind it, "
                "so entitlements cannot apply. Add the connector in Claude with "
                "OAuth against your identity provider.")
        if key in ("platform", "alb_arn"):
            raise ValueError(
                f"{where}.{key}: the connector takes no proxy platform. Tokens "
                f"arrive from Claude in the {AUTH_HEADER!r} header, with nothing "
                "in front to sign anyone in.")
        if key in ("header", "stripped_by"):
            raise ValueError(
                f"{where}.{key}: the connector reads tokens from the "
                f"{AUTH_HEADER!r} header only and trusts no other header.")
        if key not in allowed:
            raise ValueError(f"{where}.{key} is not a connector setting; "
                             f"expected one of {sorted(allowed)}")


def _check_issuers(auth: dict[str, Any]) -> None:
    """At least one issuer, and every issuer has issuer, jwks_url and audience."""

    def resolved(entry: dict[str, Any], key: str) -> bool:
        value = entry.get(key)
        values = value if isinstance(value, list) else [value]
        return any(env_or_literal(str(v or "")) for v in values)

    count = 0
    single = [k for k in ("issuer", "jwks_url", "audience") if auth.get(k)]
    if single:
        missing = [k for k in ("issuer", "jwks_url", "audience") if not resolved(auth, k)]
        if missing:
            raise ValueError(
                f"connector.auth: {', '.join(missing)} not set. An issuer without "
                "an audience would accept tokens minted for any application of "
                "that identity provider.")
        count += 1
    for n, entry in enumerate(auth.get("issuers") or []):
        if not isinstance(entry, dict):
            raise ValueError(f"connector.auth.issuers[{n}] must be a mapping")
        _refuse_unknown(entry, ISSUER_KEYS, f"connector.auth.issuers[{n}]")
        missing = [k for k in ("issuer", "jwks_url", "audience") if not resolved(entry, k)]
        if missing:
            raise ValueError(
                f"connector.auth.issuers[{n}]: {', '.join(missing)} not set. An "
                "issuer without an audience would accept tokens minted for any "
                "application of that identity provider.")
        count += 1
    if not count:
        raise ValueError("connector.auth sets no issuer; set issuer, jwks_url and "
                         "audience, or an issuers list")


def _canonical_resource(value: Any) -> str:
    """The MCP server URL in the form Claude sends as RFC 8707 `resource`:
    https, lowercase host, no default port, no trailing slash, no query or
    fragment."""
    url = str(env_or_literal(str(value or "")) or "")
    if not url:
        raise ValueError("connector.resource is not set; set it to the connector's "
                         "public MCP URL, e.g. https://connector.example.com/mcp")
    parts = urlsplit(url)
    problems = []
    if parts.scheme != "https":
        problems.append("the scheme must be https")
    if not parts.hostname:
        problems.append("there is no host")
    if parts.username is not None or parts.password is not None:
        problems.append("it carries credentials")
    if parts.netloc != parts.netloc.lower():
        problems.append("the host must be lowercase")
    if parts.netloc.endswith(":443"):
        problems.append("the default port must be omitted")
    if parts.path.endswith("/"):
        problems.append("it must not end with a slash")
    if urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")) != url:
        problems.append("it must not carry a query or fragment")
    if problems:
        raise ValueError(
            f"connector.resource is not canonical: {'; '.join(problems)}. "
            "Claude sends the canonical form as the token's resource, and the "
            "protected resource metadata must match it exactly.")
    if parts.path != MCP_PATH:
        raise ValueError(
            f"connector.resource must end in {MCP_PATH}: the connector serves "
            f"MCP at {MCP_PATH} and the chart routes that path, so the URL Claude is "
            "given has to name it.")
    return url


def _strings(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{where} must be a list")
    return tuple(s for s in (str(env_or_literal(str(v or "")) or "") for v in value) if s)
