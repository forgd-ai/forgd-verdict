"""The connector's ASGI app: authentication in front of the MCP SDK.

Three routes and nothing else:

  /healthz                                   open, liveness
  /readyz                                    open, readiness
  /.well-known/oauth-protected-resource/mcp  open, RFC 9728 metadata
  /mcp                                       Origin check, then a bearer
                                             token, then the SDK

Every `/mcp` request is authenticated here, before the SDK sees it. A
request without a valid token gets a 401 carrying `resource_metadata` and
`scope`, which is how Claude discovers the identity provider. A valid token
without `required_scope` gets a 403 with `error="insufficient_scope"`. No route
redirects: a redirect to another host drops `Authorization`, and Claude
reads any redirect on discovery as a failure.

The SDK is imported when the app is built, so the rest of the package loads
without the `connector` extra.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from ..dashboard.auth import AuthError
from ..metadata import MetadataGuard
from .config import MCP_PATH, ConnectorConfig
from .tools import Reader, build_tools

log = logging.getLogger("forgd_verdict.connector")

PRM_PREFIX = "/.well-known/oauth-protected-resource"
SERVER_NAME = "forgd-verdict findings"


def metadata_url(resource: str) -> str:
    """Where the protected resource metadata for `resource` is served."""
    parts = urlsplit(resource)
    return f"{parts.scheme}://{parts.netloc}{PRM_PREFIX}{parts.path}"


def token_scopes(claims: dict[str, Any]) -> frozenset[str]:
    """Scopes a token carries: Entra's `scp`, or the RFC 9068 `scope`, each a
    space-separated string or a list."""
    out: set[str] = set()
    for key in ("scp", "scope"):
        value = claims.get(key)
        if isinstance(value, str):
            out.update(value.split())
        elif isinstance(value, list):
            out.update(str(v) for v in value if v)
    return frozenset(out)


def _finite(value: int | float) -> bool:
    """Whether `value` is a finite float, or an int within the float range."""
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


class ConnectorTokenVerifier:
    """The SDK's `TokenVerifier`, backed by the dashboard's `oidc_jwt` verifier.

    Signature, issuer, `exp` and `aud` are checked by `AuthConfig`. A token
    that fails is `None`, and the reason goes to the log only. Scopes are
    returned, not checked: a missing scope is a 403, decided by the caller.
    """

    def __init__(self, cfg: ConnectorConfig):
        self.cfg = cfg

    async def verify_token(self, token: str):
        from mcp.server.auth.provider import AccessToken

        try:
            # Synchronous, and a JWKS fetch on a cold cache is network I/O.
            principal = await asyncio.to_thread(
                self.cfg.auth.authenticate, {"authorization": f"Bearer {token}"})
        except AuthError as exc:
            log.info("connector request rejected", extra={"fields": {"reason": str(exc)}})
            return None
        import jwt  # noqa: PLC0415 - present whenever AuthConfig parsed oidc_jwt

        # The signature was verified above; this reads the same token's claims.
        claims = jwt.decode(token, options={"verify_signature": False})
        scopes = token_scopes(claims)
        exp = claims.get("exp")
        # PyJWT accepts an `exp` it can int(), such as a numeric string.
        if (isinstance(exp, bool) or not isinstance(exp, int | float)
                or not _finite(exp)):
            log.info("connector request rejected",
                     extra={"fields": {"reason": "token rejected: exp is not a finite number"}})
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("azp") or claims.get("appid")
                          or claims.get("client_id") or ""),
            scopes=sorted(scopes),
            expires_at=int(exp),
            subject=str(claims.get("sub") or "") or None,
            claims={"iss": principal.issuer},
        )


class ConnectorApp:
    def __init__(self, cfg: ConnectorConfig, reader: Reader):
        from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
        from mcp.server.mcpserver import MCPServer
        from mcp.server.transport_security import TransportSecuritySettings

        self.cfg = cfg
        self.reader = reader
        self.verifier = ConnectorTokenVerifier(cfg)
        self.metadata_url = metadata_url(cfg.resource)
        self.metadata_path = PRM_PREFIX + urlsplit(cfg.resource).path
        self._started = time.time()
        self._screen: tuple[Any, list[Any], Any] | bool | None = None
        self.mcp = MCPServer(SERVER_NAME, tools=build_tools(reader))
        # Origin is checked in `__call__` against connector.allowed_origins.
        # The SDK's own check would also pin Host, which the ingress decides.
        inner = self.mcp.streamable_http_app(
            streamable_http_path=MCP_PATH, stateless_http=True, json_response=True,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=False))
        # Starlette answers `/mcp/` with a 307 to `/mcp` by default.
        inner.router.redirect_slashes = False
        self.inner = inner
        # Puts the verified token where `get_access_token()` finds it.
        self.handler = AuthContextMiddleware(inner)
        challenge = f'Bearer resource_metadata="{self.metadata_url}"'
        wanted = " ".join(cfg.scopes) or cfg.required_scope
        if wanted:
            challenge += f', scope="{wanted}"'
        self.challenge = challenge
        self.scope_challenge = (
            f'Bearer error="insufficient_scope", scope="{wanted}", '
            f'resource_metadata="{self.metadata_url}"')
        log.info("connector ready", extra={"fields": {
            "resource": cfg.resource, "auth": cfg.auth.describe(),
            "required_scope": cfg.required_scope,
            "allowed_origins": list(cfg.allowed_origins)}})

    def running(self):
        """The SDK's session manager, for a caller that does not send
        lifespan events (tests)."""
        return self.mcp.session_manager.run()

    def metadata(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "resource": self.cfg.resource,
            "authorization_servers": [i.issuer for i in self.cfg.auth.issuers],
            "bearer_methods_supported": ["header"],
        }
        if self.cfg.scopes:
            doc["scopes_supported"] = list(self.cfg.scopes)
        return doc

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] == "lifespan":
            await self.inner(scope, receive, send)
            return
        if scope["type"] != "http":  # pragma: no cover
            return
        path = scope.get("path", "")
        method = scope.get("method", "GET")
        if path == "/healthz":
            await _json(send, 200, {"status": "ok",
                                    "uptime_s": round(time.time() - self._started, 1)})
            return
        if path == "/readyz":
            from ..overrides import readiness

            await _json(send, *readiness(self.reader.overrides))
            return
        if path == self.metadata_path:
            if method not in ("GET", "HEAD"):
                await _json(send, 405, {"error": "method_not_allowed"})
                return
            await _json(send, 200, self.metadata())
            return
        if path != MCP_PATH:
            await _json(send, 404, {"error": "not_found"})
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers") or []}
        origin = headers.get("origin")
        if origin is not None and origin not in self.cfg.allowed_origins:
            log.info("connector request refused", extra={"fields": {
                "reason": "origin not allowed", "origin": self._screened_origin(origin)}})
            await _json(send, 403, {"error": "origin_not_allowed"})
            return

        raw = headers.get("authorization", "")
        access = None
        if raw[:7].lower() == "bearer " and raw[7:].strip():
            access = await self.verifier.verify_token(raw[7:].strip())
        if access is None:
            await self._unauthorized(send, presented=bool(raw))
            return
        required = self.cfg.required_scope
        if required not in access.scopes:
            log.info("connector request refused", extra={"fields": {
                "reason": "required scope missing", **self._screened_subject(access.subject)}})
            await _json(send, 403, {"error": "insufficient_scope"},
                        extra=[(b"www-authenticate", self.scope_challenge.encode("latin-1"))])
            return

        from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
        from starlette.authentication import AuthCredentials

        scope = dict(scope, user=AuthenticatedUser(access),
                     auth=AuthCredentials(access.scopes))
        await self.handler(scope, receive, send)

    def _log_screen(self) -> tuple[Any, list[Any], Any] | None:
        """(OrgScreen, detectors, salt) from the policy, built on first use;
        None when the policy is absent or its detectors cannot be built."""
        if self._screen is None:
            from ..overrides import org_screen_of

            policy = self.cfg.policy
            try:
                self._screen = (org_screen_of(policy),
                                policy.build_detectors(profile="connector"),
                                policy.hash_salt)
            except Exception:  # noqa: BLE001 - no scan, no value
                log.warning("connector log values are withheld: the policy's "
                            "detectors could not be built")
                self._screen = False
        return self._screen or None

    def _screened_origin(self, origin: str) -> str:
        from ..overrides import WITHHELD_UNSCANNED

        screen = self._log_screen()
        if screen is None:
            return WITHHELD_UNSCANNED
        org, detectors, salt = screen
        return MetadataGuard(detectors, salt, allow_subprocess=True).one(
            org(origin), where="connector:origin")

    def _screened_subject(self, subject: str | None) -> dict[str, Any]:
        from ..overrides import WITHHELD_UNSCANNED, screened_identity

        screen = self._log_screen()
        if screen is None:
            return {"who": WITHHELD_UNSCANNED if subject else subject}
        org, detectors, salt = screen
        return screened_identity(org(subject) if subject else subject, detectors, salt)

    async def _unauthorized(self, send: Callable, presented: bool) -> None:
        # RFC 6750: no error code when no credential was sent.
        challenge = (self.challenge + ', error="invalid_token"') if presented \
            else self.challenge
        await _json(send, 401, {"error": "unauthorized"},
                    extra=[(b"www-authenticate", challenge.encode("latin-1"))])


async def _json(send: Callable, status: int, payload: dict,
                extra: list[tuple[bytes, bytes]] | None = None) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
        (b"x-content-type-options", b"nosniff"),
    ]
    headers.extend(extra or [])
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def create_app(cfg: ConnectorConfig, reader: Reader) -> ConnectorApp:
    return ConnectorApp(cfg, reader)
