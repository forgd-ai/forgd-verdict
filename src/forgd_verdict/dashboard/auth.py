"""Who is allowed to read the findings page.

Three modes, and the difference between them is what the app is trusting.

`none`
    Nothing. Only correct behind a trusted network.

`trusted_header`
    A header the platform's auth proxy injects. **This is only safe where
    the proxy provably strips inbound copies of that header.** Azure
    Container Apps EasyAuth does; a container reachable without passing
    through its proxy does not, and there the check is no check at all --
    the caller simply sets the header. The mode is named for what it
    actually does so that nobody reads "require_principal" as
    "authenticated".

`oidc_jwt`
    Verify a signed token against the issuer's JWKS: signature, `exp`,
    `iss`, `aud`. This is the mode that generalises, because it trusts an
    assertion rather than a network position. It works anywhere the
    platform hands over an ID token -- Azure's `X-MS-TOKEN-AAD-ID-TOKEN`,
    an ALB's `X-Amzn-Oidc-Data`, IAP's `X-Goog-IAP-JWT-Assertion`.

    `cloud_run` and `iap` are different things. `cloud_run` reads
    `X-Serverless-Authorization`, the ID token of a *caller invoking the
    service* -- another service, or a user holding `run.invoker` -- verified
    against whatever issuer is configured. `iap` is a *person signed in* by
    Identity-Aware Proxy, verified against IAP's own keys.

Verification needs RSA, which the stdlib does not provide, so `oidc_jwt`
requires `forgd-verdict[dashboard]` (PyJWT). The verdict server's hot path
keeps no crypto dependency; this is the dashboard only.
"""

from __future__ import annotations

import json
import math
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.request import urlopen

from ..entitlements import MODE_NONE, MODE_OIDC_JWT, MODE_TRUSTED_HEADER, MODES, Principal
from ..models import env_or_literal, shown_url
from ..safehttp import cleartext_refusal

# Platform defaults, so an operator names a platform rather than a header.
# These are the proxies in front, not the identity providers behind them:
# the proxy decides which header the token arrives in, and the wrong one
# looks exactly like a broken IdP. Anything else -- an Istio or Envoy JWT
# filter -- sets `header` directly.
PLATFORM_HEADERS = {
    "container_apps": "x-ms-token-aad-id-token",
    # The ID token of whoever invoked the service, checked against the
    # configured issuer. A person signed in by IAP is `iap` below.
    "cloud_run": "x-serverless-authorization",
    # Verified differently from the rest: see `_verify_alb`.
    "alb_oidc": "x-amzn-oidc-data",
    # A user signed in by Identity-Aware Proxy. See `_verify_iap`.
    "iap": "x-goog-iap-jwt-assertion",
    # With --pass-authorization-header, oauth2-proxy sends the ID token as
    # `Authorization: Bearer`. Its x-auth-request-access-token is an
    # ACCESS token, minted for another audience, and would not verify.
    "oauth2_proxy": "authorization",
    "cloudflare_access": "cf-access-jwt-assertion",
    "pomerium": "x-pomerium-jwt-assertion",
}

# Signature algorithms a token may use. An ALLOWLIST, never the token's own
# `alg`, and never `none`. RSA alone rejected every login from an IdP
# signing with ES256 -- Auth0 on newer tenants, Okta when configured -- and
# the reason is logged but never returned, so the operator saw a wall of
# 401s with nothing to go on.
ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
              "ES256", "ES384", "ES512")

# JWKS changes when a key rotates, which is rare; refetching per request
# would put the identity provider on the page-load path.
JWKS_TTL_S = 3600.0

# An AWS ALB does not publish a JWKS. It signs `x-amzn-oidc-data` with
# ES256, names the key in the header's `kid`, and serves that one key as
# PEM at this regional URL. The token has no `aud`: the header's `signer`
# (the load balancer's ARN) and `client` (the IdP client id) say who it is
# for. Per docs.aws.amazon.com/elasticloadbalancing/latest/application/
# listener-authenticate-users.html.
ALB_KEY_URL = "https://public-keys.auth.elb.{region}.amazonaws.com/{kid}"
# The commercial partition only. GovCloud and China serve ALB keys from
# other hosts, and accepting their ARNs here started cleanly and then
# refused every login.
_ALB_ARN = re.compile(r"^arn:aws:elasticloadbalancing:([a-z0-9-]+):\d{12}:"
                      r"loadbalancer/app/[A-Za-z0-9-]+/[0-9a-f]+\Z")
# The kid goes into a URL, so it is a UUID-like token and nothing else.
_ALB_KID = re.compile(r"^[A-Za-z0-9-]{1,128}\Z")
ALB_KEYS_MAX = 64
# A kid that failed to fetch is not fetched again for this long. The fetch
# is synchronous, so a stream of tokens with fresh fake kids -- which needs
# only the ARN and the public client id -- would otherwise stall every
# request behind a 5 s timeout each.
ALB_MISS_TTL_S = 300.0

# Identity-Aware Proxy signs `x-goog-iap-jwt-assertion` with ES256 and
# publishes its keys as a JWKS. The audience names the backend IAP protects,
# per cloud.google.com/iap/docs/signed-headers-howto.
IAP_ISSUER = "https://cloud.google.com/iap"
IAP_JWKS_URL = "https://www.gstatic.com/iap/verify/public_key-jwk"
_IAP_AUDIENCE = re.compile(
    r"^/projects/\d+/(global/backendServices/\d+"
    r"|locations/[a-z0-9-]+/services/[a-z0-9-]+)\Z")
# At most one key fetch per this many seconds, whatever triggered it. An
# unknown kid triggers a refetch, and the fetch is synchronous, so a stream
# of tokens with fresh fake kids would otherwise put gstatic on every request.
IAP_REFETCH_S = 60.0
# A JWKS is refetched for an unknown kid at most once per this many seconds.
JWKS_REFETCH_S = 60.0
# After a key fetch fails, the next may run this many seconds later, twice
# that after a second failure in a row, and so on up to the platform's
# refetch interval. A fetch that succeeds restores that interval.
JWKS_RETRY_S = 1.0
# Key fetches in flight at once, across every platform. A fetch that finds
# every slot taken is refused rather than queued.
KEY_FETCHES_MAX = 2
KEY_FETCH_TIMEOUT_S = 5.0
IAP_JWKS_MAX_BYTES = 64 * 1024
IAP_FETCH_TIMEOUT_S = 5


LEGACY_REQUIRE_PRINCIPAL = (
    "require_principal (FORGD_DASHBOARD_REQUIRE_PRINCIPAL, --require-principal, "
    "dashboard.require_principal) is refused: it trusted any "
    "x-ms-client-principal-name value with no attestation that a proxy strips "
    "inbound copies. Configure dashboard.auth with mode: trusted_header, header "
    "and stripped_by (or mode: oidc_jwt), and remove require_principal."
)


def refuse_require_principal() -> None:
    raise ValueError(LEGACY_REQUIRE_PRINCIPAL)


class AuthError(Exception):
    """The request is not authenticated. Never carries token contents."""


@dataclass(frozen=True)
class Issuer:
    """One identity provider this dashboard accepts tokens from."""

    issuer: str
    jwks_url: str
    audience: tuple[str, ...]
    # Providers name the claim differently -- Entra `groups`, Auth0 a
    # namespaced one -- so two of them cannot share a single setting.
    groups_claim: str = "groups"


@dataclass
class AuthConfig:
    mode: str = MODE_NONE
    header: str = "x-ms-client-principal-name"
    # Who strips inbound copies of `header`. Required for trusted_header,
    # because the mode is identity forgery anywhere the container is
    # directly reachable -- any nonempty header value becomes an
    # authenticated principal, with no validation.
    #
    # The Helm chart already refuses the mode without this attestation.
    # Terraform has none, and neither did the app, so the guard held only
    # on one of the three ways to deploy. Here it holds on all of them.
    stripped_by: str = ""
    jwks_url: str = ""
    issuer: str = ""
    audience: str = ""
    # Which claim carries group membership. Entra ID uses `groups`; other
    # providers use `roles` or a namespaced claim, so it is configurable
    # rather than guessed.
    groups_claim: str = "groups"
    # Every accepted issuer, the single fields above included. More than one
    # for a deployment fronted by two IdPs, or migrating between them.
    issuers: tuple[Issuer, ...] = ()
    platform: str = ""
    # alb_oidc only: the load balancer the token must be signed by.
    alb_arn: str = ""
    _jwks: dict[str, Any] = field(default_factory=dict, repr=False)
    _alb_keys: OrderedDict = field(default_factory=OrderedDict, repr=False)
    _alb_misses: OrderedDict = field(default_factory=OrderedDict, repr=False)
    _iap_keys: dict[str, Any] = field(default_factory=dict, repr=False)
    _iap_fetched: float = field(default=-math.inf, repr=False)
    _iap_gate: FetchGate = field(default_factory=lambda: FetchGate(lambda: IAP_REFETCH_S),
                                 repr=False)
    _fetch_slots: threading.BoundedSemaphore = field(
        default_factory=lambda: threading.BoundedSemaphore(KEY_FETCHES_MAX), repr=False)
    _cache_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def parse(cls, raw: dict[str, Any] | None) -> AuthConfig:
        raw = raw or {}
        mode = str(raw.get("mode", MODE_NONE)).strip() or MODE_NONE
        if mode not in MODES:
            raise ValueError(f"dashboard.auth.mode must be one of {MODES}, got {mode!r}")
        platform = str(env_or_literal(str(raw.get("platform", "") or "")) or "")
        # Resolved before the platform is consulted. The shipped policy sets
        # `header: $FORGD_DASHBOARD_HEADER`, and read raw that placeholder is
        # a non-empty header, so a platform chosen by the chart was ignored
        # and the default EasyAuth header name was used instead.
        header = str(env_or_literal(str(raw.get("header", "") or "")) or "")
        if platform and mode != MODE_OIDC_JWT:
            # A platform names a proxy that hands over a TOKEN, and choosing
            # it chooses which header is trusted. Under trusted_header that
            # swapped the header the stripped_by attestation was about for
            # one nobody had checked: `platform: oauth2_proxy` trusted any
            # `Authorization` value as a signed-in name.
            raise ValueError(
                f"dashboard.auth.platform is only for {MODE_OIDC_JWT}; under "
                f"{mode} set `header` to the one your proxy strips")
        if not header and platform:
            if platform not in PLATFORM_HEADERS:
                raise ValueError(
                    f"dashboard.auth.platform must be one of "
                    f"{tuple(PLATFORM_HEADERS)}, got {platform!r}"
                )
            header = PLATFORM_HEADERS[platform]
        # Through env_or_literal, like every other deployment-specific
        # value in the policy -- the org id, the API key, the OTel tokens.
        # These three were read as literals, which meant an oidc_jwt
        # deployment had to commit its tenant and application ids to
        # policy.yaml, and a fork could not point the same policy at its own
        # identity provider without editing it.
        cfg = cls(
            mode=mode,
            header=(header or cls.header).lower(),
            jwks_url=str(env_or_literal(str(raw.get("jwks_url", "") or "")) or ""),
            issuer=str(env_or_literal(str(raw.get("issuer", "") or "")) or ""),
            audience=" ".join(_audiences(raw.get("audience"))),
            groups_claim=str(raw.get("groups_claim", "") or "groups"),
            # env_or_literal, or an unresolved `$FORGD_DASHBOARD_STRIPPED_BY`
            # is a non-empty string and attests to nothing.
            stripped_by=str(
                env_or_literal(str(raw.get("stripped_by", "") or "")) or ""),
            platform=platform,
            alb_arn=str(env_or_literal(str(raw.get("alb_arn", "") or "")) or ""),
        )
        if mode == MODE_TRUSTED_HEADER and not cfg.stripped_by:
            # The same attestation the Helm chart already demands. Any
            # nonempty value of `header` becomes an authenticated
            # principal with no validation, so the mode is an
            # authentication check only where something in front strips
            # inbound copies of that header.
            #
            # Helm refused this and Terraform did not, so the guard held
            # on one of the three ways to deploy. Naming the proxy records
            # the claim next to the deployment that depends on it.
            raise ValueError(
                f"dashboard.auth.mode is {MODE_TRUSTED_HEADER} but "
                "stripped_by is not set. Name the proxy you have CHECKED "
                f"strips inbound copies of {cfg.header!r}; without one, any "
                "caller who can reach the container sets that header "
                "themselves and this is no check at all."
            )
        if mode == MODE_OIDC_JWT:
            # Both verifiers need `cryptography`, which comes with PyJWT in
            # the `dashboard` extra. Checked here for both, or the ALB path
            # started cleanly and answered its first request with a 500.
            try:
                import cryptography  # noqa: F401, PLC0415
                import jwt  # noqa: F401, PLC0415
            except ImportError as exc:
                raise ValueError(
                    f"dashboard.auth.mode is {MODE_OIDC_JWT} but PyJWT is "
                    "not installed: pip install 'forgd-verdict[dashboard]'"
                ) from exc
        if mode == MODE_OIDC_JWT and platform == "alb_oidc":
            _check_alb(cfg, raw)
        elif mode == MODE_OIDC_JWT and platform == "iap":
            _check_iap(cfg, raw)
        elif mode == MODE_OIDC_JWT:
            cfg.issuers = _issuers(raw, cfg)
            if not cfg.issuers:
                missing = [
                    k for k in ("jwks_url", "issuer", "audience") if not getattr(cfg, k)
                ]
                # Refuse at startup. A JWT mode missing its audience would
                # accept tokens minted for a different application.
                raise ValueError(
                    f"dashboard.auth.mode is {MODE_OIDC_JWT} but "
                    f"{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} "
                    "not set"
                )
            # And the library, here, beside the other three checks.
            #
            # `_keys()` carries a helpful guarded import, but the bare
            # `import jwt` in `authenticate` runs first and `_keys()` is
            # never reached -- so startup SUCCEEDED with mode oidc_jwt and
            # the first protected request raised ImportError out of the
            # ASGI app. `dashboard/app.py` catches only AuthError, so
            # uvicorn answered 500: an auth control that is selected,
            # reported as active, and cannot run.
            try:
                import jwt  # noqa: F401, PLC0415
            except ImportError as exc:
                raise ValueError(
                    f"dashboard.auth.mode is {MODE_OIDC_JWT} but PyJWT is "
                    "not installed: pip install 'forgd-verdict[dashboard]'"
                ) from exc
        return cfg

    # -- verification -----------------------------------------------------

    def _keys(self, jwks_url: str = "") -> Any:
        jwks_url = jwks_url or self.jwks_url
        try:
            import jwt  # noqa: F401  (import here so `none` needs no crypto)
        except ImportError as exc:  # pragma: no cover - depends on the extra
            raise AuthError(
                "oidc_jwt needs PyJWT: install forgd-verdict[dashboard]"
            ) from exc
        with self._cache_lock:
            client = self._jwks.get(jwks_url)
            if client is None:
                client = self._jwks[jwks_url] = GatedJWKS(jwks_url, self._fetch_slot)
        return client

    def _fetch_slot(self) -> _Slot:
        """One of KEY_FETCHES_MAX fetch slots, or AuthError when none is free."""
        if not self._fetch_slots.acquire(blocking=False):
            raise AuthError("token rejected: key fetch busy")
        return _Slot(self._fetch_slots)

    def authenticate(self, headers: dict[str, str]) -> Principal | None:
        """Return the caller, or raise AuthError.

        `None` means the mode does not identify anyone, not that the request
        failed.
        """
        if self.mode == MODE_NONE:
            return None

        raw = headers.get(self.header, "")
        if not raw:
            raise AuthError("missing credential")

        if self.mode == MODE_TRUSTED_HEADER:
            # No claims: the header carries a name and nothing else.
            return Principal(name=raw)

        token = raw.split(" ", 1)[1] if raw.lower().startswith("bearer ") else raw
        if self.platform == "alb_oidc":
            return self._verify_alb(token)
        if self.platform == "iap":
            return self._verify_iap(token)
        import jwt  # noqa: PLC0415 - guarded by AuthConfig.parse

        try:
            # The issuer picks which keys to verify against, and nothing
            # else: read unverified, it is only a claim, and the signature
            # against THAT issuer's JWKS still decides. A token naming an
            # issuer that is not configured is refused before any fetch.
            claimed = jwt.decode(token, options={"verify_signature": False}).get("iss")
            accepted = next((i for i in self.issuers if i.issuer == claimed), None)
            if accepted is None:
                raise AuthError("token rejected: issuer not accepted")
            signing_key = self._keys(accepted.jwks_url).get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(ALGORITHMS),
                audience=list(accepted.audience),
                issuer=accepted.issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
            _times_in_range(claims)
        except AuthError:
            raise
        except Exception as exc:  # noqa: BLE001 - PyJWT raises a family
            # The reason is logged, never returned: a verification oracle
            # tells an attacker which part of their forgery to fix.
            raise AuthError(f"token rejected: {type(exc).__name__}") from exc
        name = str(
            claims.get("preferred_username")
            or claims.get("email")
            or claims.get("sub")
            or "unknown"
        )
        claim = accepted.groups_claim
        groups = _group_claims(claims, claim)
        names = claims.get("_claim_names")
        # Entra's two overage signals: `_claim_names` in an ID token, and
        # `hasgroups: true` from the implicit flow. Either marks the groups
        # incomplete, whatever groups the token also lists.
        incomplete = ((isinstance(names, dict) and claim in names)
                      or claims.get("hasgroups") is True)
        return Principal(name=name, groups=groups, groups_incomplete=incomplete,
                         issuer=accepted.issuer, subject=_subject(claims))

    def _alb_key(self, region: str, kid: str) -> Any:
        """One ALB signing key, by kid, cached. Bounded: the kid comes from
        the token, and an unbounded cache would grow by one entry per
        forged kid -- though a kid that is not a real key fails the fetch
        and is not cached.

        A kid whose fetch failed is not fetched again for ALB_MISS_TTL_S,
        or for JWKS_RETRY_S when the fetch did not get an answer from the
        endpoint (`_unanswered`)."""
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        with self._cache_lock:
            key = self._alb_keys.get(kid)
            if key is not None:
                self._alb_keys.move_to_end(kid)
                return key
            until = self._alb_misses.get(kid)
            if until is not None and time.time() < until:
                raise AuthError("token rejected: unknown kid")
        try:
            with self._fetch_slot(), urlopen(  # noqa: S310
                    ALB_KEY_URL.format(region=region, kid=kid),
                    timeout=KEY_FETCH_TIMEOUT_S) as r:
                key = load_pem_public_key(r.read())
        except AuthError:
            raise
        except Exception as exc:
            wait = JWKS_RETRY_S if _unanswered(exc) else ALB_MISS_TTL_S
            with self._cache_lock:
                self._alb_misses.pop(kid, None)
                self._alb_misses[kid] = time.time() + wait
                while len(self._alb_misses) > ALB_KEYS_MAX * 16:
                    self._alb_misses.popitem(last=False)
            raise
        with self._cache_lock:
            self._alb_keys[kid] = key
            while len(self._alb_keys) > ALB_KEYS_MAX:
                self._alb_keys.popitem(last=False)
        return key

    def _verify_alb(self, token: str) -> Principal:
        """Verify an ALB token by hand.

        Not through PyJWT: ALB's segments carry base64 padding and it signs
        the padded form, and PyJWT 2.14 refuses padding ("Invalid header
        padding") -- so every real login would have been a 401. Stripping
        it is not an option either, because that changes the bytes the
        signature covers. The signature is checked over the token exactly
        as received, ES256 only, and nothing is read from the payload
        before it passes.
        """
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        accepted = self.issuers[0]
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise AuthError("token rejected: shape")
            header = json.loads(_b64(parts[0]))
            if not isinstance(header, dict):
                raise AuthError("token rejected: header")
            # Checked before any fetch. `signer` names the load balancer;
            # without it, any ALB in any account could mint a token this
            # accepted, since its keys are served from the same public URL.
            if header.get("alg") != "ES256" or header.get("signer") != self.alb_arn:
                raise AuthError("token rejected: signer not accepted")
            if header.get("client") not in accepted.audience:
                raise AuthError("token rejected: client not accepted")
            kid = header.get("kid")
            if not isinstance(kid, str) or not _ALB_KID.match(kid):
                raise AuthError("token rejected: kid")
            sig = _b64(parts[2])
            if len(sig) != 64:
                raise AuthError("token rejected: signature length")
            region = _ALB_ARN.match(self.alb_arn).group(1)
            key = self._alb_key(region, kid)
            if not isinstance(key, ec.EllipticCurvePublicKey) \
                    or not isinstance(key.curve, ec.SECP256R1):
                raise AuthError("token rejected: key type")
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                       int.from_bytes(sig[32:], "big"))
            key.verify(der, f"{parts[0]}.{parts[1]}".encode("ascii"),
                       ec.ECDSA(hashes.SHA256()))
            claims = json.loads(_b64(parts[1]))
            if not isinstance(claims, dict):
                raise AuthError("token rejected: claims")
            now = time.time()
            # ALB puts `exp` and `iss` in the signed HEADER; the payload is
            # the IdP's user-info claims, which may or may not repeat them.
            # Both halves are covered by the signature, so each is read from
            # wherever it appears, at least one copy is required, and every
            # copy present must pass.
            exps = [d["exp"] for d in (header, claims) if "exp" in d]
            if not exps or not all(_timestamp(e) and e > now for e in exps):
                raise AuthError("token rejected: expired")
            nbf = claims.get("nbf")
            if nbf is not None and (not _timestamp(nbf) or nbf > now):
                raise AuthError("token rejected: not yet valid")
            issuers = [d["iss"] for d in (header, claims) if "iss" in d]
            if not issuers or any(i != accepted.issuer for i in issuers):
                raise AuthError("token rejected: issuer")
        except AuthError:
            raise
        except (InvalidSignature, Exception) as exc:  # noqa: BLE001 - urllib, json, crypto
            raise AuthError(f"token rejected: {type(exc).__name__}") from exc
        name = str(claims.get("email") or claims.get("preferred_username")
                   or claims.get("sub") or "unknown")
        return Principal(name=name, groups=_group_claims(claims, accepted.groups_claim),
                         issuer=accepted.issuer, subject=_subject(claims))

    def _iap_key(self, kid: str) -> Any:
        """One IAP signing key, by kid, from a cached JWKS.

        Refetched when the cache is older than JWKS_TTL_S or the kid is not
        in it, but never more than once per IAP_REFETCH_S, or sooner after
        a failed fetch (`FetchGate`). Keys past their TTL are not used.
        """
        now = time.time()
        with self._cache_lock:
            fresh = now - self._iap_fetched < JWKS_TTL_S
            if fresh and kid in self._iap_keys:
                return self._iap_keys[kid]
            if not self._iap_gate.ready(now):
                raise AuthError("token rejected: unknown kid")
            self._iap_gate.start(now)
        try:
            slot = self._fetch_slot()
        except AuthError:
            with self._cache_lock:
                self._iap_gate.not_made()
            raise
        try:
            with slot, urlopen(  # noqa: S310
                    IAP_JWKS_URL, timeout=IAP_FETCH_TIMEOUT_S) as r:
                body = r.read(IAP_JWKS_MAX_BYTES + 1)
            if len(body) > IAP_JWKS_MAX_BYTES:
                raise AuthError("token rejected: key set too large")
            keys = _iap_keys(body)
        except BaseException:
            with self._cache_lock:
                self._iap_gate.failed()
            raise
        with self._cache_lock:
            self._iap_keys, self._iap_fetched = keys, now
            self._iap_gate.succeeded()
        if kid not in keys:
            raise AuthError("token rejected: unknown kid")
        return keys[kid]

    def _verify_iap(self, token: str) -> Principal:
        """Verify an Identity-Aware Proxy assertion.

        ES256 only, `iss` exactly IAP's, `aud` the configured backend, and
        `exp` and `iat` required. The header's `alg` and `kid` are checked
        before any key fetch. IAP asserts who signed in and nothing about
        their groups, so the principal is marked `groups_incomplete`.
        """
        import jwt  # noqa: PLC0415 - guarded by AuthConfig.parse

        accepted = self.issuers[0]
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "ES256":
                raise AuthError("token rejected: alg")
            kid = header.get("kid")
            if not isinstance(kid, str) or not _ALB_KID.match(kid):
                raise AuthError("token rejected: kid")
            # PyJWT refuses an ES256 key on any curve but P-256.
            claims = jwt.decode(
                token,
                self._iap_key(kid),
                algorithms=["ES256"],
                audience=list(accepted.audience),
                issuer=IAP_ISSUER,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "email"]},
            )
            _times_in_range(claims)
            email, sub = claims.get("email"), claims.get("sub")
            if not (isinstance(email, str) and email and isinstance(sub, str) and sub):
                raise AuthError("token rejected: identity")
        except AuthError:
            raise
        except Exception as exc:  # noqa: BLE001 - urllib, json, PyJWT
            raise AuthError(f"token rejected: {type(exc).__name__}") from exc
        return Principal(name=email, groups_incomplete=True, issuer=IAP_ISSUER,
                         subject=sub)

    def describe(self) -> dict[str, Any]:
        out: dict[str, Any] = {"mode": self.mode}
        if self.mode != MODE_NONE:
            out["header"] = self.header
        if self.mode == MODE_OIDC_JWT and self.issuers:
            first = self.issuers[0]
            out["issuer"] = shown_url(first.issuer)
            out["audience"] = " ".join(first.audience)
            if len(self.issuers) > 1:
                out["issuers"] = [{"issuer": shown_url(i.issuer), "audience": list(i.audience)}
                                  for i in self.issuers]
        return out


class _Slot:
    """Releases a fetch slot on exit."""

    def __init__(self, semaphore: threading.BoundedSemaphore) -> None:
        self._semaphore = semaphore

    def __enter__(self) -> _Slot:
        return self

    def __exit__(self, *exc: object) -> None:
        self._semaphore.release()


def _iap_keys(body: bytes) -> dict[str, Any]:
    """`{kid: key}` for each ES256 key in an IAP JWKS body, at most
    ALB_KEYS_MAX of them. A key PyJWK cannot parse is skipped, so one bad
    entry in the set does not refuse every login."""
    import jwt  # noqa: PLC0415 - guarded by AuthConfig.parse

    keys: dict[str, Any] = {}
    for jwk in json.loads(body).get("keys") or []:
        if not isinstance(jwk, dict) or jwk.get("kty") != "EC" \
                or jwk.get("alg", "ES256") != "ES256" \
                or not isinstance(jwk.get("kid"), str):
            continue
        try:
            keys[jwk["kid"]] = jwt.PyJWK(jwk, algorithm="ES256").key
        except (jwt.PyJWKError, jwt.InvalidKeyError, ValueError, TypeError):
            continue
        if len(keys) >= ALB_KEYS_MAX:
            break
    return keys


def _unanswered(exc: BaseException) -> bool:
    """Whether a key fetch failed without an answer from the endpoint: a
    connection or timeout error, or an HTTP 429 or 5xx."""
    from http.client import HTTPException
    from urllib.error import HTTPError

    if isinstance(exc, HTTPError):
        return exc.code == 429 or exc.code >= 500
    return isinstance(exc, OSError | HTTPException)


class FetchGate:
    """When the next key fetch may start: `interval()` seconds after one
    that succeeded, and after a failure JWKS_RETRY_S, doubled for each
    failure in a row, up to `interval()`. Not thread-safe; callers hold
    their own lock."""

    def __init__(self, interval: Callable[[], float]) -> None:
        self._interval = interval
        self._started = -math.inf
        self._failures = 0

    def ready(self, now: float) -> bool:
        wait = self._interval()
        if self._failures:
            wait = min(JWKS_RETRY_S * 2 ** (self._failures - 1), wait)
        return now - self._started >= wait

    def start(self, now: float) -> None:
        self._started = now

    def succeeded(self) -> None:
        self._failures = 0

    def failed(self) -> None:
        self._failures += 1

    def not_made(self) -> None:
        """The fetch did not reach the endpoint, as when no fetch slot was
        free: the next request may try at once."""
        self._started = -math.inf


def _parse_jwk_set(data: Any) -> Any:
    """`data` as a PyJWKSet. PyJWT 2.15 parses what it caches; earlier
    versions store the raw document, so the parse happens here for both."""
    from jwt import PyJWKSet  # noqa: PLC0415 - guarded by AuthConfig.parse

    return data if isinstance(data, PyJWKSet) else PyJWKSet.from_dict(data)


class GatedJWKS:
    """One issuer's JWKS, fetched through a fetch slot.

    Fetched when the cache is cold or older than JWKS_TTL_S, and for a kid
    not in the cache at most once per JWKS_REFETCH_S, or sooner after a
    failed fetch (`FetchGate`). A request arriving while a fetch is in
    flight waits for it, up to KEY_FETCH_TIMEOUT_S, and then reads the
    cache.
    """

    def __init__(self, url: str, slot: Any) -> None:
        from jwt import PyJWKClient

        self._client = PyJWKClient(url, cache_keys=False, lifespan=JWKS_TTL_S,
                                   timeout=KEY_FETCH_TIMEOUT_S, cooldown_duration=0)
        self._slot = slot
        self._lock = threading.Lock()
        self._gate = FetchGate(lambda: JWKS_REFETCH_S)
        self._inflight: threading.Event | None = None

    def get_signing_key_from_jwt(self, token: str) -> Any:
        import jwt  # noqa: PLC0415 - guarded by AuthConfig.parse

        kid = jwt.get_unverified_header(token).get("kid")
        key = self._cached(kid)
        if key is not None:
            return key
        self._fetch()
        key = self._cached(kid)
        if key is None:
            raise AuthError("token rejected: unknown kid")
        return key

    def _cached(self, kid: Any) -> Any:
        cache = self._client.jwk_set_cache
        jwk_set = cache.get() if cache is not None else None
        if jwk_set is None or not kid:
            return None
        if isinstance(jwk_set, dict):
            # PyJWT before 2.15 caches the raw JWKS document, not a PyJWKSet.
            jwk_set = _parse_jwk_set(jwk_set)
        return next((k for k in jwk_set.keys
                     if k.key_id == kid and k.public_key_use in ("sig", None)), None)

    def _fetch(self) -> None:
        with self._lock:
            inflight = self._inflight
            if inflight is None:
                now = time.monotonic()
                if not self._gate.ready(now):
                    raise AuthError("token rejected: unknown kid")
                self._gate.start(now)
                inflight = self._inflight = threading.Event()
                mine = True
            else:
                mine = False
        if not mine:
            inflight.wait(KEY_FETCH_TIMEOUT_S)
            return
        try:
            with self._slot():
                data = self._client.fetch_data()
            if self._client.jwk_set_cache is not None:
                self._client.jwk_set_cache.put(_parse_jwk_set(data))
        except AuthError:
            with self._lock:
                self._gate.not_made()
            raise
        except BaseException:
            with self._lock:
                self._gate.failed()
            raise
        else:
            with self._lock:
                self._gate.succeeded()
        finally:
            with self._lock:
                self._inflight = None
            inflight.set()


def _subject(claims: dict[str, Any]) -> str:
    sub = claims.get("sub")
    return sub if isinstance(sub, str) else ""


def _audiences(value: Any) -> tuple[str, ...]:
    values = value if isinstance(value, list) else [value]
    return tuple(a for a in (str(env_or_literal(str(v or "")) or "") for v in values) if a)


def _issuers(raw: dict[str, Any], cfg: AuthConfig) -> tuple[Issuer, ...]:
    """The single `issuer`/`jwks_url`/`audience` plus any `issuers` list.

    An entry missing any of the three refuses to start, for the reason the
    single form does: without an audience, a token minted for another
    application of the same IdP is accepted.
    """
    out: list[Issuer] = []
    if cfg.issuer or cfg.jwks_url or cfg.audience:
        if not (cfg.issuer and cfg.jwks_url and cfg.audience):
            if raw.get("issuers"):
                missing = [k for k in ("issuer", "jwks_url", "audience") if not getattr(cfg, k)]
                raise ValueError(
                    "dashboard.auth: the single issuer form is partly set (missing "
                    f"{', '.join(missing)}) beside an `issuers` list; complete it or "
                    "clear it, so it is not silently ignored")
            return ()
        out.append(Issuer(cfg.issuer, cfg.jwks_url, _audiences(raw.get("audience")),
                          cfg.groups_claim))
    for n, entry in enumerate(raw.get("issuers") or []):
        entry = entry if isinstance(entry, dict) else {}
        iss = str(env_or_literal(str(entry.get("issuer", "") or "")) or "")
        url = str(env_or_literal(str(entry.get("jwks_url", "") or "")) or "")
        aud = _audiences(entry.get("audience"))
        if not (iss and url and aud):
            raise ValueError(f"dashboard.auth.issuers[{n}] needs issuer, jwks_url and "
                             "audience; without an audience a token minted for another "
                             "application would be accepted")
        out.append(Issuer(iss, url, aud,
                          str(entry.get("groups_claim", "") or cfg.groups_claim)))
    if len({i.issuer for i in out}) != len(out):
        raise ValueError("dashboard.auth: the same issuer is configured twice")
    for issuer in out:
        refused = cleartext_refusal(issuer.jwks_url)
        if refused:
            raise ValueError(
                f"dashboard.auth jwks_url {shown_url(issuer.jwks_url)!r} is refused: "
                f"{refused}. Tokens are verified against the keys it serves.")
    return tuple(out)


# 9999-12-31T23:59:59Z.
_MAX_EPOCH = 253402300799


def _timestamp(value: Any) -> bool:
    """A number of seconds from the epoch to the end of year 9999, and not a
    bool, which is an int in Python. The range is tested before `isfinite`:
    JSON integers have no size limit, and `isfinite` raises OverflowError
    on an int too large for a float."""
    return (isinstance(value, int | float) and not isinstance(value, bool)
            and 0 <= value <= _MAX_EPOCH and math.isfinite(value))


def _times_in_range(claims: dict) -> None:
    """AuthError unless each of `exp`, `nbf` and `iat` present is a
    `_timestamp`. PyJWT accepts an `exp` of 10**400."""
    if not all(_timestamp(claims[k]) for k in ("exp", "nbf", "iat") if k in claims):
        raise AuthError("token rejected: time claim")


def _b64(segment: str) -> bytes:
    """base64url, padded or not. Strict about the alphabet."""
    import base64
    import binascii

    try:
        # validate=True: the default silently drops characters outside the
        # alphabet, so two different strings would decode to one value.
        return base64.b64decode(segment + "=" * (-len(segment) % 4),
                                altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuthError("token rejected: encoding") from exc


def _check_alb(cfg: AuthConfig, raw: dict[str, Any]) -> None:
    """alb_oidc needs the load balancer's ARN, the IdP's issuer, and the
    client id, which stands in for the audience ALB tokens do not carry."""
    missing = [k for k in ("alb_arn", "issuer", "audience") if not getattr(cfg, k)]
    if missing:
        raise ValueError(
            f"dashboard.auth.platform is alb_oidc but {', '.join(missing)} "
            f"{'is' if len(missing) == 1 else 'are'} not set. ALB tokens carry no "
            "audience; `alb_arn` names the load balancer that must have signed "
            "them and `audience` the IdP client id in their `client` header")
    if not _ALB_ARN.match(cfg.alb_arn):
        raise ValueError("dashboard.auth.alb_arn is not an application load balancer ARN "
                         "in the commercial partition (arn:aws:); GovCloud and China "
                         "publish ALB keys elsewhere and are not supported")
    if raw.get("issuers"):
        raise ValueError("dashboard.auth.issuers is not supported with alb_oidc: "
                         "the load balancer fronts one identity provider")
    cfg.issuers = (Issuer(cfg.issuer, "", _audiences(raw.get("audience")),
                          cfg.groups_claim),)


def _check_iap(cfg: AuthConfig, raw: dict[str, Any]) -> None:
    """iap needs the audience of the backend IAP protects. Without one, a
    token IAP minted for any app in any project would verify: they share an
    issuer and a key set. Issuer and keys are IAP's and not configurable."""
    audiences = _audiences(raw.get("audience"))
    if not audiences:
        raise ValueError(
            "dashboard.auth.platform is iap but audience is not set. Set it to "
            "the backend IAP protects: /projects/NUMBER/global/backendServices/ID "
            "behind a load balancer, or /projects/NUMBER/locations/REGION/services/"
            "NAME for IAP on Cloud Run. Without it, a token for any IAP-protected "
            "app would be accepted")
    bad = [a for a in audiences if not _IAP_AUDIENCE.match(a)]
    if bad:
        raise ValueError(
            f"dashboard.auth.audience {bad[0]!r} is not an IAP audience; expected "
            "/projects/NUMBER/global/backendServices/ID or "
            "/projects/NUMBER/locations/REGION/services/NAME")
    if raw.get("issuers"):
        raise ValueError("dashboard.auth.issuers is not supported with iap: "
                         "IAP is the only issuer")
    if cfg.issuer not in ("", IAP_ISSUER) or cfg.jwks_url not in ("", IAP_JWKS_URL):
        raise ValueError(
            f"dashboard.auth.platform is iap, which verifies against {IAP_ISSUER} "
            f"and {IAP_JWKS_URL}; clear issuer and jwks_url rather than set others")
    cfg.issuers = (Issuer(IAP_ISSUER, IAP_JWKS_URL, audiences, cfg.groups_claim),)


def fetch_jwks(url: str) -> dict:  # pragma: no cover - network
    """Only used by the config check in the CLI."""
    with urlopen(url, timeout=10) as response:  # noqa: S310 - operator-supplied
        return json.loads(response.read())


def _group_claims(claims: dict[str, Any], key: str) -> tuple[str, ...]:
    """Read a group claim that may be a list, a string, or absent.

    Providers disagree: Entra ID sends a list of object ids, some send a
    single string, some send a space-separated one. Reading all three is
    cheaper than an operator discovering that their claim shape silently
    entitles nobody.
    """
    value = claims.get(key)
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(v for v in value.replace(",", " ").split() if v)
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value if v)
    return ()
