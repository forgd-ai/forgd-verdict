# The findings connector: design note

This is a design note: what the sources say about Claude's custom
connectors, the MCP protocol and the SDK, and how the connector's design
follows from them. To deploy and run the connector, see the
[operator guide](../CONNECTOR.md).

## Findings from the sources

The current MCP revision is 2026-07-28. Claude documents its OAuth
client against the authorization specs of 2025-03-26, 2025-06-18 and
2025-11-25, and its rollout of 2026-07-28 is in progress with no date given.
The connector is built to 2025-11-25 semantics. SDK v2 serves both
generations from one app.

### 1. Transport

Streamable HTTP. Claude also still accepts the legacy HTTP+SSE transport,
which the spec deprecated in 2025-03-26 and says new implementations SHOULD
NOT adopt. The connector serves Streamable HTTP only.

- "Use Streamable HTTP, which the MCP specification defines for remote
  servers. Claude also supports the legacy HTTP+SSE transport, which is
  being deprecated in favor of Streamable HTTP."
  <https://claude.com/docs/connectors/building>
- <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http>

Endpoint shape: one path, `/mcp`. Under 2025-11-25 that path takes POST,
may take a GET for a server-to-client SSE stream, and may use an
`Mcp-Session-Id` header. Under 2026-07-28 it is POST only, GET and DELETE
answer 405, and protocol-level sessions are gone. The connector runs the SDK
with `stateless_http=True` and `json_response=True`, because it has nothing
to push to the client and keeps no session. That also avoids the SDK's
in-process session dict for pre-2026 clients, which does not survive a
restart and is not shared across replicas
(<https://py.sdk.modelcontextprotocol.io/run/legacy-clients/>).

The spec requires the server to validate `Origin`. Claude's testing page
lists an overly strict check as a cause of failure
(<https://claude.com/docs/connectors/building/testing>). The connector
refuses a request whose `Origin` is present and is not an allowed origin,
and accepts a request with no `Origin` header. **UNCONFIRMED**: which
`Origin`, if any, Claude's backend sends.

### 2. Auth

The spec requires the following, in wording that 2025-11-25 and 2026-07-28
share (<https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>):

- OAuth 2.1 at the authorization server.
- RFC 9728 protected resource metadata at the MCP server, with an
  `authorization_servers` entry, found through `WWW-Authenticate:
  resource_metadata` on a 401 or at `/.well-known/oauth-protected-resource`.
- RFC 8414 or OpenID Connect Discovery at the authorization server.
- RFC 8707 `resource` on authorization and token requests.
- PKCE with S256.

Claude's client is stricter in these places
(<https://claude.com/docs/connectors/building/authentication>):

- Sign-in starts only on a 401. A `WWW-Authenticate` on a 200 is
  ignored.
- Only the first `authorization_servers` entry is used.
- The PRM `resource` must equal the URL the user enters, path included.
- Scopes come from `scope` in `WWW-Authenticate`, otherwise from the PRM's
  `scopes_supported`. `offline_access` is appended if the authorization
  server lists it.
- Discovery and token endpoints get 10 s to answer, refresh gets 30 s.
- The token endpoint must accept form-urlencoded bodies.
- A `client_credentials` grant is not supported.

**Client registration.** DCR is not required. Claude identifies itself with
a Client ID Metadata Document, with DCR, or with a client you
registered and enter in the dialog: "Claude identifies itself to your
authorization server in one of three ways: with the Client ID Metadata
Document that Anthropic hosts for it, through Dynamic Client Registration,
or with an OAuth client ID the customer registered with you and enters in
the dialog." The secret is optional, and needed only for a confidential
client. (<https://claude.com/docs/connectors/building/authentication>, and
the dialog: <https://claude.com/docs/connectors/custom/add-unlisted>.)
Authentication settings cannot be changed after the connector is added,
so a wrong client means removing it and adding it again.

**Callback URL.** `https://claude.ai/api/mcp/auth_callback` for claude.ai,
Desktop, mobile and Cowork. Claude Code uses a loopback redirect,
`http://localhost:<port>/callback` and `http://127.0.0.1:<port>/callback`
on any port. (<https://claude.com/docs/connectors/building/authentication>)
**UNCONFIRMED**: a `https://claude.com/api/mcp/auth_callback` variant. No
current page lists one. Registering it as well would be a precaution the
docs do not ask for.

**The token Claude presents.** The access token the authorization server
issued, as `Authorization: Bearer`. Claude sends `resource` set to the
canonical MCP URL: lowercase scheme and host, no trailing slash, no default
port, no fragment. The server must check that the token was minted for it,
"or use whatever audience-binding mechanism your token format supports".
(<https://claude.com/docs/connectors/building/troubleshooting>) The spec
forbids accepting a token for another audience and forbids passing the
token on: "MCP servers MUST NOT accept or transit any other tokens."

### Static credentials are refused

Claude has a beta auth type, `static_headers`: an organization Owner enters
one API key or bearer token when adding the connector, and Claude sends it
on every call from anyone in that organization. Anthropic's own guidance is
to "treat it as the organization's credential, not a person's: every
member's requests carry the same key, so don't use it to identify which
user is calling"
(<https://claude.com/docs/connectors/building/authentication#static-credentials-in-request-headers>).

There is no principal behind such a key, so there is nothing for
`Entitlements.allowed` to decide on. With entitlements configured, every
member of the Claude organization would read every org's findings, or none.
The connector refuses it. No configuration accepts a static key. A static
key sent as `Authorization: Bearer` is not a JWT from a configured issuer,
so it fails verification with a 401
(`test_an_opaque_or_static_credential_is_a_401` in
`tests/test_connector_server.py`).

### 3. Your IdP as the authorization server

Supported. "The authorization server it names can be on a different host
from your MCP server"
(<https://claude.com/docs/connectors/building/authentication>), and the spec
says it "may be hosted with the resource server or a separate entity".
Claude's troubleshooting page names Okta and Entra as issuers that serve
only `/.well-known/openid-configuration`, which Claude falls back to after
RFC 8414 (<https://claude.com/docs/connectors/building/troubleshooting>).

So the connector is a resource server and nothing else. It serves PRM
naming the IdP's issuer and verifies the IdP's JWTs with the dashboard's
`oidc_jwt` verifier. It issues no tokens and holds no client secret.

**For an IdP without DCR or CIMD**, which covers Entra, the documented path
is a client you register. You create an app registration
with redirect URI `https://claude.ai/api/mcp/auth_callback` and enter its
client id, and its secret if the client is confidential, under Advanced
settings when adding the connector
(<https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp>).
**UNCONFIRMED**: a statement in Anthropic's or Microsoft's docs that Entra
has no DCR. The design does not depend on it, because the client you
enter works either way.

**Entra needs the MCP URL registered as an Application ID URI.** Otherwise
the token request fails with `AADSTS9010010`, because Claude sends the full
MCP URL as `resource` and the default `api://{client-id}` does not match. By
default Entra accepts that URI only on a domain the tenant has verified.
(<https://claude.com/docs/connectors/building/troubleshooting#microsoft-entra-id-rejects-the-resource-value>)
The consequence for deployment is that on Entra the connector needs a
custom hostname in a verified domain. An AKS public IP's
`<label>.<region>.cloudapp.azure.com` name will not do.

Further Entra points, none confirmed from a source:

- **UNCONFIRMED**: the `aud` of the access token Entra then issues. With
  v2 access tokens it is expected to be the API app's client id, and with
  v1 tokens the requested App ID URI. The connector's `audience` accepts a
  list, so a deployment lists both the canonical MCP URL and the API app's
  client id until a real tenant shows which one arrives.
- **UNCONFIRMED**: the `iss` also differs by token version, either
  `https://sts.windows.net/<tenant>/` or
  `https://login.microsoftonline.com/<tenant>/v2.0`. Claude reads discovery
  from the first `authorization_servers` entry, so that entry and the
  token's `iss` have to agree. The expected setting is
  `accessTokenAcceptedVersion: 2` on the API app.
- **UNCONFIRMED**: Entra's `scp` claim carries the short scope name,
  `findings.read`, while Claude must request the full name,
  `https://<host>/mcp/findings.read`. Hence the two separate keys,
  `scopes` and `required_scope`, under `connector:` below.
- **UNCONFIRMED**: whether `groupMembershipClaims` on the API app puts
  `groups` in the access token the way it does in the ID token, and
  whether Entra's discovery document advertises
  `code_challenge_methods_supported`. Claude's docs list Entra as a working
  issuer, which suggests the second one works in practice.

**Enterprise Managed Auth** (silent SSO with an RFC 7523 JWT-bearer grant)
needs the authorization server to support that grant
(<https://claude.com/docs/connectors/building/enterprise-managed-auth>). It
is a property of the IdP. The connector is unaffected either way and does
not rely on it.

### 4. Network

Claude calls the connector from Anthropic's cloud, not from the user's
device. "Your MCP server must be reachable over the public internet from
Anthropic's IP ranges."
(<https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp>)

- Egress range: **`160.79.104.0/21`**. It applies to MCP tool calls, and
  discovery requests to the IdP come from the same range.
  (<https://claude.com/docs/connectors/building/authentication>;
  <https://platform.claude.com/docs/en/api/ip-addresses>, "for example,
  when making MCP tool calls to external servers")
- IPv4 only. The hostname must resolve only to globally routable
  addresses; split-horizon DNS that returns a private address fails before
  any request leaves Anthropic.
  (<https://claude.com/docs/connectors/building/troubleshooting>)
- A redirect to another host drops `Authorization`, and a layer that
  rewrites `WWW-Authenticate` or answers 403 on `/.well-known/` breaks
  discovery. (same page)
- Claude Code connects from the user's machine, not from that range.
- The range has changed before: the same page lists five single
  addresses in `34.162.0.0/16` as phased out. An operator who sets a
  source allowlist owns keeping it current.

The connector therefore must be public, and must not sit behind EasyAuth,
IAP, oauth2-proxy, Cloudflare Access or any other platform sign-in. Any of
them answers Claude with a redirect or a 401 of its own, before the
connector can send the 401 that carries `resource_metadata`. **UNCONFIRMED**
as a quotation: no official page names SSO proxies specifically. It follows
from the three bullet points above and from the 401 requirement in §2.

For a deployment that cannot be public, Claude Enterprise offers MCP tunnels
as a research preview: "Your firewall needs no inbound rules and your MCP
servers need no public endpoint"
(<https://claude.com/docs/connectors/mcp-tunnels/overview>). They are out of
scope for this design.

### 5. Artifacts

An artifact can call connector tools itself, so a live artifact needs no
request to Claude to refresh it.

- "Artifacts can connect to the apps you've connected to Claude … They can
  also connect to any custom connectors you've set up."
- "Everyone connects their own apps, even when using a shared or published
  artifact."
- "Connector tools that need approval for each action aren't available to
  artifacts."
- "On Team and Enterprise plans, an owner can turn this off for your whole
  organization."

(<https://support.claude.com/en/articles/17153992-what-are-artifacts-and-how-do-i-use-them>;
announced Oct 21, 2025 at <https://claude.com/blog/build-artifacts>)

Two consequences:

- A shared coverage matrix queries with each viewer's own token, so
  `Entitlements.allowed` applies to the viewer and not to the author.
- An admin who sets the connector's tools to require approval on every
  call takes them away from artifacts. Every tool declares
  `readOnlyHint: true`. **UNCONFIRMED**: whether Claude uses that
  annotation to decide the default approval setting.

### 6. SDK

- Package: `mcp` (<https://pypi.org/project/mcp/>). `pyproject.toml`
  requires `mcp>=2.2,<3`, and the image installs `mcp==2.2.0` from
  `deploy/constraints/base.txt`. 2.0.0 shipped with spec 2026-07-28.
- Streamable HTTP since 1.8.0
  (<https://github.com/modelcontextprotocol/python-sdk/releases/tag/v1.8.0>).
  The resource-server split, with `TokenVerifier`,
  `AuthSettings.resource_server_url`, served PRM and RFC 8707, since 1.10.0
  (<https://github.com/modelcontextprotocol/python-sdk/releases/tag/v1.10.0>, PR #982).
- v2 renames `FastMCP` to `MCPServer` (`mcp.server.mcpserver`). It keeps
  `auth` and `token_verifier` unchanged, and moves `stateless_http` and
  `json_response` onto `streamable_http_app()` and `run()`
  (<https://py.sdk.modelcontextprotocol.io/migration/>).
- It is an ASGI app. `streamable_http_app()` returns a Starlette
  application that can be mounted, with the default path `/mcp`
  (<https://py.sdk.modelcontextprotocol.io/run/asgi/>). A mounted
  sub-application's lifespan does not run, so the host app has to enter
  `session_manager.run()` in its own lifespan.
- PRM is served at `/.well-known/oauth-protected-resource/{endpoint}`, and
  a 401 with `WWW-Authenticate` is sent for a missing or rejected token
  (<https://py.sdk.modelcontextprotocol.io/run/authorization/>).

The dependency is `mcp>=2.2,<3`, in the `connector` extra alongside
`uvicorn` and `PyJWT[crypto]`. v2 handles pre-2026 clients, which is what
Claude is today, and 2026-07-28 clients from the same app.

## Auth flow, end to end

Using Entra as the example; Okta differs only in the registrations.

**Once, by the IdP admin:**

1. Create an API app registration. Add Application ID URI
   `https://<connector-host>/mcp` on a verified domain. Expose scope
   `findings.read`. Set `accessTokenAcceptedVersion: 2`. Emit `groups`
   (or app roles) if entitlements are on.
2. Create a client app registration with redirect URI
   `https://claude.ai/api/mcp/auth_callback`. Grant it `findings.read` on
   the API app with admin consent. Create a secret if it is to be a
   confidential client.
3. In Claude, go to Organization settings > Connectors > Add custom
   connector, with URL `https://<connector-host>/mcp`. Under Advanced
   settings, enter the client id and the secret.

The client secret lives in Claude's connector settings and in Entra, and
nowhere in this deployment.

**Per user, on Connect:**

1. Claude sends `POST /mcp` with no token. The connector answers
   `401` with `WWW-Authenticate: Bearer
   resource_metadata="https://<connector-host>/.well-known/oauth-protected-resource/mcp",
   scope="<scopes>"`.
2. Claude fetches the PRM: `{"resource": "https://<connector-host>/mcp",
   "authorization_servers": ["<issuer>"], "scopes_supported": [...]}`.
3. Claude fetches `<issuer>/.well-known/openid-configuration` from Entra.
4. The user's browser runs an authorization code flow with PKCE S256 at
   Entra, with `resource=https://<connector-host>/mcp` and the configured
   scope. The redirect lands on `claude.ai/api/mcp/auth_callback`.
5. Anthropic's backend exchanges the code at Entra's token endpoint, with
   the client secret if one was entered. It holds the access token and the
   refresh token. The connector never sees the refresh token.

**Per tool call:**

1. Claude sends `POST /mcp` with `Authorization: Bearer <access token>`.
2. The connector verifies the token with `AuthConfig.authenticate`:
   issuer allowlisted, signature against that issuer's JWKS from the
   `ALGORITHMS` allowlist, `exp`, `iss`, and `aud` in the configured list.
   Any failure is a 401 whose reason is logged and never returned, as on
   the dashboard.
3. It then checks `required_scope` against `scp` or `scope`. The setting is
   required: the app and the chart refuse to start without it, because an
   ID token carries no scope, and with the check off any token whose
   audience matches would pass, including a dashboard token from the same
   app registration. A valid token without it is a 403 with `WWW-Authenticate: Bearer
   error="insufficient_scope", scope="<scopes>",
   resource_metadata="<metadata URL>"`, as the spec's scope challenge
   handling asks
   (<https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#runtime-insufficient-scope-errors>).
4. The resulting `Principal` goes through `Entitlements.allowed()` to give
   the set of orgs the caller may read, and the tool runs over that set.

## How the server is built

A top-level package, `forgd_verdict.connector`, in layer 4 of
`scripts/import_graph.py` beside `dashboard`. It imports `dashboard.auth`,
`dashboard.topology`, `store.query` and `store.views`, among others, all of
them the same layer or lower. Nothing in the package tree imports it.

It serves its own 401 and metadata rather than the SDK's
`RequireAuthMiddleware`, whose 401 carries no `scope` and whose scope
failure is a 403 without the challenge the spec asks for. The verified
token is still placed where the SDK's `get_access_token()` finds it.

**The caller is verified twice.** The SDK's token verifier calls the
dashboard's `AuthConfig.authenticate`, and each tool re-derives the
`Principal` from `get_access_token().token` through the same verifier,
whose JWKS is cached by then. The second verification costs a signature
check. The alternative, a side cache keyed by token, would be a second
place that decides who the caller is.

**One implementation of each number.** The tools compute from
`store/views.py` and `dashboard/topology.py`, the code the dashboard renders
from. The per-detector breakdown of values missed live is not offered: the
query layer does not compute it, and adding it in the connector would be a
second implementation of that count.

**Why the entitlement map is shared.** `dashboard.entitlements` is one map
for both surfaces: the same people, the same groups.
`Policy.entitlements()` validates it against an auth block, refusing
`none`, `trusted_header` and `iap` and requiring issuer-scoped entries with
more than one issuer: `dashboard.auth` for the dashboard, `connector.auth`
for the connector.

**Why there is no salt.** Like the dashboard, the connector runs without
`privacy.hash_salt`, so a compromised reader does not yield the key beside
the digests. It cannot hash a configured org id into the store's pseudonym,
so labels and entitlements come from the org registry the writers keep.

**Why 12 characters of digest.** The full 64-character digest would also be
skipped by the entropy detector, as a hex digest of exact length, but the
prefix puts less into the conversation.

**The connector holds no secret.** No `connector.*` path is on
`SECRET_PATHS`; a change that gives it a credential adds the path there in
the same change.

## UNCONFIRMED, collected

The connector has not been run against a real Claude organization or a
real identity provider.

1. Which `Origin` header, if any, Claude's backend sends to an MCP server.
2. A `https://claude.com/api/mcp/auth_callback` redirect URI.
3. A documented statement that Entra has no DCR.
4. The `aud` and `iss` of an Entra access token issued with
   `resource=<MCP URL>`, by token version.
5. Entra's `scp` carrying the short scope name while the request uses the
   full one.
6. `groups` in Entra access tokens for the API app, and Entra's discovery
   advertising `code_challenge_methods_supported`.
7. An official statement naming SSO proxies (EasyAuth, IAP, oauth2-proxy)
   as incompatible. The requirement is inferred from the documented 401,
   redirect and discovery behaviour.
8. Whether Claude uses `readOnlyHint` to set a tool's default approval,
   which decides whether artifacts can call it.
9. Claude's tool-call timeout, against a 30-day store read.
