# forgd-verdict: the findings connector

The connector is experimental: it has not been run against a real Claude
organization or a real identity provider. The open questions, and what the
sources say about Claude's connectors, MCP and the SDK, are in the
[design note](design/connector.md).

The connector is a read-only remote MCP server over the findings store,
added to your Claude organization as a custom connector. A security team
asks Claude about its own findings, and builds artifacts that query them,
instead of reading only the fixed dashboard. The server is
`forgd_verdict.connector`, deployed by the Helm chart's `connector` role or
by the `app-aca`, `app-cloudrun` and `app-ecs` Terraform modules. It is off
everywhere by default.

---

## What reaches Claude

Everything a tool returns goes into a Claude conversation in your own
organization. There the Compliance API retains it like any other
conversation content, adapter 3 reads it back on its next pass where it is
configured, and the inference hook scans it if the organization governs
that surface.

What the connector returns is never matched content: records carry a
detector name, a locator, a salted digest and pseudonyms, and the privacy
invariant holds unchanged. It is still sensitive metadata: which
pseudonymous actor, on which surface, at what time, had what kind of data
detected. Turning the connector on puts that metadata into your Claude
conversations. The chart's `values.yaml` and its install notes say so.

Digests are returned as a 12-character prefix of `excerpt_hash`: enough to
see that two findings in one answer are the same value, and below the
entropy detector's 20-character minimum, so tool results do not raise
findings of their own when the hook scans the conversation.

---

## Auth

**Your identity provider is the authorization server.** The connector is
an OAuth resource server and nothing else: it issues no tokens and holds no
client secret. Claude signs each user in at your IdP and sends the access
token as `Authorization: Bearer`. The connector verifies it with the
dashboard's `oidc_jwt` verifier: issuer allowlisted, signature against that
issuer's JWKS, `exp`, `iss`, and `aud` in the configured list.

- **A request without a valid token** gets a 401 with `WWW-Authenticate:
  Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource/mcp",
  scope="<scopes>"`. That is how Claude discovers your IdP. The reason a
  token was rejected is logged, never returned.
- **The protected resource metadata**, served at that URL, names
  `connector.resource` as `resource`, your issuers as
  `authorization_servers` (Claude uses the first), and `connector.scopes`
  as `scopes_supported`.
- **A valid token without `connector.required_scope`** in its `scp` or
  `scope` claim gets a 403 with `error="insufficient_scope"`. The setting
  is required: without it any token for the right audience would pass,
  including an ID token or a dashboard token from the same app
  registration.
- **A request whose `Origin` is present and not in
  `connector.allowed_origins`** (default `https://claude.ai`) gets a 403.
  A request with no `Origin` is accepted.

**Static credentials are refused.** Claude's `static_headers` auth type
sends one key, entered by an organization Owner, on every call from
everyone in that organization. There is no person behind it for
entitlements to apply to, so no configuration accepts one: a static
credential key in `connector:` refuses startup, and a static key sent as a
bearer is not a JWT from your issuer, so it gets a 401. Add the connector
in Claude with OAuth.

**Client registration.** Your IdP does not need Dynamic Client
Registration. Register a client app with redirect URI
`https://claude.ai/api/mcp/auth_callback`, and enter its client id (and
secret, for a confidential client) under Advanced settings when adding the
connector. The secret lives in Claude and in your IdP, and nowhere in this
deployment. Authentication settings cannot be changed after the connector
is added; a wrong client means removing it and adding it again.

**On Entra:**

- Register the MCP URL, `https://<connector-host>/mcp`, as an Application
  ID URI on the API app. Otherwise the token request fails with
  `AADSTS9010010`. Entra accepts that URI only on a domain the tenant has
  verified, so the connector needs a custom hostname there: the Container
  Apps, Cloud Run and AKS default hostnames will not do.
- Set `accessTokenAcceptedVersion: 2` on the API app, so the token's `iss`
  matches the v2 issuer in `connector.auth.issuer`.
- List both the MCP URL and the API app's client id in `audience`, and set
  `scopes` to the full scope name (`https://<host>/mcp/findings.read`) and
  `required_scope` to the short one (`findings.read`).

These Entra settings are the documented requirement plus the expected
token shape; the token shape has not been seen from a real tenant.

---

## Network

Claude calls the connector from Anthropic's cloud, not from the user's
device, so the connector must be reachable over the public internet from
Anthropic's egress range, `160.79.104.0/21` today. Claude Code connects
from the user's machine instead.

- IPv4 only. The hostname must resolve only to globally routable
  addresses.
- **No platform sign-in in front of it**: not EasyAuth, IAP,
  oauth2-proxy, Cloudflare Access or anything similar. Any of them answers
  Claude with a redirect or a 401 of its own, before the connector can send
  the 401 that names your IdP. The chart, the app modules and the
  connector itself send no redirect.
- A source allowlist on Anthropic's range is optional. The range has
  changed before, a stale allowlist fails in Claude as "Couldn't reach the
  MCP server", and it cuts off Claude Code.

---

## Request to principal to orgs

Each tool call re-derives the caller from its verified token. The
`Principal` comes from the access token as the dashboard reads it from an
ID token: `name` from `preferred_username`, then `email`, then `sub`;
`groups` from `groups_claim` (default `groups`); `groups_incomplete` from
either of Entra's overage signals; `issuer` from the verified `iss`.

Org scoping uses the dashboard's rules and its map,
`dashboard.entitlements`:

- With no map, a caller reads every org.
- The map is validated against `connector.auth`. Its group names match
  groups from the connector's issuer, so if the connector signs in through
  a different IdP from the dashboard, give each entry an `issuer`.
- A tool's optional `org` argument is checked against the caller's
  entitlement. An org the caller cannot read is the tool error
  `forbidden`.
- A principal whose groups are incomplete gets the tool error
  `groups_unavailable`, with what the operator should change, not an empty
  result.
- Every read goes through a store wrapper that drops rows outside the
  caller's orgs, whatever the backend returned. Results are not cached.

Orgs are named in results by pseudonym, with a `kind` (`org`, `workspace`,
`client` for an intake client, or null for `unattributed`) and the label
the org registry gives it. The connector, like the dashboard, runs without
`privacy.hash_salt`, so labels and entitlements come from the org registry
the writers keep in the store (see
[PLATFORM.md](PLATFORM.md#org-entitlements-and-labels-without-the-salt)).
An org or workspace the registry cannot resolve grants nothing and has no
label, and results never name an org by its id. The `org` argument takes
an `org_` or `workspace_` pseudonym, an intake client's name (see
[PLATFORM.md](PLATFORM.md#intake-client-partitions)), or `unattributed`.

When runtime overrides are on, the connector reads their exclusions and
statistics reset, and `/readyz` reports their readiness (see
[OVERRIDES.md](OVERRIDES.md)).

---

## Tools

Every tool is read-only and declares `readOnlyHint: true`. There are no
write tools and no policy tools. Every argument is validated before the
store is touched: a value out of range, of the wrong type, or under a name
the tool does not take is a tool error, never a silent default.

`window` is one of `24h`, `7d` and `30d`, default `7d`. Every read starts
at the statistics reset if that is later. Capped lists say when they were
cut, and a `limit` above the maximum is refused, not clamped. Limits are
constants in the code, not policy keys.

| Tool | Arguments | Returns | Limits |
|---|---|---|---|
| `summary` | `window`, `org?` | The dashboard's summary payload, plus `orgs`: each org read, with its label and request count. | Detectors 50, surfaces 100, orgs 100. |
| `coverage` | `window`, `org?` | One row per surface: requests per control point, `seen_by`, `inline`, `audit_only`, would-deny, detections, last seen. | Surfaces 100. |
| `findings` | `window`, `org?`, `surface?`, `detector?`, `source?`, `action?` (`all`/`deny`), `since?`, `limit` | Rows as the event log shows them, newest first, with `next_since`. `action=deny` means a disposition of `deny`, `detected` or `flagged`. Read a day at a time from the newest; `truncated` is true when more rows match than `limit`, or when the read stopped after 20,000 records the caller may see, or 200,000 they may not, before the start of the window. | `limit` 1 to 200, default 50. Findings per row 20. `since` must fall inside the window. |
| `record` | exactly one of `reference_id`, `session_id` | One verdict with its findings: the inference hook's when there is one, then the compliance scan's, the managed scan's, the collector's, an agent check's and the Code hook's, newest first within a source. `other_sources` holds the newest verdict of each other source, `earlier_observations` counts every other match, and for a `reference_id` the joined Activity Feed denial, found by the inference hook verdict's `request_id` and then by the `reference_id`, with its `event`. A record in an org the caller cannot read is `found: false`. | Searches the last 30 days. Findings 100, 20 in `other_sources`. |
| `reconciliation` | `window`, `org?`, `limit` | The reconciliation counts, including values seen post-hoc and never live, and denials with their `event` and `joined_by`: `request_id` when Anthropic's request id matches an inference-hook verdict, else `reference_id` when the reference id does, else null. | `limit` 1 to 200, default 50. |
| `topology` | `org?` | Control points and surface states over the last 24 h, as the dashboard computes them. | Surfaces 100. |

A finding row is `{detector, severity, locator, digest, tool_name}`, with
`digest` the 12-character prefix. A record row is `{observed_at, source,
writer, surface, org, kind, label, disposition, action, shadow_action, reference_id,
request_id, session_id, actor, findings_count, findings,
findings_truncated}`, where `actor` is the stored pseudonym and `writer` is
`intake_token` for a Code hook or agent check record and `adapter` for every
other source. Anyone holding a fleet or client intake token can write an
`intake_token` record, with a `reference_id` or `session_id` copied from a
real one. The intake keeps a shipped finding's locator only in the form the
hook's scan produces and stores any other as `<shipped:` and a digest.

`findings` pages forward with `since`, which is inclusive: rows at exactly
that second come back again, so a client de-duplicates by `request_id`.

`topology` gives the audit scan's last run only to a caller who reads
every org: the scan's cursors are keyed by org id, which the connector
cannot match to a pseudonym.

---

## The chart role

Off by default: `connector.enabled: false`. When on, the chart renders:

- **Deployment** `<fullname>-connector`, `connector.replicas` replicas
  (default 1), running the same image with `FORGD_ROLE=connector`. Its
  readiness probe requests `/readyz` with runtime overrides on and
  `/healthz` otherwise. No hash salt and no secret reach it. Its open
  routes are `/healthz`, `/readyz` and the metadata; `/mcp` needs a token.
- **Service** `<fullname>-connector`.
- **ServiceAccount** `<fullname>-connector`, carrying the **store's
  reader identity** (`serviceAccounts.reader.clientId` and `annotations`).
  Only its name, `serviceAccounts.connector.name`, is its own. The chart
  refuses a reader client id equal to the writer's, and a missing one under
  workload identity.

  On a cluster, federate it: `connector_enabled = true` on
  `cluster-aks`, `cluster-eks` or `cluster-gke`, with
  `connector_service_account` matching the chart. Each binds exactly that
  service account to the reader identity, and refuses one equal to the
  writer's or the dashboard's. Without the binding the pod falls back to
  whatever credential the node offers, which shows up as an empty result
  rather than an auth error.

  | Module | What `connector_enabled = true` adds |
  |---|---|
  | `cluster-aks` | A federated identity credential on the reader identity. |
  | `cluster-eks` | The connector's service account in the reader role's trust policy, for Pod Identity and IRSA, and a Pod Identity association. `helm_values_hint` names the service account and gives its ingress the ALB subnets. |
  | `cluster-gke` | A `roles/iam.workloadIdentityUser` binding for the connector's KSA on the reader Google service account. |

- **Ingress** `<fullname>-connector`, a separate object, routing
  `/mcp` and `/.well-known/oauth-protected-resource/mcp` (both Exact):
  - It carries no auth annotations. The chart refuses auth, rewrite,
    redirect, mirror and snippet keys in `ingress.connector.annotations`.
  - `ingress.connector.host` gives the connector its own hostname and
    certificate; on Entra this is effectively required. It must differ
    from the dashboard's host, whose sign-in would answer Claude first.
  - `ingress.connector.sourceRanges` is an optional allowlist, rendered as
    `whitelist-source-range` on this object only.
  - In GKE mode the two paths go on the single Ingress ahead of the
    dashboard's `/`, with a BackendConfig with a health check and no IAP.
    `annotations` and `sourceRanges` are refused there; use a Cloud Armor
    policy on the backend.
  - On EKS with the AWS Load Balancer Controller, give the object the ALB
    group annotations the other objects carry, ordered before the
    dashboard's; `values-eks.example.yaml` shows them.

The chart refuses to render the role without `connector.auth.issuer`,
`jwksUrl` and `audience` (or complete `issuers`), without
`connector.requiredScope`, or with a `connector.resource` that is not
lowercase https ending in `/mcp` on the host the ingress serves. Empty,
the resource is derived as `https://<connector host>/mcp`. The connector
refuses to start on the same conditions.

---

## The Terraform app modules

`app-aca`, `app-cloudrun` and `app-ecs` each take `connector_enabled`,
default `false`; with it false the plan is unchanged. With it true, each
runs the connector as a service of its own, from the same image with
`FORGD_ROLE=connector`, with no hash salt and no secret:

| | Identity | In front of it | Source allowlist |
|---|---|---|---|
| `app-aca` | the reader managed identity | external ingress, no EasyAuth | `connector_source_ranges` on the ingress |
| `app-cloudrun` | an account of its own, in the `reader_members` output under `connector` | `allUsers` invoker, IAP off | none |
| `app-ecs` | task role `reader_role_arn`, its own execution role | its own ALB host rule, a plain forward | `connector_source_ranges` as a `source_ip` condition, at most 4 |

The settings are the chart's under `connector_*` names: `connector_issuer`,
`connector_jwks_url` and `connector_audience`, or `connector_issuers`;
`connector_required_scope`; `connector_scopes`;
`connector_allowed_origins`; `connector_groups_claim`; and
`connector_resource`. A plan is refused when the issuer, JWKS URL or
audience is missing, when the required scope is empty here and in
`policy.yaml`, or when the resource is not a lowercase https URL ending in
`/mcp` on the host the module serves it on:

- `app-aca`: empty derives `https://<connector_app_name>.<environment
  default domain>/mcp`. For a custom domain you bind yourself, set
  `connector_custom_host` and `connector_resource` together; the module
  creates no binding and no certificate.
- `app-cloudrun`: empty derives Cloud Run's deterministic URL,
  `https://<name_prefix>-connector-<project number>.<region>.run.app/mcp`.
- `app-ecs`: `connector_host` is required, and must differ from every
  other service host. Empty derives `https://<connector_host>/mcp`.

The `connector_url` output is the MCP URL, null when the connector is off.
Set it as `FORGD_CONNECTOR_URL` for the release, with the connector's
name:

| Module | Release variables |
|---|---|
| `app-aca` | `AZURE_CONNECTOR_APP` from `connector_app_name` |
| `app-cloudrun` | `GCP_RUN_CONNECTOR_SERVICE` from `connector_service_name`, also as `cloudrun.services.connector` in `ci-gcp` |
| `app-ecs` | `AWS_ECS_CONNECTOR_SERVICE` and `AWS_ECS_CONNECTOR_FAMILY` from `service_names.connector` and `task_definition_families.connector` |

The deploy scripts roll the connector with the other services after the
verdict-first gate, and pass `FORGD_CONNECTOR_URL` to the final verify.
Unset, the connector is skipped. A connector name without the URL, or the
URL without the name, is refused before anything is built. On the Helm
targets `FORGD_CONNECTOR_URL` alone makes the post-upgrade verify check
the chart's connector.

---

## Policy keys

```yaml
connector:
  # Off unless true. While false, nothing below is validated.
  enabled: false
  # The canonical MCP URL: https, lowercase host, no default port, no
  # trailing slash, path /mcp. Served as the metadata's `resource`.
  resource: $FORGD_CONNECTOR_RESOURCE
  # Requested by Claude. On Entra, the full name under the Application ID URI.
  scopes: [$FORGD_CONNECTOR_SCOPE]
  # Required. Checked against the token's `scp` or `scope`; on Entra, the
  # short name.
  required_scope: $FORGD_CONNECTOR_REQUIRED_SCOPE
  # Browser origins allowed on a request that carries Origin.
  allowed_origins: [https://claude.ai]
  # The dashboard.auth schema, oidc_jwt only. The first issuer is the
  # metadata's first `authorization_servers` entry.
  auth:
    mode: oidc_jwt
    issuer: $FORGD_CONNECTOR_ISSUER
    jwks_url: $FORGD_CONNECTOR_JWKS_URL
    audience: [$FORGD_CONNECTOR_RESOURCE, $FORGD_CONNECTOR_API_CLIENT_ID]
    groups_claim: groups
    # issuers: [...]  as dashboard.auth.issuers
```

The connector refuses to start, exiting 2, when:

- `enabled` is not a boolean, or is true with `auth` missing;
- `auth.mode` is anything but `oidc_jwt`;
- an issuer lacks `issuer`, `jwks_url` or `audience`;
- `resource` is not in canonical form, or its path is not `/mcp`;
- `required_scope` is empty;
- a key the connector does not know is present, including `platform`,
  `header`, `stripped_by` or any static credential key;
- no store is given (`--store` or `FORGD_VERDICT_STORE`); it never defaults
  to a local path;
- the `connector` extra is not installed.

There is no unauthenticated mode and no trusted-header mode. The connector
holds no secret: it verifies public-key signatures, and any OAuth client
secret is entered in Claude.

Every key above has a `FORGD_CONNECTOR_*` entry in `ENV_OVERRIDES`; the
lists (`SCOPES`, `ALLOWED_ORIGINS`, `AUDIENCE`, `ISSUERS`) take JSON. The
chart sets them from `connector.*` values.

---

## Deploying it

1. **Register the apps at your identity provider.** On Entra:
   1. An API app registration with Application ID URI
      `https://<connector-host>/mcp` on a verified domain, an exposed
      scope `findings.read`, `accessTokenAcceptedVersion: 2`, and `groups`
      (or app roles) in the token if entitlements are on.
   2. A client app registration with redirect URI
      `https://claude.ai/api/mcp/auth_callback`, granted `findings.read` on
      the API app with admin consent, and a secret if it is to be a
      confidential client.
2. **On a cluster, federate the connector's service account**:
   `connector_enabled = true` and `connector_service_account` on
   `cluster-aks`, `cluster-eks` or `cluster-gke`. The app modules need no
   separate step.
3. **Turn the role on** in the chart, or set `connector_enabled` and the
   settings under [The Terraform app modules](#the-terraform-app-modules).
   For the chart:

   ```yaml
   connector:
     enabled: true
     scopes: [https://mcp.example.com/mcp/findings.read]
     requiredScope: findings.read
     auth:
       issuer: https://login.microsoftonline.com/<tenant>/v2.0
       jwksUrl: https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys
       audience: [https://mcp.example.com/mcp, <API app client id>]
   ingress:
     connector:
       host: mcp.example.com
   ```

   The tenant and client ids are not secrets, but keep them in a values
   file outside the repository, like the org ids.
4. **Check it from outside:**
   `FORGD_CONNECTOR_URL=https://mcp.example.com/mcp scripts/verify_deployment.sh "" "" ""`.
   An unauthenticated MCP `initialize` must get a 401 whose
   `WWW-Authenticate` points at the metadata URL, and the metadata must name
   the MCP URL and an authorization server. Any redirect fails. A proxy
   answering 401 in front of the connector fails the pointer check, but a
   pass does not prove nothing sits in front.
5. **In Claude**, go to Organization settings > Connectors > Add custom
   connector, with the MCP URL, and enter the client id (and secret) under
   Advanced settings. Not with a static header: the connector refuses one.
