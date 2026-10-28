# Application Gateway for Containers on AKS: design note

This is a design note: why the AKS deployment moves from the app-routing
add-on's managed NGINX to Azure Application Gateway for Containers (AGC)
with its WAF, what the sources say, and how the chart and the Terraform
modules change. It is written before the code. Points no source settled are
marked **UNCONFIRMED** and are tested in a real cluster before the lab moves.

## Why

The `cluster-aks` module turns on the app-routing add-on, and the chart's
ingress objects are written for its managed NGINX. Microsoft has set an end
date for it:

- "Microsoft will provide official support for critical security patches
  for application routing add-on NGINX Ingress resources through
  **November 2026**." It names two targets: the add-on's Gateway API
  implementation, and Application Gateway for Containers.
  <https://learn.microsoft.com/en-us/azure/aks/app-routing-nginx-configuration>

Deployments also want a WAF in front. AGC is one of the two named
migration targets and carries a WAF whose policy attaches per HTTPRoute,
so one change covers both.

Azure Front Door Premium was the other WAF candidate. It does not replace
NGINX, its route-level WAF policies are in preview with no azurerm
support, and its GA way to exempt a path skips every managed rule on that
path. <https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-faq>

## Findings from the sources

### Cluster prerequisites

- Azure CNI or Azure CNI Overlay; kubenet is not supported. With overlay,
  AGC's subnet is exactly a /24 in the same VNet as the nodes, delegated to
  `Microsoft.ServiceNetworking/trafficControllers`. A peered VNet does not
  work.
  <https://learn.microsoft.com/en-us/azure/application-gateway/for-containers/container-networking>
- OIDC issuer and workload identity on. `cluster-aks` already sets both,
  and runs overlay with Cilium.
- A VNet that AKS manages cannot take another subnet, so AGC needs the
  cluster on a VNet the deployment owns (`vnet_subnet_id`). AKS cannot
  change `vnet_subnet_id` on an existing cluster: moving an existing
  deployment means a new cluster.

### Deployment model and controller

- Bring-your-own: Terraform creates `azurerm_application_load_balancer`,
  `azurerm_application_load_balancer_frontend` and
  `azurerm_application_load_balancer_subnet_association`. One association
  and up to five frontends per AGC; a frontend belongs to one Gateway,
  which names it with the `alb.networking.azure.io/alb-id` annotation and
  an `alb.networking.azure.io/alb-frontend` address.
  <https://learn.microsoft.com/en-us/azure/application-gateway/for-containers/quickstart-create-application-gateway-for-containers-byo-deployment>
- The ALB Controller installs from
  `oci://mcr.microsoft.com/application-lb/charts/alb-controller` (1.12.4,
  Kubernetes 1.32 or later) with a user-assigned identity federated to
  `system:serviceaccount:<ns>:alb-controller-sa`. That identity needs
  Reader on the node resource group, "AppGw for Containers Configuration
  Manager" on AGC's resource group, and Network Contributor on AGC's
  subnet. The AKS add-on that installs the controller is preview and
  azurerm cannot enable it.
  <https://learn.microsoft.com/en-us/azure/application-gateway/for-containers/quickstart-deploy-application-gateway-for-containers-alb-controller-helm>

### WAF

- `azurerm_web_application_firewall_policy` (managed rule set
  `Microsoft_DefaultRuleSet` 2.1; Bot Manager 1.0 or 1.1) and
  `azurerm_application_load_balancer_security_policy`, one per WAF policy.
  A `WebApplicationFirewallPolicy` custom resource
  (`alb.networking.azure.io/v1`) attaches a policy to a Gateway, one of its
  listeners, or an HTTPRoute.
  <https://learn.microsoft.com/en-us/azure/application-gateway/for-containers/web-application-firewall>
- Not supported on AGC: CRS rule sets, JavaScript and Captcha challenges,
  custom block responses, the HTTP DDoS rule set, and the XFF match variable
  in custom rules. GA since November 2025.
- Body inspection settings (`request_body_check`,
  `request_body_enforcement`, `max_request_body_size_in_kb`,
  `request_body_inspect_limit_in_kb`) are per policy, so routes on
  different policies can differ. **UNCONFIRMED**: that AGC applies them as
  Application Gateway v2 does, and that a route with no policy attached
  gets no WAF.

### Traffic

- The request timeout is 60 s and runs while a body is still streaming;
  HTTPRoute `timeouts.request` overrides it, 0 turns it off. Idle timeouts
  5 min, connect 5 s.
  <https://learn.microsoft.com/en-us/azure/application-gateway/for-containers/application-gateway-for-containers-components>
- HTTP/1.1 to backends. The backend sees the client in `x-forwarded-for`.
- Health probes: a `HealthCheckPolicy` on the Service, else the pod's
  readiness probe, else `GET /` with Host `localhost`.
  <https://learn.microsoft.com/en-us/azure/application-gateway/for-containers/custom-health-probe>
- **UNCONFIRMED**: the maximum request body and header sizes. Neither is
  published. OTLP batches and hook frames exceed 1 MB; the chart sets
  NGINX's limit to 64 MB today.

### TLS and hostnames

- cert-manager with Gateway API and an HTTP-01 `gatewayHTTPRoute` solver is
  documented; certificates are Kubernetes Secrets, and Key Vault is not
  supported.
  <https://learn.microsoft.com/en-us/azure/application-gateway/for-containers/how-to-cert-manager-lets-encrypt-gateway-api>
- The frontend gets a generated `*.alb.azure.com` FQDN on ports 80 and 443.
  A deployment's own hostname is a CNAME to it.

### Authentication

AGC has no counterpart to NGINX's `auth-url`, and no JWT validation. The
dashboard's sign-in moves from an auth subrequest to oauth2-proxy as a
reverse proxy: the dashboard's HTTPRoute sends traffic to oauth2-proxy,
which forwards signed-in requests to the dashboard with the ID token in
`Authorization`. That is oauth2-proxy's own upstream mode, not a
Microsoft-documented pattern.


## Design

### Terraform

**`network-azure` (new).** A VNet with a node subnet and a /24 delegated to
`Microsoft.ServiceNetworking/trafficControllers`. Outputs both subnet ids
and the AGC subnet's CIDR. A deployment with its own network passes its
subnets instead.

**`cluster-aks`.**
- `ingress`: `"app_routing"` (today's behaviour, the default for now) or
  `"agc"`. It replaces `app_routing_enabled`, which stays one release as an
  alias: `app_routing_enabled = false` with `ingress` unset means no
  ingress at all, as now, and setting both fails the plan.
- `"agc"` requires `vnet_subnet_id` and `agc_subnet_id`, turns the
  app-routing add-on off, and requires `kubernetes_version` at 1.32 or
  later (a precondition; the ALB Controller needs it).
- `node_resource_group`, so the controller's Reader grant targets a name
  known before the cluster exists.
- Under `"agc"` the module creates the AGC, its frontend and subnet
  association, the controller's user-assigned identity with its federated
  credential and three role assignments, and the WAF policies below.
- Outputs: `ingress_mode`; `ingress_class_name` (null under `"agc"`); and
  under `"agc"`, `alb_id`, `alb_frontend_name`, `alb_frontend_fqdn`,
  `waf_policy_ids` (a map keyed `protected`, `connector`, `hook`, `api`),
  and the controller identity's client and principal ids. The AGC
  subnet's CIDR comes from `network-azure`. The AKS example's
  `helm_install_command` output emits the matching `--set` flags for whichever mode is
  on.

**WAF policies.** Four. `endpoint_waf_managed_rules` (`off`, `Detection`
or `Prevention`, default `off`) sets the mode and managed rules of the
three endpoint policies:

| Policy | Managed rules | Body inspection | Custom rules | Routes |
|---|---|---|---|---|
| `protected` | DRS 2.1, Bot Manager 1.1; Prevention | on | none | dashboard (oauth2-proxy) |
| `connector` | DRS 2.1 unless `off` | up to 2000 KB unless `off` | `connector_source_ranges` allowlist; with `off`, then allow everything | connector |
| `hook` | DRS 2.1 unless `off` | up to 2000 KB unless `off` | `hook_source_ranges` allowlist; rate limit if `api_rate_limit_per_minute` is set; with `off`, then allow everything | hook |
| `api` | DRS 2.1 unless `off` | up to 2000 KB unless `off` | rate limit if `api_rate_limit_per_minute` is set; with `off`, then allow everything | public, diagnostics |

- **`off`.** The azurerm provider requires at least one managed rule set
  on every WAF policy, so all three carry DRS 2.1, and each ends with a
  custom rule that allows every request (priority 100). A request a custom
  rule allows is not evaluated by the managed rules, so DRS never runs on
  these routes. The allowlists and rate limit come before it.
- **`Detection`.** The allow rule is dropped and DRS evaluates headers, URI
  and up to 2000 KB of the body, logging what it would block to the AGC
  firewall log (`agc_log_analytics_workspace_id`). The mode is
  policy-wide, so the allowlists and rate limit would only log too; the
  module refuses `Detection` with any of them set.
- **`Prevention`.** As `Detection`, and a match is answered 403.
  `request_body_enforcement` is off, so no body is refused for its size.
  What is not settled from the documentation, and the soak and gate 1
  settle on traffic:
  - DRS 2.1 parses JSON, XML, form and multipart bodies. Rule 920420
    scores any other content type, which includes OTLP protobuf on `/v1`
    and hook-ship's NDJSON on `/intake`, at the blocking threshold.
  - Rule 200002 scores a body that fails to parse: a gzip-encoded JSON
    export, and possibly a JSON body cut at the inspection limit.
- **Overrides and exclusions.** `endpoint_waf_rule_overrides`, keyed
  `hook`, `api` or `connector`, sets a rule to `Log`, `AnomalyScoring`,
  `Block` or `Disabled` on that policy; that is how 920420 and 200002 are
  handled when they fire on legitimate traffic, since an exclusion cannot
  silence a rule that judges the whole request. `endpoint_waf_exclusions`
  names request parts DRS skips.
- **`/hook`'s body.** With managed rules on, the hook policy excludes the
  keys and values of every argument DRS parses from the body, so DRS
  inspects `/hook`'s headers and URI only. The body is prompt text, tool
  input and tool output, so code in a prompt matches SQL injection, PHP,
  shell and XSS rules, and 943120 matches the `session_id` key of every
  request, none of which carries a Referer; 943120 alone reaches the
  anomaly threshold. The request is authenticated by its signature, and
  `hook_source_ranges` limits it to Anthropic's addresses.
- **Logs.** The firewall log records the part of the request a rule
  matched. On these routes that is prompt text, telemetry and content
  submitted for scanning, so the endpoint policies scrub argument, JSON,
  form, header and cookie values from it. Gate 9 checks the scrubbing
  holds on AGC.
- **Rollout.** The bodies on `/hook`, `/v1`, `/intake` and `/scan` are
  prompt text, tool output and telemetry, which DRS is written to flag, and
  a 403 on a governed prompt is a webhook failure. The hook policy's
  argument exclusions cover `/hook`; a deployment soaks in
  `Detection` on real traffic, reads the firewall log, adds exclusions for
  rules that match legitimate content, and then moves to `Prevention`,
  which is also when the allowlists start blocking.
- The rate limit is off by default: Anthropic's webhook and OTLP traffic
  arrives from a small pool of addresses, so a limit sized for one client
  would throttle every governed prompt in an organization.
- `connector`: the connector answers 401 itself so Claude can find its
  OAuth metadata (the chart sets `enable-modsecurity: "false"` on its
  Ingress for this). A managed-rule 403 in its place breaks discovery, so
  the soak has to show its discovery requests pass before `Prevention`.
- `/hook` has a route and a policy of its own, so `hook_source_ranges`
  applies to whatever the Gateway routes there. A path match inside a
  shared policy (`RequestUri` begins with `/hook`) could disagree with the
  Gateway's path matching on case, repeated slashes or encoding.
- The allowlists are `RemoteAddr` `IPMatch` rules. They move from chart
  values to module variables because the WAF policy is an Azure resource;
  in `agc` mode the chart refuses `ingress.hook.sourceRanges` and
  `ingress.connector.sourceRanges` rather than drop them silently.

**Controller install.** The ALB Controller chart is pinned by OCI digest
and installed the way oauth2-proxy is: a documented
`helm upgrade --install` that the deployment workflow runs before this
chart, followed by a wait for its CRDs (`gateway.networking.k8s.io`,
`alb.networking.azure.io`) and a ready controller.

### Chart

**Mode.** `ingress.mode`: `nginx` (default), `gke`, `agc`. Today GKE mode is
detected from `ingress.className: gce`. For one release that still selects
`gke` when `ingress.mode` is unset; setting `ingress.mode` to something else
with `className: gce` fails. `agc` refuses each NGINX- or GKE-only value
that differs from the chart's default, since it would otherwise be ignored:
`ingress.className` other than `nginx`, a non-empty `ingress.annotations`,
`ingress.dashboard.annotations`, `ingress.diagnostics.annotations` or
`ingress.connector.annotations`, and any `ingress.gke.*` value changed from
its default. The defaults themselves (`className: nginx`,
`gke.collectorTimeoutSec: 120`) render nothing in `agc` mode and are not
refused.

**What `agc` renders.** No Ingress. Instead:

- one `Gateway` with the `alb-id` annotation and frontend address from
  `ingress.agc.albId` and `ingress.agc.frontend`;
- the same host and path routing as today, as HTTPRoutes:

| Route | Hosts | Paths | Backend | WAF policy |
|---|---|---|---|---|
| `hook` | `host`, `extraHosts` | `/hook`, if the verdict server is enabled | verdict | `hook` |
| `public` | `host`, `extraHosts` | `/v1`, `/intake`, `/scan`, each only if its role is enabled | collector, intake | `api` |
| `diagnostics` | `host`, `extraHosts` | `/healthz`, `/metrics` (verdict), `/health`, `/stats` (collector), if `ingress.diagnostics.enabled` | verdict, collector | `api` |
| `dashboard` | `dashboard.host` when it differs from `host`; otherwise `host` and `extraHosts` | `/` (prefix) | `ingress.agc.dashboardBackend` (oauth2-proxy) | `protected` |
| `connector` | `connector.host` when it differs from `host`; otherwise `host` and `extraHosts` | `/mcp` and `/.well-known/oauth-protected-resource/mcp`, both exact, on either kind of host | connector | `connector` |
| `redirect` | every host | port 80, `/`; cert-manager's own solver route for `/.well-known/acme-challenge/<token>` is longer and wins | 301 to HTTPS | none (no backend) |

- every collision check the Ingress template makes today, on the same
  values: `extraHosts` repeating `host`, `dashboard.host` or `connector.host`
  inside `extraHosts`, and the connector sharing the dashboard's host;
- `timeouts.request` on the hook and public routes from
  `ingress.agc.publicRequestTimeout` (default `300s`);
- a `WebApplicationFirewallPolicy` per route from
  `ingress.agc.wafPolicies.{protected,connector,hook,api}`. The chart fails to
  render a routed role whose policy id is empty. There is no route without
  a policy;
- a `HealthCheckPolicy` per routed backend: GET `forgd-verdict.readyPath` on
  the serving port for the chart's own Services, and GET `/ping` on
  oauth2-proxy's port for the dashboard route (oauth2-proxy's health
  endpoint; its port and path are `ingress.agc.dashboardBackend.healthPath`
  and `.port`). The dashboard's own readiness stays its pod probe.

**The dashboard.** The same refusal as today: `dashboard.serveOpen` with
the dashboard routed fails to render, in every mode. A routed dashboard in
`agc` mode needs `ingress.agc.dashboardBackend`. Without it the chart fails,
since AGC has no auth subrequest and the route would otherwise reach the app
directly.

**TLS.** One HTTPS listener per distinct hostname, each with its own
certificate Secret:

| `ingress.tls` | Listener `certificateRefs` | Issued by |
|---|---|---|
| `enabled`, `clusterIssuer` set | `<release>-tls-<n>` per host, one SAN each | cert-manager, from the Gateway's `cert-manager.io/cluster-issuer` annotation, HTTP-01 through cert-manager's solver route on the port-80 listener |
| `enabled`, `secretName` set | `secretName` on every listener; it must cover every host | the operator |
| `enabled`, neither set | fails, as today | |
| `enabled: false` | fails in `agc` mode | an HTTP-only listener would carry bearer tokens in clear |

**NetworkPolicy.** In `agc` mode, when `networkPolicy.enabled`:
- `networkPolicy.agc.subnetCidr` (`network-azure`'s `agc_subnet_cidr`) is admitted
  as an `ipBlock` to the pods behind the public, diagnostics and connector
  routes: verdict, collector, intake, connector. AGC sends data traffic and
  probes from that subnet.
- The dashboard pods admit only oauth2-proxy's pods: the chart pins the
  namespace to the release's (an HTTPRoute's backend Service is in the
  route's namespace) and takes `networkPolicy.agc.dashboardProxy.podSelector`.
  The selector is `matchLabels` only, and one whose every label is one the
  chart sets on its own pods is refused, since those pods would then reach
  the dashboard past the proxy. If oauth2-proxy's pods run under a
  NetworkPolicy of their own, it admits the AGC subnet.
- `networkPolicy.ingressController` is refused in `agc` mode. There is no
  controller in the data path.
- The `trusted_header` checks in `dashboard.yaml` take the proxy selector as
  the proxy peer in `agc` mode, in place of `ingressController`.
- `networkPolicy.extraFrom` keeps its meaning: extra peers beside the AGC
  subnet for the routed roles. `networkPolicy.dashboardExtraFrom` is refused
  while the dashboard is routed: a peer there would reach it past the proxy.
- `ingress.agc.dashboardBackend.name` may not be the dashboard's own
  Service.
- With the dashboard routed, `agc` mode requires `networkPolicy.enabled`,
  with no acknowledgement to set it aside. With the dashboard not routed,
  `networkPolicy.agcWithoutPolicyAcknowledged` lets it render without a
  policy, for a cluster that limits pod traffic some other way.

**NOTES.txt** prints the frontend FQDN to CNAME, the HTTPRoute and
WebApplicationFirewallPolicy status commands, and the oauth2-proxy and ALB
Controller prerequisites.

`ingress.proxyBodySize` has no AGC setting. The chart documents the limit
found in testing.

`deploy/helm/README.md` gains an AGC section: the ALB Controller install,
oauth2-proxy in upstream mode
(`--upstream=http://<release>-dashboard.<ns>.svc:<port>`,
`--pass-authorization-header`, `--set-authorization-header`, plus its
NetworkPolicy admitting the AGC subnet), and how the module's outputs map to
chart values.

### What does not change

- No platform auth on `/hook`, `/v1`, `/intake`, `/scan` or the connector.
  None of the `hook`, `api` and `connector` policies carries auth, and
  a render test asserts that only the dashboard route's backend is
  oauth2-proxy.
- The verdict server, collector and connector authenticate their callers
  themselves, as now.

## Tests

**Cutover gates.** Run in a scratch cluster built from the same modules and
chart. The lab does not move until every one passes:

1. A 64 MiB request through each of `/hook`, `/v1`, `/intake` and `/scan`
   reaches its backend, both with a plain body and, with
   `endpoint_waf_managed_rules = "off"`, with a body carrying
   DRS-triggering strings (SQL injection, XSS, path traversal). In
   `Detection` the same body reaches the backend and the firewall log shows
   the match; in `Prevention` it answers 403. Before `Prevention`, each of
   these reaches its backend with the policy in `Prevention` on a scratch
   deployment: a 64 MiB valid JSON body on `/hook`, `/v1` and `/scan`; an
   OTLP export as protobuf, as JSON and as gzip-encoded JSON; and a
   hook-ship NDJSON batch on `/intake`. The chart
   promises 64 MiB today (`ingress.proxyBodySize`). If AGC caps bodies
   below that, the migration stops. Lowering the promise is a separate,
   reviewed change that the owner decides on, not a step in this runbook.
2. The same DRS-triggering strings in a request to `/` (the dashboard route)
   answer 403.
3. An unauthenticated request to the connector answers the connector's 401
   with its `WWW-Authenticate` metadata, not a WAF 403.
4. With `hook_source_ranges` set, `/hook` from outside it answers 403 and
   from inside it reaches the verdict server, and the WAF log shows the real
   client address in `RemoteAddr`. The same for the connector with
   `connector_source_ranges`: outside answers 403, inside answers the
   connector's own 401.
5. A pod in another namespace, and a request addressed to a dashboard pod
   IP, cannot reach the dashboard. oauth2-proxy can, and AGC's health probes
   to every backend succeed.
6. An Entra ID sign-in through the dashboard route, with oauth2-proxy's
   split `Set-Cookie`, completes.
7. A request held open longer than 60 s on the hook and public routes
   completes.
8. Every certificate is Ready, every HTTPRoute and
   WebApplicationFirewallPolicy reports Accepted, and the existing
   `forgd-verdict verify-deployment` passes against the scratch hostname.
9. With `endpoint_waf_managed_rules` on, a synthetic DRS-triggering value
   in a JSON field on `/hook` and `/scan` appears in the firewall log
   masked, not as sent.

**Render tests:**
- the routing tables above, for every combination of enabled roles,
  `extraHosts`, a separate dashboard host and a separate connector host;
- each collision check failing as it does in `nginx` mode;
- every route having a WAF policy, and each policy matching the table;
- only the dashboard route's backend being oauth2-proxy;
- the redirect route binding to the port-80 listener only, and every other
  route to HTTPS listeners only;
- every refused value in `agc` mode;
- the TLS table;
- the NetworkPolicy peers.

**Terraform render tests:** `network-azure`; `cluster-aks` under
`ingress = "agc"`, covering the version precondition, the `app_routing_enabled`
alias and conflict, the controller's three role assignments, and each WAF
policy's settings.

## Migration

New deployments choose `agc` from the release that ships it. An existing
`app_routing` cluster on an AKS-managed VNet moves by building a new
cluster beside it, because `vnet_subnet_id` cannot change in place. That
means a new OIDC issuer and new federated credentials. The runbook:

1. Build the new network, cluster, AGC and WAF beside the old cluster. The
   old one keeps serving.
2. Install the ALB Controller and oauth2-proxy, and wait for the CRDs and
   the controller.
3. Deploy the chart in `agc` mode on a temporary hostname, a CNAME to the
   frontend FQDN.
4. Run the cutover gates against the temporary hostname.
5. Lower the production hostname's DNS TTL a day ahead, then point it at
   the new frontend. Clients that call the Anthropic webhook and OTLP
   endpoints by that hostname follow the change; endpoints configured as
   the old address change in Anthropic's settings and the identity
   provider's redirect URIs at this step.
6. Rollback until the old cluster is deleted is pointing DNS back.
7. Delete the old cluster after a week of clean verification, once the
   owner confirms.

The `cluster-aks` default becomes `"agc"` in the release after Microsoft's
support for app-routing NGINX ends.
