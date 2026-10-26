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
`Microsoft.ServiceNetworking/trafficControllers`. Outputs both subnet ids.
A deployment with its own network passes its subnets instead.

**`cluster-aks`.**
- New `ingress` variable: `"app_routing"` (today's behaviour, the default
  for now) or `"agc"`. `"agc"` requires `vnet_subnet_id` and
  `agc_subnet_id`, turns the app-routing add-on off, and sets
  `ingress_class_name` to null so nothing renders an Ingress.
- New `node_resource_group` variable, so the controller's Reader grant
  targets a name known before the cluster exists.
- Under `"agc"`, the module creates the AGC, its frontend and subnet
  association, the controller's identity with its federated credential and
  three role assignments, and two WAF policies with their security
  policies (below). Outputs: `alb_id`, `alb_frontend_name`,
  `alb_frontend_fqdn`, `waf_policy_ids`, and the controller identity's
  client id.

**WAF policies.**
- `protected`: Prevention mode, DRS 2.1 and Bot Manager 1.1, body
  inspection on. Attached to the dashboard and the connector.
- `api`: Prevention mode, no managed rule sets, `request_body_check` off.
  Custom rules only: the allowlists that replace NGINX's
  `whitelist-source-range` (`RemoteAddr` `IPMatch` scoped by `RequestUri`
  to `/hook`, and to the connector's host), and a per-client rate limit
  that is off unless `api_rate_limit_per_minute` is set. Anthropic's
  webhook and OTLP traffic arrives from a small pool of addresses, so a
  limit sized for one laptop would throttle every governed prompt in an
  organization. Attached to the
  public and diagnostics routes. The request bodies here are prompt text,
  tool output and telemetry, which DRS is written to flag, and a 403 on a
  governed prompt is a webhook failure.
- The allowlists move from chart values to module variables
  (`hook_source_ranges`, `connector_source_ranges`), because the WAF policy
  is an Azure resource. In `agc` mode the chart refuses
  `ingress.hook.sourceRanges` and `ingress.connector.sourceRanges` rather
  than drop them silently.

**Controller install.** The ALB Controller is pinned by OCI digest, and is
installed the way oauth2-proxy is: a documented `helm upgrade --install`
that a deployment workflow runs before the chart. The module outputs the
values it needs.

### Chart

`ingress.mode`: `nginx` (default), `gke`, `agc`. The GKE helper becomes
`ingress.mode == "gke"`, keeping the current GKE value as an alias for one
release.

In `agc` mode the chart renders no Ingress. It renders:

- a `Gateway` with the `alb-id` annotation and frontend address from
  `ingress.agc.albId` and `ingress.agc.frontend`, an HTTP listener on 80
  and an HTTPS listener on 443 for each host, and cert-manager's
  `cert-manager.io/cluster-issuer` annotation from
  `ingress.tls.clusterIssuer`;
- one HTTPRoute per current Ingress object, with the same paths and hosts
  (`public`, `diagnostics`, `dashboard`, `connector`), and a redirect route
  on port 80 that sends everything except `/.well-known/acme-challenge/` to
  HTTPS;
- `timeouts.request` on the public route from
  `ingress.agc.publicRequestTimeout` (default 300s, OTLP batches and hook
  frames on slow links);
- a `WebApplicationFirewallPolicy` per route from
  `ingress.agc.wafPolicies.protected` and `.api`; the chart fails to render
  a route with no policy id;
- a `HealthCheckPolicy` per routed Service: GET `forgd-verdict.readyPath`
  on the serving port;
- the dashboard route's backend from `ingress.agc.dashboardBackend`
  (oauth2-proxy's Service). The chart refuses `agc` mode with the
  dashboard enabled and no backend set, unless `dashboard.serveOpen`;
- a NetworkPolicy, on by default in `agc` mode, admitting the dashboard
  Service only from oauth2-proxy's pods. AGC reaches pod IPs from its
  subnet, so without one a request that bypasses the route reaches the
  dashboard unauthenticated.

`ingress.proxyBodySize` has no AGC setting. The chart documents the limit
found in testing.

`deploy/helm/README.md` gains an AGC section: oauth2-proxy in upstream mode
(`--upstream=http://<release>-dashboard.<ns>.svc:<port>`,
`--pass-authorization-header`, `--set-authorization-header`), the ALB
Controller install, and how the module's outputs map to chart values.

### What does not change

- No platform auth on `/hook`, `/v1`, `/intake` or `/scan`. The `api`
  policy has no managed rules and no auth, and the chart test keeps
  asserting no route other than the dashboard sends traffic through
  oauth2-proxy.
- The verdict server and collector authenticate their callers themselves,
  as now.

## Tests

Before the lab moves, in a scratch cluster on the same module:

1. An OTLP/HTTP batch and a hook frame of 1, 8, 32 and 64 MB through the
   public route. Record the largest that passes and what AGC answers above
   it.
2. A request carrying a DRS-triggering string (SQL injection, XSS) to `/`
   answers 403; the same string in a hook frame's prompt passes to the
   verdict server. This covers both "no policy means no WAF" and the `api`
   policy's body settings.
3. A request to `/hook` from outside `hook_source_ranges` answers 403
   when the list is set.
4. A large Entra ID session (oauth2-proxy's split `Set-Cookie`) through the
   dashboard route: header limits.
5. A request held open longer than 60 s on the public route completes.

Render tests: every `agc` HTTPRoute has a WAF policy; the public and
diagnostics routes use the `api` policy; only the dashboard route's backend
is oauth2-proxy; the redirect route exempts the ACME path; source-range
values are refused in `agc` mode. Terraform render tests for `network-azure`
and `cluster-aks` under `ingress = "agc"`, including the controller's three
role assignments and the two WAF policies' settings.

## Migration

New deployments choose `agc` from the release that ships it. An existing
`app_routing` cluster on an AKS-managed VNet moves by building a new
cluster beside it and moving its hostname. That is a new cluster, a new OIDC
issuer and new federated credentials, so it is a cutover, not an upgrade.
The `cluster-aks` default becomes `"agc"` in the release after Microsoft's
support for app-routing NGINX ends.
