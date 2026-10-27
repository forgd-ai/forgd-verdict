# forgd-verdict on Kubernetes

The chart runs six roles from the same image as the Container Apps
module, selected by `FORGD_ROLE`. It does not create the findings store:
findings outlive clusters, and a `helm uninstall` must not be able to take
the evidence with it. The store comes from
`../terraform/modules/store-azure` on every deployment path, this one
included, or from `store-s3` on AWS and `store-gcs` on Google Cloud.
`forgd-verdict/values-eks.example.yaml` and
`forgd-verdict/values-gke.example.yaml` are the starting points there. On
GKE, `ingress.className: gce` renders one GCE Ingress for every path and
puts IAP on the dashboard's backend alone; the example's header is the
install procedure, including how to set the dashboard's IAP audience.

## Standing up a cluster

```sh
# 1. the cluster and the federation
terraform -chdir=deploy/terraform/examples/aks apply

# 2. a name and a certificate -- neither of the above provides either
scripts/bootstrap_aks.sh <resource-group> <cluster-name> <dns-label>

# 3. the six roles
terraform -chdir=deploy/terraform/examples/aks output -raw helm_install_command
```

Step 2 exists because Terraform builds the cluster and the chart deploys the
roles, and nothing in between gives Anthropic a hostname to reach or a
certificate it will trust. It also discovers the ingress class,
`webapprouting.kubernetes.azure.com` (not the `.io` form). Get that wrong
and the controller logs `Ignoring ingress because of error while validating
ingress class` for every Ingress, including cert-manager's own solver, then
serves its default backend, which answers 200 with an empty body. The
deployment looks healthy and the only symptom is the ACME challenge getting
a 404. An exporter reads a TLS failure as a *delivery*
failure, so getting this wrong raises no error in the deployment.

It uses the Azure-issued `<label>.<region>.cloudapp.azure.com`, which needs
no domain ownership and resolves to the load balancer as soon as the label
is set, which is what lets cert-manager's HTTP-01 challenge succeed with
nothing else in place. Add a vanity name later through
`ingress.extraHosts`: same rules, same certificate, no second re-pointing of
Anthropic.

## What it needs first

1. The store, and the two identities it creates: a writer for the roles
   that record findings and a reader for the dashboard.
2. Those identities federated to this chart's service accounts, so the
   pods authenticate as themselves rather than carrying a credential. The
   AKS module does this; without it the pods fall back to whatever the node
   offers and the failure surfaces as an empty dashboard rather than as an
   auth error.
3. An ingress controller and a hostname.

## Installing

```sh
helm upgrade --install forgd deploy/helm/forgd-verdict \
  --namespace forgd --create-namespace \
  --set store.url="$(terraform -chdir=../terraform/examples/aks output -raw store_url)" \
  --set image.repository=myacr.azurecr.io/forgd-verdict \
  --set image.tag="$GIT_SHA" \
  --set ingest.image.repository=myacr.azurecr.io/forgd-verdict \
  --set ingest.image.tag="$GIT_SHA-ingest" \
  --set serviceAccounts.writer.clientId="$WRITER_CLIENT_ID" \
  --set serviceAccounts.reader.clientId="$READER_CLIENT_ID" \
  --set ingress.host=verdict.example.com \
  --set ingress.tls.clusterIssuer='<cluster-issuer>' \
  --set secrets.existingSecret=forgd-verdict \
  --set-string orgIds.primary='<organization-uuid>' \
  --set dashboard.auth.mode=oidc_jwt \
  --set dashboard.auth.header=authorization \
  --set dashboard.auth.issuer='https://login.microsoftonline.com/<tenant>/v2.0' \
  --set dashboard.auth.jwksUrl='https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys' \
  --set dashboard.auth.audience='<client-id>' \
  --set-file policy.inline=policy.yaml
```

Replace the values in angle brackets. `<cluster-issuer>` is the
cert-manager ClusterIssuer, `letsencrypt` if `scripts/bootstrap_aks.sh`
made it; to bring your own certificate, set `ingress.tls.secretName`
instead. The `dashboard.auth` values assume oauth2-proxy in front of the
dashboard (§ Putting oauth2-proxy in front); § The shipped policy's
dashboard auth does not port has the alternative.

`orgIds.primary` becomes `FORGD_ORG_ID_PRIMARY`, the variable `policy.yaml`
reads for its organization. Each `orgIds.<name>` key must match a
`$FORGD_ORG_ID_<NAME>` in the policy you load.

`--set-file policy.inline=policy.yaml` is not optional. The repository's
`policy.yaml` is the only copy. A second one inside the chart would be free
to drift from the one the Container Apps module reads, and the drift would
show up as two deployments disagreeing about a detector threshold with
nothing saying why.

### Pinning by digest

`image.digest` and `ingest.image.digest` take a digest in place of a tag:
`sha256:` and 64 lowercase hex characters, without the repository or an
`@`. When a digest is set, the image renders as `repository@sha256:...` and
the tag is ignored. Anything else in the field fails the render. While the
ingest job is enabled, set both digests or neither: one alone fails the
render, because the other image would stay on a mutable tag.

```sh
  --set image.repository=ghcr.io/forgd-ai/forgd-verdict \
  --set image.digest=sha256:<base digest> \
  --set ingest.image.repository=ghcr.io/forgd-ai/forgd-verdict \
  --set ingest.image.digest=sha256:<ingest digest>
```

Each GitHub Release lists these four lines with the digests it pushed.
The ingest job needs `ingest.image.tag` or `ingest.image.digest`, and the
render fails with neither. A digest names the image's bytes, so it cannot
fall back to the base image the way a missing tag would. But it has to be
the **`-ingest` image's** digest: the base image's digest under
`ingest.image.digest` runs adapter 3 on the base image, which reports a
clean scan.

### Branding the dashboard

The chart has no branding values. The dashboard's name, logo, favicon,
footer and colours are `dashboard.branding` in the same policy file, so they
reach the pods inside `policy.inline`. Unset, the dashboard renders neutral.
See "Branding" in [docs/PLATFORM.md](../../docs/PLATFORM.md) for the keys.

Put the logo and favicon in the policy as `data:` URIs:

```sh
printf 'data:image/png;base64,%s\n' "$(base64 < logo.png | tr -d '\n')"
```

`--set-file` reads its file as text, so it cannot carry a binary image
alongside the policy, and an image path in the policy names a file that is
not in the container unless you mount it there yourself. A path must be
absolute.

Each image is capped at 256 KB decoded, about 350 KB as base64. The policy
becomes one ConfigMap, and a ConfigMap holds at most 1 MiB, so two images at
the cap fit with room to spare. Helm also stores the values and the
rendered manifests in its release Secret, also capped at 1 MiB, so the
inline policy counts twice there, compressed; base64 image data barely
compresses.

## One hostname, three ingress objects

```
/hook      -> verdict server   Anthropic posts governed prompts here
/v1/logs   -> collector        OTLP logs   (Claude Code, Cowork)
/v1/traces -> collector        OTLP traces (office agents)
/healthz   -> verdict server   Exact
/metrics   -> verdict server   Exact, token-guarded
/health    -> collector        Exact
/stats     -> collector        Exact, token-guarded
/          -> dashboard
```

One name because it ends up in the Anthropic-side configuration in three
places.

**What you paste into the admin console is the base URL**, not these paths.
An OTLP exporter appends `/v1/logs` or `/v1/traces` itself depending on the
signal, so `Endpoint: https://<host>` is correct and
`https://<host>/v1/logs` gives you `/v1/logs/v1/logs` and a 404, which the
exporter reports as a delivery failure rather than as a bad URL. The paths
above are what the collector *serves*, and therefore what the ingress must
route.

Anthropic reads a
non-200 as a webhook *failure*, not a deny, and repeated failures trip its
circuit breaker, so nothing is governed at all. An OTLP exporter reads a
redirect as a delivery failure and drops the batch. Either way the mistake
looks like an auth improvement while it stops the deployment working, and
neither half surfaces as an error anyone is watching.

Three objects because nginx has no per-path annotation: an `auth-url`
added for the dashboard would front every location in the object carrying
it. That much the split does handle.

**The split alone is not enough.** Three things defeat it:

- `ingress.annotations` is a passthrough map on the public object itself.
  Separating the objects says nothing about what is set directly on the one
  carrying `/hook`. An `auth-*`, `rewrite-target`, `*-snippet`,
  `use-regex`, `*-redirect` or `mirror-*` key there is refused at
  render time, as is `enable-modsecurity`: the chart sets it to `"false"`
  on `/hook`, `/v1` and `/mcp`, and a second copy of the key would win.
- Some annotations are not per-location at all. ingress-nginx renders
  `auth-tls-*` and `server-snippet` into the *server* block, so setting one
  on the dashboard object applies it to every path on that hostname,
  requiring a client certificate on `/hook`, which Anthropic does not send.
  Those keys are refused while the dashboard shares the public hostname;
  set `ingress.dashboard.host` to move it and the restriction lifts.
- `nginx.ingress.kubernetes.io/enable-global-auth` defaults to true. On
  a cluster whose ingress-nginx ConfigMap sets `global-auth-url` (the usual
  way to put oauth2-proxy in front of everything), `/hook` and `/v1` are
  fronted no matter how the objects are split. The chart opts out
  explicitly, and not through a value, because setting it back is the bug.

## Putting oauth2-proxy in front

`oidc_jwt` verifies a token; it signs nobody in. A browser needs something
doing the interactive flow and passing the ID token through. The chart is
pulled by the OCI manifest digest of 7.18.0, which
`helm pull oci://ghcr.io/oauth2-proxy/charts/oauth2-proxy --version 7.18.0`
prints. A different version needs its own digest from the same command.
helm 3.17 or later accepts a digest reference, and from 3.19 helm also
refuses a digest that is not the one `--version` resolves to.

```sh
helm upgrade --install oauth2-proxy \
  oci://ghcr.io/oauth2-proxy/charts/oauth2-proxy@sha256:c413e2fa8dda85a3b7036cfe4382e6c6659afc1df03b314d8ec0eb993c99664a \
  --namespace forgd --version 7.18.0 \
  --set config.existingSecret=oauth2-proxy \
  --set extraArgs.provider=oidc \
  --set extraArgs.oidc-issuer-url="https://login.microsoftonline.com/<tenant>/v2.0" \
  --set extraArgs.set-authorization-header=true \
  --set extraArgs.pass-authorization-header=true \
  --set extraArgs.cookie-refresh=30m \
  --set-string 'ingress.annotations.nginx\.ingress\.kubernetes\.io/proxy-buffer-size=32k'
```

Three of those are not optional:

- **`cookie-refresh` shorter than the token lifetime.** Without it the ID
  token expires inside a session oauth2-proxy still considers valid, so it
  returns 202 with a stale token, the app rejects it, and the user gets a
  raw `authentication_required` with no redirect back to sign-in,
  because nginx only redirects when the *auth subrequest* fails, and it
  didn't.
- **`proxy-buffer-size` above nginx's 4k default.** An Entra ID token is
  large enough that oauth2-proxy splits the session across several
  `Set-Cookie` headers, and the callback response then exceeds the buffer:
  `upstream sent too big header` → 502 on `/oauth2/callback`, after a
  sign-in that succeeded.
- **`set-authorization-header`**, plus
  `nginx.ingress.kubernetes.io/auth-response-headers: Authorization` on the
  dashboard ingress, or the verified token never reaches the app.

Set `dashboard.auth.header=authorization` too: in `oidc_jwt` mode that is
the header the bearer token arrives in, and it defaults to the Container
Apps EasyAuth name.

## Application Gateway for Containers: `ingress.mode: agc`

Microsoft supports the AKS app-routing add-on's managed NGINX through
November 2026. `ingress.mode: agc` serves the same paths through Azure
Application Gateway for Containers instead, with a WAF policy on each route.
The reasoning and the cutover gates are in
[docs/design/agc.md](../../docs/design/agc.md).

The chart renders a Gateway and HTTPRoutes, and no Ingress:

| Route | Paths | Backend | WAF policy |
|---|---|---|---|
| hook | `/hook` | verdict | `hook`: `hook_source_ranges`, then allow |
| public | `/v1`, `/intake`, `/scan` | collector, intake | `api`: allow |
| diagnostics | `/healthz`, `/metrics`, `/health`, `/stats` | verdict, collector | `api` |
| dashboard | `/` | oauth2-proxy | `protected`: DRS 2.1, Bot Manager 1.1 |
| connector | `/mcp` and its metadata | connector | `connector`: `connector_source_ranges`, then allow |

Only the dashboard's route runs the managed rules. The others carry prompt
text, tool output and telemetry, which the rule sets are written to flag,
and a 403 there is a webhook failure or, for the connector, a broken OAuth
discovery.

In order:

1. **Infrastructure.** `network-azure` for the VNet, and `cluster-aks` with
   `ingress = "agc"`, `vnet_subnet_id` and `agc_subnet_id`. Allowlists for
   `/hook` and the connector are `cluster-aks` variables
   (`hook_source_ranges`, `connector_source_ranges`), not chart values.
2. **The ALB Controller**, pinned by digest, into its own namespace, as the
   identity `cluster-aks` federated to it:

```sh
helm upgrade --install alb-controller \
  oci://mcr.microsoft.com/application-lb/charts/alb-controller@sha256:c6c097b2de66d59bff682a03b732bdb9439b788bf190eb1e6043b87c499f4bbd \
  --namespace azure-alb-system --create-namespace --version 1.12.4 \
  --set albController.namespace=azure-alb-system \
  --set albController.podIdentity.clientID=<alb_controller_client_id>
kubectl wait --for=condition=Available deploy/alb-controller -n azure-alb-system --timeout=5m
kubectl get crd gateways.gateway.networking.k8s.io webapplicationfirewallpolicy.alb.networking.azure.io healthcheckpolicy.alb.networking.azure.io
```

   With `grant_alb_controller_node_reader = false`, the controller cannot
   configure AGC until its Reader on the node resource group is granted.
3. **cert-manager** with Gateway API support (`config.enableGatewayAPI=true`)
   and a ClusterIssuer whose HTTP-01 solver uses `gatewayHTTPRoute` with
   the Gateway as its parent. The chart puts `cert-manager.io/cluster-issuer`
   on the Gateway, and gives each HTTPS listener a secret of its own, so
   cert-manager issues one certificate per hostname. With `ingress.tls.secretName`
   set instead, every listener names that one secret, and it must cover every
   hostname.
4. **oauth2-proxy in upstream mode**, in the release's namespace. AGC has no
   auth subrequest, so the proxy sits in the path: the dashboard route sends
   everything to it, and it forwards signed-in requests to the dashboard.
   On top of the install in [Putting oauth2-proxy in front](#putting-oauth2-proxy-in-front),
   set `extraArgs.upstream=http://<release>-forgd-verdict-dashboard.<namespace>.svc:<dashboard.port>`
   and turn its own ingress off (`ingress.enabled=false`). If its pods run
   under a NetworkPolicy, admit AGC's subnet to them.
5. **This chart**, with the module's outputs:

```sh
--set ingress.mode=agc
--set ingress.agc.albId=<alb_id>
--set ingress.agc.frontend=<alb_frontend_name>
--set ingress.agc.wafPolicies.protected=<waf_policy_ids.protected>
--set ingress.agc.wafPolicies.connector=<waf_policy_ids.connector>
--set ingress.agc.wafPolicies.hook=<waf_policy_ids.hook>
--set ingress.agc.wafPolicies.api=<waf_policy_ids.api>
--set ingress.agc.dashboardBackend.name=oauth2-proxy
--set networkPolicy.enabled=true
--set networkPolicy.agc.subnetCidr=<agc_subnet_cidr>
# oauth2-proxy's pods in this namespace, the only peer the dashboard admits:
--set networkPolicy.agc.dashboardProxy.podSelector.matchLabels.app\.kubernetes\.io/name=oauth2-proxy
```

6. **DNS.** A CNAME from each hostname to `alb_frontend_fqdn`.

What the mode changes:

- `ingress.hook.sourceRanges` and `ingress.connector.sourceRanges` are
  refused: AGC's only allowlist is the WAF, set in Terraform.
- Ingress annotations, a `className` other than its default, and changed
  `ingress.gke` values are refused: nothing would read them.
- `ingress.tls.enabled: false` is refused: the only listener left would be
  HTTP.
- `ingress.proxyBodySize` has no AGC setting. AGC's request body limit is
  not published; docs/design/agc.md's first cutover gate measures it.
- AGC's request timeout is 60 s by default and runs while a body is still
  arriving. The hook and public routes set `ingress.agc.publicRequestTimeout`
  (300s).
- `networkPolicy.ingressController` and, with the dashboard routed,
  `networkPolicy.dashboardExtraFrom` are refused, and `networkPolicy.enabled`
  is required: the dashboard admits oauth2-proxy's pods and nothing else.
  `ingress.agc.dashboardBackend.name` may not be the dashboard's own Service.

## What sharing the hostname costs

`ingress.dashboard.host` is empty by default, so the dashboard shares the
public name. That is supported, and it is not free:

- **Its `/healthz` is unreachable.** `/healthz` on that host belongs to the
  verdict server and `/health` to the collector; the dashboard has no third
  alias. `verify_deployment.sh` will probe whichever service owns
  `/healthz`, so the `dashboard.health` assertion means nothing until the
  dashboard has a name of its own. Container Apps gives it one, which is why
  that deployment excludes `/healthz` from its auth provider rather than
  hitting this.
- **Server-scoped annotations are refused.** `auth-tls-*` and
  `server-snippet` configure the whole server block, so they would reach
  `/hook`. The chart refuses them while the host is shared.
- **One certificate covers both.** Only the public object declares `tls`,
  because cert-manager wants a unique `tls.secretName` per Ingress and three
  objects naming one secret is three Certificates racing for it.

Set `ingress.dashboard.host` and all three go away.

## No rewrite, anywhere

ingress-nginx enforces a case-insensitive regex location match on *every*
path of a hostname if `rewrite-target` appears on *any* Ingress for that
host, whichever object defined it.

A rewrite to serve `/verdict/*` and `/collector/*` would make `/hook` and
`/v1` stop being element-wise `Prefix` matches: `/v1anything` and
`/V1/LOGS` would reach the collector, and what kept `/hook` ahead of `/`
would be ingress-nginx's own location ordering rather than the
longest-prefix rule. Routing would work by an implementation detail, and
toggling one unrelated value could change how Anthropic's two paths
match.

So the diagnostics are served on the app's real paths instead. Both the
verdict server and the collector answer `/healthz` and `/health`, so the
two aliases are what let one hostname send a health probe to a chosen
backend; `/metrics` and `/stats` are already unique to one role each. No
prefix to strip means no rewrite to add.

`tests/test_helm_chart.py` covers each of these against what an operator can
set, not only against the default render, where the template controls every
key and a test could not fail.

## The shipped policy's dashboard auth does not port

The repository's `policy.yaml` sets `dashboard.auth.mode: trusted_header`,
with `header: $FORGD_DASHBOARD_HEADER` and `stripped_by:
$FORGD_DASHBOARD_STRIPPED_BY`. Unset, the header falls back to
`x-ms-client-principal-name`, the one Container Apps EasyAuth injects. That
mode is an authentication check only where the proxy in front strips
inbound copies of the header. EasyAuth strips it.

oauth2-proxy has no reason to strip a header named for Azure, and does not.
A dashboard fronted by oauth2-proxy while running this policy unchanged is
therefore not authenticated at all: a caller sets
`x-ms-client-principal-name` itself and is whoever it says. Signing in
through the proxy keeps working, so nothing looks wrong.

The chart refuses to render in this mode until you choose. Two ways
forward:

- **`dashboard.auth.mode: oidc_jwt`** on the chart, with `jwksUrl`,
  `issuer` and `audience`. It verifies a signature against the issuer's
  JWKS (signature, `exp`, `iss`, `aud`), so it trusts an assertion rather
  than a network position. This is the mode that ports.

  It overrides the policy for this deployment only, so one `policy.yaml`
  can serve a Container Apps deployment on `trusted_header` and a
  Kubernetes one on `oidc_jwt`.

  **It does not sign anyone in.** `oidc_jwt` only *verifies* a token, so a
  browser needs something in front that performs the interactive flow and
  passes the ID token through as a bearer token: oauth2-proxy with
  `--pass-authorization-header`, wired up through
  `ingress.dashboard.annotations`.
- **Keep `trusted_header`** and set `dashboard.trustedHeaderStrippedBy` to
  the proxy you have *checked* strips that exact header. The guard records
  the claim next to the deployment that depends on it rather than forbidding
  the mode.

  The proxy strips the header only on requests that pass through it. Any
  pod in the cluster can call the dashboard Service directly, set the
  header and be any user. So `trusted_header` also needs
  `networkPolicy.enabled`, with the ingress controller's namespace and pod
  selectors in `networkPolicy.ingressController`, which renders a
  NetworkPolicy admitting the controller and any peers in
  `networkPolicy.dashboardExtraFrom`. Each of those peers reaches the
  dashboard without passing the proxy, so the chart refuses them unless
  `networkPolicy.dashboardExtraFromTrustedAcknowledged` is true. Where
  something else isolates the dashboard, set
  `networkPolicy.trustedHeaderWithoutPolicyAcknowledged: true` instead.
  The chart refuses `trusted_header` with neither.

## Network policy

`networkPolicy.enabled` renders one NetworkPolicy for each role with a
Service (verdict, collector, dashboard, and intake and connector when
enabled). Each admits ingress on that role's port only from the pods
matched by `networkPolicy.ingressController` (`namespaceSelector` and
`podSelector`, both required together) and from any peers in
`networkPolicy.extraFrom`. The dashboard takes its extra peers from
`networkPolicy.dashboardExtraFrom` instead, and never from `extraFrom`. A
role with no peers at all gets a policy that admits nothing. Egress is not
restricted.

- The cluster's CNI must enforce NetworkPolicy, or the policies are
  accepted and do nothing. `cluster-aks` uses Cilium. On EKS, NetworkPolicy
  is enforced only if the VPC CNI runs with `enableNetworkPolicy`, which
  `cluster-eks` sets by default (`enable_network_policy`). On an EKS cluster
  of your own, enable it on the vpc-cni add-on or run another CNI that
  enforces NetworkPolicy.
- On AKS's app routing add-on the controller runs in `app-routing-system`
  with the label `app: nginx`. Confirm with `kubectl get pods -n
  app-routing-system --show-labels`.
- A load balancer that sends traffic to pod IPs directly (an ALB with
  target-type `ip`, a GKE container-native load balancer) is not a pod. List
  its source ranges as `ipBlock` peers in `extraFrom`, and again in
  `dashboardExtraFrom` for the dashboard. Under `trusted_header` a
  `dashboardExtraFrom` peer can set the header as any user, so the chart
  refuses one unless `dashboardExtraFromTrustedAcknowledged` is true. A
  load balancer that targets pod IPs bypasses the ingress controller, so
  set it only when the load balancer itself strips the header and the
  `ipBlock` holds nothing else.
- Anything else that calls a role from inside the cluster, such as a
  Prometheus scraping `/metrics`, must be listed in `extraFrom`
  (`dashboardExtraFrom` for the dashboard), or it is refused. The
  dashboard serves no `/metrics`, so a scraper never needs
  `dashboardExtraFrom`. Under `trusted_header`, any caller listed there can
  reach the dashboard as any user, and the chart refuses
  it unless `dashboardExtraFromTrustedAcknowledged` is true.
- Under `trusted_header` the chart requires both `ingressController`
  selectors whenever `networkPolicy.enabled` is true, even with
  `trustedHeaderWithoutPolicyAcknowledged`. An `ipBlock` wide enough to hold
  a load balancer's addresses usually holds pod addresses too.

An effective `auth.mode: none` serves every finding to anyone who reaches
the pod. A policy with no `dashboard.auth` resolves to it too. The chart
refuses to render it unless `dashboard.serveOpen` is true, which passes the
dashboard `--serve-open` through `FORGD_DASHBOARD_SERVE_OPEN`; without it
the dashboard would refuse to bind and the pod would restart in a loop.
Set `dashboard.auth`, set `dashboard.enabled: false`, or set
`dashboard.serveOpen: true` where the network in front of the pod is the
control. The chart also refuses `dashboard.serveOpen` under any other
mode, with `dashboard.enabled: false`, or while an Ingress routes the
dashboard: with it, set `ingress.dashboard.enabled: false` and reach the
dashboard with `kubectl port-forward` or a route you control. It refuses
`FORGD_DASHBOARD_SERVE_OPEN`, and every other `FORGD_DASHBOARD_` name, in
`extraEnv`.

## Upgrading: not `--reuse-values`

```sh
helm upgrade forgd deploy/helm/forgd-verdict \
  --namespace forgd \
  --reset-then-reuse-values \
  --set image.tag="$GIT_SHA" \
  --set ingest.image.tag="$GIT_SHA-ingest" \
  --set-file policy.inline=policy.yaml
```

**Both tags, every time.** `ingest.image.tag` is a stored override, so
`--reset-then-reuse-values` carries the previous one forward and
`--set image.tag` does not reach it. Rolling with only `image.tag` moves
the three Deployments and leaves the CronJob on the release before it:
adapter 3 scans against the previous rule set while the inline control
points run the new one. `scripts/deploy_azure.sh` prints the full command
with the tag it just built.

A stored digest is carried forward the same way, and it wins over the tag:
on a release installed by digest, `--set image.tag` changes nothing. Roll
it with both new digests, or clear them with `--set image.digest=` and
`--set ingest.image.digest=`.

`--reuse-values` reuses the previous release's values and does not merge
new chart defaults. So the first upgrade after a version that adds a value
fails on a key that exists in the chart and not in the stored release:

```
Error: UPGRADE FAILED: templates/intake.yaml:1:14
  <.Values.intake.enabled>: nil pointer evaluating interface {}.enabled
```

It fails at render, which is the good case. The bad case is a value the
templates read with `default`: there the upgrade succeeds and quietly runs
on the old value while the new default is what the chart documents.

`--reset-then-reuse-values` takes the chart's defaults and re-applies the
overrides on top, which is what `--reuse-values` reads like it does.

## Adapter 2's receiving end

`intake.enabled=true` adds a fifth role serving `POST /intake`. It is off
by default, because it needs a token and an endpoint with none issued
refuses everything. For a managed fleet set `intake.fleet.enabled=true`
and put the fleet's token in the secret as `intake-fleet-token` (and the
previous one as `intake-fleet-token-previous` while rotating). Agents and
laptops outside a fleet are listed in `intake.clients`, with each token as
`intake-token-<name>`.

### Per-org secrets

Each org's Inference hook signs with its own secret and rotates on its own
schedule, each `compliance.orgs` entry takes its own key, and a fleet per
org has its own token. List the orgs by their `orgIds` name for each role;
the lists are not secret, so a deployment on `secrets.existingSecret` needs
nothing else in values:

| List | Variables | Secret keys |
|---|---|---|
| `verdict.signingOrgs` | `WEBHOOK_SECRET_<NAME>`, `WEBHOOK_SECRET_<NAME>_PREVIOUS` | `webhook-secret-<name>`, `webhook-secret-<name>-previous` |
| `ingest.complianceOrgs` | `ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME>` | `compliance-key-<name>` |
| `intake.fleet.orgs` | `FORGD_INTAKE_FLEET_TOKEN_<NAME>`, `FORGD_INTAKE_FLEET_TOKEN_<NAME>_PREVIOUS` | `intake-fleet-token-<name>`, `intake-fleet-token-<name>-previous` |

`<NAME>` is the name upper-cased with `-` as `_`. The current key is
required and the previous one optional. A Compliance Access Key has no
previous slot: an entry takes one key. For a chart-managed secret, set
`secrets.webhookSecrets.<name>.current` and `.previous`,
`secrets.complianceKeys.<name>` and `secrets.intakeFleetTokens.<name>.current`
and `.previous`. Reference the variables in the policy: `server.secrets`,
each `compliance.orgs` entry's `api_key`, and each `intake.fleet` entry's
`tokens`, with `org: $FORGD_ORG_ID_<NAME>`. `policy.yaml` shows each form.

The chart refuses a name that is not an `orgIds` key, a secret for a name
the list does not hold, and a name whose variable repeats another's or a
single slot's: an org named `previous` would make `WEBHOOK_SECRET_PREVIOUS`.
With a list set, the single-slot secret of that role is optional.

It exists for a credential reason, not a hashing one. Without it a laptop
running the Claude Code hook needs `FORGD_VERDICT_SHIP_STORE`, data-plane
write access to the findings container, and the writer's credential can
replace findings. A developer machine could alter findings in a tool whose output is evidence, and the credential lasts as
long as their Azure session. A bearer token can only append. One laptop on
the fleet token is cut off by denying its device id
(`forgd-verdict overrides deny-device`).

Four properties:

- **Write-only.** There is no read path at all, so a stolen token cannot
  enumerate findings, only add them, or ask `/scan` for a verdict.
- **Tokens can be scoped per route.** `routes` on a fleet or client takes
  `intake`, `scan`, or both (the default). A valid token on a route it is not
  scoped to gets `403`, not `401`, so a scoping mistake does not look like a
  wrong token. The scopes live in `policy.yaml`; the chart only maps names to
  secrets.
- **It refuses any record whose `source` is not `code_hook`.** Otherwise a
  laptop token could forge inference-hook rows and move the numbers the
  dashboard reports: coverage, would-deny rates, live-vs-post-hoc
  reconciliation. The source is asserted by the sender, so it is checked.
- **It serves `/intake`, not `/v1/findings`.** The collector's ingress rule
  is `/v1` as a *prefix*, so a path under it would route to the collector.
  Longest-prefix matching would in fact pick the more specific rule, but
  that is a property of the controller rather than of this chart.

It does not re-hash what it receives, and could not usefully: the hook
hashes at match time with a per-device salt and the plaintext never
leaves the laptop, so there is nothing left to salt. Records carry
`salt_namespace` so a reader knows those hashes are not comparable with the
server's.

### It also serves `/scan`, and that changes what the role needs

A hook can post its payload here and use the verdict that comes
back, so the laptop installs no gitleaks binary and gets the tiers it could
not practically install. That makes this role one that *scans*, on a path a
developer is waiting on, so it is configured like the ones that do:

- **`FORGD_GITLEAKS_SOCKET`, and the matching `daemon` in the policy.**
  Without the daemon the CLI recompiles its rule set on every exec. In this
  role's container in a Helm deployment of the chart, under the 500m CPU
  limit the chart then set, that measured 1.12 s per exec on 2026-09-22, of which
  the scan was 2.7 ms and the rest compiling ~220 rules, against adapter 2's
  200 ms budget.
  The hook times out, falls back to scanning locally and says so on stderr, and the deployment gets less coverage than
  it believes it has.

  The socket alone does nothing. `detectors.gitleaks.daemon` is a policy
  field set per profile, and it is what stops the detector shelling
  out. A role given the socket whose profile does not name it starts a
  daemon it never speaks to.
  `test_every_role_given_the_socket_is_told_to_use_it` pins the two sides
  together.
- **The deployment hash salt.** A `/scan` finding is hashed here, not on the
  laptop, so the reasoning that makes re-hashing an `/intake` record
  pointless does not apply. Without the salt those hashes are bare
  sha256.

The two paths therefore write hashes in two namespaces, which is the same
split adapter 2 already makes.

## What the chart refuses to do

- **Render without a hash salt**, when the chart manages the secret.
  Unsalted, `excerpt_hash` is a plain sha256 of the matched text; an SSN is
  about a billion guesses, so the hash of a leaked SSN is the SSN. With
  `secrets.existingSecret`, a missing `hash-salt` key stops the pod from
  starting, but an empty value is not caught.
- **Give the dashboard the writer identity, or the same client id as the
  writer.** It is the one service a human signs into; a compromise that
  could rewrite findings would be rewriting the evidence.
- **Put a credential in `extraEnv`.** `extraEnv` reaches every workload,
  the dashboard and the connector included, and is stored in the release
  in plaintext. A key that, upper-cased, names a variable the chart wires
  from a Secret is refused: `FORGD_HASH_SALT`, `WEBHOOK_SECRET`,
  `WEBHOOK_SECRET_PREVIOUS`, `ANTHROPIC_COMPLIANCE_ACCESS_KEY`,
  `FORGD_METRICS_TOKEN`, `FORGD_DASHBOARD_FORM_KEY`,
  `FORGD_OVERRIDES_SIGNING_KEY`, `FORGD_SHARED_HEADER`, and any name
  starting `FORGD_OTEL_TOKEN_`, `FORGD_INTAKE_TOKEN_`,
  `FORGD_MANAGED_AGENTS_KEY_`, `FORGD_SINK_TOKEN_` or
  `FORGD_SHARED_HEADER_`. The error names the key and the `secrets.*`
  value or `secrets.existingSecret` key to use instead, and not the value.
  So the salt cannot reach the dashboard or the connector this way.
- **Let `extraEnv` replace a setting the chart sets or checks.** `extraEnv`
  is emitted after the chart's own entries, and Kubernetes keeps the last
  of two entries with one name, so `extraEnv.FORGD_DASHBOARD_AUTH_MODE`
  would run the dashboard on a mode the chart never checked. Refused:
  `FORGD_ROLE`, `PORT`, `FORGD_INGEST_ARGS`, and any name starting
  `FORGD_VERDICT_`, `FORGD_POLICY_`, `FORGD_DASHBOARD_`,
  `FORGD_CONNECTOR_`, `FORGD_OVERRIDES_`, `FORGD_ORG_ID_` or
  `FORGD_GITLEAKS_`. So is a cloud identity or credential: any name
  starting `AZURE_` or `AWS_CONTAINER_`, the AWS credential, role and
  profile variables, and `GOOGLE_APPLICATION_CREDENTIALS`, since the
  chart gives the dashboard and the connector the reader's identity and
  `extraEnv` would give every workload one. The error names the value to
  set instead.
- **Render an OTel token with no matching `orgIds` entry.** `policy.yaml`
  pairs each token with `otel.orgs[].id` and cross-checks the payload's
  `organization.id` against it, but the check cannot fire on an empty id,
  so a batch from any organization would be accepted on that token and
  stored under the wrong org with nothing reporting it.
- **Render without `store.url`.** An empty value means a
  deployment that persists nothing. `_apply_env_overrides` skips an empty
  string, so `store: $FORGD_VERDICT_STORE` resolves to none and
  `policy.yaml` disables the store: pods pass readiness, the dashboard
  renders, and no finding is ever written.
- **Render without `image.repository`**, which would produce `image: :<tag>`,
  accepted by `helm lint` and `kubectl --dry-run`, rejected by the kubelet
  as `InvalidImageName`.
- **Default either half of the ingest image.** On the base image the
  Presidio tier is absent, so the run completes and reports a *clean scan*.
  A forgotten value must not read as "no PII anywhere".

  The tag is the half that carries the variant. One repository is tagged
  twice (`forgd-verdict:<sha>` and `forgd-verdict:<sha>-ingest`), so
  `ingest.image.repository` is normally the same string as
  `image.repository`, and requiring it alone would prove nothing while the
  tag fell back to `image.tag`. No separate `forgd-verdict-ingest`
  repository is built.

- **Accept a malformed digest.** `image.digest` and `ingest.image.digest`
  must be `sha256:` and 64 lowercase hex characters. A whole reference or
  a bare hex string fails the render rather than reaching the kubelet.
- **Enable TLS with neither an issuer nor a secret name**, which leaves
  nginx serving its self-signed default: a click-through warning on the
  dashboard, and a TLS verification failure that Anthropic's exporter
  reports as a delivery failure.
- **Let `podLabels` or `podAnnotations` replace what the chart sets.** A
  `podLabels` key under `app.kubernetes.io/`, `helm.sh/` or
  `azure.workload.identity/` would move a pod under another Service or
  NetworkPolicy, or off its workload identity; a `podAnnotations` key
  setting an AppArmor or seccomp profile would loosen the one the
  securityContext sets.
- **Route an open dashboard.** `dashboard.serveOpen` is refused while the
  chart renders an Ingress route to the dashboard. Set
  `ingress.dashboard.enabled: false` and reach it with
  `kubectl port-forward` or a route you control.
- **Put a sink token or a shared header value in the policy.** A literal
  `sinks[].token` or `server.required_headers` value would sit in the
  policy ConfigMap, which every workload mounts. Each must be a
  `$FORGD_SINK_TOKEN_<NAME>` or `$FORGD_SHARED_HEADER[_<NAME>]` reference;
  see [Sink tokens and shared headers](#sink-tokens-and-shared-headers).
- **Scale the verdict server or the collector past one replica** without
  `sharedStateAcknowledged: true`. The session cache, the webhook-id dedupe
  store and the store sink queue are per-process: a second replica runs
  without error, but makes the latency numbers meaningless and breaks the backpressure
  that makes an exporter hold a batch instead of dropping it.

## Secrets

The chart will create a Secret from values for a lab, and says so in its
install notes. Those values land in the release object and `helm get values`
prints them, so anything else should point `secrets.existingSecret` at
external-secrets or the CSI driver.

### An OTel token needs an org id beside it

`secrets.otelTokens.<name>` without a matching `orgIds.<name>` is refused.
`policy.yaml` pairs each token with `otel.orgs[].id`, and the payload's
`organization.id` is cross-checked against it, but the check reads
`if claimed and org["id"] and claimed != org["id"]`, so an empty id cannot
make it fire and a batch from any organization is accepted on that token.
Nothing reports it: the records store successfully, attributed to the wrong
org.

The reverse is fine and is not refused. An org served only by the Compliance
API or the inference hook has no OTel token; a Team workspace is the
opposite case, with no Compliance API at all, and still has an org UUID.

A fleet exporter token, one token valid for several orgs, is listed in
`otelFleets.<fleet>` by the orgs' `orgIds` names, with the token as
`secrets.otelTokens.<fleet>` or the `otel-token-<fleet>` key. It becomes
`FORGD_OTEL_TOKEN_<FLEET>` for an `otel.orgs` entry with
`ids: [$FORGD_ORG_ID_<NAME>, ...]`. The chart refuses a fleet that names
no org, an org with no `orgIds` entry, an org id in place of a name, or
a fleet named like an org.

### Sink tokens and shared headers

The policy decides which keys are read. A `sinks[].token` written as
`$FORGD_SINK_TOKEN_<NAME>` becomes `FORGD_SINK_TOKEN_<NAME>` on the
collector, from the key `sink-token-<name>` (`<name>` lower-cased, `_` as
`-`), and on no other workload. A `server.required_headers` value written
as `$FORGD_SHARED_HEADER` comes from `shared-header`, and
`$FORGD_SHARED_HEADER_<NAME>` from `shared-header-<name>`, on the verdict
server alone. With a chart-managed Secret the values are
`secrets.sinkTokens.<name>`, `secrets.sharedHeader` and
`secrets.sharedHeaders.<name>`; the chart refuses one the policy names and
the values lack, and one the policy does not name. A key missing from
`secrets.existingSecret` stops the pod from starting.

### Rotating the signing secret

Set `secrets.webhookSecretPrevious` to the outgoing value, put the new one
in `secrets.webhookSecret`, roll, change it on the Anthropic side, then drop
it. `policy.yaml` accepts both, so there is no window in which a frame
signed with the old secret is rejected, and a rejected frame is a webhook
*failure*, not a deny.

## Dashboard admins

Runtime overrides from the dashboard ([docs/OVERRIDES.md](../../docs/OVERRIDES.md))
are off by default, and with them off the chart renders exactly as it
does without these values.
`dashboard.admins.enabled: true` does seven things:

- renders `serviceAccounts.control`, labelled `forgd.ai/store-access:
  control`, and runs the dashboard on it. The connector stays on the reader.
  Give it the store's control identity: `clientId` from store-azure's
  `control_identity_client_id`, or on EKS and GKE the annotation naming
  store-s3's `control_role_arn` or store-gcs's `control_email`. The
  `cluster-*` modules federate it with `control_enabled`;
- sets the dashboard's `AZURE_CLIENT_ID` to the control client id;
- passes `FORGD_DASHBOARD_FORM_KEY` from the secret key
  `dashboard-form-key`: `secrets.dashboardFormKey` when the chart makes the
  Secret, or that key in `secrets.existingSecret`;
- passes `FORGD_OVERRIDES_SIGNING_KEY`, the Ed25519 private key the
  dashboard signs every runtime-override record with, to the dashboard
  only, from the Secret `dashboard.admins.signingKey.secretName` (else
  `secrets.existingSecret`) under the key `dashboard.admins.signingKey.key`,
  `overrides-signing-key` by default. The chart-managed Secret never holds
  it. Create the Secret yourself, then put the printed `public_key` in
  `dashboard.admins.verifyKeys`:

  ```sh
  forgd-verdict overrides keygen --private-key-file signing.key
  kubectl create secret generic forgd-overrides-signing \
    --from-file=overrides-signing-key=signing.key
  rm signing.key
  ```

  or add the key to the Secret `secrets.existingSecret` names;
- sets `FORGD_OVERRIDES_VERIFY_KEY` on every workload to
  `dashboard.admins.verifyKeys` joined with `,`: the public keys records are
  verified with, including the signing key's. See "Signing keys" in
  [docs/OVERRIDES.md](../../docs/OVERRIDES.md) for generating and rotating
  them;
- sets `FORGD_OVERRIDES_ENABLED=true` on every workload. A service honours
  runtime overrides only with it and admin groups in the policy.
  After the first install or upgrade with admins on, run
  `forgd-verdict overrides init` once as the control identity, or use
  **Initialise** on the dashboard: until then every workload without a
  last-known-good is not ready;
- sets `FORGD_OVERRIDES_WRITER_ROLES` on every workload to one writer role
  per distinct store identity. Every writer workload runs as the writer
  service account, so it is the first of `verdict`, `collector`, `intake`
  and `ingest` whose `.enabled` is true: `ingest` only when none of the
  long-running writers is deployed. The ingest CronJob also runs the
  Managed Agents pass, under the same role. The dashboard and the connector
  only read, and are never listed. With the defaults it is `verdict`.

The chart refuses to render with admins on and a control client id or
role annotation equal to the reader's or the writer's, a control service
account name another role uses, no form key in a chart-managed Secret, no
Secret for the signing key, an empty `verifyKeys` or an entry that is not 43
characters of unpadded URL-safe base64, an
effective `dashboard.auth.mode` other than `oidc_jwt`, or
`dashboard.auth.platform: iap`, whose tokens carry no groups. It also
refuses a policy that sets `dashboard.admins.groups` while
`dashboard.admins.enabled` is false.

With admins on, `/readyz` on every role answers 503 while a pod that
started without a last-known-good cannot confirm the runtime overrides:
the store is unreadable, the object is invalid, the object is absent
while audit records exist, or a writer role's lockout is not proven. The
readiness probe on `/readyz`, on every Deployment, keeps that pod out of
its Service until it is ready. The liveness probe on `/livez` never fails
for it. The verdict server, collector and intake also have a startup
probe on `/readyz`, so one that is not ready within 60 s of starting is
restarted by the kubelet; the dashboard and the connector stay running
out of service. In GKE mode each BackendConfig's health check requests
`/readyz` too. With admins off, every one of these requests `/healthz`,
which answers 200 however the overrides read. Pods that were already
running keep serving. If every pod of
the verdict server restarts during a store outage, governed prompts have
no endpoint until it ends. See "Readiness" in
[docs/OVERRIDES.md](../../docs/OVERRIDES.md).

## No PodDisruptionBudget, and no HPA

Every role runs one replica, so `minAvailable: 1` blocks node
drains permanently and `0` does nothing. A drain takes the verdict server
down for as long as the reschedule takes; `observe` mode and the circuit
breaker are what make that survivable, and an HPA would trade a real
invariant for an availability number.

## The ingest cursor

There is no volume. The cursor
lives in the findings store, which is already durable and already reachable
with the identity the job holds. An `emptyDir` would not work: it
persists within a replica, and a scheduled job gets a new replica every
run.
