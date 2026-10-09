# Deploying

Every deployment has a findings store and the services that write to and
read from it. Terraform creates the cloud resources. On a managed container
service it creates the services too; on Kubernetes the Helm chart deploys
them into a cluster that Terraform built or that you already run. Why it is
split this way is in [DESIGN.md § Two deployment
wrappers](DESIGN.md#two-deployment-wrappers-not-one-path-per-target).

To try it on one machine first, see [QUICKSTART.md](QUICKSTART.md).

## Choose a target

| Cloud | Managed containers | Kubernetes | Findings store |
|---|---|---|---|
| Azure | `app-aca` (Container Apps) | `cluster-aks` + the chart | `store-azure` |
| AWS | `app-ecs` (ECS Fargate) | `cluster-eks` + the chart | `store-s3` |
| Google Cloud | `app-cloudrun` (Cloud Run) | `cluster-gke` + the chart | `store-gcs` |

The modules are under
[`deploy/terraform/modules/`](../deploy/terraform/modules) and the chart is
[`deploy/helm/forgd-verdict`](../deploy/helm/forgd-verdict). Every path
uses its cloud's store module, and none of the app or cluster modules, nor
the chart, creates a store, so a `terraform destroy` of the compute or a
`helm uninstall` leaves the findings in place.

On a cluster you already run, skip the cluster module. Apply the store
module, give the chart's writer and reader service accounts access to the
store's identities yourself, and install the chart. The cluster modules show what
that binding looks like on each cloud.

What each module creates:

| Module | Creates |
|---|---|
| `store-azure` | a storage account and a private container; writer, reader and, with `control_enabled`, control user-assigned identities, and their role assignments. With `control_enabled`, a `CanNotDelete` lock on the account as well |
| `store-s3` | a versioned, encrypted bucket with public access blocked; writer, reader and optional control IAM roles. It takes each role's trust policy as an input. Neither role can delete an object |
| `store-gcs` | a versioned bucket with public access prevention, optionally encrypted with a KMS key you supply; writer, reader and optional control service accounts, and the bucket bindings for them and for any `writer_members` / `reader_members` |
| `app-aca` | a Container Apps environment; verdict, collector and dashboard apps, intake and the findings connector when enabled, ingest as a Container Apps job; Easy Auth on the dashboard when `dashboard_auth_client_id` is set |
| `app-ecs` | an ECS cluster; Fargate services for verdict, collector, dashboard and, when enabled, intake and the connector; an ALB with OIDC sign-in on the dashboard host only; ingest as a task on an EventBridge schedule; one execution role per service and a scheduler role |
| `app-cloudrun` | Cloud Run services for verdict, collector, dashboard and, when enabled, intake and the connector; ingest as a Cloud Run job on Cloud Scheduler; IAP on the dashboard only; one service account per role and one for the scheduler |
| `cluster-aks` | an AKS cluster with an OIDC issuer; federated credentials from the store's identities to the chart's service accounts; `AcrPull` for the kubelet when `registry_id` is set |
| `cluster-eks` | an EKS cluster and node group, a KMS key for Kubernetes secrets unless you pass one; EKS Pod Identity associations from the store's roles to the chart's service accounts, or IRSA with `identity_mode = "irsa"`; the AWS Load Balancer Controller's role (on by default), though not the controller itself |
| `cluster-gke` | a GKE Autopilot cluster; `roles/iam.workloadIdentityUser` on the store's service accounts for the chart's service accounts |
| `monitor-azure` | optional: a Log Analytics workspace, a data collection endpoint and rule, and the role assignments adapter 5's Azure Monitor sink needs. Nothing else references it |
| `ci-aws` | the IAM role, trusted through GitHub OIDC, that `scripts/deploy_aws.sh` runs as to roll images. The role itself can create nothing |
| `ci-gcp` | the service account, impersonated through Workload Identity Federation, that `scripts/deploy_gcp.sh` runs as to roll images |

No cluster module installs anything into the cluster: none of them has a
`helm` or `kubernetes` provider. Each prints the commands that come next as
outputs.

## Where the identities come from

The identities that reach the store are created by the store module,
together with the bucket or container. The app and cluster modules only
attach them to workloads. Cloud Run is the exception.

| Path | Store identities created by | Attached to workloads by |
|---|---|---|
| Container Apps | `store-azure` | `app-aca`, as user-assigned identities on each app |
| AKS | `store-azure` | `cluster-aks` federates them to the chart's Kubernetes service accounts, which the chart creates |
| ECS | `store-s3`, with an ECS tasks trust policy you pass in | `app-ecs`, as each task's task role |
| EKS | `store-s3`, with the trust policy `cluster-eks` outputs | `cluster-eks`, through Pod Identity associations |
| Cloud Run | `app-cloudrun`, one service account per role | `store-gcs` grants those accounts bucket access through `writer_members` and `reader_members`. Its own writer and reader accounts are still created and nothing runs as them |
| GKE | `store-gcs` | `cluster-gke` binds them to the chart's Kubernetes service accounts through Workload Identity |

Verdict, collector, intake and ingest run as the writer. The dashboard
runs as the reader. When [dashboard
admins](../deploy/terraform/README.md#dashboard-admins-the-control-identity)
are enabled it runs as the control identity instead, which holds the
reader's access as well: the control role on ECS, the control client id
on Container Apps, and the control service account in the chart.

## Order of operations

The store module and the app or cluster module are composed in one
Terraform root, and Terraform orders them. That is how the AKS example
and the ECS, Cloud Run and EKS compositions in the Terraform README are
written. The GKE example instead applies `store-gcs` first and passes its
outputs to `cluster-gke`. The cross-references are not a cycle. On AWS the
trust policies are built from names, not read from a cluster. On Cloud
Run, `store-gcs` takes `app-cloudrun`'s accounts as input, and
`app-cloudrun` takes `store-gcs`'s `store_url`.

1. **Before Terraform.**
   - **Azure:** `scripts/bootstrap_tfstate.sh` creates the state backend
     and the identity that applies. `scripts/bootstrap_target_rg.sh`
     creates the resource group a stack deploys into, because that
     identity is scoped to resource groups and cannot create one.
   - **ECS and Cloud Run:** create each application secret first, in
     Secrets Manager or Secret Manager. Use a placeholder where Anthropic
     has not issued the value yet. These modules take secret ids, not
     values.
2. **Apply the root.** That creates the store, its identities and the app
   or cluster.
3. **Install the workloads.** On a managed target the apply has already
   created them. On Kubernetes:
   - **AKS:** `scripts/bootstrap_aks.sh` gives the cluster a hostname and
     a certificate. Then run `terraform output -raw helm_install_command`
     from `examples/aks`. See [Standing up a
     cluster](../deploy/helm/README.md#standing-up-a-cluster).
   - **EKS:** run the `kubeconfig_command`, `lb_controller_install_command`
     and `lb_controller_namespace_command` outputs in that order, then
     install the chart with `helm_values_hint`. See [Installing into the
     cluster](../deploy/terraform/README.md#installing-into-the-cluster).
   - **GKE:** reserve the load balancer's address, enable IAP, then
     install. The procedure is the header of
     [`values-gke.example.yaml`](../deploy/helm/forgd-verdict/values-gke.example.yaml).
4. **Point names at it.** On ECS, point each host at `alb_dns_name` and
   register `oidc_redirect_uri` with your identity provider.
5. **Verify.** Run `scripts/verify_deployment.sh`, described below.
   `app-aca` and `app-ecs` print the command as their `verify_command`
   output. On Kubernetes, run it against the ingress hostname once the
   chart is installed.

The chart refuses to render with the repository's `policy.yaml` as it
stands. That file's dashboard auth mode is only a check behind Container
Apps Easy Auth, so the chart makes you choose another. See [The shipped
policy's dashboard auth does not
port](../deploy/helm/README.md#the-shipped-policys-dashboard-auth-does-not-port).

## Verify the deployment

```
scripts/verify_deployment.sh <verdict-url> <collector-url> <dashboard-url>
```

Each argument is a base URL with a scheme and no path. Pass an empty string
for a service that is not deployed. Leaving an argument out is a usage
error, so a service cannot be dropped by forgetting it. The script exits 0
when every assertion on every deployed service passed, 1 when any failed,
and 2 on a usage error, including all three URLs empty with neither an
intake nor a connector URL set. It runs every assertion even after one fails.

It uses observed HTTP responses only, so it needs no cloud credential and
works against any target. It does not follow redirects.

| Service | Assertion |
|---|---|
| verdict | `/healthz` answers 200; an unsigned `POST /hook` gets 401 |
| collector | `/health` answers 200; an unauthenticated `POST /v1/logs` gets 401 |
| dashboard | `/healthz` answers 200; `GET /` and `GET /api/summary` each get 401, or a redirect to a sign-in page. A 200, a 403, or a redirect anywhere else fails |
| intake | only with `FORGD_INTAKE_URL` set: `/healthz` answers 200; an unauthenticated `POST /intake` and `POST /scan` each get 401 |
| connector | only with `FORGD_CONNECTOR_URL` set: an unauthenticated POST gets a 401 whose `WWW-Authenticate` points at the protected-resource metadata, and that metadata names the URL. A redirect fails |

A redirect to a login page on the verdict server, the collector or the
intake fails as `*.no-auth-redirect`. None may sit behind a platform auth
provider: Anthropic authenticates to the first two with a webhook signature
and an OTLP header, and a laptop to the intake with a bearer token, so a
login redirect turns every governed prompt, export or shipped batch into a
delivery failure.

On the dashboard a sign-in page is recognised by its host (Entra ID, Google,
Okta, Auth0, Cognito, Cloudflare Access), its path (Easy Auth's
`/.auth/login`, oauth2-proxy's `/oauth2/start`, Keycloak's
`/protocol/openid-connect/auth`, or a path containing `login`, `signin`,
`saml` or `sso`), or an OAuth authorization request (`client_id` and
`response_type` in the query, as an ALB's `authenticate-oidc` sends) or a
SAML request. A redirect elsewhere, such as an HTTP-to-HTTPS upgrade or a
proxy's path rewrite, fails: pass the URL the dashboard answers on. A 403
fails because a WAF or an IP allow-list in front of an open dashboard sends
one too, and the dashboard never does to an unauthenticated caller; a front
end that answers 403 for "not signed in" (Easy Auth's `Return403`) has to
redirect or answer 401 instead.

Environment variables it reads:

| Variable | Default | Meaning |
|---|---|---|
| `VERIFY_READY_TIMEOUT_S` | 240 | how long to wait for each health check to answer 200 |
| `VERIFY_REQUEST_TIMEOUT_S` | 15 | per-request timeout |
| `VERIFY_POLL_INTERVAL_S` | 6 | gap between health polls |
| `VERIFY_MAX_UPTIME_S` | unset | when set, `/healthz` must report `uptime_s` below it. A deploy sets it so the checks run against the revision it just rolled, not the one it replaced |
| `FORGD_INTAKE_URL` | unset | the intake's base URL. Set, the intake is checked as above; the deploy scripts set it from `AZURE_INTAKE_APP`'s address or pass it through from the CD's variables |
| `FORGD_DASHBOARD_IAP` | unset | `1` when the dashboard is behind Identity-Aware Proxy, as on Cloud Run and GKE: its `/healthz`, `/` and `/api/summary` must redirect to `https://accounts.google.com/`, and freshness is not checked |
| `FORGD_CONNECTOR_URL` | unset | the findings connector's MCP URL, as entered in Claude; enables the connector checks |

What it does not check:

- **A 401 from an auth front end passes for the wrong reason.** If a proxy
  in front of the verdict server or the collector answers 401 instead of
  redirecting, the unsigned-request assertion passes. A correctly signed
  request from Anthropic is then refused as well. The script prints a NOTE
  when the 401 carries no JSON error body, but it does not fail on it. A
  passing run is not evidence that platform auth is off.
- **That a signed request is accepted, or that a finding reaches the
  store.** It sends no signed request and no valid export.
- **Ingest, and the intake without `FORGD_INTAKE_URL`.** Neither is
  probed. The intake's checks share the gap above: a front end answering
  401 in front of `/intake` or `/scan` passes, while refusing every
  laptop's bearer token too, and no NOTE is printed for it.
- **The dashboard's health on a shared hostname.** When the chart serves
  the dashboard on the same host as the verdict server, `/healthz` there
  belongs to the verdict server, so `dashboard.health` passes against it.
  Give the dashboard its own host with `ingress.dashboard.host` for that
  assertion to mean anything. See [What sharing the hostname
  costs](../deploy/helm/README.md#what-sharing-the-hostname-costs).

## After the first deploy

Terraform does not roll images. The app modules ignore changes to the
image, or to the task definition on ECS, and the chart takes the tag from
`helm upgrade`. The deploy scripts roll images and then run
`verify_deployment.sh`:

- `scripts/deploy_azure.sh` rolls Container Apps or builds for AKS, chosen
  by `AZURE_DEPLOY_TARGET`. With `k8s` it builds and pushes the images and
  prints the `helm upgrade` to run.
- `scripts/deploy_aws.sh` rolls ECS or EKS, chosen by `AWS_DEPLOY_TARGET`.
- `scripts/deploy_gcp.sh` rolls Cloud Run or GKE, chosen by
  `GCP_DEPLOY_TARGET`.

`ci-aws` and `ci-gcp` create the identities the AWS and GCP scripts run
as. See [Terraform owns infrastructure; CI owns image
rolls](../deploy/terraform/README.md#terraform-owns-infrastructure-ci-owns-image-rolls)
and [Running it from CI](../deploy/terraform/README.md#running-it-from-ci).

**Recommended hardening: a source allowlist on the hook path.** The
verdict server reads a hook body before it can verify the signature over
it, so anyone who can reach the URL can fill its pre-auth body budget and
make governed prompts fail with 503 while it is full. Admitting only
Anthropic's Inference hooks egress range on `/hook` removes that. It ships
off because a stale range fails every governed prompt; check Anthropic's
published IP addresses first. See [SERVER.md § Deploy](SERVER.md#deploy)
for the chart's `ingress.hook.sourceRanges`, the Caddyfile matcher and the
other platforms.

## Laptops

Adapter 2, the Claude Code hook, runs on developer machines rather than in
the cloud. Distributing it as a managed hook through Intune or Jamf is
covered in [deploy/MDM.md](../deploy/MDM.md).

## Reference

- [deploy/terraform/README.md](../deploy/terraform/README.md): every module,
  how each pair composes, secrets in state, Terraform version.
- [deploy/helm/README.md](../deploy/helm/README.md): installing the chart,
  ingress, dashboard auth, secrets, upgrades.
- [`values-eks.example.yaml`](../deploy/helm/forgd-verdict/values-eks.example.yaml)
  and [`values-gke.example.yaml`](../deploy/helm/forgd-verdict/values-gke.example.yaml):
  starting values for EKS and GKE. On AKS the install command comes from
  the root's `helm_install_command` output instead.
- [`deploy/terraform/examples/aks`](../deploy/terraform/examples/aks): the
  AKS root, composing `store-azure`, `cluster-aks` and, when enabled,
  `monitor-azure`.
