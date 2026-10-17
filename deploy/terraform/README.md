# Terraform

Twelve modules, composed by one root per deployment.

```
modules/store-azure/   the findings store and the identities that reach it
modules/store-s3/      the same on AWS: a bucket, and writer and reader roles
modules/store-gcs/     the same on Google Cloud: a bucket, and writer and reader service accounts
modules/app-aca/       the five roles as Container Apps
modules/app-ecs/       the same on AWS: Fargate services, an ALB, ingest on a schedule
modules/app-cloudrun/  the same on Google Cloud: Cloud Run services, IAP on the dashboard, ingest as a scheduled job
modules/cluster-aks/   an AKS cluster, and the federation the chart needs
modules/cluster-eks/   the same on AWS: an EKS cluster, and the pod identities the chart needs
modules/cluster-gke/   the same on Google Cloud: a GKE Autopilot cluster, and the Workload Identity bindings the chart needs
modules/monitor-azure/ adapter 5's Azure Monitor destination (optional)
modules/ci-aws/        the AWS CD role that scripts/deploy_aws.sh runs as
modules/ci-gcp/        the GCP CD service account that scripts/deploy_gcp.sh runs as
examples/aks/          the AKS root
```

A root outside this repository sources a module by git ref at a release
tag, so the modules match the release's images and chart:

```hcl
module "cluster" {
  source = "git::https://github.com/forgd-ai/forgd-verdict.git//deploy/terraform/modules/cluster-aks?ref=vX.Y.Z"
  # ...
}
```

Any module above works the same way. Each one stands alone: it names no
module by a local path and reads no file outside its own directory.
`examples/aks` uses relative paths because it lives beside them; copied
out of this repository, its three `source` lines become git sources like
the one above.

`monitor-azure` is off unless `enable_azure_monitor` is set. It creates
a Log Analytics workspace, which bills per GB ingested and per GB retained,
and a fork should choose that rather than inherit it. Nothing else in the
stack references it, so turning it off destroys three resources and leaves
the findings store alone.

It produces one thing the deployment needs, `terraform output -raw
azure_monitor_sink_endpoint`, which goes verbatim into `sinks[].endpoint`.
The host alone is not enough: the sink refuses it at startup, because the
host is what the portal shows and the full URI is what does not 404 at send
time.

The identity needs Monitoring Metrics Publisher on both the rule and the
endpoint. They are separate scopes, a grant on one does not cover the
other, and the 403 you get names neither. The module assigns both.

`modules/app-aca` is supported. A fork wanting Container Apps composes it
with `store-azure` in a root of its own; the variables in
`modules/app-aca/variables.tf` describe each input.

**`store-azure` is the module every path needs.** A cluster still needs
somewhere to put findings and an identity allowed to write there, so the
Kubernetes path composes the same module unchanged and adds a cluster
beside it. Neither `app-aca` nor `cluster-aks` creates a store: findings
outlive both, and a `helm uninstall` or a `terraform destroy` must not be
able to take the evidence with it. See `DESIGN.md` § Two deployment
wrappers.

**With `control_enabled` false, `store-azure` assigns the built-in
roles**: Storage Blob Data Contributor to the writer and Storage Blob
Data Reader to the reader, with no new permission needed to apply it. With
`control_enabled` true it defines custom roles instead, so the apply needs
`Microsoft.Authorization/roleDefinitions/write` on the resource group
(Owner or User Access Administrator). The writer then holds a role with
blob `read`, `write` and `add/action`, and the reader one with blob `read`,
both with no control-plane action, so neither can delete a blob or delete
or recreate the container. The custom assignments are created beside the
built-in ones before those are removed, and the reverse when the flag
turns off, so neither identity is left without a role. See "Azure
(`store-azure`)" in
[docs/design/overrides.md](../../docs/design/overrides.md#azure-store-azure).

**`store-azure` turns shared key access off** (`shared_access_key_enabled`,
default `false`). A shared key authorizes any request on the account,
bypassing every role assignment and condition above, and anyone with
Contributor on the account can list the keys. No forgd-verdict component
uses one.

With keys off, the azurerm provider must not use the account's data
plane with a key either, and the infra identity holds no data role to use
it with Entra ID. `examples/aks` therefore sets `storage_use_azuread =
true` and `features { storage { data_plane_available = false } }` whenever
`shared_access_key_enabled` is false. A root of your own composing
`store-azure` needs the same provider settings. If you already have an
account, the next plan turns its keys off in place: anything outside
Terraform that signs with a key stops working, and a provider without these
settings fails to read the account. Set `shared_access_key_enabled = true`
to keep the keys.

**`store-azure` keeps a deleted container for 30 days**
(`container_delete_retention_days`, default `30`; `0` or `null` turns it
off). Blob soft delete and versioning do not cover deleting the container
itself, which deletes every blob in it. Without `control_enabled` the
writer's Storage Blob Data Contributor includes `containers/delete`, and
container soft delete is what makes such a delete restorable. If you already
have an account, the next plan turns container soft delete on in place.

`store-s3` is the AWS counterpart. It takes each role's trust policy as an
input, because it cannot tell whether EKS or ECS will assume the role.
Neither role can delete an object or a version: their policies grant no
`s3:Delete*`, and the bucket policy denies deletes to both, so a policy
attached to either role later cannot grant one either.

## `store-gcs`

`store-gcs` is the Google Cloud counterpart: a versioned bucket with
uniform bucket-level access, public access prevention enforced and
`force_destroy = false`, an optional Cloud KMS key, and two service
accounts. It binds no workload to either account. `cluster-gke` grants
`roles/iam.workloadIdentityUser` on each to the chart's Kubernetes service
account; on Cloud Run, attach the account to the service.
`writer_members` and `reader_members` add identities that get exactly the
writer's or the reader's bucket bindings; `app-cloudrun` uses them.
Its `store_url` output is `FORGD_VERDICT_STORE`, and the image needs the
`gcp` extra, which `deploy/Dockerfile` installs.

**The writer can delete cursors and markers, and cannot delete findings.**
GCS checks `storage.objects.delete` on any write that replaces an object,
so the store cannot overwrite its cursors or markers without it. The
writer gets `roles/storage.objectCreator` and `roles/storage.objectViewer`
on the bucket, plus a custom role holding only `storage.objects.delete`,
bound on the bucket with an IAM condition that matches exactly:

```
resource.name.startsWith("projects/_/buckets/<bucket>/objects/<prefix>/state/")
resource.name == "projects/_/buckets/<bucket>/objects/<prefix>/markers/stats_reset"
resource.name == "projects/_/buckets/<bucket>/objects/<prefix>/markers/excluded_requests"
```

Nothing under `verdicts/` or `denials/` matches, and records are written
with `if_generation_match=0`, so they are create-only. What the writer
can delete costs no evidence: losing a cursor costs a rescan, and losing a
marker costs an exclusion or a reset, which can be redone. Versioning
keeps every replaced cursor and marker as a noncurrent version, and there
is no lifecycle rule to expire them.

The reader, for the dashboard, gets `roles/storage.objectViewer` and
nothing else. The custom role is defined in the project, because GCS has no
bucket-level custom roles, but bound only on the bucket. A deleted custom
role keeps its id for 37 days, so re-creating the module in that window
needs a new `mutable_delete_role_id`.

**Give the store a dedicated bucket.** With `key_prefix` set, the create
and read bindings of both accounts carry a condition, `resource.name ==
"projects/_/buckets/<bucket>" || resource.name.startsWith(
"projects/_/buckets/<bucket>/objects/<prefix>/")`, which limits create
and get to objects under the prefix. The bucket clause is needed because
GCS checks `storage.objects.list` on the bucket, not on an object, so it
cannot be scoped by name: both accounts can list every object name in the
bucket, including names outside the prefix. They cannot read those
objects. With an empty `key_prefix` the bindings are unconditioned and
cover the whole bucket.

`tests/test_store_gcs_module.py` evaluates the condition and matches it
against the object names `GCSStore` writes, and fails on any other delete
grant, on a broadened condition, on reader delete, on a create or read
binding that loses its prefix condition, and on a project-level storage
binding.

## Composing `app-ecs` with `store-s3`

`app-ecs` creates no store and no application identity. The task roles are
`store-s3`'s: the writer role for verdict, collector, intake and ingest, the
reader role for the dashboard. On ECS both trust `ecs-tasks.amazonaws.com`,
with `aws:SourceAccount` so that a task in another account cannot present
itself as this one's:

```hcl
data "aws_caller_identity" "current" {}

locals {
  ecs_tasks_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

module "store" {
  source                    = "../modules/store-s3"
  bucket_name               = "forgd-findings-example"
  writer_assume_role_policy = local.ecs_tasks_trust
  reader_assume_role_policy = local.ecs_tasks_trust
}

module "app" {
  source          = "../modules/app-ecs"
  store_url       = module.store.store_url
  writer_role_arn = module.store.writer_role_arn
  reader_role_arn = module.store.reader_role_arn

  overrides_writer_lockout = module.store.overrides_writer_lockout
  # ...network, hosts, certificate, secret ARNs, IdP
}
```

The trust policy cannot say *which* task may take a role: every ECS task in
the account presents the same principal. What keeps the writer role off the
dashboard is who holds `iam:PassRole` on it, so grant that narrowly.

What `app-ecs` does create is the AWS side of running the tasks:

- **One execution role per role:** verdict, collector, dashboard, intake
  when enabled, ingest. This is the ECS agent's identity, not the app's: it
  pulls the image, writes that role's log group and fetches that role's
  secrets and nothing else. One shared role would hold the union, so the
  dashboard's would be able to fetch the webhook secret and the Compliance
  key. The dashboard's execution role can read no secret at all.
- **A scheduler role** for EventBridge Scheduler to run the ingest task and
  pass it its two roles. It holds no store permission.

**Secrets are Secrets Manager ARNs, never values**, and reach the container
through the task definition's `secrets` block, so neither the Terraform
variables nor the state hold one. Create each secret before the first apply,
with a placeholder where Anthropic has not issued the value yet, and pass
its full ARN, including the random suffix: the execution role's policy names
exact ARNs, and a partial one matches nothing in IAM. The hash salt is one of
these, so this module cannot see it to refuse a short one as `app-aca` does
for a `hash_salt` value; make it at least 16 characters.

**Per-org secrets.** Each org's Inference hook signs with its own secret,
each `compliance.orgs` entry takes its own key, and a fleet per org has its
own token. `webhook_secret_arns` and `intake_fleet_token_secret_arns` map an
`org_ids` name to `{current, previous}` ARNs, and `compliance_key_secret_arns`
maps one to an ARN; `app-cloudrun` takes the same maps of secret ids, as
`webhook_secret_ids`, `intake_fleet_token_secret_ids` and
`compliance_key_secret_ids`, and `app-aca` takes the values, as
`webhook_secrets`, `compliance_api_keys` and, with `enable_intake`,
`intake_fleet_tokens`, or Key Vault secret ids under the Cloud Run names. They become `WEBHOOK_SECRET_<NAME>` and `_PREVIOUS`,
`FORGD_INTAKE_FLEET_TOKEN_<NAME>` and `_PREVIOUS`, and
`ANTHROPIC_COMPLIANCE_ACCESS_KEY_<NAME>`, with `<NAME>` upper-cased and `-`
as `_`; `policy.yaml` shows where each goes. A key that is not an `org_ids`
name, or a name whose variable repeats another's or a single slot's, is
refused. With a map set, the single `webhook_secret_*` or
`compliance_key_secret_*` variable may be empty.

**The one exception is the ALB's OIDC client secret.** `authenticate-oidc`
takes the value and nothing else, so it is a `sensitive` variable and it is
in state. Set it from `TF_VAR_oidc_client_secret` and keep state in an
encrypted, access-controlled backend.

**Only the dashboard signs in.** The ALB routes by host, one per service,
because `/healthz` exists on both the verdict server and the dashboard and
path routing cannot tell them apart. The dashboard's host gets
`authenticate-oidc`, with an unauthenticated rule for `/healthz` ahead of it
so the deploy gate's probe is not redirected. The verdict, collector and
intake hosts forward with no sign-in, for the reason in `CLAUDE.md`, and
`tests/test_app_ecs.py` fails if one appears. The dashboard verifies the
ALB's token itself against the ALB's ARN, which is why the module refuses
any partition but `aws`: the ALB signing keys are published for the
commercial partition only.

After the apply, point each host at `alb_dns_name` and register
`oidc_redirect_uri` with the IdP client.

## Composing `app-cloudrun` with `store-gcs`

`app-cloudrun` creates no store and no bucket IAM. It runs each role as a
service account of its own, which is also the identity Cloud Run reads that
role's secrets with, and outputs those accounts for `store-gcs` to bind:
`writer_members` holds verdict, collector, ingest and, with
`enable_intake`, intake, and `reader_members` holds the dashboard. Each
extra writer gets exactly the bindings `store-gcs`'s own writer account
gets, including the delete on the cursors and the two markers under the
same condition, and each extra reader exactly the reader's. Both outputs
are maps keyed by role, and `store-gcs` keys each binding on that role, so
turning `enable_intake` on or off adds or removes only intake's bindings.

```hcl
module "store" {
  source         = "../modules/store-gcs"
  project_id     = "example-project"
  bucket_name    = "example-forgd-findings"
  location       = "europe-west2"
  writer_members = module.app.writer_members
  reader_members = module.app.reader_members
}

module "app" {
  source       = "../modules/app-cloudrun"
  project_id   = "example-project"
  region       = "europe-west2"
  image        = "europe-west2-docker.pkg.dev/example-project/forgd/forgd-verdict:0123abc"
  ingest_image = "europe-west2-docker.pkg.dev/example-project/forgd/forgd-verdict:0123abc-ingest"
  store_url    = module.store.store_url
  policy_yaml  = file("${path.root}/policy.yaml")

  overrides_writer_lockout = module.store.overrides_writer_lockout

  hash_salt_secret_id      = "projects/example-project/secrets/forgd-hash-salt"
  webhook_secret_id        = "projects/example-project/secrets/forgd-webhook-secret"
  compliance_key_secret_id = "projects/example-project/secrets/forgd-compliance-key"
  otel_token_secret_ids    = { primary = "projects/example-project/secrets/forgd-otel-token-primary" }
  org_ids                  = { primary = "<organization-uuid>" }

  dashboard_iap_members = ["group:security@example.com"]
}
```

The bindings live in `store-gcs`, but they name the app's accounts.
The services and the ingest job are created with `deletion_protection`, so
destroying the app module, or turning `enable_intake` off, first needs an
apply with `deletion_protection = false`. Destroying the app module deletes
its accounts, and removing it from the configuration removes the bindings on
the next apply; the bucket and the
findings in it stay, because the bucket is `store-gcs`'s and refuses to be
destroyed while it holds objects.

`store-gcs`'s own writer and reader accounts are still created, and nothing
in `app-cloudrun` runs as them.

What `app-cloudrun` creates:

- **One service account per role**, plus one for Cloud Scheduler. Each
  role's account has `roles/secretmanager.secretAccessor` on that role's
  secrets, one binding per secret, and nothing at project level; its bucket
  access comes from `store-gcs`. The
  dashboard's reads no secret at all. The scheduler's may run the ingest
  job (`roles/run.invoker` on the job) and holds nothing else.
- **Cloud Run services** for verdict, collector, dashboard and, with
  `enable_intake`, intake, and **ingest as a Cloud Run job** that Cloud
  Scheduler starts through the job's `:run` method.

**Secrets are Secret Manager ids, never values**: `projects/<project>/secrets/<name>`.
Cloud Run resolves the `latest` version of each when an instance starts,
so neither the variables nor the state hold one. Create each secret, with a
version, before the first apply; a placeholder is fine where Anthropic has
not issued the value yet, and a secret with no version stops the revision
from starting. The hash salt is one of these, so this module cannot refuse a
short one as `app-aca` does; make it at least 16 characters.

**Only the dashboard signs in.** Verdict, collector and intake grant
`roles/run.invoker` to `allUsers` and have IAP off, for the reason in
`CLAUDE.md`. The dashboard has IAP enabled on the service itself, IAP's
service agent is its only invoker, and the members in
`dashboard_iap_members` are `roles/iap.httpsResourceAccessor` on that
service. The list has no default and refuses `allUsers`. The project needs
`iap.googleapis.com` enabled, so that the IAP service agent exists. The
dashboard runs with `platform: iap` and the audience
`/projects/<number>/locations/<region>/services/<name>`, also output as
`dashboard_iap_audience`. Because IAP sits in front of every path, the
dashboard's `/healthz` is behind sign-in too, and `scripts/verify_deployment.sh`
reports the redirect as `dashboard.no-auth-redirect`. The dashboard's IAP sign-in carries no
groups, so the module refuses dashboard admins, and runtime overrides are
off on every service. Device deny (`forgd-verdict overrides deny-device`)
is therefore not available on Cloud Run: the intake never reads the denied
devices, so the only way to cut a device off is a fleet-wide rotation: issue a new fleet token with the old one in `FORGD_INTAKE_FLEET_TOKEN_PREVIOUS`, then clear it, which also cuts off every laptop not yet given the new token.

gitleaksd runs inside the verdict, collector and intake containers, started
by the entrypoint, as on every other target. Those three keep CPU allocated
between requests and run one instance each, for the reasons in `app-ecs`.

Every service and the job ignore their container image, as in § Terraform
owns infrastructure; CI owns image rolls. Cloud Run keeps the image in the
service rather than in a separate revision object, so an apply that changes
the policy or an environment value creates a revision with the running
image, not the first one.

`tests/test_app_cloudrun.py` fails on a public dashboard, on IAP on any
other service, on project-level or storage IAM, on a secret binding beyond
a role's own, on a secret as a plain environment value, on a store member
list that includes the wrong roles, and on an image Terraform would roll
back.

## Composing `cluster-eks` with `store-s3`

`cluster-eks` associates the chart's writer and reader service accounts with
`store-s3`'s two roles through EKS Pod Identity. Under Pod Identity each role
trusts `pods.eks.amazonaws.com`, which needs `sts:TagSession` as well as
`sts:AssumeRole` because the agent tags each session with the cluster,
namespace and service account. The conditions pin each role to this cluster
and to its one service account:

- `aws:RequestTag/eks-cluster-arn` refuses a session requested for any
  other cluster, in this account or another.
- `aws:RequestTag/kubernetes-namespace` and
  `aws:RequestTag/kubernetes-service-account` match the service account, so
  an association that gives the writer role to the dashboard's service
  account gets no credentials.

All three are session tags Pod Identity sets, which is the form the EKS
user guide documents for these restrictions ("Create IAM role with trust
policy required by EKS Pod Identity").

The writer's, with your account, region, cluster name and namespace:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "pods.eks.amazonaws.com" },
    "Action": ["sts:AssumeRole", "sts:TagSession"],
    "Condition": {
      "StringEquals": {
        "aws:RequestTag/eks-cluster-arn": "arn:aws:eks:us-east-1:123456789012:cluster/forgd-verdict",
        "aws:RequestTag/kubernetes-namespace": "forgd",
        "aws:RequestTag/kubernetes-service-account": "forgd-verdict-writer"
      }
    }
  }]
}
```

The reader's differs only in the service account. The conditions need the
session tags, so leave session tags enabled on the associations. Disabling
them, which AWS suggests for a `PackedPolicyTooLarge` error, makes every
condition fail and the pods get no credentials.

The module's `writer_assume_role_policy` and `reader_assume_role_policy`
outputs produce these, so a root passes them straight through:

```hcl
module "store" {
  source                    = "../modules/store-s3"
  bucket_name               = "forgd-findings-example"
  writer_assume_role_policy = module.cluster.writer_assume_role_policy
  reader_assume_role_policy = module.cluster.reader_assume_role_policy
}

module "cluster" {
  source          = "../modules/cluster-eks"
  cluster_name    = "forgd-verdict"
  vpc_id          = "vpc-..."
  subnet_ids      = ["subnet-...", "subnet-..."]
  writer_role_arn = module.store.writer_role_arn
  reader_role_arn = module.store.reader_role_arn
}
```

That is not a cycle: the trust policy is built from the account, region,
cluster name, namespace and service account names, not read from the
cluster, and the associations are created after the roles.

What the trust policy cannot tell apart is two pods running as the same
service account in the same namespace. Who may create pods there, or edit
the service accounts, is Kubernetes RBAC's to decide.

With `identity_mode = "irsa"` the module creates the cluster's IAM OIDC
provider instead, and the same two outputs become per-service-account
`sts:AssumeRoleWithWebIdentity` trust policies pinned to each subject; the
chart then needs each role ARN as a service-account annotation, which
`helm_values_hint` lists.

### Variables

| Variable | Default | |
|---|---|---|
| `cluster_name` | required | The EKS cluster's name, and the prefix of the module's IAM role and policy names: a letter, then at most 34 letters, digits and hyphens. |
| `kubernetes_version` | `"1.36"` | The EKS minor version. Moving it forward upgrades the control plane in place; EKS does not go back. |
| `tags` | `{}` | Tags on every resource the module creates that takes them. |
| `vpc_id` | required | The VPC holding `subnet_ids`. The module creates no VPC. It is passed to the Load Balancer Controller, which would otherwise read it from instance metadata that pods cannot reach. |
| `subnet_ids` | required | Private subnets, in at least two availability zones, for the nodes and the control plane's network interfaces. They need a route out to ECR, S3, STS and Anthropic's APIs. |
| `public_subnet_ids` | `[]` | Public subnets for the internet-facing ALB. Empty leaves the controller to find subnets by tag; see [Subnet tags](#subnet-tags). |
| `endpoint_public_access` | `false` | Whether the Kubernetes API is reachable from outside the VPC. Private access is always on. |
| `public_access_cidrs` | `[]` | Who may reach the public endpoint. Required, and not empty, when `endpoint_public_access` is `true`; there is no `0.0.0.0/0` default. |
| `api_allowed_security_group_ids` | `[]` | Security groups whose members may reach the private endpoint on 443; see [Reaching the API](#reaching-the-api). |
| `api_allowed_cidrs` | `[]` | Ranges that may reach the private endpoint on 443. A `/0` is refused. |
| `cluster_admin_principal_arns` | `[]` | IAM roles or users made cluster admin through access entries, besides the identity that applies; see [Reaching the API](#reaching-the-api). |
| `log_retention_days` | `365` | Retention of the control plane's api, audit and authenticator logs, in a value CloudWatch Logs accepts. The audit log records who read the forgd-verdict secret. |
| `secrets_kms_key_arn` | `""` | A KMS key for envelope encryption of Kubernetes secrets. Empty creates one, with rotation on. The encryption cannot be turned off once the cluster has it. |
| `node_instance_type` | `"m6i.xlarge"` | The node group's instance type: 4 vCPU and 16 GiB. See the sizing note on the node group in `main.tf` before going smaller. |
| `node_capacity_type` | `"ON_DEMAND"` | `ON_DEMAND` or `SPOT`. A reclaimed spot node takes the verdict server with it, and a governed prompt that cannot reach it fails. |
| `node_desired_size` | `2` | The node group's desired size. |
| `node_min_size` | `2` | The node group's minimum size. |
| `node_max_size` | `3` | The node group's maximum size. An update replaces nodes one at a time and needs room for one more than desired. |
| `node_disk_size_gb` | `64` | Each node's disk, in GiB. |
| `enable_network_policy` | `true` | Run the managed `vpc-cni` add-on with NetworkPolicy enforced; see [NetworkPolicy enforcement](#networkpolicy-enforcement). |
| `identity_mode` | `"pod_identity"` | How pods get AWS credentials: `pod_identity` (EKS Pod Identity associations) or `irsa` (an IAM OIDC provider and annotated service accounts), as above. |
| `namespace` | `"forgd"` | The namespace the chart is installed into. It is part of every association and IRSA subject, so a mismatch authenticates as nothing. |
| `dashboard_oidc_secret_name` | `"forgd-dashboard-oidc"` | The secret named in the dashboard Ingress's `auth-idp-oidc` annotation, holding the IdP client's `clientID` and `clientSecret`. The only secret the Load Balancer Controller may read. |
| `writer_service_account` | `"forgd-verdict-writer"` | The chart's writer service account: `<release fullname>-writer`, or `serviceAccounts.writer.name`. |
| `reader_service_account` | `"forgd-verdict-reader"` | The chart's reader service account: `<release fullname>-reader`, or `serviceAccounts.reader.name`. |
| `writer_role_arn` | required | `store-s3`'s `writer_role_arn`, for the verdict server, the collector and the ingest job. |
| `reader_role_arn` | required | `store-s3`'s `reader_role_arn`, for the dashboard. |
| `lb_controller_enabled` | `true` | Create the AWS Load Balancer Controller's IAM role. `false` means you supply an ingress controller, and the chart's Ingress objects do nothing until you do. |
| `connector_enabled` | `false` | Bind the chart's connector service account to the store's reader identity; set it with `connector.enabled` in the chart. |
| `connector_service_account` | `"forgd-verdict-connector"` | The chart's connector service account: `<release fullname>-connector`, or `serviceAccounts.connector.name`. Used only with `connector_enabled`. |
| `control_enabled` | `false` | Give the chart's control service account `store-s3`'s control role, for `dashboard.admins.enabled`; see [Dashboard admins](#dashboard-admins-the-control-identity). |
| `control_role_arn` | `""` | `store-s3`'s `control_role_arn`. Required with `control_enabled`, and different from both other roles. |
| `control_service_account` | `"forgd-verdict-control"` | The chart's control service account: `<release fullname>-control`, or `serviceAccounts.control.name`. Used only with `control_enabled`. |

### Reaching the API

The API endpoint is private unless `endpoint_public_access` is set, and its
network interfaces admit only the cluster's own security group, so nothing
else in the VPC can reach it until you say what may:

- `api_allowed_security_group_ids`: security groups whose members may connect
  on 443, such as a bastion's, a self-hosted CI runner's or a VPN endpoint's.
- `api_allowed_cidrs`: IPv4 or IPv6 ranges that may connect on 443, such as a
  VPN's client range. A `/0` (`0.0.0.0/0`, `::/0`) is refused.

Both are rules on a security group the module attaches to the control
plane's interfaces alone. The cluster security group is on the nodes as
well, and is left as EKS made it.

A caller that can reach the endpoint still needs an access entry. The
identity that runs `terraform apply` becomes cluster admin through one, and
nobody else does. `cluster_admin_principal_arns` lists IAM roles or users to make
admin as well (`AmazonEKSClusterAdminPolicy`, cluster scope). For an SSO or
other assumed role, give the role's `arn:aws:iam::<account>:role/<name>`,
not the `sts` session ARN. Do not list the identity that applies: it already
has an entry, and creating another fails.

**If CI applies and `cluster_admin_principal_arns` is empty, no human can
reach the cluster**, and only a CI run can grant access.

### Subnet tags

The Load Balancer Controller chooses the ALB's subnets by tag unless it is
told which:

- `kubernetes.io/role/elb=1` on the public subnets. The example's ALB is
  internet-facing and is placed in these. Setting `public_subnet_ids`
  instead makes `helm_values_hint` name them in each Ingress's
  `alb.ingress.kubernetes.io/subnets`, and the tag is then not read.
- `kubernetes.io/role/internal-elb=1` on the private subnets
  (`subnet_ids`). The controller reads it only for an ALB with
  `scheme: internal`; tag them anyway, so that switching the scheme does not
  leave the controller with no subnets.

With neither the tag nor `public_subnet_ids`, the controller finds no
subnets and builds no ALB, and says so only in its own log and the
Ingress's events.

### NetworkPolicy enforcement

`enable_network_policy` defaults to `true`. With it, the module creates the
managed `vpc-cni` add-on with `enableNetworkPolicy` set to `"true"`, after
the node group. EKS installs a self-managed vpc-cni with every cluster, so
the add-on is created with `resolve_conflicts_on_create = "OVERWRITE"` and
replaces that configuration.

The default VPC CNI accepts a NetworkPolicy and enforces none of it. With
`enable_network_policy = false` the module creates no add-on, and the
chart's `networkPolicy` renders policies the cluster then ignores. That
includes the policy the chart requires under the dashboard's
`trusted_header` mode, which keeps other pods away from the dashboard only
while it is enforced. Turn it off only when another CNI on the cluster
enforces NetworkPolicy.

### Installing into the cluster

`cluster-eks` installs nothing into the cluster, for the reason given for
`cluster-aks` below. After the apply, in order:

1. `kubeconfig_command`
2. `lb_controller_install_command`
3. `lb_controller_namespace_command`, which prepares the chart's namespace.
   It can be run again. It:
   - creates the namespace;
   - labels it `elbv2.k8s.aws/pod-readiness-gate-inject=enabled`. The
     controller's webhook then gives each pod a readiness gate that clears
     only once the pod is a healthy target of the ALB, so a rolling update
     does not stop an old pod first. Without it, the ALB has no healthy
     target for a moment on every roll and governed prompts get 502s, which
     Anthropic reports as delivery failures. The webhook only acts on pods
     created after the label, which is why this runs before the chart;
   - lets the controller read the dashboard's OIDC client secret
     (`dashboard_oidc_secret_name`, the `secretName` in the dashboard
     Ingress's `auth-idp-oidc` annotation) and no other secret. Chart 3.5.0
     grants the controller no secret access by default, and a secret it
     cannot read fails the build of the whole ingress group, so no host gets
     an ALB. Do not set `clusterSecretsPermissions.allowAllSecrets=true`
     instead: that lets the controller read every secret in the cluster,
     the chart's own included.
4. The forgd-verdict chart, with `helm_values_hint`, into the `namespace`
   output.

Under Pod Identity, neither service account may carry an
`eks.amazonaws.com/role-arn` annotation. With one, the EKS webhook injects a
web identity token, the AWS SDK tries it before the Pod Identity credentials,
and every call to S3 fails. `helm_values_hint` sets no annotation then, and
cannot remove one: Helm merges maps across `-f` files, so an annotation in
another values file survives whatever the hint says. Delete it from that file.

## A root is separated from its neighbours three ways

Keep each root separate from its neighbours in all three: different
backend keys, different storage accounts, and different resource
groups. Separate state alone is not enough. Two roots pointed at one
resource group let a `terraform destroy` on one reach the other, and two
state files in charge of one storage account mean each plan wants to take
it back from the other. The backend block is left empty, so the key is
passed at init with `-backend-config="key=..."`. If your CI derives that key
from the root's name, a second root gets its own state by existing rather
than by someone remembering.

The group a stack deploys into is not the group holding the Terraform
state, which stays put whatever the stack is, or an `init` would move the
state file rather than the deployment.

`examples/aks` takes its region from the resource group rather than
from a variable. A region variable that disagrees with the group builds
resources in the wrong region, and can fail outright where a VM size is not
offered. A wrong region is not only a failed apply: findings are written on
the verdict path, which has a 5,000 ms end-to-end timeout, and a
cross-region write spends part of that budget for nothing.

**Terraform cannot create the group it deploys into.** Creating a resource
group is a subscription-level write, and the infrastructure identity should
be scoped to resource groups; giving it subscription Contributor so a stack
could make its own group would let a run reach every resource in the
subscription. So `scripts/bootstrap_target_rg.sh` creates the group and
grants the identity Contributor and User Access Administrator on it,
another scoped grant rather than a broader one. It grants no data role on
the findings store, but User Access Administrator lets it grant itself one,
so the identity can come to read or rewrite the findings. Run it only from
a manually dispatched workflow on a gated environment. Same shape as
`bootstrap_tfstate.sh`, and for the same kind of reason.

The cost is that separate roots do not share a findings history. A rescan
reproduces the findings of adapters 3 and 6, which pull from Anthropic.
Those of adapters 1, 2 and 4 record traffic as it arrived, and a separate
root does not have them.

## `cluster-aks` does not install the chart

It builds the cluster and federates `store-azure`'s two identities to the
chart's service accounts. `helm upgrade` is a separate step, for the same
reason image rolls are: a `helm_release` under Terraform means `plan` has to
reach the API server, and a plan that cannot reach it fails rather than
reporting drift.

The stack prints the exact install command, `terraform output -raw
helm_install_command`. Its values in angle brackets are placeholders,
among them the TLS issuer and the dashboard's `oidc_jwt` settings: the
repository's `policy.yaml` uses the dashboard auth mode that is only a check
behind Container Apps EasyAuth, and the chart refuses it on Kubernetes
until you choose. See `../helm/README.md` § The shipped policy's dashboard
auth does not port. Two of its flags are not optional:
`serviceAccounts.{writer,reader}.name` are half of each federated subject,
and the chart's own default naming does not match them. Get them wrong and
the pods authenticate as *nothing*: the dashboard renders empty and the
collector accepts exports it then fails to store, neither of which looks
like an auth failure from outside. `tests/test_helm_chart.py` asserts the
two sides agree.

### Reaching the AKS API

By default the API server is private and local accounts are off.
`examples/aks` declares each variable below with the module's default and
passes it through.

| Variable | Default | |
|---|---|---|
| `private_cluster_enabled` | `true` | The API server has a private IP in the cluster's network and no public endpoint. Changing it replaces the cluster. |
| `api_server_authorized_ip_ranges` | `[]` | The ranges a public API server admits. Refused on a private cluster, which AKS does not give authorized ranges. Each entry must be a CIDR, and a `/0` (`0.0.0.0/0`, `::/0`) is refused. |
| `allow_unrestricted_public_api_server` | `false` | A public API server with no ranges admits every address. The plan refuses that combination unless this is `true`. |
| `local_account_disabled` | `true` | No static admin kubeconfig. Callers authenticate with Entra ID and are authorized by Azure RBAC. |
| `entra_admin_group_object_ids` | `[]` | Entra groups given cluster-admin while local accounts are off. |

With local accounts off, a caller needs one of the Azure Kubernetes Service
RBAC roles on the cluster, such as `Azure Kubernetes Service RBAC Cluster
Admin`, or membership of a group in
`entra_admin_group_object_ids`. Nobody has either until you grant it,
including the identity that ran `terraform apply`. `kubeconfig_command` then
adds `kubelogin convert-kubeconfig -l azurecli`, and
`scripts/bootstrap_aks.sh` runs it, so `kubectl` authenticates
as whoever `az` is signed in as, which needs
[kubelogin](https://github.com/Azure/kubelogin) installed.

With the cluster private, `kubectl`, `helm` and `scripts/bootstrap_aks.sh`
must run from a network that reaches the API server's private endpoint.
By default AKS creates the VNet itself, in the node resource group
(`MC_<resource group>_<cluster>_<region>`), so that is the network a
self-hosted runner or jump host has to be in, peered with, or reach over a
VPN. To put the cluster in a subnet of your own VNet instead, next to your
runners and private DNS, see [Your own VNet](#your-own-vnet).

Without a host there, run the install through `az aks command invoke`. It
runs the command in a pod inside the cluster that has `kubectl` and `helm`,
with the files you attach. `--file <path>` attaches single files only, and
flattens each to its base name. `--file .` attaches the current directory
with its structure, and cannot be combined with other `--file` flags. So
stage the chart and the policy in one directory and attach that. The
Terraform outputs are read locally, before the call:

```sh
aks=deploy/terraform/examples/aks
store_url="$(terraform -chdir=$aks output -raw store_url)"
writer_id="$(terraform -chdir=$aks output -raw writer_client_id)"
reader_id="$(terraform -chdir=$aks output -raw reader_client_id)"
class="$(terraform -chdir=$aks output -raw ingress_class_name)"
writer_sa="$(terraform -chdir=$aks output -json service_account_names | jq -r .writer)"
reader_sa="$(terraform -chdir=$aks output -json service_account_names | jq -r .reader)"

stage="$(mktemp -d)"
cp -R deploy/helm/forgd-verdict policy.yaml "$stage"/
cd "$stage"
az aks command invoke \
  --resource-group <resource-group> --name <cluster> \
  --file . \
  --command "helm upgrade --install forgd ./forgd-verdict \
    --namespace forgd --create-namespace \
    --set store.url=$store_url \
    --set serviceAccounts.writer.name=$writer_sa \
    --set serviceAccounts.reader.name=$reader_sa \
    --set serviceAccounts.writer.clientId=$writer_id \
    --set serviceAccounts.reader.clientId=$reader_id \
    --set ingress.className=$class \
    --set image.repository=<registry>/forgd-verdict \
    --set image.tag=<commit-sha> \
    --set ingest.image.repository=<registry>/forgd-verdict \
    --set ingest.image.tag=<commit-sha>-ingest \
    --set ingress.host=<hostname> \
    --set ingress.tls.clusterIssuer=<cluster-issuer> \
    --set secrets.existingSecret=<secret> \
    --set-string orgIds.primary=<organization-uuid> \
    --set dashboard.auth.mode=oidc_jwt \
    --set dashboard.auth.header=authorization \
    --set dashboard.auth.issuer=https://login.microsoftonline.com/<tenant>/v2.0 \
    --set dashboard.auth.jwksUrl=https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys \
    --set dashboard.auth.audience=<client-id> \
    --set-file policy.inline=policy.yaml"
```

Replace every value in angle brackets before running it. The command runs
under a shell in the pod, where an unreplaced `<...>` is a redirect. These
are the values `helm_install_command` sets, with the chart and the policy
read from the attached directory. `orgIds.primary` is the key `policy.yaml`
reads. Each call runs in a fresh pod, so the files are attached every time.

A GitHub-hosted runner cannot reach a private cluster. To use
one, set `private_cluster_enabled = false` and list the runner's egress
ranges, which for hosted runners are broad and change, in
`api_server_authorized_ip_ranges`. Setting
`allow_unrestricted_public_api_server` instead leaves the API server open
to every address.

Turning local accounts off on an existing cluster is an in-place update.
Making a public cluster private replaces it, and the federated credentials
with it, because the OIDC issuer URL changes.

### Your own VNet

| Variable | Default | |
|---|---|---|
| `vnet_subnet_id` | `null` | A subnet of your VNet for the nodes and the private API server's endpoint. With it, the control plane runs as a user-assigned identity, `<cluster>-control-plane`, which the module gives Network Contributor on the subnet before it creates the cluster. |
| `pod_cidr` | `null` | The overlay range pods get addresses from. Null is AKS's `10.244.0.0/16`. |
| `service_cidr` | `null` | The range services get addresses from. Null is AKS's `10.0.0.0/16`. Set with `dns_service_ip`. |
| `dns_service_ip` | `null` | The cluster DNS service's address, inside `service_cidr` and not its first. Null is AKS's `10.0.0.10`. |

`examples/aks` declares each with the module's default and passes it
through. With all four unset the plan is the one the module made before
they existed.

The pod and service ranges must not overlap the VNet or anything it routes
to, such as a peered VNet or an on-premises range over a VPN. AKS's default
service range, `10.0.0.0/16`, overlaps many VNets, so with your own subnet
set `service_cidr` and `dns_service_ip` too. The nodes are in overlay mode,
so pods take no addresses from the subnet; it needs one per node, one more
for each node `max_surge` adds during an upgrade, and one for the API
server's private endpoint, on top of the five addresses Azure reserves in
every subnet. The subnet must route out to AKS's required outbound
endpoints, the container registry and Anthropic's APIs. A VNet with its own
DNS servers must forward the cluster's private zone,
`privatelink.<region>.azmk8s.io`, to Azure DNS (`168.63.129.16`), or
nothing in it resolves the API server's name.

`vnet_subnet_id` must be known when Terraform plans, because it decides
whether the identity and the role assignment exist: give an existing
subnet's id, or create the subnet in an earlier apply. A subnet created in
the same apply fails the plan with `Invalid count argument`.

The applying identity needs `Microsoft.Authorization/roleAssignments/write`
on the subnet, as `User Access Administrator` or `Owner` on it gives, to
create the Network Contributor assignment. The cluster is created after the
assignment, but Azure can take a few minutes to apply a new assignment; if
the first apply fails with an authorization error on the subnet, run it
again.

**Setting `vnet_subnet_id`, or changing any of the four, on an existing
cluster replaces it**: the control plane's identity type and the node
pool's subnet cannot change in place. The OIDC issuer URL changes with the
cluster, so the federated credentials are replaced too. To move a running
deployment:

1. Plan with the new values and confirm the plan replaces
   `module.cluster.azurerm_kubernetes_cluster.this` and the federated
   credentials, and nothing in `module.store`. The store, its identities
   and the findings are untouched.
2. Apply. The verdict server is down from when the old cluster is destroyed
   until the chart is running on the new one, and Anthropic's calls in that
   window fail. Schedule it.
3. Install the chart on the new cluster as on any new one (see
   [`cluster-aks` does not install the chart](#cluster-aks-does-not-install-the-chart)),
   from a host that reaches the API server's endpoint, which is now in your
   subnet.
4. Point DNS for the ingress hostname at the new ingress address, and run
   `forgd-verdict verify-deployment`.

## The findings connector in the app modules

`app-aca`, `app-cloudrun` and `app-ecs` run the findings connector when
`connector_enabled = true`; it is off by default and the plan is unchanged
without it. [docs/CONNECTOR.md](../../docs/CONNECTOR.md) § The Terraform
app modules is the reference. Read its first section before turning it on:
whatever Claude reads through the connector enters your Claude
conversations, where the Compliance API retains it, and that metadata says
which pseudonymous actor had what kind of data detected, where and when.

It is public with no platform auth (external ingress with no EasyAuth,
`allUsers` with IAP off, a plain ALB forward) because Claude calls it
from Anthropic's cloud and it verifies the bearer token from your identity
provider itself. It runs on the store's reader identity with no hash salt
and no secret. A plan is refused without an issuer, JWKS URL and audience,
with an empty required scope, or with a `connector_resource` that does not
match the host the module serves it on.

```hcl
module "app" {
  source = "../modules/app-ecs"   # or app-aca, app-cloudrun
  # ...

  connector_enabled        = true
  connector_host           = "mcp.example.com"   # app-ecs only
  connector_issuer         = "https://login.microsoftonline.com/<tenant>/v2.0"
  connector_jwks_url       = "https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys"
  connector_audience       = ["https://mcp.example.com/mcp", "<API app client id>"]
  connector_scopes         = ["https://mcp.example.com/mcp/findings.read"]
  connector_required_scope = "findings.read"
  # app-aca and app-ecs: an optional allowlist, off by default.
  # connector_source_ranges = ["160.79.104.0/21"]
}
```

- **`app-aca`** derives the MCP URL from the app name and the environment's
  default domain. For a domain you bind yourself, set
  `connector_custom_host` and `connector_resource`; the module creates no
  binding or certificate.
- **`app-cloudrun`** derives it as
  `https://<name_prefix>-connector-<project number>.<region>.run.app/mcp`.
  The connector's account is `reader_members["connector"]` for
  `store-gcs`, and `service_account_emails["connector"]` for `ci-gcp`'s
  `cloudrun.runtime_service_accounts`; add `connector` to
  `cloudrun.services` as well.
- **`app-ecs`** needs `connector_host` on the ALB's certificate. `ci_release`
  includes the connector's service and task family.

`connector_source_ranges` is Anthropic's published egress range,
`160.79.104.0/21` today. It has changed before and a stale entry fails in
Claude as "Couldn't reach the MCP server"; it also cuts off Claude Code,
which connects from the user's machine.

For the release, set `FORGD_CONNECTOR_URL` from `connector_url` and the
connector's name: `AZURE_CONNECTOR_APP`, `GCP_RUN_CONNECTOR_SERVICE`, or
`AWS_ECS_CONNECTOR_SERVICE` and `AWS_ECS_CONNECTOR_FAMILY`. `ci-aws` and
`ci-gcp` list them in `repository_variables`. The deploy scripts roll the
connector after the verdict-first gate and check it in the final verify.
They roll an intake the same way, after the collector, when its name is
set: `AZURE_INTAKE_APP` from `app-aca`'s `intake_app_name`,
`GCP_RUN_INTAKE_SERVICE`, or `AWS_ECS_INTAKE_SERVICE` and
`AWS_ECS_INTAKE_FAMILY`.

## Readiness and restarts

Every app module holds a replica out of traffic while its readiness path
answers 503, and uses `/livez` only for liveness, on the roles that run
gitleaksd. The readiness path is `/readyz` with `dashboard_admins_enabled`
and `/healthz` without it:

- **`app-aca`:** an HTTP readiness probe on the readiness path on the verdict
  server, collector, dashboard and connector. A not-ready replica stays
  running.
- **`app-ecs`:** each service's ALB target group checks the readiness
  path, and each service container's health check requests it, after
  `/livez` on the verdict server, collector and intake. ECS replaces a task
  that fails either.
- **`app-cloudrun`:** a startup and a readiness probe on the readiness path on
  every service. A failing startup probe shuts the container down; after
  startup, a failing readiness probe only stops new traffic
  ([Google's documentation](https://docs.cloud.google.com/run/docs/configuring/healthchecks)).

"Readiness" in [docs/OVERRIDES.md](../../docs/OVERRIDES.md#readiness) has
the per-platform detail.

## Dashboard admins: the control identity

Runtime overrides from the dashboard
([docs/OVERRIDES.md](../../docs/OVERRIDES.md)) need the dashboard to write
two things in the store: the object `state/runtime-overrides.json` and
records under `audit/runtime-overrides/`, both under the key prefix. The
reader identity is shared with the findings connector, so the dashboard
gets a third identity for this, the **control** identity: the reader's
grants plus those writes and nothing else. Everything here is off by
default, and with it off every plan and render is unchanged, writer
bindings included.

`control_enabled` on a store module also takes the writers' write to
both paths away. A service reads the object only when the policy's
`dashboard.admins` lists groups and `FORGD_OVERRIDES_ENABLED` is `true`,
which the app modules set on every service with
`dashboard_admins_enabled`, beside `FORGD_OVERRIDES_WRITER_ROLES`, one
writer role per distinct store identity among the writers the module
deploys. The dashboard and the connector only read,
and are never listed. Turn `control_enabled` on in the same change
that turns `dashboard_admins_enabled` on: the app modules' control inputs
are the store module's control outputs. After that apply, run
`forgd-verdict overrides init` once as the control identity: until it
runs, every service without a last-known-good is not ready
(see "Initialising the store" in [docs/OVERRIDES.md](../../docs/OVERRIDES.md#initialising-the-store)). Each store module outputs
`overrides_writer_lockout`, true only with `control_enabled`, and each app
module refuses `dashboard_admins_enabled` at plan unless its
`overrides_writer_lockout` input is true. Pass the output through, as the
examples above do. The Helm chart cannot see the store module, so it has no
such check; there, and everywhere, the services' runtime probe is the
authoritative check (see "Writer lockout" in
[docs/OVERRIDES.md](../../docs/OVERRIDES.md#writer-lockout)).

| Module | Input | What it adds |
|---|---|---|
| `store-gcs` | `control_enabled`, `control_members` | A control account (`control_email`, `control_member`). Each control member gets the readers' `objectViewer` binding, `roles/storage.objectCreator` conditioned on the object and the audit prefix, and the delete-only custom role conditioned on the object alone, so an audit record cannot be replaced. |
| `store-s3` | `control_enabled`, `control_assume_role_policy` | A control role (`control_role_arn`) carrying the reader's policy and `s3:PutObject` on the object and `audit/runtime-overrides/*`. The bucket policy denies it a put under the audit prefix without `If-None-Match`, and adds it to `NoDeletesByTheApp`. `writer_deny_policy_json`, null unless `control_enabled`, is the writer Deny as an identity policy for a writer role made outside the module, with denies on bucket configuration and on deletes added. |
| `store-azure` | `control_enabled`, `storage_account_delete_lock`, `writer_role_name`, `reader_role_name`, `control_role_name` | A user-assigned identity (`control_identity_id`, `control_identity_client_id`, `control_identity_principal_id`) with a custom role holding blob `read`, `write` and `add/action`, assigned with an ABAC condition on the blob path. A `CanNotDelete` lock on the storage account, on by default; `storage_account_delete_lock = false` opts out, and it must be off for an apply that removes one of the module's role assignments. The lock needs `Microsoft.Authorization/locks/*`. With `control_enabled` false the writer and the reader keep the built-in roles; with it true they hold custom roles (below). |
| `app-aca` | `dashboard_admins_enabled`, `control_identity_id`, `control_client_id`, `dashboard_form_key`, `dashboard_signing_key_secret_id`, `overrides_verify_keys` | Attaches the control identity to the dashboard beside the reader, which still pulls the image, and sets `AZURE_CLIENT_ID` to it. The form key is a Container Apps secret, or with `dashboard_form_key_secret_id` a Key Vault reference read with the control identity. The dashboard alone gets `FORGD_OVERRIDES_SIGNING_KEY` from a Key Vault secret reference read with the control identity, which needs `Key Vault Secrets User` on the vault; the module does not grant it. Every service and the ingest job get `FORGD_OVERRIDES_VERIFY_KEY`, `FORGD_OVERRIDES_ENABLED=true` and `FORGD_OVERRIDES_WRITER_ROLES=verdict`: this module deploys verdict, collector and ingest, and the intake with `enable_intake`, all as `identity_id`, so the verdict server is the one writer role listed. The intake reads the denied devices, so `forgd-verdict overrides deny-device` cuts one laptop off here. |
| `app-ecs` | `dashboard_admins_enabled`, `control_role_arn`, `dashboard_form_key_secret_arn`, `dashboard_signing_key_secret_arn`, `overrides_verify_keys` | The dashboard's task role becomes the control role, its execution role may read the form key's and the signing key's secrets, the dashboard alone gets `FORGD_OVERRIDES_SIGNING_KEY`, and `ci_release.task_role_arns` includes the control role. Every service and the ingest task get `FORGD_OVERRIDES_VERIFY_KEY`, `FORGD_OVERRIDES_ENABLED=true` and `FORGD_OVERRIDES_WRITER_ROLES=verdict`: every writer task runs as `writer_role_arn`. |
| `app-cloudrun` | `dashboard_admins_enabled`, `dashboard_form_key_secret_id`, `dashboard_signing_key_secret_id`, `overrides_verify_keys` | Moves the dashboard's account from `reader_members` to `control_members` under the same key, for `store-gcs`. **Refused at plan today**: this module's dashboard signs in through IAP, whose tokens carry no groups. So `FORGD_OVERRIDES_ENABLED` and `FORGD_OVERRIDES_WRITER_ROLES` are never set, and every service has runtime overrides off. Each writer runs as a service account of its own, so the module wires every writer role, `intake` listed with `enable_intake`. |
| `cluster-gke`, `cluster-eks`, `cluster-aks` | `control_enabled`, `control_service_account`, and `control_email`, `control_role_arn` or `control_identity_id` | Binds the chart's control service account to the store's control identity. `cluster-eks` also outputs `control_assume_role_policy` for `store-s3`. |

Each app and cluster module refuses a control identity equal to the
reader's or the writer's, and a control service account that another role
already uses. With admins on, the app modules and the chart also refuse
to plan or render without a form key: the dashboard refuses to start with
admins configured and no `FORGD_DASHBOARD_FORM_KEY`. Generate one with
`openssl rand -base64 32`, and keep it where the other secrets live.

The chart's side is `dashboard.admins.enabled`, `serviceAccounts.control`
and `secrets.dashboardFormKey` (or the `dashboard-form-key` key of
`secrets.existingSecret`).

`store-azure` takes no key prefix, so its condition names
`state/runtime-overrides.json` and `audit/runtime-overrides/` at the root
of the container. A store URL with a path under the container would put
the object outside the condition, and the dashboard's writes would be
refused.

## Terraform owns infrastructure; CI owns image rolls

Every container declares `lifecycle { ignore_changes = [...image] }`.

A tag deploy is four image updates and takes about two minutes. Routing that
through `terraform apply` would add state locking, backend credentials and a
plan on every release to change one field, and a failed release would leave
state half-applied. So `scripts/deploy_azure.sh` keeps rolling images and
Terraform never fights it.

**ECS cannot ignore only the image.** The image is inside the task
definition's container JSON, so `app-ecs` ignores the whole running revision
instead: each service ignores `task_definition`, and the ingest schedule
ignores its task definition ARN. CI owns which revision runs.

That changes what an apply does. A Terraform change to a task definition
(the policy, an environment value, a secret ARN, the execution role) still
registers a new revision, but no service runs it until the next
release. `scripts/deploy_aws.sh` does the release, and follows two rules:

- **Build the new revision from the LATEST revision in each family** (the
  `task_definition_families` output), replacing only the image. Built
  from the revision currently running, it silently drops every Terraform
  change made since the last release.
- **Never deploy Terraform's revision as-is.** It carries `var.image`, the
  image of the first apply, so pointing a service at it by hand rolls the
  image back to whatever was current when the stack was created.

For the schedule the release updates the target's task definition ARN the
same way; it runs whatever revision the schedule names.

## The AWS CD identity: `ci-aws`

`modules/ci-aws` is the role `scripts/deploy_aws.sh` runs as in CI, the
AWS counterpart of the Azure CD identity: it rolls images and creates
nothing. GitHub Actions assumes it through OIDC, and its trust admits a
token from one environment of one repository:
`repo:<github_org>/<github_repo>:environment:<github_environment>`, with
`aud` `sts.amazonaws.com`. None of the three has a default. The
`deploy-aws` job in `.github/workflows/deploy.yml`, which a fork copies
from `examples/github/deploy.yml`, runs in the `verdict-cd-aws` environment, so that is the value for
`github_environment` unless you rename both.

An organization with immutable OIDC identifiers enabled names the org and
repo by numeric id in the token's subject (see docs/CREDENTIALS.md § 6b).
Set `github_owner_id` and `github_repo_id` and the role trusts that form as
well as the short one.

```hcl
module "ci" {
  source             = "../modules/ci-aws"
  github_org         = "acme"
  github_repo        = "forgd-verdict"
  github_environment = "verdict-cd-aws"
  github_owner_id    = 123456   # gh api orgs/acme --jq .id
  github_repo_id     = 789012   # gh api repos/acme/forgd-verdict --jq .id
  oidc_provider_arn  = "arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com"
  ecr_repository_arn = aws_ecr_repository.forgd.arn
  ecs                = module.app.ci_release
  # or, for the chart on EKS:
  # eks = { cluster_name = module.cluster.cluster_name, namespace = "forgd" }
}
```

An account has at most one OIDC provider for
`token.actions.githubusercontent.com`. Pass its ARN if it exists, or set
`create_oidc_provider = true`. The module refuses both, and neither.

Each permission is a call the script makes, scoped to what the call
touches: push to the one repository, register revisions in the stack's
task definition families, update the stack's services, and get and update
the one schedule. `iam:PassRole` covers exactly the roles a registered
revision names, for `ecs-tasks.amazonaws.com`, and the scheduler's role,
for `scheduler.amazonaws.com`, because `UpdateSchedule` passes the target's
role again. `ecr:GetAuthorizationToken` and `ecs:DescribeTaskDefinition`
are on `*` because neither accepts a resource. `tests/test_ci_aws.py`
refuses a create, delete, put (other than `ecr:PutImage`), run or attach
action, and any IAM action but `PassRole`.

Passing both store roles to ECS means this role could register a
dashboard revision that names the writer role. PassRole has no condition
that ties a role to a family, so this is the same trust the note on
`iam:PassRole` above asks you to grant narrowly: it is held by this role
and by whoever applies Terraform.

**On EKS** the role gets `eks:DescribeCluster`, for `aws eks
update-kubeconfig`, and an access entry with `AmazonEKSEditPolicy` scoped
to the release namespace. The chart renders Deployments, Services,
Ingresses, ConfigMaps, Secrets, ServiceAccounts and a CronJob, and no RBAC
objects, so namespace Edit is enough for `helm upgrade`. Edit also reads
the namespace's Secrets, and has to: helm keeps each release's values,
secret values included, in a Secret in that namespace, and
`--reset-then-reuse-values` reads them back. The access entry is created by
whoever applies this module; the role cannot create or change access
entries.

The `repository_variables` output lists the variables the AWS
deploy job reads, which are the script's environment variables under the
same names plus `AWS_DEPLOY_ROLE_ARN` and `AWS_REGION`.

Set them on the `verdict-cd-aws` environment rather than as repository
variables. Both reach the job's steps, but on the environment the generic
names (`FORGD_VERDICT_URL` and the rest) stay scoped to the AWS job, and it
matches where the Azure job's variables live. The job decides whether AWS
is configured in a step for that reason: a job-level `if` is evaluated
before the environment loads, and sees environment variables as empty.

Three constraints on the release:

- **The ECR repository must allow tag overwrites (MUTABLE).** A
  `workflow_dispatch` redeploy of the same tag pushes the same image tag
  again, and an IMMUTABLE repository refuses it.
- **Build on the stack's architecture.** The hosted `ubuntu-latest` runner is
  x86, and `deploy_aws.sh` refuses an `AWS_IMAGE_PLATFORM=linux/arm64` build
  there rather than fail mid-build. Run the job on `ubuntu-24.04-arm`, or set
  up QEMU and buildx and set `AWS_ALLOW_CROSS_BUILD=1`.
- **EKS in another region than ECR:** set `AWS_EKS_REGION`; it defaults to
  the region in the ECR repository URL.

## The GCP CD identity: `ci-gcp`

`modules/ci-gcp` is the service account `scripts/deploy_gcp.sh` runs as in
CI. GitHub Actions impersonates it through Workload Identity Federation,
and the pool's provider admits a token only from one environment of the
repository and owner named by `github_repository_id` and
`github_owner_id`: `github_environment`, which defaults to
`verdict-cd-gcp`. The `deploy-gcp` job in
`.github/workflows/deploy.yml`, which a fork copies from
`examples/github/deploy.yml`, runs in that `verdict-cd-gcp` environment.
Set the names in the `repository_variables` output on it, with
`GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_SERVICE_ACCOUNT` from the
`workload_identity_provider` and `service_account_email` outputs.

On GKE the account gets `roles/container.clusterViewer` on the project,
which fetches credentials and nothing more, and nothing inside the
cluster. Apply the `gke_rbac_manifest` output once with `kubectl apply -f -`
to let it edit the release namespace. `edit` there includes reading the
namespace's Secrets, the signing secret among them, and running pods as the
chart's service accounts, which reach the store through Workload Identity.
Helm keeps its release records as Secrets, so a narrower binding cannot
upgrade the release; the EKS path's `AmazonEKSEditPolicy` grants the same.

The provider admits any workflow run that declares `verdict-cd-gcp`, from
any branch, to anyone with write access to the repository. In the
environment's GitHub settings, limit its deployment branches and tags to
`v*` tags only, and add required reviewers for a deploy that waits for a
second person. See [A fork's deploy
workflow](../../docs/RELEASING.md#a-forks-deploy-workflow) in
docs/RELEASING.md for the full set of settings.

**CD from a hosted runner needs `dns_endpoint_allow_external_traffic = true`
on `cluster-gke`.** The deploy job fetches credentials through the
cluster's DNS endpoint, which by default admits only traffic from inside
Google Cloud. Turning it on opens no IP range: every request still needs
an IAM credential with `container.clusters.connect`. The alternative is a
self-hosted runner inside the VPC with the input left off, as a
`cluster-eks` deployment lists its runner in
`api_allowed_security_group_ids`.

## Terraform version

**1.9.8**, pinned in `.github/workflows/ci.yml` for validation. Use the same
locally and in any workflow that applies. 1.9 rejects things 1.5 accepted
(`for_each = [1]` among them), so a passing `terraform validate` on an older
binary is not evidence.

```
terraform version   # expect 1.9.x
```

## Moving to azurerm 5

`app-aca`, `cluster-aks`, `monitor-azure`, `store-azure` and
`examples/aks` require `hashicorp/azurerm` `~> 5.0`. A root that calls them
moves its own `required_providers` entry to `~> 5.0` in the same change,
then runs `terraform init -upgrade`. What the move asks of a deployment:

- **Resource provider registration.** azurerm 5 registers no resource
  providers unless told to; 4.x registered about sixty. Each module needs:

  | Module | Resource providers |
  |---|---|
  | `store-azure` | `Microsoft.Storage`, `Microsoft.ManagedIdentity` |
  | `monitor-azure` | `Microsoft.OperationalInsights`, `Microsoft.Insights` |
  | `cluster-aks` | `Microsoft.ContainerService`, `Microsoft.ManagedIdentity` |
  | `app-aca` | `Microsoft.App` |

  `examples/aks` lists what its three modules need in
  `resource_providers_to_register`. A namespace not yet registered in the
  subscription is registered by the identity that applies, which then needs
  its `register/action`; one already registered needs nothing.
- **No inputs or state moves.** No module input or output changed, and no
  resource address moved.
- **Renamed arguments, handled inside the modules.** The federated
  credentials take `user_assigned_identity_id`, and their resource group
  comes from the identity. `cluster-aks` declares
  `node_provisioning_profile { mode = "Manual" }`, which 5.x requires and
  which is what a 4.x cluster ran with: the default node pool and no node
  auto-provisioning.
- **Validation moves to apply.** azurerm 5 no longer checks `location`
  and resource provider values against Azure's lists at plan time, so a
  mistyped region fails at apply instead.
  `features { enhanced_validation { locations = true, resource_providers = true } }`
  in the provider block restores the 4.x checks, and
  `ARM_PROVIDER_ENHANCED_VALIDATION` is no longer read.
- **Plan before applying.** Run a plan against the deployment's state and
  confirm it replaces nothing. The modules were moved against their
  rendered plans, not against a running deployment. Look in particular at
  the AKS cluster (the new `node_provisioning_profile`), the federated
  credentials (their identity argument was renamed), and, with `app-aca`,
  the Container Apps environment's `logs_destination`, which 5.x no longer
  reads back from Azure and defaults to empty.

## Running it from CI

Run Terraform from a workflow of its own, separate from the one that rolls
images:

- **Trigger it by hand only** (`workflow_dispatch`). It needs an identity
  that can create resources and assign roles; the image-roll workflow should
  run with one that cannot, and no push, tag, merge or schedule should reach
  the bigger grant.
- **Pin the identity's OIDC trust to an environment**, and restrict that
  environment's deployment branches to `main`. A dispatch can name any
  branch, so the trust subject alone does not stop a pushed branch from
  declaring the same environment.
- **Apply the saved plan**, not a fresh one: applying a plan nobody read is
  how an apply does something the plan did not say. Requiring the resource
  group name to be typed before an `apply` keeps it from being chosen on the
  way to a plan.
- **If the workflow takes the root as an input**, check it against an
  allowlist before using it as a path.
- **Pass it no application credential.** The chart reads them from a
  Secret in the cluster, so the state holds none.

`examples/aks` has no endpoint until `helm upgrade` runs, so run
`verify_deployment.sh` against the ingress hostname once the chart is
installed, rather than as a step after `apply`.

Run `scripts/bootstrap_tfstate.sh` once first: it creates the state backend
and the infrastructure identity.

## What you must set

`terraform.tfvars` carries infrastructure. `policy.yaml` carries behaviour
and is mounted, not baked. Two surfaces, and the boundary is
*where it runs* against *what it does*.

**Secrets are in neither, and `examples/aks` is handed none.** The chart reads
them from a Secret in the cluster; `deploy/helm/README.md` says which and
how to generate them.

`app-aca` differs, which matters before
composing it in a fork. That module takes its secrets as `sensitive`
variables and writes them into the container apps' secret stores, which
puts them in the Terraform state in plaintext: `webhook_secret`, the
signing secret, and `webhook_secret_previous`, when set; `webhook_secrets`,
one pair per org; `compliance_api_key`; `compliance_api_keys`, one per org; `otel_tokens`, one per org or per `otel_fleets` fleet;
`intake_fleet_token`, `intake_fleet_token_previous`, `intake_fleet_tokens`
and `intake_tokens`, with `enable_intake`; `hash_salt`; `metrics_token`,
when set; `dashboard_auth_client_secret`,
when `dashboard_auth_client_id` is set; and `dashboard_form_key`, with
`dashboard_admins_enabled`. If you go that route, use a backend with
encryption and restricted access, and never a local state file.

Each of those can instead be named by a Key Vault secret id, and the module
then never holds the value: the container app reads it through a Key Vault
reference. The single secrets take an id variable, named as on `app-cloudrun`
where it has one (`webhook_secret_id`, `webhook_secret_previous_id`,
`compliance_key_secret_id`, `intake_fleet_token_secret_id`,
`intake_fleet_token_previous_secret_id`, `hash_salt_secret_id`,
`metrics_token_secret_id`, `dashboard_auth_client_secret_secret_id`,
`dashboard_form_key_secret_id`), and the maps an id map keyed the same way
(`webhook_secret_ids`, `compliance_key_secret_ids`,
`otel_token_secret_ids`, `intake_fleet_token_secret_ids`,
`intake_token_secret_ids`). The writer roles read with `identity_id`, the
Entra client secret with `reader_identity_id` and the form key with
`control_identity_id`; give each Key Vault Secrets User on the vault, which
the module does not grant. A slot given both a value and an id, or a name in
both a map and its id map, is refused. With only ids for the OTel tokens,
set `otel_tokens = {}`.

`app-ecs` takes Secrets Manager ARNs instead, so its state holds no
application secret other than the ALB's OIDC client secret. See § Composing
`app-ecs` with `store-s3`.

## Verifying a deployment

`terraform apply` proving the resources exist proves nothing about whether
they refuse an unsigned request. `scripts/verify_deployment.sh` is that check,
and it speaks HTTP only, so it works against any target.

`examples/aks` has no URL to give it: the endpoint does not exist until the chart
is installed, so run it against the ingress hostname afterwards rather than
from an output.

```
scripts/verify_deployment.sh \
  https://verdict.example.com \
  https://verdict.example.com \
  https://verdict.example.com
```

The hostname appears three times because the chart puts every role that
serves HTTP behind a single host on separate paths. It does cost one assertion: the
dashboard has no `/healthz` of its own on a shared host, so
`dashboard.health` passes against the verdict server's. `deploy/helm/README.md`
says what a separate dashboard hostname buys and what it costs.
