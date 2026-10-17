# Operations

Running a deployment once it is up: rolling a new release and rolling
back, changing the policy, rotating each secret, reading the health
endpoints, excluding test traffic, and two failures whose symptoms point
the wrong way. Standing a deployment up is in [DEPLOY.md](DEPLOY.md).

## Upgrade and roll back

Terraform creates the services and does not roll images: every app module
ignores changes to the image, or on ECS to the task definition. A release
is an image roll by the deploy script for the target, or a `helm upgrade`.
See [Terraform owns infrastructure; CI owns image
rolls](../deploy/terraform/README.md#terraform-owns-infrastructure-ci-owns-image-rolls).

| Target | Roll a release |
|---|---|
| Container Apps | `scripts/deploy_azure.sh <image-tag>`, with `AZURE_DEPLOY_TARGET` set to `aca` and `AZURE_CONTAINER_APP` to the verdict server's app |
| ECS or EKS | `scripts/deploy_aws.sh <sha>`, with `AWS_DEPLOY_TARGET` set to `ecs` or `eks` |
| Cloud Run or GKE | `scripts/deploy_gcp.sh <sha>`, with `GCP_DEPLOY_TARGET` set to `cloudrun` or `gke` |
| the chart, by hand | `helm upgrade` as below |

Each script builds the base and `-ingest` images from the commit and
pushes them. On Container Apps, ECS and Cloud Run it then rolls the
verdict server first and runs `verify_deployment.sh` against it alone
before touching anything else, so a bad image stops the release with only
that service on it. Then it rolls the rest and verifies the whole stack.
On EKS and GKE it runs one `helm upgrade`, which rolls every Deployment at
once. There is no verdict-first gate there, and a failed verification
after the upgrade fails the release without undoing it.

With `AZURE_DEPLOY_TARGET=k8s`, `deploy_azure.sh` builds and pushes the
images and prints the `helm upgrade` to run for AKS. Any other value,
unset or empty included, fails before anything is built.

**On the chart, set both tags every time, and use
`--reset-then-reuse-values`:**

```sh
helm upgrade forgd deploy/helm/forgd-verdict \
  --namespace forgd \
  --reset-then-reuse-values \
  --set image.tag="$GIT_SHA" \
  --set ingest.image.tag="$GIT_SHA-ingest" \
  --set-file policy.inline=policy.yaml
```

`ingest.image.tag` is a stored override. Setting only `image.tag` leaves
the ingest CronJob on the previous release, scanning with the old rule set.
`--reuse-values` does not merge new chart defaults, so the first upgrade
after a release that adds a value either fails at render or quietly runs
on the old value. See [Upgrading: not
`--reuse-values`](../deploy/helm/README.md#upgrading-not---reuse-values).

**On ECS, never point a service at Terraform's own task definition
revision.** It carries the image of the first apply. `deploy_aws.sh`
builds each new revision from the latest one in its family, with only the
image replaced, so Terraform changes since the last release are kept.

**Rolling back** is a roll of an earlier release: the same script or
`helm upgrade`, with the earlier commit's tags and that commit's
`policy.yaml`. Two targets also roll back on their own when a new
revision fails. ECS services run the deployment circuit breaker with
rollback on, and `deploy_aws.sh` fails if it fired. On Cloud Run, a
revision that never becomes ready fails the update and traffic stays on
the old revision.

The `/healthz` build stamp, below, tells you which release is answering.

## Change the policy

The image carries a copy of `policy.yaml`, but every deployment path
replaces it, and an image roll leaves the policy where it was. See
[SERVER.md](SERVER.md) for the policy file itself.

| Target | How the policy arrives | How a change reaches it |
|---|---|---|
| EKS, GKE or AKS, through the chart | `policy.inline`, a ConfigMap mounted into each role | `helm upgrade` with `--reset-then-reuse-values --set-file policy.inline=policy.yaml`. `deploy_aws.sh` and `deploy_gcp.sh` reuse the stored values and pass no policy, so their rolls keep the policy of the last upgrade that passed one. The command `deploy_azure.sh` prints for AKS passes it. |
| Container Apps (`app-aca`) or Cloud Run (`app-cloudrun`) | `policy_yaml`, gzipped into `FORGD_POLICY_INLINE_GZ` | `terraform apply`: the changed variable is a new revision on the image already running. |
| ECS (`app-ecs`) | `policy_yaml`, gzipped into `FORGD_POLICY_INLINE_GZ` in the task definition | `terraform apply` registers a new task definition revision, which the services ignore. The next `deploy_aws.sh` registers each service's revision from the latest in its family, so the policy arrives with that roll. |

## Rotate secrets

| Secret | Overlap | Steps |
|---|---|---|
| signing secret, `WEBHOOK_SECRET` | yes: `server.secrets` lists `$WEBHOOK_SECRET` and `$WEBHOOK_SECRET_PREVIOUS`, and a request signed with either verifies | 1. set `WEBHOOK_SECRET_PREVIOUS` to the current value. 2. Rotate in claude.ai and copy the new secret. 3. Set `WEBHOOK_SECRET` to it and roll. 4. After about five minutes, clear `WEBHOOK_SECRET_PREVIOUS`. On the chart, the values are `secrets.webhookSecret` and `secrets.webhookSecretPrevious` |
| per-org OTel token | yes, under a second name: the collector accepts every `otel.orgs` entry's token, and two entries may name one org. The chart and the Terraform modules generate one `FORGD_OTEL_TOKEN_<NAME>` per org name, so the second token needs a second name for the same org | 1. Add `orgIds.<name>-next` with the same UUID as `orgIds.<name>`, and the new token as `secrets.otelTokens.<name>-next` (or the `otel-token-<name>-next` key in `secrets.existingSecret`). In the policy add an `otel.orgs` entry with `label: <name>-next`, `id: $FORGD_ORG_ID_<NAME>_NEXT` and `token: $FORGD_OTEL_TOKEN_<NAME>_NEXT`, and roll. Both tokens are accepted and file under the one org. 2. Switch that org's exporter to the new token. 3. Set `secrets.otelTokens.<name>` to the new token and remove the `-next` entries from `orgIds`, the secrets and the policy, in one roll: the collector refuses to start while two entries hold the same token. On the Terraform modules the names go in `org_ids` and `otel_tokens` (`otel_token_secret_ids` on Cloud Run, `otel_token_secret_arns` on ECS) |
| fleet OTel token (`otel.orgs[].ids`) | yes: two entries with the same `ids` and different tokens are both accepted | the token serves every org in its set, so a rotation touches all of them at once. Add an entry with the same `ids` and label and the new token (for example `$FORGD_OTEL_TOKEN_LAPTOPS_NEXT`), roll, move every machine's exporter to the new token through MDM and confirm the rollout there, since `/stats` does not count exports per token, then remove the old entry and roll |
| fleet token, `FORGD_INTAKE_FLEET_TOKEN` | yes: the shipped policy's `intake.fleet` lists `$FORGD_INTAKE_FLEET_TOKEN` and `$FORGD_INTAKE_FLEET_TOKEN_PREVIOUS`, and a laptop on either is accepted | 1. Generate a new token. Move the current value to `FORGD_INTAKE_FLEET_TOKEN_PREVIOUS`, set the new one as `FORGD_INTAKE_FLEET_TOKEN`, and roll the intake. 2. Push the new token to every laptop's `policy.yaml` through MDM and wait until MDM reports it installed fleet-wide. 3. Remove `FORGD_INTAKE_FLEET_TOKEN_PREVIOUS` and roll the intake. A laptop still on the old token then gets 401 and scans locally until MDM reaches it. On the chart, the values are `secrets.intakeFleetToken` and `secrets.intakeFleetTokenPrevious`. See [deploy/MDM.md](../deploy/MDM.md#the-fleet-token) |
| metrics token, `FORGD_METRICS_TOKEN` | no: one value | set the new value, roll, and update whatever scrapes `/metrics` or `/stats` |
| Compliance Access Key | none on Anthropic's side: deleting a key takes effect on the next request | create the new key with the same two read scopes for the same single organization ([which organizations a key reads](PLATFORM.md#which-organizations-a-compliance-access-key-reads)), switch the ingest job to it, confirm a pass succeeds, then delete the old key. Cursors survive, because they belong to the organization, not the key |
| `privacy.hash_salt` | no, and not reversible | see below |

**Do not rotate the signing secret during an outage.** Anthropic's
circuit breaker resets itself only while the Inference hooks settings are
unchanged since it tripped, and a rotation counts as a change. Rotate
while it is tripped and you must turn *Enforce verdicts* off and on by
hand. See [CREDENTIALS.md](CREDENTIALS.md) for where each value comes from.

### Rotating the hash salt

Treat the salt as long-lived. Rotating it has three effects:

- **Hashes stop comparing.** Every `excerpt_hash` written before the
  rotation is incomparable with every one written after, so a value found
  on both sides counts as two distinct values.
- **Partitions are orphaned.** Org pseudonyms are salted, so findings
  written before the rotation sit under pseudonyms the current org
  registry no longer resolves. They appear unlabelled and outside org
  entitlements.
- **Losing it costs nothing further,** since nothing is decrypted with it.

Every service that writes findings must hold the same salt: the verdict
server, the collector, the intake and the ingest job. Change it on all of
them in the same roll. Otherwise findings are written under two salts at
once. The dashboard and connector are not given the salt and need no
change. The Claude Code hook uses its own per-device salt and is not
affected. See [PRIVACY.md](PRIVACY.md).

## Health endpoints

| Endpoint | On | Answers |
|---|---|---|
| `/healthz` | verdict server, collector, intake, dashboard, connector | 200 while the process serves. On the verdict server the body has `status`, `mode`, `build`, `gitleaksd` (`not_configured`, `ok` or `down`) and `uptime_s`. The verdict server, collector and intake also answer `/health` |
| `/readyz` | verdict server, collector, intake, dashboard, connector | 200 with `status: ok` while ready, and always with runtime overrides off. 503 with `status: not_ready` and a fixed reason while a service with runtime overrides on cannot confirm what is in force |
| `/livez` | verdict server, collector, intake | 503 only while a configured gitleaks daemon does not answer |
| `/metrics` | verdict server | counters, per-surface figures, detectors, session cache, store sink, runtime overrides and the pre-auth body budget (`preauth_body`). Needs `Authorization: Bearer $FORGD_METRICS_TOKEN`: 404 when the token is unset, 401 with a missing or wrong one |
| `/stats` | collector, intake | what has arrived: by signal on the collector, and by client, with refusals counted, on the intake. The same token, with the same 404 and 401 |

**The build stamp** is `<version>+<first 12 characters of the commit>`.
The image sets the commit from the `FORGD_BUILD_COMMIT` build argument.
Without it, as in a local install, the stamp is the version alone. Each
loaded plugin distribution adds `+<name>=<version>`.
`verify_deployment.sh` with `VERIFY_MAX_UPTIME_S` set uses `uptime_s` to
check that the revision answering is the one just rolled.

**`/readyz` reasons** name the failure and nothing from the store:

- `runtime overrides are not initialized`
- `runtime overrides writer lockout missing`
- `runtime overrides have no valid verify key`
- `runtime overrides have no store to read`
- `runtime overrides need a newer forgd-verdict release`
- `runtime overrides are behind a signed change request`
- `runtime overrides are not the head the signed head anchor names`
- `runtime overrides could not be confirmed`

See [OVERRIDES.md § Readiness](OVERRIDES.md#readiness).

## Pipeline monitors

A reader that stops delivering reports no error, and the dashboard then
shows fewer findings, which looks the same as there being less to find. The
overview's **Pipeline · Delivery** section watches delivery itself, apart
from what was found. Each monitor reads counts, timestamps and ids only,
and shows **unknown**, never zero, when there is nothing to judge. The
control-point panel above it covers a reader that stops altogether.

- **Delivery lag.** For the Compliance API scan and the Managed Agents scan,
  the time from a session's last activity (`session_updated_at`) to its
  record being stored, as p50, p95 and maximum. When the p95 is longer than
  the selected window, the section says comparisons with the live path in
  that window are incomplete: sessions are still arriving. The inference
  hook, the Code hook, agent checks and the collector record when they
  decided or received, so they have no lag to show.
- **Join rate.** Each as matched of total, and the share:
  - Activity Feed denials matched to an inference-hook verdict. A fall
    with steady denials means verdict records are not reaching the store;
  - OTel records attributed to a configured org. Unattributed records
    (`otel-unknown`) mean an org's token or id is not configured.

  Compliance API sessions are not matched to inline verdicts: the two
  carry session ids that are not documented to be the same value, so a
  ratio would measure the id formats rather than delivery.
- **Cursor health.** For each Compliance API org and Managed Agents
  workspace, how long ago its last completed pass started, against the
  period after which what it has not read is gone: the workspace's
  `managed_agents.window_days`, and for the Compliance API
  `compliance.retention_days`, which you set to your organization's
  retention period. The API does not report it, so without that setting
  the age is shown and the state is unknown. Past half the period it reads
  **watch**; past the whole period, **broken**: activity since the last
  pass may already be gone.
- **Silent detectors.** A detector that fired on at least three of the
  window's earlier days and not at all on its newest day, while a source it
  fired on still delivered that day. A reader that stopped is the
  control-point panel's to show, so a detector whose sources delivered
  nothing is not listed. It needs more than three days of records in the
  window.
- **Records per source per day.** The last seven days of the window, with
  **stopped** beside a source that delivered the day before and nothing on
  a day the others delivered. This is the per-source coverage view; select
  an org to see one org's. It counts records, not the share of activity
  each source saw: no source sees all of an organization's activity, so
  there is no total to divide by.

## Excluding test traffic

Exclusion keeps named frames out of the dashboard's rates. The records
stay in the store and in the event log, and the page shows how many are
excluded.

```bash
forgd-verdict exclude --store ./findings --list          # frames with findings, and their ids
forgd-verdict exclude --store ./findings --request-id X  # exclude one frame
forgd-verdict exclude --store ./findings --clear         # restore everything
forgd-verdict reset-stats --store ./findings             # start the rates from now
```

Exclusion is by `request_id`. The Claude Code hook builds one per decision
from `prompt_id` or `tool_use_id`, falling back to a ULID.

With runtime overrides off, these write `markers/*` objects in the store.
With them on, they write fields of `state/runtime-overrides.json`, and
each change is audited under the principal `cli`, marked unverified. On a
cloud store that write needs the control identity's credentials, and the
CLI refuses on a writer identity's. An exclusion equal to a configured org
id is refused. A dashboard admin can make the same changes from the Policy
tab. See [PLATFORM.md § Excluding test
traffic](PLATFORM.md#excluding-test-traffic) and
[OVERRIDES.md](OVERRIDES.md).

## Reading the Event Log

The Event Log shows 200 events a page, newest first, and **Older events**
pages back through the window. A page reads the store a day at a time from
the newest day and stops at a day boundary once it has 200 rows or has read
20,000 records, so a narrow filter can give a page with fewer rows and an
**Older events** link. A device, client or detector filter parses only
the lines that hold its value and stops once it has read 256 MiB of
objects instead, and a device or client filter reads only the Code hook
and agent check partitions, so one laptop's rows across a week of a
900-laptop fleet come back on the first page. Rows that share the last row's time are all on the
same page. A record the viewer may not see, such as an org-pending record
of a fleet they hold one org of, does not count towards the 20,000; the
page stops in the same way after 200,000 of those.

The Code hook's allow rows are hidden by default; a link on the page shows
them. A clean allow is counted into a tally row rather than stored on its
own, so a shown allow row says how many allows it stands for: those from
one session on one device since the intake's previous flush. The filter box narrows to a device id or a detector name, and only
within the orgs the viewer may see.

## Troubleshooting

**`The containerapps job '<job>' does not exist`, for a job that exists.**
`Container Apps Contributor` grants nothing on `Microsoft.App/jobs`, and
Azure reports an unauthorized read as absence. A job needs `Container Apps
Jobs Contributor`. `deploy_azure.sh` runs `job show` first so the error
names the cause.

**Records are queued and nothing is written, with no error, on Azure.**
The blob store authenticates with the app's user-assigned managed
identity, and without `AZURE_CLIENT_ID` the credential chain cannot choose
one. Set `AZURE_CLIENT_ID` to the identity's client id on every app that
reads or writes the store. `/metrics` then reports a failure as a counted
error, and `last_flush_ms` shows a slow or stuck backend. The symptom
without it is `"written": 0` with `pending` above 0 under `store`, the
stuck record counted in `inflight`.

**Hook requests answered 503 `busy` while Anthropic's activity shows
webhook failures.** Bodies whose signature has not been verified yet hold
the whole pre-auth budget. On `/metrics`, `counters.preauth_budget_exhausted`
counts the refusals and `preauth_body` shows `in_use_bytes` against
`budget_bytes`; `peak_bytes` near the budget with few signed requests
(`requests`) is traffic that is not Anthropic's. Turn on the source
allowlist ([SERVER.md § Deploy](SERVER.md#deploy)). If the traffic is
Anthropic's own, raise `server.preauth_body_budget_bytes` together with
the memory limit ([SERVER.md § Memory](SERVER.md#memory)).
`counters.body_timeout` counts bodies that did not arrive within
`server.body_read_timeout_s`.

More symptoms and their causes are in [CREDENTIALS.md
§ 6c](CREDENTIALS.md#6c-container-apps-jobs-need-a-different-role) and
[§ 7](CREDENTIALS.md#7-azure_client_id--required-and-its-absence-hangs-rather-than-fails).

**Laptops report `scan service answered 503; scanning locally`.** The
intake's `/scan` lanes are full: `scan_busy_small` or `scan_busy_large`
is rising in the intake's `/stats`. A laptop scans locally for that
prompt and its record arrives later through `/intake`. Occasional large
refusals are a laptop sending a big tool response while another is being
scanned; a steady `scan_busy_small` means the intake needs more replicas.
See [PLATFORM.md](PLATFORM.md) for the lane sizes.
