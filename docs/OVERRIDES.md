# forgd-verdict: runtime overrides

A signed-in dashboard admin changes a small allowlist of settings, and
the change reaches the running services without a release. This guide is
for the operator who turns runtime overrides on and runs them. How they
work inside, and why, is in the
[design note](design/overrides.md). Points no source settled are marked
**UNCONFIRMED**.

---

## What can be overridden

### The allowlist

Four controls, and nothing else:

| Control | Values | Who reads it | What it does |
|---|---|---|---|
| `server.mode` | `observe`, `enforce` | verdict server, intake | The same knob as `FORGD_VERDICT_MODE`, reachable from the dashboard without console access to the platform. |
| exclusions | a set of request ids | dashboard, connector | What `forgd-verdict exclude` does: named frames leave the rates and stay in the store. |
| statistics reset | a UTC timestamp, or none | dashboard, connector | What `forgd-verdict reset-stats` does: the statistics floor moves, and nothing is deleted. |
| denied devices (`denied_devices`) | a set of intake device ids, each `d` and 12 lowercase hex characters, at most 5,000 | intake | Each listed device gets 403 `device_denied` on `/intake` and `/scan`, counted as `device_denied` in `/stats`. How one laptop on a shared fleet token is cut off ([deploy/MDM.md](../deploy/MDM.md#revoking-one-device)). Device deny is not available on Cloud Run: `app-cloudrun` runs with runtime overrides off, so its intake never reads the denied devices; there, the only way to cut a device off is a fleet-wide rotation: issue a new fleet token with the old one in `FORGD_INTAKE_FLEET_TOKEN_PREVIOUS`, then clear it, which also cuts off every laptop not yet given the new token. |

**Upgrade every intake replica before denying a device.** Denying one
raises the object's `min_reader_version` to the writing release, as
setting `server.mode` does, and it stays raised while a device is denied
or `server.mode` is set. A release older than the denylist does not adopt
the object: its intake keeps its last-known-good state or, with none, is
not ready. It never applies the object while ignoring the list. A device
id is checked against the header's form (a letter or digit, then up to 63
letters, digits, `.`, `_`, `:` or `-`), scanned by the detectors like any
other value, and refused when it equals a configured org id.

`server.mode` cannot be set to `archive`, which the verdict server
decides at startup. When the baseline mode is `archive`, a `server.mode`
override is ignored and logged, and the dashboard shows the control as
unavailable.

### Explicitly not on it

`dashboard.auth.*`, `dashboard.entitlements` and `dashboard.admins`;
every `detectors.*` and `privacy.*` path; every secret path; and
`server.secrets`, `server.require_signature`, `server.on_internal_error`
and `otel.orgs[].id`. The allowlist is a closed set in code, and a test
keeps every path above off it.

## Precedence

```
policy.yaml  <  ENV_OVERRIDES  <  runtime overrides
```

`policy.yaml`, with `ENV_OVERRIDES` applied, is the **baseline**. The
overrides object applies last, for allowlisted keys only.

- **An env change is masked while an override exists.** With
  `server.mode: enforce` in the store, `FORGD_VERDICT_MODE=observe` leaves
  the service in enforce, and the verdict server logs that the override
  masks it. To use the console as an emergency brake, first run
  `forgd-verdict overrides clear server.mode` as the control identity.
- **A release does not clear overrides.** A release that changes
  `server.mode` in `policy.yaml` changes the baseline, and an active
  override keeps masking it until cleared.
- **The baseline is each service's own.** A `FORGD_VERDICT_MODE` set on
  the verdict service alone is not visible to the dashboard.

---

## Turning runtime overrides on

### Who may change it

```yaml
dashboard:
  admins:
    allowed_origins: ["https://verdict-dashboard.example.com"]
    form_key: "$FORGD_DASHBOARD_FORM_KEY"
    groups:
      - {issuer: "https://login.example/", group: "forgd-operators"}
```

- **Admins need `dashboard.auth.mode: oidc_jwt`,** without `platform:
  iap`, or the dashboard refuses to start. With more than one issuer,
  every group names its `issuer`.
- **An admin action needs a verified `sub` and complete groups.** A
  principal with an Entra groups overage is shown no controls.
- **Admin rights do not widen read scope.** With `dashboard.entitlements`
  on, every admin action is checked against the orgs it affects, on the
  page and again when it is posted. Excluding or removing an exclusion of
  a request id, and denying or accepting again a device, need every
  record that carries that id or device in the last 30 days to be in an
  org the admin may read, and at least one such record. Every other
  action (`server.mode`, the statistics reset, **clear all** on the
  exclusions or the denied devices, **clear all overrides**, initialise
  and recover) affects every org, and needs an admin entitled to every
  partition the entitlement map grants and every labelled org. A refused
  post answers 403 and logs `out_of_scope`. The Policy tab lists only the
  exclusions and denied devices the viewer may change, counts the rest,
  and withholds their values in **Recent changes**. Without entitlements,
  every admin may apply every action.
- **`allowed_origins`** is the dashboard's origin as the browser sends
  it. **`form_key`** is a secret shared by every dashboard replica, from
  the secret store; rotating it only invalidates open forms.

### When runtime overrides are on

A service honours runtime overrides only when both hold:

- the policy's `dashboard.admins` lists at least one group; and
- `FORGD_OVERRIDES_ENABLED` is exactly `true` in its environment. The
  Helm chart sets it on every workload with `dashboard.admins.enabled`,
  and `app-aca`, `app-ecs` and `app-cloudrun` with
  `dashboard_admins_enabled`. Those settings also give the dashboard the
  control identity.

With no groups listed, overrides are off: no service reads the object,
`exclude` and `reset-stats` write the legacy `markers/*` objects, and
every `overrides` command but `show` and `keygen` exits 2.

With groups listed and the variable not set, every service ignores the
object and logs one WARNING at start:

> dashboard.admins lists groups but this deployment has not enabled the
> control identity (chart value dashboard.admins.enabled, module
> variable dashboard_admins_enabled), so FORGD_OVERRIDES_ENABLED is not
> true and runtime overrides and admin actions are off

The dashboard renders no controls and answers admin actions with 403
(`control_identity_off`). The CLI still writes the object, which no
service honours.

**Turning overrides off drops every service to the baseline.** Removing
the groups, or turning the deployment's flag off, stops every override
applying on each service's next start. Clear overrides first.

### Initialising the store

1. **Apply the store module with `control_enabled = true` and the app
   module (or chart) with admins on, in one change.** The app modules'
   control inputs are the store module's control outputs (see
   [Store access](#store-access)). A service that starts before the apply
   runs with overrides off until the apply restarts it.
2. **Run `forgd-verdict overrides init` once, as the control identity**
   (see [Running the CLI as the control identity](#running-the-cli-as-the-control-identity)),
   or use **Initialise** on the dashboard's Policy tab. It writes a
   genesis record and an empty object, and does nothing on a store that
   already has one.

   Until then every service without a last-known-good is not ready
   (`runtime overrides are not initialized`): a replica does not guess
   whether an empty store is new or wiped. Run init right after the apply.
3. **Run `forgd-verdict overrides migrate-markers` once, as the control
   identity.** It folds the legacy `markers/*` objects into the overrides
   object and retires them. Until then a reader that has adopted the
   object still applies the marker objects, which the writers can change
   unaudited, and a banner says so. A reader that has adopted no object,
   before `init` or while it cannot confirm one, applies neither marker:
   its rates exclude nothing and have no reset until it adopts one. Run it
   even with no marker objects; a re-run writes nothing.

On `app-cloudrun` overrides are never on: the module refuses dashboard
admins (see
[Where dashboard admins are not available](#where-dashboard-admins-are-not-available)).

---

## Store access

The dashboard writes with a third store identity, the **control
identity**: the reader's grants, writes to `state/runtime-overrides.json`
and create-only writes under `audit/runtime-overrides/`, and the reads
the [writer lockout](#writer-lockout) check needs. With `control_enabled`,
each store module creates it and takes every write to both paths away
from the writers; with it off, plans are unchanged. The IAM detail is in
the design note's [Store access](design/overrides.md#store-access).

What the operator grants or checks, per cloud:

- **GCS (`store-gcs`).** Turning `control_enabled` on replaces the writer
  bindings `writer_create` and `writer_mutable_delete`, create before
  destroy. If a writer holds an organization custom role, grant the
  control identity `iam.roles.get` on the organization, which the module
  does not; until then that writer fails the lockout check.
  **The lockout check reads bucket bindings only.** A bucket's IAM policy
  does not include roles inherited from the project, folder or
  organization, and does not expand groups, so the check cannot see a
  writer that holds `storage.*`, Editor or Owner above the bucket or
  through a group. Audit those grants, then set
  `dashboard.admins.gcsInheritedAuditedBy` (`FORGD_OVERRIDES_GCS_INHERITED_AUDITED_BY`)
  to who did it and when. Until it is set, every writer that passes the
  bucket check reports `inherited_grants_unaudited` and nothing is
  adopted. The value is an attestation: the dashboard does not check it.
  Re-audit whenever IAM above the bucket changes.
- **S3 (`store-s3`).** The bucket policy denies the module's
  `writer_role_arn` every write to both paths. A writer role created
  outside the module (an ECS task role, an EKS service-account role) is
  not covered: attach `writer_deny_policy_json` to it, gated on the same
  flag. It denies both paths, any change to the bucket's policy or
  configuration (a lifecycle rule could otherwise expire the audit chain),
  and deletes:

  ```hcl
  resource "aws_iam_role_policy" "no_runtime_overrides" {
    count  = var.control_enabled ? 1 : 0
    role   = aws_iam_role.my_writer.name
    policy = module.store_s3.writer_deny_policy_json
  }
  ```

  That role still fails the lockout verification, which reads only the
  bucket policy, so run every writer as `writer_role_arn`.
- **Azure (`store-azure`).** With `control_enabled`, every identity gets
  a custom role, which needs `Microsoft.Authorization/roleDefinitions/write`
  on the resource group (Owner or User Access Administrator) to apply. The
  storage account gets a `CanNotDelete` lock unless
  `storage_account_delete_lock = false`; turn it off before any apply that
  removes or replaces one of the module's role assignments, or destroys
  the store. Editing the writer's condition text fails the apply with
  `RoleAssignmentExists` and leaves the old assignment.
- **app-aca** reads the signing key from Key Vault with the control
  identity, which needs `Key Vault Secrets User` on the vault. The module
  does not grant it.

### Helm and the app modules

Everything below is off by default. The app modules take the store
modules' outputs as inputs.

| Where | Inputs | What they do |
|---|---|---|
| Helm | `dashboard.admins.enabled`, `serviceAccounts.control` (`name`, `clientId`, `annotations`), `secrets.dashboardFormKey` (secret key `dashboard-form-key`), `dashboard.admins.signingKey`, `dashboard.admins.verifyKeys`, `dashboard.admins.writerIdentities`, `dashboard.admins.storageAccountId`, `dashboard.admins.gcsInheritedAuditedBy` | The dashboard runs as the control service account and gets the form key, the signing key, `FORGD_OVERRIDES_WRITER_IDENTITIES`, on Azure `FORGD_OVERRIDES_STORAGE_ACCOUNT_ID`, and on GCS `FORGD_OVERRIDES_GCS_INHERITED_AUDITED_BY` when set. Every workload gets `FORGD_OVERRIDES_ENABLED`, `FORGD_OVERRIDES_VERIFY_KEY` and `FORGD_OVERRIDES_WRITER_ROLES`. The chart refuses a control identity equal to the reader's or the writer's, a missing form key, admins without `oidc_jwt` or with `platform: iap`, an empty or blank `writerIdentities`, an Azure store URL with no `storageAccountId`, and, with the dashboard enabled, a policy with admin groups while `dashboard.admins.enabled` is false. It cannot see the store module, so it relies on the runtime lockout probe. |
| `app-aca` | `dashboard_admins_enabled`, `control_identity_id`, `control_client_id`, `dashboard_form_key`, `dashboard_signing_key_secret_id`, `overrides_verify_keys`, `overrides_writer_lockout`, `overrides_writer_identities`, `overrides_storage_account_id` | The control identity is attached beside the reader. Refused at plan unless `overrides_writer_lockout` is true, both identity inputs are set, and the identities include `identity_principal_id`. |
| `app-ecs` | `dashboard_admins_enabled`, `control_role_arn`, `dashboard_form_key_secret_arn`, `dashboard_signing_key_secret_arn`, `overrides_verify_keys`, `overrides_writer_lockout`, `overrides_writer_identities` | The dashboard task role becomes the control role. The connector keeps `reader_role_arn`. Refused at plan unless `overrides_writer_lockout` is true and the identities include `writer_role_arn`. |
| `app-cloudrun` | `dashboard_admins_enabled` and the rest | **Refused at plan**: the dashboard signs in through IAP. |
| `cluster-gke/-eks/-aks` | `control_enabled`, `control_service_account`, and `control_email` / `control_role_arn` / `control_identity_id` | Federation for the control service account. cluster-eks also outputs `control_assume_role_policy`. |
| `store-gcs` | `control_enabled`, `control_account_id`, `control_members`, `control_iam_read_role_id`, `control_role_read_role_id` | Outputs `control_email`, `control_member`, `overrides_writer_lockout` and `overrides_writer_identities`. |
| `store-s3` | `control_enabled`, `control_role_name`, `control_assume_role_policy` | Outputs `control_role_arn`, `writer_deny_policy_json`, `overrides_writer_lockout` and `overrides_writer_identities`. |
| `store-azure` | `control_enabled`, `control_identity_name`, `control_role_name`, `control_evidence_role_name`, `writer_role_name`, `reader_role_name`, `storage_account_delete_lock` | Outputs `control_identity_id`, `control_identity_client_id`, `control_identity_principal_id`, `overrides_writer_lockout`, `overrides_writer_identities` and `storage_account_id`. |

`overrides_writer_lockout` is true only with `control_enabled`, and an app
module refuses admins without it. `overrides_writer_identities` lists the
writer identities the dashboard checks: the writer role ARN on S3, the
writer IAM members on GCS, the writer principal id on Azure.

### Where dashboard admins are not available

- **Anywhere the dashboard signs in through IAP:** `app-cloudrun`, and
  the chart with `ingress.className: gce`. IAP tokens carry no groups.
  The CLI still works there.
- **store-azure with a key prefix.** The ABAC condition names paths from
  the container root.

**UNCONFIRMED:** the Azure ABAC condition string has not been applied
against a real tenant. If Azure normalises its whitespace, a plan could
show a diff on every run.

---

## Signing keys

Every record that changes or anchors the overrides is signed with
Ed25519, and every reader verifies it.

- **The private key**, `FORGD_OVERRIDES_SIGNING_KEY`, is on the dashboard
  only, and in the shell of an operator running the CLI as the control
  identity. Every other service refuses to start with it, even with
  overrides off. In `policy.yaml` it may only be a `$NAME` reference.
- **The public keys**, `FORGD_OVERRIDES_VERIFY_KEY`, comma-separated, go
  on every service that reads overrides. The dashboard and the CLI refuse
  a signing key whose public half is not listed.
- **Generate a pair** with `forgd-verdict overrides keygen
  --private-key-file signing.key`, which writes the private key to a new
  file with mode 0600 and prints `key_id` and `public_key`. It needs
  exactly one of `--private-key-file PATH` and `--private-key-stdout`.
  Put the private key in the platform's secret store, then delete the
  file.

| Deployment | Signing key, dashboard only | Verify keys, every service |
|---|---|---|
| Helm chart | a Secret named by `dashboard.admins.signingKey.secretName` (default `secrets.existingSecret`), key `dashboard.admins.signingKey.key` (default `overrides-signing-key`) | `dashboard.admins.verifyKeys` |
| app-ecs | Secrets Manager, `dashboard_signing_key_secret_arn`, read by the dashboard's execution role | `overrides_verify_keys` |
| app-aca | Key Vault, `dashboard_signing_key_secret_id`, read by the control identity | `overrides_verify_keys` |
| CLI | `FORGD_OVERRIDES_SIGNING_KEY` in the operator's shell | `FORGD_OVERRIDES_VERIFY_KEY` |

Each refuses admins with no signing-key reference or no verify key, and
a verify key that is not 43 characters of unpadded URL-safe base64.

**Rotating the signing key.** Take the steps in this order; a step taken
early leaves readers refusing records.

1. **Add the new verify key everywhere.** Generate a pair, add its public
   key beside the old one, and roll every service.
2. **Switch the signing key.** Point the dashboard's signing-key secret,
   and the CLI's variable, at the new private key, and roll the
   dashboard.
3. **Make one change that changes something** (not `init` or
   `recover`). It writes the new-key checkpoint and two new-key
   verification records that let readers drop the old key. A change to
   the value already in force does not. If a record could not be
   written, wait for the dashboard's next hourly run.
4. **Remove the old verify key everywhere,** and roll every service.

If the old key leaked, take the steps back to back: readers accept what
it signs until step 4. Whoever holds both the signing key and the control
identity can write any state every reader adopts, so guard both.

---

## Setting, showing and clearing

### On the dashboard

The Policy tab has a **Runtime overrides** panel, one row per control,
shown to admins and, once an object exists or cannot be read, to every
viewer. Each row shows the baseline value and its source, the override,
who set it and when, and whether it masks a different baseline.

- Admins get **set observe** / **set enforce** and **clear** on
  `server.mode`, **reset now** and **clear** on the statistics reset, and
  **remove** per excluded request and **clear all** on the exclusions,
  and **accept again** per denied device and **clear all** on the
  denied devices. **Clear all overrides** leaves the reset, the
  exclusions and the denied devices alone.
- **Initialise** appears while the store is not initialized, and
  **Recover** while the object is invalid or has gone after a valid read
  (see [Recovery](#recovery)).
- **Exclusions are added from the Event log**, with the **exclude**
  button on each row with findings and a request id. An admin can
  exclude only a frame the dashboard rendered for them, and with
  entitlements on, only one whose request id no record outside their
  orgs carries.
- **Devices are denied from the Event log**, with the **deny device**
  button beside the device id on each intake row whose id is a valid
  device id.
- **Recent changes** lists the last 20 applied changes, and separately
  any requested but not applied. A banner on every page shows while an
  override is active. Org ids are never shown.
- Each change shows a result: `applied`, `nochange`, `conflict` (the
  object changed; review and retry), `invalid` (recover first), `refused`,
  `unreadable` or `error` (see the dashboard log).

### From the CLI

Every write needs the control identity's credentials and the signing key
(see [Running the CLI as the control identity](#running-the-cli-as-the-control-identity)).

```sh
forgd-verdict overrides show                    # the object, what is in force, recent changes (JSON)
forgd-verdict overrides set server.mode enforce
forgd-verdict overrides clear server.mode
forgd-verdict overrides clear-all               # every override; the reset, exclusions and denied devices stay
forgd-verdict overrides deny-device <id>        # refuse an intake device on /intake and /scan
forgd-verdict overrides undeny-device <id>
forgd-verdict overrides clear-devices
forgd-verdict exclude --request-id <id>         # repeatable
forgd-verdict exclude --list                    # frames with findings and their ids
forgd-verdict exclude --clear
forgd-verdict reset-stats [--at <RFC 3339>]
forgd-verdict reset-stats --clear
```

Each takes `--store`, and `--without-gitleaks`: the CLI scans every value
it writes with the `dashboard` profile's detectors, built on the
operator's machine, and refuses every change when that profile requires
the gitleaks daemon and the socket is not reachable there. With the flag,
every configured detector but gitleaks scans the change, and the CLI says
so. `--clear` clears the object's field only; until
`migrate-markers`, a marker object's value stays in effect, and the CLI
warns. CLI changes are audited as issuer `cli`, `<os user>@<hostname>`,
and shown as "CLI, unverified".

| Exit | Meaning |
|---|---|
| 0 | applied, or `nothing to do` |
| 1 | the object is invalid (`run forgd-verdict overrides recover`), changed while the command ran (run it again), or could not be read |
| 2 | refused: overrides off, no signing key, the policy did not load, a detector matched a value, the credentials may not write, or a rule refused the change |

### Enforce by override is not durable

While `server.mode` is `enforce` only by override, the dashboard and the
verdict server say:

> server.mode is enforce only because of a runtime override. Replicas run
> in observe if dashboard.admins stops listing groups. If the store loses
> the overrides object, replicas that start afterwards are not ready and
> refuse requests until it is restored or initialized again. To make
> enforce durable, set server.mode: enforce in policy.yaml.

---

## Running the CLI as the control identity

Every write (`exclude`, `reset-stats`, and `overrides init`, `set`,
`clear`, `clear-all`, `recover` and `migrate-markers`) needs the control
identity's credentials. On writer credentials the CLI writes nothing,
exits 2, and prints:

```
refused: these credentials may not write the runtime overrides audit prefix. Changing runtime overrides needs the control identity, not the writer identity the services run as; see "Running the CLI as the control identity" in docs/OVERRIDES.md
```

Reads (`overrides show`, `exclude --list`) work on any identity that can
read the store.

After each change on a cloud store, the CLI writes a lockout
verification record, which needs `FORGD_OVERRIDES_WRITER_IDENTITIES` (and
on Azure `FORGD_OVERRIDES_STORAGE_ACCOUNT_ID`) set as on the dashboard.
Without them it warns, and cold services wait for the dashboard's next
check, within a minute. The dashboard container has both set.

The routes below have not been exercised against a live deployment;
each uses the cloud's standard way to act as an identity.

- **GCS** (`store-gcs` output `control_email`). The operator needs
  `roles/iam.serviceAccountTokenCreator` on that account:

  ```sh
  gcloud auth application-default login \
    --impersonate-service-account=<control_email>
  forgd-verdict exclude --store gs://<bucket>/<prefix> --request-id <id>
  ```

  Or `kubectl exec` into the dashboard's pod on GKE.
- **S3** (`store-s3` output `control_role_arn`). Add the operator's
  principal to the role's trust policy, `control_assume_role_policy`, and
  use a profile with `role_arn = <control_role_arn>`:

  ```sh
  AWS_PROFILE=forgd-control forgd-verdict exclude --store s3://<bucket>/<prefix> --request-id <id>
  ```

  Or `aws ecs execute-command` into the dashboard task.
- **Azure** (`store-azure` outputs `control_identity_client_id`,
  `control_identity_id`). A user-assigned managed identity works only
  from compute it is attached to, so run the CLI in the dashboard
  container:

  ```sh
  az containerapp exec --name <dashboard app> --resource-group <rg> \
    --command "forgd-verdict exclude --request-id <id>"
  ```

  On AKS use `kubectl exec`.
- **Local store.** Any user who can write the directory can run the CLI.

---

## Checking that it works

- **`/readyz`** on the verdict server, intake, collector, dashboard and
  connector answers 200 `{"status": "ok"}` while what is in force is
  known, and always with overrides off. `/healthz` and `/livez` never
  depend on overrides.
- **`forgd-verdict overrides show`** prints `runtime_overrides` (below),
  `cold_reader` (whether a service starting now would adopt this object,
  and if not, why), the object, the legacy marker state and the recent
  changes. When a cold reader would refuse the object, it and `exclude
  --list` warn on stderr.
- **The `runtime_overrides` field**, in the verdict server's `/metrics`,
  the collector's `/stats`, every startup log and the ingest run summary,
  carries `status` (`ok`, `absent`, `unreadable`, `invalid`, or
  `disabled`, with `error` saying why), `source` (`object`,
  `last_known_good` or `baseline`: what is in force), `ready`, `revision`,
  `keys`, `lockout` on a writer, `writers`, and `in_error`, 1 while the
  last refresh failed in any way. **Alert on `in_error`.**
- **The audit record.** Every change writes a signed, create-only record
  under `audit/runtime-overrides/` before the object, naming who made it
  (in plain text) and the old and new values; the dashboard's recent
  changes and `overrides show` read them. Its format is in the design
  note's [Actions and the audit record](design/overrides.md#actions-and-the-audit-record).

---

## What failure looks like

A running replica keeps the last valid object it read (its
**last-known-good**) through any store failure, including the object
disappearing. A replica that starts cold and cannot confirm what is in
force is **not ready**, on the baseline, until it can.

### Readiness

While not ready, `/readyz` answers 503 with `status: not_ready`, a fixed
`reason` and the read's `runtime_overrides` status word:

| Reason | What to do |
|---|---|
| `runtime overrides are not initialized` | Run `overrides init` ([Initialising the store](#initialising-the-store)). |
| `runtime overrides could not be confirmed` | The object is unreadable, invalid, or gone while audit records remain. Fix the read first (a role, a network path, a key); if it reads and is invalid or gone, see [Recovery](#recovery). |
| `runtime overrides writer lockout missing` | See [Writer lockout](#writer-lockout). |
| `runtime overrides have no valid verify key` | Set `FORGD_OVERRIDES_VERIFY_KEY` on the service. |
| `runtime overrides have no store to read` | The service honours overrides but resolved no store. Configure its store. |
| `runtime overrides need a newer forgd-verdict release` | The object's `server.mode` was set, or a device denied, by a newer release. Upgrade the service, or clear `server.mode` and the denied devices. |
| `runtime overrides are behind a signed change request` | A change stopped half-written, or an older object was restored. See [Recovery](#recovery). |
| `runtime overrides are not the head the signed head anchor names` | An older object was restored, or the newest change's verification record has not landed yet. See [Recovery](#recovery). |

A cold replica also refuses work, so a load balancer that ignores
`/readyz` cannot route around it:

the verdict server answers `/hook` as an internal error in enforce (500
`{"error": "scan_failed"}` by default); intake (`/intake`, `/scan`) and
the collector (`/v1/logs`, `/v1/traces`) answer 503 `{"error":
"not_ready"}`; each refusal bumps `overrides_not_ready`; and the ingest
jobs exit 1.

The dashboard and the connector are not gated. If every replica restarts
cold during a store outage, governed prompts have no ready endpoint until
the store reads. That fails closed.

With overrides on, every probe below requests `/readyz`, which is not
routed through any ingress.

| Platform | Holds it out of traffic | Restarts or replaces it |
|---|---|---|
| Helm | `readinessProbe` on every Deployment, and in GKE mode each BackendConfig's health check | The verdict server, collector and intake have a `startupProbe` on `/readyz`, so one not ready within 60 s of starting is restarted, and again after each restart. The dashboard and the connector stay running out of service. |
| Container Apps (`app-aca`) | A readiness probe on the verdict server, collector, dashboard and connector | Nothing restarts it for readiness. |
| ECS (`app-ecs`) | The ALB target group's health check, for every service | ECS replaces a task the target group reports unhealthy after the grace period (60 or 120 s), or whose container check fails six times after a 90 s start period. |
| Cloud Run (`app-cloudrun`) | A startup probe on every service, and a readiness probe | A startup probe that fails for its whole window (60 or 120 s) shuts the container down; a failing readiness probe afterwards only stops new traffic ([Google's documentation](https://docs.cloud.google.com/run/docs/configuring/healthchecks)). The module refuses admins, so none of this is reached yet. |

`verify_deployment.sh` polls `/healthz`, so it does not see readiness. It
fails a roll whose new replicas never become ready only through
`VERIFY_MAX_UPTIME_S`, when the old revision keeps answering.

### Writer lockout

A writer identity that can write the audit prefix could forge an
override, so nothing is adopted until every writer's lockout is proven.

- **Each writer probes its own lockout** with a create under the audit
  prefix, at start and then hourly. Its `runtime_overrides.lockout` is
  `denied` (the lockout holds), `allowed` (it is missing: the writer is
  not ready, warm or cold, and logs what to fix), or `unproven` (a local
  store always is). A writer that is not `denied` adopts nothing.
- **The dashboard checks every writer identity** against the cloud's IAM
  policy as it starts, hourly, and after each change, and writes a signed
  record. The check is structural: it reads the bucket policy on S3, the
  bucket bindings on GCS (plus the operator's attestation for inherited
  and group grants, above), and the role assignments that apply to the
  writer on Azure, including those made to its groups and inherited from
  above the storage account. It does not evaluate every way a principal
  can gain access, which is why each writer also probes its own lockout. Readers adopt a new object only while the newest record is
  under two hours old and shows every identity locked out. Otherwise
  their `writers` field names each failing identity and its reason (see
  [Writer lockout verification](design/overrides.md#writer-lockout-verification)),
  a cold reader is not ready, and the dashboard refuses admin actions. A
  deployment without the dashboard has no verifier, so adopts nothing.
- `FORGD_OVERRIDES_WRITER_ROLES`, which the chart and the app modules
  set, names the writer roles to expect. Unset, nothing is adopted.

**A widened writer grant takes every replica out of readiness.** If a
writer gains write on either path (the exclusion removed, a broader role
granted, or `control_enabled` turned off with admins on), each writer
goes not ready at its next probe, within an hour, and the next
verification fails; cold replicas of every role are not ready once it is
stale. To recover, either:

1. **Restore the lockout.** Re-apply the store module with
   `control_enabled = true` and remove the widening grant. Then restart
   the dashboard to verify at once (`kubectl rollout restart
   deployment/<fullname>-dashboard`, where `<fullname>` defaults to
   `<release>-forgd-verdict`; a new ECS deployment; or a new Container
   Apps revision), or wait for its retry: the dashboard rewrites a failing
   verification five minutes after its last run, doubling the wait each
   time its run fails again, and at least hourly. There is no command
   that triggers a verification.
2. **Turn runtime overrides off** (`dashboard.admins.enabled: false`, or
   `dashboard_admins_enabled = false`). Every service serves from
   `policy.yaml` alone.

**UNCONFIRMED:** the probe and the verification have been tested against
fakes shaped like each cloud, not against real S3, GCS or Azure. Any
answer of another shape fails closed.

---

## Recovery

Recovery is a valid write. Check the state first with
`forgd-verdict overrides show` and the recent changes, then run the CLI
as the control identity.

- **To return to the baseline,** clear the overrides from the dashboard
  or with `overrides clear` / `clear-all`. Every replica adopts it within
  a minute. Deleting the object is never a way to clear: it is retained
  over.
- **The object is gone while its audit records remain** (deleted, left
  out of a restore, or an init whose object write failed). Every change
  but recover is refused with a message to run it. Run
  `forgd-verdict overrides recover`. If the audit records are gone too,
  `overrides init` starts the store again, empty.
- **The object is invalid** (malformed, an unknown version, a bad
  value): run `overrides recover`.
- **An older object was restored**, or **a change stopped half-written**
  (a crash between its record and its object write). Every change but
  recover is refused, with exit 1 and `object_before_anchor` or exit 2
  and `object_behind_request`. A change in flight causes the second for
  a moment; run it again. Otherwise run `overrides recover`: while the
  newer signed records remain, it keeps the newest state, including a
  stopped change, not the restored one.
- **No fresh verification record, and the dashboard restarted** (a
  dashboard outage over two hours, or deleted records). The dashboard has
  nothing to vouch for and writes no record; cold readers stay not ready
  and admin actions are refused. Run `overrides recover`.
- **`code: verification_base_in_future`** with a `base_id` in the
  dashboard's or the CLI's log: the newest verification record is dated
  ahead of this clock. Check this clock first; if it is right, fix the
  writer's clock and delete
  `audit/runtime-overrides/<YYYY>-<MM>-<DD>/verify-<base_id>.json`.
- **`code: verification_clock_ahead`** in the dashboard's or the CLI's
  log: no verification record was written. With `ahead_s`, this
  process's clock is that many seconds ahead of the store's, more than
  five minutes; fix it (NTP on the node or the operator's machine).
  Without it, the store cannot say when a record was written, and its
  adapter needs `audit_modified`.
- **`refused: clock_behind_head`**: the change would be dated more than
  a day before the change it builds on, so a cold reader's check for a
  later request would not read it. Fix this process's clock (NTP on the
  node or the operator's machine) and run the change again.
- **`refused: retirement_unverified`**: the `legacy.migrate` record that
  retired the markers is missing or altered. Its id is the object's
  `legacy_markers_retired_by`, or the next request record's
  `base_audit_id`. Restore
  `audit/runtime-overrides/<YYYY>-<MM>-<DD>/<id>-request.json` to its
  original bytes from bucket versioning, then run `overrides recover`. If
  no version survives, delete every signed request record whose
  `legacy_markers_retired` is `true`, run `recover`, then
  `migrate-markers` again, and record what was deleted. The same refusal
  follows the WARNING "recover found a migration off the kept chain with
  no signed `applied` outcome", whose `migration` field names a migration
  that may never have committed, for example one whose object write timed
  out while another change committed at the same revision. If the change
  the object names at that revision is the one in force, the migration did
  not commit: delete its request record, run `recover`, then
  `migrate-markers` again.
- **`refused: head_ambiguous`**: two or more signed request records at
  the newest revision each verify, and nothing signed says which one was
  applied: their writes raced, the loser's `conflict` outcome and the
  winner's `applied` outcome were both lost, and no verification record
  names the winner. An invalid object naming one of them does not count. The WARNING "recover found more than one verifiable request
  record at the newest revision" names them in `records`. Read each
  `audit/runtime-overrides/<YYYY>-<MM>-<DD>/<id>-request.json`, decide
  which change should stand, delete the other request records, and run
  `recover` again. Record what was deleted.

**What recover writes:** the state of the newest audit chain that still
verifies, at a revision past every one seen, so every replica adopts it,
with `--mode observe|enforce` set over it if given. When no chain
verifies it writes empty overrides; when it keeps an older chain, it logs
`recover kept the state of an older audit record`. It refuses while the
object cannot be read. The dashboard's **Recover** runs the same, with no
confirmation step. Before trusting it, compare `overrides show` with your
own record of the changes: deleted signed records can make recover drop
later changes, such as an `enforce` (see the design note's
[The head anchor](design/overrides.md#the-head-anchor)).
