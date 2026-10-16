# Runtime overrides: design note

This is a design note: how runtime overrides work inside, and why. To turn
them on and run them, see the [operator guide](../OVERRIDES.md).

The code is `forgd_verdict.overrides`, `forgd_verdict.lockout`,
`forgd_verdict.lockout_evidence`, `forgd_verdict.dashboard.admin` and
`forgd_verdict.dashboard.controls`. Points no source settled are marked
**UNCONFIRMED**.

## Why the store, and not the policy file

On Kubernetes `policy.yaml` is a Helm-rendered ConfigMap, so a dashboard
edit to it would be reverted by the next `helm upgrade`. Editing it would
also need Kubernetes RBAC for the dashboard. Container Apps, Cloud Run and
ECS have no ConfigMap at all. Every deployment already has a findings
store, and every service already reads it or writes it, so the store is
where the override lives.

---

## Other rejected alternatives

- **The reader identity writing the overrides.** The connector shares the
  reader, and callers signed in through Claude reach the connector, so a
  reader write would let them rewrite `server.mode`. The dashboard gets
  its own control identity (see [Store access](#store-access)).
- **A CLI that writes no audit record.** The CLI has no verified
  identity, but without a record its changes would be invisible in the
  history. It writes one with issuer `cli` and `verified: false`.
- **Clearing an override when a release changes the same key.** Silently
  dropping an admin's `enforce` on an unrelated release is the worse
  surprise, so the override keeps masking the new baseline until cleared.
- **Deriving `allowed_origins` from `Host`.** Behind a proxy `Host` is
  whatever the proxy forwards (see [CSRF](#csrf)).
- **A per-process form key.** A token rendered on one dashboard replica
  and posted to another would fail.

## Store layout

```
{key_prefix/}state/runtime-overrides.json                          the overrides object: mutable, one object
{key_prefix/}audit/runtime-overrides/<YYYY-MM-DD>/<id>-<kind>.json  audit records: create-only, never modified
{key_prefix/}markers/stats_reset                        reset marker object (plain-text timestamp)
{key_prefix/}markers/excluded_requests                  exclusion marker object (newline-separated ids)
```

`runtime-overrides.json` is a flat name, so it passes `safe_state_name`
(`store/base.py`) and sits under `state/` like
the cursors and the org registry.

The audit records are not under `state/`. On GCS the
writer identity can delete most of `state/`, the cursors and the org
registry. A dedicated prefix keeps the audit out of every
mutable grant. On every cloud the writer identities are also excluded
from the overrides object itself (see [Store access](#store-access)).

### The overrides object

Everything below is inside `state/runtime-overrides.json`, in the order
`ControlState.to_json` writes it:

```json
{
  "version": 1,
  "revision": 12,
  "audit_id": "20260928T140311Z-0123456789ab",
  "audit_hash": "<sha256 hex of the head request record's stored bytes>",
  "updated_at": "2026-09-28T14:03:11Z",
  "overrides": {
    "server.mode": {
      "value": "enforce",
      "set_at": "2026-09-28T14:03:11Z",
      "set_by": {"issuer": "https://login.example/", "subject": "00u1ab…",
                 "name": "a.person@example.com", "via_group": "forgd-operators",
                 "verified": true},
      "audit_id": "20260928T140311Z-0123456789ab"
    }
  },
  "stats_reset": "2026-09-01T00:00:00Z",
  "excluded_requests": ["req_01EXAMPLE…", "PreToolUse:Bash:toolu_01…"],
  "legacy_markers_retired": true,
  "legacy_markers_retired_by": "20260915T090000Z-fedcba987654",
  "min_reader_version": "0.30.0"
}
```

- `overrides` holds policy overrides, one entry per allowlisted key.
- `stats_reset` and `excluded_requests` are top-level fields of this
  object. They hold marker state, which is not a policy override and has
  its own actions. The names are not `markers.*`, so they
  cannot be confused with the `markers/*` objects.
- `revision` goes up by one on every write. Form tokens bind to it (see
  [CSRF](#csrf)).
- `audit_id` names the request record for the write that produced this
  revision, and `audit_hash` is the SHA-256 of that record's stored
  bytes (see [Actions and the audit record](#actions-and-the-audit-record)).
  An audit id is `<UTC time as YYYYMMDDTHHMMSSZ>-<12 hex digits>`.
- `legacy_markers_retired` and `legacy_markers_retired_by` are present
  only once `migrate-markers` has retired the marker objects, and always
  together (see below). An object that is not retired carries neither.
- `min_reader_version` is the lowest forgd-verdict release that may
  apply the object. It is present only while `server.mode` is set:
  - Setting `server.mode` writes the writer's release (`__version__`,
    such as `0.30.0`, never the `version+commit` build id). It is written
    by `override.set`, or by a `state.recover` given a mode. When the
    object already holds a higher release, that one is kept, so it never
    goes down while the mode is set.
  - Every other write keeps it. Clearing `server.mode`, or clearing every
    override, removes it. An object without it keeps the bytes and
    digest it had.
  - It must be a strict release, `MAJOR.MINOR.PATCH` in digits with no
    leading zeros and no suffix, or the object is invalid
    (`min_reader_version_malformed`). It is also invalid on an object
    with no `server.mode` (`min_reader_version_without_mode`).
  - Releases compare component by component as numbers, so `0.29.10` is
    above `0.29.9`.
  - A reader whose release is lower does not adopt the object, however
    valid it is (see "Readiness" in the guide). A reader built before this
    check existed ignores the field, so it can apply a newer
    `server.mode`.
- **An object with no `audit_id` and `audit_hash` is invalid.** Readers keep their
  last-known-good, or the baseline, until `forgd-verdict overrides
  recover` writes a valid one.

### Legacy marker objects: compatibility and migration

Two sets of names are involved, and they are kept distinct throughout:

| Marker object | Field in `state/runtime-overrides.json` |
|---|---|
| `markers/stats_reset` | `stats_reset` |
| `markers/excluded_requests` | `excluded_requests` |

The dashboard and the control identity get no write to either marker
object. With runtime overrides off, `exclude` and `reset-stats` write the
marker objects. With them on, they write the fields, and the marker
objects stay in effect until `forgd-verdict overrides migrate-markers`
folds them into the overrides object and sets `legacy_markers_retired`.

- **Until `migrate-markers` runs, readers combine both.**
  - The effective exclusion set is the union of the ids in the
    `markers/excluded_requests` object and the `excluded_requests`
    field.
  - The effective reset is the later of the `markers/stats_reset` object
    and the `stats_reset` field, as `effective_since`
    does between a window and a reset.
  - A marker object that is absent contributes nothing.
- **Until `migrate-markers` runs, the writers can change what readers apply.**
  The writer identities (the verdict server, the collector, intake and
  ingest) can write `markers/*`. A writer that adds an id to
  `markers/excluded_requests` or moves `markers/stats_reset` changes the
  dashboard's rates, with no audit record. `migrate-markers` closes this
  path.
- **Once the markers are retired, readers ignore both marker objects.** A
  reader holding an object with `legacy_markers_retired: true`, whether as
  the object it just read or as its last-known-good, uses the two fields
  alone. What the marker objects hold then affects nothing, so the
  writers' access to them does not matter, and nobody needs to blank them.
- **A cold start while the object cannot be read does not serve.** A
  long-running process that starts while the object is unreadable or
  invalid has no last-known-good and does not know the markers were
  retired. It stays not ready (see "Readiness" in the guide) until its
  first valid read, so it never serves the marker objects' values. The
  ingest jobs exit 1 instead. A process that has adopted a retired object
  keeps ignoring them through any later failure.
- **With the feature on, the CLI writes the field, and never a marker
  object.** (With it off, it writes the marker objects; see
  "When runtime overrides are on" in the guide.)
  `forgd-verdict exclude` and `forgd-verdict reset-stats` write the
  `excluded_requests` and `stats_reset` fields through the same audited,
  conditional write the dashboard uses. The principal is
  issuer `cli`, with `verified: false` (see "From the CLI" in the guide).
  - `--clear` clears the field only. While the markers are not retired,
    if the marker object still holds a value, it warns that the value
    stays in effect until `migrate-markers` runs.
- **`forgd-verdict overrides migrate-markers`** reads both marker
  objects, folds them into the two fields (a union for exclusions, the
  later of the two for the reset) and sets `legacy_markers_retired: true`,
  all in one audited write. It never writes a marker object.
  - **It is operator-run.** Nothing runs it automatically, at startup or
    from the dashboard. Run it once, as the control identity. A store
    that has never held a marker object needs it too: until the markers
    are retired, a writer can create one.
  - **It is idempotent.** Once the object is retired, a re-run writes
    nothing and exits 0, whatever the marker objects hold by then.
  - **The flag is part of the audited transition.** It is covered by the
    request record's `state_sha256`, so an object that gains or loses it
    without a matching record is refused like any other unaudited change.
    An object without the field is not retired; the field is written only
    once it is true, so an object that is not retired does not carry it.
  - **Only `legacy.migrate` sets it, and nothing clears it.**
    - Every request record carries `legacy_markers_retired`, the value
      of the object it produces.
    - Along the chain, a reader refuses a record that goes from retired
      to not, and a record other than `legacy.migrate` that goes from not
      retired to retired.
    - A reader that has adopted a retired object, as its current object
      or its last-known-good, refuses any object that is not retired.
  - **A retired object names its migration.** It carries
    `legacy_markers_retired_by`, the audit id of the `legacy.migrate`
    request that retired it, present exactly when the flag is true.
    Later writes carry it forward. A reader refuses a migrated object that
    does not name its own request.
  - **Recover keeps the flag when it can find the migration.** A recover
    starts a new chain, so it cannot inherit the flag from a parent. It
    takes the migration from the state of the chain it keeps. When that
    state is not retired, it takes it from the invalid object's
    `legacy_markers_retired_by`, and failing that from the newest
    `legacy.migrate` request record in the audit store that is signed by
    a listed verify key, has a signed `applied` outcome, and whose chain
    verifies back to a chain start. The migration must be a
    stored `legacy.migrate` request whose bytes match the hash the chain
    names for it, and signed when no hash is named.
    - If the check passes, the recovered object is retired, and the
      recover record names the migration in `retired_by`, by id and
      SHA-256. A WARNING says when the retirement came from the invalid
      object, or from a migration found in the audit store, over a kept
      state that is not retired.
    - When the kept state is retired and its migration fails the check,
      recover refuses rather than write an object that is not retired.
    - When the newest `legacy.migrate` record found that way with no
      signed `error` or `conflict` outcome has no signed `applied` outcome
      either, recover refuses: it may have lost a race to a change at the
      same revision, or committed and lost its outcome write.
    - When the state recover would write is not retired, but a request
      record signed by a listed verify key, with no signed `error` or
      `conflict` outcome, says `legacy_markers_retired: true`, recover
      refuses too. Both refusals are `retirement_unverified`. Recover
      does not un-retire while such a record exists. Deleting every one
      of them, the migration and every change after it, removes the
      guarantee.
    - A reader accepts a retired chain start, a checkpoint included, only
      if `retired_by` names a migration whose bytes match, and the object
      names the same migration. Whether the migration was applied is
      never read from an outcome record.
  - **Without the pointer, a new chain starts unretired.** This happens
    when the invalid object is not JSON or names no migration, and on a
    write to an absent object, provided no migration is found as above
    and no signed request record says the markers are retired.
    - A cold reader accepts that start once the record naming its head
      lands, as for any change: it is the control identity's write, and
      it leaves an audit trail.
    - A reader that has adopted a retired object refuses it and keeps its
      last-known-good, with the ERROR and the banner, until
      `migrate-markers` is run again.
    - No reader searches the audit store for a `legacy.migrate` record;
      each check reads only the records the chain names. Only recover
      searches, as above.
- **Optional cleanup.** Once the markers are retired, the two marker
  objects can be deleted with writer credentials. Deleting them also
  closes the cold-start window above. Readers holding a retired object do
  not apply them, and nothing depends on the deletion.
- **Until the markers are retired,** the dashboard lists ids that come
  only from the `markers/excluded_requests` object with the note "set
  before runtime overrides; fold in with `forgd-verdict overrides
  migrate-markers`", and no remove control. It cannot remove them,
  because it has no write to that object. Once they are retired, those
  ids are listed as "in the retired legacy markers, so ignored".
- **A banner on every page says so until the markers are retired.** It
  names both marker objects, says they are still read and the writer
  identity can write them without an audit record, and names
  `forgd-verdict overrides migrate-markers`. It shows while the object is
  absent or not retired, whether or not either marker object exists:
  until they are retired, a writer can create one at any time and
  readers honour it.

---

## Strict reads

Failover cannot rest on `get_state`. The backends disagree about
what a read failure returns:

| Backend | Absent | Denied, network or other error |
|---|---|---|
| GCS | `None` on 404 | raises |
| S3 | `None` after `_absent` confirms it by listing the exact key | raises |
| Azure | `None` on 404 | raises |
| local | `None` | **`None`**: every `OSError`, including a permission error |

On local, an unreadable object is indistinguishable from an absent one,
so an access error would silently drop every override. And `get_state`
returns no etag on any backend, so it cannot carry a conditional write.

So every backend implements one more operation:

```python
def read_control(self) -> ControlRead: ...
# ControlRead(status="absent")
# ControlRead(status="ok", body=bytes, etag=str)
# raises StoreReadError on anything else
```

- **GCS:** 404 → absent. `etag` is the object generation.
- **S3:** a missing key → absent, confirmed by `_absent`. `etag` is the ETag.
- **Azure:** only a 404 → absent. `etag` is the blob ETag.
- **local:** only `FileNotFoundError` → absent. `etag` is a content digest.
- **spool:** has no control state. The hook never reads it.

`tests/test_store_control.py` pins absent, present and denied for every
backend, through the conformance `backend` fixture:
`test_absent_is_absent`, `test_create_then_read_returns_bytes_and_an_etag`
and `test_a_denied_read_raises_rather_than_reading_as_absent`.
`test_a_denied_state_read_raises_rather_than_reading_as_absent` in
`tests/test_store_conformance.py` pins that a denied `get_state` raises on
Azure, S3 and GCS.

Writes get two operations:

- **`write_control(body, if_etag)`** is conditional. When the object is
  absent the write is create-only; otherwise it succeeds only if the
  object still matches `if_etag`. The primitives:
  - GCS: `if_generation_match` (0 for absent), as records use.
  - S3: `IfMatch` / `IfNoneMatch="*"`. [AWS documents both for
    PutObject](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html):
    "you can add the `If-Match` header to check an object's entity tag
    (ETag) before writing an object".
  - Azure: `If-Match` / `If-None-Match: *` on Put Blob, [listed as
    supported](https://learn.microsoft.com/en-us/rest/api/storageservices/specifying-conditional-headers-for-blob-service-operations).
  - local: a lock file plus a compare.

  A lost race raises `StoreConflict`. The dashboard re-renders with the
  current state, and nothing is retried silently. A 403 from GCS, S3 or
  Azure raises `StoreForbidden`, which the CLI turns into the refusal in
  "Running the CLI as the control identity" in the guide.
- **`put_audit(record)`** is create-only under the audit prefix, using
  the same primitives records use: GCS `if_generation_match=0`,
  S3 `IfNoneMatch="*"`, Azure `overwrite=False`. `put_state` is not
  reused for audit. It takes flat names only and always overwrites.

Reads list a day at a time: `audit_days()` lists the day partitions and
`list_audit(day, leaf)` one day's names under a leaf prefix. Override
records are listed by the day's digits, which every audit id starts with
and no probe or verification name does (`lockout.override_records`), and
verification records by `verify-`.

---

## Reading and refreshing

One shared reader, `RuntimeOverrides`, is used by every service: verdict
server, intake, collector, ingest (the `ingest`/`compliance` and Managed
Agents jobs), dashboard and connector. Each component then applies the
fields it consumes. That means:

- **`server.mode`:** the verdict server and the intake.
- **`stats_reset` and `excluded_requests`:** the dashboard and the
  connector.
- **Nothing:** the collector and the ingest jobs. They consume no
  current field, so for them the reader is used for its status only.
  They still run it, so the object's status is visible from every
  service, and a key added later reaches them without new plumbing.

The ingest jobs are short-lived, so for them this is one read at start.

The cadence is the org registry's: `REFRESH_S = 60.0`
(`orgregistry.py`), an injectable clock and a lock.
The mechanism differs in one way.

- **`OrgResolver` refreshes lazily,** inside its lock, on the request
  that finds the cache stale.
- **On the verdict server that request is a governed prompt** with a
  1,500 ms budget.
- **So long-running services refresh on a background task.** A request
  reads the current snapshot and never waits on the store. The first
  read happens at startup, before the service reports ready.
- **The dashboard also re-reads** before it renders admin controls,
  because their form tokens bind the stored revision, and again after
  every admin write. The dashboard and the connector start their
  background refresh with the process, like the others.

Each process keeps a **last-known-good** snapshot in memory. It is the
last object it read that was valid, or none. What a refresh does depends
on whether the process has one:

| State read | Process with a last-known-good | Process without one (cold start) | Signalled |
|---|---|---|---|
| present and valid | applied; becomes the new last-known-good | applied; becomes the last-known-good | INFO when the effective values change |
| present, valid, with a key not on the allowlist | that key ignored, the rest applied as a valid object | same | ERROR with the number of such keys, never a key or its value; `detectors.*`/`privacy.*` keys get a distinct message |
| absent, and the audit prefix lists no records | **last-known-good kept; no revert**, and `source` reports `last_known_good` | **not ready**, on the baseline: not initialized until `overrides init` runs | ERROR on every refresh, with the banner saying to run `overrides init` |
| absent, and the audit prefix lists records or cannot be listed | **last-known-good kept; no revert** | **not ready**, on the baseline, adopting the object at the first valid read | ERROR on every refresh, with the banner |
| unreadable (`StoreReadError`) | **last-known-good kept; no revert** | **not ready**, on the baseline (`policy.yaml` + env), adopting the object at the first valid read | ERROR on every refresh, with the error type only |
| malformed JSON, unknown `version`, wrong shape, an allowlisted key with an invalid value, no head record, or a head or chain that does not verify | **last-known-good kept; no revert** | **not ready**, on the baseline, adopting the object at the first valid read | ERROR on every refresh, with a fixed code for what failed in `error` |

- **A valid object that clears an override is applied normally.**
  Clearing is a valid write, so it replaces the last-known-good like any
  other.
- **Absence is retained over.** A replica holding a last-known-good
  keeps it when the object disappears. Nothing the dashboard or the
  control identity can do deletes the object, so its absence after a
  valid read means something outside runtime overrides removed it: a writer
  credential, a person with bucket access, or a lifecycle rule. It is
  not an instruction to drop to the baseline. Dropping an `enforce`
  override because an object vanished would fail open by the same path
  a store outage does.
- **The last-known-good includes the marker fields.** While the object
  cannot be read, a running dashboard keeps its last exclusions and
  reset.
- **An empty store is never taken as a first run.** An absent object on
  a cold start with an empty audit prefix is not initialized, and the
  reader is not ready until `overrides init` writes the genesis record
  (see "Initialising the store" in the guide). An absent object with audit records
  means an object was written and has gone: the store is orphaned, which
  is treated like an unreadable object, and only `overrides recover`
  rebuilds it. So is an audit listing that fails.
- **A cold start that cannot confirm what is in force logs** that it is
  not ready, on every refresh. It keeps refreshing, and logs again when
  it adopts the object.
- **While the object is absent, a cold reader lists the whole audit
  prefix on every refresh.** That is cheap on a first run, and grows with
  the number of records when an object has gone.

"Loudly" means all of these:

- the ERROR log line on every failed refresh;
- the gauge `runtime_overrides.in_error`: 1 exactly while the last refresh
  took that ERROR path (unreadable, invalid, including a head or chain that
  does not verify, absent after a valid read, or absent on a cold start
  with audit records or a failed audit listing, or a writer lockout that
  is not proven, or a store that is not initialized, or a verify key that
  is missing or does not parse, or an object that needs a newer release,
  or no store configured), else 0. Alert on it;
- a `runtime_overrides` field wherever a service reports its state:
  - the verdict server's `/metrics` and the collector's `/stats`, both
    JSON;
  - every service's startup log;
  - the ingest jobs' run summary.

  The field carries:
  - `status`, one of `ok`, `absent`, `unreadable`, `invalid` or
    `disabled`, which is what the last read found (`disabled` means the
    feature off, or the store was not read: with `error:
    store_not_configured`, no store; with `error:
    verify_key_misconfigured`, no valid verify key; with `error:
    reader_version_too_old`, an object that needs a newer release; or,
    with `error: writer lockout missing`, a lockout that is not proven;
    see [Writer lockout probe](#writer-lockout-probe));
  - `source`, one of `object`, `last_known_good` or `baseline`, which is
    what is in force;
  - `in_error`, the gauge above, as 0 or 1;
  - `ready`, whether what is in force is known (see "Readiness" in the guide);
  - `revision`, `keys`, `error` and `held_since` when they apply. For
    an invalid object, `error` is a fixed snake_case code naming the
    check that failed, such as `unknown_version`, `invalid_mode` or
    `chain_hash_mismatch`, and never a key, a value or exception text
    from the object or an audit record. For an unreadable one it is the
    exception's type name. A CLI change against an invalid object prints
    the same code;
  - `lockout`, on a writer role, the last probe's result: `denied`,
    `allowed`, `unproven` or `exempt`;
- a banner on every dashboard page, either "Runtime overrides could not
  be read; keeping the values last read at <time>" or "…; running on
  policy.yaml and environment settings only". "Could not be read" becomes
  "are invalid" for an invalid object, and "have disappeared from the
  store" for an absent object after a valid read or on a cold start with
  audit records;
- a status field on the verdict server's startup and snapshot logs.

### Readiness: why requests are gated too

A 503 from `/readyz` only keeps a replica out of a load balancer that
asks, so the request paths check as well. While overrides are honoured
and the reader holds no verified state, the verdict server answers
`/hook` as an internal error in enforce would, whatever the baseline mode
(the normal allow verdict only under an explicit
`server.on_internal_error: allow`), after checking the signature and
required headers; intake and the collector answer 503 after
authenticating, without scanning, deciding or storing. `/v1/metrics` is
never scanned or stored and is not gated. A warm reader keeps serving on
its last-known-good, ready or not.

If every replica restarts cold during an outage (a node drain, a scale
from zero, a release), governed prompts have no ready endpoint until the
store reads. That fails closed: the other outcome is serving observe
while an audited `enforce` is in force.

`/healthz` and `/livez` do not depend on runtime overrides, so
`verify_deployment.sh` and existing callers keep working, and a store
outage never fails liveness.

On Cloud Run, Google's ["Configure container health checks for
services"](https://docs.cloud.google.com/run/docs/configuring/healthchecks)
says a failing readiness probe means "Cloud Run stops sending new traffic
to it. Cloud Run doesn't terminate the instance and sends traffic back to
the instance when it starts passing its readiness probe again", and that
"Cloud Run can route traffic to a new instance before the first readiness
probe completes", so the startup probe on the readiness path is the gate
for a new instance. `google_cloud_run_v2_service` has had
`readiness_probe` since provider 8.0.0, the lowest version the module
accepts.

### Writer lockout probe

The store modules' `control_enabled` takes the writers' writes to the
object and the audit prefix away, and `FORGD_OVERRIDES_ENABLED` turns
runtime overrides on in the services. They are set in different places,
so one can be on without the other. A writer that can write the audit
prefix can write a head record and an object that verify, so it can
forge the overrides and their chain. Each writer role therefore proves
its own lockout before it applies anything.

- **Who probes.** The verdict server, the collector, intake and the
  ingest jobs, whenever they honour runtime overrides. The dashboard, the
  connector and the CLI do not. The code is `forgd_verdict.lockout`.
- **The probe.** A conditional create, with the role's own credentials,
  of `audit/runtime-overrides/<YYYY-MM-DD>/probe-<role>-<instance>-<timestamp>.json`.
  `<instance>` is the host name and a random suffix, fixed for the
  process. The outcomes:
  - a 403 (`StoreForbidden`) is `denied`: the lockout holds;
  - a create that succeeds is `allowed`: the lockout is missing;
  - anything else, a conflict or an error, is `unproven`.

  The probe covers the audit prefix only. It never writes the object: a
  write there would create it if it is absent. A writer that can write
  the object but not the audit prefix cannot make a head record that
  verifies.
- **When.** Before the first read at startup, then with the reader's
  refresh: every hour after a `denied`, every five minutes after an
  `allowed`, and on every refresh after an `unproven`. A probe that
  errors keeps a `denied` proven less than two hours before. The ingest
  jobs probe once per run.
- **A local store cannot prove a lockout.** A directory has no
  credentials to refuse, so on `LocalFileStore` the probe is `unproven`
  without writing anything. Only the S3, GCS and Azure stores declare
  `lockout_provable`. The test suite can let a local store count as
  locked out (`lockout.allow_unprovable_stores_for_tests`, result
  `exempt`); there is no environment variable or policy key for it.
- **A writer whose own probe is not `denied` adopts nothing.**
  - The object is not read. A warm replica keeps its last-known-good,
    and a cold one is on the baseline and not ready.
  - After `allowed`, the service is not ready, warm or cold.
  - Either way `runtime_overrides` reports `status: disabled`, `error:
    writer lockout missing` and the `lockout` result, `in_error` is 1,
    and each failed probe logs an ERROR with the role and the result,
    and for `allowed`, what to fix.
  - Not ready means `/readyz` answers 503 with the reason `runtime
    overrides writer lockout missing` and `runtime_overrides: disabled`.
    The ingest jobs exit 1 with `refusing to ingest: writer lockout
    missing`.
  - Once a probe is `denied`, the next read verifies from the
    last-known-good, if the process had one, as any other refresh does.
- **Probe records are not audit records.** A create that succeeds leaves
  a probe record in the audit prefix. The cold-start check, the revision
  count and the history all ignore every name whose file part starts
  with `probe-`, `clock-` or `verify-`, so a probe record never counts as
  an orphaned chain.
- **Each probe publishes a report,** `state/overrides-lockout-<role>.json`,
  beside the org registry's per-role files: `version`, `role`,
  `instance`, `result`, `at`, and `error` (an exception type name) for
  `unproven`. The reports are for diagnosis only: no reader trusts them.
  Replicas of one role share the role's file, and the last write wins.
- **A writer's own probe is not proof.** A writer that can write `state/`
  can write any report, so readers do not read the reports. A writer
  whose own probe create succeeds is still not ready itself (above), and
  a writer adopts nothing until its own probe is `denied`. Neither makes
  the lockout proven.
- **Every reader adopts a new object only while the control identity has
  verified every writer identity's lockout from the cloud's IAM policy,
  within the last two hours** (see [Writer lockout verification](#writer-lockout-verification)).
  A writer without the lockout could have forged any object, so one
  writer identity's missing lockout holds every service, not only that
  writer.
  - The expected roles are `FORGD_OVERRIDES_WRITER_ROLES`, a
    comma-separated list of `verdict`, `collector`, `intake` and
    `ingest`. It is set on every service that reads the overrides: the
    verdict server, the collector, intake, the ingest jobs, the dashboard
    and the connector. A name that is not a writer role stops the
    service from starting. Unset or empty, no role is expected, and nothing
    is adopted. The Helm chart and the app modules set it to one
    writer role per distinct store identity among the writers they deploy,
    since roles sharing an identity prove the same lockout (see
    "Helm and the app modules" in the guide):
    - The chart, `app-aca` and `app-ecs` run every writer as one identity,
      so the list is the first long-running writer deployed, in practice
      `verdict`. `ingest` shares that identity and is listed only when no
      long-running writer is deployed, so readiness never waits on the
      CronJob. `app-aca` and `app-ecs` derive the list from the identity
      each writer runs as, which in both modules is the one writer
      identity.
    - `app-cloudrun` runs each writer as its own service account, so it
      lists every writer role, `ingest` included, and `intake` with
      `enable_intake`.
  - Every reader reads the newest verification record on every refresh,
    before it reads the object.
  - While there is no verification record, or the newest one is stale,
    unreadable or not chained to the one before it, or shows a writer
    identity without its lockout, the reader does not read the object. A
    warm replica keeps its last-known-good. A cold one is on the baseline
    and is not ready, even when the store is empty.
  - It reports `status: disabled`, `error: writer lockout missing`, and
    `writers`: each failing writer identity and its reason, or `*` and
    one of `no verification`, `verification stale`, `verification
    unreadable`, `verification chain broken`, `verification signature
    invalid`, `verification clock out of range`, `no writer identities
    verified`, `not configured` (no `FORGD_OVERRIDES_WRITER_ROLES`),
    `store cannot prove it`, or the exception type name when reading the
    verification raised. The gauge `in_error` is 1, and every refresh logs an ERROR
    naming them.
- **The dashboard also refuses admin actions until then.** It checks the
  same verification, and again before every admin action.
  - Every page carries a banner, "Admin actions are refused: writer
    lockout missing", naming each failing writer identity and its reason, and the overrides
    banner reads "Runtime overrides are not adopted: writer lockout
    missing".
  - No admin forms render, and `POST /admin/actions` answers 403 and logs
    the refusal with reason `writer_lockout`.
  - A cold dashboard is not ready, like any other reader, so the banner
    is shown only by a replica that was already running.
- **The app modules also refuse it at plan.** Each store module outputs
  `overrides_writer_lockout`, true only with `control_enabled`. `app-ecs`,
  `app-aca` and `app-cloudrun` take it as an input of the same name,
  false by default, and refuse `dashboard_admins_enabled` unless it is
  true, so a composition that passes the output through cannot enable
  admins on a store without the lockout. The input is a claim about a
  separately applied module, so the runtime probe stays the authoritative
  check. The Helm chart cannot see the store and relies on the probe alone.
- **This fails the roll.** A deployment that turns runtime
  overrides on without the store module's lockout (`control_enabled`) has
  every writer not ready from its first probe, and the platform keeps the
  new replicas out of service. `verify_deployment.sh` polls `/healthz`,
  not `/readyz`, so it fails the roll only through `VERIFY_MAX_UPTIME_S`:
  the old revision keeps answering, with an uptime past the limit.
  Without that variable it passes.
- **Cold replicas wait for a fresh verification,** on a first install as
  on an upgrade. The dashboard verifies as it starts, hourly, and after
  each change, so a replica that starts before its first verification is
  not ready until it has run. A deployment without the dashboard has no
  verifier, so its
  readers adopt nothing.
- **UNCONFIRMED: what a real cloud answers.** The probe treats only a 403
  (`StoreForbidden`) as proof. The tests exercise it against a fake store
  that answers as a cloud store would, not against real S3, GCS or Azure
  credentials. A backend that refuses the create some other way reports
  `unproven`, which fails closed.

### Writer lockout verification

The control identity proves each writer identity's lockout from the cloud's
IAM policy, and readers trust only that. The code is
`forgd_verdict.lockout_evidence`.

- **Which identities.** `FORGD_OVERRIDES_WRITER_IDENTITIES`, a
  comma-separated list set on the dashboard only, and only with admins on:
  - S3: the writer IAM role ARNs;
  - GCS: the writer IAM members: the module's writer account as
    `serviceAccount:<email>`, and each of `writer_members` as given
    (`serviceAccount:`, `user:`, `group:`, `principal:` or
    `principalSet:`);
  - Azure: the writer principal (object) ids, with the storage account's
    resource id in `FORGD_OVERRIDES_STORAGE_ACCOUNT_ID`.

  Each comes from the store module's `overrides_writer_identities` output,
  and on Azure its `storage_account_id` output:

  | Deployment | Identities | Storage account | Refused with admins on when |
  |---|---|---|---|
  | app-ecs | `overrides_writer_identities` | not used | the list does not include `writer_role_arn` |
  | app-aca | `overrides_writer_identities` | `overrides_storage_account_id` | either is empty, or the list does not include `identity_principal_id` |
  | Helm chart | `dashboard.admins.writerIdentities` (no default) | `dashboard.admins.storageAccountId` | the list is empty, or the store URL is Azure Blob and the account id is empty |

  app-cloudrun takes neither, because it refuses `dashboard_admins_enabled`
  outright (its dashboard signs in through IAP). With admins off, nothing
  is set, nothing is required, and the plans and the render are
  unchanged. The verifier also fails closed on an empty list, so the
  refusals only move that failure to plan or render time.
- **What is checked.** A writer identity is locked out when:
  - **S3**, from `GetBucketPolicy`: `Deny` statements that apply to the
    role cover `s3:PutObject`, `s3:DeleteObject` and
    `s3:DeleteObjectVersion` on both the overrides object and every key
    under `audit/runtime-overrides/`. A statement applies when its
    principal is `*` and its only condition is `ArnEquals
    aws:PrincipalArn` naming the role, as store-s3 writes it, or when it
    names the role as its principal with no condition. A statement with
    any other condition, or with `NotAction`, `NotResource` or
    `NotPrincipal`, does not count. `s3:*` and wildcard resources count
    when they cover the targets. A single object under the audit prefix
    does not cover it. Those statements must also deny
    `s3:PutBucketPolicy` and `s3:DeleteBucketPolicy` on the bucket ARN,
    since a role that can rewrite the bucket policy can remove the Deny.
    store-s3 adds that as `WriterCannotRewriteBucketPolicy` while
    `control_enabled`.
  - **GCS**, from `getIamPolicy` (version 3): every bucket binding that
    lists the member, `allUsers` or `allAuthenticatedUsers`, with any role
    other than `objectViewer`, `legacyObjectReader` or
    `legacyBucketReader`, carries a condition that is exactly the store
    module's exclusion of the overrides object and the audit prefix, or
    `(<anything>) && <exclusion>`. Custom roles count as writing. The
    check reads the condition's shape rather than searching it for the
    clauses, because a clause inside an `||` excludes nothing. Each role
    those bindings hold is read from the IAM API (`roles.get`) for its
    `includedPermissions`. A binding whose role holds
    `storage.buckets.setIamPolicy` fails whatever its condition, since the
    member can rewrite the bindings and conditions. A role whose
    permissions cannot be read fails.
  - **Azure**, from the principal's role assignments at the storage
    account scope and above, with each role's definition: every
    assignment on the container, or on a scope above it, whose role
    grants a blob mutation (write, add, delete, deleteBlobVersion,
    permanentDelete or move) carries condition version 2.0 and a
    condition in store-azure's shape. The shape is compared with
    whitespace outside quoted literals ignored. It must name every
    mutation the role grants and exclude exactly the overrides path and
    the audit prefix. A role that grants a mutation through a wildcard
    fails even with the condition, because the condition cannot list
    every action a wildcard grants. A role that can list or regenerate
    the account keys (Owner, Contributor, Storage Account Contributor)
    fails, because a shared key is outside RBAC. A role that, after its
    `notActions`, grants any `Microsoft.Authorization/*/write`, or write or
    delete on the storage account, its blob service or containers, fails
    whatever its condition: role-assignment conditions constrain data
    actions only, and with those actions the principal can reassign
    itself or replace the container. Contributor therefore fails on the
    account write, and Owner on the authorization writes. A principal
    with no assignment granting a mutation is locked out.

  A reason is a fixed code:

  | Cloud | Reasons |
  |---|---|
  | S3 | `no_deny_for_writer`, `deny_does_not_cover_overrides`, `deny_does_not_cover_bucket_policy` |
  | GCS | `no_binding_for_writer`, `unconditioned_binding`, `missing_exclusion`, `grants_set_iam_policy`, `role_permissions_unreadable` |
  | Azure | `unconditioned_assignment`, `wrong_condition_version`, `condition_not_recognised`, `condition_omits_action`, `wildcard_data_action`, `grants_account_keys`, `grants_authorization_write`, `grants_storage_control_plane_write` |
  | policy unreadable | `policy_read_denied`, `policy_read_failed`, `no_bucket_policy` or `policy_unparseable` (S3), `bucket_not_found` (GCS) |
  | not verifiable | `store_not_verifiable`, `storage_account_id_unset`, `storage_account_id_mismatch` (the id does not name the account the store URL is on), `verification_failed` |

- **UNCONFIRMED: what the GCS check cannot see.** It reads the bucket's
  own bindings only. Write granted to a writer at project, folder or
  organization level, through a Google group it belongs to, or through a
  `projectEditor:`/`projectOwner:` convenience member on the bucket's
  legacy roles is not seen, and such a writer still verifies. An operator
  should audit that no writer service account holds a `storage.*` or
  broader role (Editor, Owner) above the bucket, is a member of a group
  that holds one there or on the bucket, or holds Editor or Owner on the
  project while the bucket keeps its convenience bindings. The S3 check
  does not have this gap, because a bucket-policy Deny holds over any
  Allow. The Azure check reads inherited assignments, but not a group the
  principal belongs to.
- **Permissions.** With `control_enabled`, each store module grants the
  control identity the reads the check needs, scoped to the store, and
  outputs the identities to check. With `control_enabled` false nothing
  is added and each output is an empty list.

  | Store | Grant to the control identity | `overrides_writer_identities` |
  |---|---|---|
  | store-s3 | `s3:GetBucketPolicy` on the bucket ARN, a statement in its control policy | `writer_role_arn`. A writer role carrying `writer_deny_policy_json` instead is not named in the bucket policy's Deny and does not verify. |
  | store-gcs | the custom role `control_iam_read_role_id` (default `forgdVerdictStoreControlIamRead`), holding only `storage.buckets.getIamPolicy`, defined in the project and bound on the bucket; and `control_role_read_role_id`, holding only `iam.roles.get`, bound on the project | the writer account as a `serviceAccount:` member, and each of `writer_members` as given |
  | store-azure | the custom role `control_evidence_role_name`, holding only `Microsoft.Authorization/roleAssignments/read` and `Microsoft.Authorization/roleDefinitions/read`, assigned on the storage account | the writer identity's principal id |

  - **The GCS role read.** Reading a predefined role needs no
    permission. Reading a project custom role, which includes store-gcs's
    own `mutable_delete_role_id` that every writer holds, needs
    `iam.roles.get` on the project. So with `control_enabled`, store-gcs
    also creates the custom role `control_role_read_role_id` (default
    `forgdVerdictStoreControlRoleRead`), holding only `iam.roles.get`, and
    binds it on the project to each control member. It is the module's
    only project-level binding, and it reads role definitions, not
    anyone's grants. An organization custom role needs `iam.roles.get` on
    the organization, which the module does not grant, so a writer holding
    one reports `role_permissions_unreadable` until the operator grants it.
    UNCONFIRMED: the call itself, `GET iam.googleapis.com/v1/<role>` with
    the store client's credentials, has not been run against Google Cloud.

  store-azure also outputs `storage_account_id`. The Azure grant sits on
  the storage account rather than the container because the check lists
  assignments at the account scope, which include those inherited from
  above it (UNCONFIRMED), and reads each role definition at that scope.
- **The record.** The dashboard verifies as it starts and every hour,
  and every change verifies straight after its write
  ([The head anchor](#the-head-anchor)). Each writes the result as
  `audit/runtime-overrides/<YYYY-MM-DD>/verify-<time>-<hex>.json`: each
  identity and its reason (null when locked out), `ok`, `at`,
  `base_id` and `base_hash`, the previous record's id and the SHA-256 of
  its bytes, `head`, the overrides head a cold reader must find and
  no reader may go behind (see [The head anchor](#the-head-anchor)), and
  `written_by`, `dashboard` or `cli`, saying which wrote it. A reader
  accepts a record without `written_by`, and one whose `written_by` is
  not a lowercase code is not well formed.
  - Records are create-only, under the prefix no writer can write, and are
    ignored by the cold-start check, the revision count and the history,
    as probe records are.
  - Before writing one, the dashboard or the CLI creates a clock probe,
    `audit/runtime-overrides/<YYYY-MM-DD>/clock-<time>-<hex>.json`, and
    reads its last-modified time back from the store. If its own clock is
    more than five minutes ahead of that, it writes no record and logs
    `verification_clock_ahead` with `ahead_s`. A store that can prove a
    lockout and cannot report the time writes no record either.
  - A reader trusts only the newest record, by id. If that record fails
    any check, the reader does not fall back to an older one. The newest
    record must:
    - be well formed, with identities and reasons in the expected format;
    - be signed under a listed verify key;
    - name as its base any older record, whose stored bytes hash to
      `base_hash` and which is also signed. Two replicas verifying at once
      each write a record on the same base, and either is accepted. A
      record with no base is accepted only when the one before it has none
      either, as two replicas writing the first record at once leave;
    - be at most two hours old by `at`, and no more than five minutes in
      the future.

    The time in the id of the newest record and of its base must be no
    more than five minutes ahead of now, and within five minutes of that
    record's own `at`. The same bound applies to every audit record a
    reader walks on the overrides chain, and the history marks a record
    that fails it as tampered.
- **When verification fails.** A policy that fails the check, one the
  control identity cannot read, a record that is missing, stale or
  broken, a `head` that is not well formed, or a check that raises: readers keep their last-known-good,
  adopt nothing, and cold readers are not ready. The dashboard banner and
  every reader's `writers` field name each failing identity and its
  reason.
- **What it cannot prove.** The records sit under the prefix whose lockout
  they attest, so an identity that can already write that prefix can
  write records there. Without the private signing key, it cannot write
  one a reader trusts. It can make the newest record invalid, and then
  readers keep their last-known-good and cold readers are not ready. It
  can also delete records, so an older passing record may become the
  newest again. That record still has to pass the two-hour limit, so
  verification lapses at most two hours after the last honest pass.
  A writer whose own probe create succeeds is still not ready. Verification closes the gap between self-reports
  and the policy; it does not make a missing lockout safe.
- **A local store cannot be verified.** Only the test suite can let one
  count as locked out, as for the probe, and then no reader reads a
  verification record, so no head anchor applies either.
- **UNCONFIRMED: the real SDK and REST call shapes.** No call has been
  made to AWS, GCS or Azure. The tests use fake policy documents shaped
  like the store modules' Terraform output.
  The calls are:
  - `get_bucket_policy(Bucket=...)["Policy"]` on the store's boto3 client,
    with the error codes `NoSuchBucketPolicy`, and `AccessDenied`,
    `AccessDeniedException` or `403`;
  - `bucket.get_iam_policy(requested_policy_version=3)` in
    google-cloud-storage, with the status codes 401, 403 and 404;
  - `GET https://management.azure.com{account}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=assignedTo('<id>')`, which is transitive: it includes assignments made to groups containing the writer, each tagged with the writer it was fetched for
    with a token from the store's azure-identity credential, following
    `nextLink`, then for each assignment a `GET` of
    `{account}/providers/Microsoft.Authorization/roleDefinitions/<name>`,
    `<name>` being the last segment of its `roleDefinitionId`.
    That the principal filter at the account scope also returns
    assignments inherited from the resource group, subscription and
    management groups, and that the condition comes back as it was
    written, are both unconfirmed. Reading a role definition may need
    `Microsoft.Authorization/roleDefinitions/read` as well as
    `roleAssignments/read`.

  An answer of another shape fails closed, as `policy_read_failed` or a
  check reason.

### The head anchor

Every verification record names an overrides head. A reader that holds no
verified state adopts only the object at exactly the head the newest fresh
record names, and no reader adopts an object behind it. This is what
refuses an older version of the object restored through storage
versioning: its records are signed, so without the anchor a
cold reader would adopt it, un-retired or without an `enforce` it had
since gained.

- **When a record is written.** The dashboard writes one as it starts
  and hourly. Every change also writes one naming the head it wrote,
  straight after the write: the dashboard's admin actions, and every CLI
  change made as the control identity (`init`, `set`, `clear`,
  `clear-all`, `reset-stats`, `exclude`, `migrate-markers` and
  `recover`). A `state.checkpoint` gets its own record before the change
  that follows it.
  - Each is a full verification: it evaluates every writer identity, as
    the hourly run does.
  - The CLI evaluates the identities in
    `FORGD_OVERRIDES_WRITER_IDENTITIES` (with
    `FORGD_OVERRIDES_STORAGE_ACCOUNT_ID` on Azure). Without them its
    record verifies no writer identity. It prints `warning: the lockout
    verification naming this head does not show every writer identity
    locked out`, and readers adopt nothing new until the dashboard
    rewrites it, within `RETRY_S`.
- **What a record names.** `head` is `revision`, `audit_id` and
  `audit_hash`, covered by the record's signature. A change's record
  names the head the change wrote. The dashboard's own runs name the
  later, by revision, of:
  - a head whose record could not be written, while it is pending (see
    below);
  - the head of the state its own reader has verified and holds. When it
    holds none, the head of the store's object instead, on the three
    conditions below. It never names an object whose chain does not
    verify;
  - the head the newest record names, if that record is fresh and signed
    by a listed verify key and passes the chain checks above, whether or
    not it shows every writer identity locked out. On equal revisions this
    one is kept.

  A dashboard that holds no verified state, finds no such object head and
  finds no fresh record writes no record at all, and logs the ERROR
  `writer lockout verification not written: this dashboard holds no
  verified runtime overrides state and no fresh signed verification
  record names one`. A head from a record that is not fresh is never
  carried: that would let deleting the newer records, and a dashboard
  restart, anchor a restored object. The one exception is a store that
  has never been initialized: no object, no request record, and no signed
  record naming a head past revision 0. The dashboard then names revision
  0 with a null id and hash.
- **When a change's record is not written.** The change stands.
  - The ERROR `runtime overrides change applied, but no lockout
    verification naming its head was written. Readers that hold no
    verified state are not ready until one is; it is retried` is logged.
    The CLI also prints `warning: the change is applied, but the lockout
    verification naming its head could not be written`.
  - On the dashboard, the head stays pending, and every run names it
    until a record names it or a later head.
  - The dashboard's verifier checks every `RETRY_S` (60 seconds) whether
    a run is due. One is due:
    - while a head is pending;
    - while the head the dashboard would name is at a later revision
      than the one the newest fresh record names. The CLI does not
      retry, so this is how the dashboard anchors a head the CLI wrote
      but could not anchor;
    - when the newest fresh record does not show every writer identity
      locked out, is not the newest record the dashboard saw when its
      own last run ended, and was not written by a dashboard
      (`written_by` other than `dashboard`, or absent). This is how a CLI
      record written without `FORGD_OVERRIDES_WRITER_IDENTITIES` is
      replaced;
    - when the newest fresh record does not show every writer identity
      locked out, was written by a dashboard, this one or another
      replica, and `FAILING_RETRY_S` (300 seconds) has passed since this
      dashboard's last run, doubled for each consecutive run of its own
      that wrote no record or a failing one. Seeing a passing fresh
      record, from any replica, resets the count. A transient failure is
      replaced within five
      minutes, and a correctly configured replica replaces a
      misconfigured one's failing record within five minutes of its own
      last run. A failure that persists is retried at 5, 10, 20 and 40
      minutes, then hourly, so replicas that all fail write a bounded
      number of records.
  - After runs that wrote nothing (a store error, or
    `verification_clock_ahead`), none of these makes a run due until
    `RETRY_S` after the last, doubled for each further such run, up to
    `FAILING_RETRY_S`. Each run creates one clock probe, so a fast clock
    leaves at most one every five minutes per replica.
- **A dashboard that restarts before the retry** holds no state, and as a
  cold reader it cannot adopt a head no record names. So when its reader
  holds nothing, it names the store object's head instead, if:
  - the object's chain verifies as a cold reader walks it;
  - its revision is later than the head the newest fresh record names;
    and
  - no request record names a later revision.

  With the newer request record in place, an object restored to an
  earlier unanchored head fails the third condition, so it is not named.
- **A cold reader** adopts an object only when:
  - the newest record passes every check above, freshness included; and
  - the object is exactly the record's `head`: the same `revision`,
    `audit_id` and `audit_hash`; and
  - no later request stands. That means no request record signed by a
    listed verify key names a later revision than the object's head,
    unless that request has an outcome record that is signed by a listed
    key, names it, and says `error`. A request with no outcome, or with
    `unknown`, `conflict` or `applied`, counts as later. So does one whose
    outcome is unsigned or signed by another key, or whose `error` outcome
    was deleted. An unsigned request record does not count.

  After a write whose outcome is `unknown`, and that did not commit, a
  cold reader is not ready until `recover` commits at that revision.
  Every other change is refused while a signed request is later than
  the object.

  A fresh record with no `head` is not enough: a cold reader is not
  ready until the dashboard writes one with a head, which it does as it
  starts.
- **Cold replicas after a change.** A cold replica is not ready from a
  change until the record naming its head lands. That is normally
  straight after the write. When the write fails, it is the dashboard's
  next due run, within `RETRY_S`, or longer if that run fails too. When
  the CLI's record verifies no writer identity, it is the dashboard's
  next check, within `RETRY_S`, provided the dashboard's own run shows
  every writer identity locked out.
- **A warm reader** is unchanged. It keeps its ordering checks (a later
  revision than the one it holds, never un-retiring). It also refuses an
  object behind the newest fresh record's head, and adopts that head or
  a later revision, so it serves a change before the change's record
  lands. A record with no `head` adds nothing for a warm reader.
- **What a refusal looks like.** The read is `status: invalid`, with one
  of these errors:
  - `object_before_anchor`, for any reader: the object is at an earlier
    revision than the head, or at its revision with another `audit_id` or
    `audit_hash`;
  - `object_not_anchored`, for a cold reader: the object is at a later
    revision than the head;
  - `head_anchor_missing`, for a cold reader under a fresh record with no
    head;
  - `object_behind_request`, for a cold reader: a later request stands.
    The ERROR is `runtime overrides object is not adopted: a signed change
    request names a later revision than the object's head and has no
    signed error outcome`. The `/readyz` reason is `runtime overrides are
    behind a signed change request`, and the banner reads "Runtime
    overrides are not adopted: a signed change request names a later
    revision than the object".

  For the first three, every refresh logs the ERROR `runtime overrides
  object is not adopted: a reader with no trusted state needs the head
  the newest signed lockout verification record names, and any reader
  refuses one before it`.
  - A warm reader keeps its last-known-good.
  - A cold one is on the baseline and not ready: `/readyz` answers 503
    with the reason `runtime overrides are not the head the signed head
    anchor names`.
  - The dashboard's banner reads "Runtime overrides are not adopted: the
    object is not the head the signed lockout verification names".
  - `forgd-verdict overrides show` and `forgd-verdict exclude --list` make
    the same check a cold reader makes. They print `warning: a service
    starting now would refuse this object (<error>): <why>` on stderr
    and still exit 0. `show`'s JSON reports it as `"cold_reader": {"adopts": ...,
    "error": ...}`, which is null when there is no state.
- **Writes refuse an object behind the anchor.** A change reads the
  object as a warm reader does. An object behind a fresh record's head is
  invalid to it, and a later one is not, so a change can follow one
  whose record was not written. A change is also refused while a signed
  request record names a later revision than the object
  (`object_behind_request`, see [Recovery](#recover)). Only `recover`
  writes over either.
- **What a restored object meets.** A storage administrator without the
  signing key restores an older object, and may restart the dashboard:
  - with the newer verification records left in place, the newest fresh
    one names the latest head, and every reader refuses the earlier
    object with `object_before_anchor`;
  - whether or not verification records were deleted, a cold reader
    refuses the restored object while a later change's signed request
    record remains without a signed `error` outcome
    (`object_behind_request`). With no fresh verification record left, a
    cold reader is not ready on the lockout itself (`no verification` or
    `verification stale`), and a dashboard that restarts writes no
    record;
  - warm readers keep their last-known-good;
  - every change but `recover` is refused before anything is written.
    While a fresh verification record names a later head, the change
    reads the object as invalid (`object_before_anchor`) and the CLI
    exits 1 with:

    ```
    the runtime overrides object is invalid (object_before_anchor); run `forgd-verdict overrides recover`
    ```

    Otherwise, while that request record remains, the CLI exits 2 with:

    ```
    refused: object_behind_request: a signed request record names a later revision than the object. If no change is being written, run `forgd-verdict overrides recover`
    ```

    The dashboard answers the first with `?result=invalid` ("The
    overrides object is invalid. Recover it first.") and the second with
    `?result=refused` ("That change is not allowed."), logging the
    refusal's message as the WARNING's `detail`;
  - `recover` writes over the valid restored object, because no fresh
    verification record is left or a later signed request is. When the
    highest signed request record is later than both the object and the
    anchor's head, and is the only record at that revision without a
    signed `conflict` outcome, recover tries its chain before the
    object's own record, and writes past it ([Recovery](#recover)).

  All of this holds only while the later request records remain; see
  below.
- **What it does not catch.**
  - **A rollback that deletes request records.** A storage administrator
    without the signing key can roll the state back to an earlier head in
    two ways.
    - **Without a recover, readers adopt the restored object.** The
      administrator deletes, for every change after the earlier head,
      its signed request record (a `state.checkpoint` included), the
      verification record naming its head, and every verification record
      newer than the one naming the earlier head, then restores the
      object to exactly that head. While the earlier head's record is
      fresh, every cold reader and a restarted dashboard adopt it, the
      dashboard names it in every record from then on, and later changes
      build on it. The earlier head's record is stale two hours after it
      was written, so this way reaches back at most two hours. Warm
      readers that hold a later head refuse the object. A request with a
      signed `error` outcome never committed, so it does not need
      deleting. Deleting an `error` outcome opens nothing: its request
      then counts as later, and cold readers are not ready.
    - **With a recover, deleting one request record is enough.** Delete
      any one signed request record on the chain after the earlier head:
      the head's own, or one in the middle. No verification record needs
      deleting, the object needs no restore, and there is no time limit.
      Every chain through the deleted record stops verifying, so readers
      refuse the object (warm readers keep their last-known-good, cold
      ones are not ready) and every change but `recover` is refused. The
      documented remedy is `recover`. It finds no later chain that
      verifies and keeps the newest chain below the gap, dropping every
      change from the deleted record on, such as an `enforce`, and every
      reader then adopts it, warm readers included, since it is a later
      revision. It keeps the retirement of a `legacy.migrate` whose own
      chain still verifies. When the deleted record is that migration,
      recover refuses and writes nothing while any later signed request
      record says the markers are retired
      ([Recovery](#recover)).
      The same is true after the first way once the earlier head's
      record is stale: recover keeps the restored chain.

    Before trusting a recover, compare `forgd-verdict overrides show` and
    the history with your own record of the changes made. When the
    record it keeps is not its first candidate, recover logs the WARNING
    `recover kept the state of an older audit record: the newer ones do
    not verify`, with the kept record's id as `kept`, or `recover found no
    verifiable audit chain` when nothing verifies. After the first way it
    logs neither, because the restored object's own chain verifies; only
    the comparison shows the loss.
  - **A store emptied of everything.** With the object, every request
    record and every signed record naming a head deleted, a dashboard
    starting cold cannot tell the store from a new one and names revision
    0. An older object restored with its request records after that
    record is written is not revision 0, so cold readers refuse it at
    first. A dashboard holding no state then names it, on the conditions
    above, within `RETRY_S`, and every reader adopts it. A dashboard that
    kept running names the head it holds instead.
  - **An anchor write that fails, and deleted request records.** While
    a change's record is not written, a storage administrator who also
    deletes the request records past an earlier unanchored head can
    restore the object to that head. A dashboard that restarts then
    names it, since no request record names a later revision, and every
    reader adopts it.
  - **A replay to a signed head that was never applied.** The object
    itself is not signed; its head request record is. A write that loses
    its conditional write (outcome `conflict`) or is refused before it
    commits (`error`) leaves a signed request record, one revision past
    its base on the applied chain, whose `state_sha256` describes a whole
    object. A storage administrator without the signing key can write that
    object as `state/runtime-overrides.json`, and it verifies: its head
    record is signed, its digest matches, and its chain walks back.
    Signing does not refuse it. The anchor bounds it:
    - after a `conflict`, another write committed at that revision, and
      its record names that head straight after. The replay is then
      behind the anchor (`object_before_anchor`) for every reader and
      every change. Before that record lands, or while it cannot be
      written, cold readers refuse the replay (`object_not_anchored`), but
      a warm reader holding an earlier revision adopts it. A restarted
      dashboard can name it, since the replay's request record is at the
      highest revision, and every reader then adopts it;
    - after an `error`, nothing committed at that revision. Cold readers
      refuse the replay at first (`object_not_anchored`). A warm
      dashboard adopts it as a later revision, and a restarted one names
      it by the conditions above, so the dashboard's next due run writes
      a record naming it. Every reader then adopts it,
      until another change commits at that revision. It carries a change
      an admin asked for and the control identity signed, but that was
      refused. Once a replay is adopted, later changes build on it, so
      the history then shows the refused change as applied.
  - **The signing key and the control identity are trusted.** Whoever
    holds both can write a valid chain start at a later revision carrying
    any state, and every reader adopts it.

### A widened writer grant: what each component logs

When a writer gains write on the object or the audit prefix, the
operator sees:

- `/readyz` 503 with `runtime overrides writer lockout missing`, and
  `runtime_overrides` showing `status: disabled`, `error: writer lockout
  missing`, `in_error: 1` and `writers`;
- from a writer whose probe create succeeded, the ERROR `runtime
  overrides are disabled: writer lockout missing. This role's credentials
  created a record under the runtime overrides audit prefix, ...`;
- from every reader on each refresh, `runtime overrides: not every writer
  role has a fresh report that its lockout holds, so no new object is
  adopted`;
- from the dashboard on each failing verification, `writer lockout not
  verified: runtime overrides are not adopted until every writer identity
  is shown locked out`, and on a replica already running the banners
  "Admin actions are refused: writer lockout missing" and "Runtime
  overrides are not adopted: writer lockout missing".

A verification record dated in the future is refused because a record's
id must sort after the id of the record it chains on: if a process with a
clock more than five minutes fast wrote the newest record, every record
chained on it would carry that date, so the dashboard and the CLI write
nothing and log `verification_base_in_future`. The writer checks its
clock against the store's before it writes, from a clock probe's
last-modified time, so a process with a fast clock writes no record and
logs `verification_clock_ahead`. A record dated in the future can still
come from a store whose own time is wrong, or from a release before that
check.

### Recover

The operator procedure is "Recovery" in the guide. This is what recover does.

- **What `recover` writes:**
  - **the state of the newest audit chain that verifies.** Recover tries,
    in order:
    1. the request record at the highest revision among those signed by
       a listed verify key with no signed `error` outcome, when that
       revision is later than both the object's and that of the head the
       newest signed verification record names. A record with a signed
       `conflict` outcome is skipped, since its write did not commit. When
       more than one record is left at that revision, the one whose chain
       verifies is tried, among those with a signed `applied` outcome if
       any has one. When more than one verifies, recover refuses with
       `head_ambiguous` and writes nothing, since nothing signed says which
       write committed. The invalid object's revision and audit id do not
       settle it;
    2. the record the invalid object names, or, when the object is behind
       the head the newest signed verification record names, the record
       that head names;
    3. request records by revision, newest first, skipping a record that
       shares its base with another unless it is one of the above or a
       record names it as its base.

    It tries up to ten. The first whose chain verifies back to a chain
    start, exactly as a cold reader verifies one, gives the state: its
    overrides, `stats_reset`, `excluded_requests` and retirement are kept.
    It logs the WARNING `recover kept the state of an older audit record:
    the newer ones do not verify` when the first candidate did not
    verify;
  - `--mode observe|enforce` sets `server.mode` over that state. Without
    it the kept mode stands;
  - **only when no chain verifies**, `overrides: {}` or the `--mode`
    given, and empty `stats_reset` and `excluded_requests`, with a
    WARNING naming what was dropped;
  - `legacy_markers_retired: true` and `legacy_markers_retired_by` when
    the kept state or the invalid object names a migration that passes
    the check above, or when a `legacy.migrate` request record is signed
    by a listed verify key, has a signed `applied` outcome, and its chain
    verifies back to a chain start; else neither. Such a migration is not
    on the kept chain, which would be retired if it were, so only its
    outcome says it committed. When the newest such record with no signed
    `error` or `conflict` outcome has no signed `applied` outcome either,
    recover refuses with `retirement_unverified`. If it
    would write neither while any request record signed by a listed key,
    with no signed `error` or `conflict` outcome, says the markers are
    retired, it refuses and writes nothing (see the migration entry
    below). Deleting every such record removes that guarantee;
  - `revision` one past the highest of the invalid object's `revision`,
    when it parses, the highest `base_revision + 1` of any request record
    under the audit prefix, and the revision of the head the newest signed
    verification record names, fresh or not;
  - a `state.recover` request record, whose `base_audit_id` is the
    previous object's `audit_id` if one can be read, else null, and whose
    `new_value` is the whole state it writes. A recover starts a chain:
    readers do not walk past it.
- **Readers refuse a restored object.** A reader that has verified a
  later head refuses an older object, because its revision is not after
  the one it holds, or it un-retires the markers. A reader starting cold
  refuses any object but the head the newest fresh verification record
  names, and that head too while a later signed request stands. So
  restoring the object from before a migration does not by itself reopen
  the writers' path to `markers/*`, and nor does a recover afterwards
  while any signed request record says the markers are retired: it
  refuses instead. With the migration's request record and every later
  one deleted, recover keeps a chain from before the migration, which is
  not retired. Rollbacks
  through deleted request records are under "What it does not catch" in
  [The head anchor](#the-head-anchor).

- **Cost:** recover reads every request record under the audit prefix, to
  find the highest revision, its candidates and any migration, so it
  takes longer as the history grows. So does every change, which reads
  every request record to check that none names a later revision than
  the object, and a reader holding no state, which does the same on each
  refresh. A reader holding a last-known-good does not.

## Tests for the four cases

The four reader cases are `test_case_*` tests in `tests/test_overrides.py`.
Each pins one property:

1. **A running replica keeps the last-known-good**
   (`test_case_1_a_running_replica_keeps_its_last_known_good`). With an
   `enforce` override adopted, the object turns unreadable, then invalid,
   then absent; the source stays `last_known_good`, the mode stays
   `enforce`, and each unreadable refresh logs the ERROR.
2. **A cold start uses the baseline, then adopts the object**
   (`test_case_2_a_cold_start_uses_the_baseline_then_adopts`, and
   `test_case_2_a_cold_start_on_an_invalid_object_adopts_once_valid`).
   With the object unreadable or invalid, the mode is the baseline and the
   reader is not ready; once the object is valid and a refresh passes, the
   override is in force.
3. **Clearing applies**
   (`test_case_3_a_valid_object_that_clears_an_override_is_applied`). A
   valid object without the override replaces one with it.
4. **The durability warning**
   (`test_case_4_the_durability_warning_is_for_enforce_over_observe`).
   `durability_warning` holds for an `enforce` override over an `observe`
   baseline, and not over `enforce` or with no override. The dashboard's
   rendering of it is pinned in `test_the_durability_warning` in
   `tests/test_dashboard_admin.py`.

Recovery has its own tests in the same file:
`test_recover_an_absent_object_that_a_replica_holds` and
`test_recover_an_invalid_object_keeping_the_mode` pin that recover writes
an object a replica holding a last-known-good adopts, and
`test_recover_refuses_while_the_read_fails` and
`test_recover_refuses_a_valid_object` pin its refusals.

`tests/test_overrides_ready.py` pins readiness for the reader and through
each service's `/readyz` and the ingest command: not ready in the four
cold cases (absent with audit records, an audit listing that fails,
unreadable, invalid) and on an uninitialized store until init; ready on
a valid object, with a last-known-good, and with the feature off; and
`/healthz` answering 200 throughout.

No test runs a mutation of the code. The properties above are what the
tests assert.

## Admin authorization

- **`oidc_jwt` is required** because a group membership that is not
  verified is one the caller chooses, the reasoning
  `Policy.entitlements()` applies to entitlements.
- **`platform: iap` is refused** because IAP tokens carry no groups, so
  no admin could match.
- **Groups are issuer-scoped** (`scoped_group(issuer, group)`). With more
  than one issuer, a bare group would let an admin of one IdP create a
  group of that name in another.
- **Incomplete groups are refused.** Either Entra overage signal
  (`_claim_names` naming the groups claim, or `hasgroups: true`) sets
  `groups_incomplete`, whatever groups the token carries; groups are not
  fetched from Graph.
- **A stable subject is required.** `Principal.name` falls back to
  `"unknown"`, which is not an audit identity, so admin actions use the
  verified `sub`.
- **Admin rights are separate from read scope.** An exclusion may name
  only a request id visible in the admin's scope, so being an admin does
  not widen what the entitlement map lets a person read.
- `dashboard.admins` is not in `ENV_OVERRIDES`, and `form_key` is on
  `SECRET_PATHS`, so the Policy tab redacts it.

## CSRF

The dashboard sits behind a sign-in proxy that holds a session cookie
and injects the token. A cross-site form post from a browser carries
that cookie, and the proxy vouches for it. Cookie `SameSite` attributes
belong to the proxy, not to us, so they cannot be relied on. Every POST
must pass all of the following, in this order:

1. **Method and path.** `POST /admin/actions` only. Every other path and
   method keeps the 405. Requires
   `Content-Type: application/x-www-form-urlencoded` and a body of at
   most 4 KiB.
2. **Origin.** `Origin` must be present and, with any trailing `/`
   stripped, equal to an entry in `dashboard.admins.allowed_origins`,
   whose entries are stripped the same way. A missing or `null` Origin is
   refused. If `Sec-Fetch-Site` is present and not `same-origin`, the
   request is refused. The list is explicit rather than derived from
   `Host`, because behind a proxy `Host` is whatever the proxy forwards.
3. **Authentication and admin match,** as above.
4. **Form token.** HMAC-SHA256 under `form_key` over
   `(issuer, subject, action, key, value, revision, issued_at)`. It is
   refused if any field differs from the request or if it is older than
   five minutes. A `revision` that is not the object's current revision
   is not a token refusal: the change is made conditional on it and
   answers as a conflict.
   - **Single use comes from the store, not from memory.** The write is
     conditional on the revision the token was minted against. Once any
     write lands, the revision moves and every outstanding token
     (including this one) is dead. This holds across replicas without
     shared state.
   - `form_key` is a secret, shared by every dashboard replica. A
     per-process random key would break a token rendered on one replica
     and posted to another.
   - It is on `SECRET_PATHS`. With admins configured and no key, the
     dashboard refuses to start, and the chart and the app modules
     refuse to render or plan with admins on and no key supplied.
   - **Rotating it only invalidates open forms.** A token minted under
     the old key fails verification, and the admin reloads the page. The
     key signs nothing that is stored: the object, the audit records and
     the chain are untouched.

A refusal answers with a generic body and logs the reason, as the 401
path does. Most refusals happen before
anything scans the request, so the signed-in name the token supplied
(`preferred_username` or email) is screened with the policy's detectors
before it is logged as `who`:
- a clean name is logged as it is;
- on a match, `who` is a pseudonym salted with `privacy.hash_salt`, and
  `who_matched` names the detectors. With an empty salt, `who` is
  `<withheld>`, because a truncated bare SHA-256 of a low-entropy value
  can be guessed;
- when the detectors cannot be built or cannot run, `who` is
  `<withheld>` and `who_unscanned` is set.

The status codes:
- 415 for the wrong content type;
- 413 for a body over 4 KiB;
- 401 for an identity that does not verify;
- 400 for a malformed form or an unknown action;
- 403 for everything else: the Origin, `Sec-Fetch-Site`, incomplete
  groups, no subject, not an admin, the control identity off
  (`control_identity_off`), a writer lockout not proven
  (`writer_lockout`), and the token.

Every request that passes the token check answers 303 to
`/policy?result=<outcome>`: `applied`, `nochange`, `conflict` (including
a stale revision), `invalid`, `refused`, `unreadable` or `error`. A policy,
detector or signing-key failure before the change answers
`?result=refused`. The dashboard's CSP always carries
`form-action 'self'`, with or without admins configured; `form-action`
does not fall back to `default-src`.

---

## Actions and the audit record

| Action | Effect on `state/runtime-overrides.json` |
|---|---|
| `override.set` | set `overrides[key]` |
| `override.clear` | remove `overrides[key]` |
| `override.clear_all` | `overrides: {}`; `stats_reset` and `excluded_requests` untouched |
| `stats.reset` | `stats_reset = now` (server clock), or the CLI's `--at` |
| `stats.reset_clear` | `stats_reset = null` |
| `exclusion.add` / `exclusion.remove` | add or remove one id in `excluded_requests` |
| `exclusion.clear` | `excluded_requests = []` |
| `legacy.migrate` (CLI only) | fold the `markers/*` objects into the two fields and set `legacy_markers_retired` and `legacy_markers_retired_by` |
| `state.init` | write the genesis record and an empty object into an empty store (see "Initialising the store" in the guide) |
| `state.recover` | write a valid object over an absent or invalid one, or over a valid one while no fresh verification record exists or a signed request names a later revision, keeping the newest verifiable state (see [Recovery](#recover)) |
| `state.checkpoint` (written by every change, never requested) | carry the whole verified state, so a reader's walk ends there (see [How far a reader checks](#how-far-a-reader-checks)) |

"Clear all overrides" does not touch the marker fields. They have their
own clear actions, as the CLI's `--clear` flags do.

### Signatures

Request records, `state.checkpoint` records, outcome records and lockout
verification records are signed with Ed25519. The signature sits in the
record's `signature` field (`alg`, `kid`, `sig`) and covers the record's
canonical JSON less that field. `kid` is the first 16 hex digits of the
SHA-256 of the public key. The signing key and the control identity are
trusted; a storage administrator without the key cannot write a record a
reader accepts, but can delete records and restore older versions (see
[The head anchor](#the-head-anchor)).

### Protocol

Every change goes through the same four steps.

1. **Read the object.** Read it with `read_control`, noting its ETag,
   and verify its head (below). An object that does not verify is
   invalid, and only `state.recover` proceeds. An absent object with no
   audit records takes only `state.init`; one with records takes only
   `state.recover`. For an absent object, `revision` starts at the highest
   `base_revision + 1` any request record names, so revisions never repeat
   across a recover.
2. **Scan and write a request record.** Every value the change supplies,
   and then every string in the finished record, is scanned with the
   configured detectors (see [What is never in a record](#what-is-never-in-a-record)).
   The record is immutable and create-only under the audit prefix, and
   says what is being asked for. It is stored as JSON with sorted keys and
   a trailing newline:

   ```json
   {
     "action": "override.set",
     "at": "2026-09-28T14:03:11Z",
     "base_audit_id": "20260928T120000Z-a1b2c3d4e5f6",
     "base_hash": "<sha256 hex of the base record's stored bytes>",
     "base_revision": 11,
     "id": "20260928T140311Z-0123456789ab",
     "key": "server.mode",
     "kind": "request",
     "legacy_markers_retired": true,
     "min_reader_version": "0.37.0",
     "new_value": "enforce",
     "old_value": "observe",
     "principal": {"issuer": "https://login.example/", "subject": "00u1ab…",
                   "name": "a.person@example.com", "via_group": "forgd-operators",
                   "verified": true},
     "retired_by": null,
     "state_sha256": "<sha256 hex of the object this write produces>",
     "version": 1
   }
   ```

   - `base_audit_id` and `base_hash` name the record that produced the
     object this write replaces, by id and by the SHA-256 of its stored
     bytes. Both are null for an init. A recover names the invalid
     object's head when it can read one, and a checkpoint names the head
     it follows; both are still chain starts.
   - `state_sha256` is the SHA-256 of the object the write will store,
     without `audit_hash`, serialised with sorted keys and no spaces.
     A record cannot include its own hash, so the object's link back to
     it is `audit_hash`.
   - `legacy_markers_retired` is the flag on the object it produces.
     `retired_by` is set only on a retired `state.recover` or
     `state.checkpoint`, as the migration's `{"id": …, "sha256": …}`.
   - `min_reader_version` is the value on the object it produces, or
     null. A replay refuses a record whose value is not what its action
     makes from its parent's (`record_min_reader_mismatch`). A
     `server.mode` set, or a recover with `--mode`, may raise it; nothing
     lowers it, and removing `server.mode` (a clear or a clear-all) drops
     it to null. A chain start
     carries it in its state. The head record must carry the object's
     value (`head_min_reader_mismatch`).

   A request record makes no claim that the change happened. It has no
   `outcome` field. If this write fails, the change is refused and the
   object is not touched.
3. **Write the state conditionally.** The write is conditional on the
   ETag from step 1. It sets `revision = base_revision + 1`, `audit_id`
   to the request's `id` (also on the per-key entry it changes), and
   `audit_hash` to the SHA-256 of the record's stored bytes.
4. **Optionally, write an outcome record.** Best effort, create-only:
   `{"version": 1, "kind": "outcome", "request_id": "<the request's id>",
   "result": "applied" | "conflict" | "error" | "unknown", "at": …}`,
   signed like a request record. It is for a person reading the audit
   prefix, with one exception. `error` is written only when the store
   refuses the object write outright (a 403), before anything commits. So
   a cold reader leaves a request with a signed `error` outcome out of
   its check for later requests ([The head anchor](#the-head-anchor)).
   `recover` also reads outcomes: it never puts a request with a signed
   `conflict` outcome first among its candidates, and it does not take a
   retirement from a migration whose signed outcome is `error` or
   `conflict`. A warm reader and the history read no outcome record.

**A change is real when the state object records it.**
The object's `audit_id` and `audit_hash` name the request that produced
its current revision. That request's `base_audit_id` names the one before, and so on
back to the first. The applied changes are exactly the requests on that
chain. A request record off the chain was not applied: its conditional
write lost, failed, or never ran. This holds without object version
history and without the outcome record.

### How far a reader checks

A reader adopts an object only when its head verifies: the record
`audit_id` names exists, its stored bytes hash to `audit_hash`, it is the
write of this revision at this `updated_at`, and its `state_sha256` is the
object's digest.

On each refresh that finds a new object, the reader then walks back from
the head record. At each link it checks that the parent's bytes hash to
the child's `base_hash`, that the parent is the record `base_audit_id`
names, and that each step goes back one revision. It also applies the
retirement rules (see [Legacy marker objects](#legacy-marker-objects-compatibility-and-migration)).
A reader that has verified a head refuses any object whose revision is
not after it.

A change verifies the object the same way, as a cold reader, before it
writes. A chain broken anywhere within the walk makes every change
refuse with the object invalid, except `state.recover`, which starts a
new chain over it.
- **Where the walk ends:** at the head the reader last verified, or at a
  record that starts a chain (a `state.init`, a `state.recover` or a
  `state.checkpoint`). A cold reader walks to the newest chain start, and
  a warm reader reads only the records after its own head. Readers also
  accept a write to an absent object with no base as a start, which
  `apply_change` does not write.
- **What each link must be:** once the walk ends, the reader replays
  every record it walked, oldest first, from the object it ends at: the
  head it last verified, or the state a chain start carries (empty for an
  init). A checkpoint whose parent is the reader's own head must carry
  exactly that head's state. Each record's
  action applied to its parent must produce exactly the object whose
  digest the record carries, and its key, old value and new value must
  be the ones that change records. Only the revision, the audit id and
  hash, and `updated_at` differ from what the action makes.
- **Checkpoints bound the walk.** Before any change that would put the
  head more than 100 links (`CHECKPOINT_EVERY`) from its chain start,
  `apply_change` first writes a `state.checkpoint` record carrying the
  whole verified state, then the change on top of it. So the chain walk
  of a cold read fetches at most about 100 records however long the
  history is, and a warm read's walk fetches only what is new. The check
  for later requests is separate and reads every request record (see
  Cost).
- **A walk that ends nowhere within 100 links is refused.** The record the
  walk ends at, the reader's own head included, must be at most 100 links
  back from the object's head. Otherwise the object is invalid: a warm
  reader keeps its last-known-good, a cold one is not ready, and changes
  refuse. A forged head more than 100 links past a start is never
  adopted, and a removed or rewritten checkpoint breaks the chain.
- **What a checkpoint trusts.** A checkpoint is written only by the
  control identity, under the audit prefix the writers are locked out of,
  as a recover is. A cold reader takes its state as the start. Anyone
  with the control identity could therefore write a consistent
  checkpoint or recover carrying any state; the signing key and the
  control identity are trusted (see [The head anchor](#the-head-anchor)).

The walk is how an overwritten or forged record is caught: rewriting any
record on the verified part of the chain changes its hash, and the link
after it stops matching. The dashboard's recent-changes list flags a
record that does not match its link.

Two consequences follow from the order:

- **No applied change is ever unrecorded.** The request record exists
  before the state write that cites it.
- **A request record may exist for a change that never happened.**
  That is the price of the order, and the chain makes it detectable.

The dashboard's "recent changes" list reads the chain and shows
off-chain requests separately, as "requested, not applied".

A write by the CLI (including `migrate-markers`) uses the same protocol.
An init, a recover and a checkpoint start a chain: an init's
`base_audit_id` and `base_hash` are null, a recover's name the invalid
object's head when it can read one, and a checkpoint's name the head it
follows.

### What is never in a record

- **Excluded material:** the raw JWT or any token, the form token,
  `form_key`, any secret, any header, and any matched content.
- **Why content cannot get in:**
  - Keys come from the closed allowlist, and values are the mode, a
    timestamp, or a request id.
  - A request id must be in a format a producer writes: the inference
    hook's upstream id as one part of `[A-Za-z0-9_-]`, the Claude Code
    hook's `<event>:<tool or prompt>:<id>`, or intake's `<event>:<ULID>`,
    where `<event>` is one of the four hook events that produce a
    record.
  - Before anything is read or written, every value the change supplies
    is scanned with the deployment's configured detectors. A finding
    refuses the change, and the refusal names only the detectors. So does
    a detector that did not run, or an empty detector set.
  - An exclusion equal to an org id the policy names is refused before
    anything is read. The ids come from `orgs`, `compliance` and
    `otel.orgs` (and the entitlements map), with `$FORGD_ORG_ID_*`
    references resolved from the environment, compared ignoring case. A
    UUID matches the request id format, so the format alone does not
    stop one. The refusal names no id.
  - `migrate-markers` scans each id in `markers/excluded_requests` the
    same way. One that a detector matches, that is not a request id, or
    that is an org id is left behind rather than folded in, and a
    `markers/stats_reset` value that is not a real time is dropped. With
    the feature off, `exclude` writes `markers/excluded_requests` and
    does not check org ids.
  - **Org ids in the principal become pseudonyms.** Before the record or
    the object is built, every org id the policy names is replaced in the
    principal (`name`, `subject`, `issuer`, `via_group`), compared
    ignoring case and inside longer strings, by
    `pseudonym(id, privacy.hash_salt, "org")`, or by
    `withheld (organization id)` when there is no salt. A record that
    still holds an org id is refused.
  - The finished request record is scanned again before it is written:
    every string in it, including the principal and the old and new
    values taken from the prior state. A deployment that runs PII
    detection over email addresses therefore refuses changes from an
    admin whose name or subject is an email address.
- **Exclusion actions:**
  - `exclusion.add` and `exclusion.remove` carry the one request id in
    `new_value` or `old_value`, never the whole set.
  - `exclusion.clear` puts the count removed in `old_value`.
  - `legacy.migrate` records the reset and the retirement flag, with the
    count of exclusions before it in `old_value` and the sorted list of
    request ids after it in `new_value`.

### Other properties

- **Naming.** `audit/runtime-overrides/<YYYY-MM-DD>/<id>-<kind>.json`,
  where `<id>` starts with the time and `<kind>` is `request` or
  `outcome`, so names sort by time. The same prefix holds the lockout
  verification records, `<YYYY-MM-DD>/verify-<id>.json`, their writers'
  clock probes, `<YYYY-MM-DD>/clock-<id>.json`, and the writers' probe
  records (see [Writer lockout probe](#writer-lockout-probe)).
- **Operator identity is stored in plain text.** The privacy invariant
  covers matched content and the people whose prompts are scanned, whose
  actor ids the store pseudonymises. An audit of who flipped enforce
  needs a readable name.

## Store access

**Why a control identity.** The reader identity is shared with the
connector on Helm (`templates/serviceaccount.yaml`), Container Apps
(`app-aca`) and ECS (`app-ecs`, whose connector task role is
`reader_role_arn`).
Granting the reader a write would let the connector, which callers
signed in through Claude reach, rewrite `server.mode`.

So the dashboard gets a **control identity**, and the writer identities
lose every write to the overrides object and the audit prefix. Without
that second half, a compromised writer, including the internet-facing
verdict server, could flip every replica to observe. The hash chain
would refuse an unaudited object, but the writer could also have written
the audit records. The exclusion holds on every cloud while
`control_enabled` is set. With it false, the store modules plan exactly
the pinned baseline under `tests/pinned/store-baseline`, writer bindings
included, and the writers can write the object: with the feature off no
service reads it (see "When runtime overrides are on" in the guide).
The tests render every resource and data source in each module with
mocked providers and compare them in full with that baseline.

The control identity:

- **Grants:** the reader's grants, the writes below, and the reads the
  [writer lockout verification](#writer-lockout-verification) needs:
  `storage.buckets.getIamPolicy` on the bucket and `iam.roles.get` on the
  project on GCS, `s3:GetBucketPolicy` (and `kms:GenerateDataKey` with a
  customer-managed key) on S3, and `roleAssignments/read` and
  `roleDefinitions/read` on the storage account on Azure.
- **When it exists:** only when admins are enabled in the deployment
  inputs. The flag is off by default, and with it off every render and
  plan is unchanged.
- **Isolation:** the chart and the modules refuse a control identity
  equal to the reader's or the writer's, as the chart refuses
  reader == writer.
- **Cloud Run** gives the dashboard its own account, separate
  from the connector.
  There the control identity adds only the extra bindings on that member.

### GCS (`store-gcs`)

- **Overrides object:** `roles/storage.objectCreator` and the module's
  delete-only custom role, both conditioned on
  `resource.name == "projects/_/buckets/B/objects/<root>state/runtime-overrides.json"`.
  Overwrite needs both: "In order to replace existing objects, both
  storage.objects.create and storage.objects.delete permissions are
  required" ([IAM permissions](https://docs.cloud.google.com/storage/docs/access-control/iam-permissions)).
- **Audit prefix:** `roles/storage.objectCreator` conditioned on
  `resource.name.startsWith("projects/_/buckets/B/objects/<root>audit/runtime-overrides/")`,
  with no delete. That makes audit records create-only in IAM as well
  as in code.
- **Conditions need uniform bucket-level access,** which store-gcs
  already relies on: "You must enable uniform bucket-level access on a
  bucket before adding conditions at the bucket level"
  ([Cloud Storage IAM](https://docs.cloud.google.com/storage/docs/access-control/iam)).
- **Listing cannot be scoped:** "Since the storage.objects.list
  permission is granted at the bucket level, you cannot use the
  resource.name condition attribute to restrict object listing access to
  a subset of objects in the bucket" (same page). The control identity
  lists every object name, as the reader does.
- The object-name format is from the [conditions attribute
  reference](https://docs.cloud.google.com/iam/docs/conditions-attribute-reference).
- **The writers are excluded while `control_enabled`.** The writers'
  `roles/storage.objectCreator` binding (`writer_create`) and their
  delete-only binding (`writer_mutable_delete`) then carry a condition
  ending in
  `!resource.name.startsWith("<object>") && !resource.name.startsWith("<audit prefix>")`.
  A condition can only allow, so the exclusion is a negated clause ANDed
  onto whatever the binding already allowed. `writer_create` has no
  condition when `key_prefix` is empty and control is off; with control
  on it always has one. Replacing an object needs both create and delete,
  so a writer can neither create, replace nor delete either path.
- **Turning `control_enabled` on replaces the two writer bindings.** A
  changed condition is a new IAM binding, so that apply replaces
  `writer_create` and `writer_mutable_delete` for every writer member.
  Both carry `create_before_destroy`, so the new binding exists before
  the old one is removed, and the writers keep create and delete
  throughout the apply. Expect the plan to show them as replaced. With
  it off, neither binding is replaced.
- **`control_members` needs `control_enabled`.** The module refuses a
  non-empty `control_members` while it is false, rather than dropping
  them.

### S3 (`store-s3`)

- **Overrides object:** `s3:PutObject` on
  `arn:aws:s3:::B/<root>state/runtime-overrides.json`.
- **Audit prefix:** `s3:PutObject` on
  `arn:aws:s3:::B/<root>audit/runtime-overrides/*`. The bucket-policy
  statement `AuditRecordsAreCreateOnly` denies `s3:PutObject` on that
  prefix to the control role, matched by `ArnEquals` on
  `aws:PrincipalArn`, when `{"Null": {"s3:if-none-match": "true"}}`: a
  put without `If-None-Match` is refused, so the control role can only
  create a record. The key is [listed for
  PutObject](https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3.html),
  and the [enforce page](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html)
  shows it in bucket policies.
- **Deletes:** the control role's ARN is added to the `ArnEquals
  aws:PrincipalArn` values of `NoDeletesByTheApp`, whose principal is `*`. Bucket versioning keeps every prior
  version of the overrides object.
- **Conditional writes:** `If-Match` needs `s3:GetObject` as well as
  `s3:PutObject` ([conditional
  writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)).
  The reader grants already include it.
- **Listing is by prefix:** `s3:ListBucket` is a bucket-level action
  that takes `s3:prefix`. The control identity keeps the reader's
  prefix-conditioned list.
- **While `control_enabled`, the writer is excluded by a bucket-policy
  Deny,** `WriterCannotWriteRuntimeOverrides`. It denies `s3:PutObject`,
  `s3:DeleteObject` and `s3:DeleteObjectVersion` on the object and the
  audit prefix to the module's writer role, by `aws:PrincipalArn`. It is
  in the bucket policy, so no policy attached to the role later can lift
  it.
- **A writer role from outside the module must carry the same Deny.**
  The bucket statement names `writer_role_arn` only. An ECS task role or
  an EKS service-account role created elsewhere and granted writes to
  the bucket is not covered by it. Attach the module's
  `writer_deny_policy_json` output to every such role. It is null while
  `control_enabled` is false, like the bucket statement, so gate the
  attachment on the same flag, for example:

  ```hcl
  resource "aws_iam_role_policy" "no_runtime_overrides" {
    count  = var.control_enabled ? 1 : 0
    role   = aws_iam_role.my_writer.name
    policy = module.store_s3.writer_deny_policy_json
  }
  ```

  With control enabled this is required. Without it that
  role can write the overrides object and the audit prefix as far as its
  own policies allow. A Deny in an identity policy holds against any
  Allow the role has. The policy carries a second statement,
  `WriterCannotRewriteBucketPolicy`, denying `s3:PutBucketPolicy` and
  `s3:DeleteBucketPolicy` on the bucket, as the bucket policy does for
  `writer_role_arn`.

  It does not make that role pass the
  [writer lockout verification](#writer-lockout-verification), which
  reads only the bucket policy. Only `writer_role_arn` is named there, so
  listing such a role in `FORGD_OVERRIDES_WRITER_IDENTITIES` fails the
  verification, and leaving it out leaves its lockout unverified.

### Azure (`store-azure`)

- **With `control_enabled` false, the module assigns the built-in
  roles.** The writer holds Storage Blob Data Contributor and
  the reader Storage Blob Data Reader. No custom role, resource-group
  lookup or lock is planned, and applying it needs no permission it did
  not need before. The two assignments keep their addresses
  (`app_writes_findings`, `dashboard_reads_findings`) and render exactly as
  they did, so nothing is replaced.
- **With `control_enabled` true, no identity holds a built-in role.** The
  writer, the reader and the control identity each get a custom role with
  no `actions` (no control-plane action at all) and only the blob data
  actions the store uses. The control identity also gets a fourth custom
  role, `control_reads_assignments`, holding only the actions
  `Microsoft.Authorization/roleAssignments/read` and
  `roleDefinitions/read`, assigned on the storage account for the lockout
  verification. The storage account gets a `CanNotDelete` lock (below). Creating the roles needs
  `Microsoft.Authorization/roleDefinitions/write` on the resource group,
  which Owner and User Access Administrator hold, only then.
  - The built-in roles, from Microsoft's definitions
    ([Azure built-in roles for Storage](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage),
    updated 2026-07-01). Storage Blob Data Contributor
    (`ba92f5b4-2d11-453d-a403-e96b0029c9fe`) holds the actions
    `blobServices/containers/delete`, `containers/read`,
    `containers/write` and `blobServices/generateUserDelegationKey/action`,
    and the data actions blob `delete`, `read`, `write`, `move/action`
    and `add/action`. Storage Blob Data Reader
    (`2a2b9908-6ea1-4ae2-8e65-a410df84e7d1`) holds `containers/read` and
    `generateUserDelegationKey/action`, and blob `read`.
  - What the store calls (`store/blob.py`): `upload_blob`,
    `download_blob` and `list_blobs` on the container client, and
    nothing on the container itself or on a user delegation key.
    Microsoft's permissions table
    ([Authorize with Microsoft Entra ID](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory#permissions-for-blob-service-operations))
    maps them: Put Blob to blob `write` (create or replace) or
    `add/action` (a new blob); Put Block and Put Block List to `write`;
    Get Blob, Get Blob Properties and List Blobs to `read`. No store
    operation needs blob `delete` or `move/action`, or any container
    action.

- **Turning `control_enabled` on or off leaves no access gap.** Each of
  `app_writes_findings` and `dashboard_reads_findings` names the built-in
  role with the flag off and the custom one with it on, so the flag
  changes its role and replaces it. Both have `create_before_destroy`:
  - turning it on creates each custom-role assignment before the
    built-in one is removed;
  - turning it off creates each built-in assignment before the custom
    one is removed;
  - Azure allows both at once because they hold different roles; it
    refuses a second assignment only when scope, principal and role all
    match (`RoleAssignmentExists`).
  - A later edit to the custom writer's condition text replaces it with
    the same scope, principal and role, which Azure refuses. The apply
    then fails with `RoleAssignmentExists` and leaves the old assignment
    in place, rather than leaving the writer without a role.
  - **UNCONFIRMED:** the ordering is tested on Terraform stand-ins, not on
    a live subscription, and how long a new assignment takes to
    propagate is not measured.

  | Identity, with `control_enabled` | Custom role | Data actions |
  |---|---|---|
  | Writer (`app_writes_findings`) | `writer` (`writer_role_name`) | blob `read`, `write`, `add/action`, with the path condition below |
  | Reader (`dashboard_reads_findings`) | `reader` (`reader_role_name`) | blob `read` |
  | Control (`control_writes_overrides`) | `control_writes` (`control_role_name`) | blob `read`, `write`, `add/action`, with the path condition below |
  | Control (`control_reads_assignments`, on the storage account) | `control_reads_assignments` (`control_evidence_role_name`) | none; the actions `roleAssignments/read` and `roleDefinitions/read` |

- **Reads:** the control identity's role holds blob `read`, which its
  condition does not gate, so it reads everything the reader does.
- **Writes:** the control identity's role holds two write data actions,
  assigned on the container with an ABAC condition on
  `@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path]`,
  one clause per action:
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write`
    only where the path equals `state/runtime-overrides.json`;
  - `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action`
    where the path equals `state/runtime-overrides.json` or starts with
    `audit/runtime-overrides/`.
- **So the audit prefix is create-only.** Microsoft's permissions table
  for Blob operations
  ([Authorize with Microsoft Entra ID](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory#permissions-for-blob-service-operations))
  gives Put Blob as "For create or replace: `.../blobs/write`. To create
  new blob: `.../blobs/add/action`".
  - Every operation that changes an existing blob needs `write`, which
    the condition refuses under the audit prefix: Put Block, Put Block
    List, Set Blob Properties, Metadata or Tier, Lease Blob, and a Put
    Blob that replaces.
  - Operations `add/action` authorises create a new blob: Put Blob,
    Copy Blob to a new destination, Snapshot Blob, or Append Block. An
    audit record is a block blob, so Append Block cannot extend one.
- **What `put_audit` sends.** `upload_blob(..., overwrite=False)` in
  azure-storage-blob 12.31.0 (the locked version) sets
  `If-None-Match: *`. For a body under `max_single_put_size` it sends one
  Put Blob, which can only create. An audit record is a few hundred bytes.
- **The state object** gets `write`, because a change replaces it
  conditionally on its ETag. It also gets `add/action`, which only lets
  the control identity create the object when it is absent. That covers
  the case where the service authorises a create through `add/action`
  rather than `write`, which the docs do not settle.
- **Sources:**
  - Microsoft states that "Azure attribute-based access control (Azure
    ABAC) is generally available (GA) for controlling access to Azure
    Blob Storage"
    ([overview](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-auth-abac)).
  - The [actions and
    attributes](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-auth-abac-attributes)
    page lists Blob path for `write`, `add/action`, `delete`,
    `deleteBlobVersion/action`, `permanentDelete/action` and
    `move/action`.
  - The path "shouldn't include the container name or a preceding slash".
- **Not confirmed against a live account**: no Put Blob has run under
  this assignment. If the service ever demanded `write` for a
  create, `put_audit` would fail with a 403 and the change would be
  refused. The record is written before the object, so no change would
  apply.
- **Detection still backs it.** An overwrite by anything outside this
  role is caught by the hash chain: each record is hashed into the next
  and into the object. Blob versioning (`store-azure/main.tf`) keeps the
  prior version.
- **The writers.** While `control_enabled`, the writer's assignment
  (`app_writes_findings`) holds the custom `writer` role and
  carries an ABAC condition that refuses all six data actions above on both paths,
  with `StringNotEquals` on the object and `StringNotStartsWith` on the
  audit prefix. Reads are not gated. The role holds only `write` and
  `add/action` of those six; the condition names the others too, so it
  still holds if the role ever gains one.
  - **With `control_enabled`, the writer cannot delete or recreate the
    container.** Its role holds no `blobServices/containers/delete` or `containers/write`, the
    control-plane actions a blob-path condition cannot scope. Nor does
    it hold blob `delete` or `move/action`, so it cannot remove a blob
    anywhere in the container. With the flag off it holds Storage Blob
    Data Contributor, which can do both.
  - Undelete Blob and Set Blob Legal Hold authorise on
    `containers/write`, so with the flag on no identity of this module can
    run them.
- **The storage account is locked while `control_enabled`.** A
  `CanNotDelete` management lock (`azurerm_management_lock.findings`)
  is scoped to the storage account, on by default, and off with
  `storage_account_delete_lock = false`.
  - Microsoft: "Locks only apply to control plane Azure operations and
    not to data plane operations", and "A read-only lock or
    cannot-delete lock on a storage account doesn't protect its data
    from being deleted or modified"
    ([Lock your Azure resources](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources)).
  - So it refuses deleting the storage account through Resource Manager,
    and deleting the container through Resource Manager. It does not
    block a blob write, and does not stop a delete on the data plane: a
    container or blob deleted with the data-plane API by an identity that
    holds the action is still deleted. No identity of this module holds
    one; the lock covers a person or pipeline with Contributor on the
    resource group.
  - Microsoft also says "A cannot-delete lock on a resource or resource
    group prevents the deletion of Azure RBAC assignments". The lock
    depends on all four role assignments, so Terraform creates it after
    them and removes it before them when `control_enabled` turns off. Any
    other apply that removes or replaces one of this module's
    assignments, or destroys the store, needs the lock removed first:
    set `storage_account_delete_lock = false`, apply, then make the
    change.
  - Creating or removing a lock needs `Microsoft.Authorization/locks/*`,
    which Owner and User Access Administrator hold.
- **Listing is by prefix:** List Blobs does not take the blob path. It
  is `blobs/read` with suboperation `Blob.List`, and conditions scope it
  only through the request's `blobs:prefix` attribute (same attributes
  page). The control identity's `read` is not gated, so it lists the
  container as the reader does.
