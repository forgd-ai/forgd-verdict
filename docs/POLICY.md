# Policy

Every service reads one file, `policy.yaml`. It is merged over built-in
defaults and then over a short list of environment variables. The
annotated copy in the repository root is the reference for each key. This
page says where each section is read and documented, how `$VAR` references
resolve, and what the environment can and cannot change.

The file is found at `--policy`, else `$FORGD_VERDICT_POLICY`, else
`./policy.yaml`. The Claude Code hook and `hook-ship` read `--policy` only:
neither `$FORGD_VERDICT_POLICY` nor `./policy.yaml`, because a project's
`.claude/settings.json` sets the hook's environment and its working
directory is the project's.

A file named by `--policy` or `$FORGD_VERDICT_POLICY` must exist. When it
does not, the verdict server, the collector, the intake, the dashboard,
the connector, `ingest` and the other CLI subcommands print one line and
exit 2:

```
refusing to start the verdict server: policy file /etc/forgd/policy.yaml does not exist (named by FORGD_VERDICT_POLICY)
```

The line names the path and which of the two named it, and nothing read
from any file. The Claude Code hook scans on the built-in defaults instead
and warns; see [`hook.on_error`](#hookon_error).

With nothing named and no `./policy.yaml`, the built-in defaults load and
the environment overrides apply to them, so `FORGD_VERDICT_MODE` and
`FORGD_VERDICT_STORE` take effect without a file. A file that exists and
does not parse stops the service.

How the policy reaches each deployment target is in [SERVER.md §
Configuration](SERVER.md#configuration).

## Sections

The shared sections drive the scan core everywhere. The rest belong to one
adapter each. `server`, `hook`, `compliance` and `otel` may each carry a
`detectors:` block of their own, merged over the top-level one for that
adapter.

| Section | Controls | Read by | In depth |
|---|---|---|---|
| `detectors` | which detectors run and at what severity: T0 regex, checksums, entropy, gitleaks (T1), Presidio and LLM Guard (T2), behavioural checks | every adapter | [SERVER.md § Scan core](SERVER.md#scan-core) |
| `scan` | the scan budget and the session cache | every adapter | [SERVER.md § Scan budget](SERVER.md#scan-budget) |
| `privacy` | `hash_salt`, the salt on every `excerpt_hash`, and `allow_unsalted`, which lets a service that logs or records findings start without one | every adapter that writes findings. The hook, on a laptop, is not given the salt: see the `hook` comments | [SERVER.md § Privacy invariant](SERVER.md#privacy-invariant) |
| `deny` | `contact_line`, appended to deny reasons | every adapter that returns a deny | the comments in `policy.yaml` |
| `server` | the verdict server: mode, signing secrets, signature enforcement, body limits, the metrics token, failure behaviour, the findings store | adapter 1 | [SERVER.md § Adapter 1](SERVER.md#adapter-1--inference-hooks-verdict-server) |
| `hook` | the Claude Code hook: its detectors, the local spool, shipping decisions, remote scanning | adapter 2 | [PLATFORM.md § Adapter 2](PLATFORM.md#adapter-2--claude-code-hook-cli) |
| `compliance` | the Compliance API scanner: orgs and their access keys, its detectors and budget | adapter 3, and adapter 6, which uses its detectors | [PLATFORM.md § Adapter 3](PLATFORM.md#adapter-3--compliance-api-scanner-optional) |
| `dashboard` | dashboard authentication, entitlements, admins, branding | the dashboard; the connector reads the entitlements | [PLATFORM.md § Dashboard authentication](PLATFORM.md#dashboard-authentication) |
| `orgs` | the org registry: one id and label per Claude organization. The only place an org is named | the dashboard and connector for labels; the verdict server, collector and intake publish it to the store | [PLATFORM.md § Org entitlements and labels without the salt](PLATFORM.md#org-entitlements-and-labels-without-the-salt) |
| `intake` | adapter 2's receiving end: a bearer token per managed fleet, one per agent or other client, their routes and orgs, its store | the intake service | [`intake` below](#intake-fleets-clients-and-the-org-a-record-files-under) |
| `otel` | the OTLP collector: per-org tokens and ids, CORS origins, its detectors, and `sink_detectors` for adapter 5's redaction | adapter 4 | [PLATFORM.md § Adapter 4](PLATFORM.md#adapter-4--otel-collector) |
| `sinks` | outbound destinations for a redacted copy of what the collector receives | adapter 5 | [PLATFORM.md § Adapter 5](PLATFORM.md#adapter-5--outbound-sink-optional) |

### Sections the reference file does not set

The loader accepts these. The shipped `policy.yaml` has no active block
for any of them, and `managed_agents` appears there only as a comment.

| Section | Read by | In depth |
|---|---|---|
| `plugins` | `plugins.allow`, the allowlist of third-party detectors, stores and sinks; parsed at load (`plugins.py`) | [PLUGINS.md § `plugins.allow`](PLUGINS.md#pluginsallow) |
| `connector` | the findings connector (`connector/`) | [CONNECTOR.md § Policy keys](CONNECTOR.md#policy-keys) |
| `overrides` | `signing_key` and `verify_keys` for signed runtime overrides (`overrides_signing.py`, `overrides.py`) | [OVERRIDES.md § Signing keys](OVERRIDES.md#signing-keys) |
| `managed_agents` | adapter 6, the Managed Agents scanner, run by the ingest job (`managed/scanner.py`, `orgregistry.py`) | [PLATFORM.md § Adapter 6](PLATFORM.md#adapter-6--managed-agents-scanner-optional) |

The loader does not check top-level names. A misspelt section is ignored
without a warning. Detector names are checked. An unknown name that is
disabled is logged and ignored. An unknown name that is enabled, and is
not a plugin listed in `plugins.allow`, stops the service.

## `intake`: fleets, clients and the org a record files under

```yaml
intake:
  fleet:
    - name: laptops                     # required; the record's `client`
      tokens: [$FORGD_INTAKE_FLEET_TOKEN, $FORGD_INTAKE_FLEET_TOKEN_PREVIOUS]
      org: $FORGD_ORG_ID_PRIMARY        # optional; or `orgs`, below
      routes: [intake, scan]            # optional; both by default
      require_device: true              # optional; true by default
  clients:
    - name: invoice-bot
      token: $FORGD_INTAKE_TOKEN_INVOICE_BOT
      org: $FORGD_ORG_ID_PRIMARY        # optional
      routes: [scan]
      agent: true
      labels: [triage]
```

`fleet` is one bearer shared by every laptop in a managed fleet. `tokens`
is a list so a rotation can hold the current and the previous value; an
entry whose variable is unset is skipped, and a fleet with none set is not
configured. Each request names its device in the `X-Forgd-Device` header,
and the device id is a field on the record. A request from a fleet with no
usable device id (`d` and 12 lowercase hex characters) is refused with 403
`device_required` and counted as `device_missing`; with
`require_device: false` it is accepted and counted. One device is refused
with `forgd-verdict overrides deny-device` ([OVERRIDES.md](OVERRIDES.md)).
Device deny is not available on Cloud Run, where runtime overrides are off;
there, the only way to cut a device off is a fleet-wide rotation: issue a new fleet token with the old one in `FORGD_INTAKE_FLEET_TOKEN_PREVIOUS`, then clear it, which also cuts off every laptop not yet given the new token.
Where the laptop's id comes from is `hook.device_salt_path`
([deploy/MDM.md](../deploy/MDM.md#provisioning-the-device-salt)).

`clients` holds one token per agent, or per laptop outside a fleet. A
per-laptop client (no `agent: true`) logs a startup warning naming
`intake.fleet`.

A record files under:

1. the credential's `org`, as the pseudonym adapters 3 and 4 write that
   org's records under;
2. else the deployment's only org, when the policy names exactly one and
   every org reference in it resolves;
3. else the unattributed partition, with a startup warning naming the
   credentials it applies to.

An `org` whose variable resolves to nothing refuses to start.

### A fleet whose developers work in several orgs

```yaml
intake:
  fleet:
    - name: laptops
      tokens: [$FORGD_INTAKE_FLEET_TOKEN, $FORGD_INTAKE_FLEET_TOKEN_PREVIOUS]
      orgs: [$FORGD_ORG_ID_PROD, $FORGD_ORG_ID_DEV, $FORGD_ORG_ID_TEAM]
```

One MDM fleet often holds developers in prod, dev and a Team workspace.
`orgs` binds the fleet to all of them. Nothing a laptop sends names its
org, so the intake files each of the fleet's records under the fleet's
own partition, `fleet-<name>`, with the fleet's orgs on the record. The
dashboard and the connector then attribute each record when they read
it: a record belongs to org O when its Claude Code session id is the
`session.id` of a Claude Code OTel export the collector filed under O, O
is one of the fleet's orgs, and no other org's export carries that session
id. This needs Claude Code's OTel export configured on the laptops
(`otel.orgs`, with `id` or `ids` set so the collector checks the org), and
it reads OTel records from up to a day before the window.

A record no export attributes is **org pending**: it stays in the fleet's
partition, the Event Log marks it, and it is visible only to a reader of
every org in `orgs`, or to a reader with no entitlement map. That covers a
session whose export has not arrived yet, a session an export never names
(no OTel on that laptop), a session two orgs' exports both name, and one
whose export is filed under an org the fleet is not bound to. A record
attributed today can return to pending if another org's export later
names its session. `orgs` naming one org, after variables resolve, is the
same as `org`. Setting both `org` and `orgs`, an empty `orgs`, or an
entry whose variable is unset refuses to start.

The dashboard and the connector take each fleet's orgs from this same
`intake.fleet` list, so they need the org id variables set as the intake
does, or the orgs listed under `orgs` or `otel.orgs` so the org registry
carries them. A viewer's read opens a fleet's partition only when it can
hold a row they may see: when they hold every org in `orgs`, or hold some
of them and a session is attributed to one of those. A viewer of an org in
no fleet never reads one. Each one starts with a warning naming any fleet
whose orgs it cannot resolve; a viewer of such an org is shown none of
that fleet's records. A fleet removed from `intake.fleet` is read only by
a reader with no entitlement map, so its records leave every scoped view.

A fleet or
client name is the record's `client` field and an Event Log filter. It is
never an org, and the dashboard's org picker does not list it. Names follow
one rule: a lowercase letter, then up to 39 lowercase letters, digits or
hyphens, and not `unattributed`. A fleet and a client may not share a name
or a token.

`intake.tally_flush_s` (default 600) is how often the intake writes the
clean Code hook allows it has counted. A clean allow, with no finding and
no dropped tier, is counted into a tally row instead of being stored as a
record; every deny and finding is still a record. Readers weight a tally
row by its count, so numbers are unchanged; a crash loses at most this
long of allow counts ([PLATFORM.md](PLATFORM.md)).

## `hook.device_salt_path`

The file the laptop's device id is derived from. The intake records that id
on every shipped record, and `forgd-verdict overrides deny-device` refuses
one device by it. Provision it once per machine through MDM
([deploy/MDM.md](../deploy/MDM.md#provisioning-the-device-salt)) and name
it in the laptop policy:

```yaml
hook:
  device_salt_path: /etc/forgd/device-salt   # C:\ProgramData\forgd\device-salt on Windows
```

The shipped `policy.yaml` carries this line commented out, because the
file has to exist before the setting is useful.

| State | Device id sent | Said |
|---|---|---|
| unset | from a per-user salt in the user's home directory; deleting it gives the laptop a new id | on stderr, whenever it ships or scans remotely |
| set, fit | from the provisioned salt | nothing |
| set, unfit | none; the intake refuses the laptop with `device_required` | on stderr, naming why |

Fit, on macOS and Linux: an absolute path to a regular file, not a symlink,
holding 64 hex characters, not owned or writable by the user running the
hook, and not writable by its group or others, nor in a directory any of
them can write. On Windows only the content is checked; the ACL in
deploy/MDM.md keeps users out.

It is read from the policy file only, never from the environment, and
`hook.project_overrides` does not change that.

The dashboard cannot show which laptops send an unprovisioned id. The
record carries the device id and not where its salt came from, the intake
builds each stored record from fields it binds, and a bit the laptop
reported would be the laptop's own claim. To find unprovisioned laptops,
report `forgd-verdict hook device-id` into inventory (deploy/MDM.md) and
compare it with the device ids in the Event Log.

## `server`: request bodies before the signature

The verdict server reads a hook body before it can verify the signature
over it. Four settings bound what unsigned callers can make it hold; see
[SERVER.md § Memory](SERVER.md#memory) for how they combine with the
memory limit.

| Key | Default | Bounds |
|---|---|---|
| `server.max_body_bytes` | `67108864` (64 MiB, the protocol maximum) | one body. Over it, 413; a declared `content-length` over it is refused unread |
| `server.preauth_body_budget_bytes` | `268435456` (256 MiB) | the bytes held across every body whose signature is not verified yet. A request it has no room for is answered 503 `busy` with `Retry-After: 1`, unread |
| `server.body_read_timeout_s` | `15` | how long one body may take to arrive; past it, 503 `body_timeout` |
| `server.limit_concurrency` | `1024` | connections and requests uvicorn serves at once; past it, uvicorn answers 503 |

Each must be a positive integer (`body_read_timeout_s` a positive number),
and `preauth_body_budget_bytes` must be at least `max_body_bytes`, or the
verdict server refuses to start. None of them can be set from the
environment.

## `$VAR` references

A string value that starts with `$` names an environment variable, and
the value is read from it when the setting is used. The whole string is
the name: `$FORGD_HASH_SALT` reads `FORGD_HASH_SALT`, and nothing is
interpolated inside a longer string. An unset or empty variable resolves to
no value. Every credential in the shipped file is written this way, and
the test suite fails if it holds a literal one.

What "no value" does depends on the key:

| Unresolved | Effect |
|---|---|
| `server.store` (`$FORGD_VERDICT_STORE`) | the verdict server refuses to start |
| `server.secrets` | the server starts and logs an error; every hook request gets 503. A secret that resolves but does not decode to a key is logged as an error at startup, and every hook request gets 401 |
| `server.metrics_token` | `/metrics` on the verdict server and `/stats` on the collector and the intake are disabled and answer 404. A placeholder counts as unset; a value under 24 characters stops the verdict server and the collector from starting |
| `privacy.hash_salt` | every service that logs or records findings refuses to start, with or without a store: the verdict server, the collector, the intake and both ingest jobs. With `privacy.allow_unsalted: true` in the file it starts and warns; hashes are bare sha256, and the org registry is not published. `forgd-verdict scan` hashes with a random per-run key and says so on stderr. The dashboard and the connector read a store and never need the salt |
| `otel.orgs[].token` | that org is skipped without a log line, and its exports get 401. When no org has a token, the collector starts and logs an error, and every export gets 401 |
| `otel.orgs[].id`, with its token set | the collector refuses to start: with no id, the cross-check against the payload's `organization.id` cannot run |
| `intake.fleet[].tokens`, `intake.clients[].token` | that credential is skipped. With none left, the intake starts and logs that every submission will be refused |
| `intake.fleet[].org`, `intake.fleet[].orgs[]`, `intake.clients[].org` | the intake refuses to start |
| `dashboard.auth.stripped_by`, in `trusted_header` mode | the dashboard refuses to start |

**Organization ids** are written as `$FORGD_ORG_ID_<NAME>`, in `orgs`,
`compliance.orgs`, `otel.orgs` and `intake.fleet`, and set on the service. They resolve
like any other reference. The test suite fails if `policy.yaml` holds a
literal UUID instead.

### What stays off the dashboard's Policy tab

`forgd-verdict policy` and the dashboard's Policy tab print the same
redacted view, from one function (`policy.redacted`).

- **Secrets.** `SECRET_PATHS` lists single keys: `compliance.api_key`,
  `server.metrics_token`, `privacy.hash_salt`, `hook.ship_token`,
  `hook.scan_token`, `dashboard.admins.form_key` and
  `overrides.signing_key`. `SECRET_LIST_PATHS` lists keys inside lists:
  `token` in `otel.orgs`, `sinks` and `intake.clients`, `tokens` in
  `intake.fleet`, and `api_key` in `compliance.orgs` and
  `managed_agents.workspaces`. A new secret key goes on one of these lists.
- **How each one is shown.** A `$VAR` reference whose variable is empty is
  shown as `<unset: $VAR empty>`. Any other value is shown as
  `<redacted>`, and a list of tokens item by item. Two are shown
  differently. `server.secrets` is shown as `<N resolved>` or
  `<none resolved>`. `privacy.hash_salt` is shown as `<set>`, or
  `<UNSET: $env var is empty>`, or on the dashboard, which is not given
  the salt, as `<not shown here: this service is not given the salt>`.
- **Org ids.** An org id written as a `$FORGD_ORG_ID_*` reference is shown
  as that reference. A literal id is shown as `<org id>`. Managed Agents
  workspace keys are shown as `<workspace key>`.
- **Plugin settings.** A plugin's configuration is redacted except for
  `enabled`, `severity` and the keys it declares public.
- **Credential-named keys anywhere.** Outside the `detectors` sections,
  any key whose name ends in `token`, `tokens`, `secret`, `secrets`,
  `password`, `api_key`, `private_key`, `access_key`, `secret_key`,
  `signing_key`, `form_key`, `sas`, `connection_string` or `credentials`
  is shown as a secret is, whatever section it is in. A secret list written
  as a mapping (an `intake.fleet` of `name: tokens`) is shown as
  `<redacted: ... is not a list>`, since its keys can be the tokens.
- **URLs and store specs.** Outside the `detectors` sections, every value
  of a key ending in `endpoint`, `url`, `uri`, `issuer`, `store` or
  `origins`, and every URL inside any other string, is shown with its
  userinfo, query and fragment as `<redacted>`, and so is a host that is
  not a plain hostname or bracketed IPv6 address, and any path segment
  holding `;`, `=`, `@` or `%`. Scheme, host, port and the rest of the
  path are kept. The same form is used where the dashboard logs its
  issuer and where a store describes or refuses its URL. A built-in store
  spec (`https://`, `s3://`, `gs://`) with userinfo refuses to open.
- **Everything else** is printed as written. A `$VAR` reference stays a
  reference, unless an environment override has replaced the value.

## Environment overrides

`ENV_OVERRIDES` in `policy.py` is a fixed allowlist. Each variable, when
set and non-empty, replaces one policy path after the file is merged over
the defaults, or over nothing when no file is named and `./policy.yaml`
does not exist. An empty variable is ignored. A value that fails its coercion stops the load
with the variable's name.

The `FORGD_VERDICT_SCAN_*` and `FORGD_VERDICT_SHIP_*` variables are applied
only when the policy file sets `hook.project_overrides: true`. Otherwise each
is ignored with a line on stderr. A Claude Code project's
`.claude/settings.json` `env` block reaches the hook's environment, so
without this a cloned repository could send the hook's payload to a server
of its choosing and answer `allow`, force the weaker local fallback with a
bad token or a 1 ms timeout, or turn shipping off. The same gate applies to
a `$VAR` placeholder in `hook.scan_endpoint`, `hook.scan_token`,
`hook.ship_endpoint`, `hook.ship_store` or `hook.ship_token`, and to a `$VAR`
gitleaks `daemon` when the hook scans locally. The hook resolves a relative
gitleaks `config` or `binary` against the policy file's directory, not the
project's, and refuses a `hook.ca_file` that is not absolute.
`hook.project_overrides` has no environment override.

Without `hook.project_overrides: true`, the hook also ignores
`FORGD_VERDICT_SPOOL`, `XDG_STATE_HOME` and `HOME`, placing the spool and
the device salt from `hook.spool` and, on macOS and Linux, the password
database. It does not look gitleaks up on `PATH`: it runs an absolute
`hook.detectors.gitleaks.binary` or `detectors.gitleaks.binary`, and
otherwise does not run T1. The managed fragment for macOS and Linux starts
the hook under `env -i`, so there it gets none of these variables even
with `hook.project_overrides: true`.

| Variable | Policy path | Coercion |
|---|---|---|
| `FORGD_VERDICT_MODE` | `server.mode` | string |
| `FORGD_VERDICT_LOG_LEVEL` | `server.log_level` | string |
| `FORGD_VERDICT_BUDGET_MS` | `scan.budget_ms` | integer |
| `FORGD_VERDICT_STORE` | `server.store` | string |
| `FORGD_DASHBOARD_REQUIRE_PRINCIPAL` | `dashboard.require_principal` | boolean: `1`, `true`, `yes` or `on` is true, anything else false. True refuses to start the dashboard; configure `dashboard.auth` with `mode: trusted_header`, `header` and `stripped_by` instead |
| `FORGD_VERDICT_SHIP_MODE` | `hook.ship_mode` | string |
| `FORGD_VERDICT_SHIP_STORE` | `hook.ship_store` | string |
| `FORGD_VERDICT_SHIP_ENDPOINT` | `hook.ship_endpoint` | string |
| `FORGD_VERDICT_SHIP_TOKEN` | `hook.ship_token` | string |
| `FORGD_VERDICT_SCAN_ENDPOINT` | `hook.scan_endpoint` | string |
| `FORGD_VERDICT_SCAN_TOKEN` | `hook.scan_token` | string |
| `FORGD_VERDICT_SCAN_TIMEOUT_MS` | `hook.scan_timeout_ms` | integer |
| `FORGD_DASHBOARD_AUTH_MODE` | `dashboard.auth.mode` | string |
| `FORGD_DASHBOARD_STRIPPED_BY` | `dashboard.auth.stripped_by` | string |
| `FORGD_DASHBOARD_ISSUERS` | `dashboard.auth.issuers` | JSON array |
| `FORGD_DASHBOARD_GROUPS_CLAIM` | `dashboard.auth.groups_claim` | string |
| `FORGD_DASHBOARD_PLATFORM` | `dashboard.auth.platform` | string |
| `FORGD_DASHBOARD_ALB_ARN` | `dashboard.auth.alb_arn` | string |
| `FORGD_CONNECTOR_ENABLED` | `connector.enabled` | boolean, as above |
| `FORGD_CONNECTOR_RESOURCE` | `connector.resource` | string |
| `FORGD_CONNECTOR_SCOPES` | `connector.scopes` | JSON array |
| `FORGD_CONNECTOR_REQUIRED_SCOPE` | `connector.required_scope` | string |
| `FORGD_CONNECTOR_ALLOWED_ORIGINS` | `connector.allowed_origins` | JSON array |
| `FORGD_CONNECTOR_AUTH_MODE` | `connector.auth.mode` | string |
| `FORGD_CONNECTOR_ISSUER` | `connector.auth.issuer` | string |
| `FORGD_CONNECTOR_JWKS_URL` | `connector.auth.jwks_url` | string |
| `FORGD_CONNECTOR_AUDIENCE` | `connector.auth.audience` | JSON array |
| `FORGD_CONNECTOR_ISSUERS` | `connector.auth.issuers` | JSON array |
| `FORGD_CONNECTOR_GROUPS_CLAIM` | `connector.auth.groups_claim` | string |
| `FORGD_OVERRIDES_VERIFY_KEY` | `overrides.verify_keys` | comma-separated list |

A coerced value is still validated where it is read. `server.mode` must be
`observe`, `enforce` or `archive`, and `scan.budget_ms` must be at least 1.

**`detectors`, `privacy` and `plugins` are never environment-tunable.** No
variable reaches a path under them, or any path segment named `severity`.
Detection behaviour changes only by editing the policy. The test suite
fails if an environment variable can reach any of them or a detector's
severity, if the `ENV_OVERRIDES` table can be modified, or if a plugin that rebinds it is
accepted.

`FORGD_VERDICT_POLICY`, which picks the file, and variables such as
`FORGD_OVERRIDES_ENABLED` and `FORGD_OVERRIDES_SIGNING_KEY` are read by the
code directly. They change no policy value and are not in this table.

## `hook.on_error`

`hook.on_error` is `allow` in the built-in defaults and in the shipped
`policy.yaml`. It decides what the Claude Code hook does when it cannot
reach a verdict:

- **The scan fails.** `block` exits 2, which blocks. `allow` exits 1,
  which Claude Code treats as a non-blocking error, and the prompt or tool
  call proceeds unscanned.
- **The policy file exists and does not load.** It does not parse, its
  top level is not a mapping, `plugins` is invalid, or an environment
  override fails its coercion. The hook does not scan. It takes `on_error`
  from the file when the file parses to a mapping, and the built-in
  `allow` otherwise, then exits as above. stderr reads `forgd-verdict:
  could not load policy <path>: <error type and position>`, and the text
  of the failing line is withheld.
- **The hook does not decide within `hook.watchdog_ms`** (default 8000,
  measured from the hook's start, and refused at 10000 or more, Claude
  Code's hook timeout in the shipped settings). `block` exits 2. `allow`
  exits 0 with a top-level `systemMessage` saying the scan did not finish,
  and the prompt or tool call proceeds unscanned. Nothing is spooled.
- **The payload does not parse.** It is not JSON, not a JSON object,
  empty, or not UTF-8. The hook does not scan and exits as above. stderr
  reads `forgd-verdict: could not parse hook payload: <reason>`, which
  names the error and its position and never the payload.
- **gitleaks (T1) does not run.** gitleaks is enabled and there is no
  absolute `binary`, the binary does not exist, or it times out or fails
  during the scan. The hook says so on stderr and in a top-level
  `systemMessage`. `block` blocks, with a reason saying the request could
  not be checked; `allow` decides on the other detectors.

With no policy file, meaning a `--policy` path that does not exist or no
`--policy` at all, the hook scans on the built-in defaults. It
warns on stderr and, because Claude Code does not show stderr on exit 0,
in a top-level `systemMessage`: alone on a clean scan, merged into the
block object on a deny. The message names the path, or says none was
given, and says `hook.on_error` is `allow` on the defaults, so a scan that
fails lets the prompt or tool call through.

## Failing closed

[`examples/policy/enforce.yaml`](../examples/policy/enforce.yaml) is a
policy that fails closed. It sets `server.mode: enforce`,
`server.on_tier_dropped: deny` and `hook.on_error: block`.
`on_tier_dropped` takes `allow` or `deny`, and `hook.on_error` takes
`allow` or `block`.

`on_tier_dropped` governs a tier the budget dropped or that failed. It
does not govern text left unscanned for size: a value over the size limit
records `unscanned:oversize`, and a scan that stopped at 30,000 units
records `unscanned:capped`. Either denies whenever the policy has a
`block` detector, under `allow` as well as `deny`. Under `allow`, a
`block` finding in what was scanned is named in the deny reason; under
`deny`, the reason is the size limit. A scan that kept only 5,000
findings records `findings:capped`, which decides nothing under either
value: every unit was scanned and `block` findings are kept first.

The loader merges one file over the built-in defaults, not over the
shipped `policy.yaml`. The example is therefore a whole policy, and what
it does not set comes from the built-in defaults. To keep the shipped
tuning, set the same three keys in your copy of `policy.yaml` instead.

## URLs that carry a credential

Each URL below carries a credential, or serves the keys a credential is
verified against. It must be `https://`; `http://` is accepted only to a
loopback host (`localhost`, `127.0.0.0/8`, `::1`), for a local fake or a
sidecar. Anything else is refused at start, before a request is made.

| Key | Carries | Refused by |
|---|---|---|
| `compliance.base_url` | the Compliance Access Key | the ingest job, for that org; userinfo is refused too |
| `managed_agents.base_url` | each workspace's API key | the ingest job, for that workspace; userinfo is refused too |
| `dashboard.auth.jwks_url`, `dashboard.auth.issuers[].jwks_url` | the keys every sign-in token is verified against | the dashboard, at policy load |
| `connector.auth.jwks_url`, `connector.auth.issuers[].jwks_url` | the keys every connector token is verified against | the connector, at policy load |
| `sinks[].endpoint` | the sink's `token` as a bearer, userinfo in the URL, or an Azure Monitor managed-identity token | the service, at start. A sink with no token and no userinfo may still use `http://`, for an in-cluster collector |
| `server.store` as an Azure Blob URL | the service identity's token | every service that opens the store |
| `hook.ship_endpoint`, `hook.scan_endpoint` | the intake token | the hook, before each send |

The Compliance, Managed Agents, hook and sink clients follow no redirect:
a 3xx is a failed request, and the credential is not sent to the
`Location` host. The signing-key fetches send no credential. `dashboard.auth.issuer`
and `otel.cors_origins` are compared, never fetched, and carry nothing.

## `forgd-verdict policy`

```bash
forgd-verdict --policy policy.yaml policy
```

This prints the effective policy as JSON: the file merged over the
defaults, with the environment overrides applied, redacted as described
above. It refuses what loading the policy refuses on a service:
`hook.enabled_events` naming an event the hook does not handle, for one,
exits 2 with the reason on stderr. The hook on a laptop only warns about
such an event and drops it. Printing does not start a service or make the
checks a service makes at startup, so a setting that stops a service, such
as a missing `stripped_by`, still prints. `--check` makes them.

### Checking a policy before a roll

```bash
pip install 'forgd-verdict==<version>'
forgd-verdict policy --check --policy policy.yaml
```

`--check` builds each role from the policy the way its entry point does,
then closes it without serving, and reports every role that would refuse
to start. It exits 0, printing `ok: <path>: <roles>`, or 2 with one line
per refusal on stderr. The roles' startup warnings are printed too:

```
forgd-verdict policy: policy.yaml: collector: ValueError: otel.orgs entry 'primary' has a token but no id. ...
```

Install the version you are about to roll: the check is that release's
roles. It refuses what they refuse at start, among them:

- a `$FORGD_ORG_ID_<NAME>` that resolves to nothing where it is required,
  which is where its org's otel token, intake fleet token or compliance
  key is set;
- a detector setting that does not parse, or an enabled detector that is
  neither built in nor an allowlisted plugin;
- a weak or repeated token, a sink endpoint whose token is unset or that
  would send it in the clear, a store URL carrying credentials;
- dashboard auth, entitlements, admins and branding that do not parse, and
  an enabled connector that is not configured;
- a missing hash salt, where the role requires one.

It also refuses a top-level key that is not one of the sections above.
The roles ignore such a key, so a misspelt section would otherwise be
silently absent.

The roles checked are the verdict server, collector, intake and
dashboard, the connector when `connector.enabled` is true, and the
Compliance API scanner when `compliance` names an org. `--role` (repeatable)
checks only those named. Intake builds its detectors on its first scan
rather than at start; the check builds them, and refuses intake when they
would fail.

Some things only the running environment decides, and the check does not
look at them:

- whether a detector can run there. Every enabled detector is built, but
  no gitleaks binary or daemon, model or plugin `available()` is asked, and
  the tiers above T0 do not scan. The collector's guard on sink metadata
  runs the T0 tiers alone;
- whether the store accepts the role's identity. Each role writes to a
  local store in a temporary directory, after its configured spec has been
  checked as `open_store` checks it;
- the value of every `$VAR` the deployment sets. A reference unset here is
  checked as unset, which is how the role treats it: an otel org whose
  token is unset is skipped, so its id is not checked. Run it with the
  variables set, to placeholders where they are secrets, each token
  distinct, since a token two entries share is refused.

The messages are the ones the role prints when it refuses, so they can
name a value from the environment. A parser error is described by its line
and column only.

With no `--policy`, `$FORGD_VERDICT_POLICY` unset and no `./policy.yaml`,
it prints the built-in defaults with the environment overrides applied. A
named path that does not exist exits 2 with the one-line message above.

Run either form on the machine or in the container whose environment you
want to check: overrides and secret resolution are read from the shell it
runs in.

## Runtime overrides

A signed-in dashboard admin can change `server.mode`, exclusions and the
statistics reset while services run. The change is stored, signed and
audited in the findings store, and it applies on top of both the file and
the environment:

```
policy.yaml  <  ENV_OVERRIDES  <  runtime overrides
```

An environment override is set per service and needs a restart. A
runtime override is read from the store by the running services that use
that setting, without a restart. See [OVERRIDES.md](OVERRIDES.md).
