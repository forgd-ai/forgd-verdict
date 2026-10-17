# Security model

What forgd-verdict can stop, what it only records, who it trusts and how,
and what happens when a part of it fails. The detection rules themselves
are in [DETECTORS.md](DETECTORS.md), and how matched content is kept out
of everything it writes is in [PRIVACY.md](PRIVACY.md).

## What can block, and what only detects

Two adapters sit in the path of a request and can stop it. The rest see
data after the work has happened, so their findings arrive after the fact
and nothing they find can be prevented.

| Adapter | Can block | Blocks when |
|---|---|---|
| 1, the verdict server (Inference hooks) | yes | `server.mode` is `enforce` and a `block` finding is made. In `observe`, the shipped mode, and in `archive`, every request is allowed and the deny is recorded as `shadow_action` |
| 2, the Claude Code hook | yes | a `block` finding is made, on the events in `hook.enabled_events`. `server.mode` does not apply to it, whether it scans locally or through the intake's `/scan` |
| 3, the Compliance API scanner | no | — |
| 4, the OTel collector | no | — |
| 5, the outbound sink | no | it forwards a redacted copy of what the collector received |
| 6, the Managed Agents scanner | no | — |

**The hook is a control only when it is managed.** Installed by MDM in
the highest-ranked managed source the organization deploys, a developer
cannot remove it. Installed in a project's or a user's
`.claude/settings.json`, a developer who can edit that file can remove
it, so it is advisory. See [deploy/MDM.md](../deploy/MDM.md).

**The hook decides even when the network is down.** With remote scanning
configured, any failure to reach `/scan` (a timeout, a non-2xx, a DNS
failure) falls back to a local scan, and says so on stderr. A hook that
Claude Code kills at its own timeout lets the prompt through unscanned,
which is why `hook.scan_timeout_ms` is capped at 5000, half the 10 s hook
timeout in every shipped config, and why `hook.watchdog_ms` (default 8000,
refused at 10000 or more) ends any hook run still going by then under
`hook.on_error`. From Claude Code 2.1.295 a hook entry with
`"onFailure": "block"` makes Claude Code block the prompt when the hook
fails, times out or cannot start; the shipped managed-settings fragments
do not set it. On Windows the watchdog cannot interrupt C code that holds
the GIL; see [the hook's threat model](#the-claude-code-hooks-threat-model).

**The hook does not see what a slash command or MCP prompt expands to.**
`UserPromptExpansion` carries `expansion_type`, `command_name`,
`command_args`, `command_source` and the original `prompt`, and no
expanded content. The hook scans `prompt` and `command_args`. Text that a
skill, a command file or an MCP prompt adds on expansion reaches the model
without adapter 2 scanning it.
`hook.expansions` narrows this by refusing expansions by `command_source`,
`expansion_type` or `command_name`: a match in `deny` blocks, then a match
in `allow` passes, then `default` decides. The default is `allow`, so a
deployment that sets nothing has this gap. The deny reason names the
command and nothing else, and no environment variable, project setting or
runtime override can change the section.

**The hook does not see a file attached with an `@` file reference.** The
hook receives the prompt as typed. Content Claude Code attaches from an
`@` file reference, without a Read tool call, does not pass through the
hook, so adapter 2 does not scan it. With `OTEL_LOG_RAW_API_BODIES=1`,
adapter 4 receives the full Messages API request and scans it after the
fact ([PLATFORM.md § Adapter 4](PLATFORM.md#adapter-4--otel-collector)).
Managed `permissions.deny` `Read(...)` rules keep sensitive paths from
Claude's file reads; Claude Code's permissions documentation says it makes
a best-effort attempt to apply them to `@` file mentions too. See
[deploy/MDM.md](../deploy/MDM.md#keeping-sensitive-files-out-of-claudes-reads).

**Before Claude Code 2.1.302, a blocked prompt could still leave the
machine in a session-title request.** In Agent SDK session mode, Claude Code
2.1.280 sent the first prompt to a `generate_session_title` request in
parallel with `UserPromptSubmit`, and a block from the hook did not recall
it. With 2.1.302 the title request waits for the hook and a block stops it.
`claude -p` generates no title. On an older release, adapter 2 stops a
prompt from being answered and does not guarantee it never reaches
Anthropic. See
[PLATFORM.md § Adapter 2](PLATFORM.md#adapter-2--claude-code-hook-cli).

**The behavioural checks read the transcript's text.** The operator
envelope compares each call's tool, programs, hosts and path classes with
the operator's list. A program on the list that runs code (`python -c`, a
project script, `make`) can run anything, a symlink, alias or shell
function is not resolved, and an agent set on leaving the envelope can do
so through any of these. The injection detector matches patterns in tool
results and attachments, and text written to avoid them is not found. Both
record drift for review; neither is a sandbox
([SERVER.md](SERVER.md#behavioural-checks)).

## The Claude Code hook's threat model

The hook runs on the developer's machine, as the developer, in the
environment Claude Code starts it with. That environment includes the `env`
block of the project's `.claude/settings.json`, so a repository the
developer opens can set variables the hook's process sees. This section
says what a managed install of the shipped fragments withstands and what it
does not.

A finding inside a residual listed here is a documented limitation. A
finding outside the list is a defect.

### Strong against

A careless developer, and a project's settings or environment reaching the
hook through anything that acts inside the Python process after it starts:

- **`env -i` on POSIX.** The macOS and Linux fragment runs
  `/usr/bin/env -i /opt/forgd/venv/bin/python -I -X forgd_verdict_hook -m forgd_verdict.cli`,
  so the interpreter starts with an empty environment. `-I` makes Python
  ignore `PYTHON*` variables and the user site directory.
- **The import-time scrub on Windows.** With `-X forgd_verdict_hook`, which
  only the command line can set, the first statement of
  `forgd_verdict/__init__.py` removes the variables OpenSSL reads before
  anything imports it: `OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_ENGINES`
  and every other `OPENSSL_` or `OSSL_` name, `SSL_CERT_FILE`,
  `SSL_CERT_DIR`, `CTLOG_FILE`, `QLOGDIR` and `SSLKEYLOGFILE`
  (`forgd_verdict/_hookenv.py`). Both fragments pass the marker. A process
  started without it, such as the verdict server or the admin CLI, keeps
  them.
- **An absolute gitleaks binary.** The hook runs gitleaks only from an
  absolute `binary` in its profile, `hook.detectors.gitleaks.binary` or
  `detectors.gitleaks.binary`, and does not look it up on `PATH`.
- **An allowlisted gitleaks environment.** gitleaks gets `SYSTEMROOT` and
  nothing else from the hook's environment, a pinned `--config`,
  `--ignore-gitleaks-allow`, and a fresh empty directory as its working
  directory and `.gitleaksignore` location.
- **No policy or spool from the environment or the working directory.**
  The hook and `hook-ship` read only `--policy`. The spool and the device
  salt are placed from the policy file, and on POSIX from the password
  database. `FORGD_VERDICT_*` variables and `$VAR` placeholders in the
  `hook` section apply only with `hook.project_overrides: true`. The scan
  and ship endpoints ignore proxy variables and `SSL_CERT_*`.
- **The SIGALRM watchdog on POSIX.** `hook.watchdog_ms` arms a SIGALRM
  timer. Its handler runs on the main thread, including from C code that
  checks for signals such as `_sre` matching, and ends the run under
  `hook.on_error` before Claude Code's timeout.
- **A gitleaks that fails during the scan follows `hook.on_error`.** A
  timeout, a failed exit or a report that does not parse is reported on
  stderr and in the session, and `block` blocks. The same holds on
  `hook.scan_endpoint`: the intake names a gitleaks that failed, or that it
  could not build, in `tiers_dropped`, and the hook applies `on_error` to
  it. The hook sends its `on_error` as `x-forgd-on-error`, and under `block`
  the intake records the deny the hook enforces.
- **A remote store from a Windows hook needs `hook.project_overrides:
  true`.** A store's SDK takes its endpoint and credentials from the
  environment. A remote `hook.ship_store` needs the setting on every
  platform, and a remote `--store` on the command line needs it in a
  Windows hook process.

### Best effort against

A hostile repository on the same machine, whose `.claude/settings.json` is
written to defeat the hook. These residuals are accepted:

- **Anything that acts before the interpreter runs.**
  - Linux: `LD_PRELOAD` and `LD_LIBRARY_PATH` reach `/usr/bin/env` itself,
    which Claude Code starts with the project's environment, before
    `env -i` clears it.
  - macOS: with SIP on, `DYLD_*` variables are removed when `/usr/bin/env`
    starts, so they reach neither `env` nor the interpreter. With SIP off
    they reach `env`.
  - Windows: the loader's and DLL search order's variables,
    `__COMPAT_LAYER`, and `PYLAUNCHER_DEBUG`, which the venv's `python.exe`
    launcher reads.
  - Every platform: a venv or base interpreter a user can write, when step
    1 of [deploy/MDM.md](../deploy/MDM.md#what-has-to-land-on-the-machine)
    was skipped.
- **`PYTHONEXECUTABLE` on Windows.** CPython's path configuration reads it
  even under `-I` and uses it as `sys.executable`. That decides
  `sys.prefix`, and so which `pyvenv.cfg` is read and whose site-packages
  `.pth` files run, before the package's first statement (upstream
  gh-91057, gh-133525). A project can point it at a directory it controls
  and run code in the hook. On POSIX `env -i` removes it.
- **`MIMALLOC_*` and `TZ`, read before the scrub.** `MIMALLOC_*` is read
  when `python313.dll` loads and can print to stderr or reserve memory.
  `TZ` is read when `time` is imported at startup and changes local-time
  formatting only; every timestamp the hook writes is UTC. On POSIX
  `env -i` removes both.
- **Windows paths from the environment.** The home directory comes from
  `USERPROFILE`, then `HOMEDRIVE` and `HOMEPATH`, so a project can move the
  default spool and the device salt; an absolute `hook.spool` in the policy
  places both. `SystemRoot` is read from the environment and not reset, and
  Winsock expands it in its provider path (CPython gh-118234). `TEMP` and
  `TMP` decide where gitleaks' fresh working directory is created.
- **C code that never checks for signals.** The SIGALRM handler runs when
  C code returns or checks for signals. A C extension loop that does
  neither outlasts the watchdog.
- **Windows has no SIGALRM.** The watchdog there is a `threading.Timer`,
  which needs the GIL to fire, so C code that holds it, such as `_sre`
  backtracking on prompt text, runs until Claude Code's `timeout`. Claude
  Code treats that as a non-blocking error and the prompt goes through
  unscanned: it fails open.
- **A user with local admin** can change the venv, the policy, the managed
  settings and the gitleaks binary.

### The controls the hook cannot undermine

The verdict server (adapter 1) is called by Anthropic for every governed
prompt in a Claude Enterprise organization, Claude Code's included, and
nothing on the laptop is in that path. The Compliance API scanner
(adapter 3) reads Anthropic's own record of what was sent, after the fact.
Where the machine itself is the threat (a hostile repository on Windows, a
developer with local admin, or a machine without the managed fragments),
rely on adapter 1 in `enforce` to block and on adapter 3 for the evidence.
The hook still covers what only it sees: a tool call on the laptop before
it runs, and a scan when the network is down.

## Trust boundaries

| From | To | Authenticated by | Can |
|---|---|---|---|
| Anthropic | verdict server | a Standard Webhooks signature over the raw body with the signing secret; optionally static headers in `server.required_headers` as well | submit a frame for a verdict |
| Anthropic | collector | a per-org bearer token, which also decides the org a batch is filed under | submit OTLP logs and traces |
| a laptop in a managed fleet | intake | the fleet's bearer token, shared by every laptop in it, scoped to `intake`, `scan` or both; the device id in `X-Forgd-Device` is the laptop's claim and is not authenticated | append adapter-2 records, or ask `/scan` for a verdict. Neither route reads findings |
| an agent you build, or a laptop outside a fleet | intake | a per-client bearer token, scoped the same way | the same |
| a laptop with a device certificate | intake | each request signed with the device's key, over the route, the time and the body's SHA-256, with a certificate that chains to a CA in `intake.devices[].ca_file` and carries its EKU; the device id is the certificate's | the same |
| a person | dashboard | the mode in `dashboard.auth`: `oidc_jwt`, `trusted_header` behind a proxy that strips the header, or `none`, which binds only loopback unless `--serve-open` is passed (`FORGD_DASHBOARD_SERVE_OPEN=true` in the image, `dashboard.serveOpen` in the chart) | read findings, and with admins configured, change the runtime overrides |
| dashboard, connector | store | the reader identity | read findings |

**The collector cross-checks the org.** The token is what the deployment
issued, and `organization.id` on the payload is only what the sender
claims. Every distinct `organization.id` in a batch is compared with the
token's org id, and a batch with any mismatch is refused with 403. Records
are filed under the token's org, never the claimed one. With
`otel.orgs[].id` empty the comparison has nothing to compare against, and
any org's batch would be accepted on that token. So the collector refuses
to start when an entry has a token and no id, and the Helm chart refuses
to render one.

**The intake cannot be used to read.** It is append-only. A laptop token
appends adapter-2 records and asks `/scan` for verdicts, and nothing else.
A token used on a route it is not scoped to gets 403, a denied device 403,
and an unknown token 401. Without the intake, every laptop that ships
findings would need write access to the store itself.

**A device certificate names the device, and protects it no better than a
per-device token.** The intake takes the device id from the certificate,
so a batch's device is the one the certificate names, not one the sender
chose. The hook reads the key from a file, and the developer it runs as can
read that file, so whoever copies it signs as that device until the
certificate expires or `overrides deny-device` refuses it. A signature
covers the route and the body and is refused more than `max_skew_s` from
the intake's clock; a copy replayed inside that window is filed again,
under the same device, except that one intake replica answers a repeat of
the same batch from its record of what landed. No CRL or OCSP response is
fetched.

**A fleet token is shared, so it leaks with any one laptop.** Whoever holds
it can write records into the fleet's org and cannot read any. Those
records can carry a device id of the writer's choosing, including another
laptop's, so a record's device id says which laptop the sender claimed to
be. The intake
binds the org, the client name and the receipt time itself, and refuses
any record that claims another source. It sets the surface from the
credential, `claude-code-local` or `agent:<name>`. A shipped `actor_hash`
is kept only in the hook's pseudonym shape, and is stored rebound to the
credential as `hookuser_…`, so no sender can write a value a server-side
writer or another credential produces. The session id, request id, model
and build are kept only within a fixed character set and length. A
`reference_id` is kept only in the form the hook mints, a finding's
locator only in the form the hook's scan produces, and its digest only as
a SHA-256 hex digest; any other locator or digest is stored as a salted
digest of what was sent.

**Readers rank a token's records below an adapter's.** A record shipped
with a fleet or client token can carry a real deny's `reference_id` or a
real session id. The connector's `record` tool returns the inference
hook's verdict, then the other adapters', ahead of a Code hook or agent
check record, and labels each `writer: intake_token` or `adapter`; its
`reconciliation` joins Activity Feed denials to inference-hook verdicts
only. The headline deny rate on the dashboard, `/api/summary` and the
connector is the inference hook's, and `null` ("no adapter data" on the
dashboard) when the inference hook evaluated nothing in scope; Code hook
decisions and agent checks, which a token holder can send in any number,
are counted under `intake_token` with their own rate, also `null` when
there are none, and token-only surfaces are listed
after the others. The per-client record counts on the intake's `/stats`
(`by_client`) show a token sending far more than its fleet would. MDM rotates the token across the
fleet with an overlap ([deploy/MDM.md](../deploy/MDM.md#rotating-it)).
Denying a device cuts off a laptop running the managed hook and not
someone who has copied the token; that takes a rotation.

**A multi-org fleet's records are attributed by a join a laptop can
influence.** A fleet bound to several orgs (`intake.fleet[].orgs`) files
its records under `fleet-<name>`, and a reader attributes each one to the
org whose Claude Code OTel export carries the same session id. The laptop
chooses the session id it sends. The join is limited in three ways: only
records the collector wrote count, so a session id on a code-hook record
creates no join; only an org in that fleet's own list can be chosen, so a
laptop cannot file a record under an org its fleet is not bound to or make
a viewer of such an org see it; and a session id two orgs' exports both
carry joins neither. The join reads every org's OTel records whoever is
reading, so a session one viewer would attribute to their org is not
attributed differently because they cannot see the other claim. What
remains: a holder of the fleet token who also learns a session id another
developer's export carries, or who holds an OTel token for another org in
the fleet's list, can file records under that org. An OTel fleet token
(`otel.orgs[].ids`) is held by every laptop and accepts a claim of any org
in its `ids`, so with one, any laptop in the fleet can do this. Such a
holder can also push a victim's records back to org pending by making a second org's export name
the same session. The first is bounded by the fleet's own list, which is
the set of orgs its laptops already serve; the second costs visibility to
single-org viewers and never moves a record to a wrong org. The join is as
strong as the collector's org binding, which is why `otel.orgs[].id` must
be set.

**What denying a device holds against depends on where its salt is.** The
device id is a digest of the device salt.

- With `hook.device_salt_path` set to an MDM-provisioned file the user
  cannot rewrite, the id stays fixed for that machine. A denied laptop
  stays denied whoever signs in, and its user cannot get a new id by
  deleting a file. A provisioned file that is missing, malformed, or
  writable by the user, its group or others is refused: the hook sends no
  id, and with `require_device` (the default) the intake refuses that
  laptop's requests until the file is fixed.
- Without it, the salt is in the user's home directory. Deleting it gives
  the laptop a new id on its next request, so device deny holds only
  against a laptop whose user cooperates.

In both cases the id is what the laptop claims. Anyone holding the fleet
token can send any id, including another laptop's, or none where
`require_device: false`. Rotating the token is the control against a
copied one. A rotation also leaves the denylist naming devices that no
longer hold a token, so clear it afterwards with
`forgd-verdict overrides clear-devices`, and deny again any device that
should stay cut off.

**The unknown-device counts are per replica.** `device_first_seen` counts
each device id the first time one intake replica sees it, and
`device_missing` each fleet request with no usable id. Each replica counts
on its own, and there is no enrolment inventory to compare a device with,
so a never-seen id is counted and accepted.

**The Compliance Access Key and the Managed Agents keys stay in the ingest
job.** No internet-facing service holds them. A Compliance key with
`read:compliance_user_data` reads every chat, file, project and session in
every organization it covers, every linked organization for a
parent-scoped key ([which organizations a key reads](PLATFORM.md#which-organizations-a-compliance-access-key-reads)). A Managed Agents workspace key has no
documented read-only scope and can create and delete sessions. See
[CREDENTIALS.md](CREDENTIALS.md).

## No platform auth on the verdict server or the collector

Anthropic authenticates to the verdict server with a signature and to the
collector with an OTLP header. Neither can follow a login redirect. An
identity provider or platform auth in front of either service turns every
governed prompt, or every export, into a delivery failure before the
request reaches the app's own check. Only the dashboard sits behind
sign-in.

`scripts/verify_deployment.sh` fails a deployment on which an unsigned
request to the verdict server, or an unauthenticated export to the
collector, is redirected to a login page. It cannot tell an auth front end
that answers 401 from the app's own 401, so a passing run is not proof
that platform auth is off. See [DEPLOY.md § Verify the
deployment](DEPLOY.md#verify-the-deployment).

## Unsigned bodies on the verdict server

The signature covers the raw body, so the verdict server reads a body
before it can tell Anthropic from anyone else who can reach the hook URL.
The other services authenticate the caller from its headers before they
read a body; `tests/test_preauth_body_reads.py` lists every body read in
the code and fails on a new one until it is classified.

The defences: a byte budget across every unverified body,
`server.preauth_body_budget_bytes` (256 MiB), past which a request is
answered 503 without its body being read; a per-body cap,
`server.max_body_bytes` (64 MiB); a read timeout,
`server.body_read_timeout_s` (15 s); and uvicorn's
`server.limit_concurrency` (1024). With the shipped 2 GiB limit, unsigned
callers cannot run the process out of memory. `/metrics` counts the
refusals as `preauth_budget_exhausted` and `body_timeout` and reports the
budget's use under `preauth_body`. See [SERVER.md §
Memory](SERVER.md#memory).

The residual: a caller who sends real bytes fast enough to keep the budget
full, 256 MiB every 15 seconds with the shipped settings, makes every
governed prompt in that window a webhook failure, decided by the org's
failure handling; under *Allow the request* those prompts reach the model
ungoverned, and sustained failures trip the circuit breaker. A source
allowlist on Anthropic's Inference hooks egress range at the proxy removes
it, and is the recommended hardening: `ingress.hook.sourceRanges` in the
chart, the `@not_anthropic` matcher in `deploy/Caddyfile`. It ships off
because the range can change, and a stale list fails every governed
prompt.

## How each part fails

| Situation | Behaviour | Setting and default |
|---|---|---|
| no signing secret resolves | the verdict server starts, logs an error, and answers every hook request with 503 | `server.secrets` |
| a signing secret resolves but does not decode to a key | the verdict server logs an error at startup and answers every hook request with 401 | `server.secrets` |
| an unsigned or wrongly signed request | 401 | `server.require_signature: true` |
| a hook request arriving while unverified bodies already hold the pre-auth budget, or one declaring a `content-length` the budget has no room for | 503 `busy` with `Retry-After`, without the body being read; a body that fills the budget partway is refused the same way. A webhook failure, decided by the org's failure handling | `server.preauth_body_budget_bytes: 268435456` |
| a hook body that has not arrived in time | 503 `body_timeout` | `server.body_read_timeout_s: 15` |
| a signed frame whose `type` is not `prompt`, or has none | scanned whole, outside the envelope fields, and decided like a prompt: a `block` finding denies in `enforce`. A scan error follows `on_internal_error` | — |
| an internal scan error on the verdict server | in `observe` and `archive`, allow. In `enforce`, `fail` returns a 500 so the org's own failure handling in Anthropic decides; `allow` allows | `server.on_internal_error: fail` |
| a session flag cannot be read (`behaviour.flags`), or the judge or the tool baseline fails on a session | the frame is decided without the flag, and the session is not flagged by the check that failed: both fail open. A judge answer that does not fit its tool schema flags nothing. A failure is logged as `session flag check failed`, on the verdict server at most once a minute with the count of failed reads. A baseline that cannot be read is left as it was | — |
| a blocking tier did not run, because the budget dropped it or it failed | `allow` decides on the tiers that ran; `deny` denies and names the tier. The stored row records `tiers_dropped` either way | `server.on_tier_dropped: allow` |
| the behavioural checks (`provenance`, `taint`, `envelope`) stopped at their time limit or raised, on the verdict server, the intake's frame `/scan`, or the Compliance and Managed Agents scanners | the checks that did not finish are added to `tiers_dropped`, and `on_tier_dropped` applies to them as to any tier: `deny` denies when one is at `block`. A session's next frame resumes where the pass stopped. The verdict server counts `provenance_cut_short` or `provenance_error`, the intake `behaviour_cut_short` or `behaviour_error` | 250 ms per frame, or what is left of `scan.budget_ms`; 5 s per session on the post-hoc scanners. Not configurable |
| a value over the scan size limit: 4,194,304 characters per block on adapters 1, 2, 3 and 6, 1,000,000 per attribute on adapter 4 | the first 4,194,304 (or 1,000,000) characters and the last eighth of that are scanned, and the middle is not. `unscanned:oversize` is added to `tiers_dropped` and denies whenever the policy has a `block` detector, under either `on_tier_dropped`. Under `on_tier_dropped: allow`, a `block` finding in what was scanned is named in the deny reason; under `deny`, the reason is the size limit; with none, the reason says part of the request is over the size limit. `/metrics` on the verdict server and `/stats` on the collector count it as `oversize_unscanned` | not configurable |
| more than 30,000 scan units in one request, hook payload or OTel turn (`MAX_SCAN_UNITS`). Each string and each number is a unit, so 60 KB of `[0,0,…]` reaches the cap | the last 30,000 units are scanned and the earlier ones are not. On the hook, `command`, `content`, `new_string`, `file_text`, `prompt` and `query` are always among them. `unscanned:capped` is added to `tiers_dropped` and denies whenever the policy has a `block` detector, under either `on_tier_dropped`. Under `on_tier_dropped: allow`, a `block` finding in what was scanned is named in the deny reason; under `deny`, the reason is the size limit; with none, the reason says part of the request is over the size limit. `/metrics` and `/stats` count it as `oversize_unscanned` | not configurable |
| more than 5,000 findings in one scan (`MAX_SCAN_FINDINGS`) | every unit is scanned, and 5,000 findings are kept, `block` findings first. `findings:capped` is added to `tiers_dropped` and decides nothing: the kept findings decide, under either `on_tier_dropped`. A sink that redacts masks every value of the group whole | not configurable |
| a claude.ai chat listed with `deleted_at` (adapter 3) | its messages are fetched and scanned while the API still serves them. When the fetch answers 404, or no messages come back, the record carries `deleted_at`, `unscanned:deleted` in `tiers_dropped` and no message counts, the dashboard shows it as `deleted` with its messages "not read", and the summary counts it under "Deleted before read". Under `on_tier_dropped: deny` it is a `deny` whenever the policy has a `block` detector. Any other failed fetch holds the chat cursor, so the next pass lists the chat again | `server.on_tier_dropped: allow` |
| a chat artifact listed with no `version_id` (adapter 3) | inline `content` on the entry is scanned. With none, the artifact counts in `artifacts_failed` and `unscanned:artifact` is added, as for an artifact whose fetch failed | — |
| a Managed Agents history that could not be paged to its end (adapter 6) | the events read are scanned, `unscanned:partial` is added to `tiers_dropped`, and the summary counts it under "Histories read in part". Under `on_tier_dropped: deny` it is a `deny` whenever the policy has a `block` detector | `server.on_tier_dropped: allow` |
| one session or chat observed by several passes (adapters 3 and 6) | the summary, the reconciliation and the connector's `record` tool keep one observation per session: the one with a `block` finding, then any finding, then content read at all, then the whole history read, then the most messages, then the latest. A later pass that read less, such as a chat deleted after a detection, never replaces an earlier detection; the kept record carries the later `deleted_at`. The window applies before this choice. Every observation stays in the store and the event log | not configurable |
| `compliance.base_url` or `managed_agents.base_url` is not `https://`, or carries userinfo | the ingest job refuses that org or workspace, since the Access Key or API key goes with every request; `http://` is accepted for a loopback host only. An `https://` host other than `api.anthropic.com` is logged as a warning naming the host | `https://api.anthropic.com` |
| the Compliance or Managed Agents API answers with a redirect | the request fails with the 3xx status and the key is not sent to the `Location` host; the item is counted as failed and holds its cursor. Ids from a listing are percent-encoded into one path segment, and an id that is empty, `.` or `..` is an item that could not be read. The Azure lockout evidence fetch and a proxied sink also follow no redirect | — |
| a gitleaks timeout, crash or bad config | the tier is recorded as skipped and `on_tier_dropped` applies. Under the shipped `allow`, a secret only gitleaks would catch gets through. In the Claude Code hook it is reported on stderr and in the session, and `hook.on_error` applies: `block` blocks | `hook.on_error` in the hook |
| an identity or metadata value (request id, session id, model, service name) that only gitleaks recognises | the value is replaced before it is written where gitleaks runs as a daemon, and on the laptop hook's spool and the Compliance and Managed Agents ingest jobs, which call the gitleaks subprocess once per record and replace every value of the record if that call fails. Any other service whose gitleaks runs as a subprocess checks with the T0 detectors only and writes the value as it is. See [PRIVACY.md](PRIVACY.md) | `detectors.gitleaks.daemon` |
| a configured gitleaks daemon that dies mid-run | a scan error, not a skipped tier, so `on_internal_error` applies: a 500 in `enforce` with the shipped `fail` | — |
| a configured gitleaks daemon unreachable at startup | the service refuses to start; `/livez` answers 503 while it is down | `detectors.gitleaks.daemon` |
| a `detectors.gitleaks.config` the gitleaks daemon did not load | the container refuses to start, naming both paths. Each role runs its own daemon and compares only the profiles it builds: `server` the server profile, `collect` the `otel` profile, `intake` the server and hook profiles, which must agree. An app whose daemon was started some other way refuses to build its detectors | `detectors.gitleaks.config`, `FORGD_GITLEAKS_CONFIG` |
| the hook's scan crashes | `allow` exits non-zero without a decision, which Claude Code treats as a non-blocking error; `block` exits 2, which blocks. stderr names the exception type only | `hook.on_error`: `allow` in the built-in defaults and the shipped `policy.yaml` |
| the hook's policy file exists and does not load: it does not parse, its top level is not a mapping, `plugins` is invalid, or an environment override fails its coercion | no scan. `on_error` comes from the file when it parses to a mapping, otherwise the built-in `allow`; `block` exits 2, which blocks, and `allow` is a non-blocking error. stderr names the path and the error type, never the text | `hook.on_error: allow` |
| the hook has no policy file: a `--policy` path that does not exist, or no `--policy`. The hook and `hook-ship` read neither `FORGD_VERDICT_POLICY` nor `./policy.yaml` | scans on the built-in defaults and warns on stderr and in a top-level `systemMessage`. The warning says `hook.on_error` is `allow` there, so a scan that fails lets the prompt or tool call through | `hook.on_error: allow` |
| the hook payload does not parse, is not a JSON object, is empty, or is not UTF-8 | `block` exits 2, which blocks; `allow` is a non-blocking error. stderr names the error and its position, never the text | `hook.on_error: allow` |
| runtime overrides cannot be confirmed | `/readyz` answers 503 on the verdict server, collector, intake, dashboard and connector. The verdict server answers each signed hook request with 500 in every mode, `observe` included, unless `server.on_internal_error` is `allow`, when it allows. The collector and the intake refuse with 503 | see [OVERRIDES.md § Readiness](OVERRIDES.md#readiness) |
| `server.store` is an unresolved `$VAR` | the verdict server refuses to start | `server.store` |
| `server.store: ""` | the verdict server runs with no durable store and records nothing | `server.store` |
| `privacy.hash_salt` empty | the verdict server, the collector, the intake and both ingest jobs refuse to start, with or without a store, unless the policy file sets `privacy.allow_unsalted: true`. `forgd-verdict scan` runs, hashing with a random per-run key, and says so on stderr | `privacy.hash_salt` |
| a policy file named by `--policy` or `FORGD_VERDICT_POLICY` does not exist | the verdict server, collector, intake, dashboard, connector, `ingest` and the other CLI subcommands print one line naming the path and exit 2. The hook is in its own row above. A named file deleted under a running dashboard is an error on the Policy tab, and the tab does not show the defaults | — |
| no policy file is named and `./policy.yaml` does not exist | the built-in defaults load, with the environment overrides applied | — |

Two of these fail open by default, and both are choices a deployment can
change: `on_tier_dropped: allow` and `hook.on_error: allow`. A detector
that fails is not reported as a clean run: it is listed as skipped, on
the stored row and in the logs. A scan error on the verdict server is
logged and counted as `scan_error` on `/metrics`.

## What the chart refuses to do

The Helm chart refuses to render a configuration that would deploy and
run but silently weaken a guarantee:

- no hash salt, when the chart manages the secret;
- the dashboard given the writer identity;
- an OTel token with no org id beside it;
- no store URL, or no image repository;
- either half of the ingest image left to default, which would run without
  the Presidio tier and report a clean scan;
- TLS with neither an issuer nor a secret name;
- the verdict server or the collector scaled past one replica without
  acknowledging that their caches and queues are per-process;
- an `extraEnv` key naming a variable the chart wires from a Secret, such
  as `FORGD_HASH_SALT` or `FORGD_SINK_TOKEN_<NAME>`. `extraEnv` reaches
  every workload, so this is what keeps the salt off the dashboard and the
  connector;
- an `extraEnv` key naming a variable the chart sets or checks, such as
  `FORGD_DASHBOARD_AUTH_MODE`, or a cloud identity such as
  `AZURE_CLIENT_ID`. `extraEnv` is emitted after the chart's own entries
  and its copy would win;
- a literal sink token or shared header value in the policy, which would
  sit in the ConfigMap every workload mounts. The chart supplies each from
  its own Secret key to the one workload that reads it;
- `dashboard.serveOpen` while an Ingress routes the dashboard.

See [deploy/helm/README.md § What the chart refuses to
do](../deploy/helm/README.md#what-the-chart-refuses-to-do).

## Store identities

The findings store is reached through three identities, created by the
store modules. Which module attaches each one to which workload on each
target is in [DEPLOY.md § Where the identities come
from](DEPLOY.md#where-the-identities-come-from).

| Identity | Held by | Can |
|---|---|---|
| writer | verdict server, collector, intake, ingest job | write findings. On S3, neither role can delete an object or a version. On GCS it can delete everything under `state/` and the two marker objects, and nothing under `verdicts/` or `denials/`, and records are create-only. Without `control_enabled`, `state/` includes `state/runtime-overrides.json`. On Azure, with `control_enabled` it holds a custom role with no delete; without it, the built-in Storage Blob Data Contributor |
| reader | dashboard, connector | read findings, and nothing else |
| control | the dashboard, when dashboard admins are enabled | write the runtime overrides object and its audit records. With `control_enabled`, the writers lose write access to both |

The writer can write the two legacy marker objects, `markers/excluded_requests`
and `markers/stats_reset`. With runtime overrides off, the dashboard and
connector apply them as written, unaudited. With overrides on, a reader
applies them only while it holds an adopted overrides object that has not
retired them: a reader that has adopted none, before `overrides init` or
while it cannot confirm the object, applies neither, so its rates exclude
no frame and have no reset, and the Policy tab says so.

On Azure without `control_enabled`, the writer's Storage Blob Data
Contributor includes `Microsoft.Storage/storageAccounts/blobServices/containers/delete`,
so a compromised writer can delete the findings container and every blob in
it. Blob soft delete and versioning do not cover a container delete.
Container soft delete does: `store-azure` turns it on by default
(`container_delete_retention_days`, 30 days), and a deleted container can be
restored within that window and not after it. The `CanNotDelete` lock on the
storage account exists only with `control_enabled`, and then the writer's
custom role has no container delete.

The connector holds the reader identity only, never the writer or the
control identity. `cluster-aks` federates its service account to the
reader and refuses a control identity or a control service account equal
to the reader's or the connector's, and the chart refuses a connector
whose reader client id equals the writer's
(`deploy/terraform/modules/cluster-aks/main.tf`,
`deploy/helm/forgd-verdict/templates/serviceaccount.yaml`).

The dashboard is the one service a person signs into, so it never holds
the writer identity: a compromise there could otherwise rewrite the
evidence. It is never given the hash salt either, because it reads every
finding hash. See [Terraform README § Dashboard admins: the control
identity](../deploy/terraform/README.md#dashboard-admins-the-control-identity)
and [OVERRIDES.md](OVERRIDES.md).

**Never grant `delete:compliance_user_data` on a Compliance Access Key.**
Create the key with exactly `read:compliance_activities` and
`read:compliance_user_data`. Adapter 3's client makes only `GET` requests
(`compliance/client.py`), so the delete scope adds nothing it uses. A
leaked key with it could permanently delete chats, files and projects
across every organization it covers
([which organizations a key reads](PLATFORM.md#which-organizations-a-compliance-access-key-reads)). Scopes cannot be changed after
the key is created.
