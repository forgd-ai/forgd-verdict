# The detection platform

Everything in this repository that is not the verdict server: the adapters
that put the same scan core on control points the inference hook cannot
reach, the one that redacts what leaves for a SIEM, the append-only findings
store adapters 1, 2, 3, 4 and 6 write to, and the dashboard that reads it.
Adapter 1 and the scan core have their own reference in
[SERVER.md](SERVER.md); the Install section and the Configuration section,
which covers every adapter's block in `policy.yaml`, are there too.

`DESIGN.md` covers why the parts are shaped this way, `BENCH.md` holds
measured numbers, and `AGENT-BUILDERS.md` shows agents you build yourself
using the same `/scan` endpoint.

---

## Quick start

```bash
# Adapter 2 on a payload like Claude Code's. The hook reads only --policy.
echo '{"hook_event_name":"UserPromptSubmit","prompt":"key AKIAIOSFODNN7EXAMPLE"}' \
  | forgd-verdict hook --policy policy.yaml

# Adapter 3, auditing what already happened.
export ANTHROPIC_COMPLIANCE_ACCESS_KEY='sk-ant-api01-...'
forgd-verdict compliance sessions --family local --join
```

---

## Adapter 2 — Claude Code hook CLI

```jsonc
// .claude/settings.json, or the highest-ranked managed source — see deploy/MDM.md
{
  "hooks": {
    "UserPromptSubmit": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "/usr/bin/env", "args": ["-i", "/opt/forgd/venv/bin/python", "-I", "-X", "forgd_verdict_hook", "-m", "forgd_verdict.cli", "hook", "--policy", "/etc/forgd/policy.yaml"], "timeout": 10 }] }
    ],
    "UserPromptExpansion": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "/usr/bin/env", "args": ["-i", "/opt/forgd/venv/bin/python", "-I", "-X", "forgd_verdict_hook", "-m", "forgd_verdict.cli", "hook", "--policy", "/etc/forgd/policy.yaml"], "timeout": 10 }] }
    ],
    "PreToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "/usr/bin/env", "args": ["-i", "/opt/forgd/venv/bin/python", "-I", "-X", "forgd_verdict_hook", "-m", "forgd_verdict.cli", "hook", "--policy", "/etc/forgd/policy.yaml"], "timeout": 10 }] }
    ]
  }
}
```

`PreToolUse` matches every tool except `EndConversation`, MCP tools and
`WebFetch` included; `EndConversation` skips both PreToolUse and
PostToolUse. A matcher that names tools skips every tool it does not name,
including tools added to Claude Code later.

`command` + `args` is the exec form, which spawns the binary directly rather
than through a shell. `/usr/bin/env -i` starts the interpreter with an
empty environment, and `-X forgd_verdict_hook` makes the package remove the
variables OpenSSL reads before it loads, which is what covers Windows,
where the fragment has no `env -i`; see
[deploy/MDM.md](../deploy/MDM.md#what-has-to-land-on-the-machine). `UserPromptSubmit` defaults to a 30 s timeout for
`command` hooks rather than the 600 s most events get, because it blocks model
processing; the 10 s above is inside both.

Prefer an absolute path to the binary over a `PATH` lookup. A copied install
can serve a stale build, and a stale build of this hook allows prompts a
current one denies.

**The prompt text arrives in `prompt`.** `user_input` is also read, so a
rename in either direction cannot silently disarm the hook.

**Register every event in `hook.enabled_events`.** The policy decides what
the hook scans; the settings file decides what Claude Code calls it for.
`UserPromptExpansion` fires when a slash command or MCP prompt expands.
Without its registration its `prompt` and `command_args` reach the model
with no scan and `hook.expansions` cannot refuse it. The expanded content
is not in the payload either way. The test suite fails if the shipped fragment or this example
leaves out an event in the policy's list.

**A file attached with an `@` file reference is not scanned here.** The
hook receives the prompt as typed. Content Claude Code attaches from an
`@` file reference, without a Read tool call, does not pass through the
hook, so adapter 2 does not scan it. Managed `permissions.deny`
`Read(...)` rules keep sensitive paths from Claude's file reads, and
Claude Code applies them to `@` file mentions on a best-effort basis; see
[deploy/MDM.md](../deploy/MDM.md#keeping-sensitive-files-out-of-claudes-reads).

Reads the hook payload on stdin, runs the same core, and answers in the
current hook output contract. Events block in different shapes, and the
wrong one is not an error: it is valid JSON and exit 0, so the prompt or
call proceeds:

```json
// PreToolUse
{"hookSpecificOutput": {"hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": "..."}}

// UserPromptSubmit, UserPromptExpansion and PostToolUse -- top-level.
// `permissionDecision` is a PreToolUse concept and these events ignore it.
{"decision": "block", "reason": "..."}
```

`systemMessage`, used for warnings, is a universal top-level field, not
part of `hookSpecificOutput`. `hook.enabled_events` takes only these four events, plus `SessionEnd`,
which the hook handles without the list. The services and
`forgd-verdict policy` refuse a policy that names any other event; the
hook logs a warning naming it, drops it and scans the rest.

**On allow it prints nothing and exits 0.** Emitting
`permissionDecision: "allow"` would be wrong: for `PreToolUse` that
auto-approves the call and bypasses the normal permission flow, turning a DLP
scanner into a permission bypass. Silence means "no decision; normal
permission flow applies". A hook with no policy file still adds a
`systemMessage` saying it is scanning on the built-in defaults; see
[POLICY.md § `hook.on_error`](POLICY.md#hookon_error).

`shell_exfil` is a local-only detector class (curl/nc pipes with credential
paths, `env | curl`, `curl | sh`) at `warn` severity. Warnings surface via
`systemMessage`; they never block.

Hooks run synchronously in the developer's flow, so the budget is 200 ms.
Measured 57 ms median on a 10 KB prompt with T0+T1 including process start
(Apple silicon). T2 is off locally.

### Scanning on the service instead of the laptop

Set `hook.scan_endpoint` and `hook.scan_token` in the policy, and the hook
posts its payload to the intake service's `/scan` and uses the verdict that
comes back. On a managed laptop the token is the fleet token, written into
the root-owned `policy.yaml` by MDM; see
[deploy/MDM.md](../deploy/MDM.md#the-fleet-token). Where the hook is not a
managed control, a developer can instead set `FORGD_VERDICT_SCAN_ENDPOINT`
and `FORGD_VERDICT_SCAN_TOKEN` in their own `.claude/settings.local.json`,
which is not committed. The hook reads them only with
`hook.project_overrides: true` in the policy. The laptop then needs
no gitleaks binary, and there is one definition of a violation instead of
two. For a hook payload `/scan` builds the hook's profile, local-only
detectors such as `shell_exfil` included, so the rules are the ones the
laptop would apply, not the verdict server's.

```jsonc
"env": {
  "FORGD_VERDICT_SCAN_ENDPOINT": "https://intake.example.com/scan",
  "FORGD_VERDICT_SCAN_TOKEN": "<the fleet's intake token>"
}
```

The endpoint must be `https://`, or `http://` to a loopback address. A
redirect is refused and treated as a failure. Without
`hook.project_overrides: true`, the hook ignores an endpoint set in the
environment or written as a `$VAR` placeholder: a managed hook would
otherwise take its scanner from whichever repository the developer opened.
For the same reason the hook uses no proxy and ignores `SSL_CERT_FILE` and
`SSL_CERT_DIR`. It trusts `hook.ca_file` when set, else OpenSSL's built-in
CA locations.

A managed hook still runs in the developer's environment. Run it as the
example above does. `-I` stops Python reading `PYTHONPATH`, `PYTHONSTARTUP`
and the user site directory, any of which lets a repository run its own code
before the hook starts. `--policy` with a root-owned path stops the hook
reading `$FORGD_VERDICT_POLICY` or `./policy.yaml` from the project. Set
`hook.detectors.gitleaks.binary` to an absolute path. The hook does not
look gitleaks up on `PATH`, which the project's environment sets: with no
absolute `binary`, or one that does not exist, the hook does not run T1,
says so on stderr and follows `hook.on_error`.

**A failure is never a decision.** A timeout, a refused connection or an
error status falls back to the local scan, and says which on stderr:
`scan service unreachable (TimeoutError)` or `scan service answered 403`.
Claude Code routes hook stderr to its debug log, so a fallback does not show
in the UI; the reliable tell is the spool, which only the local path writes.

`hook.scan_timeout_ms` (default 1000, `FORGD_VERDICT_SCAN_TIMEOUT_MS`) is
separate from `budget_ms`, which bounds the local scan. Measure the round
trip from your developers to the intake region, including a cold DNS lookup
on a session's first prompt, before lowering it: a timeout below that sends
the first prompt of every session to the local fallback. It is capped at
5000 ms, half the 10 s hook timeout in every shipped config, because Claude
Code kills a hook that outlives its own timeout and the prompt goes through
unscanned.

`hook.watchdog_ms` (default 8000, no environment override) bounds the whole
hook run from its start: policy load, the remote wait and the local scan. A
hook still running then stops and follows `hook.on_error`, so a hung
detector or a slow filesystem ends in a decision rather than in Claude
Code's kill. The policy refuses a value at or above 10000, the shipped hook
timeout.

`/scan` writes the finding to the store itself, hashed with the deployment
salt.

### Agents you build yourself

Anthropic's inference hooks do not cover Developer Platform organizations, so
an agent on a platform API key reaches the model with no adapter 1 in the
way. You own the agent loop, so the check goes there:

- **A Messages API loop** posts its `messages` array to `/scan` before each
  model call, as a `type: "prompt"` frame, and does not make the call on a
  deny. It gets adapter 1's verdict, detectors and behavioural checks.
- **An Agent SDK agent** registers `UserPromptSubmit`, `PreToolUse` and
  `PostToolUse` callbacks that post their input to `/scan`. A `PostToolUse`
  deny replaces the tool's output before the model sees it.
- **Its OTel** gets its own row when `OTEL_SERVICE_NAME` is set and the same
  name is listed under `otel.agents`.

Each agent is an intake client scoped to `scan`, and its records are filed as
`agent:<client>`, never as an Anthropic surface.
[AGENT-BUILDERS.md](AGENT-BUILDERS.md) has the token setup, Python
and TypeScript callbacks, failure and deny handling, and what was measured.

**A block stops the model call, not session-title generation.** In
Agent SDK session mode, Claude Code sends the first prompt to a
`generate_session_title` request in parallel with the `UserPromptSubmit`
hook. In the reproduction it left 540 ms before the block landed, so the
prompt reached Anthropic even though the user saw it blocked. `claude -p`
does not generate a title, and there a block stopped every model call. No
documented setting turns title generation off. On an org with inference
hooks, adapter 1 sees that request, which contradicts the overview's
statement that title generation is not sent to the endpoint. On an org
without them, nothing does. Treat adapter 2 as stopping the prompt from
being answered, not as guaranteeing it never leaves the machine.

**Unmanaged installs are advisory only.** A developer who can edit
`.claude/settings.json` can remove the hook. For enforcement, deploy the
hook through managed settings and set `allowManagedHooksOnly: true`.

---

## Adapter 3 — Compliance API scanner (optional)

```bash
forgd-verdict compliance sessions --family local --since 2026-09-01T00:00:00Z --join
forgd-verdict compliance denials
```

Pulls from three endpoint families. All three are required for coverage;
see `DESIGN.md`.

Scans every org in `compliance.orgs`, serially, each with its own
Compliance Access Key and cursor file; see
[Which organizations a Compliance Access Key reads](#which-organizations-a-compliance-access-key-reads)
for the key each entry needs. One org failing does not abandon
the rest; the summary reports per-org outcomes. The loader refuses a
configuration where two orgs' `state_path`s share a file name, compared
without case, because a pass that fails midway would advance the cursor
for an org it never scanned. In a findings store a cursor is named by
that file name alone, so `./prod/cursor.json` and `./dev/cursor.json`
would be one cursor.

`compliance.base_url` must be `https://`, or `http://` to a loopback host
for a local fake; the job refuses any other, and logs a warning naming
the host when it is not `api.anthropic.com`. The client follows no
redirect. `managed_agents.base_url` is held to the same rules.

A chat deleted in claude.ai is fetched like any other while the API
still serves its messages. When it no longer does, the chat is recorded
as `deleted` with its messages not read (`unscanned:deleted`), never as
a clean chat, and a detection recorded for it earlier stays the chat's
result in every summary. The ingest summary counts these as
`chats_deleted_unread`.

**Enterprise only.** A Team org has no Compliance API, so it belongs in
`otel.orgs` and adapter 4 is its only fleetwide visibility.

| Endpoint | Covers |
|---|---|
| `/apps/sessions/{local,remote}` | Cowork, Claude Code, Claude Science, M365, Chrome |
| `/apps/chats` + `/{id}/messages` | claude.ai chats |
| `/apps/artifacts/{version}/content` | code and markdown Claude generated in a chat |

Joins findings to `inference_hooks_request_denied` activities via
`reference_id`. Read-only, rate-limited under the shared 600 req/min budget,
cursors persisted so it resumes. Both truncation caps are raised to the
server maximum (`-1`).

### Which organizations a Compliance Access Key reads

A key's organizations are chosen when it is created and cannot be changed
afterwards
([Anthropic: Set up the Compliance API](https://platform.claude.com/docs/en/manage-claude/compliance-api-access)).
A key for the parent organization reads every organization under it; a key
for a single organization reads that organization only. The parent's
primary owner can create either; an organization owner can create only a
key for their own organization. With `read:compliance_user_data`, a
parent-scoped key reads every chat, file, project and session transcript
in every linked organization.

Use one single-organization key per `compliance.orgs` entry, for the org
that entry's `id` names. That is least privilege, and it is also what keeps
the records right: adapter 3 sends no organization filter on any request,
and files everything a pass reads under the entry's `id`. A parent-scoped
key in one entry files every linked organization's sessions, chats and
denials under that one org. The same parent-scoped key in N entries reads
every organization N times and files each finding N times, once under each
entry's org.

### Spot checking a detector's precision

The store keeps hashes, so nothing downstream can tell a real person's name
from a code fragment spaCy mistook for one. This re-fetches the content and
re-runs one detector to judge it.

```bash
# the key is not stored in this repo; supply it yourself, or use --env-file
export ANTHROPIC_COMPLIANCE_ACCESS_KEY='sk-ant-api01-...'

# ask the store which sessions carried the finding, then check those
forgd-verdict spotcheck presidio:person --from-store ./findings
forgd-verdict spotcheck regex:ssn --from-store ./findings --reveal
forgd-verdict spotcheck checksum:nhs-number --chats
```

Prints matched values to the terminal only: no store, no spool, no CSV, no
log sink. Masked to the first and last two characters by default, which is
enough to tell whether `94• ••• ••19` is an NHS number; `--reveal` for the
cases where only the whole value settles it, such as a name.

Use `--from-store` rather than sampling blindly. One detector's findings
can sit in a few sessions out of hundreds, none of them among the first
sampled.

Each detector supplies its own matched values through `matches()`. A
detector that cannot (gitleaks, which runs as a subprocess) raises rather
than returning an empty result, because nothing found and nothing checkable
look identical otherwise.

`--env-file` is never read unless named: a security tool that silently picks
up a credential file in the working directory behaves differently depending
on where it ran. An existing export beats the file. `.env` is gitignored.

---

## Adapter 4 — OTel collector

```bash
FORGD_VERDICT_STORE=./findings forgd-verdict collect --policy policy.yaml   # POST /v1/logs, /v1/traces
```

Anthropic pushes OpenTelemetry to a URL you host. An admin sets the endpoint
and a bearer token; the collector authenticates the token, scans the content
attributes with the shared core, and writes findings to the same store.

**Detection only.** OTel is emitted after the work has happened, so there is
no verdict to return. Enforcement on these surfaces is adapter 2.

| Surface | Signal | Path | Prompt content by default | Configured |
|---|---|---|---|---|
| Claude Code | logs | `/v1/logs` | redacted; needs `OTEL_LOG_USER_PROMPTS=1` | per-machine env vars |
| Cowork | logs | `/v1/logs` | included | admin console, org-wide |
| Office agents — Excel, Word, PowerPoint, Outlook | traces | `/v1/traces` | included, nothing filtered | admin console, org-wide |

**Claude Code sends only structure unless told otherwise.** Each switch adds
one kind of content (these apply to the Agent SDK too, since it runs the same
CLI):

| Variable | Adds | Volume |
|---|---|---|
| `OTEL_LOG_USER_PROMPTS=1` | prompt text on `claude_code.user_prompt` | one event per prompt |
| `OTEL_LOG_TOOL_DETAILS=1` | tool input arguments (commands, paths, patterns) on `claude_code.tool_result` | one event per tool call |
| `OTEL_LOG_TOOL_CONTENT=1` | file contents and command output on a `tool.output` span event; needs tracing | large: tool output, truncated at 60 KB |
| `OTEL_LOG_RAW_API_BODIES=1` | the full Messages API request and response, as `api_request_body` / `api_response_body` | largest: the whole conversation, every request |

Only the raw API bodies carry what an agent read, because the request
body holds the tool results. But each body is the whole conversation so far,
re-sent on every turn and every retry. So the collector records each
session's findings once, keyed on the detector and the value's digest.
A card number in a long session is one finding, not one per request.
Forwarding through adapter 5 still masks it in every event.

**A managed OTLP endpoint wins.** If managed settings set
`OTEL_EXPORTER_OTLP_ENDPOINT`, Claude Code drops a process-level
`OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` and says so only with `--debug`. A machine
whose MDM already exports to another backend cannot be pointed at this
collector with environment variables. Put the collector in the same managed
file, or forward to it downstream of the existing backend. Testing locally
on such a machine shows no batches and no error.

Both OTLP/HTTP encodings are accepted, JSON and protobuf, decoded without a
protobuf dependency, either one sent as is or with `Content-Encoding: gzip`.
`otel.max_body_bytes` bounds the body as sent and again once decompressed.
gRPC is not implemented: Anthropic rejects it at configuration time.

Cowork and office agent telemetry are available on Team and Enterprise,
unlike the Compliance API. For a Team workspace this adapter is the only
fleetwide visibility there is.

| Response | When |
|---|---|
| `200` | accepted and queued for the store writer; not yet written (see below) |
| `401` | no valid token, checked before the body is read |
| `403` | payload's `organization.id` disagrees with the token's org. On a fleet token: `organization_mismatch` when a claim is outside its set, `organization_missing` when a record claims no org, `organization_mixed` when the batch claims more than one |
| `400` | undecodable body, or gzip that is corrupt or cut short — it will not decode on retry either |
| `413` | over `otel.max_body_bytes`, as sent or once decompressed |
| `415` | a `Content-Encoding` other than `gzip` or `identity`, checked before the body is read |
| `503` + `Retry-After` | writer behind, `otel.export_workers` exports already being decoded and scanned (`busy`, checked before the body is read), a body not received within 30 seconds (`body_timeout`), or a transient failure; the exporter retries |
| `503` + `Retry-After`, `too_many_records` | the body carries more than 10,000 records (log records, or spans and their events). Nothing in it is scanned or stored |
| `503` + `Retry-After`, `decoded_too_large` | the body's attribute values render to more than 8 characters per byte of the body (at least 4,000,000), counting each level of a nested array or kvlist. Nothing in it is scanned or stored |

**A `200` is not a store write.** It means the batch was scanned and its
records were queued for the store's background writer, and an exporter does
not resend a batch after a `200`. Delivery after that point is
at-most-once: a failed write is retried twice and then the batch is
dropped, as is a retried batch that no longer fits in the queue. Each
failed write logs the WARNING `store flush failed`, whose `dropped_total`
field counts the records dropped so far; a collector that shuts down with
records still queued logs `store sink closed before its queue was written`.
The collector's `/stats` does not include the store writer's counters, so
those log lines are where such a drop shows. A full queue is handled
before the `200`: the collector answers `503` with `busy`, counts it under
`counts.queue_full` in `/stats`, and the exporter keeps the batch and
retries. Answering `503` while the store is degraded, so the exporter
retries rather than the batch being dropped, is a planned follow-up.

The intake (adapter 2) writes its two routes differently.

A `/scan` record is queued for the intake's batching writer, and delivery
after the verdict is at-most-once. `/scan` does not wait on that queue:
when it is full the verdict is still a `200`, and the record is counted
only in `store.dropped` in the intake's `/stats`. The queue holds
`intake.store_max_queue` records, default `max(5000, 4 × store_batch_size)`,
and that is what the intake holds in memory while the store hangs. A batch
write that still fails after two retries is dropped and counted in
`store.dropped`, and a crash loses at most one flush interval of records
(`intake.store_flush_s`, default 60 s). The counters under `store` count
these `/scan` records only. `pending` counts every record accepted and not
yet written: `queued`, plus `batched` in the writer's hands, plus
`inflight` in a write.

A clean allow is not written as a record. Every `/scan` deny, every
verdict with a finding at any severity, and every one with a dropped tier
is a record as above. A Code hook allow with none of those is counted
into a tally row, one per day, org partition, client, device, session and
surface, and the rows are queued on the writer every
`intake.tally_flush_s` (default 600 s), sooner when 50,000 rows are held,
and on shutdown. A tally row's `tally` is the number of allows it stands
for, and the dashboard, the summary API and the connector weight it by
that, so request, coverage, would-deny, finding and cache counts are the
ones the records would give. A tally row carries no timing, so the Code
hook's scan latency is taken from the verdicts kept as records. A tally
row's time is that of the newest allow it holds, so a window whose start
falls between two flushes counts every allow of a row whose newest allow
is inside it: the Code hook's allow count can include the allows of up to
one `tally_flush_s` before the window starts, and never misses one inside
it. A batch shipped to `/intake` folds its clean allows the same way
before it is written, and its `accepted` count is still every record
sent. A shipped record keeps only the fields the hook writes: a
`cache_hit`, `budget_exceeded`, `shadow_action`, timing or body count a
laptop sets is dropped, so a shipped allow folds and counts as the hook's
own would. Each flush writes the allows since the previous one, so rows
add up across flushes, replicas and restarts; a crash loses at most one
`tally_flush_s` of allow counts, never a deny or a finding. In `/stats`, `tally` holds the `rows` and
`allows` counted and not yet queued and `dropped` (allows past 100,000
distinct rows between flushes), and `counts` holds `tally_rows` queued and
`tally_requeued` (a flush the writer's queue refused, or one whose guard
or queueing raised, counted back in for the next one). At 900 laptops a week was about a million records and is
about 116,000 rows this way.

A batch shipped to `/intake` does not go through that writer. It is
answered `200` only after it is in the store, and the laptop deletes its
spool file on a `2xx`. Writes run on a pool of 4 threads of their own, so
a hung store does not hold up `/scan`. A batch that finds every thread
busy is answered `503` with `Retry-After` and is not queued. A write that
takes longer than 10 s, below the hook's 20 s client timeout, is answered
the same way, but it keeps running and may still land. A retry of the same
body while that write runs is answered `503` again; once it has landed, the
retry is answered `200` with the first write's counts and is not written
again. The map that remembers written batches is per process and holds the
last 4,096, so delivery is at-least-once: a retry that reaches another
replica, arrives after a restart, or follows an evicted entry is written a
second time. A body with more than 5,000 non-empty lines is refused with
`413` `too_many_records` before any line is parsed, and the hook sidelines
it rather than retrying; the hook's spool files stay within that. A store
failure is a `503` with `Retry-After`, and the laptop keeps the spool file
and sends it again. A write hung in the store can hold up the intake's
shutdown until the platform kills the process.

In the intake's `/stats`, `/intake` writes show under `intake_writes`
(`inflight`, `workers`) and under `counts`: `store_timeout` (answered
`503` after the timeout), `write_busy` (every thread busy),
`write_in_flight` (a retry while its write runs), `duplicate_batch` (a
retry answered from the map), `late_landed` (a timed-out write that
landed), `too_many_records`, and `store_error` (the write raised).

A `/scan` body over `intake.scan_max_body_bytes` (default 2 MiB) is
refused with `413` `payload_too_large`, before it is read when its
`Content-Length` says so, and the hook scans that payload locally. The cap
is below `/intake`'s because a scan holds the interpreter through each pass
over its text: while a 4 MiB body was scanned, a small `/scan` on another
thread took about 1 s, the hook's remote timeout, and at 2 MiB about
0.3 s.

`/scan` runs on two lanes of threads of its own. A body over 256 KiB takes
the large lane, which scans one at a time and answers the next `503`
`busy` with `Retry-After: 1` at once, before reading its body when its
`Content-Length` says it is large. Every other body takes the small lane:
four at a time, up to 64 more waiting at most 250 ms for a thread, and
`503` past either. The hook scans locally on a `503`, as on any answer
that is not a verdict, so a busy intake costs a laptop its local scan and
not a decision. In `/stats` the lanes show under `scan_lanes` (`workers`,
`running`, `waiting`) and refusals under `counts` as `scan_busy`,
`scan_busy_small` and `scan_busy_large`. A `scan_busy_small` that keeps
rising means the intake needs another replica.

A batch over 10,000 records is refused whole, so the sender must batch
below that. The OpenTelemetry SDKs' batch processors export at most 512
records per request unless configured otherwise. The SDK settings are
`OTEL_BLRP_MAX_EXPORT_BATCH_SIZE` for logs and
`OTEL_BSP_MAX_EXPORT_BATCH_SIZE` for spans; they are OpenTelemetry SDK
settings, and Claude Code is not known to read them. An OpenTelemetry
Collector between the sender and this one needs its batch processor's
`send_batch_max_size` set to 10,000 or less. Retrying the same body gets
the same answer: a sender that keeps sending over-cap batches retries
until it gives up, and then loses the batch.

Configure orgs under `otel.orgs` in `policy.yaml`. The token is both the
authentication and the routing key: it decides which org a batch is filed
under, and `organization.id` on the payload is cross-checked against it
rather than trusted instead of it. Two entries holding the same token
refuse to start.

### A fleet token for several orgs

Claude Code exports with one token per machine. When the same managed
laptops serve developers in more than one org, give the entry `ids`
instead of `id`, and every batch is filed under the org it claims:

```yaml
otel:
  orgs:
    - label: laptops
      ids: [$FORGD_ORG_ID_PROD, $FORGD_ORG_ID_DEV]
      token: $FORGD_OTEL_TOKEN_LAPTOPS
```

- Each record in a batch must carry `organization.id`, every claim must
  be in `ids`, and the batch must claim one org. Anything else is refused
  whole with `403` and counted: `org_missing`, `org_mismatch` or
  `org_mixed` in `/stats`. One exporter process sends one org's
  telemetry, so a batch claiming two is not expected.
- An entry with `id` keeps the single-org rules: a batch with no claim is
  filed under the token's org.
- Setting both `id` and `ids`, an empty `ids`, or an element that is empty,
  resolves to nothing or repeats another refuses to start.
- An org can be in a fleet entry and have an `id` entry of its own.
- The Helm chart and the Terraform modules do not generate an `ids`
  entry yet. Their `orgIds`/`org_ids` checks require one org id per token
  name, so a fleet token needs `otel.orgs` written in `policy.yaml`.
- These exports are what attributes an intake fleet's records when the
  fleet is bound to several orgs (`intake.fleet[].orgs`). Each laptop holds
  this token, so it can claim any org in `ids`; see
  [SECURITY-MODEL.md](SECURITY-MODEL.md#trust-boundaries).

---

## Adapter 5 — outbound sink (optional)

```yaml
sinks:
  - name: siem
    type: otlp
    endpoint: https://otel-collector.example.com:4318
    token: $FORGD_SINK_TOKEN_SIEM
    redact: [regex:aws-access-key, presidio:email_address]
    drop_events: [token_usage]
    metadata: {env: prod}
```

Forwards what adapter 4 receives to a destination you run, after scanning.
**Absent by default:** no `sinks:`, nothing built, nothing run.

The core scans the raw content, then redacts, filters and annotates; a sink
only encodes and ships. Per destination:

| key | effect |
|---|---|
| `redact` | detector ids, or a bare tier name, whose matches are masked |
| `drop_events` | event names dropped entirely, including a span's events |
| `metadata` | stamped on every event; never overwrites an existing key. Literal strings: a `$VAR` is sent as written. A key or value the metadata guard would replace (a detector match, over 128 characters, or not valid UTF-8) refuses to start, naming the sink, the entry's position and the detector but not the text |
| `max_queue` | bounded; the oldest batch is dropped when full |
| `orgs` | `otel.orgs[].label` values to forward for; omit for every org. A label stands for the org ids its entry names, its `id` or each of its `ids`, and a record is forwarded when the org it is filed under is one of them, whichever token it arrived on. An unknown or duplicated label refuses to start |

Redaction replaces the matched span and leaves the rest:
`deploy with [redacted:regex:aws-access-key] please`. What was removed is
reported as `forgd.redacted.<detector>` on the event, never the value. The
masked value is re-scanned before it leaves; anything still matching is
replaced whole.

An array or kvlist attribute is forwarded as its JSON text and scanned one
element at a time, every string, number and kvlist key on its own, nested
ones included, so a value split across two elements is found on the join
between them as one split across two attributes is. A match in any element
replaces the whole attribute with `[redacted:<detector>:whole-value]`.

The re-scan runs every detector over each masked value on its own, so its
cost grows with the number of masked values in a batch. For gitleaks that
is one call to `gitleaksd` per masked value when `detectors.gitleaks.daemon`
is set, and one `gitleaks` process per masked value when it is not. The
shipped `otel` profile sets it from `$FORGD_GITLEAKS_SOCKET`; a collector
that forwards to a sink without that variable starts a process for every
masked value. See [DETECTORS.md § T1: `gitleaks`](DETECTORS.md#t1-gitleaks).

**The guarantee is that a detected value is not forwarded.** It is not that
the stream contains no secrets: identity keys, values under 8 characters,
`resource` and the event name are never scanned, so nothing in them is
masked.

A sink whose `redact` list names something the running core cannot produce
does not start. A tier the budget skipped masks the affected values whole.
A downstream outage never reaches Anthropic: the queue drops and counts,
and never blocks ingest. Forwarding is at-most-once too: a batch that fails
to send is retried twice and then dropped, and logged as the WARNING
`sink batch dropped`. Drop counts are on the collector's `/stats`, under
`sinks[].dropped`.

The `otlp` and `azure-monitor` sinks send each flush over one kept-alive
connection, unless a proxy from the environment applies to the endpoint,
when each batch opens its own. Delivery is at least once. If a reused
connection is reset or closed before the response arrives, the batch is
sent once more on a new connection, and the receiver may already have
accepted the first copy. A failed batch is also retried up to twice
before it is dropped, and a failure after the receiver accepted it, such
as a timeout waiting for the response, sends it again. A receiver that
must not count an event twice de-duplicates. The sinks add no id of their
own to an event, so a key has to come from the attributes the sender
exported.

Names, emails, phone numbers and places come from Presidio, which is too
slow for the collector's ingest path. `otel.sink_detectors` builds it for
redaction only, and a sink that redacts a `presidio:` id runs it in its own
worker after the export has been acknowledged:

```
ingest path       scan (T0, T1, checksums) -> queue the finding for the store -> queue -> 200
sink worker       Presidio over the same units -> merge -> redact -> send
```

Measured in the ingest image against a ~250-character message: the ingest
side returned in under a millisecond, and the worker's pass took 373 ms warm
and 1.15 s cold. If that pass fails, every value in the batch is masked
whole, never forwarded unmasked. Presidio's findings mask the forwarded copy
only and are not written to the store. It needs the `ml` extra and its
model, so set `collector.useIngestImage=true` in the chart. On the base image
it is absent, and a sink naming `presidio:*` refuses to start.

`type: otlp` and `type: azure-monitor` exist. `Sink` is a Protocol, so
another exporter is a new implementation behind the same interface.

Why it is shaped this way: `DESIGN.md` § Adapter 5 forwards a copy it has
already redacted.

---

## Adapter 6 — Managed Agents scanner (optional)

Claude Managed Agents runs the agent loop and its sandbox on Anthropic's
infrastructure. No inference hook, Claude Code hook or documented OTel
export attaches to it, so adapters 1 to 5 see nothing a managed agent does.
Its event history is persisted server-side and can be read in full, and
`forgd-verdict ingest` reads it on the same schedule as adapter 3 when
`managed_agents.workspaces` is configured.

- **What is scanned.** The user's messages, the agent's messages and
  thinking, every tool call's input and every tool result, built-in, MCP
  and custom. Lifecycle events and `user.tool_confirmation` are skipped: a
  confirmation's deny message comes from whoever approves tool calls, not
  from the agent.
  An event type this does not recognise is scanned whole. Detectors are
  the compliance profile's, Presidio included, and the provenance and taint
  checks run when that profile enables them.
- **What is written.** Source `managed_scan`, surface `managed-agents`, the
  agent id as a salted pseudonym, findings only. The dashboard shows a
  "Managed scan" column when there are any. These records are not compared
  with the inference hook, because a managed agent's traffic never passes
  one.
- **The walk.** No updated-since filter is documented on the session list,
  so a pass walks newest first, rescans each session whose `updated_at`
  moved, and stops at the first one created before `window_days` (30). The
  cursor is kept in the store, one per workspace, and saved only after the
  records are written. A session whose history cannot be read is counted in
  `sessions_failed` and retried next pass without holding up the rest.
- **A workspace with no API key is reported**, as `ok: false, error: "no api
  key"`, and a malformed `managed_agents` block is reported without stopping the
  Compliance pass.
- **The key can delete sessions.** A workspace API key has no documented
  read-only scope. This adapter only issues GETs, but the key it holds can
  create and delete sessions. Scope it to a workspace holding only the
  agents to be scanned.
- **A Platform-only deployment** (Managed Agents and no Enterprise org) needs
  no Compliance Access Key. `ingest` runs whichever of the two is
  configured.

Unverified against a live workspace: the event history's pagination, which
the docs describe only as `has_more`. The client follows `next_page` when
one is returned and `after_id` from the last event otherwise, and logs a
warning when neither advances.

The preventive half is your own code, since nothing on Anthropic's
side inspects a `user.message`. `AGENT-BUILDERS.md` § Managed Agents
has a gate for outgoing messages and tool confirmations.

### Workspace identity

Adapter 6 files each workspace's records under `pseudonym(key, salt,
"workspace")`: a partition of its own kind, beside the orgs that adapters 3
and 4 file under `pseudonym(id, salt, "org")`.

```yaml
managed_agents:
  workspaces:
    - key: support-agents       # immutable; never reused
      label: support-agents     # display only; free to rename
      api_key: $FORGD_MANAGED_AGENTS_KEY_SUPPORT_AGENTS
```

- **`key` is required.** Nothing the Managed Agents API returns to a
  workspace API key identifies the workspace, so the operator assigns one:
  1 to 64 letters, digits, `_` or `-`. It names the partition and the
  cursor, `managed-<key>.json`. A workspace without one is refused by
  label, with the line to add, and `ingest` reports `error: "invalid
  managed_agents.workspaces"` with that text as `detail`. The label is
  never used in its place.
- **`label` is display only.** Renaming it keeps the partition, the cursor
  and every entitlement. Logs and the `ingest` summary name a workspace by
  label; they never show the key.
- **Changing a key starts a new partition, and reusing a retired key
  merges two workspaces' history.** Nothing in the API responses can
  detect either.
- **The prefix keeps the kinds apart.** A workspace pseudonym is
  `workspace_` and ten hex digits, so it cannot equal an org pseudonym.
  Two keys that share a pseudonym, whether duplicated or colliding at 40
  bits, are refused by the ingest job, which is the only writer of
  workspace records, so adapter 6 does not run. The verdict server, the
  collector and the intake log the collision and publish the registry with
  no workspaces, so readers resolve no workspace and every org as usual;
  a mistake here never stops governed traffic. The message names both
  workspaces by label.
- **The cursor is seeded once.** If `managed-<key>.json` does not exist
  and `managed-<label>.json` does, a workspace's first pass starts from the
  label's cursor rather than rescanning `window_days` of sessions. The
  cursor maps session ids, which are unique across workspaces, so a cursor
  another workspace left skips none of this one's sessions.
- **Entitlements grant a workspace by key**, under `workspaces`:

  ```yaml
  dashboard:
    entitlements:
      map:
        - group: support-leads
          orgs: [$FORGD_ORG_ID_PROD]
          workspaces: [support-agents]
  ```

  Each list resolves in its own namespace, and a viewer's access is the
  union. A policy whose map lists a workspace's key or label under `orgs`,
  or a workspace's label rather than its key under `workspaces`, is refused
  when the dashboard or the connector starts; the verdict server does not
  read entitlements and starts regardless. The message names the workspace
  by label.
- **Readers.** The dashboard's org picker lists a workspace as `<label>
  (workspace)`. The connector's `org` argument takes an `org_` or a
  `workspace_` pseudonym, and each org object in its results carries
  `kind`: `org`, `workspace`, `client` for an intake client, or null for
  `unattributed`.
- **The Policy tab** shows `<workspace key>` in place of each key.
- **A workspace whose `api_key` does not resolve** is reported as `ok:
  false, error: "no api key"`.

Why this shape, and what was not done:

- **No API identifier.** None is exposed to the key, so it cannot anchor
  the partition.
- **No immutable label.** It would force a partition move for a cosmetic
  change, and the label is the value operators expect to edit.
- **No namespaced input under the org prefix** (`pseudonym("workspace:" +
  key, salt, "org")`). Its output is still `org_…`, so it can collide with a
  real org at 40 bits and cannot be told apart from one in the store, the
  registry or the connector's `org` argument.
- **No `kind` field on one registry list.** Every consumer of `orgs` would
  have to learn to skip workspace entries. A separate section is ignored by
  a consumer that does not know it.
- **No entitlements by label.** A rename would change a grant, and reusing
  a label would transfer one.

---

### Intake client partitions

The intake files each client's records under the client's `name` from
`intake.clients`, as it is written there: a partition of its own, beside
the `org_` and `workspace_` pseudonyms. The name is not hashed. A client
name cannot contain an underscore, so it never collides with a pseudonym.

- **Entitlements grant an intake client by name**, under `clients`:

  ```yaml
  dashboard:
    entitlements:
      map:
        - group: platform-team
          orgs: [$FORGD_ORG_ID_PROD]
          clients: [invoice-bot, support-bot]
  ```

  A value that is not in the client name form is refused. A name that is
  not in `intake.clients`, such as a retired client's, grants that
  partition's existing records and nothing else.
- **A map that grants no client is refused** when `intake.clients` names
  any. The dashboard and the connector do not start, and the error names
  `clients:`. With no map, every viewer reads every client's partition,
  as for orgs.
- **Readers.** The dashboard's org picker lists each configured client by
  name. The connector's `org` argument also takes a client's name, and the
  org object for that partition carries `kind: client`.

A client is not bound to an org. One client can carry several orgs'
traffic, or none, so an org would be a boundary the records do not have.

## Findings store and dashboard

Nothing a verdict produces survives on its own: the timing CSV sits on
container-local disk that dies with the replica, `/metrics` is in-process,
and a log stream is a rolling buffer. Without a store, a shadow run cannot
report its own would-have-denied rate.

Adapters 1–4 write to an append-only findings store, and a dashboard reads
it. Adapter 5 forwards a redacted copy elsewhere and writes nothing here.

```mermaid
flowchart LR
    CA["Compliance API"] --> J["ingest job<br/>cron · holds the key"]
    A1["adapter 1<br/>live verdicts"] --> SK["async sink<br/>off the hot path"]
    A2["adapter 2<br/>laptop"] --> SP["local spool"]
    A2 -. "/scan" .-> IN["intake service"]
    IN --> S
    OT["Cowork · office agents<br/>Claude Code"] --> A4["adapter 4<br/>OTLP collector"]
    SP --> SH["hook-ship"]
    J --> S[("findings store<br/>append-only JSONL")]
    SK --> S
    SH --> S
    A4 --> S
    S --> D["dashboard"]
```

```bash
forgd-verdict ingest --store ./findings --family local     # adapter 3 -> store
forgd-verdict hook-ship --store ./findings                 # adapter 2 -> store
FORGD_VERDICT_STORE=./findings forgd-verdict collect --policy policy.yaml   # adapter 4 -> store
forgd-verdict dashboard --store ./findings --port 8080     # serve
forgd-verdict dashboard --store ./findings --render out.html   # static snapshot
```

### Adapter 3 runs as a job

In Azure it is a Container Apps Job rather than a service: it holds the
Compliance Access Key, runs a pass, and exits. Created with a `Manual`
trigger so it never fires until you switch it to a schedule. A cron firing
into a deployment with no key yet should be a log line, not a crash-loop, and
`forgd-verdict ingest` exits 0 with a remediation message when no key is
configured.

The commands here use `$RG` for the resource group, `$JOB` for the ingest
job and `$COLLECTOR` for the collector container app.

```bash
# activate
az containerapp job secret set -g "$RG" -n "$JOB" \
  --secrets compliance-key='sk-ant-api01-...'
az containerapp job start -g "$RG" -n "$JOB"

# then, once a pass looks right, put it on a schedule
az containerapp job update -g "$RG" -n "$JOB" \
  --trigger-type Schedule --cron-expression "0 */6 * * *"
```

The key lives only as a job secret. Neither the verdict server nor the
dashboard has it, which is the point of splitting ingest from presentation.

The job runs 2 vCPU / 4 GiB with a 3600 s replica timeout, against 1 vCPU /
2 GiB for the online services. That is the T2 tier: `en_core_web_lg` is about
1 GiB resident on top of a 1.4 GB image, and one pass walks every session
updated since the last run plus every claude.ai chat. It must be pointed at
the `-ingest` image tag: a job on the base image runs, finds nothing at T2,
and reports it as a clean scan.

### Adapter 4 runs as a service

A container app (`$COLLECTOR`), external ingress on 8100, `FORGD_ROLE=collect`. Rolled
after the verdict server and the dashboard on every tag.

It must not sit behind a platform auth provider, for the same reason as
the verdict server: Anthropic's exporter authenticates with an OTLP header,
and an auth redirect turns every export into a delivery failure rather than
reaching the app's own token check. `verify_deployment.sh` asserts a 401 on
an unauthenticated export, and rejects a login redirect on that request,
before the deploy is allowed to finish.

`AZURE_COLLECTOR_APP` empty or unset rolls `ca-forgd-collector`. Set it to
`none` when the collector is not deployed here: the deploy skips it, says so,
and passes the verifier an empty collector URL. A named app that is missing
is a hard failure.

Per-org bearer tokens live in the app's secret store, never in GitHub,
the same handling as the signing secret and the metrics token.

### Adapter 2 spools, then ships

The hook scans and blocks locally, then appends its decision to a local
spool. Something else drains the spool, on a trigger set by `hook.ship_mode`:

| mode | cost on the blocking path | freshness |
|---|---|---|
| `sessionend` | none — a `SessionEnd` hook with `async: true` | when the session ends |
| `detached` | one fork+exec, ~5–15 ms per hook call | near real-time |
| `off` (default) | none | never leaves the laptop |

With remote scanning on, the spool holds only decisions the local fallback
made; `/scan` records the rest server-side.

Two destinations, and `hook.ship_endpoint` is the supported one:

| setting | writes to | needs |
|---|---|---|
| `ship_endpoint` + `ship_token` | the `/intake` endpoint | the fleet's bearer token (`intake.fleet`), distributed by MDM |
| `ship_store` | the findings store directly | store credentials on the laptop |

`hook.scan_token` holds the same fleet token. Every laptop in a fleet sends
it, and names itself in the `X-Forgd-Device` header with its device salt's
namespace. One device is cut off with `forgd-verdict overrides deny-device`
and the whole fleet by rotating the token
([deploy/MDM.md](../deploy/MDM.md#the-fleet-token)). `intake.clients` holds a
token per agent, or per laptop outside a fleet; a per-laptop client logs a
startup warning. Device deny is not available on Cloud Run: `app-cloudrun`
runs with runtime overrides off, so its intake never reads the denied
devices; there, the only way to cut a device off is a fleet-wide rotation: issue a new fleet token with the old one in `FORGD_INTAKE_FLEET_TOKEN_PREVIOUS`, then clear it, which also cuts off every laptop not yet given the new token.

An intake token can be scoped with `routes`: `intake`, `scan`, or both,
which is the default. A laptop that scans remotely and does not ship needs
only `scan`. A valid token on a route it is not scoped to gets `403`, not
`401`, and so does a denied device.

Every fleet and client needs a `name`: a lowercase letter, then up to 39
lowercase letters, digits or hyphens. It is the `client` field on each
record and an Event Log filter, never an org. Records file under the
credential's `org`, else the deployment's only org, else the unattributed
partition. A fleet with `orgs` instead of `org` files its records under its
own partition, `fleet-<name>`, and the dashboard attributes each to an org
through the session id on Claude Code's OTel export ([POLICY.md](POLICY.md#a-fleet-whose-developers-work-in-several-orgs)).
A missing or malformed name, two credentials with one name, or two holding
the same token refuse to start.

A remote `ship_store` (`https://`, `s3://`, `gs://` or a `stores` plugin)
is refused, not warned about, unless `hook.project_overrides: true`: its
SDK takes credentials and the endpoint from the environment, which on a
laptop the project sets. `hook-ship --store` on the command line opens a
remote store, except in a Windows hook process, where it needs
`hook.project_overrides: true` too. A remote store that is opened warns on
every drain; a local one does not. With `hook.project_overrides: true`, `ship_mode`, `ship_endpoint`,
`ship_store` and `ship_token` take `FORGD_VERDICT_SHIP_*` environment
overrides, so one project opts in from its own `.claude/settings.json`
without editing the shared policy; under the POSIX fragment's `env -i`
there are none to take. Leave it false where the hook is a managed
control.

Why the spool exists, and why shipping is off by default:
`DESIGN.md` § Adapter 2 spools rather than uploading.

### Excluding test traffic

```bash
forgd-verdict exclude --store ./findings --list          # frames with findings, and their ids
forgd-verdict exclude --store ./findings --request-id X  # omit one frame
forgd-verdict exclude --store ./findings --clear         # restore everything
```

The record stays in the store, stays in the event log, and the page states
the count. Exclusion is by `request_id`; the Claude Code hook composes one per
decision from `prompt_id` or `tool_use_id`, falling back to a ULID.

**Where these are stored.** With runtime overrides off (the policy's
`dashboard.admins` lists no groups), exclusions and `reset-stats` write the
`markers/*` objects, as they always have. With them on, they write fields
of the runtime overrides object, `state/runtime-overrides.json`, and each
change is audited under the principal `cli`, marked unverified. The CLI
decides on the policy alone. A service honours the object only when
`FORGD_OVERRIDES_ENABLED` is also `true` (see "When runtime overrides are
on" in [OVERRIDES.md](OVERRIDES.md)). An
exclusion equal to a configured org id is refused. On a cloud store the
write needs the control identity's credentials: on a writer identity's the
CLI refuses and says so (see "Running the CLI as the control identity" in
[OVERRIDES.md](OVERRIDES.md)). Readers also honour the `markers/*`
objects that `exclude` and `reset-stats` write with runtime overrides
off, and the writer identities can change those. `forgd-verdict overrides
migrate-markers` folds them into the object and retires them, after which
readers ignore `markers/*` entirely. It is safe to repeat. A dashboard admin can make the same changes, and flip
`server.mode`, from the Policy tab. See [OVERRIDES.md](OVERRIDES.md).

Storage is time-partitioned JSONL, on the local filesystem or Azure Blob
(`forgd-verdict[azure]`), or in an S3 bucket at `s3://bucket/prefix`
(`forgd-verdict[aws]`) or a GCS bucket at `gs://bucket/prefix`
(`forgd-verdict[gcp]`), not a database: two independent
writers need no coordination because each writes its own immutable objects, so
there is no locking, no migrations, and no shared-filesystem corruption risk.
The cost is that aggregation is a full scan in Python, fine at modest
volume, and `Store` is the seam when it stops being fine.

**The store holds findings, never content**, the same invariant as `Finding`
itself. Organization and person identifiers are hashed on the way in, so the
dashboard can group by user without naming anyone. `session_id` stays in the
clear: it is the opaque handle needed to fetch a transcript back
through the Compliance API during review.

### Dashboard authentication

`dashboard.auth.mode` takes one of three values, and the difference is what
the app trusts:

| mode | trusts | safe where |
|---|---|---|
| `none` | nothing | a trusted network only |
| `trusted_header` | a header the auth proxy injects | only where that proxy strips inbound copies |
| `oidc_jwt` | a signature | anywhere the platform issues an ID token |

`trusted_header` is an authentication check only where the proxy in front
strips inbound copies of the header. Container Apps EasyAuth does;
oauth2-proxy does not strip an Azure-named header. The app logs a warning on
every start while the mode is in use, and the chart refuses the combination
unless `dashboard.trustedHeaderStrippedBy` names a proxy you have verified.
On Kubernetes the chart also requires `networkPolicy.enabled` with both
`networkPolicy.ingressController` selectors, or
`networkPolicy.trustedHeaderWithoutPolicyAcknowledged`, because a pod that
calls the dashboard Service directly skips the proxy and can set the header
itself.

`oidc_jwt` verifies signature, `exp`, `iss` and `aud` against the issuer's
JWKS, with RSA, RSA-PSS or EC signatures (an allowlist; the token's own
`alg` is never trusted). `platform:` picks the header the token arrives in:
`container_apps`, `cloud_run`, `alb_oidc`, `iap`, `oauth2_proxy`,
`cloudflare_access` or `pomerium`. More than one identity provider goes in
`issuers:`, and the token's `iss` selects which keys verify it. A missing
`audience` refuses to start. The chart takes all of these as
`dashboard.auth.*` values.

`alb_oidc` works differently, because an AWS ALB publishes no JWKS, puts no
`aud` in its token, and pads its base64 segments, which PyJWT rejects. The
dashboard therefore verifies the ES256 signature itself over the token as
received. It then requires the header's `signer` to be `alb_arn` and its
`client` to be the configured `audience`, and checks `exp` and `iss`. It
fetches the key as PEM from the region's `public-keys.auth.elb` endpoint. Needs
`forgd-verdict[dashboard]`, which brings PyJWT; the verdict server's hot
path keeps no crypto dependency. A rejection returns a flat 401 and the
reason is logged, never returned.

On GCP, a person signing in to the dashboard is `iap`, not `cloud_run`.
The two read different tokens:

| platform | header | what the token says |
|---|---|---|
| `cloud_run` | `x-serverless-authorization` | a caller was allowed to *invoke* the service (`run.invoker`): another service, or a user calling it directly. Verified against the configured `issuer`/`jwks_url`/`audience` like any other ID token |
| `iap` | `x-goog-iap-jwt-assertion` | Identity-Aware Proxy *signed a person in*, and which backend it let them through to |

`iap` verifies as Google documents it: ES256 only, keys from
`https://www.gstatic.com/iap/verify/public_key-jwk`, `iss` exactly
`https://cloud.google.com/iap`, `exp` and `iat` required with no clock-skew
leeway (as on the other token paths), and `email` and `sub` present. The keys are cached for an hour and fetched at most once a
minute, with a 5 s timeout, whether the cache expired or a token named an
unknown `kid`. The issuer and key URL are fixed, so leave `issuer` and
`jwks_url` empty. `audience` is required and names the backend IAP protects:
`/projects/NUMBER/global/backendServices/ID` behind a load balancer, or
`/projects/NUMBER/locations/REGION/services/NAME` for IAP directly on Cloud
Run. Without it, the dashboard refuses to start: every IAP-protected app in
every project shares that issuer and those keys, so their tokens would
otherwise verify. The viewer is named by `email`. IAP tokens carry no
groups and `dashboard.entitlements.map` matches only groups, so the
dashboard refuses to start with both set, and the chart refuses to render.
`deploy/terraform/modules/app-cloudrun` puts IAP directly on the dashboard's
Cloud Run service and sets `platform: iap` and that audience for it. With no
groups, the module also refuses dashboard admins, so runtime overrides are
off on Cloud Run, and with them device deny, which is not available on Cloud
Run: there, the only way to cut a device off is a fleet-wide rotation: issue a new fleet token with the old one in `FORGD_INTAKE_FLEET_TOKEN_PREVIOUS`, then clear it, which also cuts off every laptop not yet given the new token.

The Kubernetes deployment runs `oidc_jwt` behind oauth2-proxy: the proxy
does the interactive flow and passes the ID token in `authorization`, and
the app verifies it. Set `dashboard.auth.header=authorization`: it defaults
to the EasyAuth header name, which carries no token. See
`deploy/helm/README.md` for the proxy settings that are not optional, and
`CREDENTIALS.md` § 8 for the credential.

**The dashboard holds no credentials.** It reads the store and nothing else:
no signing secret, no Compliance Access Key.

Sign-in is restricted to the tenant, so everyone in it can read the
dashboard. To narrow that, set *Assignment required* on the enterprise
application, or restrict which orgs a viewer sees with
`dashboard.entitlements.map`, which requires `oidc_jwt`. The group claim
differs by provider (`groups_claim`, policy.yaml). A viewer whose token
omits their groups (Entra ID above its group limit) is refused with
`groups_unavailable` and a reason, rather than shown an empty page.

#### Org entitlements and labels without the salt

Configuration names orgs by id and Managed Agents workspaces by key, and the
store holds `pseudonym(id, salt, "org")` and `pseudonym(key, salt,
"workspace")`.
The dashboard and the connector are not given `privacy.hash_salt`, so
they resolve ids through an org registry in the store. The registry is
three files, one per writer, each written at startup to the store that
writer sends findings to:

- `state/org-registry-verdict.json`, by the verdict server
- `state/org-registry-collector.json`, by the collector
- `state/org-registry-intake.json`, by the intake

Each is version 2 and has two sections. `orgs` holds one entry per org the
writer's policy names in `orgs`, `dashboard.entitlements.map`,
`compliance` and `otel.orgs`. `workspaces` holds one entry per
`managed_agents.workspaces` key. Each entry carries its pseudonym, and its
label if one is configured. A reader merges whichever of the three files
exist.

A reader that does hold the salt computes pseudonyms directly. It reads the
files only to check them against its own salt: if any entry's pseudonym
differs, it logs a warning that names the writer roles and no org, because
its entitlements and labels then point at partitions the writers do not
write to. It checks when the store is attached and at most once a minute
after that.

- **A writer needs a store and a salt to publish.** With an empty
  `privacy.hash_salt` it logs a warning, writes nothing, and leaves any
  existing file as it is, so one misconfigured writer cannot replace a
  correct registry.
- **Writers may name different orgs.** An org one writer names and another
  does not resolves through the writer that names it. Where writers name the
  same org, its label is the first one given, in the order verdict server,
  collector, intake; a writer with no label for it defers to the next.
- **Writers must share a salt.** If two files give an org or a workspace
  different pseudonyms, it grants no access and has no label; everything
  else still resolves. The reader logs a warning that names the writer roles
  and no org or workspace.
- **Versions.** A reader accepts versions 1 and 2. A version 1 file is
  read for orgs only. Workspaces resolve
  only while at least one present file is version 2; with none, every
  workspace grants no access and has no label, and the reader logs a warning
  once per refresh. A file of any other version, or with an entry whose
  pseudonym's prefix does not match its section, counts as malformed.
- **Writers refuse colliding workspaces.** Two workspace keys that share a
  pseudonym stop the verdict server, the collector and the intake at
  construction, before anything is published.
- **Name every org in the writers' policy.** The registry holds what that
  policy names. An org that only the dashboard's policy names has no entry.
- **Refresh.** A reader re-reads the files at most once a minute. A registry
  republished after the reader started is used within about a minute, plus
  up to 20 seconds of the dashboard's page cache.
- **Fail closed.** If none of the files exists, any that exists is
  unreadable or malformed, or an org has no entry, that org grants no
  access and has no label. The entitlement map still counts as configured,
  so a scoped viewer sees no org. The reader logs a warning that names no
  org.
- **Labels never fall back to the id.** An org with no configured label is
  shown by pseudonym only, on the dashboard and in connector results, with
  or without the salt. Log lines name an org by its label or its
  pseudonym, never its id.

**The registry is trusted the way findings are.** Readers take it as the
writers wrote it. Anyone who can write to the store can rewrite it and
point an org id at another org's pseudonym, which redirects an entitlement
to that org's rows and moves its label. Store write access already lets
someone forge findings, so this adds no new grant, but it is a reason to
keep the dashboard and connector on the reader identity, which cannot
write.

> **Never put platform auth in front of the verdict server or the
> collector.** Anthropic authenticates with a webhook signature and an OTLP
> header; an auth redirect turns every governed prompt or export into a
> delivery failure.

The page loads no scripts: the CSP is `default-src 'none'` with no
`script-src`. `tokens.css` and the webfonts ship in the package, and a logo
and favicon, when configured, are served by the dashboard itself.

Colour carries meaning in two places and nowhere else: the coverage matrix
bands its columns by whether a control can block, and the detector chart
colours each bar by severity. Both ship with a label or a legend. The two
series colours are one warm/cool pair, `--chart-alert` and
`--chart-primary`; a replacement pair needs to stay distinguishable from
each other and from the page background.

### Branding

Unconfigured, the dashboard is neutral: the name "verdict" as text in the
header, no favicon, no footer and a neutral palette. `dashboard.branding`
in `policy.yaml` sets the rest:

```yaml
dashboard:
  branding:
    name: Acme                          # 32 characters at most
    logo: data:image/png;base64,...     # or an absolute path; PNG, SVG or WebP, 256 KB
    favicon: /etc/acme/mark.png
    footer: {text: acme.example, link: https://acme.example}
    chart_palette: ["#C75B3A", "#4A7AB5"]   # alert series, primary series
    theme:
      "--bg-card": "#0C1F3A"
      "--warn-text": "#E0A090"
```

`theme` takes the colour tokens of `tokens.css` and the colour slots the
page CSS, admin controls and charts use; `THEME_TOKENS` in
`dashboard/branding.py` lists them. Values are hex or
`rgb()`/`rgba()`/`hsl()`/`hsla()` with numeric arguments. Images are checked
by their bytes, and an SVG that can run script or load anything is refused.
The Policy tab and `forgd-verdict policy` show an image as its type and size,
never its contents.
Any invalid value stops the dashboard from starting, with an error naming
the key. No environment variable overrides branding.

