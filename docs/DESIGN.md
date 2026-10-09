# DESIGN.md

Why the parts of forgd-verdict are shaped the way they are. `SERVER.md` and
`PLATFORM.md` cover what they do and how to run them; this file covers the
decisions behind them.

Measurements live in `BENCH.md`. The protocol facts the code depends on are
in `PROTOCOL.md`.

---

## The gitleaks config is pinned

**T1's config is pinned.** gitleaks would otherwise read
`<target path>/.gitleaks.toml` and the `GITLEAKS_CONFIG` /
`GITLEAKS_CONFIG_TOML` environment variables, which means the scanned context
can switch off its own scan: a one-file DLP bypass for adapter 2, which runs
inside the developer's working directory. forgd-verdict always passes
`--config` (a baseline shipped in the package), scrubs both env vars, passes
`--ignore-gitleaks-allow`, and runs the subprocess from a neutral directory.
Custom rules go in `detectors.gitleaks.config`, an administrative setting
on a trusted path. See `PROTOCOL.md` § Config resolution.

gitleaks' default rule set allowlists well-known documentation
keys (`AKIAIOSFODNN7EXAMPLE` among them) which T0 flags. Neither tier
subsumes the other.

---

## T2 runs on adapter 3 only

**T2 runs on adapter 3 only.** The adapters share one policy file but not
one latency budget, so `compliance.detectors` overrides the top-level
`detectors` for the scanner (see `Policy.for_profile`). Presidio costs ~8.4 s
on a 223 KB frame and a real Claude for M365 transcript is ~160 KB, which on
the inference hook would spend most of the verdict timeout on one prompt,
and overrunning there is a *webhook failure*, not a deny.

NER entities only: `PERSON`, `LOCATION`, `EMAIL_ADDRESS`, `PHONE_NUMBER`,
`NRP`. Presidio's structured recognizers stay off because T0 covers the same
ground better. The tier is gated so it never runs on source code, where spaCy
scores code fragments as people with the same confidence it gives a real
name. `BENCH.md` has the measured precision and the reasoning per filter.

---

## Weak-shape checksum rules are label-gated

**A checksum is a filter, not an identity proof.** mod-11 passes about one
ten-digit number in eleven, so weak-shape rules are label-gated:
`nhs-number`, `aba-routing`, `canadian-sin` and `imei` all require a nearby
label. `iban` does not: its country code and check digits make the shape
self-identifying and mod-97 is a 1-in-97 filter. Ungated, `nhs-number`
would block any text with ten-digit numbers in it: one in eleven passes
mod-11 by chance, with no mention of the NHS anywhere.

---

## Two exceptions to the privacy invariant

Two exceptions, both documented where they happen:

* **Archive mode** writes whole frames to disk.
  Treat `archive_dir` as a transcript store: 0600 files, encrypted volume,
  its own retention clock.
* **An unsalted `excerpt_hash`** is a bare sha256, and for a low-entropy
  value (an SSN has ~10⁹ possibilities; a PAN fewer once Luhn is applied) it
  is brute-forceable by anyone holding the findings or the logs. A service
  that logs or records findings refuses to start without
  `privacy.hash_salt` unless the policy file sets
  `privacy.allow_unsalted: true`. The hook uses a per-device salt instead,
  and `forgd-verdict scan` a random per-run key.

---

## The session cache validates a prefix, not a count

The protocol notes that *"a turn
whose every block is excluded is omitted entirely"*, so message indices are
not guaranteed stable across frames of one session, so a bare message count
would silently skip a shifted message. The cache stores a cheap shape
signature per message (block types and per-block lengths) plus a digest of
the first message, and falls back to a full rescan on any mismatch. The check
is O(messages), not O(bytes).

---

## `budget_exceeded` and `tiers_dropped` are different facts

Keep the two apart. `budget_exceeded` latches on elapsed time alone, so it
is a latency signal and can be true while nothing was dropped.
`tiers_dropped` is the coverage signal, and it is the one that matters: a
shallower scan looks exactly like a clean one.

---

## Three endpoint families, not one

That split is easy to miss and the consequence is silent: scanning only
sessions means every prompt typed into claude.ai is never fetched, so a
seeded credential produces no finding and the scan looks clean. Artifacts
matter for the same reason: a credential written into generated code is
invisible to a message-text-only scan.

---

## Adapter 2 spools rather than uploading

The spool is the durability layer. Laptops are offline constantly, so a
fire-and-forget upload loses findings silently; draining a spool is
retryable and a failed batch is parked rather than dropped. Appends are one
`os.write()` under `PIPE_BUF` on an `O_APPEND` file, which POSIX makes
atomic, so concurrent hook processes interleave whole lines with no lock a
crashed hook could wedge.

---

## Exclusion instead of a statistics reset

A statistics reset moves the floor and stops counting every record before it,
real findings included. Exclusion is the narrow version: it omits named
frames from the computed rates and nothing else.

---

## Audit findings are counted separately

The control points answer different questions, so the data model keeps them
apart rather than summing them:

| Control | Runs | Can it block? | Reports |
|---|---|---|---|
| Inference hooks | before inference | **yes** — Anthropic holds the request | `allow` / `deny` |
| Claude Code hook | before the tool executes | **yes** | `allow` / `deny` |
| Compliance API scan | after inference, from retained transcripts | **no** | `detected` / `clean` |
| OTel collection | after the work, from emitted telemetry | **no** | `detected` / `clean` |

By the time the Compliance API reads a transcript, inference has happened and
the response has gone back, so its output is an observation rather than a
withheld verdict. OTel is the same case arriving by a different route: it is
telemetry, emitted after the fact, with nothing waiting on a reply.
Presenting either in a shared allow/deny column would imply it declined to
block something it was never in a position to block.

`is_inline` is the single place this is decided, and it is keyed on the
source, so a new non-blocking adapter is counted correctly by default rather
than by remembering to exclude it.

Concretely: `would_deny` counts inline controls only. `deny_rate` is the
inference hook's: its would-deny verdicts over its evaluations. Code hook
decisions and agent checks arrive through an intake token, which every
laptop in a fleet holds, so they are counted apart under `intake_token`
with their own rate rather than in the headline. A rate with nothing to
measure is `null`, never 0: on a Team workspace, where the Code hook is
the only fleet-wide control, the headline reads "no adapter data" and the
token's rate is shown beside it, labelled "via intake token". Post-hoc findings are
`detections` with their own rate. `VerdictRecord.disposition` returns each control's answer in
its own terms.

That makes the post-hoc scan useful for two things: measuring what the inline
controls missed, and covering surfaces they never saw.

---

## The gitleaks sidecar

The CLI recompiles its whole rule set on every `exec`. Measured: 15 ms on a
fast laptop core, 182 ms in-image at 1 vCPU, and 477 ms as the verdict
server's subprocess on Azure Container Apps at 1 vCPU, when the rule set was
~170 regexes. It is a fixed cost: it does not shrink with body size, more
cores do not help because the compile is single-threaded, and the session
cache cannot amortize it because every frame pays it again. On the inference-hook path
it dominates the latency.

`sidecar/gitleaksd` links gitleaks as a library, compiles the rule set once
and answers over a Unix socket: 0.21 ms in-image at 1 vCPU, 870x faster.
Same rules, same config file, same findings; only the process boundary
moves, which a test asserts by running both transports over identical input
and comparing detector, locator and hash.

A socket rather than a TCP port because the secret being scanned crosses this
boundary: a socket carries filesystem permissions, is mode 0600, and cannot
be reached from off-box by a misconfigured ingress. It replaces the temp
file on disk that the CLI path uses, so it is less exposed.

Two failures the daemon path has to avoid, both of which look like a clean
scan:

* The library reports `StartLine` 0-based while the CLI's JSON report is
  1-based. The Python line map is written against the CLI, so unconverted,
  every daemon finding lands on the wrong `ScanUnit` and is dropped, and the
  detector returns an empty list. The sidecar converts, so one convention
  crosses the boundary, and the transport-equality test checks it.
* A `scan()` that returns `[]` when the backend is unavailable silently
  skips a dead daemon. A configured daemon bypasses that gate and lets
  `DaemonUnavailable` propagate, and `required` makes the policy layer
  refuse to build at all when the socket is missing at startup.

The tier is marked required via `daemon` rather than `enabled: true`
because `true` would also break `forgd-verdict serve` on any machine
without a gitleaks binary, which the quick start tells people to run.

---

## Adapter 4 is a separate service, and hand-decodes OTLP

Three decisions, each with an alternative that looked cheaper.

**Its own container, not a route on the verdict server.** Adapter 1 answers
inside the org's 5,000 ms verdict timeout with a circuit breaker behind it.
A telemetry firehose on the same event loop turns a slow scan of a 60 KB API
body into a webhook failure, which fails a user's request rather than
merely missing a finding. The two paths have opposite failure preferences,
so they do not share a process.

**No protobuf dependency.** The collector receives raw prompt text, tool
parameters and file paths from surfaces where Anthropic redacts nothing, so
its dependency list is its attack surface. Reading OTLP needs four messages
and their field numbers; protobuf's own compatibility rules freeze those,
which is what makes hardcoding them safe in a way that hardcoding attribute
*names* is not. `opentelemetry-proto` plus `protobuf` would be carried whole
to use a fraction of it.

The wire format collides:
`ExportLogsServiceRequest.resource_logs` and
`ExportTraceServiceRequest.resource_spans` are both field 1, and the
collision continues down: `scope_logs`/`scope_spans` both 2,
`log_records`/`spans` both 2. So a logs body decodes cleanly as traces and
produces phantom records rather than an error. The request path is the only
thing that knows which schema applies, and it is passed in explicitly.

**Schema-tolerant extraction.** An allowlist of attribute names decides what
a finding is *called* and where identity comes from; it does not decide what
gets scanned. Anything string-shaped that is not structural is scanned. Of
the three surfaces, one schema is beta and says its attributes may change
between releases, and one has no published attribute reference at all, and
all three ship on Anthropic's cadence. The failure this avoids is a silent
miss, of the kind where adapter 3 skips claude.ai chats or the hook reads
the wrong prompt field. An upstream rename should
raise `unrecognised_attributes`, not lower findings to zero.

The inverse risk is scanning identity. `user.email` rides on every event
from every surface, so scanning it would make every event a finding and
report total coverage. Identifiers are matched
by name and by suffix and never scanned.

---

## Adapter 5 forwards a copy it has already redacted

A1-A4 answer "something arrived, what do we do about it". Adapter 5 answers
"something is leaving, what should it look like" -- the only adapter that
changes what a third party receives.

**The core owns what leaves; a sink owns only how it travels.** `send`
receives events that are already redacted and cannot widen them. If
redaction lived in an exporter, every future exporter would reimplement it
and one of them would get it subtly wrong, and a redaction error is a
leak.

**Scanning runs on the original.** Detection quality must not depend on what
the sink is configured to redact, so redaction is applied to a copy and the
store keeps the finding either way.

**A sink that cannot apply its redaction policy does not start.** Adapter 3
degrading is correct: the audit job under-reports and the findings page
shows fewer detections. Adapter 5 degrading is a leak -- the data leaves
anyway, uncensored, and the counter that would have said so is in someone
else's system. The same reasoning covers a tier the budget skipped: a scan
that did not run is not the same as a scan that found nothing.

**The masked value is re-scanned before it leaves.** Three cases can put
a secret past the span arithmetic: `dedupe_findings` collapsing a repeated
value to one span, Presidio reporting offsets in `prose_only` coordinates,
and overlapping spans. Re-scanning turns "the offsets should be right" into
"the output was checked", and costs one pass over one attribute on an
adapter with no latency budget.

**A downstream outage must never reach Anthropic.** A non-200 is an export
failure and sustained failures trip the circuit breaker, so the queue is
bounded, drops the oldest batch with a counter, and never blocks the ingest
path. Flushing inline would defeat this: with a 10s timeout and two
retries it would hold the OTLP response open for up to 30s.

**OTLP only.** Emitting to your own OpenTelemetry
Collector and letting it fan out to Splunk HEC, CloudWatch or Datadog is one
integration instead of N, and it matches the deployment model. The neutral
intermediate is OTel's *data model*, which is not the same thing as OTLP the
wire protocol -- it is a superset of what those destinations need, so each
is a projection rather than a translation through someone else's envelope.

**The `forgd.` attribute namespace is stripped from inbound records.**
`forgd.parent_span` is read back to decide whether an event belongs to a
dropped turn, so a sender-supplied value let an event evade `drop_events`.
Reserved at the decode boundary rather than defended at each use.


## Multi-org is one customer, not several

Each operator forks this and deploys it themselves, so a deployment
serves one company. That company often holds more than one Claude
organization (prod and dev, subsidiaries, regions, a Team workspace beside
an Enterprise one), which is what multi-org means here. Several companies
sharing one store is not a supported shape, and nothing in the design is
built for it.

Two consequences.

**Restricting which orgs a viewer sees is a preference, not a boundary.**
Everyone with dashboard access already works for the company that owns every
org in it. You may still want an EU org restricted to EU staff. That is
your policy to set, and it defaults to off.

**Coverage differs per org, legitimately.** The Compliance API is Enterprise
only. A Team org can be governed by the Code hook and observed by OTel, and
cannot be scanned post-hoc at all. A dashboard that renders that as a gap is
reporting a plan limit as a misconfiguration.

Each org is scanned with its own single-organization Compliance Access Key
([which organizations a key reads](PLATFORM.md#which-organizations-a-compliance-access-key-reads)), so scanning N orgs is N keys, N
cursor files and N failure modes. Sharing one cursor file across orgs is
silent data loss rather than an error: a pass that fails midway advances
the cursor for an org it never scanned, and those sessions are never looked
at again. The loader refuses that configuration.

---

## Two deployment wrappers, not one path per target

You fork this and deploy it yourself, so how it is installed is part of
what ships. Terraform handles cloud resources and Helm handles Kubernetes
workloads.

The boundary between them is not the same on every target:

| Target | Terraform | Helm |
|---|---|---|
| Existing Kubernetes cluster | store + identity only | everything else |
| New Kubernetes cluster | paves the cluster too | everything else |
| Container Apps / ECS / Cloud Run | all of it | not applicable |

Terraform is needed either way. It is optional for the *workload* layer on
Kubernetes, because an operator who already runs a cluster should be able to
`helm install` into it, and unavoidable for the managed container services,
where there is no workload layer to delegate to. That asymmetry is why the
managed-service modules are several times the size of the Kubernetes ones:
ECS needs a VPC, an ALB and two IAM roles before it needs a container.

**The findings store module is the only piece every path needs.** A deployment
on an existing cluster still needs a bucket and an identity that can write
to it, and so do ECS and Cloud Run. Factoring that out is what stops five
targets re-implementing bucket-plus-IAM.

Not a shell script per cloud. A bootstrap script hand-rolls what Terraform
does natively (existence checks and "already exists" branches, a state
machine written in bash), and a platform team handed a
`bootstrap_*.sh` rewrites it as Terraform before it goes near their account.

---

## Terraform owns infrastructure; CI owns image rolls

A tag deploy is four image updates and takes about two minutes. Routed
through `terraform apply` it would add state locking, backend credentials
and a plan on every release, to change one field, and a failed release
would leave state half-applied.

So the modules declare `lifecycle { ignore_changes = [image] }` and CI keeps
rolling images with the provider CLI.

---

## Cold start is a correctness bug here, not a latency preference

Every module has to set a replica floor and say why. The org's verdict
timeout covers connection through response, so a cold start on adapter 1 is
a webhook failure rather than a slow allow: the org's failure policy
applies and repeated failures trip the circuit breaker.

This matters most on Cloud Run, where scale-to-zero is the default, so the
cheapest configuration is a broken one.

---

## Policy is configuration, not part of the image

The image carries the committed `policy.yaml` only so that it can start
without one. A deployment mounts its own: the Helm chart takes it as
`policy.inline` and the app modules as `policy_yaml`. A policy that lived
only in the image would force a build pipeline to change a detector from
`warn` to `block`, which is the thing an operator tunes most often.

That also settles where configuration lives, which is what keeps several
deployment targets from becoming several config dialects:

| Surface | Carries |
|---|---|
| `values.yaml` / `terraform.tfvars` | region, sizes, ingress, secret references, image tag, replica floor |
| `policy.yaml` | detectors, thresholds, orgs, budgets, auth mode |

Two surfaces, and the boundary is *where it runs* against *what it does*.
The policy half is identical on every target, and it stays a mounted file
rather than values keys, because it is heavily commented, and those comments are
most of its value.

---

## Why the dashboard trusts a signature rather than a header

`trusted_header` is correct behind a proxy that terminates in front of the
app and strips inbound copies. Anywhere the container is directly
reachable, the caller sets the header themselves and it is no check at all
-- so the mode is named for what it does and warns on every start.

A missing `audience` refuses to start because a token minted for another
application in the same tenant is a valid token and not a credential for
this one. A rejection returns a flat 401 with the reason logged and never
returned: a verification oracle tells a forger which part to fix.

The dashboard holding no credentials is the reason ingest and presentation
are separate services. The key that can read every chat in the organization
stays in a cron job nobody signs into.

Who may read the dashboard is the deployer's choice. Tenant-wide read is a
reasonable posture for an evaluation deployment, because the store holds
findings rather than prompt content. A deployment carrying a real
organization's traffic should restrict it with `dashboard.entitlements`.

---

## The dashboard's identity check is provider-neutral

`auth.mode: oidc_jwt` verifies a signature against a JWKS URL and checks
`exp`, `iss` and `aud`. That is the standard, and it trusts an assertion
rather than a network position, so it works behind any OIDC provider on any
platform.

The group claim is the sharp edge. Providers disagree about it more than
anything else, and entitlements make it load-bearing for an access decision
rather than a display name, so a provider whose groups arrive in an
unexpected shape silently entitles nobody.

---

## Rejected: an admin endpoint on the verdict server

For runtime overrides (`OVERRIDES.md`), the dashboard could call the
verdict server to change the mode, and that would avoid any store write.
It is rejected. The verdict server has no platform auth,
because Anthropic authenticates to it with a signature, and an auth
redirect in front of it turns every governed prompt into a delivery
failure. An admin endpoint would add an authenticated control surface to
the one service built not to carry one, reachable from wherever the
governed-prompt endpoint is reachable. It would also need a second
credential between the dashboard and the server. And it would reach only
the replica it hit, where the store reaches every replica and the intake
too.

---

## No operator

An operator earns its cost when something needs continuous reconciliation.
Here the workloads are static and the policy is a mounted file: Terraform
creates, Helm installs, CI rolls images. A `VerdictDeployment` CRD would be
a worse values file with a Go controller attached to maintain.

---

## Non-obvious constraints, collected

* **Never enable platform auth on the verdict server.** Anthropic
  authenticates with a webhook signature; an auth redirect turns every
  governed prompt into a webhook failure.
* **`ship_mode` defaults to `off`.** A central record of what developers
  typed should be a deliberate choice, not a side effect of installing a
  hook.
* **Never emit `permissionDecision: "allow"`.** On `PreToolUse` that
  auto-approves the call and bypasses the normal permission flow, turning a
  DLP scanner into a permission bypass. Silence means "no decision".
* **The store holds findings, never content.** Organization and person
  identifiers are hashed on the way in. `session_id` stays in the clear:
  it is the handle needed to fetch a transcript back through
  the Compliance API during review.
