# PROTOCOL.md

The facts about Anthropic's protocols and the gitleaks CLI that forgd-verdict
depends on. Inference hooks and the Claude Code hook contract are both
subject to change, so re-check them against the sources below.

**Last verified 2026-10-16**, against the pages below as published that day
and gitleaks 8.30.1. Each page is also served as Markdown with `.md`
appended to its URL, which is the form to compare against: a summarised
fetch has misreported field names.

Sources:

* `platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint`
* `platform.claude.com/docs/en/manage-claude/inference-hooks-configuration`
* `code.claude.com/docs/en/hooks`
* `code.claude.com/docs/en/managed-settings`
* `platform.claude.com/docs/en/manage-claude/compliance-api`, `.../compliance-sessions`, `.../compliance-activity-feed`
* `platform.claude.com/docs/en/api/compliance/activities/list` and `.../api/compliance/apps/chats/list`, for per-type fields and parameters
* the gitleaks README and `report/finding.go` at the tag CI pins

---

## Inference hooks requests

Anthropic POSTs each frame to the configured URL with `Content-Type:
application/json`, `User-Agent: anthropic-dlp/1`, `Accept-Encoding:
identity`, any custom headers the administrator set, and, once the
organization has a signing secret, three Standard Webhooks headers:
`webhook-id` (equal to the body's `request_id`), `webhook-timestamp`
(Unix seconds; reject one more than five minutes off), and
`webhook-signature` (space-separated `v1,<base64>` values, each an
HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{raw body}` with the
standard-base64-decoded secret after `whsec_`). Requests come from
`160.79.106.0/24`.

Two frame types are sent, and others may follow:

* `prompt`: the transcript up to the point of inference.
* `tool_call`: the tool calls in one model response, sent when
  **Validate tool calls** is on, which it is by default. `messages` holds
  only that `assistant` message, with any `text` blocks and one `tool_use`
  block per call, and one verdict covers every call. Each `tool_use`
  carries `tool_info`, saying who runs or provides the tool (`platform`,
  `application`, `third_party`, `client`, or a kind not yet defined). The
  server scans the frame whole, without the session cache or the
  transcript checks, and counts it as `tool_call_frames`.

Top-level fields: `type`, `request_id`, `tenant_id`, `actor` (`type`
`user`, `id`, `email_address`), `source.application`, `messages`,
`session_id`, `model` and `metadata`, a reserved string map sent empty.
Content blocks are `text`, `tool_use` (`id`, `tool_name`, `input`,
`tool_info`), `tool_result` (`content` as text, `is_error`, `tool_name`,
`tool_use_id`) and `attachment` (`file_name`, `media_type`, `size_bytes`,
`text`, the extracted text; never raw bytes). Most fields can be null. An
unknown block type is to be accepted; the server scans its string fields.
For an unknown frame type Anthropic asks for an allow rather than an error;
the server instead scans it whole and decides it like a prompt, which
never answers with an error either.

Bodies are sent untruncated, up to 64 MiB; `server.max_body_bytes`
defaults to that.

The verdict is HTTP 200 with `action` (`allow` or `deny`), and on a deny
`deny_reason` (truncated at 500 characters) and `reference_id` (at most 50
characters from `[A-Za-z0-9._:/-]`, else dropped). Anything else, including
a non-200 or an unknown `action`, is a webhook failure and the
organization's failure handling applies. At most 64 KiB of the response is
read. The timeout is 1 to 10,000 ms, 5,000 by default, for the whole
exchange; a failed connection is retried once after 100 ms within it.
Prompt and tool call frames share one circuit breaker.

---

## Claude Code hook output

Adapter 2 answers with exit 0 and a JSON object on stdout. Claude Code
parses stdout as JSON only if it starts with `{` and ends with `}`, so the
hook writes no trailing newline. Exit 2 also blocks, but carries no
structured reason.

The block shape differs per event, and the wrong shape is a silent allow,
not an error:

| Event | Block output |
|---|---|
| `PreToolUse` | `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..."}}` |
| `UserPromptSubmit` | `{"decision": "block", "reason": "..."}` at the top level. `permissionDecision` is ignored on this event. |
| `UserPromptExpansion` | `{"decision": "block", "reason": "..."}` at the top level, as `UserPromptSubmit` |
| `PostToolUse` | `{"decision": "block", "reason": "..."}` at the top level, as `UserPromptSubmit` |

`hook.enabled_events` takes only these four events, plus `SessionEnd`,
which the hook handles without the list. The services and
`forgd-verdict policy` refuse a policy that names any other event; the
hook logs a warning naming it, drops it and scans the rest.

`UserPromptExpansion` fires when a slash command or MCP prompt expands.
It carries `expansion_type` (`slash_command` or `mcp_prompt`),
`command_name`, `command_args`, `command_source` and the original
`prompt`, and no expanded content.

`systemMessage` is a top-level field on every event. Nested inside
`hookSpecificOutput` it is ignored.

**verdict never emits `allow`.** `permissionDecision` accepts `"allow"`,
`"deny"`, `"ask"` and `"defer"`; on `PreToolUse`, `"allow"` auto-approves
the call and bypasses the normal permission flow. On a clean scan the hook
prints nothing and exits 0, which is "no decision". The one exception is a
hook with no policy file, which emits a top-level `systemMessage` saying it
is scanning on the built-in defaults: alone on a clean scan, merged into the
block object on a deny.

On `UserPromptSubmit` the hook scans `prompt` and `user_input`. The docs
show only `prompt` as of the last check and have shown `user_input`
before, so the hook keeps reading both. On `UserPromptExpansion` it
scans `prompt` and `command_args`. The text a skill or MCP prompt adds
when it expands is not in the payload, so the hook does not scan it. An
event the hook does not recognise produces nothing to scan. The shipped
`policy.yaml` enables `UserPromptSubmit`, `UserPromptExpansion` and
`PreToolUse`.

`hook.expansions` refuses a `UserPromptExpansion` by the command it
names, before any scan. A rule sets one or more of `command_source`,
`expansion_type` and `command_name`, and matches when every field it
sets equals the payload's. A match in `deny` blocks; otherwise a match in
`allow` passes; otherwise `default` decides. The default is `allow`. An
expansion that passes is scanned as above. The deny reason names the
command only (`forgd-verdict: /<command_name> is not permitted by policy
(expansion control)`), never `prompt` or `command_args`. The section is
validated at load, and no environment or runtime override reaches it. A
policy file that sets `hook.expansions` without `UserPromptExpansion` in
`hook.enabled_events` loads with a warning, since no expansion reaches
the rules.

Hook `timeout` in managed settings is in seconds. A `command` hook defaults
to 600 on most events and to 30 on `UserPromptSubmit`. `SessionEnd` hooks
share a 1.5 s budget, which a longer per-hook `timeout` raises to match, up
to 60. Hook entries accept `args` (exec form) as well as `command`.

A hook that fails, times out or cannot start is a non-blocking error, and
the action goes ahead. From Claude Code 2.1.295 a `command` or `http` hook
entry takes `"onFailure": "block"`, which blocks the action instead;
`"continue"` is the default. The shipped managed-settings fragments do not
set it, so a hook Claude Code kills at its timeout lets the prompt through
(see [SECURITY-MODEL.md](SECURITY-MODEL.md)).

## gitleaks invocation

T1 runs gitleaks once per frame over all scan units joined into one stream;
a line map converts each reported line back to its unit. There are two
transports with the same rules and findings: the `sidecar/gitleaksd` daemon
over a Unix socket, and the CLI as a subprocess.

The subprocess is invoked as:

    gitleaks stdin --no-banner --no-color --exit-code 0 --log-level error \
      --report-format json --report-path - \
      --config <pinned config> --ignore-gitleaks-allow [--redact=100]

* `gitleaks stdin` is the streaming mode. `gitleaks detect --no-git --pipe`
  was deprecated in v8.19.0.
* `--exit-code 0` stops a found leak looking like a subprocess failure.
* `--report-path -` writes the JSON report to stdout, which the detector
  reads, so the report and the plaintext in it never reach disk. A clean
  run prints `[]`. Nothing on stdout is reported as a failed tier whatever
  the exit code: a bad `--config` exits 1 that way, and a binary without
  `--report-path -` support exits 0 that way. A report that is not a JSON
  list is a failed tier too. With `gitleaks.redact: true` the report holds
  masked values, and `excerpt_hash` is then computed over the masked string.
* Report fields are the Go struct's exported names: `RuleID`, `StartLine`,
  `EndLine`, `Secret`, `Match`, `Description`, `Entropy`, `Fingerprint`.
  `Line` is never serialized.
* `StartLine` is 1-based in stdin mode.
* gitleaks' default rule set allowlists well-known documentation keys such
  as `AKIAIOSFODNN7EXAMPLE`. T0 flags them and T1 does not.

### Config resolution

gitleaks resolves its config in this order:

1. `--config` / `-c`
2. `$GITLEAKS_CONFIG` (a path)
3. `$GITLEAKS_CONFIG_TOML` (inline content)
4. `<target path>/.gitleaks.toml`
5. the built-in default

Steps 2 to 4 let the scanned context or its environment turn the scan off:
a `.gitleaks.toml` with an allowlist of `.*` in the working directory takes
detections to zero, with no error. `gitleaks:allow` comments do the same one
line at a time. Adapter 2 runs inside the developer's working directory, so
this would be a one-file bypass.

forgd-verdict therefore:

* passes `--config` on every invocation, pointing at
  `detectors.gitleaks.config` from `policy.yaml` if set, otherwise at the
  packaged `detectors/gitleaks-baseline.toml`;
* removes `GITLEAKS_CONFIG` and `GITLEAKS_CONFIG_TOML` from the subprocess
  environment;
* always passes `--ignore-gitleaks-allow`;
* runs the subprocess from the system temp directory, not the caller's.

The daemon refuses to start without a `--config` path.

## claude.ai chats are not in the session endpoints

The Compliance API session endpoints cover Cowork, Claude Code, Claude
Science, Claude for Microsoft 365 and Claude in Chrome. claude.ai chat
content is in none of them. It is under a separate family:

    GET /v1/compliance/apps/chats
    GET /v1/compliance/apps/chats/{id}/messages
    GET /v1/compliance/apps/artifacts/{version_id}/content

A scan that reads only sessions reports messages scanned and zero findings,
and nothing errors, so a missing chat scan looks like a clean result.

* Chats use cursor pagination (`after_id` / `first_id` / `last_id` /
  `has_more`), ascending. The time bound must match the sort key:
  `updated_at.*` with `order_by=updated_at`, `created_at.*` with the
  default. Mixing them returns 400. adapter 3 pages forward with
  `after_id` only.
* A chat deleted in claude.ai still lists, with `deleted_at` set. Whether
  `/{id}/messages` still serves its messages is not documented; adapter 3
  fetches them, scans what comes back, and records the chat as deleted and
  unread on a 404 or an empty list.
* Artifacts hold the code and markdown Claude generates and are fetched per
  `version_id`. A credential written into an artifact is not in the message
  text.

## Denial activities

An `inference_hooks_request_denied` activity in the Activity Feed carries
`reference_id`, the value the verdict returned, which is how adapter 3
joins a denial to its own record. It also carries `request_id`, Anthropic's
id for the denied request and the frame's own `request_id`, and `event`,
the frame `type` that was denied (`prompt` when absent).

## The connection test (`config-test`)

Anthropic sends frames with `source.application == "config-test"` when an
admin saves or tests the endpoint, and as the circuit-breaker recovery
probe. The server answers them like any other frame.

* Recovery probes start 10 minutes after the breaker trips and repeat about
  once a minute. Automatic recovery runs only while the Inference hooks
  settings are unchanged since the trip, and rotating the signing secret
  counts as a change.
* The test fires while Enforce verdicts is off. A passing test shows the
  endpoint is reachable and configured; it does not show that live prompts
  are routed to it. The admin console's Endpoint status reads *Not
  enforcing* in that state.
* `model` is an empty string on these frames, not absent and not null.
* `request_id` has carried the prefix `dlp_config_test_`. This is not
  documented and nothing in forgd-verdict depends on it.
* `source.application` is advisory routing metadata, not a trust boundary.
  The frames are signed like any other.

The findings store keeps `config-test` records. The dashboard counts them
as synthetic probes and leaves them out of request totals, surface rows and
latency percentiles.

A tool call frame's record carries `event: tool_call`, and a frame of a
type the server does not recognise `event: other`; a prompt frame's record
has no `event`, as have records written before it. The dashboard counts
tool call verdicts on their own, beside "Prompts evaluated live", and
leaves them out of request totals, the deny rate, surface request counts
and latency percentiles, while their findings count as any other. The
event log marks them "(tool calls)".

## Observed `source.application` values

Values seen on inference hooks frames:

| Value | Product | Documented |
|---|---|---|
| `config-test` | connection test and recovery probe | yes |
| `claude-ai` | claude.ai | yes |
| `claude-code` | Claude Code | yes |
| `cowork` | Cowork | yes |
| `sheet_agent` | Claude for Microsoft 365 | no |
| `claude-design` | not confirmed | no |

`sheet_agent` uses an underscore where every documented value uses a hyphen.
Values for the other Microsoft 365 apps have not been observed.

The Compliance API names the same products differently: `claude-ai`,
`cowork`, `claude_code`, `office_agents` and `office_agents/<app>`. Anything
joining the two must normalise the names or it counts one surface twice.
Unknown values pass through `normalize_surface` unchanged and get their own
dashboard row.
