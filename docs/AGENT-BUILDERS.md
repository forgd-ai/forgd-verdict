# Agents you build yourself

Anthropic's inference hooks govern claude.ai, Cowork and Claude Code in a
Claude Enterprise organization. *"Platform organizations (API access through
the Claude Platform) are out of scope."* An agent you build on a Developer
Platform API key reaches the model with no adapter 1 in the way, so the check
has to run in your own code.

Which applies depends on how the agent authenticates:

| Agent authenticates with | Adapter 1 sees its model calls | What you add |
|---|---|---|
| An Enterprise user's Claude Code OAuth token (`claude setup-token`) | yes, measured | nothing required; OTel for a per-agent row |
| A Developer Platform API key, Messages API loop | no | a frame check before each model call |
| A Developer Platform API key, Agent SDK | no | hook callbacks posting to `/scan` |

Putting a proxy in front of the Anthropic API is not recommended. You own
the agent loop, so the check belongs there. You then decide where it goes,
what a failure does and what the user sees, and nothing new sits in the
request path.

## The token

Each agent is its own intake client, scoped to `scan`. An agent host is a
server and has no reason to be able to append records.

```yaml
intake:
  clients:
    - name: invoice-bot
      token: $FORGD_INTAKE_TOKEN_INVOICE_BOT
      routes: [scan]
      org: $FORGD_ORG_ID_PRIMARY   # the org its records file under
      agent: true         # file its hook payloads as agent:invoice-bot
      labels: [triage]    # source.application values it may use as a label
```

Generate the token, set it on the intake service, and hold it in the agent's
own secret store. A token scoped only to `intake` gets 403 from `/scan`.
The name is a lowercase letter, then up to 39 lowercase letters, digits or
hyphens. Two clients with one name, or holding the same token, refuse to
start.

An agent's records file under its client's `org`, else the deployment's
only org, else the unattributed partition. On the dashboard an agent is a
filter in the Event Log (`client=invoice-bot`, or its name under any of its
rows). The org picker lists Claude organizations only.

## Messages API: check each frame

Immediately before every `messages.create`, post the `messages` array you are
about to send, and do not send it on a deny.

```python
import json, os, urllib.request

SCAN_URL = "https://intake.example.com/scan"
SCAN_TOKEN = os.environ["FORGD_SCAN_TOKEN"]

def verdict(messages, session_id):
    req = urllib.request.Request(
        SCAN_URL,
        data=json.dumps({"type": "prompt", "session_id": session_id,
                         "source": {"application": "triage"},
                         "messages": messages}).encode(),
        headers={"authorization": f"Bearer {SCAN_TOKEN}",
                 "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)

v = verdict(messages, session_id)
if v["action"] == "deny":
    ...  # show v["deny_reason"]; do not call the model
else:
    response = client.messages.create(model=MODEL, max_tokens=1024, messages=messages)
```

- **The whole array, every time.** Content the agent read enters the
  transcript as `tool_result` blocks: files, web fetches, MCP results. A check
  on the user's prompt alone misses all of it. The frame is adapter 1's shape,
  with `text`, `tool_use`, `tool_result` and `attachment` blocks. A growing
  transcript is not rescanned whole, because the session cache scans only what
  changed since the last frame.
- **Any other body is scanned too.** A body with no `hook_event_name` that is
  not a `type: "prompt"` frame with a `messages` list is scanned whole, as the
  verdict server scans a frame of an unknown type: `messages` as a transcript
  when it is a list, every other field outside the envelope as text. It gets
  the same verdict and record, without the session cache or the behavioural
  checks.
- **What comes back is adapter 1's verdict.** `action`, `deny_reason`,
  `reference_id` and `detectors`, with the deployment's mode applied: in
  `observe` a deny arrives as `action: allow` with `shadow_action: deny`.
  Branch on `action`, and the mode switch applies to your agent too.
- **The provenance and taint checks run here too.** A send to a destination
  that only a tool result named, or one carrying data found in something the
  agent read, is reported as a warning.
- **`deny_reason` is written for the end user.** It names the kind of data and
  never the value. `reference_id` joins to the record in the store, so show it
  or log it where support can find it.
- **A failure is not an allow.** An unreachable `/scan` is an exception in your
  code, and the check cannot fail closed on your behalf. Treat a timeout or an
  error the way the organization's inference hook is set to fail: if that is
  closed, do not call the model. Calling it anyway is choosing to fail open.
- **Check once per logical request.** Every post is stored as a record. If you
  retry `messages.create` after a 429 or a 5xx, reuse the verdict for the same
  messages instead of posting again.
- **`messages` only.** Like adapter 1, the frame carries no `system` prompt
  and no tool definitions. For an agent you built, both are yours rather than
  the user's.
- `/scan` bodies are limited to `intake.scan_max_body_bytes`, 2 MiB by
  default, and a larger one is refused with `413`. Raising it lets a larger
  frame through and slows every laptop's `/scan` while that frame is
  scanned. Only one body over 256 KiB is scanned at a time; another is
  answered `503` with `Retry-After: 1`.

Records land under source `agent_scan` and surface `agent:invoice-bot`, or
`agent:invoice-bot/triage` when `source.application` is one of the client's
`labels`. A frame cannot present itself as an Anthropic surface: anything
else in `source.application` is ignored, and the session id is stored as a
salted digest. The dashboard shows an "Agent check" column when there are any.

## Agent SDK: hook callbacks

The Agent SDK runs the Claude Code CLI, and the CLI makes the model calls, so
there is no point in your code with the whole frame in hand. The hooks cover
the three places content enters or leaves:

| Event | Scanned | On a deny |
|---|---|---|
| `UserPromptSubmit` | the prompt | the prompt is blocked |
| `PreToolUse` | the tool input | the call is refused |
| `PostToolUse` | the tool's response | `updatedToolOutput` replaces it before the model sees it |

`/scan` takes the callback's input unchanged and answers with adapter 2's
verdict. That verdict always enforces. The deployment's `observe` mode
applies to frames and not to this path, as it does not to laptops' hooks. A
deployment measuring before it enforces still denies here, so an agent that
should only measure has to ignore `action` itself.

`PostToolUse` cannot un-run the tool: a file was still read and a
request still sent. What it stops is the output reaching the model.

A PII match in a file the agent was asked to process is not necessarily a
leak, so decide what a `PostToolUse` deny should mean for your agent before
you enable it. The code below withholds the output.

**Python** (`claude-agent-sdk`). Not measured. `updatedToolOutput` is in
the TypeScript SDK's types as of 0.3.280. Python SDK 0.1.53 has only the
older, MCP-only `updatedMCPToolOutput` and passes the dict through
unchecked, so on a version without it a `PostToolUse` deny is silently
ignored while the store records a deny. Check your version's
`PostToolUseHookSpecificOutput` before relying on it.

```python
import asyncio, json, os, urllib.request
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, query

SCAN_URL = "https://intake.example.com/scan"
SCAN_TOKEN = os.environ["FORGD_SCAN_TOKEN"]

def _post(payload):
    req = urllib.request.Request(
        SCAN_URL, data=json.dumps(payload).encode(),
        headers={"authorization": f"Bearer {SCAN_TOKEN}",
                 "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=2) as r:
        return json.load(r)

async def dlp(input_data, tool_use_id, context):
    try:
        v = await asyncio.to_thread(_post, input_data)
    except Exception:
        # Closed. Return {} here instead to fail open.
        v = {"action": "deny", "deny_reason": "The data-loss check is unavailable."}
    if v.get("action") != "deny":
        return {}
    event, reason = input_data["hook_event_name"], v["deny_reason"]
    if event == "UserPromptSubmit":
        return {"decision": "block", "reason": reason}
    if event == "PreToolUse":
        return {"hookSpecificOutput": {"hookEventName": event,
                                       "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}
    return {"hookSpecificOutput": {"hookEventName": event,
                                   "updatedToolOutput": f"[withheld: {reason}]"}}

options = ClaudeAgentOptions(hooks={
    event: [HookMatcher(hooks=[dlp])]
    for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse")
})

async for message in query(prompt=prompt, options=options):
    ...
```

**TypeScript** (`@anthropic-ai/claude-agent-sdk`, Node 20.3 or later for
`AbortSignal.any`):

```typescript
import { query, type HookCallback } from "@anthropic-ai/claude-agent-sdk";

const SCAN_URL = "https://intake.example.com/scan";
const SCAN_TOKEN = process.env.FORGD_SCAN_TOKEN!;

const dlp: HookCallback = async (input, toolUseID, { signal }) => {
  let v: { action?: string; deny_reason?: string };
  try {
    const r = await fetch(SCAN_URL, {
      method: "POST",
      headers: { authorization: `Bearer ${SCAN_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify(input),
      signal: AbortSignal.any([signal, AbortSignal.timeout(2000)]),
    });
    if (!r.ok) throw new Error(`scan answered ${r.status}`);
    v = await r.json();
  } catch {
    // Closed. Return {} here instead to fail open.
    v = { action: "deny", deny_reason: "The data-loss check is unavailable." };
  }
  if (v.action !== "deny") return {};
  const event = input.hook_event_name;
  const reason = v.deny_reason ?? "Blocked by data-loss policy.";
  if (event === "UserPromptSubmit") return { decision: "block", reason };
  if (event === "PreToolUse")
    return { hookSpecificOutput: { hookEventName: event, permissionDecision: "deny",
                                   permissionDecisionReason: reason } };
  return { hookSpecificOutput: { hookEventName: "PostToolUse",
                                 updatedToolOutput: `[withheld: ${reason}]` } };
};

const hooks = { hooks: [dlp] };
for await (const message of query({
  prompt,
  options: { hooks: { UserPromptSubmit: [hooks], PreToolUse: [hooks], PostToolUse: [hooks] } },
})) {
  // ...
}
```

Things measured with the TypeScript SDK 0.3.280 that the snippets do not
show:

- **A block is reported as success.** The result message was
  `subtype: "success", is_error: false`, and the block appeared only in the
  result text. A caller that checks `is_error` counts a DLP block as a
  success.
- **A block stops the model call, not session-title generation.** In
  session mode the CLI sends the first prompt to a `generate_session_title`
  request in parallel with `UserPromptSubmit`, 540 ms before the block landed
  in the reproduction. No documented setting turns it off. On an API key
  no forgd-verdict adapter sees that request.
- **`settingSources: []` disables project hooks.** A `.claude/settings.json`
  hook runs only when settings are loaded, and a container has no settings
  file. On a server the callbacks above are the whole of adapter 2.
- **The whole frame is not available here.** The callbacks see each piece as
  it passes and never the transcript the model receives, so the provenance
  and taint checks, which need that transcript, do not run on this path.

With `agent: true` on the client, these records are filed under
`agent:invoice-bot`. They are counted with the dashboard's code-hook
decisions, where a `PostToolUse` deny is shown as output withheld and not
as blocked before running, because the tool had run. The session id is kept when it is a lowercase UUID,
as Claude Code's are, so it joins the agent's OTel records. Anything else,
including a custom `sessionId` in capitals, is stored as a digest.

## OTel: a row per agent

Set `CLAUDE_CODE_ENABLE_TELEMETRY=1` and the `OTEL_*` variables on the agent
as for Claude Code (PLATFORM.md, adapter 4). Two things differ for an agent:

- **Name it.** Set `OTEL_SERVICE_NAME` to the agent's name and list the same
  name under `otel.agents`. Otherwise the SDK reports `service.name:
  claude-code` and lands in the Claude Code row with developers' laptops. A
  name you set but do not declare is filed by substring as a product
  (`email-triage` as Outlook) or, through the `claude_code.` event prefix, as
  Claude Code. `OTEL_RESOURCE_ATTRIBUTES=agent.name=…` does not help, because
  `service.name` is read first.
- **Give it its own org token.** An API-key session sends no
  `organization.id`, so the collector has nothing to cross-check and the
  token is the only thing binding the batch to an org. A token shared with a
  developer org files the agent's findings under that org.

## Managed Agents: gate what goes in and what runs

Claude Managed Agents runs the loop and the sandbox on Anthropic's side, and
nothing there inspects a `user.message`. Adapter 6 scans every session
afterwards (PLATFORM.md, adapter 6). Only your application can stop something
first, at the two points where it takes part in the session:

| Point | What you do | On a deny |
|---|---|---|
| sending a `user.message` | post it to `/scan` as a frame first | do not send it |
| a tool call waiting for approval | post it to `/scan` as a `PreToolUse` payload | answer `user.tool_confirmation` with `result: "deny"` |

The second needs `permission_policy: {"type": "always_ask"}` on the tools you
want gated. The agent toolset defaults to `always_allow`, and under that
nothing reaches your code before a call runs. `always_ask` pauses the session
on every gated call and needs your client attached to answer it. Under
`auto`, Anthropic's own server-side check decides some calls, and a call it
allows runs before you see it.

```python
import json, os, urllib.request

API = "https://api.anthropic.com"
HEADERS = {"x-api-key": os.environ["ANTHROPIC_API_KEY"],
           "anthropic-version": "2023-06-01",
           "anthropic-beta": "managed-agents-2026-04-01",
           "content-type": "application/json"}
SCAN_URL = "https://intake.example.com/scan"
SCAN = {"authorization": f"Bearer {os.environ['FORGD_SCAN_TOKEN']}",
        "content-type": "application/json"}

def _post(url, headers, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)

def send_message(session_id, text):
    content = [{"type": "text", "text": text}]
    v = _post(SCAN_URL, SCAN, {"type": "prompt", "session_id": session_id,
                               "messages": [{"role": "user", "content": content}]})
    if v["action"] == "deny":
        return v["deny_reason"]  # show it; nothing was sent
    _post(f"{API}/v1/sessions/{session_id}/events", HEADERS,
          {"events": [{"type": "user.message", "content": content}]})

def confirm(session_id, event):
    """`event` is an agent.tool_use or agent.mcp_tool_use waiting on you:
    evaluated_permission "ask", named in session.status_idle's
    stop_reason.event_ids."""
    v = _post(SCAN_URL, SCAN, {"hook_event_name": "PreToolUse",
                               "session_id": session_id,
                               "tool_name": event["name"], "tool_input": event["input"]})
    answer = {"type": "user.tool_confirmation", "tool_use_id": event["id"],
              "result": "deny" if v["action"] == "deny" else "allow"}
    if v["action"] == "deny":
        answer["deny_message"] = v["deny_reason"]
    _post(f"{API}/v1/sessions/{session_id}/events", HEADERS, {"events": [answer]})
```

- **The two checks do not share a mode.** The message check is a frame, so
  the deployment's `observe` mode applies to it: a deny comes back as
  `action: allow` with `shadow_action: deny`. The tool check is a hook
  payload, which always enforces, as in the SDK section. They also use
  different detector sets: the verdict server's for a frame and the hook's
  for a tool call. A deployment still measuring should read `shadow_action`
  on the first and ignore `action` on the second.
- **The agent sees the deny.** It receives the call as a failed tool result
  carrying your `deny_message`, and can try something else. `deny_reason`
  names the kind of data and never the value.
- **The same failure rule applies.** If `/scan` cannot be reached, choose
  closed or open; `urllib` raises, and the code above lets it propagate.
- **Custom tools** (`agent.custom_tool_use`) run in your own handler, so
  check their input there the same way, and their output with a
  `PostToolUse` payload before you return `user.custom_tool_result`.
- **Self-hosted environments** execute the agent toolset on your worker and
  return `user.tool_result`. That is the one Managed Agents path where a tool's
  output can be checked before the model reads it: post it as a `PostToolUse`
  payload and withhold it on a deny.
- **The provenance and taint checks run only post-hoc here.** These two
  points each see one piece at a time, not the transcript. Adapter 6 runs
  both over the full history afterwards.

Give this client its own intake token scoped to `scan`, with `agent: true`,
so its records are filed as `agent:<name>`.
