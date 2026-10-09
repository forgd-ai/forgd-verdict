# Quick start

Run the verdict server on your own machine, send it one signed request
with a fake AWS key in it, and read the finding back from a local findings
store and the dashboard. Nothing here talks to Anthropic or to a cloud
store.

You need Python 3.11+, [uv](https://docs.astral.sh/uv/), `curl` and
`openssl`. `gitleaks` is optional: it is detected on `PATH` and adds the T1
tier, and every step below works without it.

Run everything from a clone of this repository, in one shell. The servers
run in the background of that shell, their process ids kept in `$SERVER`
and `$DASHBOARD`, and the last step stops them.

## 1. Install

```bash
uv venv && source .venv/bin/activate
uv pip install -e '.[server]'
```

`[server]` adds uvicorn, which `serve` and `dashboard` both need.

Check the scan core before starting anything. `scan` exits 1 on a deny, 0
on an allow, and 3 on an allow from an incomplete scan, where a blocking
detector did not run (gitleaks without its binary, say). It prints the
verdict, with the tiers that did not run in `tiers_dropped`:

```bash
printf 'ship it with AKIAIOSFODNN7EXAMPLE' | forgd-verdict scan -
```

The output names the detector (`regex:aws-access-key`), a locator and an
`excerpt_hash`. The key itself appears nowhere in it, and it never appears
in a log, a stored finding or a deny reason either.

## 2. Configure

The repository's `policy.yaml` reads its secrets and its store location
from the environment. Three variables are enough to run it locally:

```bash
export WEBHOOK_SECRET="whsec_$(openssl rand -base64 32)"
export FORGD_HASH_SALT="$(openssl rand -hex 32)"
export FORGD_VERDICT_STORE=./findings
```

`WEBHOOK_SECRET` is the signing secret. In a deployment it is the one
Anthropic shows you when you create the Inference hook; here you make one
up, and step 4 signs with it. The repository's `policy.yaml` sets
`server.store: $FORGD_VERDICT_STORE`, and the server refuses to start
while that reference is unresolved. With a path it writes append-only
JSONL under that directory. A policy with `store: ""` runs with no durable
store and records nothing.

`FORGD_HASH_SALT` is `privacy.hash_salt`, prepended to every matched value
before it is hashed. Every service that logs or records findings refuses
to start without it, with or without a store, because a bare SHA-256 of a low-entropy value, such as
an SSN or a card number, can be reversed by brute force. Keep the same
value for as long as you keep the findings: hashes made with different
salts do not compare.

The policy starts in `observe` mode: every request is allowed, and what
would have been denied is recorded.

## 3. Start the verdict server

```bash
forgd-verdict serve --policy policy.yaml --host 127.0.0.1 & SERVER=$!
sleep 2; curl -s http://127.0.0.1:8000/healthz
```

The policy binds `0.0.0.0:8000`; `--host 127.0.0.1` keeps it on loopback.
`/healthz` answers `"status": "ok"` with the mode and the build.

## 4. Send a signed request

Anthropic POSTs each governed request to the configured URL with
[Standard Webhooks](https://www.standardwebhooks.com/) signature headers,
and the server answers `401` to anything unsigned. This script builds a
minimal prompt frame with a fake AWS key in it, signs it with
`$WEBHOOK_SECRET` the same way, and posts it:

```bash
python - <<'EOF'
import base64, hashlib, hmac, json, os, time, urllib.request

body = json.dumps({
    "type": "prompt",
    "request_id": "req_quickstart",
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "actor": {"type": "user", "id": "user_quickstart"},
    "source": {"application": "claude-ai"},
    "session_id": "00000000-0000-0000-0000-000000000001",
    "model": "claude-opus-5",
    "messages": [{"role": "user", "content": [
        {"type": "text", "text": "deploy with AKIAIOSFODNN7EXAMPLE"}]}],
    "metadata": {},
}).encode()

key = base64.b64decode(os.environ["WEBHOOK_SECRET"].removeprefix("whsec_"))
webhook_id, ts = "msg_quickstart", str(int(time.time()))
mac = hmac.new(key, f"{webhook_id}.{ts}.".encode() + body, hashlib.sha256)
req = urllib.request.Request("http://127.0.0.1:8000/", data=body, method="POST", headers={
    "content-type": "application/json",
    "webhook-id": webhook_id,
    "webhook-timestamp": ts,
    "webhook-signature": "v1," + base64.b64encode(mac.digest()).decode(),
})
print(urllib.request.urlopen(req).read().decode())
EOF
```

```json
{"action": "allow", "findings_count": 1}
```

`allow`, because the server is in `observe` mode. The signed payload is
`{webhook-id}.{webhook-timestamp}.` followed by the raw body bytes, and a
timestamp more than 300 s from the server's clock is rejected.

## 5. Read the finding

The server batches store writes and flushes every 60 s, or when it stops.
Stop it now to flush. `wait` returns once its shutdown, flush included,
has finished:

```bash
kill $SERVER; wait $SERVER
find findings -name '*.jsonl'
```

The file sits under
`findings/verdicts/source=inference_hook/org=org_<hash>/date=<today>/`.

The row records `"action": "allow"` and `"shadow_action": "deny"`, the
`reference_id`, and the finding as detector, locator and hash. The
`tenant_id` is stored as an `org_` pseudonym, and the verdict log line and
the timing CSV carry the same pseudonym.

The dashboard reads the store and nothing else. The repository's
`policy.yaml` puts it behind a platform auth proxy, and in that mode it
refuses to start unless `dashboard.auth.stripped_by` names a proxy that
strips the identity header. Locally there is no proxy, so turn
authentication off with `FORGD_DASHBOARD_AUTH_MODE`, which overrides
`dashboard.auth.mode`. With it off, the dashboard refuses to bind anything
but loopback unless `--serve-open` is passed:

```bash
FORGD_DASHBOARD_AUTH_MODE=none \
  forgd-verdict dashboard --store ./findings --host 127.0.0.1 --port 8080 & DASHBOARD=$!
sleep 2
```

Open <http://127.0.0.1:8080/>. The request is counted as a would-deny under
`claude-ai`, against `regex:aws-access-key`. The same figures are on the
JSON summary:

```bash
curl -s http://127.0.0.1:8080/api/summary
```

## 6. Try enforce mode

`FORGD_VERDICT_MODE` overrides `server.mode`, so switching to real verdicts
does not need a policy edit. Restart the server in enforce mode and run the
step 4 script again:

```bash
FORGD_VERDICT_MODE=enforce forgd-verdict serve --policy policy.yaml --host 127.0.0.1 & SERVER=$!
sleep 2
```

This time the response is a deny, with the user-facing reason and a
`reference_id`.

## 7. Clean up

```bash
kill $SERVER $DASHBOARD
rm -rf findings timings.csv
```

## Next

- [SERVER.md](SERVER.md): the verdict server, the scan core and every
  `policy.yaml` block.
- [PLATFORM.md](PLATFORM.md): the other adapters, the findings store and
  the dashboard.
- [PROTOCOL.md](PROTOCOL.md): the protocol facts the code depends on.
