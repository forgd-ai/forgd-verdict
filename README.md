# forgd-verdict

[![ci](https://github.com/forgd-ai/forgd-verdict/actions/workflows/ci.yml/badge.svg)](https://github.com/forgd-ai/forgd-verdict/actions/workflows/ci.yml)
[![licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

forgd-verdict is data loss prevention for an organization's use of Claude.
It finds secrets and personal data (API keys, credentials, national IDs,
card numbers and similar) in what people and agents send to Claude and in
what comes back, and it can block a prompt before it reaches the model.

- **Before inference:** Anthropic's inference hooks call the verdict
  server with each prompt, and it answers allow or deny. On Claude Code,
  a hook does the same before a tool runs.
- **After the fact:** it scans conversation history from the Compliance
  API, telemetry pushed over OpenTelemetry, and Managed Agents sessions,
  where it cannot block. It records what it found, and can join those
  findings to the live verdicts.
- **Findings:** each is stored as a detector name, a location and a
  one-way digest, never the matched value.
- **Dashboard and connector:** a dashboard shows coverage, findings and
  latency across every surface. An optional read-only connector lets a
  security team query the same findings from Claude. The connector is
  experimental: it has not yet been run against a real Claude organization
  or identity provider.

You deploy it into your own cloud, against your own Claude organizations:
Azure, AWS or Google Cloud, on managed containers or Kubernetes. Findings
are written to storage in that cloud. Either fork this repository and
deploy from the fork, or keep a repository of your own deployment files
that runs a published release (the images, the Helm chart, the Terraform
modules and the PyPI package); [docs/DEPLOY-FROM-RELEASES.md](docs/DEPLOY-FROM-RELEASES.md)
says when to choose which and has a skeleton for the second.

## Status

Inference hooks are a beta Anthropic protocol, and drift should be
expected. [docs/PROTOCOL.md](docs/PROTOCOL.md) records the protocol facts
the code depends on and where each comes from. Points not yet confirmed
against a live organization are marked in the docs that rely on them, for
example the Managed Agents event-history pagination
([PLATFORM.md § Adapter 6](docs/PLATFORM.md#adapter-6--managed-agents-scanner-optional))
and the connector's open questions
([design/connector.md § UNCONFIRMED, collected](docs/design/connector.md#unconfirmed-collected)).

## Requirements

- **Inference hooks** (adapter 1): turned on by an Owner or Primary owner
  (`organization:manage`). Admin is not enough.
- **Compliance API** (adapter 3): enabled by the Primary owner at the
  parent organization, which cascades to all linked orgs.
- **A Team workspace** has an org UUID like an Enterprise org, but no
  Compliance API, so adapter 3 cannot serve it and adapter 4 (OTel) is its
  only fleetwide visibility.
- **Managed Agents** (adapter 6): a workspace API key per workspace.
- **Claude Code hook** (adapter 2): an enforcement control only when it is
  distributed as a managed hook, see [deploy/MDM.md](deploy/MDM.md). The
  hook receives the prompt as typed: content Claude Code attaches from an
  `@` file reference, without a Read tool call, does not pass through it,
  so adapter 2 does not scan it. Managed `permissions.deny` `Read(...)`
  rules for sensitive paths narrow this; see
  [deploy/MDM.md](deploy/MDM.md#keeping-sensitive-files-out-of-claudes-reads).
- **Runtime:** Python 3.11 or later. Deployment targets are Azure, AWS and
  Google Cloud, each on its managed container service or on Kubernetes.

Every credential, where it comes from and where it goes is in
[docs/CREDENTIALS.md](docs/CREDENTIALS.md).

## Architecture

```mermaid
flowchart TD
    P["policy.yaml"]
    C["scan core (forgd_verdict)<br/>detectors → Finding[]<br/>decide(Finding[]) → Verdict"]
    P --> C
    C --> A1["A1 · Inference hooks server<br/>HTTPS, Anthropic → us<br/>allow / deny, before inference<br/>+ provenance and taint checks"]
    C --> A2["A2 · Claude Code hook<br/>stdin → verdict, locally or via /scan<br/>allow / deny, before the tool runs"]
    C --> A3["A3 · Compliance scanner<br/>pull, after the fact<br/>detect only, join by request_id"]
    C --> A4["A4 · OTel collector<br/>Anthropic pushes OTLP → us<br/>detect only, near real time"]
    A4 --> A5["A5 · Outbound sink (optional)<br/>redact, filter, annotate → their SIEM<br/>the only adapter that changes what leaves"]
    C --> A6["A6 · Managed Agents scanner (optional)<br/>pull session histories, after the fact<br/>detect only"]
```

Detection logic, policy, and deny-message wording live in the core exactly
once. Adapters translate transport in and out; none of them makes a policy
decision of its own.

| Adapter | Blocks or detects | Where it runs | Doc |
|---|---|---|---|
| A1 · Inference hooks server | blocks: allow or deny before inference | a service in your cloud that Anthropic calls | [SERVER.md](docs/SERVER.md) |
| A2 · Claude Code hook | blocks: allow or deny before the tool runs; does not see content attached from an `@` file reference | each developer machine, scanning locally or through the intake service's `/scan` | [PLATFORM.md § Adapter 2](docs/PLATFORM.md#adapter-2--claude-code-hook-cli), [MDM.md](deploy/MDM.md) |
| A3 · Compliance scanner | detects, after the fact | the `ingest` job, on a schedule | [PLATFORM.md § Adapter 3](docs/PLATFORM.md#adapter-3--compliance-api-scanner-optional) |
| A4 · OTel collector | detects, near real time | a service in your cloud that Anthropic exports to | [PLATFORM.md § Adapter 4](docs/PLATFORM.md#adapter-4--otel-collector) |
| A5 · Outbound sink | neither: redacts and forwards what A4 receives to your SIEM | inside the collector, absent unless `sinks:` is configured | [PLATFORM.md § Adapter 5](docs/PLATFORM.md#adapter-5--outbound-sink-optional) |
| A6 · Managed Agents scanner | detects, after the fact | the `ingest` job, alongside A3 | [PLATFORM.md § Adapter 6](docs/PLATFORM.md#adapter-6--managed-agents-scanner-optional), [AGENT-BUILDERS.md](docs/AGENT-BUILDERS.md) |

Adapters 1, 2, 3, 4 and 6 write to one append-only findings store, and the
dashboard reads it. [docs/DESIGN.md](docs/DESIGN.md) covers why the parts
are shaped this way.

## Quick start

```bash
uv venv && source .venv/bin/activate
uv pip install -e '.[server]'
printf 'ship it with AKIAIOSFODNN7EXAMPLE' | forgd-verdict scan -
```

`scan` exits 1 on a deny, 0 on an allow, and 3 when a blocking detector
did not run. It prints the detector, a locator and an `excerpt_hash`,
never the key. The hash is salted with `FORGD_HASH_SALT`. Without one,
`scan` hashes with a random key that lasts only for that run and says so
on stderr, so its hashes cannot be reversed or compared with another
run's.
[docs/QUICKSTART.md](docs/QUICKSTART.md) goes on to run the verdict server
locally, send it a signed request, and read the finding back from a local
store and the dashboard.

## Deploying

[docs/DEPLOY.md](docs/DEPLOY.md) covers choosing a cloud and a target, the
order of operations, and verifying a deployment. Terraform creates the
cloud resources ([deploy/terraform/README.md](deploy/terraform/README.md)),
and on Kubernetes the Helm chart deploys the services
([deploy/helm/README.md](deploy/helm/README.md)).

`forgd-verdict verify-deployment` (`scripts/verify_deployment.sh` in a
checkout) checks a deployment over HTTP alone, with no credentials:

* an unsigned POST to the verdict server must return 401, because a
  200 would mean the app came up accepting unsigned traffic;
* the response must not be a redirect to a login page, because platform
  auth in front of the verdict server would turn every governed prompt
  into a webhook failure.

The collector gets the same two checks on an unauthenticated export.

The checks have one known gap: an auth front end configured to answer
401 rather than redirect passes the unsigned-POST assertion for the
wrong reason, while refusing Anthropic's signed requests too. A passing
run is not evidence that platform auth is off.

## Configuration

Every service reads one file, `policy.yaml`, merged over built-in defaults
and a short list of environment variables. Secrets are never written into
it: a value such as `$WEBHOOK_SECRET` is resolved from the environment, and
the secrets themselves live in your platform's secret store.
`forgd-verdict --policy policy.yaml policy` prints the effective policy,
redacted. [docs/POLICY.md](docs/POLICY.md) is the index to every section.

## Privacy invariant

A matched secret or PII value never reaches a log, a finding, a
`reference_id` or a deny reason. What leaves a scan for each match is the
detector name, a locator and a one-way digest.
[docs/PRIVACY.md](docs/PRIVACY.md) covers the hash salt and what is stored
where.

## Documentation

- [docs/QUICKSTART.md](docs/QUICKSTART.md): run the verdict server locally
  and read a finding back.
- [docs/DEPLOY.md](docs/DEPLOY.md): choose a cloud and a target, and deploy.
- [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md): what can block, the
  trust boundaries, and how each part fails.

Everything else: [docs/README.md](docs/README.md).

## Versioning

Semver here tracks the rule set, not the Python API: when a detector
changes, what gets blocked changes, and that is the compatibility surface
someone integrating against this cares about.

The running build is reported at `GET /healthz` as `version+commit` and
stamped on every finding as `build`. `schema_version` covers a record's
shape; `build` covers its meaning. A finding from before `nhs-number` was
label-gated is a different claim from one after, and the stamp separates
them without deleting every record and rescanning.

## Non-goals

No rewrite on the inbound path. The inference-hook protocol is allow/deny,
so there is nowhere to put altered text, and adapter 2's `PreToolUse` could
rewrite tool input but does not. Adapter 5 redacts on the way out, which
is a different path and an optional one.

No policy management service. No multi-tenant SaaS hardening: one
deployment serves one operator, who may hold several organizations.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security, licence and trademark

Report vulnerabilities as described in [SECURITY.md](SECURITY.md), not in
a public issue.

Licensed under Apache-2.0; see [LICENSE](LICENSE). Apache-2.0 does not
grant rights to the forgd name or marks (LICENSE §6).
