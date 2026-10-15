# Documentation

## Start here

- [QUICKSTART.md](QUICKSTART.md): run the verdict server locally, send it a
  signed request with a fake key, and read the finding back.
- [DEPLOY.md](DEPLOY.md): choose a cloud and a target, the order of
  operations, and verifying a deployment.
- [DEPLOY-FROM-RELEASES.md](DEPLOY-FROM-RELEASES.md): run a published
  release from a repository of your own deployment files, without forking.
- [OPERATIONS.md](OPERATIONS.md): rolling and rolling back releases,
  rotating secrets, health endpoints, excluding test traffic.

## Configuration and detection

- [POLICY.md](POLICY.md): an index to `policy.yaml`, `$VAR` references,
  environment overrides and `forgd-verdict policy`.
- [DETECTORS.md](DETECTORS.md): every detector and rule, with its gating,
  severity and failure behaviour.
- [CREDENTIALS.md](CREDENTIALS.md): every credential, where it comes from,
  and where it goes.
- [OVERRIDES.md](OVERRIDES.md): runtime overrides that a dashboard admin
  changes without a release: turning them on, the permissions, signing
  keys, and what failure looks like.
- [PLUGINS.md](PLUGINS.md): adding a detector, store or sink as an
  allowlisted plugin.

## Security and privacy

- [SECURITY-MODEL.md](SECURITY-MODEL.md): what can block, the trust
  boundaries, how each part fails, and the store identities.
- [PRIVACY.md](PRIVACY.md): the privacy invariant, the hash salt, and what
  is stored where.
- [RELEASING.md](RELEASING.md): the repository settings that decide who
  can publish a release or deploy a fork, and what they leave open.
- [../SECURITY.md](../SECURITY.md): reporting a vulnerability.

## Reference

- [SERVER.md](SERVER.md): the verdict server and the scan core.
- [PLATFORM.md](PLATFORM.md): the other adapters, the findings store and
  the dashboard.
- [CONNECTOR.md](CONNECTOR.md): the read-only MCP connector over the
  findings store, and how to deploy it.
- [AGENT-BUILDERS.md](AGENT-BUILDERS.md): scanning agents you build
  yourself through `/scan`.
- [PROTOCOL.md](PROTOCOL.md): the Anthropic protocol and gitleaks CLI facts
  the code depends on.
- [BENCH.md](BENCH.md): measured latency, throughput and precision.

## Deployment wrappers

- [deploy/terraform/README.md](../deploy/terraform/README.md): the
  Terraform modules and how they compose.
- [deploy/helm/README.md](../deploy/helm/README.md): the Helm chart.
- [deploy/MDM.md](../deploy/MDM.md): distributing the Claude Code hook as a
  managed hook through Intune or Jamf.

## Design notes

How things work inside, and why. None of them is needed to deploy or run
forgd-verdict.

- [DESIGN.md](DESIGN.md): why the parts are shaped the way they are.
- [design/overrides.md](design/overrides.md): the runtime overrides
  protocol, the head anchor, the lockout checks and the per-cloud IAM
  reasoning.
- [design/connector.md](design/connector.md): what the sources say about
  Claude's connectors, MCP and the SDK, and the connector's open questions.

## Project

- [../CONTRIBUTING.md](../CONTRIBUTING.md): development setup, tests and
  conventions.
