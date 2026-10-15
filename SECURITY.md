# Security policy

## Reporting a vulnerability

Report it privately, by either route:

- on GitHub, from this repository's **Security** tab: **Report a
  vulnerability**. The report is visible only to you and the maintainers;
- by email to **security@forgd.ai**.

Do not open a public issue, discussion or pull request for a
vulnerability. Include the version or commit, the component, the steps to
reproduce, and what an attacker gains. If the report involves a matched
secret or personal data, describe the shape of it rather than sending a
real value.

## How a fix is made

A vulnerability is fixed in private until it is released. The maintainers
open a draft security advisory for it and develop the fix in the
advisory's temporary private fork, which only the maintainers and the
people they invite can see, the reporter included. The fix does not
appear as a public branch or pull request.

The fix ships as a patch release, cut as in
[docs/RELEASING.md](docs/RELEASING.md). Once it is published, the
advisory is published with it, naming the affected and fixed versions,
and credits the reporter unless they ask not to be named.

## Supported versions

Only the latest minor release receives security fixes. Each release and
its changes are listed on this repository's GitHub Releases page, with
the digests of its images and Helm chart and the sha256 of its wheels.

## Scope

In scope:

- the verdict server (adapter 1)
- the Claude Code hook (adapter 2)
- the OTel collector (adapter 4)
- the intake service
- the dashboard
- the findings connector
- the Helm chart in `deploy/helm/`
- the Terraform modules in `deploy/terraform/`
- the privacy invariant: a matched secret or PII value reaching a log, a
  finding, a `reference_id` or a deny reason, in any component. See
  [docs/PRIVACY.md](docs/PRIVACY.md).

Out of scope:

- Anthropic's platform, including Inference hooks, the Compliance API and
  OpenTelemetry export. Report those to Anthropic.
- A deployer's own cloud misconfiguration, such as a platform auth
  provider in front of the verdict server, a store left publicly
  readable, or secrets written into Terraform state. Where the chart or a
  module accepts a configuration that silently weakens a guarantee it
  documents, that is in scope.
- A detector missing a value it was not designed to match. Report false
  negatives and false positives as ordinary issues. The detection rules
  are in [docs/DETECTORS.md](docs/DETECTORS.md).

How the components trust each other is in
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).
