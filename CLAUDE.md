# forgd-verdict — working conventions

## Who this is for

Whoever runs this forks it and deploys it themselves, into their own
cloud, against their own Claude organizations, writing to their own store.

Two things follow, and both are easy to forget:

**Our defaults become their defaults.** A default that is only safe because
we know about it is a bug. Prefer refusing to start, or warning loudly, over
a quiet value that happens to work here.

**Multi-org is not multi-tenant.** One deployment serves one operator, who
may hold several organizations or Team workspaces (prod and dev,
subsidiaries, regions). It is never several unrelated parties sharing a
store, so segregation between orgs is the operator's preference, not a
boundary we must enforce.

A Team workspace has an org UUID like an Enterprise org, but no Compliance
API, so adapter 3 cannot serve it and adapter 4 is its only fleetwide
visibility. Different coverage per org is legitimate, not a gap.

## Never commit

**Organization UUIDs.** An org id is not a credential, but it identifies
whoever owns the organization, and a repo is the wrong place to enumerate which organizations a
deployment serves. Reference them as `$FORGD_ORG_ID_<NAME>` in `policy.yaml`
and set the variable on the service. `tests/test_org_partition.py` pins this
for `policy.yaml`; nothing pins it anywhere else, so be careful in docs,
issue comments and commit messages.

**Secrets of any kind**: the Anthropic signing secret, the Compliance Access
Key, per-org OTel tokens, the metrics token, `privacy.hash_salt`. These live
in the container app's secret store and nowhere else: not in GitHub, not in
a file, not pasted into a conversation. `SECRET_PATHS` / `SECRET_LIST_PATHS`
in `policy.py` keep them off the dashboard's Policy tab; add new ones there.

**Matched content.** The privacy invariant: a matched secret or PII value
never reaches a log, a finding, a `reference_id`, or a deny reason. Detector
name, locator and a one-way digest only.

**Credential-shaped fixtures, written out whole.** A test that needs a
token, a private key or an auth header builds it from pieces:
`"glpat-" + "..."`, `"-----BEGIN " + "RSA PRIVATE KEY-----"`,
`"Bearer " + "..."`. GitHub secret scanning reads each line as written. It
blocks a provider token at push, but a private key, a `Basic` or `Bearer`
header or a connection string with a password goes through and raises an
alert afterwards. `scripts/credential_shapes.py` finds the shapes gitleaks
does not; `.pre-commit-config.yaml` runs it, with gitleaks and the binary
check, on each commit once `pre-commit install` has been run.

## How work lands

Branch, then a PR against `main`.

Semver tracks the rule set, not the Python API. A detector change is a
minor; a deployment or docs change is a patch. Do not default to minor.

## Things that are load-bearing and look optional

- **No platform auth on the verdict server or the collector.** Anthropic
  authenticates with a signature and an OTLP header respectively; an auth
  redirect turns every governed prompt or export into a delivery failure.
  `verify_deployment.sh` runs on every roll and rejects a response that
  redirects to a login page. That catches the usual misconfiguration but
  does not prove the rule holds: a provider set to answer 401 rather than
  redirect looks the same as the app's own refusal. Do not read a passing
  verify as evidence that platform auth is off.
- **`otel.orgs[].id`:** with it empty the cross-check against the payload's
  `organization.id` cannot run, and any org's batch is accepted on a valid
  token.
- **Do not grant `delete:compliance_user_data`** on a Compliance Access Key.
- **`ENV_OVERRIDES` must never reach `detectors` or `privacy`**. A test
  enforces it. Detection behaviour is not environment-tunable.

## Brand

`forgd` is always lowercase, including at the start of a sentence, in docs
and in the README.

## Writing

Commit messages say what changed and why it was not obvious.

Comments say what the code does. The reasoning behind a choice belongs in
the commit that made it, where it is dated and attached to a diff; beside
the code it outlives the decision and nobody re-checks it. Two exceptions:
a comment may state a non-obvious mechanism a reader needs to follow the
code, and a comment explaining a bug that was actually hit says what the
bug did.

No marketing register, no contrastive reframes ("it isn't X, it's Y"), no
aphorisms.

## Writing in this repository

This applies to everything written here: commit messages, PR titles and
descriptions, issue and review comments, branch names and code comments.

**Never name:**

- a private repository, or its issue or PR numbers. Refer only to public
  issues and PRs in this repository.
- a private deployment, lab or environment.
- an organization, tenant, subscription or client id.
- a real deployment's hostname.
- a customer, or a person's private details.
- an internal tool or workflow.

**Changes from elsewhere.** Write up a change brought from another
repository fresh. Do not paste an upstream or private message or thread,
and do not add a "cherry-picked from" or "ported from" line.

**Names are content.** Everything under "Never name" applies to paths
too: no file or directory name carries an internal name, an id, a
hostname or an issue number.

**Binary, encoded or generated assets** (images, fonts, archives,
base64 blobs, minified or generated files) are synthetic. Anything else
needs a maintainer to review its provenance, metadata and strings and to
list it, with its hash, in `tests/allowed-binaries.txt` before it ships.

**No real data.** Tests, fixtures, docs and examples use synthetic values
only: no real org UUIDs, no tool names from a real session, no tokens, no
prompt content and no log excerpts. Use RFC example UUIDs, `example.com`,
and keys that are obviously fake and marked `gitleaks:allow`.

**The privacy invariant applies to write-ups.** An issue or PR describes a
finding by detector name, locator and digest, and never quotes its matched
content, even content that looks fake.

**Before pushing,** run the leak checks: `gitleaks git --redact` over your
branch with `.gitleaks.toml`, and a search of your diff for UUIDs and for
hostnames that are not synthetic.

**When unsure,** leave it out and ask a maintainer.
