# Contributing

Thanks for working on forgd-verdict. This page covers setting up, running
the checks CI runs, and the conventions a change is reviewed against. The
full conventions, written for people and for coding agents alike, are in
[CLAUDE.md](CLAUDE.md).

Report a vulnerability as described in [SECURITY.md](SECURITY.md), not in a
public issue.

## Setup

You need Python 3.11 or later and [uv](https://docs.astral.sh/uv/). CI
tests on 3.11, 3.12 and 3.13.

```bash
uv sync --all-extras
```

`uv.lock` is not committed. The hashed, pinned set for everything that
ships, the images and the wheels, is `deploy/constraints/*.txt`, generated
by `scripts/compile_constraints.sh`. A universal lock cannot match those
pins while the `ml` extra's `llm-guard` pins `presidio-analyzer` and
`regex` exactly, so `uv sync` resolves its own versions for development.

`gitleaks`, `helm` and `terraform` are optional locally. The tests that
need one skip when it is missing (see [Terraform and Helm](#terraform-and-helm)).

## Running the suite

```bash
uv run pytest -q                  # conformance, signature, privacy, incremental
uv run python loadtest.py --help  # latency harness
```

* **Protocol conformance:** golden frames (text, tool_use/tool_result,
  attachments, null fields, unknown block type, unknown top-level type,
  config-test), verdict shape for each, dedupe on repeated `webhook-id`.
* **Signature vectors:** valid, wrong secret, expired and future timestamp,
  multi-candidate header, rotated pair, raw-bytes requirement, standard vs
  URL-safe base64, malformed secret.
* **Privacy:** seeded secrets must appear in no log line, CSV cell, metrics
  value, or verdict field.
* **Incremental:** a 50-turn synthetic session delivered as cumulative
  frames stays roughly flat in per-frame scan time after frame 1; shrunk,
  null-session and shifted-prefix cases fall back to a full scan with correct
  results.

## Lint and layering

```bash
uv run ruff check src tests loadtest.py deploy/assert_presidio.py
uv run python scripts/import_graph.py --check
```

`import_graph.py --check` fails on a module importing one from a higher
layer, unless it is listed in `KNOWN_UPWARD`. It also fails on a stale
`KNOWN_UPWARD` entry, a file that will not parse, an unresolvable import,
and a top-level module missing from `LAYERS`.

## Terraform and Helm

CI pins Terraform `1.9.8` (`TERRAFORM_VERSION` in
`.github/workflows/ci.yml`) and Helm `3.19.0`. It runs `terraform fmt
-check` and `terraform validate` on every module and example, and the
Python tests render the modules and the chart.

Tests that need a binary skip when it is missing. In CI a missing binary
fails the run instead: the Validate Terraform step fails when `terraform`
is not installed, and later steps check that the chart and gitleaks tests
did not skip. With `CI` set, the Terraform rendering tests also fail
rather than skip on a terraform older than 1.7 or a module whose providers
were never initialised (`_require` in `tests/terraform_render.py`).

Run the module tests under Terraform 1.9.8 before pushing a module change:
which values are known at plan time differs between versions, so a test
that passes on another release can fail in CI.

## CI

`.github/workflows/ci.yml` runs pytest on 3.11–3.13, ruff, CLI smoke tests,
a gitleaks scan of both the tree and the full history, a Docker build plus
container smoke test (signed golden frame → 200, unsigned → 401), and a
bare install with no extras: every other job installs `.[dev]`, so without
it a broken default path ships unnoticed. It also validates the workflow
files, checks the layering, lints the Helm chart, checks that the gitleaks
sidecar and the subprocess agree, and builds both wheels.

**No repository secrets are required:** every test is offline, and
signatures are minted inside the job. If CI ever needs a secret, something
has been wired wrong.

Two choices there:

* It installs the MIT-licensed gitleaks binary, pinned by version and
  SHA-256, rather than `gitleaks/gitleaks-action`, which is `NOASSERTION`
  rather than a standard OSS licence and requires a registration-gated
  licence key for organization-owned repos.
* It asserts the T1 tests did not skip. Those tests `skipif` on a missing
  binary, so a regression in the install step would otherwise leave the suite
  green having tested nothing.

## Detectors

A false positive is a blocked user. `tests/test_detectors.py` holds the
precision tests, and a detector change ships with named false-positive
tests beside its true positives, the way
`test_ssn_false_positives_suppressed`,
`test_pan_false_positives_suppressed` and
`test_jwt_false_positives_suppressed` do.

Every detector, with its gating and severity, is in
[docs/DETECTORS.md](docs/DETECTORS.md). To add a detector without forking,
use the plugin extension point in [docs/PLUGINS.md](docs/PLUGINS.md).

## What never goes in the repository

- **Organization UUIDs.** Reference them as `$FORGD_ORG_ID_<NAME>` in
  `policy.yaml` and set the variable on the service. This also applies to
  docs, issue comments and commit messages.
- **Secrets of any kind**, including the signing secret, access keys,
  tokens and `privacy.hash_salt`. They belong in the platform's secret
  store.
- **Matched content.** A matched secret or PII value never reaches a log,
  a finding, a `reference_id` or a deny reason: only the detector name, a
  locator and a one-way digest. `tests/test_privacy.py` enforces it, and
  [docs/PRIVACY.md](docs/PRIVACY.md) explains it.

Test fixtures use well-known fake values, such as `AKIAIOSFODNN7EXAMPLE`.
A fixture that needs a private key, a `Basic` or `Bearer` header or a
connection string with a password builds it from pieces,
`"-----BEGIN " + "RSA PRIVATE KEY-----"`: GitHub secret scanning reports
those shapes when they appear whole on one line, after the push has landed.

To catch them before a commit leaves your machine:

```bash
uvx pre-commit install
```

`.pre-commit-config.yaml` then runs gitleaks on the staged changes,
`scripts/credential_shapes.py` on the staged files and
`scripts/check_binaries.py` on each commit. It needs `gitleaks` on your
`PATH`. CI runs the same checks in the `secret scan` job.

## Commits and pull requests

Work on a branch and open a pull request against `main`.

- Commit messages say what changed and why it was not obvious.
- Comments say what the code does. The reasoning behind a choice belongs
  in the commit that made it. Two exceptions: a comment may state a
  non-obvious mechanism a reader needs to follow the code, and a comment
  explaining a bug that was actually hit says what the bug did.
- No marketing register in code, docs or commits.
- `forgd` is always lowercase.

## Signing off commits

Pull requests to the public repository, `forgd-ai/forgd-verdict`, need a
sign-off on every commit:

```bash
git commit -s
```

`-s` adds a `Signed-off-by: Your Name <you@example.com>` trailer from your
`user.name` and `user.email`. It certifies the
[Developer Certificate of Origin](https://developercertificate.org): that
you wrote the change or have the right to submit it under the project's
license. The trailer must name the commit's author exactly, on merge
commits too (`git merge --signoff`). A `Co-authored-by:` trailer needs no
sign-off of its own.

Two kinds of commit need no sign-off:

- **Dependabot commits.** In a pull request opened by `dependabot[bot]`,
  a commit whose author email is exactly
  `49699333+dependabot[bot]@users.noreply.github.com` passes whatever its
  trailer says. Dependabot signs off as `support@github.com`, which never
  matches its author address. Run locally, the check exempts no commit
  this way unless `PR_AUTHOR_LOGIN=dependabot[bot]` is set.
- **Clean merges.** GitHub's "Update branch" button makes a merge commit
  with no sign-off. A two-parent merge passes when
  `git show --remerge-diff` shows nothing, that is, when it adds nothing
  beyond an automatic merge of its parents. A merge that resolves a
  conflict or adds a change of its own still needs
  `git merge --signoff`. The check needs git 2.36 or later.

`scripts/check_dco.sh <base> <head>` runs the same check locally, for
example `scripts/check_dco.sh origin/main HEAD`. To add a missing sign-off:

```bash
git commit --amend -s --no-edit     # the last commit
git rebase --signoff origin/main    # every commit on the branch
```

then force-push the branch.

## Releasing

A `v*` tag publishes a release, and in a fork that copies
`examples/github/deploy.yml`, deploys one. Who can do either is decided by
repository settings, not by the workflows: a `v*` tag ruleset and the
environments' required reviewers and tag limits.
[docs/RELEASING.md](docs/RELEASING.md) lists them.

## Versioning

Semver tracks the rule set, not the Python API. A detector change is a
minor; a deployment or docs change is a patch. The running build is
reported at `GET /healthz` and stamped on every finding as `build`. See
[README.md § Versioning](README.md#versioning).
