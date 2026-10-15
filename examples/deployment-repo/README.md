# forgd-verdict deployment

This repository deploys [forgd-verdict](https://github.com/forgd-ai/forgd-verdict)
from its public releases, to AKS. It holds only this deployment's files;
the code, images, chart and Terraform modules are published by
forgd-verdict.

Start from the copy of this skeleton at the tag of the release you run,
and follow forgd-verdict's
[docs/DEPLOY-FROM-RELEASES.md](https://github.com/forgd-ai/forgd-verdict/blob/main/docs/DEPLOY-FROM-RELEASES.md)
to set it up.

| Path | What it is |
|---|---|
| `release.yaml` | The release this deployment runs, and its chart version |
| `policy.yaml` | The policy, passed to the chart as `policy.inline` |
| `values.yaml` | Helm values, without identifiers |
| `infra/` | The Terraform root: the store, the cluster and the deploy identity's grants, from the release's modules |
| `.github/workflows/ci.yml` | Checks the policy, values and Terraform against the release on every pull request |
| `.github/workflows/deploy.yml` | Rolls the release, dispatch only |

## Moving to a new release

In one pull request, set the new `version` and `chart` in `release.yaml`
and each module's `?ref=v<version>` in `infra/main.tf`. `ci.yml` checks
them against the new release. Merge it, then run `deploy`.

## Rolling

Actions, then `deploy`, then Run workflow, on `main`. It imports the
release's images into your registry (or pulls them from ghcr.io), runs
`helm upgrade --install` from the public chart, waits for `/healthz` to
report the release, and runs `forgd-verdict verify-deployment` from the
same release.
