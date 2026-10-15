# Deploying from releases, without forking

There are two ways to run forgd-verdict.

- **Fork this repository** and deploy from your fork. The deploy scripts
  build the images from your tree and push them to your registry. Choose
  this when you change the code: a detector of your own that a
  [plugin](PLUGINS.md) cannot express, or a patch you need before it is
  released.
- **Keep a deployment repository** that holds only your own files (your
  policy, Helm values, a Terraform root and two workflows) and runs a
  published release. The images come from `ghcr.io/forgd-ai/forgd-verdict`,
  the chart from `oci://ghcr.io/forgd-ai/charts/forgd-verdict`, the
  Terraform modules from this repository at the release's tag, and the
  policy check and the deployment verifier from the `forgd-verdict` package
  on PyPI at the same version. Choose this when you run forgd-verdict as
  released. Moving to a new release is a pull request that changes one
  version number and three module refs.

[`examples/deployment-repo`](../examples/deployment-repo) is a skeleton of
the second, for AKS. It is moved to each release as part of cutting it, so
the copy at a release's tag runs that release.

## What the skeleton holds

| Path | What it is |
|---|---|
| `release.yaml` | The release this deployment runs, and its chart version |
| `policy.yaml` | The policy, passed to the chart with `--set-file policy.inline`. In this repository it links to the shipped `policy.yaml`; copy the file, not the link |
| `values.yaml` | Helm values without identifiers: the ingress, the dashboard's sign-in, the Secret's name and the service accounts' names |
| `infra/` | A Terraform root: [`examples/aks`](../deploy/terraform/examples/aks) with its three modules sourced by git ref at the release's tag, and `access.tf`, which grants the deploy workflow's identity what a roll needs |
| `.github/workflows/ci.yml` | On every pull request: the policy passes the release's `forgd-verdict policy --check`, the release's chart renders with `values.yaml`, and `infra/` validates with the release's modules |
| `.github/workflows/deploy.yml` | Dispatch only: rolls the release to the cluster, checks `/healthz` reports it, and runs the release's `forgd-verdict verify-deployment` |

Other clouds follow the same shape. Compose the store, app or cluster
modules your target needs ([DEPLOY.md § Choose a target](DEPLOY.md#choose-a-target))
in `infra/` by git ref, the way [deploy/terraform/README.md](../deploy/terraform/README.md)
shows, and change the sign-in and image steps of `deploy.yml` for your
cloud. The release's images are on GHCR, so any cluster that can pull from
it, or from your mirror of it, can run them.

## Setting it up

1. **Copy the skeleton** from the tag of the release you want to run into
   a new private repository, replacing the `policy.yaml` link with the
   file. Edit `policy.yaml` for your organizations; [POLICY.md](POLICY.md)
   describes every section. Set `ingress.host` and the oauth2-proxy URLs
   in `values.yaml`.
2. **Create the state backend and the identities.** In Azure,
   `scripts/bootstrap_tfstate.sh` and `scripts/bootstrap_target_rg.sh`,
   run from a checkout of this repository at the tag, create the state account, the identity that
   applies Terraform and the resource group the stack deploys into
   ([DEPLOY.md § Order of operations](DEPLOY.md#order-of-operations)).
   Create a user-assigned identity for the deploy workflow too, with a
   federated credential whose subject is
   `repo:<owner>/<repo>:environment:deploy`.
3. **Decide where the deploy workflow runs.** It needs the cluster's API
   server. `infra/` builds a private cluster by default, which a
   GitHub-hosted runner cannot reach. Either run the workflow on a
   self-hosted runner in the cluster's network (the `DEPLOY_RUNNER`
   variable names its label), or apply `infra/` with
   `private_cluster_enabled = false` and `api_server_authorized_ip_ranges`
   covering the addresses your runner uses.
4. **Apply `infra/`.** Pass `cd_identity_name` and
   `cd_identity_resource_group_name` for the deploy identity, and
   `cluster_admin_principal_ids` for the people who will run `kubectl` by
   hand. Pass `registry_id` to have the images copied into your own
   registry: the deploy identity then gets a role to import into it and
   `AcrPull` to read each image's digest back. Leave it empty to pull from
   GHCR.
5. **Prepare the cluster** as one of those admins: give it a hostname and
   a certificate (`scripts/bootstrap_aks.sh`, [Standing up a
   cluster](../deploy/helm/README.md#standing-up-a-cluster)), put
   oauth2-proxy in front of the dashboard ([Putting oauth2-proxy in
   front](../deploy/helm/README.md#putting-oauth2-proxy-in-front)), and
   create the namespace (`infra/`'s `namespace`, `forgd` by default) and
   the Secret `values.yaml` names, with
   the keys [§ Secrets](../deploy/helm/README.md#secrets) lists. The deploy
   identity can write only inside that namespace, so it cannot create it.
6. **Create the `deploy` environment** in the repository's settings.
   Limit it to `main`, so a workflow on another branch cannot use the
   identity its federated credential names, and add required reviewers if
   a roll should wait for approval. Set the variables `deploy.yml`'s header
   lists: sign-in, the cluster, the runner and namespace if they are not
   the defaults, `AZURE_ACR` if you mirror, and the identifiers from
   `infra/`'s outputs. None of them is a secret.
7. **Run `deploy`** from the Actions tab.

## Moving to a new release

In one pull request:

- `release.yaml`: the new `version`, and the `chart` whose `appVersion`
  it is, which `examples/deployment-repo/release.yaml` at the tag names;
- `infra/main.tf`: each module's `?ref=v<version>`.

`ci.yml` then checks the policy, the values and the Terraform root against
the new release before anything is rolled. It fails when the module refs
or the chart's `appVersion` disagree with `release.yaml`'s version. Compare your `values.yaml` and `infra/` with the
skeleton at the new tag: the skeleton's diff between two tags is what
changed in the inputs the release expects.

Merge it, apply `infra/` if its plan has changes, and run `deploy`.

## What the checks see and what they do not

`forgd-verdict policy --check` builds each role from the policy the way
its entry point does and refuses what the role would refuse at start
([POLICY.md](POLICY.md)). CI runs it with a placeholder for every
`$VAR` outside a comment in the policy, so it shows the release accepts the policy's
shape. It cannot show that the values in your Secret are right, that a
detector is reachable, or that the store accepts the workloads' identity.

`deploy.yml` checks that `/healthz` reports `<version>+<commit>` before it
verifies. Old pods keep serving while new ones fail to pull, so a passing
verify alone does not show the roll landed. `verify-deployment` then
checks each service answers and refuses what it should
([DEPLOY.md § Verify the deployment](DEPLOY.md#verify-the-deployment)).
