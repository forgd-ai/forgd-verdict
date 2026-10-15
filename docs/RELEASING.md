# Releasing

A `v*` tag starts two workflows. In `forgd-ai/forgd-verdict`,
`.github/workflows/release.yml` publishes the wheels to PyPI, the images
and the chart to GHCR, and a GitHub Release. In a fork,
`examples/github/deploy.yml`, once copied to `.github/workflows/`, builds
the images and rolls the fork's own deployment.

## What the workflow checks do not stop

GitHub runs a workflow as it is in the commit that triggered it. For a tag
push, that is the tagged commit, so whoever can push a `v*` tag also
chooses the workflow file that runs for it. A check inside the workflow
holds only when the tagged commit leaves it in place.

`release.yml` checks that the tagged commit is on `main`, that the run is
in `forgd-ai/forgd-verdict`, and that no version it is about to publish
already exists on GHCR or PyPI, so a release that fails after any push is finished by
cutting the next patch version. These catch a tag on the wrong commit, a fork's tag and a
version cut twice. They do not stop someone who can push a `v*` tag, who
can remove them in the commit they tag. The repository settings below are
what decides who can publish.

## Before the first tag in forgd-ai/forgd-verdict

A maintainer with admin access configures these in the repository's
settings before the first `v*` tag is pushed.

1. **A tag ruleset on `v*`.** Under Rules → Rulesets, a tag ruleset,
   active, targeting tags that match `v*`, with "Restrict creations",
   "Restrict updates" and "Restrict deletions". Its bypass list holds only
   the release maintainers. Nobody else can create, move or delete a `v*`
   tag.
2. **Required reviewers on `pypi`.** Under Environments, `pypi` lists
   release maintainers as required reviewers, with "Prevent self-review"
   off and "Allow administrators to bypass configured protection rules"
   off. The images, chart and PyPI jobs all run in `pypi` and wait for it
   at the same time, so a release asks for one approval, and none of them
   starts until a release maintainer approves it. The GitHub Release job
   runs after all three have succeeded and has no environment. For the
   images, chart and Release this holds only while the tagged workflow
   names `pypi`, because the tag pusher chooses that file; the PyPI
   trusted publisher's environment pin (item 4) is the gate a tagged
   commit cannot remove.

   With "Prevent self-review" off, the maintainer who pushed the tag can
   approve their own release. That is the setting while the maintainers
   are few enough that waiting for another one would hold a release up.
   Turning it on makes the approver someone other than whoever started
   the run, which on a re-run is whoever clicked re-run.
3. **Deployment limited to `v*` tags.** On `pypi`, "Deployment branches
   and tags" is set to selected tags matching `v*`, with no branch. A job
   on a branch, a dispatch from a branch included, cannot use it. A dispatch from a branch runs ci and builds the
   wheels, then the images and chart jobs are refused and the run ends
   failed, having published nothing.
4. **A trusted publisher on each PyPI project, naming the `pypi`
   environment.** `forgd-verdict` and `forgd-verdict-hook` exist on PyPI.
   A maintainer adds a trusted publisher to each in the project's
   publishing settings, with owner `forgd-ai`, repository
   `forgd-verdict`, workflow `release.yml` and environment `pypi`. PyPI
   then issues an upload token only to a job running in `pypi`, which the
   settings above gate. Add both before the first tag: the PyPI job runs
   alongside the images and chart, so an upload PyPI refuses leaves the
   version on GHCR and not on PyPI, and the release is finished by cutting
   the next patch version. A failed image or chart push likewise leaves
   the version on PyPI and is finished the same way.
5. **The `@forgd-ai/forgd-verdict-maintainers` team.** `.github/CODEOWNERS`
   names it as the owner of every path. Under the organization's Teams,
   create it with the release maintainers as members, and give it Write
   access or higher on the repository. GitHub ignores a CODEOWNERS entry
   for a team that does not exist or cannot write to the repository, and
   then requests no review from it.

### What the reviewer checks before approving

The approval is the control that matters, so the reviewer confirms, for the
tagged commit:

- it is on `main`: `git merge-base --is-ancestor <sha> origin/main`;
- `.github/workflows/release.yml` at that commit is the one on `main`:
  `git diff origin/main <sha> -- .github/workflows/release.yml` prints
  nothing.

### What these settings do not cover

The images, the chart and the GitHub Release are pushed with the run's
`GITHUB_TOKEN`. An environment gates the jobs that name it, not the token:
any workflow in the repository that asks for `packages: write` or
`contents: write` gets it, on any branch. Write access to the repository
is therefore enough to push to `ghcr.io/forgd-ai` and to create a release
without the `pypi` environment. Only PyPI is behind the environment
alone. Keep write access to the repository to people who may publish.

## First release

The release publishes two GHCR packages in the `forgd-ai` organization:

- `forgd-verdict`, the images, tagged `<version>` and `<version>-ingest`;
- `charts/forgd-verdict`, the Helm chart.

Either create them before the first tag, or let the first release's push
create them.

1. **Link each package to `forgd-ai/forgd-verdict` and give the repository
   write access.** In each package's settings, under "Manage Actions
   access", add the repository with the Write role. The images carry an
   `org.opencontainers.image.source` label naming the repository, which
   links a package that the push creates. The chart does not, so check
   `charts/forgd-verdict` by hand. Without write access, the push is
   refused.
2. **Make both packages public after the first push.** A new package is
   private. Under the package's settings, "Change visibility" makes it
   public. Until then, anonymous `docker pull` and `helm pull` fail.

Before each push, the workflow looks up the version it is about to
publish. On a package that does not exist yet, GHCR might answer
"not found" or "denied". **UNCONFIRMED:** no one has seen which. The
workflow counts "denied" as absent, with a warning, only while the
repository has no GitHub Release. The last job creates one, so after the
first release a "denied" fails the run. A dispatched run skips the lookups,
so a dry run does not test this path.

## Cutting a release

`scripts/cut_release.sh` cuts a release in two steps, either side of a
pull request. Both run from a clean `main` that matches `origin/main`.

1. **Prepare.** `scripts/cut_release.sh prepare <version>` runs the tests
   and lint. It then creates `release/v<version>` and commits the bump on
   it, signed off. The core, the hook, the hook's pin and the chart's
   `appVersion` become `<version>`, and the chart's own version moves up
   one patch. It pushes the branch and prints the `gh pr create` command
   for it. It does not push `main` or tag anything.
2. **Review and merge.** Open the pull request, have it reviewed, and
   merge it like any other change.
3. **Tag.** On `main`, pulled to include the merge, run
   `scripts/cut_release.sh tag <version>`. It fetches and checks that:
   - `main` matches `origin/main`;
   - every version source in the tree reads `<version>`;
   - `v<version>` exists neither locally nor on `origin`.

   Then it creates the annotated tag and pushes the tag alone.
4. **Approve.** The tag starts `release.yml`, which runs ci and builds
   the wheels, then asks for one approval in `pypi`. That approval starts
   the images, chart and PyPI jobs together; the GitHub Release follows
   once they have succeeded. The reviewer checks the tagged commit as
   described above before approving.

## A fork's deploy workflow

`examples/github/deploy.yml` deploys on every `v*` tag pushed to the fork,
and on a manual run from any branch or tag. Its in-workflow conditions,
like the release workflow's, are part of the file the tagged commit
carries. Before copying it to `.github/workflows/`:

1. **A tag ruleset on `v*`**, as above, restricting creation, update and
   deletion to the people who may deploy.
2. **Deployment limited to `v*` tags** on `verdict-cd-azure`,
   `verdict-cd-aws` and `verdict-cd-gcp`. Each cloud identity trusts the
   job's environment by name, so this is what keeps a workflow on a branch
   from assuming it.
3. **Required reviewers** on those environments, with "Prevent
   self-review" on, for a deployment that waits for a second person. A
   tag then deploys only once someone approves it.

In a private repository, environment protection rules depend on the
GitHub plan; check which of them the fork's plan enforces before relying
on them.

## Verifying the settings

No test in this repository can see them. A `v*` tag pushed by someone
outside the ruleset's bypass list is refused before any workflow runs. On
the first release, before anyone approves, confirm that the images, chart
and PyPI jobs are waiting for review in `pypi`, with the release
maintainers as its reviewers.
