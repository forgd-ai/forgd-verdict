#!/usr/bin/env bash
# Deploy every forgd-verdict service on GCP from one commit.
#
# The GCP counterpart of deploy_aws.sh: CI is a thin caller, and the same
# command runs locally when CI is broken. Nothing here calls terraform.
# Terraform owns the infrastructure; this script owns which image runs.
#
# Ordering and failure semantics:
#   check the environment -> every missing variable is named at once, before
#                            anything is built
#   build both images     -> refuses to push an unrunnable image, and fails
#                            before any service is touched if the ingest
#                            image's Presidio tier does not load
#   push                  -> retried; a fresh IAM grant propagates lazily
#
# cloudrun (deploy/terraform/modules/app-cloudrun):
#   each update replaces the image and nothing else. Every other field of
#   the service or job stays as Terraform last set it.
#   update verdict        -> the DLP gate. `gcloud run services update` waits
#                            for the new revision to serve; a revision that
#                            never becomes ready fails the update and traffic
#                            stays on the old one. Then verify_deployment.sh
#                            runs against the verdict server alone. A failure
#                            stops the release with only this service on the
#                            new image.
#   update collector, then intake if configured, then dashboard, then the
#   connector if configured
#   verify the stack      -> every deployed URL, the dashboard behind IAP, and
#                            the connector's MCP URL when it is configured
#   update the ingest job -> the next scheduled execution runs the new image.
#
# gke (deploy/helm/forgd-verdict):
#   get-credentials       -> through the cluster's DNS endpoint. From a hosted
#                            GitHub runner that needs cluster-gke's
#                            dns_endpoint_allow_external_traffic = true; the
#                            alternative is a self-hosted runner in the VPC.
#   helm upgrade          -> one upgrade sets both tags and reuses every other
#                            value. It rolls every Deployment at the same time;
#                            the chart has no verdict-first ordering, so there
#                            is no pre-rollout gate on GKE. --wait returns once
#                            the new pods are ready.
#   verify the stack      -> after every service has already moved, with the
#                            connector's MCP URL when FORGD_CONNECTOR_URL is
#                            set. A failure fails the release but does not
#                            undo the upgrade.
#
# The verdict-first gate never checks the connector: it has not been rolled
# yet, so FORGD_CONNECTOR_URL is cleared for that one call.
#
# Requires an authenticated gcloud (CI: the ci-gcp account via Workload
# Identity Federation).
set -euo pipefail

usage() {
  cat <<'EOF'
usage: deploy_gcp.sh <sha>

Builds <image>:<sha> and <image>:<sha>-ingest, pushes both to
Artifact Registry and rolls them onto a Cloud Run or GKE deployment.

Always required:
  GCP_PROJECT_ID           the project the services, job or cluster are in
  GCP_ARTIFACT_REPOSITORY  <location>-docker.pkg.dev/<project>/<repository>
  GCP_DEPLOY_TARGET        cloudrun or gke
  FORGD_VERDICT_URL        verdict server base URL, e.g. https://verdict.example.com
  FORGD_COLLECTOR_URL      collector base URL (gke: may be empty if not deployed)
  FORGD_DASHBOARD_URL      dashboard base URL (gke: may be empty if not deployed)

Optional:
  FORGD_IMAGE_NAME         <image>, the image name within the repository
                           (default forgd-verdict)
  GCP_IMAGE_PLATFORM       docker build platform (default linux/amd64; cloudrun
                           runs linux/amd64 only)
  GCP_ALLOW_CROSS_BUILD    set to build for another architecture than the host's
  FORGD_CONNECTOR_URL      the findings connector's MCP URL, checked after the
                           rollout (cloudrun: required with
                           GCP_RUN_CONNECTOR_SERVICE, refused without it)
  FORGD_INTAKE_URL         the intake's base URL, checked for a 401 rather than
                           a sign-in after the rollout; empty: not checked

cloudrun (names from the app-cloudrun stack):
  GCP_REGION               the Cloud Run region
  GCP_RUN_VERDICT_SERVICE
  GCP_RUN_COLLECTOR_SERVICE
  GCP_RUN_DASHBOARD_SERVICE
  GCP_RUN_INTAKE_SERVICE   empty or unset: no intake
  GCP_RUN_CONNECTOR_SERVICE  empty or unset: no connector
  GCP_RUN_INGEST_JOB       ingest_job_name

gke:
  GCP_GKE_CLUSTER          cluster name, for the kubeconfig
  GCP_GKE_LOCATION         cluster region or zone
  GCP_GKE_RELEASE          helm release name
  GCP_GKE_NAMESPACE        release namespace
  GCP_GKE_CHART            optional; default deploy/helm/forgd-verdict

Run from the repository root.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") usage >&2; exit 2 ;;
esac
TAG="$1"

# Next to this script, not relative to $PWD: CI runs `scripts/deploy_gcp.sh`
# from the repo root and an operator runs it from wherever they are.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="${HERE}/verify_deployment.sh"

say() { printf '\n==> %s\n' "$*"; }
die() { echo "deploy_gcp.sh: $*" >&2; exit 1; }

# --- the environment, all of it, before anything is built ---------------
missing=()
need() { local v; for v in "$@"; do [ -n "${!v:-}" ] || missing+=("$v"); done; }
# Set, but may be empty ("not deployed here").
need_set() { local v; for v in "$@"; do [ -n "${!v+x}" ] || missing+=("$v"); done; }

need GCP_PROJECT_ID GCP_ARTIFACT_REPOSITORY GCP_DEPLOY_TARGET FORGD_VERDICT_URL
TARGET="${GCP_DEPLOY_TARGET:-}"
case "$TARGET" in
  cloudrun)
    need FORGD_COLLECTOR_URL FORGD_DASHBOARD_URL GCP_REGION \
      GCP_RUN_VERDICT_SERVICE GCP_RUN_COLLECTOR_SERVICE GCP_RUN_DASHBOARD_SERVICE \
      GCP_RUN_INGEST_JOB
    if [ -n "${GCP_RUN_CONNECTOR_SERVICE:-}" ]; then
      need FORGD_CONNECTOR_URL
    elif [ -n "${FORGD_CONNECTOR_URL:-}" ]; then
      die "FORGD_CONNECTOR_URL is set but GCP_RUN_CONNECTOR_SERVICE is not; set it to roll the connector, or unset FORGD_CONNECTOR_URL"
    fi
    ;;
  gke)
    need_set FORGD_COLLECTOR_URL FORGD_DASHBOARD_URL
    need GCP_GKE_CLUSTER GCP_GKE_LOCATION GCP_GKE_RELEASE GCP_GKE_NAMESPACE
    ;;
  "") ;;
  *) die "GCP_DEPLOY_TARGET is '${TARGET}'; it must be cloudrun or gke" ;;
esac
if [ ${#missing[@]} -gt 0 ]; then
  die "required and not set: ${missing[*]} (see -h)"
fi

REGISTRY="${GCP_ARTIFACT_REPOSITORY%%/*}"
[[ "$REGISTRY" == *-docker.pkg.dev ]] && [ "$REGISTRY" != "$GCP_ARTIFACT_REPOSITORY" ] \
  || die "GCP_ARTIFACT_REPOSITORY '${GCP_ARTIFACT_REPOSITORY}' is not <location>-docker.pkg.dev/<project>/<repository>"
REPO="${GCP_ARTIFACT_REPOSITORY}/${FORGD_IMAGE_NAME:-forgd-verdict}"

PLATFORM="${GCP_IMAGE_PLATFORM:-linux/amd64}"
ARCH="$(printf '%s' "$PLATFORM" | cut -d/ -f2)"
if [ "$TARGET" = cloudrun ] && [ "$PLATFORM" != linux/amd64 ]; then
  die "GCP_IMAGE_PLATFORM is '${PLATFORM}'; Cloud Run runs linux/amd64 only"
fi
# Refused here rather than as `exec format error` halfway through a build:
# an arm64 stack needs an arm64 runner (ubuntu-24.04-arm), or QEMU set up
# before this runs.
case "$(uname -m)" in
  x86_64|amd64) HOST_ARCH=amd64 ;;
  aarch64|arm64) HOST_ARCH=arm64 ;;
  *) HOST_ARCH="$(uname -m)" ;;
esac
if [ "$HOST_ARCH" != "$ARCH" ] && [ -z "${GCP_ALLOW_CROSS_BUILD:-}" ]; then
  die "building ${PLATFORM} on a ${HOST_ARCH} host: use a ${ARCH} runner, or set GCP_ALLOW_CROSS_BUILD=1 once QEMU/buildx is set up"
fi
IMAGE="${REPO}:${TAG}"
# Adapter 3 runs a larger image: the same scan core plus the Presidio T2
# tier, the same tag with a suffix, built from the same commit here.
INGEST_IMAGE="${REPO}:${TAG}-ingest"
COLLECTOR_URL="${FORGD_COLLECTOR_URL:-}"
DASHBOARD_URL="${FORGD_DASHBOARD_URL:-}"
CONNECTOR_URL="${FORGD_CONNECTOR_URL:-}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Fresh IAM grants propagate lazily. Retry auth-shaped failures rather than
# failing the first deploy of a new environment.
retry_auth() {
  local attempt=1 max=6
  until "$@"; do
    if [ $attempt -ge $max ]; then
      echo "still failing after $max attempts: $*" >&2
      return 1
    fi
    echo "auth/permission not ready (attempt $attempt/$max) — retrying in 20s"
    sleep 20
    attempt=$((attempt + 1))
  done
}

# --- build and push -------------------------------------------------------
say "building ${IMAGE} (${PLATFORM})"
DOCKER_BUILDKIT=1 docker build --platform "$PLATFORM" \
  -f deploy/Dockerfile --build-arg FORGD_BUILD_COMMIT="$TAG" \
  --target base -t "$IMAGE" .

say "building ${INGEST_IMAGE} (${PLATFORM})"
# Built before anything is rolled: this stage asserts that Presidio's model
# loads and that the entity identifiers in policy.yaml are ones it
# recognises.
DOCKER_BUILDKIT=1 docker build --platform "$PLATFORM" \
  -f deploy/Dockerfile --build-arg FORGD_BUILD_COMMIT="$TAG" \
  --target ingest -t "$INGEST_IMAGE" .

for img in "$IMAGE" "$INGEST_IMAGE"; do
  arch="$(docker image inspect "$img" --format '{{.Architecture}}')"
  [ "$arch" = "$ARCH" ] || die "refusing to push a ${arch} image (${img}); the build is ${PLATFORM}"
done

# The credential helper and push are one auth boundary: push exercises
# authorization when it uploads layers, so retry them together.
push_images() {
  gcloud auth configure-docker "$REGISTRY" --quiet >/dev/null \
    && docker push "$IMAGE" >/dev/null \
    && docker push "$INGEST_IMAGE" >/dev/null
}
retry_auth push_images
say "pushed ${IMAGE} and ${INGEST_IMAGE}"

# --- gke ------------------------------------------------------------------
if [ "$TARGET" = gke ]; then
  export KUBECONFIG="${WORK}/kubeconfig"
  gcloud container clusters get-credentials "$GCP_GKE_CLUSTER" --location "$GCP_GKE_LOCATION" \
    --project "$GCP_PROJECT_ID" --dns-endpoint >/dev/null
  say "helm upgrade ${GCP_GKE_RELEASE} (${GCP_GKE_NAMESPACE})"
  helm upgrade "$GCP_GKE_RELEASE" "${GCP_GKE_CHART:-deploy/helm/forgd-verdict}" \
    --namespace "$GCP_GKE_NAMESPACE" --reset-then-reuse-values \
    --set "image.repository=${REPO}" --set "ingest.image.repository=${REPO}" \
    --set "image.tag=${TAG}" --set "ingest.image.tag=${TAG}-ingest" --wait

  say "verifying the deployed stack"
  FORGD_CONNECTOR_URL="$CONNECTOR_URL" FORGD_DASHBOARD_IAP=1 \
    "$VERIFY" "$FORGD_VERDICT_URL" "$COLLECTOR_URL" "$DASHBOARD_URL"
  say "deployed ${TAG}"
  exit 0
fi

# --- cloudrun: the DLP gate first, proven before anything else is touched -
update_service() {
  local role="$1" service="$2"
  say "updating ${role} (${service})"
  gcloud run services update "$service" --image="$IMAGE" \
    --region="$GCP_REGION" --project="$GCP_PROJECT_ID" --quiet
}

started=$SECONDS
update_service verdict "$GCP_RUN_VERDICT_SERVICE"

say "smoke: ${FORGD_VERDICT_URL}"
# The verifier waits for a replica younger than this roll before asserting
# anything, so a 401 from the instance being replaced cannot pass the gate.
# The other two are passed empty, and the connector cleared, because they
# have not been rolled yet.
FORGD_CONNECTOR_URL="" FORGD_INTAKE_URL="" VERIFY_MAX_UPTIME_S=$((SECONDS - started + 60)) "$VERIFY" "$FORGD_VERDICT_URL" "" ""

update_service collector "$GCP_RUN_COLLECTOR_SERVICE"
if [ -n "${GCP_RUN_INTAKE_SERVICE:-}" ]; then
  update_service intake "$GCP_RUN_INTAKE_SERVICE"
fi
update_service dashboard "$GCP_RUN_DASHBOARD_SERVICE"
if [ -n "${GCP_RUN_CONNECTOR_SERVICE:-}" ]; then
  update_service connector "$GCP_RUN_CONNECTOR_SERVICE"
fi

say "verifying the deployed stack"
FORGD_CONNECTOR_URL="$CONNECTOR_URL" FORGD_DASHBOARD_IAP=1 \
  "$VERIFY" "$FORGD_VERDICT_URL" "$COLLECTOR_URL" "$DASHBOARD_URL"

say "updating ingest (${GCP_RUN_INGEST_JOB})"
gcloud run jobs update "$GCP_RUN_INGEST_JOB" --image="$INGEST_IMAGE" \
  --region="$GCP_REGION" --project="$GCP_PROJECT_ID" --quiet
echo "  next scheduled run uses ${TAG}-ingest"

say "deployed ${TAG}"
