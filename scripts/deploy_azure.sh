#!/usr/bin/env bash
# Deploy every forgd-verdict service from one image.
#
# Script-first so the CI system is a thin caller: porting to Azure DevOps is
# a runner swap, and the same command runs locally when CI is broken.
#
# Ordering and failure semantics:
#   build both images     -> refuses to push an unrunnable image, and fails
#                            before any service is touched if the ingest
#                            image's Presidio tier does not load
#   push                  -> retried; a fresh AcrPush grant propagates lazily
#   update verdict server -> the DLP gate. Smoke-tested before anything else
#                            is touched, so a bad image is caught while only
#                            one service is on it.
#   update dashboard      -> read-only; safe to roll after
#   update collector      -> detection only, nothing waiting on a verdict
#   update intake         -> if AZURE_INTAKE_APP is set; laptops retry
#   update connector      -> if AZURE_CONNECTOR_APP is set; read-only
#   verify the stack      -> every rolled URL, the connector's MCP URL included
#   update ingest job     -> next scheduled run picks it up
#
# The verdict-first gate never checks the connector: it has not been rolled
# yet, so FORGD_CONNECTOR_URL is cleared for that one call.
#
# The assertions themselves are in scripts/verify_deployment.sh, which speaks
# HTTP and nothing else -- so the same checks run against a deployment on any
# other target. This script owns WHEN they run, and that ordering is the gate.
#
# Requires an authenticated az session (CI: the CD identity via OIDC).
# Usage: scripts/deploy_azure.sh <image-tag>
#
# Required:
#   AZURE_ACR             the registry name, without .azurecr.io
#   AZURE_DEPLOY_TARGET   aca or k8s. aca rolls the container apps; k8s
#                         builds and pushes the images and prints the helm
#                         roll, rolling nothing
#   AZURE_RESOURCE_GROUP  the group holding the container apps (aca only)
#   AZURE_CONTAINER_APP   the verdict server's container app (aca only)
# Optional:
#   FORGD_IMAGE_NAME      the repository within the registry (default
#                         forgd-verdict)
#   FORGD_POLICY_FILE     the policy file named in the printed helm command
#                         (default policy.yaml)
#   AZURE_COLLECTOR_APP   the collector's container app (default
#                         ca-forgd-collector); none skips it
set -euo pipefail

TAG="${1:?usage: deploy_azure.sh <image-tag>}"

# Next to this script, not relative to $PWD: CI runs `scripts/deploy_azure.sh`
# from the repo root and an operator runs it from wherever they are.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="${HERE}/verify_deployment.sh"

usage() {
  echo "deploy_azure.sh: $*" >&2
  echo "usage: AZURE_ACR=<registry> AZURE_DEPLOY_TARGET=k8s scripts/deploy_azure.sh <image-tag>" >&2
  echo "       AZURE_ACR=<registry> AZURE_DEPLOY_TARGET=aca AZURE_RESOURCE_GROUP=<group> AZURE_CONTAINER_APP=<app> scripts/deploy_azure.sh <image-tag>" >&2
  exit 2
}

ACR="${AZURE_ACR:-}"
[ -n "$ACR" ] || usage "AZURE_ACR is required: the registry name, without .azurecr.io"
RG="${AZURE_RESOURCE_GROUP:-}"
TARGET="${AZURE_DEPLOY_TARGET:-}"
case "$TARGET" in
  aca)
    [ -n "$RG" ] || usage "AZURE_RESOURCE_GROUP is required with AZURE_DEPLOY_TARGET=aca: the group holding the container apps"
    # A name that is set but names no app fails at the roll, after the push.
    VERDICT_APP="${AZURE_CONTAINER_APP:-}"
    [ -n "$VERDICT_APP" ] || usage "AZURE_CONTAINER_APP is required with AZURE_DEPLOY_TARGET=aca: the verdict server's container app"
    ;;
  # The images are still needed: `helm upgrade --set image.tag=<sha>` rolls
  # to a tag that must exist.
  k8s) VERDICT_APP="" ;;
  *) usage "AZURE_DEPLOY_TARGET is '${TARGET}'; it must be aca or k8s" ;;
esac
IMAGE_NAME="${FORGD_IMAGE_NAME:-forgd-verdict}"
POLICY_FILE="${FORGD_POLICY_FILE:-policy.yaml}"
DASHBOARD_APP="${AZURE_DASHBOARD_APP:-ca-forgd-dashboard}"
# Adapter 4. Empty or unset rolls ca-forgd-collector; `none` means "not
# deployed here" and the collector is skipped. A named app that is missing
# is a hard failure.
COLLECTOR_APP="${AZURE_COLLECTOR_APP:-ca-forgd-collector}"
[ "$COLLECTOR_APP" != none ] || COLLECTOR_APP=""
INGEST_JOB="${AZURE_INGEST_JOB:-cj-forgd-ingest}"
# The intake (app-aca's intake_app_name). Empty or unset means "not
# deployed here"; set-but-missing is a hard failure.
INTAKE_APP="${AZURE_INTAKE_APP:-}"
# The findings connector. Empty or unset means "not deployed here"; like the
# collector, set-but-missing is a hard failure.
CONNECTOR_APP="${AZURE_CONNECTOR_APP:-}"
# Its MCP URL, the one entered in Claude. Empty derives
# https://<app fqdn>/mcp; set it when the connector is served on a custom
# host (app-aca's connector_url output).
CONNECTOR_URL="${FORGD_CONNECTOR_URL:-}"
# Empty unless the collector is deployed and rolled. The verifier reads an
# empty base URL as "not deployed here".
COLLECTOR_URL=""
IMAGE="${ACR}.azurecr.io/${IMAGE_NAME}:${TAG}"
# Adapter 3 runs a larger image: same scan core, plus the Presidio T2
# tier. Same tag with a suffix, built from the same commit in this same
# job -- the inline and post-hoc control points cannot drift.
INGEST_IMAGE="${ACR}.azurecr.io/${IMAGE_NAME}:${TAG}-ingest"

say() { printf '\n==> %s\n' "$*"; }

# Terraform-managed RBAC can land after this job starts, and fresh role
# assignments propagate lazily. Retry auth-shaped failures rather than
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

diagnostics() {
  echo "==> DEPLOY FAILED — diagnostics"
  [ "$TARGET" = aca ] || return 0
  for app in "$VERDICT_APP" "$DASHBOARD_APP" ${COLLECTOR_APP:+"$COLLECTOR_APP"} ${INTAKE_APP:+"$INTAKE_APP"} ${CONNECTOR_APP:+"$CONNECTOR_APP"}; do
    echo "--- $app"
    az containerapp show -g "$RG" -n "$app" \
      --query "{image:properties.template.containers[0].image,state:properties.runningStatus}" \
      -o json 2>/dev/null || true
    az containerapp logs show -g "$RG" -n "$app" --tail 20 --type console 2>/dev/null | tail -10 || true
  done
}
trap diagnostics ERR

if [ "$TARGET" = aca ] && [ -z "$CONNECTOR_APP" ] && [ -n "$CONNECTOR_URL" ]; then
  echo "FORGD_CONNECTOR_URL is set but AZURE_CONNECTOR_APP is not; set it to roll" >&2
  echo "the connector, or unset FORGD_CONNECTOR_URL." >&2
  exit 1
fi

say "building ${IMAGE} (linux/amd64)"
# Built on the runner with docker rather than with `az acr build`, so the
# CD identity needs only AcrPush on the registry, and a subscription that
# refuses ACR Tasks (TasksOperationsNotAllowed) can still deploy.
#
# --platform is pinned because the Container Apps nodes are amd64 and a
# build on an arm64 laptop would otherwise push an unrunnable image.
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 \
  -f deploy/Dockerfile --build-arg FORGD_BUILD_COMMIT="$TAG" \
  --target base -t "$IMAGE" .

say "building ${INGEST_IMAGE} (linux/amd64)"
# Built before anything is rolled, not after: this stage asserts that
# Presidio's model loads and that the entity identifiers in policy.yaml are
# ones it recognises. A failure there should cost a deploy, not leave the
# online services on a new image and the job on an old one.
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 \
  -f deploy/Dockerfile --build-arg FORGD_BUILD_COMMIT="$TAG" \
  --target ingest -t "$INGEST_IMAGE" .

for img in "$IMAGE" "$INGEST_IMAGE"; do
  arch="$(docker image inspect "$img" --format '{{.Architecture}}')"
  [ "$arch" = "amd64" ] || { echo "refusing to push non-amd64 image ($img: $arch)" >&2; exit 1; }
done

# login and push are one auth boundary: push exercises authorization when it
# uploads layers, not at login, so refresh and retry them together.
push_image() {
  az acr login --name "$ACR" >/dev/null \
    && docker push "$IMAGE" >/dev/null \
    && docker push "$INGEST_IMAGE" >/dev/null
}
retry_auth push_image
say "pushed"

if [ "$TARGET" = k8s ]; then
  say "AZURE_DEPLOY_TARGET=k8s; images built and pushed, nothing rolled"
  echo
  echo "  $IMAGE"
  echo "  $INGEST_IMAGE"
  echo
  echo "Roll the Kubernetes deployment with the tag above:"
  echo
  echo "  helm upgrade forgd deploy/helm/forgd-verdict --namespace forgd \\"
  echo "    --reset-then-reuse-values \\"
  echo "    --set image.tag=${TAG} --set ingest.image.tag=${TAG}-ingest \\"
  echo "    --set-file policy.inline=${POLICY_FILE}"
  echo
  echo "Then the gate, which is the check that matters:"
  echo
  echo "  scripts/verify_deployment.sh https://<host> https://<host> \"\""
  if [ -n "$CONNECTOR_URL" ]; then
    echo
    echo "With the chart's connector, the verifier checks it too:"
    echo
    echo "  FORGD_CONNECTOR_URL=${CONNECTOR_URL} scripts/verify_deployment.sh https://<host> https://<host> \"\""
  fi
  exit 0
fi

# --- the DLP gate first, and prove it before touching anything else ------
say "rolling ${VERDICT_APP}"
retry_auth az containerapp update -g "$RG" -n "$VERDICT_APP" --image "$IMAGE" -o none

VERDICT_FQDN="$(az containerapp show -g "$RG" -n "$VERDICT_APP" \
  --query properties.configuration.ingress.fqdn -o tsv)"

say "smoke: ${VERDICT_FQDN}"
# The gate, and it needs no credentials. VERIFY_MAX_UPTIME_S makes the
# verifier wait for a replica on the NEW revision before asserting anything:
# a 401 from the revision this deploy is replacing proves nothing about the
# image being rolled.
#
# The other two services are passed empty ("not deployed here") because they
# have not been rolled yet. That ordering is the point of this call: the DLP
# gate is proven while only one service is on the new image.
FORGD_CONNECTOR_URL="" FORGD_INTAKE_URL="" VERIFY_MAX_UPTIME_S=180 "$VERIFY" "https://${VERDICT_FQDN}" "" ""  # collector, dashboard

# --- read-only services after the gate is proven -------------------------
say "rolling ${DASHBOARD_APP}"
retry_auth az containerapp update -g "$RG" -n "$DASHBOARD_APP" --image "$IMAGE" -o none

DASH_FQDN="$(az containerapp show -g "$RG" -n "$DASHBOARD_APP" \
  --query properties.configuration.ingress.fqdn -o tsv)"

# --- adapter 4, after the gate, before the job ---------------------------
if [ -n "$COLLECTOR_APP" ]; then
  say "rolling ${COLLECTOR_APP}"
  if ! az containerapp show -g "$RG" -n "$COLLECTOR_APP" -o none 2>/dev/null; then
    echo "AZURE_COLLECTOR_APP is set to '${COLLECTOR_APP}' but that app does not" >&2
    echo "exist (or the deploy identity cannot read it -- an unauthorized GET is" >&2
    echo "reported as absence). Set it to none to deploy without the collector." >&2
    exit 1
  fi
  retry_auth az containerapp update -g "$RG" -n "$COLLECTOR_APP" --image "$IMAGE" -o none

  COLLECTOR_FQDN="$(az containerapp show -g "$RG" -n "$COLLECTOR_APP" \
    --query properties.configuration.ingress.fqdn -o tsv)"
  COLLECTOR_URL="https://${COLLECTOR_FQDN}"
else
  say "AZURE_COLLECTOR_APP=none; collector not deployed here, not rolled or verified"
fi

if [ -n "$INTAKE_APP" ]; then
  say "rolling ${INTAKE_APP}"
  if ! az containerapp show -g "$RG" -n "$INTAKE_APP" -o none 2>/dev/null; then
    echo "AZURE_INTAKE_APP is set to '${INTAKE_APP}' but that app does not" >&2
    echo "exist (or the deploy identity cannot read it -- an unauthorized GET is" >&2
    echo "reported as absence). Unset it to deploy without the intake." >&2
    exit 1
  fi
  retry_auth az containerapp update -g "$RG" -n "$INTAKE_APP" --image "$IMAGE" -o none
  INTAKE_FQDN="$(az containerapp show -g "$RG" -n "$INTAKE_APP" \
    --query properties.configuration.ingress.fqdn -o tsv)"
fi

if [ -n "$CONNECTOR_APP" ]; then
  say "rolling ${CONNECTOR_APP}"
  if ! az containerapp show -g "$RG" -n "$CONNECTOR_APP" -o none 2>/dev/null; then
    echo "AZURE_CONNECTOR_APP is set to '${CONNECTOR_APP}' but that app does not" >&2
    echo "exist (or the deploy identity cannot read it -- an unauthorized GET is" >&2
    echo "reported as absence). Unset it to deploy without the connector." >&2
    exit 1
  fi
  retry_auth az containerapp update -g "$RG" -n "$CONNECTOR_APP" --image "$IMAGE" -o none

  if [ -z "$CONNECTOR_URL" ]; then
    CONNECTOR_FQDN="$(az containerapp show -g "$RG" -n "$CONNECTOR_APP" \
      --query properties.configuration.ingress.fqdn -o tsv)"
    CONNECTOR_URL="https://${CONNECTOR_FQDN}/mcp"
  fi
fi

# Everything that is deployed here is now on the new image, so verify the
# whole stack before the job -- the collector's 401 has to hold before the
# next ingest run, and re-checking the verdict server costs three requests.
# No VERIFY_MAX_UPTIME_S: by now the verdict server has been up for as long
# as the other rolls took, and that is not a fault.
say "verifying the deployed stack"
FORGD_CONNECTOR_URL="$CONNECTOR_URL" FORGD_INTAKE_URL="${INTAKE_FQDN:+https://${INTAKE_FQDN}}" \
  "$VERIFY" "https://${VERDICT_FQDN}" "$COLLECTOR_URL" "https://${DASH_FQDN}"

say "rolling ${INGEST_JOB}"
# Jobs need "Container Apps Jobs Contributor", NOT "Container Apps
# Contributor" -- the latter grants only Microsoft.App/containerApps/* and
# nothing on Microsoft.App/jobs. With the wrong role the CLI reports
# `does not exist`, because Azure surfaces an unauthorized GET as absence,
# which sends you looking for a missing resource instead of a missing grant.
if ! az containerapp job show -g "$RG" -n "$INGEST_JOB" -o none 2>/dev/null; then
  echo "cannot read job ${INGEST_JOB}. If it exists, the deploy identity is" >&2
  echo "missing 'Container Apps Jobs Contributor' on it -- an unauthorized" >&2
  echo "GET is reported as 'does not exist'." >&2
  exit 1
fi
retry_auth az containerapp job update -g "$RG" -n "$INGEST_JOB" --image "$INGEST_IMAGE" -o none
echo "  next scheduled run uses ${TAG}"

trap - ERR
say "deployed ${TAG}"
echo "  verdict:   https://${VERDICT_FQDN}/hook"
echo "  ingest:    ${IMAGE_NAME}:${TAG}-ingest (Presidio T2 included)"
echo "  dashboard: https://${DASH_FQDN}/"
# An `if`, not `[ ... ] && echo`: as the last command of the script that
# test's exit status became the deploy's, so a successful deploy with no
# collector reported failure.
if [ -n "$COLLECTOR_URL" ]; then
  echo "  collector: ${COLLECTOR_URL}/v1/logs"
fi
if [ -n "$INTAKE_APP" ]; then
  echo "  intake:    https://${INTAKE_FQDN}/intake"
fi
if [ -n "$CONNECTOR_APP" ]; then
  echo "  connector: ${CONNECTOR_URL}"
fi
