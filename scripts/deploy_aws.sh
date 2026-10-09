#!/usr/bin/env bash
# Deploy every forgd-verdict service on AWS from one commit.
#
# The AWS counterpart of deploy_azure.sh: CI is a thin caller, and the same
# command runs locally when CI is broken. Nothing here calls terraform.
# Terraform owns the infrastructure; this script owns which image runs.
#
# Ordering and failure semantics:
#   check the environment -> every missing variable is named at once, before
#                            anything is built
#   ecs: preflight        -> every family and service named here exists, and
#                            each family's CPU architecture matches the build,
#                            before anything is built or touched
#   build both images     -> refuses to push an unrunnable image, and fails
#                            before any service is touched if the ingest
#                            image's Presidio tier does not load
#   push                  -> retried; a fresh IAM grant propagates lazily
#
# ecs (deploy/terraform/modules/app-ecs):
#   each revision is registered from the LATEST revision in its family with
#   only the image replaced, never from the revision a service is running
#   (deploy/terraform/README.md, "Terraform owns infrastructure").
#   roll verdict          -> the DLP gate. Waits for services-stable, fails if
#                            the circuit breaker rolled it back, then runs
#                            verify_deployment.sh against the verdict server
#                            alone. A failure stops the release with only this
#                            service on the new image.
#   roll collector, dashboard, then intake and the connector if configured
#   verify the stack      -> every deployed URL, and the connector's MCP URL
#                            when it is configured
#   point the schedule    -> the ingest schedule's target names the new ingest
#                            revision; every other field of the schedule is
#                            passed back unchanged. The next run picks it up.
#
# eks (deploy/helm/forgd-verdict):
#   helm upgrade          -> one upgrade sets both tags and reuses every other
#                            value. It rolls every Deployment at the same time;
#                            the chart has no verdict-first ordering, so there
#                            is no pre-rollout gate on EKS. --wait returns once
#                            the new pods are ready.
#   verify the stack      -> after every service has already moved, with the
#                            connector's MCP URL when FORGD_CONNECTOR_URL is
#                            set. A failure fails the release but does not
#                            undo the upgrade.
#
# The verdict-first gate never checks the connector: it has not been rolled
# yet, so FORGD_CONNECTOR_URL is cleared for that one call.
#
# Requires an authenticated AWS session (CI: the CD role via OIDC).
set -euo pipefail

usage() {
  cat <<'EOF'
usage: deploy_aws.sh <sha>

Builds forgd-verdict:<sha> and forgd-verdict:<sha>-ingest, pushes both to
ECR and rolls them onto an ECS or EKS deployment.

Always required:
  AWS_ECR_REPOSITORY       repository URI, <account>.dkr.ecr.<region>.amazonaws.com/<name>
  AWS_DEPLOY_TARGET        ecs or eks
  FORGD_VERDICT_URL        verdict server base URL, e.g. https://verdict.example.com
  FORGD_COLLECTOR_URL      collector base URL (eks: may be empty if not deployed)
  FORGD_DASHBOARD_URL      dashboard base URL (eks: may be empty if not deployed)

Optional:
  AWS_IMAGE_PLATFORM       docker build platform (default linux/amd64)
  FORGD_CONNECTOR_URL      the findings connector's MCP URL, checked after the
                           rollout (ecs: required with AWS_ECS_CONNECTOR_SERVICE
                           and AWS_ECS_CONNECTOR_FAMILY, refused without them)
  FORGD_INTAKE_URL         the intake's base URL, checked for a 401 rather than
                           a sign-in after the rollout; empty: not checked

ecs (names from the app-ecs outputs):
  AWS_ECS_CLUSTER                                         cluster_name
  AWS_ECS_VERDICT_SERVICE    AWS_ECS_VERDICT_FAMILY       service_names / task_definition_families
  AWS_ECS_COLLECTOR_SERVICE  AWS_ECS_COLLECTOR_FAMILY
  AWS_ECS_DASHBOARD_SERVICE  AWS_ECS_DASHBOARD_FAMILY
  AWS_ECS_INTAKE_SERVICE     AWS_ECS_INTAKE_FAMILY        both empty or unset: no intake
  AWS_ECS_CONNECTOR_SERVICE  AWS_ECS_CONNECTOR_FAMILY     both empty or unset: no connector
  AWS_ECS_INGEST_FAMILY
  AWS_INGEST_SCHEDULE                                     ingest_schedule_name
  AWS_INGEST_SCHEDULE_GROUP                               optional; the default group if unset

eks:
  AWS_EKS_CLUSTER          cluster name, for the kubeconfig
  AWS_EKS_RELEASE          helm release name
  AWS_EKS_NAMESPACE        release namespace
  AWS_EKS_CHART            optional; default deploy/helm/forgd-verdict

Run from the repository root.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") usage >&2; exit 2 ;;
esac
TAG="$1"

# Next to this script, not relative to $PWD: CI runs `scripts/deploy_aws.sh`
# from the repo root and an operator runs it from wherever they are.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="${HERE}/verify_deployment.sh"

say() { printf '\n==> %s\n' "$*"; }
die() { echo "deploy_aws.sh: $*" >&2; exit 1; }

# --- the environment, all of it, before anything is built ---------------
missing=()
need() { local v; for v in "$@"; do [ -n "${!v:-}" ] || missing+=("$v"); done; }
# Set, but may be empty ("not deployed here").
need_set() { local v; for v in "$@"; do [ -n "${!v+x}" ] || missing+=("$v"); done; }

need AWS_ECR_REPOSITORY AWS_DEPLOY_TARGET FORGD_VERDICT_URL
TARGET="${AWS_DEPLOY_TARGET:-}"
case "$TARGET" in
  ecs)
    need FORGD_COLLECTOR_URL FORGD_DASHBOARD_URL AWS_ECS_CLUSTER \
      AWS_ECS_VERDICT_SERVICE AWS_ECS_VERDICT_FAMILY \
      AWS_ECS_COLLECTOR_SERVICE AWS_ECS_COLLECTOR_FAMILY \
      AWS_ECS_DASHBOARD_SERVICE AWS_ECS_DASHBOARD_FAMILY \
      AWS_ECS_INGEST_FAMILY AWS_INGEST_SCHEDULE
    if [ -n "${AWS_ECS_INTAKE_SERVICE:-}" ] || [ -n "${AWS_ECS_INTAKE_FAMILY:-}" ]; then
      need AWS_ECS_INTAKE_SERVICE AWS_ECS_INTAKE_FAMILY
    fi
    if [ -n "${AWS_ECS_CONNECTOR_SERVICE:-}" ] || [ -n "${AWS_ECS_CONNECTOR_FAMILY:-}" ]; then
      need AWS_ECS_CONNECTOR_SERVICE AWS_ECS_CONNECTOR_FAMILY FORGD_CONNECTOR_URL
    elif [ -n "${FORGD_CONNECTOR_URL:-}" ]; then
      die "FORGD_CONNECTOR_URL is set but AWS_ECS_CONNECTOR_SERVICE and AWS_ECS_CONNECTOR_FAMILY are not; set both to roll the connector, or unset FORGD_CONNECTOR_URL"
    fi
    ;;
  eks)
    need_set FORGD_COLLECTOR_URL FORGD_DASHBOARD_URL
    need AWS_EKS_CLUSTER AWS_EKS_RELEASE AWS_EKS_NAMESPACE
    ;;
  "") ;;
  *) die "AWS_DEPLOY_TARGET is '${TARGET}'; it must be ecs or eks" ;;
esac
if [ ${#missing[@]} -gt 0 ]; then
  die "required and not set: ${missing[*]} (see -h)"
fi

REPO="$AWS_ECR_REPOSITORY"
REGISTRY="${REPO%%/*}"
REGION="$(printf '%s' "$REGISTRY" | sed -n 's/^[0-9]*\.dkr\.ecr\.\([a-z0-9-]*\)\.amazonaws\.com\(\.cn\)\{0,1\}$/\1/p')"
[ -n "$REGION" ] && [ "$REGISTRY" != "$REPO" ] \
  || die "AWS_ECR_REPOSITORY '${REPO}' is not <account>.dkr.ecr.<region>.amazonaws.com/<name>"

PLATFORM="${AWS_IMAGE_PLATFORM:-linux/amd64}"
ARCH="${PLATFORM#*/}"
# Refused here rather than as `exec format error` halfway through a build:
# an arm64 stack needs an arm64 runner (ubuntu-24.04-arm), or QEMU set up
# before this runs.
case "$(uname -m)" in
  x86_64|amd64) HOST_ARCH=amd64 ;;
  aarch64|arm64) HOST_ARCH=arm64 ;;
  *) HOST_ARCH="$(uname -m)" ;;
esac
if [ "$HOST_ARCH" != "$ARCH" ] && [ -z "${AWS_ALLOW_CROSS_BUILD:-}" ]; then
  die "building ${PLATFORM} on a ${HOST_ARCH} host: use a ${ARCH} runner, or set AWS_ALLOW_CROSS_BUILD=1 once QEMU/buildx is set up"
fi
IMAGE="${REPO}:${TAG}"
# Adapter 3 runs a larger image: the same scan core plus the Presidio T2
# tier, the same tag with a suffix, built from the same commit here.
INGEST_IMAGE="${REPO}:${TAG}-ingest"
COLLECTOR_URL="${FORGD_COLLECTOR_URL:-}"
DASHBOARD_URL="${FORGD_DASHBOARD_URL:-}"
CONNECTOR_URL="${FORGD_CONNECTOR_URL:-}"

WORK="$(mktemp -d)"
ROLLING=0
on_exit() {
  local rc=$?
  if [ $rc -ne 0 ] && [ $ROLLING -eq 1 ]; then ecs_diagnostics; fi
  rm -rf "$WORK"
}
trap on_exit EXIT

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

# --- ecs ------------------------------------------------------------------
# role:service:family, in roll order after verdict.
ecs_roles() {
  echo "verdict:${AWS_ECS_VERDICT_SERVICE}:${AWS_ECS_VERDICT_FAMILY}"
  echo "collector:${AWS_ECS_COLLECTOR_SERVICE}:${AWS_ECS_COLLECTOR_FAMILY}"
  echo "dashboard:${AWS_ECS_DASHBOARD_SERVICE}:${AWS_ECS_DASHBOARD_FAMILY}"
  if [ -n "${AWS_ECS_INTAKE_SERVICE:-}" ]; then
    echo "intake:${AWS_ECS_INTAKE_SERVICE}:${AWS_ECS_INTAKE_FAMILY}"
  fi
  if [ -n "${AWS_ECS_CONNECTOR_SERVICE:-}" ]; then
    echo "connector:${AWS_ECS_CONNECTOR_SERVICE}:${AWS_ECS_CONNECTOR_FAMILY}"
  fi
}

ecs_preflight() {
  local role service family want got failures services=()
  case "$ARCH" in
    amd64) want=X86_64 ;;
    arm64) want=ARM64 ;;
    *) die "AWS_IMAGE_PLATFORM '${PLATFORM}' is not linux/amd64 or linux/arm64" ;;
  esac
  while IFS=: read -r role service family; do
    services+=("$service")
    check_family "$role" "$family" "$want"
  done < <(ecs_roles)
  check_family ingest "$AWS_ECS_INGEST_FAMILY" "$want"

  # A name set to a service that does not exist is a hard failure, here and
  # not halfway through the rolls.
  failures="$(aws ecs describe-services --cluster "$AWS_ECS_CLUSTER" --services "${services[@]}" \
    --query 'failures[].arn' --output text)"
  [ -z "$failures" ] || [ "$failures" = "None" ] \
    || die "not found in cluster ${AWS_ECS_CLUSTER}: ${failures}"

  aws scheduler get-schedule --name "$AWS_INGEST_SCHEDULE" \
    ${AWS_INGEST_SCHEDULE_GROUP:+--group-name "$AWS_INGEST_SCHEDULE_GROUP"} \
    --output json >/dev/null \
    || die "cannot read schedule '${AWS_INGEST_SCHEDULE}'"
}

check_family() {
  local role="$1" family="$2" want="$3" got
  got="$(aws ecs describe-task-definition --task-definition "$family" \
    --query 'taskDefinition.runtimePlatform.cpuArchitecture' --output text)" \
    || die "cannot describe task definition family '${family}' (${role})"
  # A family registered without runtimePlatform runs on X86_64.
  [ "$got" = "None" ] && got=X86_64
  [ "$got" = "$want" ] || die "family '${family}' runs ${got}; the build is ${PLATFORM}"
}

# Registers a revision of <family> from its latest ACTIVE revision with the
# <role> container's image replaced, and prints the new ARN.
register_from_latest() {
  local role="$1" family="$2" image="$3"
  local latest="${WORK}/${role}.latest.json" input="${WORK}/${role}.register.json"
  # `|| die`: this runs inside $(...), where bash does not apply set -e, so a
  # failed read went on to report a missing container instead.
  aws ecs describe-task-definition --task-definition "$family" --include TAGS --output json >"$latest" \
    || die "cannot read the latest revision of family '${family}'"
  jq -e --arg role "$role" '[.taskDefinition.containerDefinitions[] | select(.name == $role)] | length == 1' \
    "$latest" >/dev/null \
    || die "family '${family}' does not have exactly one container named '${role}'"
  jq --arg role "$role" --arg image "$image" '
    (.tags // []) as $tags
    | .taskDefinition
    | del(.taskDefinitionArn, .revision, .status, .requiresAttributes,
          .compatibilities, .registeredAt, .registeredBy, .deregisteredAt)
    | .containerDefinitions |= map(if .name == $role then .image = $image else . end)
    | if ($tags | length) > 0 then .tags = $tags else . end
  ' "$latest" >"$input"
  aws ecs register-task-definition --cli-input-json "file://${input}" \
    --query 'taskDefinition.taskDefinitionArn' --output text
}

roll_service() {
  local role="$1" service="$2" family="$3" arn primary
  say "rolling ${role} (${service})"
  arn="$(register_from_latest "$role" "$family" "$IMAGE")"
  echo "  registered ${arn}"
  retry_auth aws ecs update-service --cluster "$AWS_ECS_CLUSTER" --service "$service" \
    --task-definition "$arn" --output json >/dev/null
  # One `wait services-stable` gives up after 10 minutes, and a bad image
  # outlasts that: the circuit breaker needs three failed tasks, each an
  # image pull, the grace period and three health checks. Up to 30 minutes,
  # so a rollback is reported as one rather than as a timeout mid-rollback.
  local waited=0
  until aws ecs wait services-stable --cluster "$AWS_ECS_CLUSTER" --services "$service"; do
    waited=$((waited + 1))
    [ $waited -lt 3 ] || die "${service} did not become stable within 30 minutes"
    echo "  still rolling after $((waited * 10)) minutes"
  done
  # The services run a deployment circuit breaker with rollback, and a
  # rolled-back service is stable too, on the old revision.
  primary="$(aws ecs describe-services --cluster "$AWS_ECS_CLUSTER" --services "$service" \
    --query "services[0].deployments[?status=='PRIMARY'].taskDefinition | [0]" --output text)"
  [ "$primary" = "$arn" ] \
    || die "${service} is stable on ${primary}, not ${arn}: the rollout failed and ECS rolled it back"
}

point_schedule() {
  local arn="$1" current="${WORK}/schedule.json" input="${WORK}/schedule.update.json"
  say "pointing schedule ${AWS_INGEST_SCHEDULE} at ${arn}"
  aws scheduler get-schedule --name "$AWS_INGEST_SCHEDULE" \
    ${AWS_INGEST_SCHEDULE_GROUP:+--group-name "$AWS_INGEST_SCHEDULE_GROUP"} \
    --output json >"$current"
  jq -e --arg family "$AWS_ECS_INGEST_FAMILY" \
    '.Target.EcsParameters.TaskDefinitionArn // "" | test(":task-definition/" + $family + ":")' \
    "$current" >/dev/null \
    || die "schedule '${AWS_INGEST_SCHEDULE}' does not target family '${AWS_ECS_INGEST_FAMILY}'"
  # UpdateSchedule replaces the whole schedule: a field left out is reset.
  jq --arg arn "$arn" '
    del(.Arn, .CreationDate, .LastModificationDate)
    | .Target.EcsParameters.TaskDefinitionArn = $arn
  ' "$current" >"$input"
  aws scheduler update-schedule --cli-input-json "file://${input}" --output json >/dev/null
}

ecs_diagnostics() {
  echo "==> DEPLOY FAILED — service deployments"
  local role service family
  while IFS=: read -r role service family; do
    echo "--- ${service}"
    aws ecs describe-services --cluster "$AWS_ECS_CLUSTER" --services "$service" \
      --query 'services[0].deployments[].{status:status,taskDefinition:taskDefinition,rollout:rolloutState,reason:rolloutStateReason}' \
      --output json 2>/dev/null || true
  done < <(ecs_roles)
}

# --- build and push -------------------------------------------------------
if [ "$TARGET" = ecs ]; then
  say "preflight: ${AWS_ECS_CLUSTER}"
  ecs_preflight
fi

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

# login and push are one auth boundary: push exercises authorization when it
# uploads layers, not at login, so refresh and retry them together.
push_images() {
  aws ecr get-login-password --region "$REGION" \
    | docker login --username AWS --password-stdin "$REGISTRY" >/dev/null \
    && docker push "$IMAGE" >/dev/null \
    && docker push "$INGEST_IMAGE" >/dev/null
}
retry_auth push_images
say "pushed ${IMAGE} and ${INGEST_IMAGE}"

# --- eks ------------------------------------------------------------------
if [ "$TARGET" = eks ]; then
  export KUBECONFIG="${WORK}/kubeconfig"
  aws eks update-kubeconfig --name "$AWS_EKS_CLUSTER" --region "${AWS_EKS_REGION:-$REGION}" \
    --kubeconfig "$KUBECONFIG" >/dev/null
  say "helm upgrade ${AWS_EKS_RELEASE} (${AWS_EKS_NAMESPACE})"
  helm upgrade "$AWS_EKS_RELEASE" "${AWS_EKS_CHART:-deploy/helm/forgd-verdict}" \
    --namespace "$AWS_EKS_NAMESPACE" --reset-then-reuse-values \
    --set "image.repository=${AWS_ECR_REPOSITORY}" --set "ingest.image.repository=${AWS_ECR_REPOSITORY}" \
    --set "image.tag=${TAG}" --set "ingest.image.tag=${TAG}-ingest" --wait

  say "verifying the deployed stack"
  FORGD_CONNECTOR_URL="$CONNECTOR_URL" "$VERIFY" "$FORGD_VERDICT_URL" "$COLLECTOR_URL" "$DASHBOARD_URL"
  say "deployed ${TAG}"
  exit 0
fi

# --- ecs: the DLP gate first, proven before anything else is touched -----
ROLLING=1
started=$SECONDS
roll_service verdict "$AWS_ECS_VERDICT_SERVICE" "$AWS_ECS_VERDICT_FAMILY"

say "smoke: ${FORGD_VERDICT_URL}"
# The verifier waits for a replica younger than this roll before asserting
# anything, so a 401 from the task being replaced cannot pass the gate. The
# other two are passed empty, and the connector cleared, because they have
# not been rolled yet.
FORGD_CONNECTOR_URL="" FORGD_INTAKE_URL="" VERIFY_MAX_UPTIME_S=$((SECONDS - started + 60)) "$VERIFY" "$FORGD_VERDICT_URL" "" ""

while IFS=: read -r role service family; do
  [ "$role" = verdict ] && continue
  roll_service "$role" "$service" "$family"
done < <(ecs_roles)

say "verifying the deployed stack"
FORGD_CONNECTOR_URL="$CONNECTOR_URL" "$VERIFY" "$FORGD_VERDICT_URL" "$COLLECTOR_URL" "$DASHBOARD_URL"

say "registering ingest"
INGEST_ARN="$(register_from_latest ingest "$AWS_ECS_INGEST_FAMILY" "$INGEST_IMAGE")"
point_schedule "$INGEST_ARN"
echo "  next scheduled run uses ${TAG}-ingest"

say "deployed ${TAG}"
