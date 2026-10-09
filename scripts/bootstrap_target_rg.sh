#!/usr/bin/env bash
# Create a resource group for a stack to deploy into, and let the infra
# identity work in it.
#
# WHY THIS IS NOT TERRAFORM. The identity that runs Terraform is scoped to a
# resource group; creating a resource group is a SUBSCRIPTION-level write.
# So a stack cannot create the group it deploys into without being given
# subscription Contributor, which is a materially bigger grant than
# "Contributor on these two groups" and would let a dispatch reach every
# resource in the subscription. Same reasoning as bootstrap_tfstate.sh,
# which cannot create its own state backend for the same kind of reason.
#
# Run once per stack, by a human with subscription rights.
#
# Usage:
#   IDENTITY_RG=<identity-group> IDENTITY=<identity-name> GH_ENV=<environment> \
#     scripts/bootstrap_target_rg.sh <resource-group> <location>
#
# IDENTITY is the infra identity bootstrap_tfstate.sh created, and
# IDENTITY_RG the group it lives in. GH_ENV is the environment the infra
# workflow runs in, the one bootstrap_tfstate.sh was given.
set -euo pipefail

usage() {
  echo "bootstrap_target_rg.sh: $*" >&2
  echo "usage: IDENTITY_RG=<identity-group> IDENTITY=<identity-name> GH_ENV=<environment> scripts/bootstrap_target_rg.sh <resource-group> <location>" >&2
  exit 2
}

[ $# -eq 2 ] || usage "expected <resource-group> and <location>"
RG="$1"
LOCATION="$2"
# Where the infra identity already lives. It is not moved: one identity,
# several scoped grants.
missing=()
for v in IDENTITY_RG IDENTITY GH_ENV; do
  [ -n "${!v:-}" ] || missing+=("$v")
done
[ ${#missing[@]} -eq 0 ] || usage "required and not set: ${missing[*]}"

say() { printf '\n==> %s\n' "$*"; }

SUB_ID="$(az account show --query id -o tsv)"
PRINCIPAL_ID="$(az identity show -n "$IDENTITY" -g "$IDENTITY_RG" --query principalId -o tsv)"

say "1/2 resource group $RG"
if az group show -n "$RG" -o none 2>/dev/null; then
  echo "  already exists"
else
  az group create -n "$RG" -l "$LOCATION" -o none
  echo "  created in $LOCATION"
fi

say "2/2 roles for $IDENTITY on $RG"
RG_SCOPE="/subscriptions/${SUB_ID}/resourceGroups/${RG}"
# Filtered on principalId rather than listed with --assignee, which looks the
# identity up in Microsoft Graph and needs directory read.
grant() {
  local held
  held="$(az role assignment list --role "$1" --scope "$RG_SCOPE" \
    --query "length([?principalId=='${PRINCIPAL_ID}'])" -o tsv)"
  case "$held" in
    0) ;;
    [1-9]*) echo "  already held: $1"; return ;;
    *) echo "unexpected role assignment count for $1: '$held'" >&2; exit 1 ;;
  esac
  # The list can miss an assignment that exists; the create then reports
  # RoleAssignmentExists, which is the outcome the list was checking for.
  local err
  if ! err="$(az role assignment create --assignee-object-id "$PRINCIPAL_ID" \
    --assignee-principal-type ServicePrincipal \
    --role "$1" --scope "$RG_SCOPE" -o none 2>&1 >/dev/null)"; then
    if [[ "$err" == *RoleAssignmentExists* ]]; then
      echo "  already held: $1"
      return
    fi
    echo "$err" >&2
    exit 1
  fi
  echo "  granted: $1"
}
# Contributor to build the stack. User Access Administrator because the
# cluster module assigns AcrPull to the kubelet identity and federates the
# store identities -- both are role assignments, and an identity that cannot
# create them produces a cluster whose pods cannot pull or authenticate.
grant "Contributor"
grant "User Access Administrator"

# No Storage Blob Data role is granted here, so the identity has no direct
# access to the findings store it builds. User Access Administrator lets it
# grant itself one on this group, so it can come to read or rewrite the
# findings. Run it only from a manually dispatched workflow on a gated
# environment, as bootstrap_tfstate.sh sets up.

cat <<EOF

==> done

  $RG is ready for a stack to deploy into, and $IDENTITY can build in it.

Point the workflow at it:

  gh variable set AKS_RESOURCE_GROUP --env "$GH_ENV" --body "$RG"

The infra identity keeps its existing grant on $IDENTITY_RG, which is where
the registry lives -- the cluster module assigns AcrPull at the registry's
own scope, so that grant is still needed.
EOF
