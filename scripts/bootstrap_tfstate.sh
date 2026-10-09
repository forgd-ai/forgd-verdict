#!/usr/bin/env bash
# Create the Terraform state backend, and the identity that runs
# `terraform apply`. Run ONCE, by a human, before any `terraform apply`.
#
# Not Terraform itself: Terraform needs somewhere to keep state before it
# can create anything, and a state backend Terraform manages would be
# described by the state it holds.
#
# WHAT THIS CREATES IS PRIVILEGED. The infra identity can create resources
# and assign roles -- Contributor plus User Access Administrator, scoped to
# ONE resource group. That is deliberately more than the deploy identity
# has, so run apply from a workflow that only a manual dispatch
# (workflow_dispatch) starts: a tag must never be able to recreate a
# storage account.
#
# THE STATE HOLDS NO SECRETS. The Kubernetes deployment takes the signing
# secret, the Compliance Access Key, the OTel tokens and the hash salt from
# a Secret in the cluster, so Terraform is handed none and the state
# records none.
#
# The container is still created private, with versioning, blob soft
# delete and container soft delete, and nothing but the infra identity is
# granted access here. State still names every resource a destroy would
# reach.
#
# Usage:
#   INFRA_IDENTITY=<identity-name> \
#   GH_REPO=<owner>/<repo> \
#   GH_ENV=<environment> \
#   AKS_RESOURCE_GROUP=<stack-group> \
#   AKS_FINDINGS_ACCOUNT=<findings-account> \
#   AZURE_ACR=<registry> \
#     scripts/bootstrap_tfstate.sh <resource-group> <state-account-name>
#
# INFRA_IDENTITY is created in <resource-group> if it does not exist. GH_ENV
# is the environment of GH_REPO whose jobs may assume it.
#
# The two groups are NOT the same one. <resource-group> holds the state
# account and the registry; AKS_RESOURCE_GROUP is the group the stack
# BUILDS, so a `terraform destroy` reaches only what the stack made. Create
# it with scripts/bootstrap_target_rg.sh, which also grants the identity
# below on it.
#
# AKS_FINDINGS_ACCOUNT is the account Terraform will CREATE for findings,
# not the state account -- deliberately separate, so losing state cannot
# take the findings with it.
set -euo pipefail

usage() {
  echo "bootstrap_tfstate.sh: $*" >&2
  echo "usage: INFRA_IDENTITY=<identity-name> GH_REPO=<owner>/<repo> GH_ENV=<environment> AKS_RESOURCE_GROUP=<stack-group> AKS_FINDINGS_ACCOUNT=<findings-account> AZURE_ACR=<registry> scripts/bootstrap_tfstate.sh <resource-group> <state-account-name>" >&2
  exit 2
}

[ $# -eq 2 ] || usage "expected <resource-group> and <state-account-name>"
RG="$1"
ACCT="$2"
missing=()
for v in INFRA_IDENTITY GH_REPO GH_ENV AKS_RESOURCE_GROUP AKS_FINDINGS_ACCOUNT AZURE_ACR; do
  [ -n "${!v:-}" ] || missing+=("$v")
done
[ ${#missing[@]} -eq 0 ] || usage "required and not set: ${missing[*]}"
[[ "$GH_REPO" == */* ]] || usage "GH_REPO is '${GH_REPO}'; it must be <owner>/<repo>"
CONTAINER="${TFSTATE_CONTAINER:-tfstate}"
IDENTITY="$INFRA_IDENTITY"

say() { printf '\n==> %s\n' "$*"; }

SUB_ID="$(az account show --query id -o tsv)"
LOCATION="$(az group show -n "$RG" --query location -o tsv)"

say "1/5 state account $ACCT"
if az storage account show -n "$ACCT" -g "$RG" -o none 2>/dev/null; then
  echo "  exists, left as it is. If it allows shared key access, turn that off:"
  echo "    az storage account update -n ${ACCT} -g ${RG} --allow-shared-key-access false"
else
  # The backend authenticates with Entra ID (use_azuread_auth).
  az storage account create -n "$ACCT" -g "$RG" -l "$LOCATION" \
    --sku Standard_LRS --kind StorageV2 \
    --min-tls-version TLS1_2 --allow-blob-public-access false \
    --allow-shared-key-access false \
    --https-only true -o none
fi
# Versioning and soft delete are not optional here. A corrupted or truncated
# state file is the one failure that can orphan every resource it describes.
# Blob soft delete and versioning do not cover deleting the container.
az storage account blob-service-properties update -n "$ACCT" -g "$RG" \
  --enable-versioning true --enable-delete-retention true \
  --delete-retention-days 30 \
  --enable-container-delete-retention true \
  --container-delete-retention-days 30 -o none

say "2/5 container $CONTAINER"
az storage container-rm create --name "$CONTAINER" --storage-account "$ACCT" \
  --resource-group "$RG" --public-access off -o none

say "3/5 infra identity $IDENTITY"
if ! az identity show -n "$IDENTITY" -g "$RG" -o none 2>/dev/null; then
  az identity create -n "$IDENTITY" -g "$RG" -l "$LOCATION" -o none
fi
CLIENT_ID="$(az identity show -n "$IDENTITY" -g "$RG" --query clientId -o tsv)"
PRINCIPAL_ID="$(az identity show -n "$IDENTITY" -g "$RG" --query principalId -o tsv)"
TENANT_ID="$(az account show --query tenantId -o tsv)"

say "4/5 roles"
RG_SCOPE="/subscriptions/${SUB_ID}/resourceGroups/${RG}"
STATE_SCOPE="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${ACCT}/blobServices/default/containers/${CONTAINER}"

# Filtered on principalId rather than listed with --assignee, which looks the
# identity up in Microsoft Graph and needs directory read.
grant() {
  local held
  held="$(az role assignment list --role "$1" --scope "$2" \
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
    --role "$1" --scope "$2" -o none 2>&1 >/dev/null)"; then
    if [[ "$err" == *RoleAssignmentExists* ]]; then
      echo "  already held: $1"
      return
    fi
    echo "$err" >&2
    exit 1
  fi
  echo "  granted: $1"
}

# Control plane, resource group scope. User Access Administrator is what
# lets Terraform create the role assignment that lets the apps reach the
# findings container, and it is the grant that makes this identity
# privileged -- it can assign roles, including to itself, within this group.
grant "Contributor" "$RG_SCOPE"
grant "User Access Administrator" "$RG_SCOPE"

# Data plane, THE STATE CONTAINER ONLY. Terraform reads and writes its own
# state; at account or group scope the grant would cover every other
# container there as well.
grant "Storage Blob Data Contributor" "$STATE_SCOPE"

say "5/5 federated credential for $GH_ENV, and nothing else"
# The subject pins the ENVIRONMENT, so only a job that declares
# `environment: <GH_ENV>` can assume this identity. A workflow that
# does not -- including the tag-triggered deploy -- cannot borrow it.
# TWO credentials, not one. GitHub is moving to an IMMUTABLE subject that
# embeds the org and repo numeric ids:
#
#   repo:<owner>/<repo>:environment:<GH_ENV>                               (classic)
#   repo:<owner>@<org-id>/<repo>@<repo-id>:environment:...                 (immutable)
#
# Which one an org presents is not ours to choose, and registering only the
# classic form fails at login with AADSTS700213, which names the subject
# GitHub presented.
ORG_ID="$(gh api "orgs/${GH_REPO%%/*}" --jq .id 2>/dev/null || true)"
REPO_ID="$(gh api "repos/${GH_REPO}" --jq .id 2>/dev/null || true)"

# A credential of the same name with another subject is refused rather than
# replaced: it trusts something this run did not ask for.
add_cred() {
  local existing
  existing="$(az identity federated-credential list --identity-name "$IDENTITY" -g "$RG" \
    --query "[].[name, subject]" -o tsv | awk -F '\t' -v name="$1" '$1 == name { print $2 }')"
  if [ "$existing" = "$2" ]; then
    echo "  exists: $1"
    return
  elif [ -n "$existing" ]; then
    echo "federated credential $1 exists with subject '$existing', not '$2'." >&2
    echo "Delete it or give this one another name." >&2
    exit 1
  fi
  az identity federated-credential create \
    --name "$1" --identity-name "$IDENTITY" -g "$RG" \
    --issuer "https://token.actions.githubusercontent.com" \
    --subject "$2" \
    --audiences "api://AzureADTokenExchange" -o none
  echo "  created: $1"
}

add_cred "gh-${GH_ENV}" "repo:${GH_REPO}:environment:${GH_ENV}"
if [ -n "$ORG_ID" ] && [ -n "$REPO_ID" ]; then
  OWNER="${GH_REPO%%/*}"; NAME="${GH_REPO##*/}"
  add_cred "gh-${GH_ENV}-immutable" \
    "repo:${OWNER}@${ORG_ID}/${NAME}@${REPO_ID}:environment:${GH_ENV}"
else
  echo "  WARNING: could not read the org/repo ids; if login fails with" >&2
  echo "  AADSTS700213, add the immutable-subject credential by hand." >&2
fi

# A DEPLOYMENT BRANCH POLICY, and this is the actual gate.
#
# The federated credential trusts the environment, and a workflow_dispatch
# can name any branch. Without this, anyone who can push a branch could put
# a workflow on it declaring `environment: ${GH_ENV}` and receive this
# identity and these secrets -- a dispatch-only trigger on your apply
# workflow would not stop them, because they would be running their own file.
#
# Not `|| true`: if this fails the bootstrap stops, because without the
# branch policy the federated credential trusts a job on any branch.
# -F, not -f: `-f` sends every value as a string and the API rejects
# `"false"` where it wants a boolean. The error is clear when you see it and
# invisible until you run it.
gh api -X PUT "repos/${GH_REPO}/environments/${GH_ENV}" \
  -F "deployment_branch_policy[protected_branches]=false" \
  -F "deployment_branch_policy[custom_branch_policies]=true" \
  --silent
if [ -n "$(gh api "repos/${GH_REPO}/environments/${GH_ENV}/deployment-branch-policies" \
  --jq '.branch_policies[] | select(.name == "main" and .type == "branch") | .name')" ]; then
  echo "  branch policy: already set"
else
  gh api -X POST "repos/${GH_REPO}/environments/${GH_ENV}/deployment-branch-policies" \
    -f "name=main" -f "type=branch" --silent
  echo "  branch policy: main only"
fi
gh variable set AZURE_INFRA_CLIENT_ID --env "$GH_ENV" --repo "$GH_REPO" --body "$CLIENT_ID"
gh variable set AZURE_TENANT_ID       --env "$GH_ENV" --repo "$GH_REPO" --body "$TENANT_ID"
gh variable set AZURE_SUBSCRIPTION_ID --env "$GH_ENV" --repo "$GH_REPO" --body "$SUB_ID"
gh variable set TFSTATE_ACCOUNT       --env "$GH_ENV" --repo "$GH_REPO" --body "$ACCT"
gh variable set TFSTATE_CONTAINER     --env "$GH_ENV" --repo "$GH_REPO" --body "$CONTAINER"
gh variable set AZURE_RESOURCE_GROUP  --env "$GH_ENV" --repo "$GH_REPO" --body "$RG"
# Terraform's own required inputs. None is a credential -- a registry name
# is not one -- but without them `plan` fails asking for input, which with
# -input=false is just an error.
gh variable set AKS_RESOURCE_GROUP   --env "$GH_ENV" --repo "$GH_REPO" --body "${AKS_RESOURCE_GROUP:?set AKS_RESOURCE_GROUP to the group the stack builds into -- NOT $RG, which holds the state account}"
gh variable set AKS_FINDINGS_ACCOUNT --env "$GH_ENV" --repo "$GH_REPO" --body "${AKS_FINDINGS_ACCOUNT:?set AKS_FINDINGS_ACCOUNT to the findings storage account name (3-24 lowercase alnum, globally unique)}"
gh variable set AZURE_ACR            --env "$GH_ENV" --repo "$GH_REPO" --body "${AZURE_ACR:?set AZURE_ACR to the registry name, without .azurecr.io}"

cat <<OUT

────────────────────────────────────────────────────────────────────────────
Backend ready.

  state:    ${ACCT}/${CONTAINER}
  identity: ${IDENTITY}
              Contributor + User Access Administrator on ${RG}
              Storage Blob Data Contributor on the STATE CONTAINER only.
              User Access Administrator lets it grant itself other roles,
              in ${RG} and in any group bootstrap_target_rg.sh grants it.
  gate:     ${GH_ENV} deploys from 'main' only. That branch policy is what
              stops someone pushing a branch with their own workflow that
              declares this environment.

STILL TO DO, and none of it belongs in this script:

  SET NO SECRETS ON '${GH_ENV}'. Terraform composes no secret store, and a
  secret in GitHub that nothing reads is a copy of a credential in a place
  it has no reason to be. Terraform apply is given no credential.

  The hash salt, the signing secret, the Compliance Access Key and the OTel
  tokens go in the cluster's Secret instead -- see deploy/helm/README.md.
  Generate the salt and the tokens rather than choosing them:

    openssl rand -base64 32

  The signing secret comes from claude.ai AFTER the endpoint exists, so the
  first install runs with the placeholder and every hook request is refused
  with 401 until you set it and roll. That is the safe failure.
────────────────────────────────────────────────────────────────────────────
OUT
