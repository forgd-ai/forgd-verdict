#!/usr/bin/env bash
# Everything between `terraform apply` and `helm upgrade`.
#
# Terraform builds the cluster and the federation; the chart deploys the
# roles. Neither gives the cluster a NAME Anthropic can reach or a
# CERTIFICATE it will trust, and without both there is no deployment -- an
# exporter reads a TLS failure as a delivery failure, not as a certificate
# problem, so it is silent from our side.
#
# Deliberately a script rather than Terraform. A `helm_release` in state
# means `terraform plan` has to reach the API server, and a plan that cannot
# reach it fails instead of reporting drift. This is also re-runnable: every
# step is an upgrade-or-install.
#
# Usage: scripts/bootstrap_aks.sh <resource-group> <cluster-name> <dns-label>
set -euo pipefail

RG="${1:?usage: bootstrap_aks.sh <resource-group> <cluster-name> <dns-label>}"
CLUSTER="${2:?cluster name required}"
LABEL="${3:?dns label required}"

# Pinned. cert-manager's CRDs move between minors, and an unpinned install
# is a third party deciding what runs in the cluster that holds the
# findings.
#
# CERT_MANAGER_DIGEST is the OCI manifest digest of that version's chart at
# quay.io/jetstack/charts/cert-manager; `helm pull` prints it. helm pulls
# the chart by digest, and from 3.19 also refuses one whose digest is not
# the one --version resolves to. A CERT_MANAGER_VERSION other than the
# pinned one needs its own CERT_MANAGER_DIGEST. Needs helm 3.17 or later;
# earlier releases reject a digest reference.
PINNED_CERT_MANAGER_VERSION=v1.16.3
PINNED_CERT_MANAGER_DIGEST=sha256:3396b90b7268eb1de584b96d90054d8361575983b5e352bc9abf3e26eda31d55
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-$PINNED_CERT_MANAGER_VERSION}"
if [ "$CERT_MANAGER_VERSION" = "$PINNED_CERT_MANAGER_VERSION" ]; then
  CERT_MANAGER_DIGEST="${CERT_MANAGER_DIGEST:-$PINNED_CERT_MANAGER_DIGEST}"
elif [ -z "${CERT_MANAGER_DIGEST:-}" ]; then
  echo "CERT_MANAGER_VERSION=$CERT_MANAGER_VERSION is not the pinned $PINNED_CERT_MANAGER_VERSION;" >&2
  echo "set CERT_MANAGER_DIGEST to its chart's digest, from" >&2
  echo "  helm pull oci://quay.io/jetstack/charts/cert-manager --version $CERT_MANAGER_VERSION" >&2
  exit 1
fi
if ! [[ "$CERT_MANAGER_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "CERT_MANAGER_DIGEST must be sha256:<64 hex digits>, got $CERT_MANAGER_DIGEST" >&2
  exit 1
fi
# Discovered from the cluster below, not defaulted.
#
# It was defaulted, to "webapprouting.kubernetes.io", and the real name is
# "webapprouting.kubernetes.azure.com". The controller then logs
#
#   Ignoring ingress because of error while validating ingress class
#
# for every Ingress including cert-manager's solver, and serves its DEFAULT
# BACKEND -- which answers 200 with an empty body. /healthz returned 200 and
# the deployment looked healthy; the only symptom was the ACME challenge
# getting a 404.
#
# A test asserted that the bootstrap and the Terraform output agreed, and
# it passed with both holding the wrong name. So this reads the value the
# add-on published.
INGRESS_CLASS="${INGRESS_CLASS:-}"
ACME_EMAIL="${ACME_EMAIL:-}"

say() { printf '\n==> %s\n' "$*"; }

for bin in az kubectl helm; do
  command -v "$bin" >/dev/null || { echo "$bin is required" >&2; exit 1; }
done

say "credentials for $CLUSTER"
# With local accounts disabled the kubeconfig authenticates through Entra,
# which kubectl reaches only through kubelogin; converted to azurecli, it
# signs in as whoever `az` is signed in as. Unset reads as empty and means
# local accounts are on.
LOCAL_ACCOUNTS_DISABLED="$(az aks show --resource-group "$RG" --name "$CLUSTER" \
  --query disableLocalAccounts -o tsv)"
case "$LOCAL_ACCOUNTS_DISABLED" in
  true)
    command -v kubelogin >/dev/null || {
      echo "kubelogin is required: $CLUSTER has local accounts disabled, so kubectl authenticates through Entra." >&2
      echo "Install it from https://github.com/Azure/kubelogin or with \`az aks install-cli\`." >&2
      exit 1
    } ;;
  false | "") ;;
  *)
    echo "az aks show returned disableLocalAccounts=$LOCAL_ACCOUNTS_DISABLED; expected true or false" >&2
    exit 1 ;;
esac
az aks get-credentials --resource-group "$RG" --name "$CLUSTER" --overwrite-existing >/dev/null
if [ "$LOCAL_ACCOUNTS_DISABLED" = true ]; then
  kubelogin convert-kubeconfig -l azurecli
fi
kubectl cluster-info >/dev/null || {
  echo "kubectl cluster-info failed for $CLUSTER. The usual causes:" >&2
  echo "  - the API server is private and this machine is not on the cluster's network" >&2
  echo "  - the caller holds no Azure Kubernetes Service RBAC role on the cluster" >&2
  echo "See \"Reaching the AKS API\" in deploy/terraform/README.md." >&2
  exit 1
}

# --- a name ---------------------------------------------------------------
#
# The Azure-issued <label>.<region>.cloudapp.azure.com needs no domain
# ownership and resolves to the load balancer the moment it is set, which is
# what lets the HTTP-01 challenge below succeed with nothing else in place.
#
# Set on the add-on's NginxIngressController rather than on the Service: the
# add-on reconciles that Service, so an annotation written directly onto it
# is reverted, usually after it has already appeared to work.
say "ingress class"
if [ -z "$INGRESS_CLASS" ]; then
  INGRESS_CLASS="$(kubectl get nginxingresscontroller default \
    -o jsonpath='{.spec.ingressClassName}' 2>/dev/null || true)"
fi
if [ -z "$INGRESS_CLASS" ]; then
  echo "could not read the ingress class from the NginxIngressController" >&2
  echo "set INGRESS_CLASS, or enable the app routing add-on" >&2
  exit 1
fi
kubectl get ingressclass "$INGRESS_CLASS" >/dev/null 2>&1 || {
  echo "no IngressClass named $INGRESS_CLASS; nginx would ignore every Ingress" >&2
  echo "and serve its default backend, which answers 200 with an empty body" >&2
  exit 1
}
echo "  $INGRESS_CLASS"

say "dns label: $LABEL"
if kubectl get nginxingresscontroller default >/dev/null 2>&1; then
  kubectl patch nginxingresscontroller default --type merge -p "$(cat <<JSON
{"spec":{"loadBalancerAnnotations":{"service.beta.kubernetes.io/azure-dns-label-name":"$LABEL"}}}
JSON
)"
else
  echo "no NginxIngressController named 'default'; is the app routing add-on enabled?" >&2
  echo "set app_routing_enabled = true in the cluster-aks module, or supply your own" >&2
  exit 1
fi

# --- a certificate --------------------------------------------------------
say "cert-manager $CERT_MANAGER_VERSION ($CERT_MANAGER_DIGEST)"
helm upgrade --install cert-manager \
  "oci://quay.io/jetstack/charts/cert-manager@$CERT_MANAGER_DIGEST" \
  --namespace cert-manager --create-namespace \
  --version "$CERT_MANAGER_VERSION" \
  --set crds.enabled=true \
  --wait --timeout 10m

# The webhook must be answering before a ClusterIssuer will admit, and it
# comes up after the deployment reports ready. Applying too early fails with
# a connection refused that reads like a cluster problem.
say "waiting for the cert-manager webhook"
kubectl -n cert-manager rollout status deploy/cert-manager-webhook --timeout=5m

say "ClusterIssuer (HTTP-01 via $INGRESS_CLASS)"
# HTTP-01 rather than DNS-01: DNS-01 needs a zone we control, and the whole
# point of the Azure label is not needing one. The tradeoff is that the name
# must already resolve to this load balancer, which it does.
kubectl apply -f - <<YAML
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    ${ACME_EMAIL:+email: $ACME_EMAIL}
    privateKeySecretRef:
      name: letsencrypt-account-key
    solvers:
      - http01:
          ingress:
            ingressClassName: $INGRESS_CLASS
YAML

# --- the name it ended up with -------------------------------------------
say "waiting for the load balancer"
FQDN=""
for _ in $(seq 1 60); do
  IP="$(kubectl -n app-routing-system get svc nginx \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
  if [ -n "$IP" ]; then
    FQDN="$(az network public-ip list --query \
      "[?ipAddress=='$IP'].dnsSettings.fqdn | [0]" -o tsv 2>/dev/null || true)"
    [ -n "$FQDN" ] && [ "$FQDN" != "None" ] && break
  fi
  sleep 5
done

if [ -z "$FQDN" ] || [ "$FQDN" = "None" ]; then
  echo "the load balancer has no DNS name yet; the label may still be propagating" >&2
  echo "check: kubectl -n app-routing-system get svc nginx" >&2
  exit 1
fi

cat <<EOF

==> ready

  hostname   $FQDN
  class      $INGRESS_CLASS
  issuer     letsencrypt

Install the chart against it:

  helm upgrade --install forgd deploy/helm/forgd-verdict \\
    --namespace forgd --create-namespace \\
    --set ingress.host=$FQDN \\
    --set ingress.className=$INGRESS_CLASS \\
    --set ingress.tls.clusterIssuer=letsencrypt \\
    --set-string orgIds.primary=<organization-uuid> \\
    --set-file policy.inline=policy.yaml \\
    ...   # the rest from: terraform -chdir=deploy/terraform/examples/aks output -raw helm_install_command

The certificate is issued on the first request to the name, so the first
probe can take a minute. Until it is issued nginx serves its own, and an
exporter will refuse that -- which is why the deploy gate is the check that
matters rather than a pod being Running.
EOF
