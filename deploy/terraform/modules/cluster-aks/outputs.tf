output "cluster_name" {
  value = azurerm_kubernetes_cluster.this.name
}

output "oidc_issuer_url" {
  value       = azurerm_kubernetes_cluster.this.oidc_issuer_url
  description = "What the federated credentials trust. Useful when a pod authenticates as nothing and the subject needs checking."
}

output "ingress_class_name" {
  value       = var.app_routing_enabled ? "webapprouting.kubernetes.azure.com" : "nginx"
  description = <<-DESC
    Pass to the chart's ingress.className.

    `webapprouting.kubernetes.azure.com`, not `...kubernetes.io`. It was the
    latter here and in the bootstrap, and the failure is the quietest kind:
    the controller logs

      Ignoring ingress because of error while validating ingress class
      error="no object matching key \"webapprouting.kubernetes.io\" in local store"

    and serves its DEFAULT BACKEND instead -- which answers 200 with an
    empty body. So /healthz returned 200, the deployment looked fine, and
    the only visible symptom was cert-manager's HTTP-01 challenge getting a
    404 on a path its own Ingress was also being ignored for.

    The authoritative value is in the cluster, not here:

      kubectl get nginxingresscontroller default \
        -o jsonpath='{.spec.ingressClassName}'

    scripts/bootstrap_aks.sh reads it from there rather than defaulting to
    the value above.
  DESC
}

output "kubeconfig_command" {
  value       = "az aks get-credentials --resource-group ${var.resource_group_name} --name ${azurerm_kubernetes_cluster.this.name} --overwrite-existing${var.local_account_disabled ? " && kubelogin convert-kubeconfig -l azurecli" : ""}"
  description = "With local_account_disabled, kubectl authenticates through kubelogin as the signed-in az identity. With private_cluster_enabled, run it from a network that reaches the cluster's private endpoint: the AKS-managed VNet in the node resource group, or one peered with it. Without one, az aks command invoke runs kubectl and helm inside the cluster."
}

output "namespace" {
  value = var.namespace
}
