output "cluster_name" {
  value = azurerm_kubernetes_cluster.this.name
}

output "oidc_issuer_url" {
  value       = azurerm_kubernetes_cluster.this.oidc_issuer_url
  description = "What the federated credentials trust. Useful when a pod authenticates as nothing and the subject needs checking."
}

output "ingress_mode" {
  value       = local.ingress
  description = "\"app_routing\", \"agc\", or \"none\" (app_routing_enabled = false: an ingress controller you supply)."
}

output "ingress_class_name" {
  value       = local.ingress == "agc" ? null : (local.ingress == "app_routing" ? "webapprouting.kubernetes.azure.com" : "nginx")
  description = <<-DESC
    Pass to the chart's ingress.className. Null with ingress = "agc", where
    the chart renders a Gateway and no Ingress.

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

output "alb_id" {
  value       = local.agc ? azurerm_application_load_balancer.this[0].id : null
  description = "The chart's ingress.agc.albId."
}

output "alb_frontend_name" {
  value       = local.agc ? azurerm_application_load_balancer_frontend.this[0].name : null
  description = "The chart's ingress.agc.frontend."
}

output "alb_frontend_fqdn" {
  value       = local.agc ? azurerm_application_load_balancer_frontend.this[0].fully_qualified_domain_name : null
  description = "The frontend's generated *.alb.azure.com name. Point the deployment's hostnames at it with a CNAME."
}

output "waf_policy_ids" {
  value = local.agc ? {
    protected = azurerm_web_application_firewall_policy.protected[0].id
    connector = azurerm_web_application_firewall_policy.connector[0].id
    api       = azurerm_web_application_firewall_policy.api[0].id
  } : null
  description = "The chart's ingress.agc.wafPolicies."
}

output "alb_controller_client_id" {
  value       = local.agc ? azurerm_user_assigned_identity.alb_controller[0].client_id : null
  description = "The ALB Controller Helm release's albController.podIdentity.clientID."
}

output "alb_controller_principal_id" {
  value       = local.agc ? azurerm_user_assigned_identity.alb_controller[0].principal_id : null
  description = "For a Reader grant on the node resource group made outside this module, with grant_alb_controller_node_reader = false."
}

output "node_resource_group_id" {
  value = azurerm_kubernetes_cluster.this.node_resource_group_id
}
