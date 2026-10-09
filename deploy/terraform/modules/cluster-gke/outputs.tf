output "cluster_name" {
  value = google_container_cluster.this.name
}

output "location" {
  value = google_container_cluster.this.location
}

output "kubeconfig_command" {
  value       = "gcloud container clusters get-credentials ${google_container_cluster.this.name} --region ${google_container_cluster.this.location} --project ${var.project_id}${var.dns_endpoint_allow_external_traffic ? " --dns-endpoint" : var.endpoint_public_access ? "" : " --internal-ip"}"
  description = "With dns_endpoint_allow_external_traffic on, the kubeconfig names the DNS endpoint, reachable from anywhere with IAM. Otherwise, with endpoint_public_access off, it names the private endpoint, reachable from inside the VPC."
}

output "workload_identity_pool" {
  value       = local.workload_pool
  description = "The pool the store accounts' workloadIdentityUser bindings name."
}

output "namespace" {
  value = var.namespace
}
