output "store_url" {
  value = module.store.store_url
}

output "writer_client_id" {
  value       = module.store.identity_client_id
  description = "serviceAccounts.writer.clientId."
}

output "reader_client_id" {
  value       = module.store.reader_identity_client_id
  description = "serviceAccounts.reader.clientId. The dashboard's, and not the writer's."
}

output "kubeconfig_command" {
  value = module.cluster.kubeconfig_command
}

output "ingress_class_name" {
  value = module.cluster.ingress_class_name
}

# The install, with every value this stack decided already filled in.
#
# Printed rather than executed: a `helm_release` managed by Terraform means
# `plan` needs to reach the API server, and a plan that cannot reach it
# fails rather than reporting drift.
#
# The service account names are not optional here. They are half of the
# federated subject, and the chart's own default naming would not match.
output "helm_install_command" {
  value = join(" ", [
    "helm upgrade --install forgd deploy/helm/forgd-verdict",
    "--namespace ${var.namespace} --create-namespace",
    "--set store.url=${module.store.store_url}",
    "--set serviceAccounts.writer.name=${local.writer_service_account}",
    "--set serviceAccounts.reader.name=${local.reader_service_account}",
    "--set serviceAccounts.writer.clientId=${module.store.identity_client_id}",
    "--set serviceAccounts.reader.clientId=${module.store.reader_identity_client_id}",
    "--set ingress.className=${module.cluster.ingress_class_name}",
    "--set image.repository=<registry>/forgd-verdict",
    "--set image.tag=<commit-sha>",
    # ONE repository, tagged twice. No `<registry>/forgd-verdict-ingest`
    # repository is built; the ingest variant is the -ingest TAG. The chart
    # requires this value rather than deriving it,
    # because falling back to image.tag runs adapter 3 on the base image and
    # every scan reports clean.
    "--set ingest.image.repository=<registry>/forgd-verdict",
    "--set ingest.image.tag=<commit-sha>-ingest",
    "--set ingress.host=<hostname>",
    "--set ingress.tls.clusterIssuer=<cluster-issuer>",
    "--set secrets.existingSecret=<secret>",
    "--set-string orgIds.primary=<organization-uuid>",
    # The dashboard behind oauth2-proxy; deploy/helm/README.md § The shipped
    # policy's dashboard auth does not port has the alternative.
    "--set dashboard.auth.mode=oidc_jwt",
    "--set dashboard.auth.header=authorization",
    "--set dashboard.auth.issuer=https://login.microsoftonline.com/<tenant>/v2.0",
    "--set dashboard.auth.jwksUrl=https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys",
    "--set dashboard.auth.audience=<client-id>",
    "--set-file policy.inline=policy.yaml",
  ])
}

output "service_account_names" {
  value = {
    writer = local.writer_service_account
    reader = local.reader_service_account
  }
  description = "Half of each federated subject. Must equal what the chart renders."
}

output "azure_monitor_sink_endpoint" {
  description = "Paste into `sinks[].endpoint`. Empty when enable_azure_monitor is false."
  value       = try(module.monitor[0].ingestion_endpoint, "")
}
