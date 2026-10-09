output "cluster_name" {
  value = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  value = aws_eks_cluster.this.endpoint
}

output "cluster_security_group_id" {
  value       = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  description = "The security group EKS attaches to the control plane and the managed nodes."
}

output "oidc_issuer_url" {
  value       = local.irsa ? aws_eks_cluster.this.identity[0].oidc[0].issuer : null
  description = "The cluster's OIDC issuer, when identity_mode is irsa. Null under pod_identity, where nothing trusts it."
}

output "oidc_provider_arn" {
  value = local.irsa ? aws_iam_openid_connect_provider.this[0].arn : null
}

output "kubeconfig_command" {
  value = "aws eks update-kubeconfig --region ${data.aws_region.current.region} --name ${aws_eks_cluster.this.name}"
}

output "namespace" {
  value = var.namespace
}

output "writer_assume_role_policy" {
  value       = local.irsa ? data.aws_iam_policy_document.irsa_trust["writer"].json : local.pod_identity_trust["writer"]
  description = "Pass to store-s3's writer_assume_role_policy."
}

output "reader_assume_role_policy" {
  value       = local.irsa ? data.aws_iam_policy_document.irsa_trust["reader"].json : local.pod_identity_trust["reader"]
  description = "Pass to store-s3's reader_assume_role_policy."
}

output "control_assume_role_policy" {
  value       = var.control_enabled ? (local.irsa ? data.aws_iam_policy_document.irsa_trust["control"].json : local.pod_identity_trust["control"]) : null
  description = "Pass to store-s3's control_assume_role_policy. Null unless control_enabled."
}

output "lb_controller_role_arn" {
  value = var.lb_controller_enabled ? aws_iam_role.lb_controller[0].arn : null
}

output "lb_controller_install_command" {
  value = var.lb_controller_enabled ? join(" \\\n  ", compact([
    "curl -fsSLo aws-load-balancer-controller-3.5.0.tgz https://aws.github.io/eks-charts/aws-load-balancer-controller-3.5.0.tgz && echo '45051f634b33e10baccb3354d0681b7de787c60445e599fa276e0c9aedd4ccd5  aws-load-balancer-controller-3.5.0.tgz' > aws-load-balancer-controller-3.5.0.tgz.sha256 && if command -v sha256sum >/dev/null; then sha256sum -c aws-load-balancer-controller-3.5.0.tgz.sha256; else shasum -a 256 -c aws-load-balancer-controller-3.5.0.tgz.sha256; fi && helm upgrade --install aws-load-balancer-controller ./aws-load-balancer-controller-3.5.0.tgz",
    "--namespace ${local.lb_controller_namespace}",
    "--set clusterName=${aws_eks_cluster.this.name}",
    "--set region=${data.aws_region.current.region}",
    "--set vpcId=${var.vpc_id}",
    "--set serviceAccount.create=true",
    "--set serviceAccount.name=${local.lb_controller_service_account}",
    local.irsa ? "--set-string serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn=${aws_iam_role.lb_controller[0].arn}" : "",
  ])) : null
  description = "Downloads chart 3.5.0 (controller v3.5.0), the version iam_policy.json was taken from, into the current directory, checks its SHA-256 with sha256sum or shasum, and installs it from that file only if the hash matches. Run after kubeconfig_command, before lb_controller_namespace_command."
}

output "lb_controller_namespace_command" {
  value = var.lb_controller_enabled ? join(" && ", [
    "kubectl create namespace ${var.namespace} --dry-run=client -o yaml | kubectl apply -f -",
    "kubectl label namespace ${var.namespace} elbv2.k8s.aws/pod-readiness-gate-inject=enabled --overwrite",
    "kubectl create role aws-load-balancer-controller-oidc-secret --namespace=${var.namespace} --verb=get,list,watch --resource=secrets --resource-name=${var.dashboard_oidc_secret_name} --dry-run=client -o yaml | kubectl apply -f -",
    "kubectl create rolebinding aws-load-balancer-controller-oidc-secret --namespace=${var.namespace} --role=aws-load-balancer-controller-oidc-secret --serviceaccount=${local.lb_controller_namespace}:${local.lb_controller_service_account} --dry-run=client -o yaml | kubectl apply -f -",
  ]) : null
  description = "Prepares the chart's namespace for the Load Balancer Controller: creates it, turns on pod readiness gate injection, and lets the controller read the dashboard's OIDC client secret and no other. Safe to run again. Run after lb_controller_install_command, before the forgd-verdict chart."
}

output "helm_values_hint" {
  value = yamlencode(merge(
    {
      workloadIdentity = { enabled = false }
      serviceAccounts = merge({
        writer = merge(
          { name = var.writer_service_account },
          local.irsa ? { annotations = { "eks.amazonaws.com/role-arn" = var.writer_role_arn } } : null,
        )
        reader = merge(
          { name = var.reader_service_account },
          local.irsa ? { annotations = { "eks.amazonaws.com/role-arn" = var.reader_role_arn } } : null,
        )
        }, var.connector_enabled ? {
        connector = { name = var.connector_service_account }
        } : {}, var.control_enabled ? {
        control = merge(
          { name = var.control_service_account },
          local.irsa ? { annotations = { "eks.amazonaws.com/role-arn" = var.control_role_arn } } : null,
        )
      } : {})
    },
    var.lb_controller_enabled ? {
      ingress = merge(
        { className = "alb" },
        length(var.public_subnet_ids) > 0 ? merge({
          annotations = { "alb.ingress.kubernetes.io/subnets" = join(",", var.public_subnet_ids) }
          diagnostics = { annotations = { "alb.ingress.kubernetes.io/subnets" = join(",", var.public_subnet_ids) } }
          dashboard   = { annotations = { "alb.ingress.kubernetes.io/subnets" = join(",", var.public_subnet_ids) } }
          }, var.connector_enabled ? {
          connector = { annotations = { "alb.ingress.kubernetes.io/subnets" = join(",", var.public_subnet_ids) } }
        } : {}) : null,
      )
    } : null,
  ))
  description = "Chart values this cluster implies, as YAML for `helm upgrade -n <namespace> -f`. Install into the `namespace` output."

  precondition {
    condition     = var.reader_role_arn != var.writer_role_arn
    error_message = "reader_role_arn equals writer_role_arn. The dashboard must hold store-s3's reader role, or the one service a human signs into can rewrite the findings."
  }
  precondition {
    condition     = local.control_ok
    error_message = "control_enabled needs control_role_arn, store-s3's control_role_arn, and it must differ from writer_role_arn and reader_role_arn. The reader role is shared with the connector, and the writer's can rewrite the findings."
  }
  precondition {
    condition     = local.control_sa_ok
    error_message = "control_service_account must be a service account of its own, not the writer's, the reader's or the connector's."
  }
}
