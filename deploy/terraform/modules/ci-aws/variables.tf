variable "name_prefix" {
  type        = string
  default     = "forgd-verdict"
  description = "The role is <name_prefix>-deploy."
  validation {
    condition     = can(regex("^[a-zA-Z0-9+=,.@_-]{1,57}$", var.name_prefix))
    error_message = "name_prefix must be at most 57 IAM role-name characters, so that <prefix>-deploy fits in 64."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "github_org" {
  type        = string
  description = "The GitHub owner of the repository that deploys, as in github.com/<org>/<repo>."
  validation {
    condition     = can(regex("^[A-Za-z0-9](?:-?[A-Za-z0-9])*$", var.github_org)) && length(var.github_org) <= 39
    error_message = "github_org must be a GitHub user or organization name: up to 39 letters, digits or single hyphens, not starting or ending with one."
  }
}

variable "github_repo" {
  type        = string
  description = "The repository that deploys: the customer's fork."
  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,100}$", var.github_repo)) && !contains([".", ".."], var.github_repo)
    error_message = "github_repo must be a repository name, without the owner: up to 100 letters, digits, dots, underscores or hyphens."
  }
}

variable "github_environment" {
  type        = string
  description = "The GitHub environment the deploy job runs in: verdict-cd-aws for the deploy-aws job in .github/workflows/deploy.yml, which a fork copies from examples/github/deploy.yml. The role trusts a token from this environment and nothing else in the repository."
  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,255}$", var.github_environment))
    error_message = "github_environment must be one environment name of 1 to 255 letters, digits, dots, underscores or hyphens."
  }
}

variable "github_owner_id" {
  type        = number
  default     = null
  description = "The numeric id of github_org (`gh api orgs/<org> --jq .id`). Set it, with github_repo_id, when the organization has immutable OIDC identifiers enabled: its tokens then name the org and repo by id, and the short-form subject alone matches nothing."
}

variable "github_repo_id" {
  type        = number
  default     = null
  description = "The numeric id of the repository (`gh api repos/<org>/<repo> --jq .id`). Set with github_owner_id."
}

variable "create_oidc_provider" {
  type        = bool
  default     = false
  description = "Create the account's token.actions.githubusercontent.com OIDC provider. Set this or oidc_provider_arn, not both."
}

variable "oidc_provider_arn" {
  type        = string
  default     = null
  description = "The account's existing token.actions.githubusercontent.com OIDC provider. Set this or create_oidc_provider, not both."
}

variable "ecr_repository_arn" {
  type        = string
  description = "The one repository the role may push to."
  validation {
    condition     = can(regex("^arn:aws[a-z-]*:ecr:[a-z0-9-]+:[0-9]{12}:repository/[a-z0-9._/-]+$", var.ecr_repository_arn))
    error_message = "ecr_repository_arn must be one ECR repository ARN, with no wildcard."
  }
}

variable "ecs" {
  type = object({
    service_arns         = list(string)
    task_definition_arns = list(string)
    task_role_arns       = list(string)
    schedule_arn         = string
    schedule_role_arn    = string
  })
  default     = null
  description = "The app-ecs stack the role may roll. Pass module.<app-ecs>.ci_release. Null: no ECS permissions."
  validation {
    condition = var.ecs == null ? true : alltrue([
      for arn in concat(var.ecs.service_arns, var.ecs.task_role_arns, [var.ecs.schedule_arn, var.ecs.schedule_role_arn]) :
      !strcontains(arn, "*")
    ])
    error_message = "ecs ARNs must name resources; only task_definition_arns may end in :* (every revision of one family)."
  }
  validation {
    condition = var.ecs == null ? true : alltrue([
      for arn in var.ecs.task_definition_arns : can(regex("^arn:aws[a-z-]*:ecs:[a-z0-9-]+:[0-9]{12}:task-definition/[A-Za-z0-9_-]+:\\*$", arn))
    ])
    error_message = "ecs.task_definition_arns must each be arn:...:task-definition/<family>:*."
  }
}

variable "eks" {
  type = object({
    cluster_name = string
    namespace    = string
  })
  default     = null
  description = "The cluster and the release namespace helm upgrades in. Null: no EKS permissions and no access entry."
  validation {
    condition     = var.eks == null ? true : length(var.eks.namespace) > 0 && length(var.eks.cluster_name) > 0
    error_message = "eks.cluster_name and eks.namespace must both be set."
  }
}
