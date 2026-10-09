variable "project_id" {
  type        = string
  description = "The project that holds the pool, the CD account, the Cloud Run services and job, and the GKE cluster."
}

variable "region" {
  type        = string
  description = "The Cloud Run region, e.g. europe-west2. Set it as GCP_REGION."
}

variable "name_prefix" {
  type        = string
  default     = "forgd-verdict"
  description = "The account is <name_prefix>-deploy."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,22}$", var.name_prefix))
    error_message = "name_prefix must be 5 to 23 lowercase letters, digits or hyphens starting with a letter, so that <prefix>-deploy is a service account id of at most 30."
  }
}

variable "pool_id" {
  type        = string
  default     = "forgd-verdict-github"
  description = "The Workload Identity Pool id. A deleted pool keeps its id for 30 days, so a re-apply after a destroy needs a new one."
  validation {
    condition     = can(regex("^[a-z0-9-]{4,32}$", var.pool_id)) && !startswith(var.pool_id, "gcp-")
    error_message = "pool_id must be 4 to 32 lowercase letters, digits or hyphens, and not start with gcp-."
  }
}

variable "github_repository_id" {
  type        = string
  description = "The numeric id of the repository that deploys, the customer's fork (`gh api repos/<owner>/<repo> --jq .id`). A numeric id survives a rename, and a new repository at the old name does not inherit it."
  validation {
    condition     = can(regex("^[0-9]+$", var.github_repository_id))
    error_message = "github_repository_id must be the repository's numeric id, as a string."
  }
}

variable "github_owner_id" {
  type        = string
  description = "The numeric id of the repository's owner (`gh api repos/<owner>/<repo> --jq .owner.id`)."
  validation {
    condition     = can(regex("^[0-9]+$", var.github_owner_id))
    error_message = "github_owner_id must be the owner's numeric id, as a string."
  }
}

variable "github_environment" {
  type        = string
  default     = "verdict-cd-gcp"
  description = "The GitHub environment the deploy job runs in. The provider admits a token from this environment and nothing else in the repository."
  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,255}$", var.github_environment))
    error_message = "github_environment must be one environment name of 1 to 255 letters, digits, dots, underscores or hyphens."
  }
}

variable "artifact_registry" {
  type = object({
    location      = string
    repository_id = string
  })
  description = "The one Artifact Registry repository, in project_id, the account may push to."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,62}$", var.artifact_registry.repository_id)) && length(var.artifact_registry.location) > 0
    error_message = "artifact_registry must name one repository by id and location, with no wildcard."
  }
}

variable "cloudrun" {
  type = object({
    services                 = map(string)
    ingest_job               = string
    runtime_service_accounts = list(string)
  })
  default     = null
  description = <<-D
    The app-cloudrun stack the account may roll, in region. services maps
    role -> service name for verdict, collector, dashboard and, when they are
    enabled, intake and connector. runtime_service_accounts are the emails those services
    and the job run as: app-cloudrun's service_account_emails values. The
    account may act as these and no other. Null: no Cloud Run permissions.
  D
  validation {
    condition = var.cloudrun == null ? true : (
      contains(keys(var.cloudrun.services), "verdict") &&
      contains(keys(var.cloudrun.services), "collector") &&
      contains(keys(var.cloudrun.services), "dashboard") &&
      alltrue([for role in keys(var.cloudrun.services) : contains(["verdict", "collector", "dashboard", "intake", "connector"], role)])
    )
    error_message = "cloudrun.services must have verdict, collector and dashboard, may have intake and connector, and nothing else."
  }
  validation {
    condition = var.cloudrun == null ? true : alltrue([
      for name in concat(values(var.cloudrun.services), [var.cloudrun.ingest_job]) : can(regex("^[a-z][a-z0-9-]{0,62}$", name))
    ])
    error_message = "cloudrun service and job names must each name one resource, with no wildcard."
  }
  validation {
    condition = var.cloudrun == null ? true : length(var.cloudrun.runtime_service_accounts) > 0 && alltrue([
      for email in var.cloudrun.runtime_service_accounts : can(regex("^[a-z][a-z0-9-]{4,29}@[a-z0-9.:-]+\\.iam\\.gserviceaccount\\.com$", email))
    ])
    error_message = "cloudrun.runtime_service_accounts must each be one service account email."
  }
}

variable "gke" {
  type = object({
    cluster   = string
    location  = string
    namespace = string
  })
  default     = null
  description = <<-D
    The cluster and the release namespace helm upgrades in. The account gets
    roles/container.clusterViewer on the project, to fetch credentials, and
    nothing inside the cluster. Bind it in the namespace by applying the
    gke_rbac_manifest output: RoleBindings, subject the account's email, to
    ClusterRole edit and to a Role over the chart's GKE custom resources.
    edit lets the account read the namespace's Secrets, including the
    signing secret, and run pods as the chart's service accounts, which act
    as the store's accounts through Workload Identity; helm needs it to
    read and write its release records, which are Secrets.
    The deploy job fetches credentials through the cluster's DNS endpoint,
    so CD from a hosted GitHub runner needs cluster-gke's
    dns_endpoint_allow_external_traffic = true, or else a self-hosted runner
    inside the VPC. Null: no GKE permissions.
  D
  validation {
    condition     = var.gke == null ? true : length(var.gke.cluster) > 0 && length(var.gke.location) > 0 && length(var.gke.namespace) > 0
    error_message = "gke.cluster, gke.location and gke.namespace must all be set."
  }
}
