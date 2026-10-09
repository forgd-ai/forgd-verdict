# The findings store on Google Cloud, and the service accounts allowed to
# reach it.
#
# The counterpart of `store-azure` and `store-s3`: a bucket, a writer and a
# reader, created apart from any compute so that a `terraform destroy` of an
# app stack cannot take the evidence with it.
#
# PRIVACY: what lands here is findings -- detector, locator, and a one-way
# digest -- never prompt content. The bucket is private and stays private:
# public access prevention is enforced and uniform bucket-level access turns
# object ACLs off.
#
# DELETE. GCS checks `storage.objects.delete` on any write that replaces an
# object, and the store replaces three kinds in place: the cursors under
# `state/` and the two marker objects. So the writer holds delete on exactly
# those names, through an IAM condition, and on nothing else. A record is
# written with `if_generation_match=0` and is never replaced, so neither
# service account can delete a finding. What the writer can delete costs no
# evidence: a lost cursor costs a rescan, and a lost marker costs an
# exclusion or a reset that can be redone. Versioning keeps every replaced
# cursor and marker as a noncurrent version.
#
# PREFIX. With `key_prefix` set, create and get are limited to objects under
# it. A list is checked on the bucket and cannot be scoped by name, so both
# accounts can list every object name in the bucket. Use a dedicated bucket.
#
# The module binds no workload to either account. Grant
# `roles/iam.workloadIdentityUser` on each to the Kubernetes service account
# or attach it to the Cloud Run service in the stack that runs the app.
# `writer_members` and `reader_members` add identities that get exactly the
# writer's or the reader's bucket bindings, conditions included; app-cloudrun
# passes its per-role accounts here.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.0"
    }
  }
}

locals {
  # Every object name the store writes starts with this. Empty means the
  # whole bucket.
  key_root = var.key_prefix == "" ? "" : "${var.key_prefix}/"

  # The IAM resource name of an object in this bucket, up to the object name.
  object_root = "projects/_/buckets/${var.bucket_name}/objects/${local.key_root}"

  # The objects the store replaces in place: STATE_PREFIX, RESET_MARKER and
  # EXCLUDE_MARKER in src/forgd_verdict/store/base.py, under the key prefix.
  mutable_delete_condition = join(" || ", [
    "resource.name.startsWith(\"${local.object_root}state/\")",
    "resource.name == \"${local.object_root}markers/stats_reset\"",
    "resource.name == \"${local.object_root}markers/excluded_requests\"",
  ])

  # With a key prefix, the data bindings hold on the bucket itself, where
  # storage.objects.list is checked, and on objects under the prefix. The
  # bucket clause lets a list see every object name in the bucket.
  prefix_scoped  = var.key_prefix != ""
  data_condition = "resource.name == \"projects/_/buckets/${var.bucket_name}\" || resource.name.startsWith(\"${local.object_root}\")"

  kms = var.kms_key_name != null

  # The module's own account under a fixed key, and each extra under its
  # caller's key, so that every key is known at plan time even when a
  # member's email is not.
  writer_members = merge(
    { module = "serviceAccount:${google_service_account.writer.email}" },
    { for k, m in var.writer_members : "extra-${k}" => m },
  )
  reader_members = merge(
    { module = "serviceAccount:${google_service_account.reader.email}" },
    { for k, m in var.reader_members : "extra-${k}" => m },
  )

  # The dashboard's control identity (docs/OVERRIDES.md): the module's
  # control account under a fixed key, and each of control_members under its
  # caller's key, all only while control_enabled. Each also gets the readers'
  # binding, through read_members.
  control_members = var.control_enabled ? merge(
    { control = "serviceAccount:${google_service_account.control[0].email}" },
    { for k, m in var.control_members : "extra-${k}" => m },
  ) : {}
  read_members = merge(local.reader_members, local.control_members)

  # The only names the control identity may create: the runtime overrides
  # object and the audit prefix, under the key prefix.
  control_overrides_object = "${local.object_root}state/runtime-overrides.json"
  control_audit_prefix     = "${local.object_root}audit/runtime-overrides/"
  control_create_condition = join(" || ", [
    "resource.name == \"${local.control_overrides_object}\"",
    "resource.name.startsWith(\"${local.control_audit_prefix}\")",
  ])
  # Replacing the overrides object needs delete as well as create. The audit
  # prefix gets no delete.
  control_delete_condition = "resource.name == \"${local.control_overrides_object}\""

  # While control_enabled, the writers' create and delete hold everywhere
  # they otherwise would except the overrides object and the audit prefix,
  # which only the control identity writes. Conditions only allow, so the
  # exclusion is a negated clause ANDed onto each; it applies with and
  # without a key prefix. Off, both are the conditions they were before
  # control existed.
  writer_exclusion = join(" && ", [
    "!resource.name.startsWith(\"${local.control_overrides_object}\")",
    "!resource.name.startsWith(\"${local.control_audit_prefix}\")",
  ])
  writer_create_condition = (!var.control_enabled ? local.data_condition
    : local.prefix_scoped ? "(${local.data_condition}) && ${local.writer_exclusion}"
  : local.writer_exclusion)
  writer_delete_condition = var.control_enabled ? "(${local.mutable_delete_condition}) && ${local.writer_exclusion}" : local.mutable_delete_condition
}

data "google_storage_project_service_account" "gcs" {
  count   = local.kms ? 1 : 0
  project = var.project_id
}

# With a customer-managed key, GCS encrypts as its own service agent, and
# without this every write fails.
resource "google_kms_crypto_key_iam_member" "gcs_agent" {
  count         = local.kms ? 1 : 0
  crypto_key_id = var.kms_key_name
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs[0].email_address}"
}

resource "google_storage_bucket" "findings" {
  project  = var.project_id
  name     = var.bucket_name
  location = var.location
  # False, so a destroy fails on a bucket that still holds findings rather
  # than emptying it first.
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = var.labels

  # There is no lifecycle rule. Expiring noncurrent versions would be GCS
  # deleting old cursors and markers on a timer, and a rule is one edit
  # away from matching records too.
  versioning {
    enabled = true
  }

  dynamic "encryption" {
    for_each = local.kms ? [1] : []
    content {
      default_kms_key_name = var.kms_key_name
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.gcs_agent]
}

resource "google_service_account" "writer" {
  project      = var.project_id
  account_id   = var.writer_account_id
  display_name = "forgd-verdict findings writer"
  description  = "The verdict server, the collector and the ingest job."
}

resource "google_service_account" "reader" {
  project      = var.project_id
  account_id   = var.reader_account_id
  display_name = "forgd-verdict findings reader"
  description  = "The dashboard. Reads findings and never writes or deletes."
}

resource "google_service_account" "control" {
  count = var.control_enabled ? 1 : 0

  project      = var.project_id
  account_id   = var.control_account_id
  display_name = "forgd-verdict dashboard control"
  description  = "The dashboard with admins enabled. The reader's access plus writes to the runtime overrides object and its audit records."
}

# The WRITERS, the module's account and each of writer_members: create, get
# and list. objectCreator holds create without delete, so on its own it
# cannot replace an object. With a key prefix, create and get are limited to
# objects under it. While control_enabled, create never reaches the runtime
# overrides object or its audit records.
resource "google_storage_bucket_iam_member" "writer_create" {
  for_each = local.writer_members

  bucket = google_storage_bucket.findings.name
  role   = "roles/storage.objectCreator"
  member = each.value

  dynamic "condition" {
    for_each = var.control_enabled || local.prefix_scoped ? [1] : []
    content {
      title       = var.control_enabled ? "forgd-verdict writes" : "forgd-verdict key prefix"
      description = var.control_enabled ? "Objects under the key prefix, if any, except the runtime overrides object and its audit records." : "The bucket, for listing, and objects under the key prefix."
      expression  = local.writer_create_condition
    }
  }

  # A changed condition is a new binding. Created first, the writers keep
  # create while the old binding is removed.
  lifecycle {
    create_before_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "writer_read" {
  for_each = local.writer_members

  bucket = google_storage_bucket.findings.name
  role   = "roles/storage.objectViewer"
  member = each.value

  dynamic "condition" {
    for_each = local.prefix_scoped ? [1] : []
    content {
      title       = "forgd-verdict key prefix"
      description = "The bucket, for listing, and objects under the key prefix."
      expression  = local.data_condition
    }
  }
}

# Delete, and nothing else, as a role that can be scoped by a condition.
# Defined in the project because GCS has no bucket-level custom roles; it is
# bound only on this bucket, below.
resource "google_project_iam_custom_role" "mutable_delete" {
  project     = var.project_id
  role_id     = var.mutable_delete_role_id
  title       = "forgd-verdict store: replace cursors and markers"
  description = "Only storage.objects.delete. Bound with a condition to the store's state and marker objects."
  permissions = ["storage.objects.delete"]
}

resource "google_storage_bucket_iam_member" "writer_mutable_delete" {
  for_each = local.writer_members

  bucket = google_storage_bucket.findings.name
  role   = google_project_iam_custom_role.mutable_delete.id
  member = each.value

  condition {
    title       = "forgd-verdict mutable objects"
    description = var.control_enabled ? "The store's cursors and its two markers, except the runtime overrides object. Never verdicts or denials." : "The store's cursors and its two markers. Never verdicts or denials."
    expression  = local.writer_delete_condition
  }

  lifecycle {
    create_before_destroy = true
  }
}

# The dashboard's access, for the module's reader, each of reader_members
# and each control member, and it only READS.
#
# The dashboard is the one internet-facing service a human signs into, so a
# compromise there must not be able to alter or delete findings.
resource "google_storage_bucket_iam_member" "reader_read" {
  for_each = local.read_members

  bucket = google_storage_bucket.findings.name
  role   = "roles/storage.objectViewer"
  member = each.value

  dynamic "condition" {
    for_each = local.prefix_scoped ? [1] : []
    content {
      title       = "forgd-verdict key prefix"
      description = "The bucket, for listing, and objects under the key prefix."
      expression  = local.data_condition
    }
  }

  lifecycle {
    precondition {
      condition     = var.control_enabled || length(var.control_members) == 0
      error_message = "control_members is set but control_enabled is false, so they would get no binding. Set control_enabled, or move them to reader_members."
    }
  }
}

# The control identity's writes: create on the overrides object and under
# the audit prefix, and delete on the overrides object alone. Its reads are
# the readers' binding above.
resource "google_storage_bucket_iam_member" "control_create" {
  for_each = local.control_members

  bucket = google_storage_bucket.findings.name
  role   = "roles/storage.objectCreator"
  member = each.value

  condition {
    title       = "forgd-verdict runtime overrides"
    description = "The runtime overrides object and its audit records."
    expression  = local.control_create_condition
  }

  lifecycle {
    precondition {
      condition     = length(setintersection(keys(var.control_members), keys(var.reader_members))) == 0
      error_message = "control_members and reader_members share a key. Both key the readers' binding, so one entry would replace the other."
    }
    precondition {
      condition     = length(setintersection(values(local.control_members), concat(values(local.reader_members), values(local.writer_members)))) == 0
      error_message = "A control member is also a reader or a writer member. The control identity must be its own: the reader's is shared with the connector, and the writer's can rewrite the findings."
    }
  }
}

# The control identity reads the bucket's IAM policy to verify the
# writers' lockout. GCS has no bucket-level custom roles, so the role is
# defined in the project and bound only on this bucket.
resource "google_project_iam_custom_role" "control_iam_read" {
  count       = var.control_enabled ? 1 : 0
  project     = var.project_id
  role_id     = var.control_iam_read_role_id
  title       = "forgd-verdict store: read the bucket IAM policy"
  description = "Only storage.buckets.getIamPolicy. Bound on the findings bucket for the dashboard's control identity."
  permissions = ["storage.buckets.getIamPolicy"]
}

resource "google_storage_bucket_iam_member" "control_iam_read" {
  for_each = local.control_members

  bucket = google_storage_bucket.findings.name
  role   = google_project_iam_custom_role.control_iam_read[0].id
  member = each.value
}

# The lockout check reads each role a writer holds for its permissions,
# and a project custom role, such as mutable_delete, can be read only with
# iam.roles.get on the project. This role and its binding are the module's
# one project-level grant.
resource "google_project_iam_custom_role" "control_role_read" {
  count       = var.control_enabled ? 1 : 0
  project     = var.project_id
  role_id     = var.control_role_read_role_id
  title       = "forgd-verdict store: read role definitions"
  description = "Only iam.roles.get. Bound on the project for the dashboard's control identity."
  permissions = ["iam.roles.get"]
}

resource "google_project_iam_member" "control_role_read" {
  for_each = local.control_members

  project = var.project_id
  role    = google_project_iam_custom_role.control_role_read[0].id
  member  = each.value
}

resource "google_storage_bucket_iam_member" "control_overrides_delete" {
  for_each = local.control_members

  bucket = google_storage_bucket.findings.name
  role   = google_project_iam_custom_role.mutable_delete.id
  member = each.value

  condition {
    title       = "forgd-verdict runtime overrides object"
    description = "Replacing the runtime overrides object. Never an audit record."
    expression  = local.control_delete_condition
  }
}

# Where these bindings lived before they took extra members. Without these a
# plan destroys each old address, and destroying an iam_member removes the
# binding its replacement just created.
moved {
  from = google_storage_bucket_iam_member.writer_create
  to   = google_storage_bucket_iam_member.writer_create["module"]
}

moved {
  from = google_storage_bucket_iam_member.writer_read
  to   = google_storage_bucket_iam_member.writer_read["module"]
}

moved {
  from = google_storage_bucket_iam_member.writer_mutable_delete
  to   = google_storage_bucket_iam_member.writer_mutable_delete["module"]
}

moved {
  from = google_storage_bucket_iam_member.reader_read
  to   = google_storage_bucket_iam_member.reader_read["module"]
}
