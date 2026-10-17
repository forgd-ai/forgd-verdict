# The key that seals matched values (privacy.sealing, docs/PRIVACY.md).
#
# An asymmetric Cloud KMS key for decryption only, in a key ring of its
# own. Every forgd-verdict service seals with the key's public half, which
# is an output and goes into the policy; none of them is granted anything
# here. The module grants roles/cloudkms.cryptoKeyDecrypter on the key to
# `decrypt_members`, the people who act on findings, and nothing else.
# A project-level grant of a role that can decrypt still reaches the key;
# keep the services' project roles to what store-gcs grants.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.0"
    }
  }
}

resource "google_kms_key_ring" "seal" {
  project  = var.project_id
  name     = var.key_ring_name
  location = var.location
}

resource "google_kms_crypto_key" "seal" {
  name     = var.key_name
  key_ring = google_kms_key_ring.seal.id
  purpose  = "ASYMMETRIC_DECRYPT"
  # Days a destroyed version can still be restored. Destroying it loses
  # every value sealed to it.
  destroy_scheduled_duration = var.destroy_scheduled_duration
  deletion_policy            = var.deletion_policy
  labels                     = var.labels

  version_template {
    algorithm        = var.algorithm
    protection_level = var.protection_level
  }

  lifecycle {
    precondition {
      condition     = length(setintersection(var.decrypt_members, var.service_members)) == 0
      error_message = "A member in service_members is also in decrypt_members. No forgd-verdict service may decrypt sealed values: each needs only the public key."
    }
  }
}

resource "google_kms_crypto_key_iam_member" "decrypt" {
  for_each      = toset(var.decrypt_members)
  crypto_key_id = google_kms_crypto_key.seal.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = each.value
}

data "google_kms_crypto_key_version" "seal" {
  crypto_key = google_kms_crypto_key.seal.id
  version    = var.key_version
}
