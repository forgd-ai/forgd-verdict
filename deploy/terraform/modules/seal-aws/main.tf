# The key that seals matched values (privacy.sealing, docs/PRIVACY.md).
#
# An asymmetric KMS key for decryption only. Every forgd-verdict service
# seals with the key's public half, which is an output and goes into the
# policy; none of them is granted anything here, and the key policy
# denies the listed ones kms:Decrypt outright. The module allows
# kms:Decrypt to `decrypt_principal_arns`, the people who act on findings,
# and grants nothing else.
#
# The account keeps every other action on the key, so the key can still be
# administered, but not kms:Decrypt or kms:CreateGrant: delegating key use
# to IAM would let any principal whose IAM policy allows kms:Decrypt open
# every sealed value, and a grant is another way to give it.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_root = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"

  policy = {
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid       = "AccountAdministersTheKeyAndCannotUseIt"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        NotAction = ["kms:Decrypt", "kms:CreateGrant"]
        Resource  = "*"
      }],
      length(var.decrypt_principal_arns) == 0 ? [] : [{
        Sid       = "OperatorsDecryptSealedValues"
        Effect    = "Allow"
        Principal = { AWS = var.decrypt_principal_arns }
        Action    = ["kms:Decrypt"]
        Resource  = "*"
        Condition = { StringEquals = { "kms:EncryptionAlgorithm" = "RSAES_OAEP_SHA_256" } }
      }],
      length(var.service_principal_arns) == 0 ? [] : [{
        Sid       = "ServicesNeverDecrypt"
        Effect    = "Deny"
        Principal = { AWS = var.service_principal_arns }
        Action    = ["kms:Decrypt", "kms:CreateGrant"]
        Resource  = "*"
      }],
    )
  }
}

resource "aws_kms_key" "seal" {
  description              = var.description
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = var.key_spec
  deletion_window_in_days  = var.deletion_window_in_days
  policy                   = jsonencode(local.policy)
  tags                     = var.tags

  lifecycle {
    precondition {
      condition     = length(setintersection(var.decrypt_principal_arns, var.service_principal_arns)) == 0
      error_message = "A principal in service_principal_arns is also in decrypt_principal_arns. No forgd-verdict service may decrypt sealed values: each needs only the public key."
    }
  }
}

resource "aws_kms_alias" "seal" {
  name          = "alias/${var.alias}"
  target_key_id = aws_kms_key.seal.key_id
}

data "aws_kms_public_key" "seal" {
  key_id = aws_kms_key.seal.arn
}
