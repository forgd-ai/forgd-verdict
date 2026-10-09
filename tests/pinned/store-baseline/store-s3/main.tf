# The findings store on AWS, and the roles allowed to reach it.
#
# The counterpart of `store-azure`, for the same reason that module exists:
# ECS, EKS and a cluster that only wants `helm install` all need a bucket and
# an identity permitted to write there, and none of them should create it.
# Findings outlive the compute, so a `terraform destroy` of an app stack must
# not be able to take the evidence with it.
#
# PRIVACY: what lands here is findings -- detector, locator, and a one-way
# digest -- never prompt content. The bucket is private and stays private:
# all four public-access blocks are on and ACLs are disabled. A findings
# export is still sensitive: it is hashed, and those hashes are salted
# precisely because a bare digest of a low-entropy value is reversible.
#
# The module does not know whether its roles are assumed by EKS (IRSA or Pod
# Identity) or ECS (a task role), so each role's trust policy is an input.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

locals {
  # Every object key the store writes starts with this. Empty means the
  # whole bucket.
  key_root = var.key_prefix == "" ? "" : "${var.key_prefix}/"

  kms = var.kms_key_arn != null
}

resource "aws_s3_bucket" "findings" {
  bucket = var.bucket_name
  # False, so a destroy fails on a bucket that still holds findings rather
  # than emptying it first.
  force_destroy = false
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "findings" {
  bucket                  = aws_s3_bucket.findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ACLs off. Every object belongs to the bucket owner, so access is decided by
# IAM and the bucket policy alone and a writer cannot grant a third party
# read on an object it put.
resource "aws_s3_bucket_ownership_controls" "findings" {
  bucket = aws_s3_bucket.findings.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "findings" {
  bucket = aws_s3_bucket.findings.id
  # The store is append-only apart from its state and marker objects, so
  # versioning buys little against our own writes. It buys a recovery path
  # against an operator deleting a partition by hand: the delete leaves a
  # marker and the data stays as a noncurrent version.
  #
  # There is no lifecycle rule expiring noncurrent versions. It would be S3
  # deleting findings on a timer, in a store that promises nothing deletes.
  # The cost is that each rewrite of a state or marker object keeps its old
  # version indefinitely; those objects are small.
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.kms ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    # One data key per bucket rather than per object. Without it every put
    # and get is a KMS call, billed and rate-limited separately.
    bucket_key_enabled = local.kms
  }
}

# The WRITERS: the verdict server, the collector and the ingest job. Not the
# dashboard -- see `reader` below.
#
# ListBucket is not only for reading. With a key prefix it is scoped by
# `s3:prefix`, which a GetObject does not carry, so S3 answers a missing
# state object with 403. The store resolves that by listing the exact key,
# which this grant does allow (store/s3.py `_absent`).
data "aws_iam_policy_document" "writer" {
  statement {
    sid       = "ReadWriteFindings"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.findings.arn}/${local.key_root}*"]
  }

  statement {
    sid       = "ListFindings"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.findings.arn]
    dynamic "condition" {
      for_each = var.key_prefix == "" ? [] : [1]
      content {
        test     = "StringLike"
        variable = "s3:prefix"
        values   = [var.key_prefix, "${local.key_root}*"]
      }
    }
  }

  # With a customer-managed key, S3 calls KMS as the caller. Without these
  # every put fails with an AccessDenied that names S3, not the key.
  dynamic "statement" {
    for_each = local.kms ? [1] : []
    content {
      sid       = "UseFindingsKey"
      actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
      resources = [var.kms_key_arn]
    }
  }
}

# The dashboard's policy, and it only READS.
#
# The dashboard is the one internet-facing service a human signs into, so a
# compromise there must not be able to alter or delete findings -- rewriting
# the evidence, in a tool whose output is evidence.
data "aws_iam_policy_document" "reader" {
  statement {
    sid       = "ReadFindings"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.findings.arn}/${local.key_root}*"]
  }

  statement {
    sid       = "ListFindings"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.findings.arn]
    dynamic "condition" {
      for_each = var.key_prefix == "" ? [] : [1]
      content {
        test     = "StringLike"
        variable = "s3:prefix"
        values   = [var.key_prefix, "${local.key_root}*"]
      }
    }
  }

  dynamic "statement" {
    for_each = local.kms ? [1] : []
    content {
      sid       = "DecryptFindings"
      actions   = ["kms:Decrypt"]
      resources = [var.kms_key_arn]
    }
  }
}

resource "aws_iam_policy" "writer" {
  name   = "${var.writer_role_name}-findings"
  policy = data.aws_iam_policy_document.writer.json
  tags   = var.tags
}

resource "aws_iam_policy" "reader" {
  name   = "${var.reader_role_name}-findings"
  policy = data.aws_iam_policy_document.reader.json
  tags   = var.tags
}

resource "aws_iam_role" "writer" {
  name               = var.writer_role_name
  assume_role_policy = var.writer_assume_role_policy
  tags               = var.tags
}

resource "aws_iam_role" "reader" {
  name               = var.reader_role_name
  assume_role_policy = var.reader_assume_role_policy
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "writer" {
  role       = aws_iam_role.writer.name
  policy_arn = aws_iam_policy.writer.arn
}

resource "aws_iam_role_policy_attachment" "reader" {
  role       = aws_iam_role.reader.name
  policy_arn = aws_iam_policy.reader.arn
}

# Neither role policy grants a delete, and this deny means a policy attached
# to either role later cannot grant one either: an explicit deny in the
# bucket policy wins over any allow. Matching on aws:PrincipalArn rather than
# naming the roles as principals covers every session assumed from them.
#
# It does not stop a PutObject over an existing key. Versioning is what keeps
# the replaced object, and neither role can remove a version.
data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "NoDeletesByTheApp"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.findings.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.writer.arn, aws_iam_role.reader.arn]
    }
  }

  statement {
    sid     = "TLSOnly"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.findings.arn,
      "${aws_s3_bucket.findings.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "findings" {
  bucket = aws_s3_bucket.findings.id
  policy = data.aws_iam_policy_document.bucket.json

  # S3 rejects concurrent configuration writes to one bucket with
  # OperationAborted, and a policy that lands before the public-access block
  # is evaluated against the old settings.
  depends_on = [aws_s3_bucket_public_access_block.findings]
}
