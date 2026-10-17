output "sealing_key" {
  description = "privacy.sealing.key: the KMS, the key by ARN, and its public half."
  value = {
    kms        = "aws"
    id         = aws_kms_key.seal.arn
    public_key = data.aws_kms_public_key.seal.public_key_pem
  }
}

output "key_arn" {
  value = aws_kms_key.seal.arn
}
