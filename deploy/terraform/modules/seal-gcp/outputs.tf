output "sealing_key" {
  description = "privacy.sealing.key: the KMS, the key version, and its public half."
  value = {
    kms        = "gcp"
    id         = "${google_kms_crypto_key.seal.id}/cryptoKeyVersions/${var.key_version}"
    public_key = data.google_kms_crypto_key_version.seal.public_key[0].pem
  }
}

output "crypto_key_id" {
  value = google_kms_crypto_key.seal.id
}
