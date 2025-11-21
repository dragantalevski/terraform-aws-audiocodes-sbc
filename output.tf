output "iam_current" {
  value = data.aws_caller_identity.current.account_id
}

output "ac_saz_sbc_instance_profile" {
  value = aws_iam_instance_profile.ac_saz_sbc_instance_profile.name
}

output "public_ip_id" {
  value = aws_eip.public_ip.allocation_id
}
output "public_ip" {
  value = aws_eip.public_ip.public_ip
}

output "ac_sbc_key" {
  value = aws_key_pair.ac_sbc_key.key_name
}

output "ac_sbc_public_key" {
  value = aws_key_pair.ac_sbc_key.public_key
}

