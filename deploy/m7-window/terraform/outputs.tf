output "client_public_ip" {
  description = "Public IPv4 of the client box (SSH here to set up the generator/prober)."
  value       = aws_instance.client.public_ip
}

output "client_private_ip" {
  description = "Primary private IP of the client box."
  value       = aws_instance.client.private_ip
}

output "server_private_ip" {
  description = "Private IP of the dev/server box — the generator/prober target (Envoy)."
  value       = data.aws_instance.server.private_ip
}

output "envoy_target" {
  description = "The Envoy base URL the generator/prober hit."
  value       = "http://${data.aws_instance.server.private_ip}:${var.envoy_port}"
}

output "legit_ips" {
  description = "Secondary IPs the generator binds as legit identities."
  value       = var.legit_ips
}

output "attacker_ip" {
  description = "Secondary IP the prober binds as the attacker identity."
  value       = var.attacker_ip
}

output "ssh" {
  description = "SSH to the client box."
  value       = "ssh -i ~/.ssh/canarysting-dev ubuntu@${aws_instance.client.public_ip}"
}
