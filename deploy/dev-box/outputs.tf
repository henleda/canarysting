output "instance_id" {
  description = "EC2 instance id."
  value       = aws_instance.dev.id
}

output "public_ip" {
  description = "Public IPv4 of the dev box."
  value       = aws_instance.dev.public_ip
}

output "public_dns" {
  description = "Public DNS of the dev box."
  value       = aws_instance.dev.public_dns
}

output "ami_id" {
  description = "Resolved Ubuntu 24.04 arm64 AMI."
  value       = data.aws_ami.ubuntu.id
}

output "ssh" {
  description = "SSH command (provisioning finishes a few minutes after boot)."
  value       = "ssh -i ~/.ssh/canarysting-dev ubuntu@${aws_instance.dev.public_ip}"
}

output "provision_check" {
  description = "Run this once SSH is up to confirm cloud-init finished."
  value       = "ssh -i ~/.ssh/canarysting-dev ubuntu@${aws_instance.dev.public_ip} 'cat /var/log/canarysting-provision.done'"
}
