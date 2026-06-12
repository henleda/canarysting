output "boxes" {
  description = "Per-scope box addresses (public for SSH/setup, private for the in-VPC role)."
  value = {
    for k, b in aws_instance.box : k => {
      public_ip  = b.public_ip
      private_ip = b.private_ip
      instance   = b.id
    }
  }
}

output "ssh" {
  description = "Ready-to-use SSH commands per box."
  value = {
    for k, b in aws_instance.box : k => "ssh -i ~/.ssh/canarysting-dev ubuntu@${b.public_ip}"
  }
}
