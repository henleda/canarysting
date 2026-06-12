# READ-ONLY data sources only. This module finds the existing dev/server box's VPC
# + subnet by the tags the dev-box module set, and the Ubuntu AMI — and creates its
# OWN boxes in that subnet. It NEVER imports the dev-box state, NEVER references the
# server instance, and NEVER modifies the server's security group (the crossing uses
# a file/rsync transport and each box attacks its OWN localhost canaries, so no
# server ingress rule is needed). The live M7 server is untouched by apply/destroy.

data "aws_vpc" "dev" {
  filter {
    name   = "tag:Name"
    values = ["${var.dev_name}-vpc"]
  }
}

data "aws_subnet" "public" {
  filter {
    name   = "tag:Name"
    values = ["${var.dev_name}-public"]
  }
}

# Latest Ubuntu 24.04 arm64 (matches the dev box family). The contributor boxes run
# COLD-START (no eBPF observe baseline), so a BTF kernel is not strictly required,
# but keeping one AMI family is simplest.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-arm64-server-*"]
  }
  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}
