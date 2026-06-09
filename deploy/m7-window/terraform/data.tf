# Find the existing dev/server box's network + instance by the tags the dev-box
# module set (deploy/dev-box). The client box joins the SAME subnet so it reaches
# the server over PRIVATE IPs only — no public exposure of Envoy.

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

data "aws_security_group" "dev" {
  filter {
    name   = "tag:Name"
    values = ["${var.dev_name}-sg"]
  }
}

# The server/dev box itself — for its private IP (the generator/prober target).
data "aws_instance" "server" {
  filter {
    name   = "tag:Name"
    values = [var.dev_name]
  }
  filter {
    name   = "instance-state-name"
    values = ["running"]
  }
}

# Latest Ubuntu 24.04 arm64 (matches the dev box; BTF kernel not required on the
# client, but keeping one AMI family is simplest).
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
