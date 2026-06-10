resource "aws_key_pair" "client" {
  key_name   = var.name
  public_key = file(pathexpand(var.public_key_path))
}

resource "aws_security_group" "client" {
  name        = "${var.name}-sg"
  description = "M7 client box: SSH from operator; all egress (reaches the server Envoy over private IPs)."
  vpc_id      = data.aws_vpc.dev.id

  ingress {
    description = "SSH from operator IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }
  egress {
    description = "All egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.name}-sg", Project = "canarysting", Role = "m7-client" }
}

# Open the server box's Envoy port to the client SG only — PRIVATE, no public CIDR.
# This rule is added to the dev/server SG (found by tag); destroy removes it.
resource "aws_security_group_rule" "server_envoy_from_client" {
  type                     = "ingress"
  from_port                = var.envoy_port
  to_port                  = var.envoy_port
  protocol                 = "tcp"
  security_group_id        = data.aws_security_group.dev.id
  source_security_group_id = aws_security_group.client.id
  description              = "M7 client generator and prober to server Envoy (private only)"
}

# Open the server's dashboard data tap to the client SG only (private) so the M9
# attacker can POST its live real-cost ledger to the tap (D5 live meter). Without
# this the meter no-ops and the run-end -cost-out JSON is the source of truth.
resource "aws_security_group_rule" "server_tap_from_client" {
  type                     = "ingress"
  from_port                = var.tap_port
  to_port                  = var.tap_port
  protocol                 = "tcp"
  security_group_id        = data.aws_security_group.dev.id
  source_security_group_id = aws_security_group.client.id
  description              = "M9 client attacker live-cost-meter POST to server dashboard tap (private only)"
}

resource "aws_instance" "client" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.client.key_name
  subnet_id                   = data.aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.client.id]
  associate_public_ip_address = true
  user_data                   = file("${path.module}/user_data.sh")

  # The four caller identities as real private IPs the generator/prober bind, so
  # the server observes a real population of distinct sources. t4g.small allows 4
  # IPs/interface, so the FIRST legit identity is the PRIMARY (auto-configured by
  # the OS) and the rest are secondaries (configured at boot by user_data).
  private_ip            = var.legit_ips[0]
  secondary_private_ips = concat(slice(var.legit_ips, 1, length(var.legit_ips)), [var.attacker_ip])

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    encrypted   = true
  }
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  tags = { Name = var.name, Project = "canarysting", Role = "m7-client" }
}
