resource "aws_key_pair" "k3" {
  key_name   = var.name
  public_key = file(pathexpand(var.public_key_path))
}

# ONE shared SG for all three boxes: SSH from the operator + all egress. Deliberately
# adds NO ingress to the server SG and NO inter-box rules — each box attacks its OWN
# localhost canary surface, and confirmation spools move operator-relayed over SSH
# (all from the operator IP, which SSH already allows). Egress covers apt/Go module
# fetch + the rsync to the aggregator box.
resource "aws_security_group" "k3" {
  name        = "${var.name}-sg"
  description = "CanarySting k3 crossing boxes: SSH from operator; all egress. No server-SG or inter-box rules."
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
  tags = { Name = "${var.name}-sg", Project = "canarysting", Role = "k3-crossing" }
}

resource "aws_instance" "box" {
  for_each = var.boxes

  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.k3.key_name
  subnet_id                   = data.aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.k3.id]
  associate_public_ip_address = true
  private_ip                  = each.value
  user_data                   = file("${path.module}/user_data.sh")

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    encrypted   = true
  }
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  tags = { Name = "${var.name}-${each.key}", Project = "canarysting", Role = "k3-crossing", Scope = each.key }
}
