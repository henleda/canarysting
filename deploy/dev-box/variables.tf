variable "region" {
  description = "AWS region for the dev box."
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type. m7g.large = Graviton arm64, 2 vCPU / 8 GiB."
  type        = string
  default     = "m7g.large"
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed to reach SSH (port 22). Lock to your operator /32."
  type        = string
}

variable "public_key_path" {
  description = "Path to the SSH public key installed on the box."
  type        = string
  default     = "~/.ssh/canarysting-dev.pub"
}

variable "root_volume_gb" {
  description = "Root EBS (gp3) volume size in GiB. Room for Go builds, Docker images, eBPF objects."
  type        = number
  default     = 40
}

variable "name" {
  description = "Name tag / resource prefix."
  type        = string
  default     = "canarysting-dev"
}
