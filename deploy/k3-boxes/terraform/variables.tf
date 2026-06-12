variable "region" {
  description = "AWS region (must match the dev/server box)."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Name tag / resource prefix for the k3 crossing boxes."
  type        = string
  default     = "canarysting-k3"
}

variable "dev_name" {
  description = "The dev/server box's name prefix — used to find its VPC + subnet by tag (READ-ONLY data sources; this module never touches the dev-box state or the server instance)."
  type        = string
  default     = "canarysting-dev"
}

variable "instance_type" {
  description = "Contributor box type. t4g.small = Graviton arm64, 2 vCPU / 2 GiB — ample for a light cold-start canary surface (Envoy + 1 backend + engine + adapter). ~\\$12/mo each."
  type        = string
  default     = "t4g.small"
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed to SSH the boxes (operator /32). The operator's laptop is also the rsync relay that moves each box's confirmation spool to the aggregator box."
  type        = string
}

variable "public_key_path" {
  description = "SSH public key installed on the boxes (reuse the dev key)."
  type        = string
  default     = "~/.ssh/canarysting-dev.pub"
}

variable "root_volume_gb" {
  description = "Root gp3 volume (GiB). Room for Go + Docker (Envoy + backend) + the binaries."
  type        = number
  default     = 20
}

variable "boxes" {
  description = "The three enrolled contributor scopes: logical name => primary private IP. IPs must be free in the dev subnet (10.20.1.0/24; .24/.101-103/.111 are taken)."
  type        = map(string)
  default = {
    "scope-1" = "10.20.1.120"
    "scope-2" = "10.20.1.130"
    "scope-3" = "10.20.1.140"
  }
}
