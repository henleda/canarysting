variable "region" {
  description = "AWS region (must match the dev/server box)."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Name tag / resource prefix for the client box."
  type        = string
  default     = "canarysting-m7-client"
}

variable "dev_name" {
  description = "The dev/server box's name prefix — used to find its VPC, subnet, SG, and instance by tag."
  type        = string
  default     = "canarysting-dev"
}

variable "instance_type" {
  description = "Client box type. t4g.small = Graviton arm64, 2 vCPU / 2 GiB — ample for a traffic generator. ~\\$12/mo."
  type        = string
  default     = "t4g.small"
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed to SSH the client box. Lock to your operator /32."
  type        = string
}

variable "public_key_path" {
  description = "SSH public key installed on the client box (reuse the dev key)."
  type        = string
  default     = "~/.ssh/canarysting-dev.pub"
}

variable "root_volume_gb" {
  description = "Root gp3 volume (GiB). Room for Go + the generator/prober."
  type        = number
  default     = 20
}

variable "legit_ips" {
  description = "Secondary private IPs presented as the LEGIT generator identities."
  type        = list(string)
  default     = ["10.20.1.101", "10.20.1.102", "10.20.1.103"]
}

variable "attacker_ip" {
  description = "Secondary private IP presented as the attacker (prober) identity."
  type        = string
  default     = "10.20.1.111"
}

variable "envoy_port" {
  description = "Server-box Envoy ingress port the client reaches."
  type        = number
  default     = 8080
}
