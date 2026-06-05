#!/usr/bin/env bash
# CanarySting dev box provisioning (ROADMAP M0).
# Runs once on first boot via cloud-init. Installs the Go + eBPF/CO-RE toolchain
# the kernel and proxy work need, plus Docker for the staged environment (M4/M7).
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive
GO_VERSION="1.25.3"

apt-get update -y
apt-get install -y --no-install-recommends \
  build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config \
  git make curl ca-certificates jq unzip

# bpftool — provided by linux-tools. The versioned package can lag a fresh kernel,
# so try it but don't fail the whole provision if it isn't published yet.
apt-get install -y linux-tools-common linux-tools-generic || true
apt-get install -y "linux-tools-$(uname -r)" || true

# Go (arm64), pinned to match the local toolchain.
curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz" -o /tmp/go.tgz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tgz
rm -f /tmp/go.tgz
cat > /etc/profile.d/go.sh <<'EOF'
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
EOF
chmod +x /etc/profile.d/go.sh

# Docker (staged microservice environment, M4/M7).
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu

# Completion marker — polled by the operator to know cloud-init finished.
{
  echo "provisioned_at=$(date -u +%FT%TZ)"
  echo "kernel=$(uname -r)"
  echo "go=$(/usr/local/go/bin/go version 2>/dev/null || echo MISSING)"
  echo "clang=$(clang --version 2>/dev/null | head -1 || echo MISSING)"
  echo "bpftool=$(bpftool version 2>/dev/null | head -1 || echo MISSING)"
  echo "btf=$([ -f /sys/kernel/btf/vmlinux ] && echo present || echo MISSING)"
  echo "docker=$(docker --version 2>/dev/null || echo MISSING)"
} > /var/log/canarysting-provision.done
chown ubuntu:ubuntu /var/log/canarysting-provision.done
