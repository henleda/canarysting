#!/usr/bin/env bash
# First-boot prep for a k3 crossing contributor box. Installs the toolchain needed to
# build staged-range + envoy-adapter on the box and to run a light canary surface
# (Docker: Envoy + one backend). Heavy lifting (rsync repo, build, seed canaries,
# write config, enable units) is done by box-setup.sh, run by the operator after boot.
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl git build-essential rsync jq

# Docker (for Envoy + the backend container).
install -m0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=arm64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
usermod -aG docker ubuntu || true

# Go (build staged-range + envoy-adapter on-box; matches the dev box family).
GO_VER=1.25.3
curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-arm64.tar.gz" -o /tmp/go.tgz
rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz
echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh

# CanarySting dirs (binaries, config, durable state).
mkdir -p /opt/canarysting/bin /etc/canarysting /var/lib/canarysting
chown -R ubuntu:ubuntu /opt/canarysting /etc/canarysting /var/lib/canarysting

touch /var/lib/canarysting/.cloud-init-done
