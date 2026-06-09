#!/usr/bin/env bash
# Run on the CLIENT box. Builds + installs the benign generator and the prober and
# starts them against the server's Envoy. The generator binds the legit secondary
# IPs; the prober binds the attacker secondary IP (configured at boot by
# canarysting-secondary-ips.service). Restart=always units survive reboots.
#
# Usage: client-setup.sh <server-private-ip>
set -euo pipefail

SERVER_PRIV="${1:?usage: client-setup.sh <server-private-ip>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
export PATH="$PATH:/usr/local/go/bin"
BIN=/opt/canarysting/bin
ETC=/etc/canarysting

echo "=== build generator + prober ==="
go build -o /tmp/client-generator ./deploy/m7-window/client-generator
go build -o /tmp/prober ./deploy/m7-window/prober
sudo mkdir -p "$BIN" "$ETC"
sudo install -m0755 /tmp/client-generator "$BIN/client-generator"
sudo install -m0755 /tmp/prober "$BIN/prober"

echo "=== write /etc/canarysting/m7.env ==="
sudo tee "$ETC/m7.env" >/dev/null <<EOF
ENVOY_TARGET=http://$SERVER_PRIV:8080
LEGIT_IPS=10.20.1.101,10.20.1.102,10.20.1.103
ATTACKER_IP=10.20.1.111
EOF

echo "=== verify the secondary IPs are configured ==="
for ip in 10.20.1.101 10.20.1.102 10.20.1.103 10.20.1.111; do
  ip -o addr show | grep -q "$ip" && echo "  $ip ok" || echo "  WARN $ip not configured (canarysting-secondary-ips.service?)"
done

echo "=== install + start generator + prober ==="
sudo install -m0644 deploy/m7-window/systemd/canarysting-generator.service /etc/systemd/system/
sudo install -m0644 deploy/m7-window/systemd/canarysting-prober.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now canarysting-generator.service
sudo systemctl enable --now canarysting-prober.service

echo
systemctl is-active canarysting-generator canarysting-prober || true
echo "Client is generating benign traffic from 3 identities and probing canaries from the attacker IP."
