#!/usr/bin/env bash
# Run on the SERVER box (the dev box). Builds the staged-range engine + the Envoy
# adapter, installs the systemd units + config, brings up the service mesh behind
# Envoy, and starts the observe-baseline + ground-truth-labeler window. The client
# box is set up separately with client-setup.sh.
#
# Idempotent: re-running rebuilds and restarts. The baseline DB at
# /var/lib/canarysting survives across restarts AND reboots.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
export PATH="$PATH:/usr/local/go/bin"
SCOPE=m7-window
BIN=/opt/canarysting/bin
ETC=/etc/canarysting
COMPOSE="docker compose -f deploy/m7-window/server-compose.yml"

echo "=== build engine + adapter ==="
go build -o /tmp/staged-range ./cmd/staged-range
go build -o /tmp/envoy-adapter ./cmd/envoy-adapter
sudo mkdir -p "$BIN" "$ETC"
sudo install -m0755 /tmp/staged-range "$BIN/staged-range"
sudo install -m0755 /tmp/envoy-adapter "$BIN/envoy-adapter"
sudo install -m0644 deploy/m7-window/ground-truth-registry.json "$ETC/ground-truth-registry.json"
sudo install -m0644 deploy/m7-window/topology-identities.json "$ETC/topology-identities.json"

echo "=== write /etc/canarysting/m7.env ==="
# The dashboard tap must bind the host's PRIVATE VPC IP (not loopback) so the CLIENT box
# + the M9 attacker (-tap-addr) and the dashboard-backend can reach it cross-host. Derive
# it from IMDSv2 (the box is IMDSv2-only), falling back to the first hostname -I address.
TAP_TOKEN="$(curl -s -m2 -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null)"
PRIVATE_IP="$(curl -s -m2 -H "X-aws-ec2-metadata-token: $TAP_TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null)"
[ -z "$PRIVATE_IP" ] && PRIVATE_IP="$(hostname -I | awk '{print $1}')"
echo "  tap will bind the private IP: ${PRIVATE_IP}:8088"
sudo tee "$ETC/m7.env" >/dev/null <<EOF
SCOPE=$SCOPE
BASELINE_DB=/var/lib/canarysting/baseline.db
GROUND_TRUTH=$ETC/ground-truth-registry.json
DASHBOARD_TAP_ADDR=${PRIVATE_IP}:8088
STING_FLOOR=1
DEMO_FLOOR_FLAG=
TOPOLOGY_FLAG=-topology-identities $ETC/topology-identities.json
# SLICE-2 one-way SIEM/SOAR emitter — OFF by default (empty => no argument, window
# posture byte-unchanged). To enable, set e.g.
#   SIEM_FLAG=-siem-format json -siem-endpoint https://your-siem.example/hec
# or "-siem-format cef" / "-siem-format stdout". The event is LOCAL-RICH (raw
# src/path/SPIFFE) and goes to the operator's OWN SIEM — never the cross-customer feed.
SIEM_FLAG=
EOF

echo "=== install + start systemd units (engine, then adapter) ==="
sudo install -m0644 deploy/m7-window/systemd/canarysting-staged-range.service /etc/systemd/system/
sudo install -m0644 deploy/m7-window/systemd/canarysting-adapter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now canarysting-staged-range.service
sleep 2
sudo systemctl enable --now canarysting-adapter.service

echo "=== bring up the service mesh + Envoy ==="
$COMPOSE up -d --build
for i in $(seq 1 60); do curl -fsS http://127.0.0.1:9901/ready >/dev/null 2>&1 && break; sleep 1; done

echo
echo "=== status ==="
systemctl is-active canarysting-staged-range canarysting-adapter || true
$COMPOSE ps
echo
echo "Window STARTED. Baseline accrues from the mesh + the client generator;"
echo "calibration accrues from the prober's labeled canary touches."
echo "NEXT: on the CLIENT box, run:  deploy/m7-window/client-setup.sh <this-box-private-ip>"
