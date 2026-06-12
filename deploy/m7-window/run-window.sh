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

echo "=== write /etc/canarysting/m7.env ==="
sudo tee "$ETC/m7.env" >/dev/null <<EOF
SCOPE=$SCOPE
BASELINE_DB=/var/lib/canarysting/baseline.db
GROUND_TRUTH=$ETC/ground-truth-registry.json
DASHBOARD_TAP_ADDR=127.0.0.1:8088
STING_FLOOR=1
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
