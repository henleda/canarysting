#!/usr/bin/env bash
# Run on the SERVER box. Builds + deploys the CISO dashboard (the Go backend that reads
# the engine tap, and the Next.js frontend), then installs + restarts the two dashboard
# systemd units. run-window.sh builds only the engine + adapter; the dashboard is deployed
# here so the live wall picks up frontend/backend changes (e.g. the attacker-journey ribbon).
#
#   sudo deploy/m7-window/deploy-dashboard.sh
#
# Idempotent: re-running rebuilds + restarts. Reads /etc/canarysting/m7.env (SCOPE, the tap
# addr). The backend reads the engine's read-only tap; it writes nothing.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
export PATH="$PATH:/usr/local/go/bin"
BIN=/opt/canarysting/bin
APP="$REPO/dashboard/app"

echo "=== build dashboard-backend (Go) ==="
go build -o /tmp/dashboard-backend ./cmd/dashboard-backend
sudo mkdir -p "$BIN"
sudo install -m0755 /tmp/dashboard-backend "$BIN/dashboard-backend"

echo "=== build dashboard frontend (next build) ==="
if ! command -v npm >/dev/null 2>&1; then
  echo "  npm not found on PATH; install Node (the dashboard-web unit runs 'next start')." >&2
  exit 1
fi
cd "$APP"
npm ci
npm run build
cd "$REPO"

echo "=== install + (re)start the dashboard units ==="
sudo install -m0644 deploy/m7-window/systemd/canarysting-dashboard-backend.service /etc/systemd/system/
sudo install -m0644 deploy/m7-window/systemd/canarysting-dashboard-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now canarysting-dashboard-backend.service
sleep 1
sudo systemctl enable --now canarysting-dashboard-web.service
sleep 2
sudo systemctl restart canarysting-dashboard-backend.service canarysting-dashboard-web.service

echo
echo "=== status ==="
systemctl is-active canarysting-dashboard-backend canarysting-dashboard-web || true
echo
echo "Dashboard deployed. View it via an SSH tunnel from your laptop:"
echo "  ssh -i ~/.ssh/canarysting-dev -L 3001:127.0.0.1:3001 ubuntu@<server-public-ip>"
echo "  then open http://localhost:3001"
