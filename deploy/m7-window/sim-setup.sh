#!/usr/bin/env bash
# Stand up the one-box demo TRAFFIC SIMULATOR (T2): add the source identities as
# secondary IPs, build+install simdriver + llm-attacker, write /etc/canarysting/
# sim.env, and install+start canarysting-simdriver.service. Run ON the demo box
# (which already has the repo + Go + the engine/adapter/Envoy from the one-box
# engine setup). Idempotent.
#
#   SIM_TARGET=http://10.20.1.120:8080 ./sim-setup.sh
#
# Live Tier-C LLM runs are OFF by default (SIM_LIVE_INTERVAL=0). To enable a
# bounded live beat, set SIM_LIVE_INTERVAL (e.g. 15m) AND place the key at
# /etc/canarysting/anthropic.key — spend is still hard-capped fail-closed at
# SIM_DAILY_CAP_USD by the spendledger.
set -uo pipefail

REPO=/home/ubuntu/canarysting
BIN=/opt/canarysting/bin
ETC=/etc/canarysting
STATE=/var/lib/canarysting
IFACE="${IFACE:-$(ip route | awk '/default/{print $5; exit}')}"
export PATH="$PATH:/usr/local/go/bin"
cd "$REPO" || { echo "repo not at $REPO"; exit 1; }

# Tunables (env-overridable).
SIM_TARGET="${SIM_TARGET:-http://127.0.0.1:8080}"
SIM_TAP="${SIM_TAP:-http://127.0.0.1:8088}"
SIM_BENIGN_IPS="${SIM_BENIGN_IPS:-10.20.1.101,10.20.1.102,10.20.1.103}"
SIM_ATTACKER_IP="${SIM_ATTACKER_IP:-10.20.1.111}"
SIM_RECON_IP="${SIM_RECON_IP:-10.20.1.112}"
SIM_BASE_RPM="${SIM_BASE_RPM:-30}"
SIM_MALICIOUS_PCT="${SIM_MALICIOUS_PCT:-3}"
SIM_RECON_PCT="${SIM_RECON_PCT:-5}"
SIM_DAILY_CAP_USD="${SIM_DAILY_CAP_USD:-20}"
SIM_BUDGET_FILE="${SIM_BUDGET_FILE:-$STATE/sim-budget.json}"
SIM_CASSETTE="${SIM_CASSETTE:-/tmp/m9-demo3.cassette}"
SIM_CASSETTE_INTERVAL="${SIM_CASSETTE_INTERVAL:-4m}"
SIM_LIVE_INTERVAL="${SIM_LIVE_INTERVAL:-0}"
SIM_LIVE_BUDGET_USD="${SIM_LIVE_BUDGET_USD:-0.5}"
SIM_KEY_FILE="${SIM_KEY_FILE:-$ETC/anthropic.key}"

echo "=== add source identities as secondary IPs on $IFACE ==="
# .101-.103 (benign) / .111 (declared attacker) / .112 (UNLABELED recon scanner).
for ip in ${SIM_BENIGN_IPS//,/ } "$SIM_ATTACKER_IP" "$SIM_RECON_IP"; do
  if ! ip addr show dev "$IFACE" | grep -q "inet $ip/"; then
    sudo ip addr add "$ip/24" dev "$IFACE" 2>/dev/null \
      && echo "  + $ip" || echo "  (could not add $ip — may already be assigned to the ENI)"
  else
    echo "  = $ip (present)"
  fi
done

echo "=== build + install simdriver + llm-attacker ==="
go build -o /tmp/simdriver ./deploy/m7-window/simdriver || { echo "BUILD FAIL simdriver"; exit 1; }
go build -o /tmp/llm-attacker ./cmd/llm-attacker || { echo "BUILD FAIL llm-attacker"; exit 1; }
sudo mkdir -p "$BIN" "$STATE"
sudo install -m0755 /tmp/simdriver "$BIN/simdriver"
sudo install -m0755 /tmp/llm-attacker "$BIN/llm-attacker"

echo "=== write $ETC/sim.env ==="
sudo mkdir -p "$ETC"
sudo tee "$ETC/sim.env" >/dev/null <<EOF
SIM_TARGET=$SIM_TARGET
SIM_TAP=$SIM_TAP
SIM_BENIGN_IPS=$SIM_BENIGN_IPS
SIM_ATTACKER_IP=$SIM_ATTACKER_IP
SIM_RECON_IP=$SIM_RECON_IP
SIM_BASE_RPM=$SIM_BASE_RPM
SIM_MALICIOUS_PCT=$SIM_MALICIOUS_PCT
SIM_RECON_PCT=$SIM_RECON_PCT
SIM_DAILY_CAP_USD=$SIM_DAILY_CAP_USD
SIM_BUDGET_FILE=$SIM_BUDGET_FILE
SIM_CASSETTE=$SIM_CASSETTE
SIM_CASSETTE_INTERVAL=$SIM_CASSETTE_INTERVAL
SIM_LIVE_INTERVAL=$SIM_LIVE_INTERVAL
SIM_LIVE_BUDGET_USD=$SIM_LIVE_BUDGET_USD
SIM_KEY_FILE=$SIM_KEY_FILE
EOF

echo "=== install + start canarysting-simdriver.service ==="
sudo install -m0644 deploy/m7-window/systemd/canarysting-simdriver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now canarysting-simdriver.service
sleep 2
echo "  simdriver: $(systemctl is-active canarysting-simdriver)"
echo "  (logs: journalctl -u canarysting-simdriver -f)"
echo "  live Tier-C spend: $([ "$SIM_LIVE_INTERVAL" = "0" ] && echo "OFF" || echo "every $SIM_LIVE_INTERVAL, capped \$$SIM_LIVE_BUDGET_USD/run, \$$SIM_DAILY_CAP_USD/day fail-closed")"
