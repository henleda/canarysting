#!/usr/bin/env bash
# Run ON a k3 contributor box (after the repo is rsynced to /home/ubuntu/canarysting).
# Stands up a LIGHT cold-start canary surface (Envoy + whoami backend + the
# ext_proc adapter w/ sockops + a staged-range engine), brushes the negative-space
# canaries with the deterministic scripted attacker to reach a Tier-3 JAIL, and
# emits ONE D6-3 confirmation under this box's OPAQUE token to the confirm spool.
#
# Cold-start by design: no -observe-cgroup (M=1.0, no baseline), no -demo-data-floor.
# -aggressive so the 5-canary scripted attacker reliably crosses the jail threshold.
#
#   SCOPE=scope-1 SCOPE_TOKEN=<hex16> ./box-setup.sh
set -uo pipefail

SCOPE="${SCOPE:?set SCOPE (e.g. scope-1)}"
TOKEN="${SCOPE_TOKEN:?set SCOPE_TOKEN (opaque hex from openssl rand -hex 16)}"
REPO=/home/ubuntu/canarysting
ETC=/etc/canarysting
BIN=/opt/canarysting/bin
STATE=/var/lib/canarysting
CONFIRM="$STATE/confirm.ndjson"
COMPOSE="docker compose -f deploy/m5-demo/docker-compose.yml"

cd "$REPO" || { echo "repo not found at $REPO (rsync it first)"; exit 1; }
export PATH="$PATH:/usr/local/go/bin"

echo "=== clean any prior run ==="
sudo pkill -f '/opt/canarysting/bin/staged-range' 2>/dev/null || true
sudo pkill -f '/opt/canarysting/bin/envoy-adapter' 2>/dev/null || true
$COMPOSE down >/dev/null 2>&1 || true
# Fresh confirm spool AND a fresh baseline DB each run (cold-start: no baseline ever
# accrues without -observe-cgroup, so M stays 1.0 — the DB is here only for the durable
# EventStore + Sharpen + Ledger that the D6-3 confirmation path requires).
sudo rm -f "$CONFIRM" "$STATE"/baseline.db*
sleep 1

echo "=== build staged-range + envoy-adapter ==="
go build -o /tmp/staged-range ./cmd/staged-range || { echo "BUILD FAIL staged-range"; exit 1; }
go build -o /tmp/envoy-adapter ./cmd/envoy-adapter || { echo "BUILD FAIL envoy-adapter"; exit 1; }
sudo install -m0755 /tmp/staged-range "$BIN/staged-range"
sudo install -m0755 /tmp/envoy-adapter "$BIN/envoy-adapter"

echo "=== per-box ground-truth registry (attacker = localhost; cold-start labels are irrelevant but staged-range requires a registry) ==="
sudo tee "$ETC/ground-truth-registry.json" >/dev/null <<JSON
{ "scopes": [ { "scope": "$SCOPE", "legit": [], "attacker": ["127.0.0.1"] } ] }
JSON

echo "=== start engine (staged-range; -aggressive cold-start; Tier-3 INLINE so the jail outcome is reported; -contribute under opaque token) ==="
"$BIN/staged-range" -scope-boundary "$SCOPE" -grpc-addr 127.0.0.1:50052 \
  -baseline-db "$STATE/baseline.db" \
  -aggressive -contain-inline -jail-inline \
  -contribute -scope-token "$TOKEN" -confirm-spool "$CONFIRM" \
  -ground-truth-registry "$ETC/ground-truth-registry.json" -i-am-running-a-staged-range \
  >/tmp/k3-engine.log 2>&1 &
sleep 2
grep -q "gRPC Engine service listening" /tmp/k3-engine.log || { echo "ENGINE did not come up:"; tail -20 /tmp/k3-engine.log; exit 1; }

echo "=== start adapter (root: ext_proc :50051 + sockops bridge + enforce; floor 2 = all 5 axes) ==="
sudo "$BIN/envoy-adapter" -listen 127.0.0.1:50051 -engine 127.0.0.1:50052 -scope "$SCOPE" -inline -sting-floor 2 \
  >/tmp/k3-adapter.log 2>&1 &
sleep 3
grep -q "ext_proc on" /tmp/k3-adapter.log || { echo "ADAPTER did not come up:"; sudo cat /tmp/k3-adapter.log; exit 1; }

echo "=== bring up Envoy + whoami backend (host-net) ==="
$COMPOSE up -d
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:9901/ready >/dev/null 2>&1 && break; sleep 1; done

echo "=== scripted attacker: brush canaries on one keepalive socket -> escalate -> Tier-3 jail ==="
go run ./deploy/m5-demo/attacker || true
sleep 2

echo "============================================================"
echo "=== RESULT: confirm spool ($CONFIRM) ==="
if sudo test -s "$CONFIRM"; then
  echo "  CONFIRMATIONS: $(sudo wc -l < "$CONFIRM") line(s)"
  sudo cat "$CONFIRM"
else
  echo "  EMPTY — no confirmation emitted (engine never reached a Tier-3 jail, or ReportOutcome did not fire)"
fi
echo "=== engine log (tier / jail / contribute / confirm) ==="
grep -iE "tier|jail|contribut|confirm|record|emit|outcome" /tmp/k3-engine.log | tail -15
echo "=== adapter ledger (CANARY TOUCH / verdict / jail) ==="
sudo grep -iE "CANARY TOUCH|verdict|jail|tier|contain" /tmp/k3-adapter.log | tail -15
