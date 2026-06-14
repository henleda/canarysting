#!/usr/bin/env bash
# Stand up a FAST cold-start DEMO box (the compelling attacker-arc target): a realistic
# front-door + a fast M=1 engine (no observe, fresh small store -> sub-second inline
# verdict) + the -demo-escalation dwell band, so an escalating attacker is BLED by the
# inline attrition (tarpit + poisoned fake-config) for several touches before the
# kernel jail — instead of the flat 403 the bloated calibrated M7 server produced.
#
# Run ON a fresh/cold box that already has the repo rsynced + Go + Docker.
#   SCOPE=demo-range ./demo-box-setup.sh
set -uo pipefail

SCOPE="${SCOPE:-demo-range}"
REPO=/home/ubuntu/canarysting
BIN=/opt/canarysting/bin
ETC=/etc/canarysting
STATE=/var/lib/canarysting
COMPOSE="docker compose -f deploy/m5-demo/docker-compose.yml"
cd "$REPO" || { echo "repo not at $REPO"; exit 1; }
export PATH="$PATH:/usr/local/go/bin"

echo "=== clean any prior run ==="
sudo pkill -f '/opt/canarysting/bin/staged-range' 2>/dev/null || true
sudo pkill -f '/opt/canarysting/bin/envoy-adapter' 2>/dev/null || true
sudo pkill -f '/opt/canarysting/bin/mesh-frontend' 2>/dev/null || true
$COMPOSE down >/dev/null 2>&1 || true
sudo rm -f "$STATE"/demo.db* "$STATE/confirm.ndjson"
sleep 1

echo "=== build staged-range + envoy-adapter + the realistic mesh front-door ==="
go build -o /tmp/staged-range ./cmd/staged-range || { echo "BUILD FAIL staged-range"; exit 1; }
go build -o /tmp/envoy-adapter ./cmd/envoy-adapter || { echo "BUILD FAIL adapter"; exit 1; }
go build -o /tmp/mesh-frontend ./deploy/m7-window/mesh || { echo "BUILD FAIL mesh"; exit 1; }
sudo install -m0755 /tmp/staged-range "$BIN/staged-range"
sudo install -m0755 /tmp/envoy-adapter "$BIN/envoy-adapter"
sudo install -m0755 /tmp/mesh-frontend "$BIN/mesh-frontend"

echo "=== per-box ground-truth registry (attacker = localhost) ==="
sudo tee "$ETC/ground-truth-registry.json" >/dev/null <<JSON
{ "scopes": [ { "scope": "$SCOPE", "legit": [], "attacker": ["127.0.0.1"] } ] }
JSON

echo "=== realistic front-door (mesh frontend) on 127.0.0.1:8000 [replaces whoami] ==="
sudo SVC_NAME=frontend LISTEN=127.0.0.1:8000 nohup "$BIN/mesh-frontend" >/tmp/frontend.log 2>&1 &
sleep 1
curl -fsS -o /dev/null -w "  frontend / -> %{http_code}\n" --max-time 5 http://127.0.0.1:8000/ 2>/dev/null || echo "  frontend not up yet"

echo "=== FAST engine: M=1 (NO -observe-cgroup), fresh small DB, -demo-escalation band, -contain-inline ==="
"$BIN/staged-range" -scope-boundary "$SCOPE" -grpc-addr 127.0.0.1:50052 \
  -baseline-db "$STATE/demo.db" \
  -contain-inline -demo-escalation \
  -dashboard-tap-addr 0.0.0.0:8088 \
  -ground-truth-registry "$ETC/ground-truth-registry.json" -i-am-running-a-staged-range \
  >/tmp/demo-engine.log 2>&1 &
sleep 2
grep -q "gRPC Engine service listening" /tmp/demo-engine.log || { echo "ENGINE FAIL:"; tail -12 /tmp/demo-engine.log; exit 1; }

echo "=== adapter (root: ext_proc :50051 + sockops + enforce; floor 2) ==="
sudo "$BIN/envoy-adapter" -listen 127.0.0.1:50051 -engine 127.0.0.1:50052 -scope "$SCOPE" -inline -sting-floor 2 \
  >/tmp/demo-adapter.log 2>&1 &
sleep 3
grep -q "ext_proc on" /tmp/demo-adapter.log || { echo "ADAPTER FAIL:"; sudo cat /tmp/demo-adapter.log; exit 1; }

echo "=== Envoy only (the mesh frontend is the :8000 backend, NOT whoami) ==="
$COMPOSE up -d --no-deps envoy
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:9901/ready >/dev/null 2>&1 && break; sleep 1; done

echo "=== escalating attacker: one keepalive conn brushes canaries -> Tag -> Contain(poison) -> Jail ==="
go run ./deploy/m5-demo/attacker 2>&1 | head -14 || true
sleep 2

echo "============================================================"
echo "=== RESULT: front-door realism (random path -> 404, not a uniform stub) ==="
for p in / /robots.txt /totally-random-xyz; do printf "  %s -> " "$p"; curl -s -o /tmp/r -w "%{http_code} %{size_download}b" --max-time 8 "http://127.0.0.1:8080$p" 2>/dev/null; echo " | $(head -c 40 /tmp/r|tr -d "\n")"; done
echo "=== adapter ledger: tier climb + ATTRITION (poison/tarpit) firing? ==="
sudo grep -iE "CANARY TOUCH|ATTRITION|KERNEL CONTAINMENT|submit FAILED" /tmp/demo-adapter.log | tail -18 || echo "  (none)"
