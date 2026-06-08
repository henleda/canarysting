#!/usr/bin/env bash
# M5 demo + exit-bar gate: a real attacker through real Envoy escalates to Tier 3
# and is JAILED in-kernel by its socket cookie, while a bystander on the same host
# keeps working — the CISO precision proof, end to end.
#
# Brings up Envoy + a backend, starts the engine (-aggressive, so a single flow can
# reach Jail on a handful of canary touches at cold start) and the ext_proc adapter
# (root: sockops cookie bridge + enforce cgroup programs), then runs the scripted
# keepalive attacker (the gate). Exits non-zero on any violation. Run on the box.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
SCOPE=demo-scope
ADAPTER_LOG=/tmp/cs-adapter-m5.log
COMPOSE="docker compose -f deploy/m5-demo/docker-compose.yml"
export PATH="$PATH:/usr/local/go/bin"

cleanup() {
  echo "--- cleanup ---"
  [ -n "${ADAPTER_PID:-}" ] && sudo kill "$ADAPTER_PID" 2>/dev/null || true
  [ -n "${ENGINE_PID:-}" ] && kill "$ENGINE_PID" 2>/dev/null || true
  $COMPOSE down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== build ==="
go build -o /tmp/cs-engine ./cmd/engine
go build -o /tmp/cs-adapter ./cmd/envoy-adapter

echo "=== start engine (-aggressive, gRPC :50052) ==="
/tmp/cs-engine -scope-boundary "$SCOPE" -grpc-addr 127.0.0.1:50052 -aggressive >/tmp/cs-engine-m5.log 2>&1 &
ENGINE_PID=$!

echo "=== start adapter (root: ext_proc :50051 + sockops bridge + enforce jail) ==="
sudo /tmp/cs-adapter -listen 127.0.0.1:50051 -engine 127.0.0.1:50052 -scope "$SCOPE" -inline >"$ADAPTER_LOG" 2>&1 &
ADAPTER_PID=$!
sleep 2
grep -q "ext_proc on" "$ADAPTER_LOG" || { echo "FAIL: adapter did not start"; cat "$ADAPTER_LOG"; exit 1; }

echo "=== bring up Envoy + backend ==="
$COMPOSE up -d
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:9901/ready >/dev/null 2>&1 && break; sleep 1; done

echo
echo "=== scripted attacker (the gate) ==="
set +e
go run ./deploy/m5-demo/attacker
RC=$?
set -e

echo
echo "=== adapter escalation ledger (tier climbing to Jail) ==="
sudo grep "CANARY TOUCH" "$ADAPTER_LOG" 2>/dev/null | tail -8 || grep "CANARY TOUCH" "$ADAPTER_LOG" | tail -8 || true

# Positive evidence gate: the attacker going silent is only a KERNEL jail if the
# adapter actually programmed verdict_map for a Tier-3 verdict. Without this, a
# connection that died for any other reason would false-pass the demo.
echo
echo "=== verify positive kernel-jail evidence ==="
if sudo grep -q "KERNEL CONTAINMENT applied action=jail" "$ADAPTER_LOG" 2>/dev/null; then
  sudo grep "KERNEL CONTAINMENT applied action=jail" "$ADAPTER_LOG" | tail -2
  echo "OK: adapter programmed a kernel jail (verdict_map) for a Tier-3 verdict"
else
  echo "FAIL: no kernel jail was programmed — the attacker's silence was NOT a kernel jail"
  RC=1
fi

exit $RC
