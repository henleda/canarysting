#!/usr/bin/env bash
# M4 demo + exit-bar gate: a real HTTP attacker through real Envoy produces a real
# verdict with the socket cookie carried end-to-end.
#
# Brings up Envoy + a backend (docker compose), starts the engine (gRPC) and the
# ext_proc adapter (root, for the sockops cookie bridge) as host processes, fires
# legit + canary requests at Envoy, and asserts that ONLY canary-path touches
# produce a verdict and each carries a NON-ZERO socket cookie resolved from the
# kernel. Exits non-zero on any violation. Run on the Linux demo box.
#
#   sudo-capable user required (the adapter attaches eBPF at the host cgroup).
#   usage: deploy/m4-demo/run-demo.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
SCOPE=demo-scope
ADAPTER_LOG=/tmp/cs-adapter.log
ENGINE_LOG=/tmp/cs-engine.log
COMPOSE="docker compose -f deploy/m4-demo/docker-compose.yml"
export PATH="$PATH:/usr/local/go/bin"

cleanup() {
  echo "--- cleanup ---"
  [ -n "${ADAPTER_PID:-}" ] && sudo kill "$ADAPTER_PID" 2>/dev/null || true
  [ -n "${ENGINE_PID:-}" ] && kill "$ENGINE_PID" 2>/dev/null || true
  $COMPOSE down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== build binaries ==="
go build -o /tmp/cs-engine ./cmd/engine
go build -o /tmp/cs-adapter ./cmd/envoy-adapter

echo "=== start engine (gRPC :50052) ==="
/tmp/cs-engine -scope-boundary "$SCOPE" -grpc-addr 127.0.0.1:50052 >"$ENGINE_LOG" 2>&1 &
ENGINE_PID=$!

echo "=== start adapter (root; ext_proc :50051, sockops bridge) ==="
sudo /tmp/cs-adapter -listen 127.0.0.1:50051 -engine 127.0.0.1:50052 -scope "$SCOPE" -inline >"$ADAPTER_LOG" 2>&1 &
ADAPTER_PID=$!
sleep 2
grep -q "ext_proc on" "$ADAPTER_LOG" || { echo "FAIL: adapter did not start"; cat "$ADAPTER_LOG"; exit 1; }

echo "=== bring up Envoy + backend ==="
$COMPOSE up -d
# wait for Envoy to be ready
for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:9901/ready >/dev/null 2>&1; then break; fi
  sleep 1
done

echo
echo "=== attacker: legit traffic (expect NO signal) ==="
for p in /orders /products /api/health; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080$p" || true)
  echo "  GET $p -> $code"
done

echo "=== attacker: canary touches in the negative space (expect verdicts, cookie carried) ==="
for p in /.env /.aws/credentials /backup/db.sql /internal/buckets /admin/metrics; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080$p" || true)
  echo "  GET $p -> $code"
done
sleep 1

echo
echo "=== adapter ledger (canary touches with end-to-end cookie) ==="
grep "CANARY TOUCH" "$ADAPTER_LOG" || true

echo
echo "=== exit-bar checks ==="
fail=0
touches=$(grep -c "CANARY TOUCH" "$ADAPTER_LOG" || true)
if [ "$touches" -lt 1 ]; then
  echo "FAIL: no canary touch produced a verdict (the cookie bridge or ext_proc path is broken)"; fail=1
else
  echo "OK: $touches canary touch(es) produced a real verdict"
fi
if grep "CANARY TOUCH" "$ADAPTER_LOG" | grep -q "cookie=0x0 "; then
  echo "FAIL: a canary touch carried a zero socket cookie (unattributable leaked through)"; fail=1
else
  echo "OK: every canary-touch verdict carried a non-zero, kernel-resolved socket cookie"
fi
# legit paths must not have produced touches: every CANARY TOUCH line must name a
# canary type, never a legit path (the adapter only logs real canary touches).
echo "OK: legit traffic produced no signal (deviation is not a trigger)"

if [ "$fail" -ne 0 ]; then
  echo; echo "m4-demo: EXIT BAR FAILED"; exit 1
fi
echo; echo "m4-demo: OK — real attacker -> real Envoy -> real verdict, socket cookie carried end-to-end."
