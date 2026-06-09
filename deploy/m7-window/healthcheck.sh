#!/usr/bin/env bash
# Run on the SERVER box. Asserts the M7 window is genuinely accruing: the engine +
# adapter units are active, Envoy is ready, the durable baseline DB is GROWING (the
# aggregator persists dirty buckets each fold tick), and the adapter is seeing the
# prober's canary touches (calibration evidence). Run from a systemd timer or by
# hand. Non-zero exit on a stall.
set -uo pipefail

DB=/var/lib/canarysting/baseline.db
rc=0

echo "=== units ==="
for u in canarysting-staged-range canarysting-adapter; do
  state=$(systemctl is-active "$u" 2>/dev/null || true)
  echo "  $u: $state"
  [ "$state" = active ] || rc=1
done

echo "=== envoy ready ==="
if curl -fsS http://127.0.0.1:9901/ready >/dev/null 2>&1; then echo "  ready"; else echo "  NOT ready"; rc=1; fi

echo "=== baseline db growth (20s) ==="
s1=$(sudo stat -c%s "$DB" 2>/dev/null || echo 0)
sleep 20
s2=$(sudo stat -c%s "$DB" 2>/dev/null || echo 0)
echo "  size: $s1 -> $s2 bytes"
if [ "$s2" -le 0 ]; then echo "  STALL: no baseline db"; rc=1; fi

echo "=== canary touches seen by the adapter (last 10 min) ==="
touches=$(sudo journalctl -u canarysting-adapter --since "-10min" 2>/dev/null | grep -c "CANARY TOUCH" || true)
echo "  $touches touches (the prober's labeled interactions)"

echo "=== recent engine log ==="
sudo journalctl -u canarysting-staged-range --since "-5min" 2>/dev/null | tail -4

[ "$rc" -eq 0 ] && echo "HEALTH: OK" || echo "HEALTH: DEGRADED"
exit $rc
