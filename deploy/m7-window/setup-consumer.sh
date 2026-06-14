#!/usr/bin/env bash
# Run ON the M7 server. Re-plumbs the live staged-range engine as a D6-3 CONSUMER of
# the cross-customer network: rebuilds the binary (now with -consume/-shared-spool),
# points it at the cleared cross-customer pattern spool, and restarts the unit ONCE.
# The bbolt baseline PERSISTS; in-memory calibration re-accrues (~minutes).
# Reversible:  sudo ./setup-consumer.sh off   clears the consume flags + restarts.
#
#   sudo ./setup-consumer.sh on    # consume /var/lib/canarysting/shared-in.ndjson
#   sudo ./setup-consumer.sh off   # revert to the pre-consumer posture
set -uo pipefail

REPO=/home/ubuntu/canarysting
ETC=/etc/canarysting
BIN=/opt/canarysting/bin
STATE=/var/lib/canarysting
SHARED="$STATE/shared-in.ndjson"
UNIT=/etc/systemd/system/canarysting-staged-range.service
export PATH="$PATH:/usr/local/go/bin"
cd "$REPO" || { echo "repo not at $REPO"; exit 1; }

MODE="${1:-on}"
setenv() {
  local k="$1" v="$2"
  if grep -q "^${k}=" "$ETC/m7.env"; then sudo sed -i "s|^${k}=.*|${k}=${v}|" "$ETC/m7.env";
  else echo "${k}=${v}" | sudo tee -a "$ETC/m7.env" >/dev/null; fi
}

echo "=== rebuild + reinstall staged-range (now has -consume/-shared-spool/-jail-inline) ==="
go build -o /tmp/staged-range ./cmd/staged-range || exit 1
sudo install -m0755 /tmp/staged-range "$BIN/staged-range"
echo "=== install updated unit (adds \$CONSUME_FLAG \$SHARED_SPOOL_FLAG) ==="
sudo install -m0644 deploy/m7-window/systemd/canarysting-staged-range.service "$UNIT"

if [ "$MODE" = "off" ]; then
  setenv CONSUME_FLAG ""
  setenv SHARED_SPOOL_FLAG ""
  echo "=== consumer OFF (reverted) ==="
else
  if ! sudo test -s "$SHARED"; then
    echo "shared pattern spool $SHARED missing/empty — scp the cleared-out pattern there first"; exit 1
  fi
  setenv CONSUME_FLAG "-consume"
  setenv SHARED_SPOOL_FLAG "-shared-spool $SHARED"
  echo "=== consumer ON; shared pattern lines: $(sudo wc -l < "$SHARED") ==="
fi

echo "=== restart engine (baseline DB persists; calibration re-accrues) ==="
sudo systemctl daemon-reload
sudo systemctl restart canarysting-staged-range.service
sleep 4
echo "  unit: $(systemctl is-active canarysting-staged-range.service)"
echo "=== engine boot log (consume load) ==="
sudo journalctl -u canarysting-staged-range --since "-30sec" --no-pager 2>/dev/null | grep -iE "consume|shared|DEMO DATA FLOOR|STAGED RANGE" | tail -8
