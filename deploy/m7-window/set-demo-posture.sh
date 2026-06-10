#!/usr/bin/env bash
# Run on the SERVER box. M9 demo toggle for the engine's escalation posture (D6).
# Flips cmd/staged-range between the default realistic 3–5-touch escalation and
# -aggressive (every threshold 0.01 → a single canary touch trips Tier 2).
#
#   sudo ./set-demo-posture.sh aggressive   # single-touch escalation (fast demo)
#   sudo ./set-demo-posture.sh default      # realistic escalation (revert)
#
# It rewrites the AGGRESSIVE_FLAG line in /etc/canarysting/m7.env and restarts the
# engine. NOTE: this temporarily changes the LIVE window's posture for the demo —
# always revert to `default` afterwards. The baseline/event DB is untouched.
set -euo pipefail

MODE="${1:?usage: set-demo-posture.sh [default|aggressive]}"
ETC=/etc/canarysting
ENVFILE="$ETC/m7.env"

case "$MODE" in
  aggressive) FLAG="-aggressive" ;;
  default)    FLAG="" ;;
  *) echo "unknown mode: $MODE (want: default|aggressive)" >&2; exit 2 ;;
esac

[ -f "$ENVFILE" ] || { echo "$ENVFILE not found; run run-window.sh first" >&2; exit 1; }

# Replace any existing AGGRESSIVE_FLAG line, else append one.
if grep -q '^AGGRESSIVE_FLAG=' "$ENVFILE"; then
  sudo sed -i "s|^AGGRESSIVE_FLAG=.*|AGGRESSIVE_FLAG=$FLAG|" "$ENVFILE"
else
  echo "AGGRESSIVE_FLAG=$FLAG" | sudo tee -a "$ENVFILE" >/dev/null
fi

echo "=== posture set to '$MODE' (AGGRESSIVE_FLAG='$FLAG') ==="
echo "=== restarting engine (loads new binaries/flags; baseline DB persists) ==="
sudo systemctl restart canarysting-staged-range.service
sleep 2
systemctl is-active canarysting-staged-range.service || true
echo "Done. Revert after the demo with: sudo $0 default"
