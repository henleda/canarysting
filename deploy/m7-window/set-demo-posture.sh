#!/usr/bin/env bash
# Run on the SERVER box. Sets the M9 demo posture by writing two knobs into
# /etc/canarysting/m7.env and restarting the affected units. The baseline/event DB is
# UNTOUCHED; in-memory calibration evidence DOES reset on the engine restart (re-accrues).
#
#   sudo ./set-demo-posture.sh demo        # FLOOR=Aggressive (all 5 axes) + realistic
#                                          #   3-5-touch escalation — the founder-approved
#                                          #   demo posture (DEMO_ARC.md).
#   sudo ./set-demo-posture.sh default     # FLOOR=Moderate + realistic — the window's
#                                          #   normal posture (revert after the demo).
#   sudo ./set-demo-posture.sh aggressive  # FLOOR=Aggressive + engine -aggressive
#                                          #   (single-touch escalation — the FAST variant;
#                                          #   discloses as a demo posture).
#
# Two independent knobs (see DEMO_SESSION_PLAN.md):
#   STING_FLOOR     (adapter -sting-floor): 1=Moderate (velocity+poison), 2=Aggressive
#                   (all five axes). THIS is what lights up the five-axis breadth.
#   AGGRESSIVE_FLAG (engine -aggressive): empty=realistic 3-5-touch escalation,
#                   "-aggressive"=single-touch (trips Tier 2 on the first touch).
# The founder chose realistic escalation, so `demo` sets the FLOOR only and leaves the
# tier thresholds realistic. ALWAYS revert with `default` after the demo so the live
# learning window is not left at FloorAggressive.
set -euo pipefail

MODE="${1:?usage: set-demo-posture.sh [demo|default|aggressive]}"
ETC=/etc/canarysting
ENVFILE="$ETC/m7.env"

# Knobs: STING_FLOOR (adapter axes), AGGRESSIVE_FLAG (single-touch tiers),
# DEMO_ESCALATION_FLAG (the 3-5-touch dwell band so the attacker is bled by the inline
# attrition before the jail), DEMO_FLOOR_FLAG (relax the baseline day-span gates so M
# goes live). The `demo` posture runs the DWELL band at M=1 (DEMO_FLOOR_FLAG OFF): the
# band needs touch-count scoring (M=1) so the flow Tags@1/Contains@~3/Jails@~5; a live
# (high) M would jail on touch 1 and skip the attrition bleed. M-live is therefore NOT
# part of the `demo` posture (the cross-customer consume signal does not need it).
case "$MODE" in
  demo)       STING_FLOOR=2; AGG="";            DFLOOR=""; ESCAL="-demo-escalation" ;;
  default)    STING_FLOOR=1; AGG="";            DFLOOR=""; ESCAL="" ;;
  aggressive) STING_FLOOR=2; AGG="-aggressive"; DFLOOR=""; ESCAL="" ;;
  *) echo "unknown mode: $MODE (want: demo|default|aggressive)" >&2; exit 2 ;;
esac

[ -f "$ENVFILE" ] || { echo "$ENVFILE not found; run run-window.sh first" >&2; exit 1; }

# setenv KEY VALUE — replace an existing KEY= line in m7.env, else append it.
setenv() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "$ENVFILE"; then
    sudo sed -i "s|^${key}=.*|${key}=${val}|" "$ENVFILE"
  else
    echo "${key}=${val}" | sudo tee -a "$ENVFILE" >/dev/null
  fi
}

setenv STING_FLOOR "$STING_FLOOR"
setenv AGGRESSIVE_FLAG "$AGG"
setenv DEMO_ESCALATION_FLAG "$ESCAL"
setenv DEMO_FLOOR_FLAG "$DFLOOR"

echo "=== posture '$MODE': STING_FLOOR=$STING_FLOOR (1=moderate,2=aggressive/all-5-axes) AGGRESSIVE_FLAG='$AGG' DEMO_FLOOR_FLAG='$DFLOOR' ==="
sudo systemctl daemon-reload
echo "=== restarting engine + adapter (baseline DB persists; calibration evidence re-accrues) ==="
sudo systemctl restart canarysting-staged-range.service
sleep 2
sudo systemctl restart canarysting-adapter.service
sleep 1
systemctl is-active canarysting-staged-range.service canarysting-adapter.service || true
echo "Done. Revert after the demo with: sudo $0 default"
echo "NOTE: an adapter restart alone can break cross-host cookie resolution (F11) — a full"
echo "      box REBOOT is the safe path before a live attack run (see DEMO_SESSION_PLAN.md)."
