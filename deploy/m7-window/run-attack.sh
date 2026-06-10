#!/usr/bin/env bash
# Run on the CLIENT box. One command to drive the M9 adversary against the live
# M7 window: health-check the server, stop the always-on prober for a clean
# single-cookie trace, run the chosen attacker, then print the real-cost ledger.
#
#   ./run-attack.sh --scripted                 # zero-API reference trace ($0)
#   ./run-attack.sh                            # live LLM attacker ($5 cap)
#   ./run-attack.sh --budget 0.50 --max-turns 5  # smallest live smoke
#   ./run-attack.sh --aggressive               # ask the SERVER to flip to
#                                              #   single-touch escalation posture
#
# D6 (both postures demoable): the realistic 3–5-touch escalation is the engine's
# default; --aggressive trips Tier 2 on the first touch. Tier thresholds live on
# the SERVER engine (cmd/staged-range -aggressive), so --aggressive flips it over
# SSH when SERVER_SSH is set, else it prints the exact server command to run. The
# attacker binary itself is identical in both postures.
#
# D6a: the LLM attacker and the prober both bind 10.20.1.111; we stop the prober
# for the run and restart it on exit so the demo shows one clean escalating flow.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
export PATH="$PATH:/usr/local/go/bin"
ETC=/etc/canarysting
BIN=/opt/canarysting/bin

# --- defaults (overridable by flags) ---
SCRIPTED=0
AGGRESSIVE=0
BUDGET=5.0
MAX_TURNS=30
MODEL=claude-opus-4-8
EFFORT=high
COST_OUT=/tmp/m9-cost.json

# --- parse flags ---
while [ $# -gt 0 ]; do
  case "$1" in
    --scripted)    SCRIPTED=1 ;;
    --aggressive)  AGGRESSIVE=1 ;;
    --budget)      BUDGET="$2"; shift ;;
    --max-turns)   MAX_TURNS="$2"; shift ;;
    --model)       MODEL="$2"; shift ;;
    --effort)      EFFORT="$2"; shift ;;
    --cost-out)    COST_OUT="$2"; shift ;;
    -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

# --- load the window env (ENVOY_TARGET, ATTACKER_IP) ---
if [ -f "$ETC/m7.env" ]; then
  # shellcheck disable=SC1090
  . "$ETC/m7.env"
fi
TARGET="${ENVOY_TARGET:?ENVOY_TARGET not set; run client-setup.sh first}"
SRC_IP="${ATTACKER_IP:-10.20.1.111}"

# Derive the server host from the target, and the tap address (same host, :8088)
# for the live cost meter. The live meter requires the engine's tap to be
# reachable from this box (bind -dashboard-tap-addr to the server's private IP,
# SG-restricted). If the tap is server-loopback-only, the meter POST simply no-ops
# and the run still completes; the run-end ledger below is the source of truth.
SERVER_HOST="$(printf '%s' "$TARGET" | sed -E 's#^https?://##; s#[:/].*$##')"
TAP_ADDR="${TAP_ADDR:-http://$SERVER_HOST:8088}"

echo "=== M9 attack: target=$TARGET src-ip=$SRC_IP tap=$TAP_ADDR ==="

# --- 1. health-check the server (don't burn tokens against a dead target) ---
if curl -fsS "$TAP_ADDR/healthz" >/dev/null 2>&1; then
  echo "  server tap: healthy"
else
  echo "  server tap: NOT reachable at $TAP_ADDR/healthz"
  if [ "$SCRIPTED" -eq 0 ]; then
    echo "  refusing to start a paid LLM run against an unverified target." >&2
    echo "  (use --scripted for a \$0 run, or check the server units / tap binding.)" >&2
    exit 1
  fi
  echo "  continuing scripted (\$0) run anyway."
fi

# --- D6: posture (server-side) ---
if [ "$AGGRESSIVE" -eq 1 ]; then
  if [ -n "${SERVER_SSH:-}" ]; then
    echo "=== flipping SERVER engine to AGGRESSIVE posture via $SERVER_SSH ==="
    ssh "$SERVER_SSH" "sudo $REPO/deploy/m7-window/set-demo-posture.sh aggressive" || {
      echo "  WARN: could not flip posture over SSH; ensure the server engine runs with -aggressive." >&2
    }
  else
    echo "=== --aggressive requested: set posture ON THE SERVER box, then re-run here ==="
    echo "    server\$ sudo deploy/m7-window/set-demo-posture.sh aggressive"
    echo "    (revert after the demo: sudo deploy/m7-window/set-demo-posture.sh default)"
    echo "    or export SERVER_SSH=user@server to let this script flip it for you."
  fi
fi

# --- 2. (D6a) stop the prober for a clean single-cookie trace, restart on exit ---
PROBER_WAS_ACTIVE=0
if systemctl is-active --quiet canarysting-prober 2>/dev/null; then
  PROBER_WAS_ACTIVE=1
  echo "=== stopping canarysting-prober for a clean single-flow trace ==="
  sudo systemctl stop canarysting-prober || true
fi
restore_prober() {
  if [ "$PROBER_WAS_ACTIVE" -eq 1 ]; then
    echo "=== restarting canarysting-prober ==="
    sudo systemctl start canarysting-prober || true
  fi
}
trap restore_prober EXIT

# --- 3. build if stale ---
echo "=== build llm-attacker ==="
go build -o /tmp/llm-attacker ./cmd/llm-attacker
sudo mkdir -p "$BIN"
sudo install -m0755 /tmp/llm-attacker "$BIN/llm-attacker"

# --- 4. assemble args ---
ARGS=(-target "$TARGET" -src-ip "$SRC_IP" -tap-addr "$TAP_ADDR" -cost-out "$COST_OUT")
if [ "$SCRIPTED" -eq 1 ]; then
  ARGS+=(-scripted)
else
  ARGS+=(-model "$MODEL" -effort "$EFFORT" -hard-cap-usd "$BUDGET" -max-turns "$MAX_TURNS")
  # key resolution: prefer the EnvironmentFile, else the env var (D4).
  if [ -f "$ETC/anthropic.key" ]; then
    ARGS+=(-key-file "$ETC/anthropic.key")
  elif [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "  no API key: create $ETC/anthropic.key (0600) or export ANTHROPIC_API_KEY" >&2
    echo "  (or run with --scripted for a \$0 reference trace)" >&2
    exit 1
  fi
fi

# --- 5. run (live output) ---
echo "=== run ==="
"$BIN/llm-attacker" "${ARGS[@]}"
RC=$?

# --- 6. real-cost surfacing (D5): the run-end ledger + the side-by-side proxy ---
echo
echo "=== M9 cost ledger ($COST_OUT) ==="
[ -f "$COST_OUT" ] && cat "$COST_OUT"
echo
echo "Dashboard: the live meter (real \$ burn) is on the CISO screen's Attacker-cost panel,"
echo "shown beside the defender-side proxy estimate (never merged)."

exit $RC
