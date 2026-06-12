#!/usr/bin/env bash
# Operator-relay driver for the D6-3 live cross-customer crossing. Pulls each
# contributor box's confirmation spool to a local inbox (distinct filename per
# scope, to preserve distinctness), then runs cmd/aggregator -once over a chosen
# set of scopes with the enrolled-token allowlist. Demonstrates:
#   k=2 (two scopes)   -> nothing crosses (cleared-out stays empty)
#   k=3 (three scopes) -> exactly one crossing (cleared-out gains one line)
#
# Run from the repo root on the operator box (the laptop that can SSH all three).
#
#   ./deploy/k3-boxes/run-crossing.sh pull          # rsync each box's confirm spool in
#   ./deploy/k3-boxes/run-crossing.sh k2            # aggregate scope-1 + scope-2 (reject)
#   ./deploy/k3-boxes/run-crossing.sh k3            # aggregate all three (cross)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin"
KEY=~/.ssh/canarysting-dev
INBOX=/tmp/k3-inbox
CLEARED="$INBOX/cleared-out.ndjson"
CONFIRM_IN="$INBOX/confirm-in.ndjson"
# scope => box public IP (override via env if the IPs change)
S1="${S1:-13.218.176.91}"
S2="${S2:-52.206.224.254}"
S3="${S3:-44.201.161.196}"
# enrolled tokens from /tmp/k3-tokens.env (SCOPE1_TOKEN / SCOPE2_TOKEN / SCOPE3_TOKEN)
# shellcheck disable=SC1091
. /tmp/k3-tokens.env
TOKENS="$SCOPE1_TOKEN,$SCOPE2_TOKEN,$SCOPE3_TOKEN"

mkdir -p "$INBOX"

pull() {
  echo "=== pull each box's confirm spool -> $INBOX/scope-N.ndjson (distinct names) ==="
  rsync -az -e "ssh -i $KEY" ubuntu@"$S1":/var/lib/canarysting/confirm.ndjson "$INBOX/scope-1.ndjson"
  rsync -az -e "ssh -i $KEY" ubuntu@"$S2":/var/lib/canarysting/confirm.ndjson "$INBOX/scope-2.ndjson"
  rsync -az -e "ssh -i $KEY" ubuntu@"$S3":/var/lib/canarysting/confirm.ndjson "$INBOX/scope-3.ndjson"
  for f in "$INBOX"/scope-*.ndjson; do echo "  $f: $(wc -l < "$f") line(s)"; done
}

aggregate() {
  local label="$1"; shift
  go build -o /tmp/aggregator ./cmd/aggregator || exit 1
  : > "$CLEARED"                       # reset the cleared spool for a clean per-beat count
  cat "$@" > "$CONFIRM_IN"
  echo "=== $label: aggregate $(echo "$@" | wc -w) scope spool(s) ==="
  /tmp/aggregator -confirm-in "$CONFIRM_IN" -cleared-out "$CLEARED" -enrolled-tokens "$TOKENS" -once
  echo "=== RESULT: cleared-out = $(wc -l < "$CLEARED") line(s) ==="
  cat "$CLEARED" 2>/dev/null || true
}

case "${1:-}" in
  pull) pull ;;
  k2)   aggregate "REJECT k=2" "$INBOX/scope-1.ndjson" "$INBOX/scope-2.ndjson" ;;
  k3)   aggregate "CROSS  k=3" "$INBOX/scope-1.ndjson" "$INBOX/scope-2.ndjson" "$INBOX/scope-3.ndjson" ;;
  *) echo "usage: $0 {pull|k2|k3}" >&2; exit 2 ;;
esac
