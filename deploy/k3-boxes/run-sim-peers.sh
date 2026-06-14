#!/usr/bin/env bash
# Populate the cross-customer network with SIMULATED peer data for the demo's
# "art of the possible". Generates varied behavioral archetypes corroborated by N
# synthetic "sim-peer-*" deployments, runs the UNCHANGED aggregator to cross them
# (k>=3), and ships the crossings to the consuming engine's shared spool.
#
# HONESTY (mandatory): these are scopes WE synthesize, not real customers. The
# consuming engine MUST run with -sim-peers-demo so the dashboard discloses
# "simulated peer data" on the cross-customer panel — never present these as real
# peers. Rule 9 holds by construction: only the coarse 7-field patterns cross
# (cat the wire below); the sim-peer-* token names never leave the input spool.
set -uo pipefail
REPO=/home/ubuntu/canarysting
STATE=/var/lib/canarysting
PEERS="${PEERS:-5}"                                       # >=3 to cross, >=5 (FeedK) for feed-eligibility
SHARED_SPOOL="${SHARED_SPOOL:-$STATE/shared-in.ndjson}"   # the engine's -shared-spool (consume side)
WORK="${WORK:-/tmp/sim-peers}"
export PATH="$PATH:/usr/local/go/bin"
cd "$REPO" || { echo "repo not at $REPO"; exit 1; }
mkdir -p "$WORK"

echo "=== generate simulated peer confirmations ($PEERS peers corroborate each archetype) ==="
go run ./cmd/sim-peers -confirm-out "$WORK/confirm.ndjson" -tokens-out "$WORK/tokens.txt" -peers "$PEERS" || exit 1

echo "=== cross them through the UNCHANGED aggregator (k>=3) ==="
go run ./cmd/aggregator -confirm-in "$WORK/confirm.ndjson" -cleared-out "$WORK/cleared.ndjson" \
  -enrolled-tokens-file "$WORK/tokens.txt" -once || exit 1

echo "=== ship the crossings to the consuming engine's shared spool ==="
sudo install -m0644 "$WORK/cleared.ndjson" "$SHARED_SPOOL"
echo "  -> $SHARED_SPOOL ($(wc -l < "$WORK/cleared.ndjson") crossed patterns)"
echo "  the wire (one crossed pattern — opaque + 7 coarse fields; NO token, NO raw data):"
echo "    $(head -1 "$WORK/cleared.ndjson")"
echo
echo "NEXT: run the engine with  -consume -shared-spool $SHARED_SPOOL -sim-peers-demo"
echo "      (the -sim-peers-demo flag makes the dashboard disclose the peers are SIMULATED)."
echo "DISCLOSE in the demo: these are $PEERS scopes WE synthesized (sim-peer-*), not real peer customers."
