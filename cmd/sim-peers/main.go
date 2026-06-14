// Command sim-peers synthesizes SIMULATED peer-deployment confirmations for the
// cross-customer demo — the "art of the possible" once the network has real
// breadth. It builds a small library of VARIED behavioral archetypes (coarse,
// 7-field patterns) and writes each as a confirmation under N distinct enrolled
// "sim-peer-*" tokens to the aggregator's confirm spool, plus the enrolled-token
// allowlist file. The UNCHANGED aggregator (cmd/aggregator) then crosses any
// archetype corroborated by >= k distinct tokens, exactly as it would for real
// peers — sim-peers only produces the INPUT, never bypasses the chokepoint.
//
// HONESTY / RULE 9: it constructs ONLY network.SharedPattern (booleans + 0..3
// bands + a closed-enum poison class) — there is no raw data it could leak (the
// type cannot hold any), and each pattern is re-validated through
// network.ParseSharedPattern before it is written. The "simulated" provenance
// rides as the sim-peer-* token NAMES (visible the moment you cat the wire); the
// demo MUST disclose that these are scopes WE synthesized, not real peers, and the
// dashboard labels the consumer surface "simulated" when fed by them.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/canarysting/canarysting/internal/intelligence/network"
	"github.com/canarysting/canarysting/internal/intelligence/transport"
)

// archetypes is the library of distinct simulated adversary fingerprints. Each is
// a plausible, internally-coherent coarse pattern; they differ enough that a
// crossing is EARNED by genuine corroboration of the SAME pattern across peers,
// not manufactured by every peer reporting one identical blob (the k=3 weakness
// the design called out). All PoisonClass values are in the closed enum
// {"", credential, topology, success}; all bands are 0..3.
func archetypes() []network.SharedPattern {
	return []network.SharedPattern{
		// automated credential-scanner: fast (automation) cadence, walked the poison
		// to the credential stage, bled the longest hold, never gave up.
		{ReachedContain: true, EngagedVelocity: true, EngagedPoison: true, HeldBand: 3, DisengagedEarly: false, PoisonClass: "credential", CadenceBand: 0},
		// topology mapper: human-paced, mapped the fabricated topology, disengaged early.
		{ReachedContain: true, EngagedVelocity: true, EngagedPoison: true, HeldBand: 2, DisengagedEarly: true, PoisonClass: "topology", CadenceBand: 2},
		// success-chaser: persisted to the success stage, velocity not engaged, slow cadence.
		{ReachedContain: true, EngagedVelocity: false, EngagedPoison: true, HeldBand: 1, DisengagedEarly: false, PoisonClass: "success", CadenceBand: 1},
		// smash-and-grab: contained but bailed fast, velocity only (no poison), automation cadence.
		{ReachedContain: true, EngagedVelocity: true, EngagedPoison: false, HeldBand: 1, DisengagedEarly: true, PoisonClass: "", CadenceBand: 0},
		// patient prober: contained, mapped topology, mid hold, slowest (human) cadence band.
		{ReachedContain: true, EngagedVelocity: true, EngagedPoison: true, HeldBand: 2, DisengagedEarly: false, PoisonClass: "topology", CadenceBand: 3},
	}
}

func main() {
	var (
		confirmOut = flag.String("confirm-out", "", "REQUIRED: the aggregator's -confirm-in spool to append simulated confirmations to")
		tokensOut  = flag.String("tokens-out", "", "REQUIRED: write the enrolled sim-peer token allowlist here (the aggregator's -enrolled-tokens-file)")
		peers      = flag.Int("peers", network.FeedK, "distinct simulated peer deployments (tokens) corroborating each pattern; >=k to cross, >=FeedK for feed-eligibility")
		nArch      = flag.Int("archetypes", 0, "how many distinct archetypes to emit (0 = all)")
		prefix     = flag.String("token-prefix", "sim-peer", "token name prefix — the simulated-provenance marker (keep it obviously synthetic)")
	)
	flag.Parse()
	if *confirmOut == "" || *tokensOut == "" {
		log.Fatal("sim-peers: -confirm-out and -tokens-out are required")
	}
	if *peers < network.AggregationThreshold {
		log.Fatalf("sim-peers: -peers=%d < k=%d; no pattern would cross", *peers, network.AggregationThreshold)
	}

	arch := archetypes()
	if *nArch > 0 && *nArch < len(arch) {
		arch = arch[:*nArch]
	}

	// `peers` distinct simulated peer deployments; each corroborates every archetype,
	// so each pattern is seen by all `peers` enrolled tokens.
	tokens := make([]string, *peers)
	for j := range tokens {
		tokens[j] = fmt.Sprintf("%s-%02d", *prefix, j)
	}

	spool := transport.NewConfirmSpool(*confirmOut)
	confs := 0
	for i, sp := range arch {
		// Re-validate through the INBOUND chokepoint before emitting: refuse to write a
		// pattern the aggregator would reject (fail-closed; no malformed confirmations).
		patternBytes, err := json.Marshal(sp)
		if err != nil {
			log.Fatalf("sim-peers: marshal archetype %d: %v", i, err)
		}
		if _, err := network.ParseSharedPattern(patternBytes); err != nil {
			log.Fatalf("sim-peers: archetype %d is not a valid shared pattern: %v", i, err)
		}
		for _, tok := range tokens {
			if err := spool.SendConfirmation(tok, patternBytes); err != nil {
				log.Fatalf("sim-peers: send confirmation (%s): %v", tok, err)
			}
			confs++
		}
	}

	if err := os.WriteFile(*tokensOut, []byte(strings.Join(tokens, "\n")+"\n"), 0o644); err != nil {
		log.Fatalf("sim-peers: write tokens file: %v", err)
	}

	log.Printf("sim-peers: wrote %d confirmations (%d archetypes x %d simulated peers) + %d enrolled tokens -> %s",
		confs, len(arch), *peers, len(tokens), *tokensOut)
	log.Printf("sim-peers: each archetype is corroborated by %d distinct tokens (crosses at k=%d; feed-eligible at FeedK=%d)",
		*peers, network.AggregationThreshold, network.FeedK)
	log.Printf("sim-peers: DISCLOSE — these are %d scopes WE synthesized (%s-*), not real peer customers", len(tokens), *prefix)
}
