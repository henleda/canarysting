package main

import (
	"encoding/json"
	"testing"

	"github.com/canarysting/canarysting/internal/intelligence/network"
)

// Every archetype must (a) survive the inbound chokepoint that the aggregator
// applies (network.ParseSharedPattern), (b) round-trip byte-for-byte through it,
// and (c) be DISTINCT from the others — a crossing must be earned by genuine
// corroboration of the same pattern across peers, not manufactured by all peers
// reporting one identical blob (the k=3 weakness the design flagged).
func TestArchetypesValidDistinctRoundTrip(t *testing.T) {
	arch := archetypes()
	if len(arch) < network.AggregationThreshold {
		t.Fatalf("need at least k=%d archetypes to be useful, got %d", network.AggregationThreshold, len(arch))
	}
	seen := map[network.SharedPattern]bool{}
	for i, sp := range arch {
		b, err := json.Marshal(sp)
		if err != nil {
			t.Fatalf("archetype %d marshal: %v", i, err)
		}
		got, err := network.ParseSharedPattern(b)
		if err != nil {
			t.Fatalf("archetype %d is not a valid shared pattern: %v", i, err)
		}
		if got != sp {
			t.Fatalf("archetype %d did not round-trip: %+v != %+v", i, got, sp)
		}
		if seen[sp] {
			t.Fatalf("archetype %d is a duplicate — crossings must be earned by corroboration, not identical blobs", i)
		}
		seen[sp] = true
	}
}
