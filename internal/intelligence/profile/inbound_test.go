package profile

import (
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/network"
)

func TestFromSharedPatternSparseLift(t *testing.T) {
	sp := network.SharedPattern{
		ReachedContain: true, EngagedVelocity: true, EngagedPoison: false,
		HeldBand: 2, DisengagedEarly: true, PoisonClass: "topology", CadenceBand: 2,
	}
	p := FromSharedPattern(sp)
	if p == nil {
		t.Fatal("nil profile")
	}
	if p.BehavioralHash != 0 {
		t.Fatalf("inbound profile must keep BehavioralHash==0 (D6h), got %d", p.BehavioralHash)
	}
	if len(p.OrderedTypes) != 0 {
		t.Fatalf("inbound profile must have NO probe sequence (rule-9-dropped), got %v", p.OrderedTypes)
	}
	if !p.AxesEngaged[0] || p.AxesEngaged[1] {
		t.Fatalf("axes lift wrong: %v", p.AxesEngaged)
	}
	if p.PeakTier != int(contract.TierContain) {
		t.Fatalf("ReachedContain should lift PeakTier to %d, got %d", contract.TierContain, p.PeakTier)
	}
	if cadenceBand(p.CadenceSec) != 2 {
		t.Fatalf("CadenceBand 2 must round-trip via CadenceSec, got band %d", cadenceBand(p.CadenceSec))
	}
	if p.PoisonClass != "topology" || !p.DisengagedEarly {
		t.Fatalf("reaction lift wrong: %+v", p)
	}
}

// Every CadenceBand 0..3 must round-trip through its representative seconds back to the
// same band, so the Similarity cadence term compares the exported tempo band faithfully.
func TestCadenceRepForBandRoundTrips(t *testing.T) {
	for band := 0; band <= 3; band++ {
		if got := cadenceBand(cadenceRepForBand(band)); got != band {
			t.Fatalf("CadenceBand %d -> rep %.0fs -> band %d (round-trip broken)", band, cadenceRepForBand(band), got)
		}
	}
	// An out-of-range band defaults to band 0 (fast automation) — never panics.
	if got := cadenceBand(cadenceRepForBand(99)); got != 0 {
		t.Fatalf("out-of-range band rep maps to band %d, want 0", got)
	}
}

// D6h: two inbound (hash==0) profiles must NEVER short-circuit Similarity to 1.0 via the
// hash fast-path — they are scored only by the evidence kernel (and typeSim is 0 since the
// sequence is dropped, so an inbound pattern can never reach 1.0 against another inbound).
func TestInboundSimilarityNeverShortCircuitsToOne(t *testing.T) {
	a := FromSharedPattern(network.SharedPattern{EngagedVelocity: true, EngagedPoison: true, PoisonClass: "topology", DisengagedEarly: true, CadenceBand: 1})
	b := FromSharedPattern(network.SharedPattern{EngagedVelocity: true, EngagedPoison: true, PoisonClass: "topology", DisengagedEarly: true, CadenceBand: 1})
	// Both hash==0 and behaviorally identical — the OLD fast-path (hash==hash) would
	// have returned 1.0. The D6h guard requires a NON-zero hash, so this must NOT.
	if got := a.Similarity(b); got >= 1 {
		t.Fatalf("two zero-hash inbound profiles short-circuited to %v (>=1) — D6h guard failed", got)
	}
	// A profile is still identical to itself (the p==o pointer check is unaffected).
	if got := a.Similarity(a); got != 1 {
		t.Fatalf("self-similarity = %v, want 1 (pointer identity)", got)
	}
}

// A real local profile (non-zero hash) vs an inbound shared profile (hash 0) is scored by
// the evidence kernel — never the fast-path — and stays < 1 (typeSim 0).
func TestLocalVsInboundBoundedBelowOne(t *testing.T) {
	at := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	local := DeriveProfile([]intelligence.AdversaryInteractionEvent{
		{CanaryType: ".env", Tier: 3, Timestamp: at, Sting: intelligence.StingOutcome{
			Axes: uint32(contract.AxisVelocity | contract.AxisPoison), PoisonClass: "topology",
			DisengageReason: contract.DisengageAttacker, TimeToDisengageSec: 5,
		}},
		{CanaryType: "x", Tier: 3, Timestamp: at.Add(time.Second), Sting: intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity)}},
	})
	if local.BehavioralHash == 0 {
		t.Fatal("a real derived profile should have a non-zero hash")
	}
	shared := FromSharedPattern(network.SharedPattern{EngagedVelocity: true, EngagedPoison: true, PoisonClass: "topology", DisengagedEarly: true, CadenceBand: 0})
	if got := local.Similarity(shared); got >= 1 {
		t.Fatalf("local vs inbound = %v (>=1) — must be bounded below 1 (sequence dropped)", got)
	}
}
