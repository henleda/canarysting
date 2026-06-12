package sharedset

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/network"
	"github.com/canarysting/canarysting/internal/intelligence/profile"
	"github.com/canarysting/canarysting/internal/intelligence/transport"
)

var base = time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

// fakeSource returns a scope's events (window ignored — test events are in-window) and
// counts queries so a test can assert the hot-path short-circuit.
type fakeSource struct {
	byScope map[string][]intelligence.AdversaryInteractionEvent
	queries int
}

func (f *fakeSource) Query(scope string, _, _ time.Time) ([]intelligence.AdversaryInteractionEvent, error) {
	f.queries++
	return f.byScope[scope], nil
}

// a flow that engaged velocity+poison, reached a poison reaction, and disengaged early —
// the behavior a matching shared pattern describes.
func malatkEvents(scope string, cookie uint64) []intelligence.AdversaryInteractionEvent {
	return []intelligence.AdversaryInteractionEvent{
		{ScopeKey: scope, FlowID: cookie, CanaryType: ".env", Tier: 3, Timestamp: base, Sting: intelligence.StingOutcome{
			Axes: uint32(contract.AxisVelocity | contract.AxisPoison), TimeHeldSec: 10,
			PoisonReached: 2, PoisonClass: "topology", DisengageReason: contract.DisengageAttacker, TimeToDisengageSec: 5,
		}},
		{ScopeKey: scope, FlowID: cookie, CanaryType: "x", Tier: 3, Timestamp: base.Add(500 * time.Millisecond), Sting: intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity)}},
	}
}

func matchingShared() network.SharedPattern {
	return network.SharedPattern{
		ReachedContain: true, EngagedVelocity: true, EngagedPoison: true,
		HeldBand: 2, DisengagedEarly: true, PoisonClass: "topology", CadenceBand: 0,
	}
}

// Cold (nothing consumed) => Match returns 0 WITHOUT touching the event source.
func TestMatchColdNoFetch(t *testing.T) {
	src := &fakeSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{}}
	s := NewStore(src)
	if got := s.Match("s", contract.FlowIdentity{SocketCookie: 1}, base); got != 0 {
		t.Fatalf("cold Match = %v, want 0", got)
	}
	if src.queries != 0 {
		t.Fatalf("cold Match must not fetch events, queried %d times", src.queries)
	}
}

// A consumed shared pattern sharpens a local flow that behaves like it (detection
// context). The match is bounded < 1 (the decoy sequence is dropped, so typeSim is 0 —
// a cross-customer pattern is a strictly weaker signal than a local profile).
func TestMatchConsumedPatternLiftsMatchingFlow(t *testing.T) {
	src := &fakeSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{
		"scope-b": malatkEvents("scope-b", 7),
	}}
	s := NewStore(src)
	s.Add(matchingShared())

	got := s.Match("scope-b", contract.FlowIdentity{SocketCookie: 7}, base)
	if got <= 0 || got >= 1 {
		t.Fatalf("a flow matching a shared pattern should score in (0,1), got %v", got)
	}
	// The axis + reaction + cadence corroborators sum to ~0.60 for a true repeat.
	if got < 0.5 {
		t.Fatalf("a strong cross-customer match should be ~0.6, got %v", got)
	}
}

// D6h: an inbound pattern (BehavioralHash==0) must NEVER short-circuit Similarity to 1.0,
// even against a local flow whose derived hash could collide — the consumer is bounded
// by the evidence kernel, never the self-match fast-path.
func TestMatchNeverReachesOneViaHashFastPath(t *testing.T) {
	src := &fakeSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{
		"s": malatkEvents("s", 1),
	}}
	s := NewStore(src)
	s.Add(matchingShared())
	if got := s.Match("s", contract.FlowIdentity{SocketCookie: 1}, base); got >= 1 {
		t.Fatalf("inbound Match reached %v (>=1) — the hash fast-path fired for a shared pattern", got)
	}
}

// Scope isolation: a shared pattern is global, but the EMERGING flow is derived from its
// OWN scope's events. A flow with no events in the queried scope yields no match.
func TestMatchEmergingFlowIsScopeIsolated(t *testing.T) {
	src := &fakeSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{
		"scope-a": malatkEvents("scope-a", 7),
	}}
	s := NewStore(src)
	s.Add(matchingShared())
	// Same cookie, DIFFERENT scope with no events => no emerging profile => 0.
	if got := s.Match("scope-b", contract.FlowIdentity{SocketCookie: 7}, base); got != 0 {
		t.Fatalf("a flow in an empty scope must not match, got %v", got)
	}
}

// Add never records into any jail-floor structure — it only grows the shared set (rule 8
// / D6h: an inbound pattern is detection context, never local confirmed-malice).
func TestAddGrowsSharedSetOnly(t *testing.T) {
	s := NewStore(&fakeSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{}})
	s.Add(matchingShared())
	s.Add(matchingShared())
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
}

// The full D6 loop in one process: a malicious pattern, exhibited by 3 distinct scopes,
// clears the egress gate at k=3, is sent over the file-spool transport, received +
// validated on the far side, consumed into the shared set, and then sharpens a matching
// local flow in deployment B — DETECTION CONTEXT (bounded < 1). The cross-customer
// money-shot, end to end, with rules 8/9 intact.
func TestEndToEndCrossCustomerLoop(t *testing.T) {
	// Producer A: derive the jailed flow's profile -> candidate (opted-in, no count).
	prof := profile.DeriveProfile(malatkEvents("scope-a", 1))
	cand := prof.Candidate(network.ContributionContext{Contribute: true})
	export, _ := cand.EgressFields()

	// Three distinct scopes independently confirm the SAME coarse pattern -> k=3.
	l, err := network.NewLedger()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"scope-a", "scope-b", "scope-c"} {
		if _, err := l.RecordForm(s, export); err != nil {
			t.Fatal(err)
		}
	}
	cleared, err := network.ClearWithLedger(cand, network.ClearContext{Ledger: l})
	if err != nil {
		t.Fatalf("k=3 pattern must clear: %v", err)
	}

	// Transport A -> spool -> B.
	spool := transport.NewSpool(filepath.Join(t.TempDir(), "wire.ndjson"))
	if err := spool.Send(cleared); err != nil {
		t.Fatalf("Send: %v", err)
	}
	received, err := spool.Receive()
	if err != nil || len(received) != 1 {
		t.Fatalf("Receive = (%v, %v), want 1 pattern", received, err)
	}

	// Consumer B: a DIFFERENT deployment with its own scope + a flow that behaves like
	// the cross-customer pattern. The shared set sharpens it (detection context).
	srcB := &fakeSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{
		"scope-z": malatkEvents("scope-z", 42),
	}}
	consumer := NewStore(srcB)
	for _, sp := range received {
		consumer.Add(sp)
	}
	got := consumer.Match("scope-z", contract.FlowIdentity{SocketCookie: 42}, base)
	if got <= 0 || got >= 1 {
		t.Fatalf("the cross-customer pattern should sharpen B's matching flow in (0,1), got %v", got)
	}
}
