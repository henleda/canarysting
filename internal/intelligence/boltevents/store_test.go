package boltevents

import (
	"bytes"
	"encoding/gob"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/cost"
)

// outcomeDiscriminatorField is the name of the gob discriminator on outcomeRecord
// (kept here so the guard test below documents exactly which field name must NOT
// appear on AdversaryInteractionEvent).
const outcomeDiscriminatorField = "OutcomeAmendmentMarker"

// TestEventTypeHasNoOutcomeDiscriminatorField neutralizes the gob-discriminator
// trap STATICALLY: the two blob types in one bucket are told apart only by the
// outcomeRecord.OutcomeAmendmentMarker field zero-filling to false on an event
// blob (no wire type-tag — the live M7 store's blobs are prefix-free). If
// AdversaryInteractionEvent ever gained a same-named field, every event blob would
// decode as an outcome and Query would drop them all (silent data-loss). This test
// fails the build the instant such a field appears.
func TestEventTypeHasNoOutcomeDiscriminatorField(t *testing.T) {
	rt := reflect.TypeOf(intelligence.AdversaryInteractionEvent{})
	if _, found := rt.FieldByName(outcomeDiscriminatorField); found {
		t.Fatalf("AdversaryInteractionEvent has a field named %q — this collides with the "+
			"outcomeRecord gob discriminator: every event blob would decode as an outcome and "+
			"Query would drop them all. Rename the discriminator (boltevents/store.go) to a name "+
			"that does not appear on the event type.", outcomeDiscriminatorField)
	}
}

func openStore(t *testing.T) (*Store, *persist.Store) {
	t.Helper()
	p, _, err := persist.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return New(p), p
}

func ev(scope string, ts time.Time) intelligence.AdversaryInteractionEvent {
	return intelligence.AdversaryInteractionEvent{
		ScopeKey: scope, FlowID: 7, CanaryType: "aws.key", Timestamp: ts,
		Features: map[string]float64{"adjacency_novelty": 1.0}, Tier: 2, Verdict: "contain",
	}
}

func TestAppendQueryRoundTrip(t *testing.T) {
	s, _ := openStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := s.Append(ev("scopeA", base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Query("scopeA", base.Add(-time.Hour), base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	if got[0].Features["adjacency_novelty"] != 1.0 {
		t.Errorf("features not round-tripped: %+v", got[0].Features)
	}
}

func TestQueryTimeWindow(t *testing.T) {
	s, _ := openStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_ = s.Append(ev("scopeA", base))
	_ = s.Append(ev("scopeA", base.Add(2*time.Hour)))
	got, _ := s.Query("scopeA", base.Add(-time.Minute), base.Add(time.Minute))
	if len(got) != 1 {
		t.Fatalf("time window filter failed: got %d, want 1", len(got))
	}
}

// Query never returns another scope's events (rule 5).
func TestQueryNeverCrossesScope(t *testing.T) {
	s, _ := openStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_ = s.Append(ev("tenant-A", now))
	_ = s.Append(ev("tenant-B", now))
	got, _ := s.Query("tenant-A", now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 || got[0].ScopeKey != "tenant-A" {
		t.Fatalf("scope isolation broken: %+v", got)
	}
}

// CaptureVerdict retains Tier>=Tag and drops Tier 0 (Observe).
func TestCaptureVerdictTierFilter(t *testing.T) {
	s, _ := openStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sev := contract.SignalEvent{Flow: contract.FlowIdentity{SocketCookie: 9}, Scope: "scopeA", Canary: "aws.key", Timestamp: now}

	// Observe tier: not captured.
	if err := s.CaptureVerdict(sev, contract.Verdict{Scope: "scopeA", Tier: contract.TierObserve}, nil); err != nil {
		t.Fatal(err)
	}
	// Tag tier: captured.
	if err := s.CaptureVerdict(sev, contract.Verdict{Scope: "scopeA", Tier: contract.TierTag}, map[string]float64{"identity_novelty": 1}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("capture tier filter wrong: got %d events, want 1 (Observe dropped)", len(got))
	}
	if got[0].Tier != int(contract.TierTag) {
		t.Errorf("captured wrong tier: %d", got[0].Tier)
	}
}

// CaptureVerdict records the engine's suspicion Score, and it round-trips.
func TestCaptureVerdictRecordsScore(t *testing.T) {
	s, _ := openStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sev := contract.SignalEvent{Flow: contract.FlowIdentity{SocketCookie: 9}, Scope: "scopeA", Canary: "aws.key", Timestamp: now}
	if err := s.CaptureVerdict(sev, contract.Verdict{Scope: "scopeA", Tier: contract.TierContain, Score: 3.75}, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Score != 3.75 {
		t.Fatalf("Score = %v, want 3.75", got[0].Score)
	}
}

// An OLD interaction-event blob written before the Score field existed must still
// decode (gob zero-fills the missing field => Score=0), so the live M7 store needs
// no migration. We simulate the old blob by gob-encoding a struct WITHOUT Score.
func TestOldEventBlobDecodesZeroScore(t *testing.T) {
	s, p := openStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	type oldEvent struct {
		ScopeKey   string
		FlowID     uint64
		CanaryType string
		Timestamp  time.Time
		Features   map[string]float64
		Tier       int
		Verdict    string
		Sting      intelligence.StingOutcome
		// NOTE: no Score field — this mirrors the pre-M8 record shape.
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(oldEvent{
		ScopeKey: "scopeA", FlowID: 7, CanaryType: "aws.key", Timestamp: now, Tier: 2, Verdict: "contain",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AppendEvent("scopeA", buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("old blob did not decode: got %d events, want 1", len(got))
	}
	if got[0].Score != 0 {
		t.Fatalf("old blob Score = %v, want 0 (missing field zero-fills)", got[0].Score)
	}
	if got[0].Tier != 2 || got[0].Verdict != "contain" {
		t.Fatalf("old blob lost fields: %+v", got[0])
	}
}

// AmendOutcome merges a reported outcome into the matching event by (cookie, ts).
func TestAmendOutcomeMergesIntoQuery(t *testing.T) {
	s, _ := openStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sev := contract.SignalEvent{Flow: contract.FlowIdentity{SocketCookie: 0xABC}, Scope: "scopeA", Canary: "aws.key", Timestamp: now}
	if err := s.CaptureVerdict(sev, contract.Verdict{Scope: "scopeA", Tier: contract.TierContain, Score: 3}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.AmendOutcome(contract.OutcomeRecord{
		SocketCookie:    0xABC,
		Scope:           "scopeA",
		TimestampUnixMs: now.UnixMilli(),
		Outcome:         contract.StingOutcome{Mechanism: "fake_tree", TimeHeldSec: 2.5, BytesServed: 4096, RequestsAbsrb: 7, TokenCostProxy: 1024, DepthReached: 3},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1 (outcome merged, not appended as an event)", len(got))
	}
	if got[0].Sting.BytesServed != 4096 || got[0].Sting.TimeHeldSec != 2.5 || got[0].Sting.Mechanism != "fake_tree" {
		t.Fatalf("outcome not merged into event: %+v", got[0].Sting)
	}
	if got[0].Score != 3 {
		t.Fatalf("merge corrupted the event: Score = %v, want 3", got[0].Score)
	}
}

// AmendOutcome with a different cookie does NOT touch the event's outcome.
func TestAmendOutcomeWrongCookieNoMerge(t *testing.T) {
	s, _ := openStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sev := contract.SignalEvent{Flow: contract.FlowIdentity{SocketCookie: 0xABC}, Scope: "scopeA", Canary: "aws.key", Timestamp: now}
	_ = s.CaptureVerdict(sev, contract.Verdict{Scope: "scopeA", Tier: contract.TierContain}, nil)
	_ = s.AmendOutcome(contract.OutcomeRecord{SocketCookie: 0xDEF, Scope: "scopeA", TimestampUnixMs: now.UnixMilli(), Outcome: contract.StingOutcome{BytesServed: 4096}})
	got, _ := s.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Sting.BytesServed != 0 {
		t.Fatalf("wrong-cookie outcome merged anyway: %+v", got[0].Sting)
	}
}

// AmendOutcome never crosses a scope: an outcome stored in scope-B leaves scope-A
// untouched, even with the same cookie+timestamp.
func TestAmendOutcomeDoesNotCrossScope(t *testing.T) {
	s, _ := openStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sevA := contract.SignalEvent{Flow: contract.FlowIdentity{SocketCookie: 0xABC}, Scope: "scopeA", Canary: "aws.key", Timestamp: now}
	_ = s.CaptureVerdict(sevA, contract.Verdict{Scope: "scopeA", Tier: contract.TierContain}, nil)
	// Outcome with the SAME cookie+ts but a DIFFERENT scope.
	_ = s.AmendOutcome(contract.OutcomeRecord{SocketCookie: 0xABC, Scope: "scopeB", TimestampUnixMs: now.UnixMilli(), Outcome: contract.StingOutcome{BytesServed: 4096}})
	got, _ := s.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 || got[0].Sting.BytesServed != 0 {
		t.Fatalf("scope-B outcome leaked into scope-A: %+v", got)
	}
}

// An amended outcome survives a reopen of the durable store.
func TestAmendOutcomeSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.db")
	p1, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1 := New(p1)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sev := contract.SignalEvent{Flow: contract.FlowIdentity{SocketCookie: 0xABC}, Scope: "scopeA", Canary: "aws.key", Timestamp: now}
	_ = s1.CaptureVerdict(sev, contract.Verdict{Scope: "scopeA", Tier: contract.TierContain}, nil)
	_ = s1.AmendOutcome(contract.OutcomeRecord{SocketCookie: 0xABC, Scope: "scopeA", TimestampUnixMs: now.UnixMilli(), Outcome: contract.StingOutcome{Mechanism: "tarpit", BytesServed: 2048, TimeHeldSec: 5}})
	_ = p1.Close()

	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2 := New(p2)
	got, _ := s2.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("got %d events after reopen, want 1", len(got))
	}
	if got[0].Sting.BytesServed != 2048 || got[0].Sting.TimeHeldSec != 5 {
		t.Fatalf("outcome did not survive reopen: %+v", got[0].Sting)
	}
}

// AmendOutcome twice for the same (cookie, ts) must NOT double-count: Query
// returns exactly one event with the LAST-WRITTEN outcome, and cost.Rollup over it
// counts the cost exactly once. This proves the (cookie, ts) merge is last-writer-
// wins (a map overwrite), not an additive fold of every outcome blob.
func TestAmendOutcomeDoubleAmendDoesNotDoubleCount(t *testing.T) {
	s, _ := openStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sev := contract.SignalEvent{Flow: contract.FlowIdentity{SocketCookie: 0xABC}, Scope: "scopeA", Canary: "aws.key", Timestamp: now}
	if err := s.CaptureVerdict(sev, contract.Verdict{Scope: "scopeA", Tier: contract.TierContain, Score: 3}, nil); err != nil {
		t.Fatal(err)
	}
	// Amend twice for the SAME (cookie, ts) with the same cost figure.
	out := contract.StingOutcome{Mechanism: "fake_tree", TimeHeldSec: 2.5, BytesServed: 4096, RequestsAbsrb: 7, TokenCostProxy: 1024, DepthReached: 3}
	for i := 0; i < 2; i++ {
		if err := s.AmendOutcome(contract.OutcomeRecord{
			SocketCookie:    0xABC,
			Scope:           "scopeA",
			TimestampUnixMs: now.UnixMilli(),
			Outcome:         out,
		}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want exactly 1 (outcomes amend, never append a new event)", len(got))
	}
	// The single event carries the cost exactly once — not doubled.
	if got[0].Sting.BytesServed != 4096 || got[0].Sting.TimeHeldSec != 2.5 {
		t.Fatalf("double-amend doubled (or lost) the cost on the event: %+v", got[0].Sting)
	}

	// cost.Rollup over the queried events must count the cost exactly once.
	roll := cost.Rollup(got)
	if roll.Interactions != 1 {
		t.Fatalf("Rollup.Interactions = %d, want 1", roll.Interactions)
	}
	if roll.BytesServed != 4096 || roll.TimeImposedSec != 2.5 || roll.TokensBurned != 1024 || roll.RequestsAbsorbed != 7 {
		t.Fatalf("Rollup double-counted the amended outcome: %+v", roll)
	}
}

// AmendOutcome with a matching cookie but a MISMATCHED timestamp must not merge:
// the join key is the composite (cookie, ts), so both halves must match. The
// event's Sting stays zero.
func TestAmendOutcomeWrongTimestampNoMerge(t *testing.T) {
	s, _ := openStore(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sev := contract.SignalEvent{Flow: contract.FlowIdentity{SocketCookie: 0xABC}, Scope: "scopeA", Canary: "aws.key", Timestamp: now}
	if err := s.CaptureVerdict(sev, contract.Verdict{Scope: "scopeA", Tier: contract.TierContain}, nil); err != nil {
		t.Fatal(err)
	}
	// Same cookie, DIFFERENT timestamp (1ms off, still inside the query window).
	if err := s.AmendOutcome(contract.OutcomeRecord{
		SocketCookie:    0xABC,
		Scope:           "scopeA",
		TimestampUnixMs: now.Add(time.Millisecond).UnixMilli(),
		Outcome:         contract.StingOutcome{BytesServed: 4096, TimeHeldSec: 5},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Sting.BytesServed != 0 || got[0].Sting.TimeHeldSec != 0 {
		t.Fatalf("mismatched-timestamp outcome merged anyway (cookie matched but ts did not): %+v", got[0].Sting)
	}
}

// Events survive a reopen of the durable store.
func TestEventsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.db")
	p1, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1 := New(p1)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_ = s1.Append(ev("scopeA", now))
	_ = p1.Close()

	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2 := New(p2)
	got, _ := s2.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 1 {
		t.Fatalf("events did not survive reopen: got %d", len(got))
	}
}
