package boltevents

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/intelligence"
)

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
