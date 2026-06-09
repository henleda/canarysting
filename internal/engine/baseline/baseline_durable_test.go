package baseline

import (
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

// fakeFeatureSource returns fixed features and a fixed ok, recording whether it
// was consulted.
type fakeFeatureSource struct {
	f      Features
	ok     bool
	called bool
}

func (s *fakeFeatureSource) Features(contract.ScopeKey, contract.FlowIdentity, time.Time) (Features, bool) {
	s.called = true
	return s.f, s.ok
}

// With no FeatureSource wired, Multiplier behaves exactly as before M7: neutral.
func TestMultiplierNoSourceIsNeutral(t *testing.T) {
	s := New(Config{Calibrated: func(contract.ScopeKey) bool { return true }})
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	s.SetLive("scopeA", true)
	s.SetBucketSufficient("scopeA", DefaultBucketer(at), true)
	// Ready scope, but no source → neutral Features → d=0 → M=1.
	if m := s.Multiplier("scopeA", contract.FlowIdentity{SocketCookie: 1}, at); m != 1.0 {
		t.Fatalf("no-source M = %v, want 1.0", m)
	}
}

// A source that cannot derive (ok=false) yields neutral features; gating still
// applies and M stays 1.0.
func TestMultiplierSourceNotOkIsNeutral(t *testing.T) {
	s := New(Config{Calibrated: func(contract.ScopeKey) bool { return true }})
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	s.SetLive("scopeA", true)
	s.SetBucketSufficient("scopeA", DefaultBucketer(at), true)
	fs := &fakeFeatureSource{f: Features{AdjacencyNovelty: 1, IdentityNovelty: 1}, ok: false}
	s.UseFeatureSource(fs)
	if m := s.Multiplier("scopeA", contract.FlowIdentity{SocketCookie: 1}, at); m != 1.0 {
		t.Fatalf("not-ok source M = %v, want 1.0", m)
	}
	if !fs.called {
		t.Fatal("feature source was not consulted")
	}
}

// A source that derives real features on a READY scope amplifies M above 1 —
// proving the wiring runs derived features through the frozen math.
func TestMultiplierSourceAmplifiesWhenReady(t *testing.T) {
	s := New(Config{Calibrated: func(contract.ScopeKey) bool { return true }})
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	s.SetLive("scopeA", true)
	s.SetBucketSufficient("scopeA", DefaultBucketer(at), true)
	// The spec's "abnormal flow" worked example: new adjacency + new identity +
	// moderate volume deviation → M ≈ 2.5 (docs/BASELINE_MULTIPLIER.md §5).
	fs := &fakeFeatureSource{f: Features{AdjacencyNovelty: 1, IdentityNovelty: 1, VolumeDeviation: 0.6}, ok: true}
	s.UseFeatureSource(fs)
	m := s.Multiplier("scopeA", contract.FlowIdentity{SocketCookie: 1}, at)
	if m <= 2.0 || m >= 3.0 {
		t.Fatalf("amplified M = %v, want in (2.0, 3.0)", m)
	}
	// Sanity: identical features through the pure math give the same M.
	if want := MFromFeatures(fs.f, DefaultParams()); m != want {
		t.Fatalf("M = %v, want MFromFeatures = %v (wiring must not alter the math)", m, want)
	}
}

// Even with maximal derived features, an UNREADY scope (not live) forces M=1 —
// the gates are independent of feature derivation.
func TestMultiplierGatedWhenNotLive(t *testing.T) {
	s := New(Config{Calibrated: func(contract.ScopeKey) bool { return true }})
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	// calibrated + bucket-sufficient but NOT live.
	s.SetBucketSufficient("scopeA", DefaultBucketer(at), true)
	fs := &fakeFeatureSource{f: Features{AdjacencyNovelty: 1, IdentityNovelty: 1, PortNovelty: 1, VolumeDeviation: 1, CadenceDeviation: 1}, ok: true}
	s.UseFeatureSource(fs)
	if m := s.Multiplier("scopeA", contract.FlowIdentity{SocketCookie: 1}, at); m != 1.0 {
		t.Fatalf("not-live M = %v, want 1.0 (gate independent of features)", m)
	}
}

func TestBucketerCardinality(t *testing.T) {
	// A full week of hours.
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) // a Monday
	def := map[string]bool{}
	win := map[string]bool{}
	for h := 0; h < 24*7; h++ {
		ts := start.Add(time.Duration(h) * time.Hour)
		def[DefaultBucketer(ts)] = true
		win[WindowBucketer(ts)] = true
	}
	if len(def) != 168 {
		t.Fatalf("DefaultBucketer cardinality = %d, want 168", len(def))
	}
	if len(win) != 8 {
		t.Fatalf("WindowBucketer cardinality = %d, want 8", len(win))
	}
}
