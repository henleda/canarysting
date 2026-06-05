package engine

import (
	"errors"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/scope"
	"github.com/canarysting/canarysting/internal/engine/scoring"
	"github.com/canarysting/canarysting/internal/engine/tiers"
)

// newTestEngine builds an engine bound to a single operator scope, with a given
// evidence floor so calibration tests can flip without 50 labels.
func newTestEngine(t *testing.T, floor int) (*Service, *calibration.Store) {
	t.Helper()
	resolver, err := scope.NewStaticResolver(scope.Config{Boundary: "scope"})
	if err != nil {
		t.Fatal(err)
	}
	calib := calibration.New(calibration.Config{EvidenceFloor: floor})
	scorer := scoring.New(5*time.Minute, calib, scoring.NoExclusions{})
	eng, err := New(Config{
		Resolver:    resolver,
		Scorer:      scorer,
		Decider:     tiers.StaticDecider{},
		Tiers:       tiers.DefaultConfig(),
		Calibration: calib,
	})
	if err != nil {
		t.Fatal(err)
	}
	return eng, calib
}

func touch(scope contract.ScopeKey, cookie uint64, ct string, at time.Time) contract.SignalEvent {
	return contract.SignalEvent{
		Flow:      contract.FlowIdentity{SocketCookie: cookie},
		Canary:    contract.CanaryType(ct),
		Scope:     scope,
		Timestamp: at,
	}
}

func TestSubmit_EscalatesAcrossTiersEndToEnd(t *testing.T) {
	eng, _ := newTestEngine(t, 1000)
	t0 := time.Unix(1_000_000, 0)
	// Default thresholds: Tag>=1.30, Contain>=3.00, Jail>=5.10. Cold-start score
	// is the count of distinct touches, so escalation is depth-of-interaction.
	steps := []struct {
		ct   string
		want contract.Tier
	}{
		{"a", contract.TierObserve}, // score 1
		{"b", contract.TierTag},     // score 2
		{"c", contract.TierContain}, // score 3
		{"d", contract.TierContain}, // score 4
		{"e", contract.TierContain}, // score 5
		{"f", contract.TierJail},    // score 6
	}
	for i, s := range steps {
		v, err := eng.Submit(touch("scope", 42, s.ct, t0.Add(time.Duration(i)*time.Second)))
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if v.Tier != s.want {
			t.Errorf("after %d distinct touches: got tier %d (score %.1f), want %d", i+1, v.Tier, v.Score, s.want)
		}
	}
}

func TestSubmit_ScopeAIsolationFromScopeB(t *testing.T) {
	// One engine, two scopes via explicit ev.Scope (a multi-scope deployment).
	resolver, _ := scope.NewStaticResolver(scope.Config{
		Cluster: func(contract.FlowIdentity) (contract.ScopeKey, bool) { return "unused", true },
	})
	calib := calibration.New(calibration.Config{EvidenceFloor: 1000})
	eng, err := New(Config{
		Resolver: resolver,
		Scorer:   scoring.New(5*time.Minute, calib, nil),
		Decider:  tiers.StaticDecider{},
		Tiers:    tiers.DefaultConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1_000_000, 0)
	// Drive scope-a up to Contain (3 distinct touches), same socket cookie.
	for i, ct := range []string{"a", "b", "c"} {
		eng.Submit(touch("scope-a", 1, ct, t0.Add(time.Duration(i)*time.Second)))
	}
	// scope-b, same cookie, one touch: must be Observe — unaffected by scope-a.
	v, err := eng.Submit(touch("scope-b", 1, "a", t0))
	if err != nil {
		t.Fatal(err)
	}
	if v.Tier != contract.TierObserve || v.Score != 1.0 {
		t.Fatalf("scope-b leaked from scope-a: tier %d score %.1f", v.Tier, v.Score)
	}
}

func TestSubmit_VerdictCarriesFlowScopeAndScore(t *testing.T) {
	eng, _ := newTestEngine(t, 1000)
	v, err := eng.Submit(touch("scope", 0xABCD, "a", time.Unix(1_000_000, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if v.Flow.SocketCookie != 0xABCD {
		t.Errorf("verdict dropped the flow identity: %+v", v.Flow)
	}
	if v.Scope != "scope" {
		t.Errorf("verdict scope = %q, want scope", v.Scope)
	}
	if v.Score != 1.0 {
		t.Errorf("verdict score = %.2f, want 1.0", v.Score)
	}
}

func TestSubmit_ResolvesScopeWhenEventScopeEmpty(t *testing.T) {
	eng, _ := newTestEngine(t, 1000)
	ev := touch("", 1, "a", time.Unix(1_000_000, 0)) // empty scope -> resolver
	v, err := eng.Submit(ev)
	if err != nil {
		t.Fatal(err)
	}
	if v.Scope != "scope" {
		t.Fatalf("engine did not resolve empty scope; got %q", v.Scope)
	}
}

func TestSubmit_CalibratedFlagFlipsAtFloor(t *testing.T) {
	eng, calib := newTestEngine(t, 2)
	t0 := time.Unix(1_000_000, 0)

	v, _ := eng.Submit(touch("scope", 1, "a", t0))
	if v.Calibrated {
		t.Fatal("must report uncalibrated before the evidence floor")
	}
	// Feed labels to cross the floor of 2.
	calib.Ingest(contract.FeedbackLabel{Scope: "scope", WasMalicious: true, CanariesTouched: []contract.CanaryType{"a"}})
	calib.Ingest(contract.FeedbackLabel{Scope: "scope", WasMalicious: true, CanariesTouched: []contract.CanaryType{"a"}})

	v, _ = eng.Submit(touch("scope", 1, "b", t0.Add(time.Second)))
	if !v.Calibrated {
		t.Fatal("must report calibrated once the evidence floor is met")
	}
}

func TestNew_RefusesToStartOnUnresolvableResolver(t *testing.T) {
	// A resolver whose Validate fails must stop engine startup.
	_, err := New(Config{
		Resolver: badResolver{},
		Scorer:   scoring.New(time.Minute, calibration.New(calibration.Config{}), nil),
		Decider:  tiers.StaticDecider{},
		Tiers:    tiers.DefaultConfig(),
	})
	if !errors.Is(err, scope.ErrUnresolved) {
		t.Fatalf("engine must refuse to start on unresolvable scope; got %v", err)
	}
}

func TestNew_RefusesInvalidTierConfig(t *testing.T) {
	resolver, _ := scope.NewStaticResolver(scope.Config{Boundary: "scope"})
	bad := tiers.DefaultConfig()
	bad.FailClosed[contract.TierJail] = false // Tier 3 must fail-closed
	_, err := New(Config{
		Resolver: resolver,
		Scorer:   scoring.New(time.Minute, calibration.New(calibration.Config{}), nil),
		Decider:  tiers.StaticDecider{},
		Tiers:    bad,
	})
	if err == nil {
		t.Fatal("engine must reject an invalid tier config at startup")
	}
}

// badResolver always fails Validate and Resolve.
type badResolver struct{}

func (badResolver) Resolve(contract.FlowIdentity) (contract.ScopeKey, error) {
	return "", scope.ErrUnresolved
}
func (badResolver) Validate() error { return scope.ErrUnresolved }
