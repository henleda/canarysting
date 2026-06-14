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

// fixedMultiplier injects a constant baseline multiplier for the end-to-end
// "abnormal flow escalates faster" test.
type fixedMultiplier float64

func (m fixedMultiplier) Multiplier(contract.ScopeKey, contract.FlowIdentity, time.Time) float64 {
	return float64(m)
}

func TestSubmit_AbnormalFlowEscalatesOnFewerTouches(t *testing.T) {
	resolver, _ := scope.NewStaticResolver(scope.Config{Boundary: "scope"})
	calib := calibration.New(calibration.Config{EvidenceFloor: 1000})
	// A strongly-abnormal flow (M ≈ 2.6) sharpens a real touch: one touch now
	// scores 2.6, crossing the default Tag threshold (1.30) that a normal single
	// touch (score 1.0) does not reach.
	scorer := scoring.New(5*time.Minute, calib, nil).UseMultiplier(fixedMultiplier(2.6))
	eng, err := New(Config{
		Resolver: resolver,
		Scorer:   scorer,
		Decider:  tiers.StaticDecider{},
		Tiers:    tiers.DefaultConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := eng.Submit(touch("scope", 1, "a", time.Unix(1_000_000, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if v.Score != 2.6 {
		t.Fatalf("abnormal single touch score = %.2f, want 2.6 (base 1.0 × M 2.6)", v.Score)
	}
	if v.Tier != contract.TierTag {
		t.Fatalf("abnormal single touch tier = %d, want %d (Tag) — baseline must sharpen escalation", v.Tier, contract.TierTag)
	}
}

// TestSubmit_DemoTierDepthMultiplierDwellsAtLiveM proves the demo-escalation band's
// graduated Tag→Contain→Jail dwell holds even when the baseline multiplier is live:
// with TierDepthMultiplier wired, the tier is decided on depth-of-interaction
// (touch count = score/M), so a live M ≈3 no longer forces straight-to-jail. The
// Verdict.Score still carries the full B×M (the live M stays visible). The control
// (no TierDepthMultiplier) confirms that without the fix the same 2 touches jail.
func TestSubmit_DemoTierDepthMultiplierDwellsAtLiveM(t *testing.T) {
	resolver, _ := scope.NewStaticResolver(scope.Config{Boundary: "scope"})
	demo := tiers.DefaultConfig()
	demo.ConfidenceRequired = map[contract.Tier]float64{
		contract.TierTag:     0.01, // threshold 1.01
		contract.TierContain: 0.30, // threshold 2.60
		contract.TierJail:    0.50, // threshold 4.50
	}
	const M = 3.0
	ts := time.Unix(1_000_000, 0)
	newEng := func(depth bool) *Service {
		calib := calibration.New(calibration.Config{EvidenceFloor: 1000})
		scorer := scoring.New(5*time.Minute, calib, nil).UseMultiplier(fixedMultiplier(M))
		cfg := Config{Resolver: resolver, Scorer: scorer, Decider: tiers.StaticDecider{}, Tiers: demo}
		if depth {
			cfg.TierDepthMultiplier = fixedMultiplier(M)
		}
		eng, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return eng
	}

	// WITH depth tiering: tier climbs by distinct-touch count regardless of M.
	eng := newEng(true)
	eng.Submit(touch("scope", 1, "a", ts)) // B=1
	v, _ := eng.Submit(touch("scope", 1, "b", ts))
	if v.Tier != contract.TierTag {
		t.Fatalf("2 touches @ M=%.0f: tier=%d, want Tag(%d) — depth tiering must dwell, not jail", M, v.Tier, contract.TierTag)
	}
	if v.Score != 2*M { // B×M still rides the verdict so the live M stays visible
		t.Fatalf("Verdict.Score=%.2f, want %.2f (full B×M)", v.Score, 2*M)
	}
	v, _ = eng.Submit(touch("scope", 1, "c", ts)) // B=3
	if v.Tier != contract.TierContain {
		t.Fatalf("3 touches @ M=%.0f: tier=%d, want Contain(%d)", M, v.Tier, contract.TierContain)
	}
	eng.Submit(touch("scope", 1, "d", ts))
	v, _ = eng.Submit(touch("scope", 1, "e", ts)) // B=5
	if v.Tier != contract.TierJail {
		t.Fatalf("5 touches @ M=%.0f: tier=%d, want Jail(%d)", M, v.Tier, contract.TierJail)
	}

	// CONTROL — no depth tiering: the same 2 touches jail immediately (score 6.0 >
	// Jail threshold 4.5), the all-jail behavior this fix corrects.
	ctl := newEng(false)
	ctl.Submit(touch("scope", 2, "a", ts))
	cv, _ := ctl.Submit(touch("scope", 2, "b", ts))
	if cv.Tier != contract.TierJail {
		t.Fatalf("control (no depth tiering): 2 touches @ M=%.0f tier=%d, want Jail(%d) — confirms M compresses without the fix", M, cv.Tier, contract.TierJail)
	}
}

// badResolver always fails Validate and Resolve.
type badResolver struct{}

func (badResolver) Resolve(contract.FlowIdentity) (contract.ScopeKey, error) {
	return "", scope.ErrUnresolved
}
func (badResolver) Validate() error { return scope.ErrUnresolved }
