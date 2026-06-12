package boot

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/boltevents"
	"github.com/canarysting/canarysting/internal/intelligence/network"
	"github.com/canarysting/canarysting/internal/intelligence/sharedset"
	"github.com/canarysting/canarysting/internal/intelligence/sharpen"
)

// D6e: a local Tier-3 jail records the jailed flow's coarse pattern into the cross-scope
// ledger — but ONLY when Contribute is opted in, and only via the ReportOutcome path
// (where the amended five-axis outcome has landed). The SAME derived profile feeds both
// the local sharpen store and the ledger.
func TestD6ContributeRecordsLocalJailWhenOptedIn(t *testing.T) {
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	mkSrc := func() *fakeSharpenSource {
		return &fakeSharpenSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{
			"scopeA": {{ScopeKey: "scopeA", FlowID: 1, CanaryType: ".env", Tier: 3, Timestamp: now, Sting: intelligence.StingOutcome{
				Axes: uint32(contract.AxisVelocity | contract.AxisPoison), TimeHeldSec: 10,
				PoisonReached: 2, PoisonClass: "topology", DisengageReason: contract.DisengageAttacker, TimeToDisengageSec: 5,
			}}},
		}}
	}
	run := func(contribute bool) *network.Ledger {
		ps, _, err := persist.Open(filepath.Join(t.TempDir(), "b.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ps.Close() })
		l, err := network.NewLedger()
		if err != nil {
			t.Fatal(err)
		}
		ce := &capturingEngine{
			inner:        fakeInner{tierByCookie: map[uint64]contract.Tier{1: contract.TierJail}},
			events:       boltevents.New(ps),
			sharpen:      sharpen.NewStore(mkSrc()),
			pendingJails: map[uint64]struct{}{},
			ledger:       l,
			contribute:   contribute,
		}
		if _, err := ce.Submit(contract.SignalEvent{Flow: contract.FlowIdentity{SocketCookie: 1}, Scope: "scopeA", Canary: ".env", Timestamp: now}); err != nil {
			t.Fatal(err)
		}
		if err := ce.ReportOutcome(contract.OutcomeRecord{SocketCookie: 1, Scope: "scopeA", Outcome: contract.StingOutcome{Axes: contract.AxisVelocity | contract.AxisPoison}, TimestampUnixMs: now.UnixMilli()}); err != nil {
			t.Fatal(err)
		}
		return l
	}

	if got := run(true).Patterns(); got != 1 {
		t.Fatalf("Contribute=true: ledger recorded %d patterns, want 1", got)
	}
	if got := run(false).Patterns(); got != 0 {
		t.Fatalf("Contribute=false: ledger recorded %d patterns, want 0 (no contribution without opt-in)", got)
	}
}

// D6g/D6f: with Consume set and a spool of cleared patterns, Build loads them into the
// shared-set consumer; without Consume, it loads nothing.
func TestD6ConsumeLoadsSpoolWhenOptedIn(t *testing.T) {
	validLine := `{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":true,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1}` + "\n"
	spool := filepath.Join(t.TempDir(), "shared.ndjson")
	if err := os.WriteFile(spool, []byte(validLine+validLine), 0o600); err != nil {
		t.Fatal(err)
	}

	build := func(consume bool) *Built {
		b, err := Build(Options{
			Boundary: "scopeA", Window: time.Minute,
			BaselineDBPath: filepath.Join(t.TempDir(), "base.db"),
			Consume:        consume, SharedSpoolPath: spool,
		}, observe.NoopObserver{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { b.Close() })
		return b
	}

	on := build(true)
	if on.SharedSet == nil || on.SharedSet.Len() != 2 {
		t.Fatalf("Consume=true: loaded %v shared patterns, want 2", on.SharedSet.Len())
	}
	off := build(false)
	if off.SharedSet == nil || off.SharedSet.Len() != 0 {
		t.Fatalf("Consume=false: loaded %d shared patterns, want 0 (no consumption without opt-in)", off.SharedSet.Len())
	}
}

// The composite matcher returns the MAX of the local + shared strengths (and tolerates
// nil members) — both are weight context, fed into the single FingerprintMatch dimension.
func TestMatcherSetReturnsMax(t *testing.T) {
	m := matcherSet{local: constMatcher(0.3), shared: constMatcher(0.7)}
	if got := m.Match("s", contract.FlowIdentity{}, time.Now()); got != 0.7 {
		t.Fatalf("composite = %v, want 0.7 (max)", got)
	}
	if got := (matcherSet{local: constMatcher(0.5)}).Match("s", contract.FlowIdentity{}, time.Now()); got != 0.5 {
		t.Fatalf("composite with nil shared = %v, want 0.5", got)
	}
	if got := (matcherSet{}).Match("s", contract.FlowIdentity{}, time.Now()); got != 0 {
		t.Fatalf("empty composite = %v, want 0", got)
	}
}

// Regression guarantee: a non-consuming deployment is byte-identical to D5-Phase-2. With
// an EMPTY shared-set (the real sharedset.Store, cold short-circuit => 0), the composite
// passes the local matcher's value through unchanged.
func TestMatcherSetEmptySharedIsLocalPassthrough(t *testing.T) {
	empty := sharedset.NewStore(nil) // no patterns, no source => Match returns 0 (cold)
	m := matcherSet{local: constMatcher(0.42), shared: empty}
	if got := m.Match("s", contract.FlowIdentity{SocketCookie: 1}, time.Now()); got != 0.42 {
		t.Fatalf("with an empty shared-set the composite must pass the local value through, got %v want 0.42", got)
	}
}

type constMatcher float64

func (c constMatcher) Match(contract.ScopeKey, contract.FlowIdentity, time.Time) float64 {
	return float64(c)
}
