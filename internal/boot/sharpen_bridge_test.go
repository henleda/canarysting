package boot

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/boltevents"
	"github.com/canarysting/canarysting/internal/intelligence/sharpen"
)

// fakeInner is a contract.Engine whose verdict tier is fixed per cookie, so the bridge
// test can drive a deterministic Tier-3 (jail) vs Tier-2 (contain) without depending on
// scoring thresholds.
type fakeInner struct{ tierByCookie map[uint64]contract.Tier }

func (f fakeInner) Submit(ev contract.SignalEvent) (contract.Verdict, error) {
	return contract.Verdict{Flow: ev.Flow, Scope: ev.Scope, Tier: f.tierByCookie[ev.Flow.SocketCookie]}, nil
}

// fakeSharpenSource feeds the sharpen store canned per-flow events, decoupling the
// bridge test from how/whether AmendOutcome rewrites the durable store — the bridge's
// job is only to call RecordJail at the right time, which this lets us observe.
type fakeSharpenSource struct {
	byScope map[string][]intelligence.AdversaryInteractionEvent
}

func (f *fakeSharpenSource) Query(scope string, _, _ time.Time) ([]intelligence.AdversaryInteractionEvent, error) {
	return f.byScope[scope], nil
}

// The D5-2 bridge: a Tier-3 jail at Submit only MARKS the flow pending (its StingOutcome
// is still zero then); the confirmed-malicious profile is recorded at ReportOutcome,
// once the amended five-axis outcome has landed. This verifies (a) Submit-jail alone
// records nothing, (b) ReportOutcome then records, and (c) a Tier-2 verdict never feeds
// the bridge even after its outcome is reported.
func TestSharpenBridgeRecordsOnReportNotSubmit(t *testing.T) {
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	types := []string{".env", "backup/db.sql"}
	axesAttr := contract.AxisVelocity | contract.AxisPoison
	axes := uint32(axesAttr)

	src := &fakeSharpenSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{}}
	mk := func(scope string, cookie uint64) {
		for i, ty := range types {
			src.byScope[scope] = append(src.byScope[scope], intelligence.AdversaryInteractionEvent{
				ScopeKey: scope, FlowID: cookie, CanaryType: ty, Tier: 3,
				Timestamp: now.Add(time.Duration(i) * time.Second), Sting: intelligence.StingOutcome{Axes: axes},
			})
		}
	}
	for _, c := range []uint64{1, 2, 3, 4} { // scopeA: jailed 1,2,3 + probe 4
		mk("scopeA", c)
	}
	for _, c := range []uint64{11, 12, 13, 14} { // scopeB: contained 11,12,13 + probe 14
		mk("scopeB", c)
	}

	// A real durable store so CaptureVerdict/AmendOutcome don't error; their effect is
	// irrelevant here (the sharpen store reads from src, not from them).
	ps, _, err := persist.Open(filepath.Join(t.TempDir(), "bridge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	sh := sharpen.NewStore(src)
	ce := &capturingEngine{
		inner: fakeInner{tierByCookie: map[uint64]contract.Tier{
			1: contract.TierJail, 2: contract.TierJail, 3: contract.TierJail,
			11: contract.TierContain, 12: contract.TierContain, 13: contract.TierContain,
		}},
		events:       boltevents.New(ps),
		sharpen:      sh,
		pendingJails: map[uint64]struct{}{},
	}

	submit := func(scope contract.ScopeKey, cookie uint64) {
		t.Helper()
		if _, err := ce.Submit(contract.SignalEvent{Flow: contract.FlowIdentity{SocketCookie: cookie}, Scope: scope, Canary: ".env", Timestamp: now}); err != nil {
			t.Fatal(err)
		}
	}
	report := func(scope contract.ScopeKey, cookie uint64) {
		t.Helper()
		if err := ce.ReportOutcome(contract.OutcomeRecord{SocketCookie: cookie, Scope: scope, Outcome: contract.StingOutcome{Axes: axesAttr}, TimestampUnixMs: now.UnixMilli()}); err != nil {
			t.Fatal(err)
		}
	}

	probeA := contract.FlowIdentity{SocketCookie: 4}

	// (a) Jail-Submit alone must NOT record: a probe matching the jailed behavior still
	// scores 0 — nothing enters the confirmed set until the outcome is reported.
	for _, c := range []uint64{1, 2, 3} {
		submit("scopeA", c)
	}
	if got := sh.Match("scopeA", probeA, now); got != 0 {
		t.Fatalf("Submit-jail alone recorded a profile: Match=%v, want 0 (bridge must wait for ReportOutcome)", got)
	}

	// (b) ReportOutcome drains each pending jail into RecordJail — now the probe sharpens.
	for _, c := range []uint64{1, 2, 3} {
		report("scopeA", c)
	}
	if got := sh.Match("scopeA", probeA, now); got < 0.999 {
		t.Fatalf("after 3 jails were reported, a matching probe should sharpen (~1.0), got %v", got)
	}

	// (c) Tier-2 (Contain) must NEVER feed the bridge: 3 contained flows + their reports
	// leave the confirmed set empty, so a matching probe in scopeB still scores 0.
	for _, c := range []uint64{11, 12, 13} {
		submit("scopeB", c)
		report("scopeB", c)
	}
	if got := sh.Match("scopeB", contract.FlowIdentity{SocketCookie: 14}, now); got != 0 {
		t.Fatalf("Tier-2 verdicts fed the sharpen bridge: scopeB Match=%v, want 0 (only Tier-3 jails are confirmed-malicious)", got)
	}
}
