package boot_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/boot"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/audit"
)

// Refuse-to-start: with no resolvable scope, Build fails (never a global scope).
func TestBuildRefusesEmptyBoundary(t *testing.T) {
	if _, err := boot.Build(boot.Options{}, observe.NoopObserver{}); err == nil {
		t.Fatal("Build accepted an empty boundary; must refuse to start")
	}
}

// Without the observe path wired, the engine runs touch-only: M is a forced 1.0
// and an uncalibrated scope scores the raw distinct-touch count.
func TestTouchOnlyWithoutObserve(t *testing.T) {
	built, err := boot.Build(boot.Options{Boundary: "scopeA", Window: time.Minute}, observe.NoopObserver{})
	if err != nil {
		t.Fatal(err)
	}
	defer built.Close()
	if built.Aggregator != nil {
		t.Fatal("aggregator wired without an observe cgroup")
	}
	v, err := built.Engine.Submit(contract.SignalEvent{
		Flow: contract.FlowIdentity{SocketCookie: 0xABCD}, Scope: "scopeA",
		Canary: "aws.key", Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Calibrated {
		t.Error("scope reported calibrated with no feedback")
	}
	if v.Score != 1.0 {
		t.Errorf("single touch score = %v, want 1.0 (M=1 touch-only)", v.Score)
	}
}

// With a durable DB, the engine captures Tier≥Tag interactions into the durable
// EventStore — and drops a sub-Tag (Observe) touch.
func TestCaptureWiringRecordsInteractions(t *testing.T) {
	db := filepath.Join(t.TempDir(), "baseline.db")
	built, err := boot.Build(boot.Options{Boundary: "scopeA", Window: time.Minute, BaselineDBPath: db}, observe.NoopObserver{})
	if err != nil {
		t.Fatal(err)
	}
	defer built.Close()
	if built.Events == nil {
		t.Fatal("EventStore not wired with a DB path")
	}

	now := time.Now()
	flow := contract.FlowIdentity{SocketCookie: 0xBEEF}
	// First touch: base 1.0 → Observe tier → not captured.
	if _, err := built.Engine.Submit(contract.SignalEvent{Flow: flow, Scope: "scopeA", Canary: "aws.key", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	// Second distinct touch on the same flow within the window: base 2.0 → Tag → captured.
	if _, err := built.Engine.Submit(contract.SignalEvent{Flow: flow, Scope: "scopeA", Canary: "ssh.key", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	got, err := built.Events.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("captured %d interaction events, want 1 (Observe dropped, Tag kept)", len(got))
	}
	if got[0].Tier < int(contract.TierTag) {
		t.Errorf("captured an Observe-tier event: tier=%d", got[0].Tier)
	}
}

// SLICE A: with a durable DB the engine appends a TAMPER-EVIDENT audit record for a
// Tier>=Tag verdict at the Submit seam, threading the RAW L7/identity context — while
// the addressless cross-customer egress event stays byte-for-byte addressless. The
// chain validates end-to-end. Mirrors TestCaptureWiringRecordsInteractions' scoring.
func TestAuditChainCapturedAtSubmitSeam(t *testing.T) {
	db := filepath.Join(t.TempDir(), "baseline.db")
	built, err := boot.Build(boot.Options{Boundary: "scopeA", Window: time.Minute, BaselineDBPath: db}, observe.NoopObserver{})
	if err != nil {
		t.Fatal(err)
	}
	defer built.Close()
	if built.Audit == nil {
		t.Fatal("audit store not wired with a DB path")
	}

	now := time.Now()
	// A flow carrying the raw L7 + identity context the adapter stamps.
	flow := contract.FlowIdentity{
		SocketCookie: 0xBEEF,
		SPIFFEID:     "spiffe://cluster/sa/scanner",
		L7Attributes: map[string]string{
			contract.AttrRequestMethod: "GET",
			contract.AttrRequestPath:   "/.env?token=abc",
			contract.AttrSourceAddress: "203.0.113.7:54321",
		},
	}
	// First touch: Observe tier → not chained. Second distinct touch: Tag → chained.
	if _, err := built.Engine.Submit(contract.SignalEvent{Flow: flow, Scope: "scopeA", Canary: "aws.key", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := built.Engine.Submit(contract.SignalEvent{Flow: flow, Scope: "scopeA", Canary: "ssh.key", Timestamp: now}); err != nil {
		t.Fatal(err)
	}

	// (a) Exactly one tamper-evident record, threaded with the raw L7/identity context.
	blob, err := built.Audit.Export("scopeA")
	if err != nil {
		t.Fatal(err)
	}
	var report audit.CaseReport
	if err := json.Unmarshal(blob, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Records) != 1 {
		t.Fatalf("audit chain has %d records, want 1 (Observe dropped, Tag chained)", len(report.Records))
	}
	r := report.Records[0]
	if r.Path != "/.env?token=abc" || r.SourceAddress != "203.0.113.7:54321" || r.SPIFFEID != "spiffe://cluster/sa/scanner" {
		t.Fatalf("audit record did not thread the raw L7/identity context: %+v", r)
	}
	if r.SocketCookie != 0xBEEF || r.Tier < int(contract.TierTag) {
		t.Fatalf("audit record action facts wrong: cookie=%x tier=%d", r.SocketCookie, r.Tier)
	}
	if r.BytesRealDataCrossed != 0 {
		t.Fatalf("bytes_real_data_crossed must be the structural 0, got %d", r.BytesRealDataCrossed)
	}
	// (b) The chain validates.
	if !report.Verify.Intact {
		t.Fatalf("freshly captured chain must verify intact: %+v", report.Verify)
	}

	// (c) Rule 9: the addressless cross-customer egress event carries NO raw address —
	// the rich context lives ONLY in the local audit record above. The egress event
	// type has no address/path field by construction; assert the join-id is the cookie
	// (an internal id) and nothing more leaked.
	ev, err := built.Events.Query("scopeA", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 {
		t.Fatalf("egress events = %d, want 1", len(ev))
	}
	if ev[0].FlowID != 0xBEEF {
		t.Fatalf("egress event join id must be the socket cookie, got %x", ev[0].FlowID)
	}
}

// ContainInline makes Tier 2 (Contain) verdicts INLINE (so the adapter runs the
// M6 attrition pump) while leaving Tier 3 (Jail) async. Touch-only cold-start
// scoring is the distinct-touch count, so 3 distinct touches on one flow score
// 3.0 → Contain (Tag≥1.30, Contain≥3.00, Jail≥5.10).
func TestContainInlineMakesTierTwoInline(t *testing.T) {
	containVerdict := func(inline bool) contract.Verdict {
		t.Helper()
		built, err := boot.Build(boot.Options{Boundary: "scopeA", Window: time.Minute, ContainInline: inline}, observe.NoopObserver{})
		if err != nil {
			t.Fatal(err)
		}
		defer built.Close()
		now := time.Now()
		flow := contract.FlowIdentity{SocketCookie: 0xC0DE}
		var v contract.Verdict
		for _, c := range []string{"aws.key", "ssh.key", "db.dump"} { // 3 distinct → score 3.0 → Contain
			if v, err = built.Engine.Submit(contract.SignalEvent{Flow: flow, Scope: "scopeA", Canary: contract.CanaryType(c), Timestamp: now}); err != nil {
				t.Fatal(err)
			}
		}
		if v.Tier != contract.TierContain {
			t.Fatalf("3 distinct touches => tier %d, want Contain (%d)", v.Tier, contract.TierContain)
		}
		return v
	}
	if v := containVerdict(true); v.Mode != contract.ModeInline {
		t.Errorf("ContainInline=true: Tier-2 mode = %v, want ModeInline (attrition pump)", v.Mode)
	}
	if v := containVerdict(false); v.Mode != contract.ModeAsync {
		t.Errorf("ContainInline=false: Tier-2 mode = %v, want ModeAsync (kernel-enforced default)", v.Mode)
	}
}
