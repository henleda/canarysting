package l7events

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/intelligence"
)

func openStore(t *testing.T) (*Store, *persist.Store) {
	t.Helper()
	p, _, err := persist.Open(filepath.Join(t.TempDir(), "baseline.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return New(p), p
}

func flowWithL7(cookie uint64, method, path, src, spiffe string) contract.FlowIdentity {
	return contract.FlowIdentity{
		SocketCookie: cookie,
		SPIFFEID:     spiffe,
		L7Attributes: map[string]string{
			contract.AttrRequestMethod: method,
			contract.AttrRequestPath:   path,
			contract.AttrSourceAddress: src,
		},
	}
}

// TestCaptureWritesEnrichedRecordOnTouch is the core slice-1 guarantee: a Tier>=Tag
// touch produces ONE enriched record that carries the raw L7 + identity context
// (method/path/source/SPIFFE) and the engine decision.
func TestCaptureWritesEnrichedRecordOnTouch(t *testing.T) {
	s, _ := openStore(t)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	flow := flowWithL7(0xABCDEF, "GET", "/.env?token=abc", "203.0.113.7:54321", "spiffe://cluster/sa/scanner")
	v := contract.Verdict{Scope: "scope-a", Tier: contract.TierContain, Score: 2.5, Calibrated: true, Mode: contract.ModeInline}
	feats := map[string]float64{"adjacency_novelty": 0.9}

	s.Capture("scope-a", flow.SocketCookie, "decoy_file", v, FromFlow(flow), feats, now)

	recs := s.Snapshot("scope-a")
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.Method != "GET" || r.Path != "/.env?token=abc" {
		t.Fatalf("L7 request line not captured: method=%q path=%q", r.Method, r.Path)
	}
	if r.SourceAddress != "203.0.113.7:54321" {
		t.Fatalf("source address not captured: %q", r.SourceAddress)
	}
	if r.SPIFFEID != "spiffe://cluster/sa/scanner" {
		t.Fatalf("SPIFFE not captured: %q", r.SPIFFEID)
	}
	if r.SocketCookie != 0xABCDEF {
		t.Fatalf("join cookie (rule 4) not captured: %x", r.SocketCookie)
	}
	if r.Tier != int(contract.TierContain) || r.Verdict != "contain" || r.Score != 2.5 || !r.Calibrated {
		t.Fatalf("engine decision not captured: %+v", r)
	}
	if r.CanaryType != "decoy_file" {
		t.Fatalf("canary type not captured: %q", r.CanaryType)
	}
	if r.BytesRealDataCrossed != 0 {
		t.Fatalf("a canary touch crosses ZERO real bytes; got %d", r.BytesRealDataCrossed)
	}
	if r.Features["adjacency_novelty"] != 0.9 {
		t.Fatalf("features not captured: %+v", r.Features)
	}
	if r.EventID == "" {
		t.Fatal("event id must be set")
	}
}

// TestObserveTierNotRetained mirrors boltevents.CaptureVerdict's Tier>=Tag gate:
// a Tier-0 (Observe) touch is not recorded.
func TestObserveTierNotRetained(t *testing.T) {
	s, _ := openStore(t)
	flow := flowWithL7(1, "GET", "/x", "1.2.3.4:1", "")
	s.Capture("scope-a", flow.SocketCookie, "decoy_file",
		contract.Verdict{Scope: "scope-a", Tier: contract.TierObserve}, FromFlow(flow), nil, time.Now())
	if got := len(s.Snapshot("scope-a")); got != 0 {
		t.Fatalf("Observe-tier touch must not be retained, got %d records", got)
	}
}

// TestUnscopedRefused: an empty (forged-then-zeroed) scope is refused — never store
// unscoped (rule 5).
func TestUnscopedRefused(t *testing.T) {
	s, _ := openStore(t)
	flow := flowWithL7(1, "GET", "/x", "1.2.3.4:1", "")
	s.Capture("", flow.SocketCookie, "decoy_file",
		contract.Verdict{Tier: contract.TierTag}, FromFlow(flow), nil, time.Now())
	if got := len(s.Snapshot("")); got != 0 {
		t.Fatalf("empty scope must be refused, got %d", got)
	}
}

// TestNilL7AttributesGuarded: an unattributed flow (nil L7Attributes map) must not
// panic and still records the touch (with empty L7 context).
func TestNilL7AttributesGuarded(t *testing.T) {
	s, _ := openStore(t)
	flow := contract.FlowIdentity{SocketCookie: 9} // no SPIFFE, nil L7Attributes
	s.Capture("scope-a", flow.SocketCookie, "decoy_file",
		contract.Verdict{Scope: "scope-a", Tier: contract.TierTag}, FromFlow(flow), nil, time.Now())
	recs := s.Snapshot("scope-a")
	if len(recs) != 1 {
		t.Fatalf("want 1 record from an unattributed touch, got %d", len(recs))
	}
	if recs[0].Method != "" || recs[0].Path != "" || recs[0].SourceAddress != "" || recs[0].SPIFFEID != "" {
		t.Fatalf("unattributed flow must have empty L7 context, got %+v", recs[0])
	}
}

// TestRecurrenceKeyBumpsHitCount: a repeat touch on the same (cookie, method, path)
// collapses onto one record (bumps HitCount) instead of flooding the log.
func TestRecurrenceKeyBumpsHitCount(t *testing.T) {
	s, _ := openStore(t)
	flow := flowWithL7(7, "GET", "/.env", "1.1.1.1:2", "")
	v := contract.Verdict{Scope: "scope-a", Tier: contract.TierTag}
	for i := 0; i < 5; i++ {
		s.Capture("scope-a", flow.SocketCookie, "decoy_file", v, FromFlow(flow), nil, time.Now())
	}
	recs := s.Snapshot("scope-a")
	if len(recs) != 1 {
		t.Fatalf("repeat touches on the same request line should collapse, got %d records", len(recs))
	}
	if recs[0].HitCount != 5 {
		t.Fatalf("HitCount want 5, got %d", recs[0].HitCount)
	}
	// A DIFFERENT path is a distinct record (the spray dimension the cap bounds).
	other := flowWithL7(7, "GET", "/admin-secrets", "1.1.1.1:2", "")
	s.Capture("scope-a", other.SocketCookie, "decoy_file", v, FromFlow(other), nil, time.Now())
	if got := len(s.Snapshot("scope-a")); got != 2 {
		t.Fatalf("a distinct path should be a distinct record, got %d", got)
	}
}

// TestPerScopeIsolation: records never leak across scopes (rule 5).
func TestPerScopeIsolation(t *testing.T) {
	s, _ := openStore(t)
	fa := flowWithL7(1, "GET", "/a", "1.1.1.1:1", "")
	fb := flowWithL7(2, "GET", "/b", "2.2.2.2:2", "")
	s.Capture("scope-a", fa.SocketCookie, "decoy_file", contract.Verdict{Scope: "scope-a", Tier: contract.TierTag}, FromFlow(fa), nil, time.Now())
	s.Capture("scope-b", fb.SocketCookie, "decoy_file", contract.Verdict{Scope: "scope-b", Tier: contract.TierTag}, FromFlow(fb), nil, time.Now())

	a := s.Snapshot("scope-a")
	b := s.Snapshot("scope-b")
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("each scope should hold exactly its own record: a=%d b=%d", len(a), len(b))
	}
	if a[0].Path != "/a" || b[0].Path != "/b" {
		t.Fatalf("scopes crossed: a=%q b=%q", a[0].Path, b[0].Path)
	}
}

// TestPersistRehydrateRoundTrip: records survive a reboot (close + reopen the same
// db) — the local-rich record is durable like the deviant log.
func TestPersistRehydrateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.db")

	p1, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1 := New(p1)
	flow := flowWithL7(0xDEAD, "POST", "/.env?x=1", "9.9.9.9:9", "spiffe://x")
	s1.Capture("scope-a", flow.SocketCookie, "decoy_file",
		contract.Verdict{Scope: "scope-a", Tier: contract.TierJail, Score: 5}, FromFlow(flow), map[string]float64{"id": 1}, time.Now())
	if err := p1.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: rehydrate must restore the record verbatim.
	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p2.Close() })
	s2 := New(p2)
	recs := s2.Snapshot("scope-a")
	if len(recs) != 1 {
		t.Fatalf("rehydrate lost the record: got %d", len(recs))
	}
	r := recs[0]
	if r.Path != "/.env?x=1" || r.Method != "POST" || r.SourceAddress != "9.9.9.9:9" || r.SPIFFEID != "spiffe://x" {
		t.Fatalf("rehydrated record lost L7 context: %+v", r)
	}
	if r.Tier != int(contract.TierJail) || r.Score != 5 {
		t.Fatalf("rehydrated record lost the decision: %+v", r)
	}
	if r.Features["id"] != 1 {
		t.Fatalf("rehydrated record lost features: %+v", r.Features)
	}
	// A by-cookie lookup (rule-4 join-back) finds it.
	if got := s2.LookupByCookie("scope-a", 0xDEAD); len(got) != 1 {
		t.Fatalf("LookupByCookie should find the rehydrated record, got %d", len(got))
	}
}

// TestCapEvictsOldest: a spray of distinct request lines is bounded by the cap;
// eviction is observable.
func TestCapEvictsOldest(t *testing.T) {
	s, _ := openStore(t)
	s.cap = 3 // shrink for the test
	base := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	v := contract.Verdict{Scope: "scope-a", Tier: contract.TierTag}
	for i := 0; i < 10; i++ {
		path := "/p" + string(rune('0'+i))
		flow := flowWithL7(uint64(i), "GET", path, "1.1.1.1:1", "")
		// strictly increasing LastSeen so the OLDEST is the earliest inserted survivor.
		s.Capture("scope-a", flow.SocketCookie, "decoy_file", v, FromFlow(flow), nil, base.Add(time.Duration(i)*time.Minute))
	}
	recs := s.Snapshot("scope-a")
	if len(recs) != 3 {
		t.Fatalf("cap should bound the set to 3, got %d", len(recs))
	}
	if s.Evicted() == 0 {
		t.Fatal("eviction must be observable (Evicted counter)")
	}
	// The on-disk set must also respect the cap (the eviction is persisted).
	got := 0
	_ = s.store.RangeL7Touches("scope-a", func(_, _ []byte) error { got++; return nil })
	if got != 3 {
		t.Fatalf("on-disk set should also be capped at 3, got %d", got)
	}
}

// TestTTLReaper: a record older than the TTL ages out and its eviction is persisted.
func TestTTLReaper(t *testing.T) {
	s, _ := openStore(t)
	s.ttl = time.Hour
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	stale := flowWithL7(1, "GET", "/old", "1.1.1.1:1", "")
	fresh := flowWithL7(2, "GET", "/new", "2.2.2.2:2", "")
	v := contract.Verdict{Scope: "scope-a", Tier: contract.TierTag}
	s.Capture("scope-a", stale.SocketCookie, "decoy_file", v, FromFlow(stale), nil, now.Add(-2*time.Hour))
	s.Capture("scope-a", fresh.SocketCookie, "decoy_file", v, FromFlow(fresh), nil, now.Add(-1*time.Minute))

	if removed := s.Reap(now); removed != 1 {
		t.Fatalf("reaper should drop the 1 stale record, got %d", removed)
	}
	recs := s.Snapshot("scope-a")
	if len(recs) != 1 || recs[0].Path != "/new" {
		t.Fatalf("only the fresh record should survive: %+v", recs)
	}
	got := 0
	_ = s.store.RangeL7Touches("scope-a", func(_, _ []byte) error { got++; return nil })
	if got != 1 {
		t.Fatalf("the reaper eviction must be persisted: on-disk count %d", got)
	}
}

// TestEgressEventStaysAddressless is the rule-9 invariant guard: the cross-customer
// egress event (intelligence.AdversaryInteractionEvent) must remain structurally
// ADDRESSLESS — it must have NO field that could carry a raw address / path /
// method / SPIFFE. Slice 1 must add those ONLY to the local sibling
// (EnrichedTouchRecord here), NEVER to the egress event. This fails the build if
// anyone widens the egress event with a leaky field name.
func TestEgressEventStaysAddressless(t *testing.T) {
	rt := reflect.TypeOf(intelligence.AdversaryInteractionEvent{})
	leaky := []string{"path", "method", "address", "addr", "spiffe", "sourceaddress", "url", "host", "ip", "header"}
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		for _, bad := range leaky {
			if strings.Contains(name, bad) {
				t.Fatalf("AdversaryInteractionEvent gained field %q (matches %q): the cross-customer egress event must stay ADDRESSLESS (rule 9). Put raw L7 context on the LOCAL l7events.EnrichedTouchRecord sibling, never on the egress event.", rt.Field(i).Name, bad)
			}
		}
	}
	// And the local sibling DOES carry them (so this slice actually captured them).
	lr := reflect.TypeOf(EnrichedTouchRecord{})
	for _, want := range []string{"Path", "Method", "SourceAddress", "SPIFFEID"} {
		if _, ok := lr.FieldByName(want); !ok {
			t.Fatalf("EnrichedTouchRecord is missing the local-rich field %q", want)
		}
	}
}
