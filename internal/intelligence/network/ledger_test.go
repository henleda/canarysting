package network

import (
	"reflect"
	"strings"
	"testing"
)

func refExport() any { e, _ := ReferenceCandidate().EgressFields(); return e }

// A scope recording the same pattern repeatedly is ONE distinct scope — re-exhibition
// must not inflate the count (the whole k-anonymity guarantee).
func TestLedgerRecordIdempotentPerScope(t *testing.T) {
	l, _ := NewLedger()
	exp := refExport()
	for i := 0; i < 5; i++ {
		n, err := l.RecordForm("scope-a", exp)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("one scope recorded %dx => count %d, want 1", i+1, n)
		}
	}
}

func TestLedgerCountsDistinctScopes(t *testing.T) {
	l, _ := NewLedger()
	exp := refExport()
	for _, s := range []string{"a", "b", "c", "a", "b"} { // a,b repeat
		if _, err := l.RecordForm(s, exp); err != nil {
			t.Fatal(err)
		}
	}
	if got := l.distinctScopes(coarseKeyFromExportT(t, exp)); got != 3 {
		t.Fatalf("distinct scopes = %d, want 3 (a,b,c; repeats ignored)", got)
	}
}

func TestLedgerUnknownKeyIsZero(t *testing.T) {
	l, _ := NewLedger()
	// Never recorded => fail-closed 0 (=> sub-k => deny).
	if got := l.distinctScopes(coarseKeyFromExportT(t, refExport())); got != 0 {
		t.Fatalf("unknown key count = %d, want 0", got)
	}
}

// Distinct coarse patterns are counted SEPARATELY: recording pattern X in 3 scopes does
// not lift pattern Y's count.
func TestLedgerKeysSeparatePatterns(t *testing.T) {
	l, _ := NewLedger()
	x := referenceExport{ReachedContain: true, EngagedVelocity: true, HeldBand: 2, PoisonClass: "topology", CadenceBand: 1}
	y := x
	y.CadenceBand = 3 // different tempo band => different cell
	for _, s := range []string{"a", "b", "c"} {
		if _, err := l.RecordForm(s, x); err != nil {
			t.Fatal(err)
		}
	}
	if got := l.distinctScopes(coarseKeyFromExportT(t, y)); got != 0 {
		t.Fatalf("pattern Y (different CadenceBand) count = %d, want 0 (separate cell)", got)
	}
	if got := l.distinctScopes(coarseKeyFromExportT(t, x)); got != 3 {
		t.Fatalf("pattern X count = %d, want 3", got)
	}
}

// ClearWithLedger denies until the real count reaches k, then crosses.
func TestClearWithLedgerKGate(t *testing.T) {
	l, _ := NewLedger()
	exp := refExport()
	optedIn := cand{export: exp, ctx: ContributionContext{Contribute: true}}

	l.RecordForm("a", exp)
	l.RecordForm("b", exp) // only 2 distinct < k=3
	if _, err := ClearWithLedger(optedIn, ClearContext{Ledger: l}); err == nil {
		t.Fatal("sub-k pattern must be denied by the ledger gate")
	}
	l.RecordForm("c", exp) // now k=3
	if c, err := ClearWithLedger(optedIn, ClearContext{Ledger: l}); err != nil || c == nil {
		t.Fatalf("k>=3 pattern must clear: %v", err)
	}
}

func TestClearWithLedgerNilLedgerDenies(t *testing.T) {
	exp := refExport()
	if _, err := ClearWithLedger(cand{export: exp, ctx: ContributionContext{Contribute: true}}, ClearContext{Ledger: nil}); err == nil {
		t.Fatal("nil ledger must fail closed (no k-anonymity provenance)")
	}
}

// The tripwire: a producer that asserts a count is rejected — the count is the ledger's
// job (D6d).
func TestClearWithLedgerTripwireOnProducerCount(t *testing.T) {
	l, _ := NewLedger()
	exp := refExport()
	for _, s := range []string{"a", "b", "c"} {
		l.RecordForm(s, exp)
	}
	bad := cand{export: exp, ctx: ContributionContext{Contribute: true, SeenInScopes: 99}}
	if _, err := ClearWithLedger(bad, ClearContext{Ledger: l}); err == nil {
		t.Fatal("a producer-asserted SeenInScopes must trip the tripwire, even at real k>=3")
	}
}

func TestClearWithLedgerNotOptedIn(t *testing.T) {
	l, _ := NewLedger()
	exp := refExport()
	for _, s := range []string{"a", "b", "c"} {
		l.RecordForm(s, exp)
	}
	if _, err := ClearWithLedger(cand{export: exp, ctx: ContributionContext{Contribute: false}}, ClearContext{Ledger: l}); err == nil {
		t.Fatal("an un-opted-in scope must not cross even at k>=3")
	}
}

// D6c structural guard: the ledger key carries NO hash/identity field — it is the coarse
// tuple, never the reversible BehavioralHash.
func TestCoarseKeyHasNoHashOrIdentity(t *testing.T) {
	kt := reflect.TypeOf(coarseKey{})
	for i := 0; i < kt.NumField(); i++ {
		n := strings.ToLower(kt.Field(i).Name)
		for _, banned := range []string{"hash", "scope", "flow", "cookie", "ip", "identity", "seq", "order", "digest"} {
			if strings.Contains(n, banned) {
				t.Fatalf("coarseKey.%s would key the cross-scope ledger on a reversible/identity field (D6c)", kt.Field(i).Name)
			}
		}
	}
}

// The two key-derivation paths must agree (Record via coarseKeyFromExport, ClearWithLedger
// via coarseKeyFromPayload(clearFields)), and the int bands must survive the
// payload round-trip (copyScalar emits int64 for an int field — coarseKeyFromPayload must
// read it, not zero it). A mismatch would silently break k (Record one cell, gate another).
func TestCoarseKeyTwoPathsAgreeAndPreserveBands(t *testing.T) {
	for _, e := range []referenceExport{
		{ReachedContain: true, EngagedVelocity: true, EngagedPoison: true, DisengagedEarly: true, HeldBand: 3, CadenceBand: 2, PoisonClass: "credential"},
		{}, // all-zero
		{EngagedPoison: true, HeldBand: 1, CadenceBand: 0, PoisonClass: "success"},
	} {
		kx, err := coarseKeyFromExport(e)
		if err != nil {
			t.Fatal(err)
		}
		p, err := clearFields(e)
		if err != nil {
			t.Fatal(err)
		}
		if kp := coarseKeyFromPayload(p); kx != kp {
			t.Fatalf("two-path key mismatch:\n export-path %+v\n payload-path %+v", kx, kp)
		}
	}
	// Pin the band-survival explicitly (the int64 mishandle would zero these).
	k, _ := coarseKeyFromExport(referenceExport{ReachedContain: true, EngagedVelocity: true, HeldBand: 3, CadenceBand: 2, PoisonClass: "credential"})
	want := coarseKey{ReachedContain: true, EngagedVelocity: true, HeldBand: 3, CadenceBand: 2, PoisonClass: "credential"}
	if k != want {
		t.Fatalf("coarseKey = %+v, want %+v (HeldBand/CadenceBand must survive copyScalar's int64)", k, want)
	}
}

// RecordForm must fail closed on an UNCLEARABLE export — record nothing, return an error,
// and leave every cell at 0 (a bogus pattern cannot seed the ledger).
func TestRecordFormRejectsUnclearable(t *testing.T) {
	l, _ := NewLedger()
	type bad struct {
		Secret string `egress:"safe,free string, not a registered enum"`
	}
	n, err := l.RecordForm("a", bad{Secret: "x"})
	if err == nil || n != 0 {
		t.Fatalf("RecordForm(unclearable) = (%d, %v), want (0, error)", n, err)
	}
}

// A nil ledger (NewLedger CSPRNG failure + a dropped error) fails closed, never panics.
func TestNilLedgerFailsClosed(t *testing.T) {
	var l *Ledger
	if n, err := l.RecordForm("a", refExport()); err == nil || n != 0 {
		t.Fatalf("nil-ledger RecordForm = (%d, %v), want (0, error)", n, err)
	}
	if got := l.distinctScopes(coarseKey{}); got != 0 {
		t.Fatalf("nil-ledger distinctScopes = %d, want 0", got)
	}
}

// coarseKeyFromExportT is a test helper: derive the key or fail the test.
func coarseKeyFromExportT(t *testing.T, export any) coarseKey {
	t.Helper()
	k, err := coarseKeyFromExport(export)
	if err != nil {
		t.Fatalf("coarseKeyFromExport: %v", err)
	}
	return k
}
