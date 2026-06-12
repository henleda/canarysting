package network

import "testing"

func enrolledSet(tokens ...string) func(string) bool {
	m := map[string]struct{}{}
	for _, t := range tokens {
		m[t] = struct{}{}
	}
	return func(t string) bool { _, ok := m[t]; return ok }
}

func demoShared() SharedPattern {
	return SharedPattern{
		ReachedContain: true, EngagedVelocity: true, EngagedPoison: true,
		HeldBand: 2, DisengagedEarly: true, PoisonClass: "topology", CadenceBand: 1,
	}
}

// crosses reports whether the aggregator can now clear+send sp (k>=aggregationK).
func crosses(t *testing.T, l *Ledger, sp SharedPattern) bool {
	t.Helper()
	_, err := ClearWithLedger(SharedCandidate(sp), ClearContext{Ledger: l})
	return err == nil
}

// Three DISTINCT ENROLLED tokens confirming the same coarse pattern reach k=3 and the
// pattern crosses; two do not. This is the live A→B crossing the aggregator enables.
func TestIngestCountsDistinctEnrolledTokens(t *testing.T) {
	l, err := NewAggregatorLedger(enrolledSet("tok-a", "tok-b", "tok-c"))
	if err != nil {
		t.Fatal(err)
	}
	sp := demoShared()
	if _, err := l.IngestConfirmation("tok-a", sp); err != nil {
		t.Fatal(err)
	}
	if _, err := l.IngestConfirmation("tok-b", sp); err != nil {
		t.Fatal(err)
	}
	if crosses(t, l, sp) {
		t.Fatal("k=2 < 3 must NOT cross")
	}
	if _, err := l.IngestConfirmation("tok-c", sp); err != nil {
		t.Fatal(err)
	}
	if !crosses(t, l, sp) {
		t.Fatal("k=3 distinct enrolled tokens must cross")
	}
}

// THE k-provenance guard (D63e): an un-enrolled / forged token is REJECTED and never
// counted, so a single enrolled box padding with forged tokens can NEVER fabricate k=3.
func TestIngestRejectsUnenrolledTokens(t *testing.T) {
	l, _ := NewAggregatorLedger(enrolledSet("tok-a")) // only ONE real enrolled scope
	sp := demoShared()
	if _, err := l.IngestConfirmation("tok-a", sp); err != nil {
		t.Fatal(err)
	}
	for _, forged := range []string{"forged-1", "forged-2", ""} {
		if _, err := l.IngestConfirmation(forged, sp); err == nil {
			t.Fatalf("un-enrolled token %q must be rejected", forged)
		}
	}
	if crosses(t, l, sp) {
		t.Fatal("1 enrolled + forged tokens must stay k=1 — the gaming attack must be bounded")
	}
}

// One enrolled token confirming repeatedly is ONE distinct scope (idempotent) — it cannot
// self-inflate to k.
func TestIngestIdempotentPerToken(t *testing.T) {
	l, _ := NewAggregatorLedger(enrolledSet("tok-a", "tok-b", "tok-c"))
	sp := demoShared()
	for i := 0; i < 5; i++ {
		l.IngestConfirmation("tok-a", sp)
	}
	if crosses(t, l, sp) {
		t.Fatal("one token confirming 5x is k=1; must not cross")
	}
}

// IngestConfirmation requires an aggregator ledger (the enrollment check is a constructor
// dependency, not optional) — a plain NewLedger cannot ingest cross-scope confirmations.
func TestIngestRequiresAggregatorLedger(t *testing.T) {
	l, _ := NewLedger() // no enrollment
	if _, err := l.IngestConfirmation("tok-a", demoShared()); err == nil {
		t.Fatal("a non-aggregator ledger must reject IngestConfirmation")
	}
	if _, err := NewAggregatorLedger(nil); err == nil {
		t.Fatal("NewAggregatorLedger(nil) must error — an aggregator needs an enrollment check")
	}
}

// Re-entry parity: the SAME pattern recorded via IngestConfirmation (the count) and cleared
// via SharedCandidate (the egress key) must agree — distinct patterns must NOT collide into
// one cell. A second, DIFFERENT pattern at k=2 stays sub-k even while the first is at k=3.
func TestIngestReEntryKeyParity(t *testing.T) {
	l, _ := NewAggregatorLedger(enrolledSet("a", "b", "c"))
	x := demoShared()
	y := x
	y.CadenceBand = 3 // a different coarse cell
	for _, tok := range []string{"a", "b", "c"} {
		l.IngestConfirmation(tok, x)
	}
	for _, tok := range []string{"a", "b"} {
		l.IngestConfirmation(tok, y)
	}
	if !crosses(t, l, x) {
		t.Fatal("x at k=3 must cross")
	}
	if crosses(t, l, y) {
		t.Fatal("y (different cell) at k=2 must NOT cross — patterns must not collide into one count")
	}
}
