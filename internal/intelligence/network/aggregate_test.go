package network

import (
	"reflect"
	"strings"
	"testing"
)

// The external feed floors at FeedK (>= aggregationK): a cell below FeedK distinct scopes
// is never eligible, and a caller cannot lower the floor.
func TestAggregatedFloorsAtFeedK(t *testing.T) {
	l, _ := NewLedger()
	exp := refExport()
	for _, s := range []string{"a", "b", "c", "d"} { // 4 < FeedK
		if _, err := l.RecordForm(s, exp); err != nil {
			t.Fatal(err)
		}
	}
	if got := l.Aggregated(FeedK); len(got) != 0 {
		t.Fatalf("a cell at k=4 (< FeedK=%d) must not appear, got %d", FeedK, len(got))
	}
	if got := l.Aggregated(3); len(got) != 0 { // a caller cannot ask below FeedK
		t.Fatalf("Aggregated(3) must be floored to FeedK; a k=4 cell stays excluded, got %d", len(got))
	}
	if _, err := l.RecordForm("e", exp); err != nil { // 5th distinct scope => k=FeedK
		t.Fatal(err)
	}
	if got := l.Aggregated(FeedK); len(got) != 1 {
		t.Fatalf("a cell at k=%d must appear, got %d", FeedK, len(got))
	}
}

func TestAggregatedNilAndEmpty(t *testing.T) {
	var l *Ledger
	if got := l.Aggregated(FeedK); got != nil {
		t.Fatalf("nil ledger => nil, got %v", got)
	}
	l2, _ := NewLedger()
	if got := l2.Aggregated(FeedK); len(got) != 0 {
		t.Fatalf("empty ledger => no patterns, got %d", len(got))
	}
}

func TestAggregatedDeterministic(t *testing.T) {
	l, _ := NewLedger()
	a := referenceExport{ReachedContain: true, EngagedVelocity: true, HeldBand: 1, PoisonClass: "topology", CadenceBand: 0}
	b := a
	b.CadenceBand = 3
	for _, s := range []string{"s1", "s2", "s3", "s4", "s5"} {
		l.RecordForm(s, a)
		l.RecordForm(s, b)
	}
	first, second := l.Aggregated(FeedK), l.Aggregated(FeedK)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Aggregated not deterministic:\n %v\n %v", first, second)
	}
	if len(first) != 2 {
		t.Fatalf("want 2 patterns at k=FeedK, got %d", len(first))
	}
}

// D7a presence-only: an AggregatedPattern must carry NO count/prevalence/scope/identity —
// only the coarse cleared fields.
func TestAggregatedPatternHasNoCountOrIdentity(t *testing.T) {
	rt := reflect.TypeOf(AggregatedPattern{})
	for i := 0; i < rt.NumField(); i++ {
		n := strings.ToLower(rt.Field(i).Name)
		for _, banned := range []string{"count", "prevalence", "scope", "bucket", "hash", "flow", "cookie", "ip", "identity", "seen", "salt"} {
			if strings.Contains(n, banned) {
				t.Fatalf("AggregatedPattern.%s leaks a count/identity into the feed (D7a presence-only)", rt.Field(i).Name)
			}
		}
	}
}
