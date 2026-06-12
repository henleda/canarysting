package sharpen

import (
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
)

var base = time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

func mkEvents(scope string, cookie uint64, types []string, axes contract.AttritionAxis) []intelligence.AdversaryInteractionEvent {
	var evs []intelligence.AdversaryInteractionEvent
	for i, t := range types {
		evs = append(evs, intelligence.AdversaryInteractionEvent{
			ScopeKey:   scope,
			FlowID:     cookie,
			CanaryType: t,
			Tier:       2,
			Timestamp:  base.Add(time.Duration(i) * time.Second),
			Sting:      intelligence.StingOutcome{Axes: uint32(axes)},
		})
	}
	return evs
}

// fakeSource returns a scope's events (ignoring the time window — the test events are
// all in-window) and counts queries so a test can assert the hot-path short-circuit.
type fakeSource struct {
	byScope map[string][]intelligence.AdversaryInteractionEvent
	queries int
}

func (f *fakeSource) Query(scope string, _, _ time.Time) ([]intelligence.AdversaryInteractionEvent, error) {
	f.queries++
	return f.byScope[scope], nil
}

func storeWith(scope string, flows map[uint64][]string, axes contract.AttritionAxis) (*Store, *fakeSource) {
	src := &fakeSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{}}
	for c, types := range flows {
		src.byScope[scope] = append(src.byScope[scope], mkEvents(scope, c, types, axes)...)
	}
	return NewStore(src), src
}

func TestMatchColdScopeNoFetch(t *testing.T) {
	// No confirmed-malicious profiles => Match returns 0 WITHOUT touching the event
	// source (the hot-path short-circuit — the common case).
	src := &fakeSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{}}
	s := NewStore(src)
	if got := s.Match("s", contract.FlowIdentity{SocketCookie: 1}, base); got != 0 {
		t.Fatalf("cold-scope Match = %v, want 0", got)
	}
	if src.queries != 0 {
		t.Fatalf("cold-scope Match must not fetch events, but queried %d times", src.queries)
	}
}

func TestRecordJailThenMatch(t *testing.T) {
	scope := contract.ScopeKey("s")
	types := []string{".env", "backup/db.sql"}
	axes := contract.AxisVelocity | contract.AxisPoison
	// 3 distinct jailed flows + an emerging flow (4), all the SAME behavior.
	s, _ := storeWith(string(scope), map[uint64][]string{1: types, 2: types, 3: types, 4: types}, axes)
	for _, c := range []uint64{1, 2, 3} {
		s.RecordJail(scope, contract.FlowIdentity{SocketCookie: c}, base)
	}
	if got := s.Match(scope, contract.FlowIdentity{SocketCookie: 4}, base); got < 0.999 {
		t.Fatalf("a flow matching 3 confirmed-jailed behaviors should match ~1.0, got %v", got)
	}
}

func TestMatchUnderJailFloor(t *testing.T) {
	scope := contract.ScopeKey("s")
	types := []string{".env"}
	s, _ := storeWith(string(scope), map[uint64][]string{1: types, 2: types, 4: types}, contract.AxisVelocity)
	for _, c := range []uint64{1, 2} { // only 2 distinct jailed flows < MinConfirmedJails
		s.RecordJail(scope, contract.FlowIdentity{SocketCookie: c}, base)
	}
	if got := s.Match(scope, contract.FlowIdentity{SocketCookie: 4}, base); got != 0 {
		t.Fatalf("under the %d-jail floor Match must be 0, got %v", MinConfirmedJails, got)
	}
}

func TestRecordJailCountsDistinctFlows(t *testing.T) {
	// One flow jailed repeatedly is ONE distinct flow — it must not, by itself, cross
	// the floor (so a single persistent actor cannot self-sharpen the scope).
	scope := contract.ScopeKey("s")
	types := []string{".env"}
	s, _ := storeWith(string(scope), map[uint64][]string{1: types, 4: types}, contract.AxisVelocity)
	for i := 0; i < MinConfirmedJails+2; i++ {
		s.RecordJail(scope, contract.FlowIdentity{SocketCookie: 1}, base.Add(time.Duration(i)*time.Minute))
	}
	if got := s.Match(scope, contract.FlowIdentity{SocketCookie: 4}, base); got != 0 {
		t.Fatalf("one flow jailed %dx is 1 distinct flow; Match must be 0, got %v", MinConfirmedJails+2, got)
	}
}

func TestMatchFreshness(t *testing.T) {
	scope := contract.ScopeKey("s")
	types := []string{".env", "x"}
	s, _ := storeWith(string(scope), map[uint64][]string{1: types, 2: types, 3: types, 4: types}, contract.AxisPoison)
	for _, c := range []uint64{1, 2, 3} {
		s.RecordJail(scope, contract.FlowIdentity{SocketCookie: c}, base)
	}
	if got := s.Match(scope, contract.FlowIdentity{SocketCookie: 4}, base); got < 0.999 {
		t.Fatalf("fresh match should be ~1.0, got %v", got) // sanity
	}
	stale := base.Add(FreshnessWindow + time.Hour)
	if got := s.Match(scope, contract.FlowIdentity{SocketCookie: 4}, stale); got != 0 {
		t.Fatalf("a confirmed behavior past the freshness window must not match, got %v", got)
	}
}

func TestMatchScopeIsolation(t *testing.T) {
	// Confirmed-malicious in scope A must NOT match a flow in scope B (rule 5).
	types := []string{".env"}
	s, _ := storeWith("scope-a", map[uint64][]string{1: types, 2: types, 3: types}, contract.AxisVelocity)
	for _, c := range []uint64{1, 2, 3} {
		s.RecordJail("scope-a", contract.FlowIdentity{SocketCookie: c}, base)
	}
	if got := s.Match("scope-b", contract.FlowIdentity{SocketCookie: 1}, base); got != 0 {
		t.Fatalf("cross-scope match leaked: scope-b flow matched scope-a's confirmed set (%v)", got)
	}
}

func TestMatchFuzzyBounded(t *testing.T) {
	scope := contract.ScopeKey("s")
	confirmed := []string{".env", "backup/db.sql"}
	emerging := []string{".env", "admin/metrics"} // partial overlap, different behavior
	src := &fakeSource{byScope: map[string][]intelligence.AdversaryInteractionEvent{}}
	for _, c := range []uint64{1, 2, 3} {
		src.byScope[string(scope)] = append(src.byScope[string(scope)], mkEvents(string(scope), c, confirmed, contract.AxisVelocity|contract.AxisPoison)...)
	}
	src.byScope[string(scope)] = append(src.byScope[string(scope)], mkEvents(string(scope), 4, emerging, contract.AxisVelocity)...)
	s := NewStore(src)
	for _, c := range []uint64{1, 2, 3} {
		s.RecordJail(scope, contract.FlowIdentity{SocketCookie: c}, base)
	}
	got := s.Match(scope, contract.FlowIdentity{SocketCookie: 4}, base)
	if got <= 0 || got >= 1 {
		t.Fatalf("a partially-similar emerging flow should score in (0,1), got %v", got)
	}
}
