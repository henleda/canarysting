package network

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/cost"
)

// cand wraps an export struct with a (by default clearable) contribution context.
type cand struct {
	export any
	ctx    ContributionContext
}

func (c cand) EgressFields() (any, ContributionContext) { return c.export, c.ctx }

func okCtx() ContributionContext {
	return ContributionContext{Contribute: true, SeenInScopes: aggregationK}
}
func mk(export any) Candidate { return cand{export: export, ctx: okCtx()} }

// mustDeny asserts Clear rejects the candidate (nil *Cleared + non-nil error).
func mustDeny(t *testing.T, name string, c Candidate) {
	t.Helper()
	got, err := Clear(c)
	if err == nil || got != nil {
		t.Fatalf("%s: expected DENY, got (%v, err=%v)", name, got, err)
	}
}

// --- 1 / 13: happy path ---

func TestClearHappyPath(t *testing.T) {
	c, err := Clear(ReferenceCandidate())
	if err != nil || c == nil {
		t.Fatalf("reference candidate must clear: %v", err)
	}
	if len(c.Fields()) != 7 {
		t.Fatalf("cleared %d fields, want 7: %v", len(c.Fields()), c.Fields())
	}
	// A form-only Clear() carrier is NOT transmittable (D6d): it has no ledger-backed
	// k-anonymity provenance.
	if _, err := c.Marshal(); err == nil {
		t.Fatal("form-only Clear() carrier must not Marshal (not ledger-verified)")
	}
}

// The real crossing path: ClearWithLedger over a ledger driven to k>=3 produces a
// ledger-verified, Marshalable carrier that round-trips the 7 coarse fields.
func TestClearWithLedgerHappyPath(t *testing.T) {
	l, err := NewLedger()
	if err != nil {
		t.Fatal(err)
	}
	export, _ := ReferenceCandidate().EgressFields()
	for _, scope := range []string{"scope-a", "scope-b", "scope-c"} {
		if _, err := l.RecordForm(scope, export); err != nil {
			t.Fatalf("RecordForm(%s): %v", scope, err)
		}
	}
	// The producer asserts NO count (tripwire): Contribute only, SeenInScopes 0.
	c, err := ClearWithLedger(cand{export: export, ctx: ContributionContext{Contribute: true}}, ClearContext{Ledger: l})
	if err != nil || c == nil {
		t.Fatalf("k>=3 pattern must clear via the ledger: %v", err)
	}
	b, err := c.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var round map[string]any
	if json.Unmarshal(b, &round) != nil || len(round) != 7 {
		t.Fatalf("marshalled payload did not round-trip 7 fields: %s", b)
	}
}

// --- 2 / 3: default-deny + new-field-drops (the load-bearing property) ---

func TestUntaggedFieldDenied(t *testing.T) {
	type x struct {
		ReachedContain bool `egress:"safe,coarse tier bucket"`
		Extra          int  // UNTAGGED — a new field nobody justified
	}
	mustDeny(t, "untagged field", mk(x{ReachedContain: true, Extra: 1}))
}

// --- 4: kind allowlist with default-deny, not a denylist ---

func TestNonAllowlistedKindsDenied(t *testing.T) {
	cases := map[string]any{
		"slice": struct {
			B []int `egress:"safe,r"`
		}{},
		"map": struct {
			B map[string]int `egress:"safe,r"`
		}{},
		"ptr": struct {
			B *int `egress:"safe,r"`
		}{},
		"any": struct {
			B any `egress:"safe,r"`
		}{},
		"freestr": struct {
			Note string `egress:"safe,r"`
		}{Note: "anything"}, // name not a registered enum
		"badenumval": struct {
			PoisonClass string `egress:"safe,r"`
		}{PoisonClass: "not-a-stage"},
	}
	for name, exp := range cases {
		mustDeny(t, name, mk(exp))
	}
}

// --- 5: recursive walk denies a raw/identity field nested in a struct, and time.Time ---

func TestRecursiveWalkAndTime(t *testing.T) {
	type inner struct {
		ScopeKey string `egress:"safe,r"` // identity name hiding one level down
	}
	type outer struct {
		Reached bool `egress:"safe,coarse"`
		Inner   inner
	}
	mustDeny(t, "nested identity field", mk(outer{Inner: inner{ScopeKey: "cust-a"}}))

	type withTime struct {
		Reached bool      `egress:"safe,coarse"`
		Seen    time.Time `egress:"safe,r"`
	}
	mustDeny(t, "time.Time field", mk(withTime{}))
}

// --- 6: identity / semantic name denylist ---

func TestIdentityNamesDenied(t *testing.T) {
	mustDeny(t, "IP", mk(struct {
		IP int `egress:"safe,r"`
	}{}))
	mustDeny(t, "FlowID", mk(struct {
		FlowID uint64 `egress:"safe,r"`
	}{}))
	mustDeny(t, "ScopeKey", mk(struct {
		ScopeKey int `egress:"safe,r"`
	}{}))
	mustDeny(t, "Cadence(features)", mk(struct {
		Features int `egress:"safe,r"`
	}{}))
	mustDeny(t, "BehavioralHash (D9)", mk(struct {
		BehavioralHash uint64 `egress:"safe,r"`
	}{}))
}

// --- 7: AX4/AX5 never cross (by name AND by marker) ---

func TestAX4AX5NeverCross(t *testing.T) {
	// By name — even if (wrongly) tagged safe.
	mustDeny(t, "ExploitsObserved", mk(struct {
		ExploitsObserved int64 `egress:"safe,r"`
	}{ExploitsObserved: 3}))
	mustDeny(t, "ExposureSignals", mk(struct {
		ExposureSignals int64 `egress:"safe,r"`
	}{ExposureSignals: 2}))
	// A RENAMED same-valued field still caught by the *exploit* / *exposure* substring.
	mustDeny(t, "renamed exploit", mk(struct {
		ExploitBurnCount int64 `egress:"safe,r"`
	}{}))
	// The blocked marker hard-denies regardless of a safe-looking sibling.
	mustDeny(t, "blocked marker", mk(struct {
		Reached bool  `egress:"safe,coarse"`
		Raw     int64 `egress:"blocked,ax4-exploits"`
	}{Reached: true}))
}

// --- 8: candidate-type denylist (scope-local / raw / engine state) ---

func TestCandidateTypeDenylist(t *testing.T) {
	mustDeny(t, "cost.Summary", mk(cost.Summary{}))
	mustDeny(t, "intelligence.StingOutcome", mk(intelligence.StingOutcome{}))
	mustDeny(t, "intelligence.AdversaryInteractionEvent", mk(intelligence.AdversaryInteractionEvent{}))
	// Embedding a denylisted type must not launder it.
	type wrap struct {
		cost.Summary
		Reached bool `egress:"safe,coarse"`
	}
	mustDeny(t, "embedded cost.Summary", mk(wrap{}))
}

// --- 9 / 10: opt-in + k-anonymity ---

func TestOptInAndKAnonymity(t *testing.T) {
	valid := referenceExport{ReachedContain: true, PoisonClass: ""}
	mustDeny(t, "not opted in", cand{export: valid, ctx: ContributionContext{Contribute: false, SeenInScopes: aggregationK}})
	mustDeny(t, "sub-k", cand{export: valid, ctx: ContributionContext{Contribute: true, SeenInScopes: aggregationK - 1}})
	mustDeny(t, "zero-value ctx", cand{export: valid, ctx: ContributionContext{}})

	// D5: there is NO producer-supplied k field to invert the gate.
	if _, ok := reflect.TypeOf(ContributionContext{}).FieldByName("AggregationK"); ok {
		t.Fatal("ContributionContext must NOT expose a producer-supplied AggregationK (D5)")
	}
}

// --- 11: the carrier's serialization is itself gated (D3) ---

func TestCarrierSerializationGated(t *testing.T) {
	// A Cleared whose payload was somehow seeded with a non-scalar must fail Marshal —
	// the carrier is part of the chokepoint, not a second egress surface. ledgerVerified
	// is set so the carrier-breach (scalar) check is what rejects it, not the form-only
	// gate.
	bad := &Cleared{payload: map[string]any{"leak": []byte("raw")}, ledgerVerified: true}
	if _, err := bad.Marshal(); err == nil {
		t.Fatal("Marshal must reject a non-scalar payload entry (carrier breach)")
	}
	ptr := 7
	bad2 := &Cleared{payload: map[string]any{"leak": &ptr}, ledgerVerified: true}
	if _, err := bad2.Marshal(); err == nil {
		t.Fatal("Marshal must reject a pointer payload entry")
	}
}

// --- 14 / 15: single chokepoint + surface reflection guard ---

func TestSingleChokepointSurface(t *testing.T) {
	// Cleared has only unexported fields (no external literal can construct one): the
	// single-chokepoint invariant is type-enforced. Assert via reflection.
	ct := reflect.TypeOf(Cleared{})
	for i := 0; i < ct.NumField(); i++ {
		if ct.Field(i).PkgPath == "" {
			t.Fatalf("Cleared.%s is EXPORTED — a second construction path defeats the chokepoint", ct.Field(i).Name)
		}
	}
	// Surface guard: every exported field of the reference export is in the safe-kind
	// allowlist or a registered enum string (mirrors TestDriverObservationCarriesNoRawData).
	rt := reflect.TypeOf(referenceExport{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Type.Kind() == reflect.String {
			if _, ok := enumValues[strings.ToLower(f.Name)]; !ok {
				t.Fatalf("reference export string field %s is not a registered enum", f.Name)
			}
			continue
		}
		if !safeKind(f.Type.Kind()) {
			t.Fatalf("reference export field %s has non-allowlisted kind %s", f.Name, f.Type.Kind())
		}
		// Every numeric reference field must declare a coarse band (D1 [leak-review]).
		if isBandedKind(f.Type.Kind()) {
			if _, _, ok := parseBand(f.Tag); !ok {
				t.Fatalf("reference export numeric field %s must declare a coarse band=LO..HI", f.Name)
			}
		}
	}
}

// --- coarseness: scalar kind is not coarseness (the leak-review's constructed leak) ---

func TestNumericMustDeclareCoarseBand(t *testing.T) {
	// int with no band clause -> deny (cannot prove it is coarse).
	mustDeny(t, "int no band", mk(struct {
		Bucket int `egress:"safe,coarse but no band"`
	}{Bucket: 1}))
	// raw value outside its declared band -> deny (the disguised-second-count leak).
	mustDeny(t, "value out of band", mk(struct {
		HeldBand int64 `egress:"safe,band=0..3,r"`
	}{HeldBand: 987654}))
	// band span too wide -> deny (a producer cannot declare band=0..1e6 to launder a count).
	mustDeny(t, "band too wide", mk(struct {
		Count int64 `egress:"safe,band=0..1000000,r"`
	}{Count: 5}))
	// raw byte-count out of a plausible small band -> deny.
	mustDeny(t, "byte count", mk(struct {
		TreeBytes int64 `egress:"safe,band=0..3,r"`
	}{TreeBytes: 8054}))
	// float denied outright (continuous => singling-out; the RTT leak).
	mustDeny(t, "float denied", mk(struct {
		Cadence float64 `egress:"safe,band=0..1,r"`
	}{Cadence: 0.0034219}))
	// a genuinely coarse, in-range band clears.
	if c, err := Clear(mk(struct {
		Bucket int `egress:"safe,band=0..3,coarse percentile bucket"`
	}{Bucket: 2})); err != nil || c == nil {
		t.Fatalf("a valid coarse band must clear: %v", err)
	}
}

func TestExpandedIdentityNamesDenied(t *testing.T) {
	// Network / org / location quasi-identifiers must be denied even with a valid band.
	mustDeny(t, "Region", mk(struct {
		Region int `egress:"safe,band=0..3,r"`
	}{Region: 1}))
	mustDeny(t, "Asn", mk(struct {
		Asn int `egress:"safe,band=0..3,r"`
	}{Asn: 1}))
	mustDeny(t, "Tenant", mk(struct {
		Tenant int `egress:"safe,band=0..3,r"`
	}{}))
	mustDeny(t, "ClusterID", mk(struct {
		ClusterID int `egress:"safe,band=0..3,r"`
	}{}))
	mustDeny(t, "URL", mk(struct {
		URL int `egress:"safe,band=0..3,r"`
	}{}))
}
