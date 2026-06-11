package profile

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/network"
)

var base = time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

func ev(flowID uint64, scope, canary string, tier, offsetSec int, sting intelligence.StingOutcome) intelligence.AdversaryInteractionEvent {
	return intelligence.AdversaryInteractionEvent{
		ScopeKey:   scope,
		FlowID:     flowID,
		CanaryType: canary,
		Tier:       tier,
		Timestamp:  base.Add(time.Duration(offsetSec) * time.Second),
		Sting:      sting,
	}
}

func TestDeriveProfileEmpty(t *testing.T) {
	if DeriveProfile(nil) != nil {
		t.Fatal("empty events must yield a nil profile")
	}
}

func TestDeriveProfileDeterministic(t *testing.T) {
	mk := func() *Profile {
		return DeriveProfile([]intelligence.AdversaryInteractionEvent{
			ev(0x1, "s", ".env", 1, 0, intelligence.StingOutcome{}),
			ev(0x1, "s", ".aws/credentials", 2, 12, intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity | contract.AxisPoison), TimeHeldSec: 8, PoisonReached: 2, PoisonClass: "topology"}),
		})
	}
	a, b := mk(), mk()
	if a.BehavioralHash != b.BehavioralHash || !reflect.DeepEqual(a, b) {
		t.Fatal("DeriveProfile is not deterministic for identical events")
	}
}

func TestBehavioralHashIgnoresIdentity(t *testing.T) {
	// Same behavior, DIFFERENT FlowID + ScopeKey => the SAME BehavioralHash. The hash
	// must key on behavior only, never identity.
	mk := func(flow uint64, scope string) *Profile {
		return DeriveProfile([]intelligence.AdversaryInteractionEvent{
			ev(flow, scope, ".env", 2, 0, intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity), TimeHeldSec: 5}),
			ev(flow, scope, "backup/db.sql", 2, 30, intelligence.StingOutcome{Axes: uint32(contract.AxisPoison), TimeHeldSec: 5, PoisonReached: 1, PoisonClass: "credential"}),
		})
	}
	if mk(0x1, "scope-a").BehavioralHash != mk(0x999, "scope-b").BehavioralHash {
		t.Fatal("BehavioralHash depends on FlowID/ScopeKey — it must key on behavior only (rule 9)")
	}
}

func TestProfileAndExportCarryNoIdentity(t *testing.T) {
	// Reflection guard (mirrors TestDriverObservationCarriesNoRawData): neither Profile
	// NOR ExportForm may carry a raw IDENTIFIER field. Note: bare "identity" is NOT a
	// token here — IdentityNov / AdjacencyNov are derived NOVELTY SCORES (scoring
	// context, 0..1), not identifiers; the actual cross-boundary identity guard is
	// network.Clear's name-denylist, exercised by TestExportFormIsClearable.
	bad := []string{"scopekey", "flowid", "flow_id", "cookie", "ipaddr", "host", "spiffe", "socketcookie", "cgroup"}
	for _, typ := range []reflect.Type{reflect.TypeOf(Profile{}), reflect.TypeOf(ExportForm{})} {
		for i := 0; i < typ.NumField(); i++ {
			n := strings.ToLower(typ.Field(i).Name)
			for _, b := range bad {
				if strings.Contains(n, b) {
					t.Fatalf("%s.%s is an identity-named field", typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
}

func TestExportFormIsClearable(t *testing.T) {
	p := DeriveProfile([]intelligence.AdversaryInteractionEvent{
		ev(0x1, "s", ".env", 2, 0, intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity | contract.AxisPoison), TimeHeldSec: 8, PoisonReached: 2, PoisonClass: "topology", DisengageReason: contract.DisengageAttacker, TimeToDisengageSec: 6}),
	})
	if err := ValidateProfileForSharing(p); err != nil {
		t.Fatalf("a coarse profile's ExportForm must pass the egress filter: %v", err)
	}
	c, err := network.Clear(p.Candidate(network.ContributionContext{Contribute: true, SeenInScopes: 9999}))
	if err != nil || c == nil {
		t.Fatalf("network.Clear rejected a coarse profile's candidate: %v", err)
	}
}

func TestExportOmitsLocalOnlySignals(t *testing.T) {
	// ExploitsObserved/ExposureSignals are deployment-local-only — they must NOT be
	// fields on ExportForm (structurally absent => can never cross).
	et := reflect.TypeOf(ExportForm{})
	for i := 0; i < et.NumField(); i++ {
		n := strings.ToLower(et.Field(i).Name)
		if strings.Contains(n, "exploit") || strings.Contains(n, "exposure") {
			t.Fatalf("ExportForm.%s leaks a deployment-local-only signal", et.Field(i).Name)
		}
	}
}

func TestDisengagedEarlyOnlyAttacker(t *testing.T) {
	// D2-2 (the subtle leak the review flagged): DisengagedEarly is TRUE only for
	// DisengageAttacker; a generator-exhausted / defender-capped / unknown session must
	// never set it (else a defender cap reads as "the attacker gave up").
	atk := DeriveProfile([]intelligence.AdversaryInteractionEvent{ev(0x1, "s", ".env", 2, 0, intelligence.StingOutcome{TimeHeldSec: 3, DisengageReason: contract.DisengageAttacker, TimeToDisengageSec: 3})})
	if !atk.DisengagedEarly || atk.TimeToDisengageSec != 3 {
		t.Fatal("attacker disengage was not recorded")
	}
	for _, r := range []int{contract.DisengageDefenderCapped, contract.DisengageGeneratorDone, contract.DisengageUnknown} {
		p := DeriveProfile([]intelligence.AdversaryInteractionEvent{ev(0x1, "s", ".env", 2, 0, intelligence.StingOutcome{TimeHeldSec: 8, DisengageReason: r})})
		if p.DisengagedEarly || p.TimeToDisengageSec != 0 {
			t.Fatalf("DisengageReason %d wrongly set DisengagedEarly — a defender-cap must never look like an attacker disengage", r)
		}
	}
}

func TestPerAxisEngagedFromBitset(t *testing.T) {
	p := DeriveProfile([]intelligence.AdversaryInteractionEvent{ev(0x1, "s", ".env", 3, 0, intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity | contract.AxisOpExposure)})})
	if want := [NumAxes]bool{true, false, false, false, true}; p.AxesEngaged != want {
		t.Fatalf("AxesEngaged = %v, want %v (velocity + opexposure)", p.AxesEngaged, want)
	}
}

func TestDeriveProfileOrderIndependent(t *testing.T) {
	// The determinism guarantee under PERMUTATION (not just a re-run): two events that
	// tie on (timestamp, canary-type) AND reach the same deepest poison stage with
	// DIFFERENT classes must not let input order decide PoisonClass / BehavioralHash.
	e1 := ev(0x1, "s", ".env", 2, 0, intelligence.StingOutcome{Axes: uint32(contract.AxisPoison), TimeHeldSec: 8, PoisonReached: 2, PoisonClass: "topology"})
	e2 := ev(0x1, "s", ".env", 2, 0, intelligence.StingOutcome{Axes: uint32(contract.AxisPoison), TimeHeldSec: 8, PoisonReached: 2, PoisonClass: "credential"})
	a := DeriveProfile([]intelligence.AdversaryInteractionEvent{e1, e2})
	b := DeriveProfile([]intelligence.AdversaryInteractionEvent{e2, e1})
	if a.PoisonClass != b.PoisonClass || a.BehavioralHash != b.BehavioralHash {
		t.Fatalf("DeriveProfile is input-order-dependent: class %q/%q, hash %d/%d", a.PoisonClass, b.PoisonClass, a.BehavioralHash, b.BehavioralHash)
	}
}

func TestSimilaritySelfEmptyTypes(t *testing.T) {
	// A profile with no probe sequence (kernel-enforced / empty CanaryType) must still
	// self-score 1.0 — the invariant D5's MaliciousProfileStore relies on.
	p := DeriveProfile([]intelligence.AdversaryInteractionEvent{ev(0x1, "s", "", 3, 0, intelligence.StingOutcome{})})
	if p == nil || len(p.OrderedTypes) != 0 {
		t.Fatalf("expected a non-nil empty-types profile, got %+v", p)
	}
	if s := p.Similarity(p); s != 1.0 {
		t.Fatalf("self-similarity of an empty-types profile = %v, want 1.0", s)
	}
}

func TestToExportFormClampsPoisonClass(t *testing.T) {
	// An out-of-vocab PoisonClass (a future/malformed value) must coarsen to "" so the
	// candidate still Clears — not silently drop the WHOLE profile at the all-or-nothing
	// gate. Every legitimate class stays itself.
	p := DeriveProfile([]intelligence.AdversaryInteractionEvent{ev(0x1, "s", ".env", 2, 0, intelligence.StingOutcome{PoisonReached: 1, PoisonClass: "service"})})
	if got := p.ToExportForm().PoisonClass; got != "" {
		t.Fatalf("out-of-vocab PoisonClass not clamped: %q", got)
	}
	if err := ValidateProfileForSharing(p); err != nil {
		t.Fatalf("a clamped profile must still pass the egress filter: %v", err)
	}
	for _, c := range []string{"credential", "topology", "success"} {
		if clampPoisonClass(c) != c {
			t.Fatalf("clamp dropped a legitimate class %q", c)
		}
	}
}

func TestExportDropsDecoyTaxonomy(t *testing.T) {
	// D6-1: the decoy-taxonomy probe SEQUENCE (OrderedTypes) must never cross. ExportForm
	// carries no slice / sequence / type-name field.
	et := reflect.TypeOf(ExportForm{})
	for i := 0; i < et.NumField(); i++ {
		f := et.Field(i)
		n := strings.ToLower(f.Name)
		if f.Type.Kind() == reflect.Slice || strings.Contains(n, "ordered") || strings.Contains(n, "types") {
			t.Fatalf("ExportForm.%s may carry the decoy taxonomy/sequence — it must be dropped", f.Name)
		}
	}
}

func TestSimilarityNoMutualAbsenceInflation(t *testing.T) {
	// Two DISTINCT profiles that engaged NO axes and share no probe types must NOT score
	// high just because they agree on what neither did (the both-not-engaged inflation).
	p := DeriveProfile([]intelligence.AdversaryInteractionEvent{ev(0x1, "s", ".env", 1, 0, intelligence.StingOutcome{})})
	q := DeriveProfile([]intelligence.AdversaryInteractionEvent{ev(0x2, "s", "admin/metrics", 1, 0, intelligence.StingOutcome{})})
	if p.BehavioralHash == q.BehavioralHash {
		t.Skip("hashes collided; not the case under test")
	}
	if s := p.Similarity(q); s > 0.2 {
		t.Fatalf("two no-axis, disjoint-type profiles scored %v — mutual absence is inflating similarity", s)
	}
}

func TestSimilarityBounds(t *testing.T) {
	p := DeriveProfile([]intelligence.AdversaryInteractionEvent{
		ev(0x1, "s", ".env", 2, 0, intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity | contract.AxisPoison), TimeHeldSec: 8, PoisonClass: "topology", PoisonReached: 2}),
		ev(0x1, "s", "backup/db.sql", 2, 12, intelligence.StingOutcome{Axes: uint32(contract.AxisPoison), TimeHeldSec: 8}),
	})
	if s := p.Similarity(p); s < 0.999 {
		t.Fatalf("self-similarity = %v, want ~1.0", s)
	}
	q := DeriveProfile([]intelligence.AdversaryInteractionEvent{ev(0x2, "s", "admin/metrics", 1, 0, intelligence.StingOutcome{})})
	s := p.Similarity(q)
	if s < 0 || s > 1 {
		t.Fatalf("similarity out of [0,1]: %v", s)
	}
	if s >= p.Similarity(p) {
		t.Fatalf("a disjoint profile (%v) should be less similar than self", s)
	}
	if p.Similarity(nil) != 0 {
		t.Fatal("similarity to a nil profile must be 0")
	}
}
