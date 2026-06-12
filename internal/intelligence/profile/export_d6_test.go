package profile

import (
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/network"
)

func d6ev(reason int, ttdSec, heldSec float64) intelligence.AdversaryInteractionEvent {
	return intelligence.AdversaryInteractionEvent{
		CanaryType: ".env",
		Tier:       3,
		Timestamp:  time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC),
		Sting: intelligence.StingOutcome{
			DisengageReason:    reason,
			TimeToDisengageSec: ttdSec,
			TimeHeldSec:        heldSec,
		},
	}
}

// D6b (the rule-9 SEMANTIC guard the egress filter cannot catch): DisengagedEarly must
// be TRUE only for DisengageReason == DisengageAttacker(1). A generator-exhausted (2) or
// defender-capped (3) session — or an unclassified one (0) — must NEVER set it, EVEN
// when TimeToDisengageSec > 0. Otherwise OUR max-hold cap (reason 3) would cross the
// boundary disguised as "the attacker gave up," corrupting the cross-customer signal —
// and it would pass every field-name/kind test in network.Clear. derive.go is the sole
// guard; this pins it so a refactor cannot loosen it.
func TestDisengagedEarlyOnlyForAttacker(t *testing.T) {
	for _, reason := range []int{
		contract.DisengageUnknown,        // 0
		contract.DisengageGeneratorDone,  // 2
		contract.DisengageDefenderCapped, // 3
	} {
		// TimeToDisengageSec deliberately > 0 to prove the bool keys on the REASON, not
		// on the presence of a disengage time.
		p := DeriveProfile([]intelligence.AdversaryInteractionEvent{d6ev(reason, 12.5, 40)})
		if p == nil {
			t.Fatalf("reason %d: nil profile", reason)
		}
		if p.DisengagedEarly {
			t.Fatalf("DisengageReason=%d set DisengagedEarly=true (a defender/generator end mislabeled as an attacker disengage — D6b leak)", reason)
		}
		if ef := p.ToExportForm(); ef.DisengagedEarly {
			t.Fatalf("DisengageReason=%d exported DisengagedEarly=true (D6b semantic leak)", reason)
		}
	}
	// The positive case: a genuine attacker disengage DOES set it.
	p := DeriveProfile([]intelligence.AdversaryInteractionEvent{d6ev(contract.DisengageAttacker, 8, 20)})
	if p == nil || !p.DisengagedEarly {
		t.Fatal("DisengageAttacker(1) must set DisengagedEarly=true (the engagement signal)")
	}
}

// CadenceBand (D6a) is exported as the 0..3 band of the median inter-arrival, never the
// raw seconds. Two events 0.5s apart => sub-5s band 0 (tight automation).
func TestExportFormCarriesCadenceBand(t *testing.T) {
	base := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	fast := DeriveProfile([]intelligence.AdversaryInteractionEvent{
		{CanaryType: ".env", Timestamp: base},
		{CanaryType: "x", Timestamp: base.Add(500 * time.Millisecond)},
	})
	if got := fast.ToExportForm().CadenceBand; got != cadenceBand(fast.CadenceSec) || got != 0 {
		t.Fatalf("fast-cadence export CadenceBand = %d, want 0 (sub-5s automation)", got)
	}
	// A slower, human-paced cadence lands in a higher band.
	slow := DeriveProfile([]intelligence.AdversaryInteractionEvent{
		{CanaryType: ".env", Timestamp: base},
		{CanaryType: "x", Timestamp: base.Add(200 * time.Second)},
	})
	if got := slow.ToExportForm().CadenceBand; got != 3 {
		t.Fatalf("slow-cadence export CadenceBand = %d, want 3 (human-paced)", got)
	}
}

// End-to-end: the REAL producer shape (a derived Profile -> Candidate) crosses ONLY when
// the cross-scope ledger reaches k>=3 for that exact coarse pattern, and the resulting
// carrier Marshals. Proves profile + network integrate as designed (Contribute opt-in,
// no producer-asserted count, ledger-driven k, ledger-verified carrier).
func TestProfileCrossesOnlyViaLedgerAtK(t *testing.T) {
	base := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	mk := func() *Profile {
		return DeriveProfile([]intelligence.AdversaryInteractionEvent{
			{CanaryType: ".env", Tier: 3, Timestamp: base, Sting: intelligence.StingOutcome{
				Axes: uint32(contract.AxisVelocity | contract.AxisPoison), TimeHeldSec: 10,
				PoisonReached: 2, PoisonClass: "topology", DisengageReason: contract.DisengageAttacker, TimeToDisengageSec: 5,
			}},
			{CanaryType: "backup/db.sql", Tier: 3, Timestamp: base.Add(time.Second), Sting: intelligence.StingOutcome{
				Axes: uint32(contract.AxisVelocity), TimeHeldSec: 8,
			}},
		})
	}
	prof := mk()
	cand := prof.Candidate(network.ContributionContext{Contribute: true}) // no producer count
	l, err := network.NewLedger()
	if err != nil {
		t.Fatal(err)
	}
	export, _ := cand.EgressFields()

	// Below k: denied.
	if _, err := l.RecordForm("scope-1", export); err != nil {
		t.Fatal(err)
	}
	if _, err := network.ClearWithLedger(cand, network.ClearContext{Ledger: l}); err == nil {
		t.Fatal("a pattern seen in 1 scope must be denied (sub-k)")
	}
	// Two more distinct scopes independently exhibit the SAME coarse pattern -> k=3.
	for _, s := range []string{"scope-2", "scope-3"} {
		if _, err := l.RecordForm(s, export); err != nil {
			t.Fatal(err)
		}
	}
	c, err := network.ClearWithLedger(cand, network.ClearContext{Ledger: l})
	if err != nil || c == nil {
		t.Fatalf("a profile pattern at k=3 must cross: %v", err)
	}
	if _, err := c.Marshal(); err != nil {
		t.Fatalf("the ledger-verified carrier must Marshal: %v", err)
	}
}
