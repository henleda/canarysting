package profile

import (
	"fmt"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/network"
)

// ExportForm is the COARSENED, egress-tagged projection of a Profile — the only shape
// of D2 intelligence eligible to cross a deployment boundary, and the producer half of
// the rule-9 cross-boundary path (Profile -> ToExportForm -> network.Clear -> *Cleared).
// Its fields mirror the egress filter's reference candidate EXACTLY (every field is an
// already-coarse scalar / closed-enum string with an egress:"safe,<reason>" tag), so it
// passes network.Clear by construction. It deliberately OMITS the decoy-taxonomy probe
// sequence (leaks placement), the raw Axes bitset (leaks floor config), raw cadence/
// durations (single out), and the AX4/AX5 ExploitsObserved/ExposureSignals (deployment-
// local-only — also hard-blocked by the egress filter's *exploit*/*exposure* denylist).
type ExportForm struct {
	ReachedContain  bool   `egress:"safe,coarse tier bucket (reached T2+); not a raw tier or threshold"`
	EngagedVelocity bool   `egress:"safe,per-axis engaged boolean; not the raw Axes bitset (which leaks floor config)"`
	EngagedPoison   bool   `egress:"safe,per-axis engaged boolean"`
	HeldBand        int    `egress:"safe,band=0..3,imposed-hold band 0..3 (bucketed seconds); not a raw duration"`
	DisengagedEarly bool   `egress:"safe,attacker-disengaged-before-cap boolean (the engagement signal)"`
	PoisonClass     string `egress:"safe,coarse poison reaction class from the closed vocab; stage taxonomy dropped"`
}

// validPoisonClasses is the closed poison-reaction vocab the egress filter's string
// enum accepts (network/justify.go enumValues["poisonclass"]). The production source
// (attrition.poisonClassForStage) only ever emits these, but contract.StingOutcome.
// PoisonClass is an unconstrained string, so clamp here: a future/malformed value
// coarsens to "" rather than failing network.Clear — which, because Clear is
// all-or-nothing, would otherwise silently drop the WHOLE otherwise-valid candidate.
var validPoisonClasses = map[string]bool{"": true, "credential": true, "topology": true, "success": true}

func clampPoisonClass(c string) string {
	if validPoisonClasses[c] {
		return c
	}
	return ""
}

// ToExportForm coarsens a Profile to its egress-eligible projection. Axis ordinals:
// 0=velocity, 1=poison (features.go axisBits / AxisNames).
func (p *Profile) ToExportForm() ExportForm {
	return ExportForm{
		ReachedContain:  p.PeakTier >= int(contract.TierContain),
		EngagedVelocity: p.AxesEngaged[0],
		EngagedPoison:   p.AxesEngaged[1],
		HeldBand:        heldBand(p.HeldSec),
		DisengagedEarly: p.DisengagedEarly,
		PoisonClass:     clampPoisonClass(p.PoisonClass),
	}
}

// exportCandidate is the network.Candidate wrapping a coarsened profile + its
// contribution context. Constructed only via Profile.Candidate.
type exportCandidate struct {
	form ExportForm
	ctx  network.ContributionContext
}

func (c exportCandidate) EgressFields() (any, network.ContributionContext) { return c.form, c.ctx }

// Candidate wraps the coarsened profile + a contribution context into the
// network.Candidate the SINGLE egress filter Clear()s. The ContributionContext (the
// per-deployment opt-in + the cross-scope SeenInScopes count) is supplied by D6's
// cross-scope ledger; until that ledger lands, callers must fail closed — the egress
// filter rejects an un-opted-in / sub-k candidate, so nothing crosses.
func (p *Profile) Candidate(ctx network.ContributionContext) network.Candidate {
	return exportCandidate{form: p.ToExportForm(), ctx: ctx}
}

// formCheckSeenInScopes is a high count used ONLY to validate the export FORM (below),
// so ValidateProfileForSharing checks field-level Clear-ability, not the runtime opt-in/
// k-anonymity policy (that is D6's ledger's job at the actual crossing).
const formCheckSeenInScopes = 1 << 20

// ValidateProfileForSharing reports whether a profile's coarsened ExportForm passes the
// single egress filter's FIELD-level checks (tagged-safe coarse scalars, no identity/
// raw data, the band/enum constraints). It is the producer-side guard that the D6
// export path is constructible. It deliberately uses a satisfying contribution context
// so it validates the FORM, not the opt-in/k-anonymity policy — those are enforced at
// the real crossing with the ledger-supplied context. The deployment-local-only
// ExploitsObserved/ExposureSignals are structurally absent from ExportForm and can
// never cross. nil profile => error.
func ValidateProfileForSharing(p *Profile) error {
	if p == nil {
		return fmt.Errorf("profile: nil profile is not shareable")
	}
	_, err := network.Clear(p.Candidate(network.ContributionContext{
		Contribute:   true,
		SeenInScopes: formCheckSeenInScopes,
	}))
	return err
}
