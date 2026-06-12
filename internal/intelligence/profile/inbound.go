package profile

import (
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/network"
)

// FromSharedPattern sparse-lifts a received cross-customer network.SharedPattern into a
// Profile for the Similarity kernel — the INBOUND counterpart of ToExportForm. It is
// deliberately SPARSE: only the exported coarse fields are set, OrderedTypes is EMPTY
// (the decoy probe sequence is rule-9-dropped, so typeSim — the kernel's dominant 0.40
// term — contributes 0; a cross-customer pattern is therefore a STRICTLY WEAKER match
// than a local confirmed profile, which is correct: we deliberately know less about it),
// and BehavioralHash is left 0 so the Similarity self-match fast-path can NEVER fire for
// an inbound pattern (D6h). It is detection CONTEXT only — never recorded, never a
// trigger (rule 8).
func FromSharedPattern(sp network.SharedPattern) *Profile {
	p := &Profile{
		CadenceSec:      cadenceRepForBand(sp.CadenceBand),
		PoisonClass:     sp.PoisonClass,
		DisengagedEarly: sp.DisengagedEarly,
		BehavioralHash:  0, // D6h sentinel: not a real behavioral identity; no fast-path match
	}
	if sp.ReachedContain {
		p.PeakTier = int(contract.TierContain)
	}
	p.AxesEngaged[0] = sp.EngagedVelocity
	p.AxesEngaged[1] = sp.EngagedPoison
	return p
}

// cadenceRepForBand maps a 0..3 CadenceBand back to a representative seconds value whose
// cadenceBand() round-trips to that band, so the Similarity cadence term compares the
// shared pattern's exported tempo band against the emerging flow's band (earned
// evidence, never a reconstructed float). The exact seconds are immaterial — only the
// band the value falls in matters to the kernel.
func cadenceRepForBand(band int) float64 {
	switch band {
	case 1:
		return 10 // cadenceBand(10) == 1
	case 2:
		return 60 // cadenceBand(60) == 2
	case 3:
		return 200 // cadenceBand(200) == 3
	default:
		return 1 // band 0: sub-5s automation (cadenceBand(1) == 0)
	}
}
