package profile

import "github.com/canarysting/canarysting/internal/contract"

// NumAxes is the number of attrition axes (contract.Axis* bit order: velocity,
// poison, opportunity-cost, exploit-burn, operational-exposure). The per-axis
// engagement signature below is indexed by this ordinal.
const NumAxes = 5

// axisBits maps the ordinal -> the contract bit, so AxesEngaged tracks the
// AttritionAxis constants rather than a hand-rolled shift (robust to a reorder).
var axisBits = [NumAxes]contract.AttritionAxis{
	contract.AxisVelocity, contract.AxisPoison, contract.AxisOppCost,
	contract.AxisExploitBurn, contract.AxisOpExposure,
}

// AxisNames labels the per-axis engagement booleans in bit order.
var AxisNames = [NumAxes]string{"velocity", "poison", "opportunity", "exploit", "exposure"}

// Feature-map keys read as scoring CONTEXT only (rule 8 — never a trigger). These
// mirror the baseline.Features keys the dashboard fingerprint also reads, so the D2
// profile and the dashboard fingerprint agree on the behavioral pattern.
const (
	featAdjacency = "adjacency_novelty"
	featIdentity  = "identity_novelty"
)

// tarpitPersistSec is the imposed-hold threshold above which an actor is judged to
// have "persisted through the tarpit" — a behavioral reaction signal. Mirrors the
// dashboard's tarpitPersistSec so both layers agree.
const tarpitPersistSec = 30.0

// cadenceBand coarsens a median inter-arrival (seconds) into a small stable band, so
// the BehavioralHash (which keys on the band, not the raw seconds) does not shatter on
// timing jitter while still separating fast automation from slow manual probing.
func cadenceBand(sec float64) int {
	switch {
	case sec <= 0 || sec < 5:
		return 0 // sub-5s: tight automation (or single-touch, cadence 0)
	case sec < 30:
		return 1
	case sec < 120:
		return 2
	default:
		return 3 // slow / human-paced
	}
}

// heldBand coarsens total imposed-hold seconds into the 0..3 band the egress filter's
// ExportForm requires (band=0..3; a raw duration would single out / leak the tarpit
// config, so only the coarse band may cross).
func heldBand(sec float64) int {
	switch {
	case sec <= 0:
		return 0
	case sec < 4:
		return 1
	case sec < 30:
		return 2
	default:
		return 3
	}
}
