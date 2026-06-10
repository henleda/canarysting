package seeder

import (
	"fmt"

	"github.com/canarysting/canarysting/internal/contract"
)

// PlacementOrigin records WHY a canary was placed where it was. It is metadata
// only — it is NEVER scored, tiered, or used to decide a flow is suspicious.
// Only a canary touch enters the response pipeline (CLAUDE.md rule 8).
type PlacementOrigin int

const (
	OriginOperatorBroad PlacementOrigin = iota // broad minefield seeding
	OriginNegativeSpace                        // paths/ports/adjacencies legit flows never use (M7)
	OriginLateralPath                          // near plausible lateral-movement routes (M7)
)

// Proposal is a planner's suggestion of WHERE to place a canary of a given type.
type Proposal struct {
	Location Location
	Type     contract.CanaryType
	Origin   PlacementOrigin
}

// Planner decides WHERE bait goes. It returns proposals only; it never scores,
// tiers, or emits a verdict, and it is unreachable from the signal-emission path
// — so baseline-informed placement can never trigger a sting (docs/CANARY.md
// "Baseline-informed placement"). The seeder tells the planner HOW MANY of each
// type it wants (intent-weighted by the caller); the planner decides the
// locations.
type Planner interface {
	Plan(scope contract.ScopeKey, mode Mode, want map[contract.CanaryType]int) []Proposal
}

// BroadPlanner is the explicit M3 default: it scatters canaries across synthetic,
// broadly-reachable locations with no baseline knowledge. It mirrors the engine's
// deferred-seam pattern (scoring.NeutralMultiplier, baseline gating to 1.0).
//
// M7 negative-space placement keeps the layering intact: the seeder MUST NOT
// import internal/engine. Instead the composition root (cmd/engine) derives the
// per-scope negative-space/adjacency hint from internal/engine/baseline and
// passes it to the seeder as a contract-typed value (engine -> contract ->
// seeder). A BaselinePlanner then reads that hint and returns
// OriginNegativeSpace/OriginLateralPath proposals, with ZERO change to the
// registry or the signal seam.
type BroadPlanner struct {
	// Locations optionally pins explicit locations per type (e.g. real demo
	// services in M4). When empty, synthetic per-scope locations are generated.
	Locations map[contract.CanaryType][]Location
}

// Plan returns proposals per type. For a type with PINNED Locations, it places
// ALL of them — pinning a location is an explicit "put a canary here" instruction
// (e.g. the M4/M9 demo set, including directory canaries), so the mix count must
// not silently drop the extras. For an unpinned type it synthesizes want[type]
// deterministic locations keyed by scope and type.
func (b BroadPlanner) Plan(scope contract.ScopeKey, _ Mode, want map[contract.CanaryType]int) []Proposal {
	var props []Proposal

	// Pinned types: place every pinned location, even if the mix doesn't request
	// this type (the operator pinned it deliberately).
	for typ, pinned := range b.Locations {
		for _, loc := range pinned {
			props = append(props, Proposal{Location: loc, Type: typ, Origin: OriginOperatorBroad})
		}
	}

	// Unpinned types: synthesize want[type] locations.
	for typ, n := range want {
		if len(b.Locations[typ]) > 0 {
			continue // already placed all pinned locations above
		}
		for i := 0; i < n; i++ {
			loc := Location(fmt.Sprintf("cs://%s/%s/%d", scope, typ, i))
			props = append(props, Proposal{Location: loc, Type: typ, Origin: OriginOperatorBroad})
		}
	}
	return props
}
