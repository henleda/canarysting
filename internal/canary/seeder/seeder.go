// Package seeder places canaries within reach of east-west traffic and keeps
// them fresh. Two modes: minefield (broad/passive) and active deception
// (targeted at flows the engine has tagged). Placement is scope-aware. See
// docs/CANARY.md.
package seeder

import "github.com/canarysting/canarysting/internal/contract"

// Mode selects placement strategy.
type Mode int

const (
	Minefield Mode = iota // broad passive seeding
	Active                // richer surface fed to a tagged flow
)

// Seeder places and refreshes canaries.
type Seeder interface {
	// Seed places canaries for a scope under the given mode.
	Seed(scope contract.ScopeKey, mode Mode) error
	// Refresh rotates placements to maintain freshness automatically.
	Refresh(scope contract.ScopeKey) error
}

// TODO: implement placement + automated freshness; never require operators to
// hand-maintain decoys.
