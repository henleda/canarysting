package seeder

import (
	"errors"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
)

// Location is a proxy-observable handle for a placed canary: a path, header,
// bucket name, or file path the adapter matches an observed interaction against.
type Location string

// PlacementID uniquely identifies one placement.
type PlacementID string

// Placement is one canary placed in exactly one scope. It is a FLAT record: it
// holds NO reference to another placement (no Unlocks/Next/chain field). Canary
// independence (docs/CANARY.md, ARCH §11) is enforced by this data model, not by
// discipline — a reflective test asserts no field references another placement.
type Placement struct {
	ID        PlacementID
	Scope     contract.ScopeKey // exactly one scope
	Type      contract.CanaryType
	Location  Location
	Instance  catalog.Instance
	Mode      Mode
	PlacedAt  time.Time
	ExpiresAt time.Time       // freshness deadline; the refresh loop rotates past it
	Origin    PlacementOrigin // WHY here (operator-broad / negative-space / lateral); never scored
}

var (
	// ErrNoScope is returned when a placement has no scope. Fail safe on
	// uncertainty: a scopeless placement is refused, never placed globally.
	ErrNoScope = errors.New("seeder: placement has no scope; refusing to place")
	// ErrNoLocation is returned when a placement has no location.
	ErrNoLocation = errors.New("seeder: placement has no location")
)

// Registry stores placements, partitioned by scope. Lookups are scoped: a
// placement in one scope is invisible to every other scope.
type Registry interface {
	Put(Placement) error
	// Lookup resolves an observed location to its placement WITHIN a scope.
	Lookup(scope contract.ScopeKey, loc Location) (Placement, bool)
	List(scope contract.ScopeKey) []Placement
	Remove(scope contract.ScopeKey, loc Location) error
	// Expired returns every placement (across scopes) whose ExpiresAt is at or
	// before now — the input to the freshness sweep.
	Expired(now time.Time) []Placement
}

// MemRegistry is an in-memory, scope-partitioned Registry, safe for concurrent
// use (the adapter hot path and the refresh loop touch it concurrently).
type MemRegistry struct {
	mu    sync.Mutex
	state map[contract.ScopeKey]map[Location]Placement
}

// NewMemRegistry returns an empty registry.
func NewMemRegistry() *MemRegistry {
	return &MemRegistry{state: map[contract.ScopeKey]map[Location]Placement{}}
}

// Put stores a placement, rejecting any with no scope or location.
func (m *MemRegistry) Put(p Placement) error {
	if p.Scope == "" {
		return ErrNoScope
	}
	if p.Location == "" {
		return ErrNoLocation
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	byLoc := m.state[p.Scope]
	if byLoc == nil {
		byLoc = map[Location]Placement{}
		m.state[p.Scope] = byLoc
	}
	byLoc[p.Location] = p
	return nil
}

// Lookup resolves a location within a scope. A scope-b lookup never sees a
// scope-a placement.
func (m *MemRegistry) Lookup(scope contract.ScopeKey, loc Location) (Placement, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.state[scope][loc]
	return p, ok
}

// List returns a copy of the placements in a scope.
func (m *MemRegistry) List(scope contract.ScopeKey) []Placement {
	m.mu.Lock()
	defer m.mu.Unlock()
	byLoc := m.state[scope]
	out := make([]Placement, 0, len(byLoc))
	for _, p := range byLoc {
		out = append(out, p)
	}
	return out
}

// Remove deletes a placement by location within a scope.
func (m *MemRegistry) Remove(scope contract.ScopeKey, loc Location) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if byLoc := m.state[scope]; byLoc != nil {
		delete(byLoc, loc)
	}
	return nil
}

// Expired returns every placement whose ExpiresAt is at or before now.
func (m *MemRegistry) Expired(now time.Time) []Placement {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Placement
	for _, byLoc := range m.state {
		for _, p := range byLoc {
			if !p.ExpiresAt.IsZero() && !p.ExpiresAt.After(now) {
				out = append(out, p)
			}
		}
	}
	return out
}
