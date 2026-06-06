// Package seeder places canaries within reach of east-west traffic and keeps
// them fresh. Two modes: minefield (broad/passive) and active deception
// (targeted at flows the engine has tagged). Placement is scope-aware. It carries
// NO scoring or decision logic — the caller (engine -> seeder, one-directional)
// supplies the mode; the seeder never infers that a flow is suspicious and never
// reads the engine's live weights. See docs/CANARY.md.
package seeder

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
)

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

// Default freshness windows. Stale or obviously-fake decoys lose value (a primary
// reason earlier deception products failed), so placements expire and rotate.
const (
	DefaultMinefieldTTL = 24 * time.Hour
	DefaultActiveTTL    = 1 * time.Hour
)

// Store is the concrete Seeder: it generates harmless instances from the catalog,
// places them via a Planner into a scope-keyed Registry, and rotates them
// automatically. The placement DENSITY per mode/type is the seeder's only use of
// intent strength — never a score.
type Store struct {
	cat     *catalog.Catalog
	reg     Registry
	planner Planner
	ttl     map[Mode]time.Duration
	mix     map[Mode]map[contract.CanaryType]int
	jitter  time.Duration
	clock   func() time.Time

	mu    sync.Mutex
	rng   *rand.Rand
	idSeq uint64
}

// Config configures a Store. Catalog is required.
type Config struct {
	Catalog *catalog.Catalog
	// Registry stores placements; nil uses a fresh MemRegistry.
	Registry Registry
	// Planner decides locations; nil uses BroadPlanner (the M3 default).
	Planner Planner
	// TTL per mode; zero entries use the documented defaults.
	TTL map[Mode]time.Duration
	// Mix is the per-mode, per-type placement count (density). nil uses the
	// documented default (Active is a richer, higher-intent surface).
	Mix map[Mode]map[contract.CanaryType]int
	// Jitter randomizes expiry so an attacker cannot fingerprint the refresh
	// cadence; zero uses ttl/10.
	Jitter time.Duration
	// Clock is the time source; nil uses time.Now. Tests inject a fake clock.
	Clock func() time.Time
	// Rand seeds expiry jitter; nil uses a fresh seeded source. Locations are the
	// planner's concern and are deterministic in the BroadPlanner M3 default.
	Rand *rand.Rand
}

// New builds a Store with documented defaults filled in.
func New(cfg Config) (*Store, error) {
	if cfg.Catalog == nil {
		return nil, fmt.Errorf("seeder: nil catalog")
	}
	s := &Store{
		cat:     cfg.Catalog,
		reg:     cfg.Registry,
		planner: cfg.Planner,
		ttl:     cfg.TTL,
		mix:     cfg.Mix,
		jitter:  cfg.Jitter,
		clock:   cfg.Clock,
		rng:     cfg.Rand,
	}
	if s.reg == nil {
		s.reg = NewMemRegistry()
	}
	if s.planner == nil {
		s.planner = BroadPlanner{}
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.rng == nil {
		s.rng = rand.New(rand.NewSource(rand.Int63()))
	}
	if s.ttl == nil {
		s.ttl = map[Mode]time.Duration{}
	}
	if s.ttl[Minefield] <= 0 {
		s.ttl[Minefield] = DefaultMinefieldTTL
	}
	if s.ttl[Active] <= 0 {
		s.ttl[Active] = DefaultActiveTTL
	}
	if s.mix == nil {
		s.mix = defaultMix()
	}
	return s, nil
}

var _ Seeder = (*Store)(nil)

// defaultMix: minefield places one of each type broadly; active is a richer,
// higher-intent surface (more high-seed types) fed to a tagged flow.
func defaultMix() map[Mode]map[contract.CanaryType]int {
	return map[Mode]map[contract.CanaryType]int{
		Minefield: {
			catalog.TypePlantedCredential: 1,
			catalog.TypeFakeSecret:        1,
			catalog.TypeDecoyFile:         1,
			catalog.TypeFakeBucket:        1,
			catalog.TypeFakeEndpoint:      1,
		},
		Active: {
			catalog.TypePlantedCredential: 3,
			catalog.TypeFakeSecret:        3,
			catalog.TypeDecoyFile:         2,
			catalog.TypeFakeBucket:        1,
			catalog.TypeFakeEndpoint:      1,
		},
	}
}

// Registry exposes the placement registry (the adapter's lookup target).
func (s *Store) Registry() Registry { return s.reg }

// Seed places canaries for a scope under the given mode. It refuses an empty
// scope (fail safe on uncertainty — never a global placement).
func (s *Store) Seed(scope contract.ScopeKey, mode Mode) error {
	if scope == "" {
		return ErrNoScope
	}
	props := s.planner.Plan(scope, mode, s.mix[mode])
	for _, p := range props {
		if err := s.place(scope, mode, p); err != nil {
			return err
		}
	}
	return nil
}

// place generates a fresh harmless instance for a proposal and registers it.
func (s *Store) place(scope contract.ScopeKey, mode Mode, p Proposal) error {
	inst, err := s.cat.Generate(p.Type) // fail-closed: never places a non-harmless instance
	if err != nil {
		return err
	}
	now := s.clock()
	return s.reg.Put(Placement{
		ID:        s.nextID(),
		Scope:     scope,
		Type:      p.Type,
		Location:  p.Location,
		Instance:  inst,
		Mode:      mode,
		PlacedAt:  now,
		ExpiresAt: now.Add(s.expiry(mode)),
		Origin:    p.Origin,
	})
}

// expiry is the TTL for a mode plus jitter, so rotation timing varies.
func (s *Store) expiry(mode Mode) time.Duration {
	ttl := s.ttl[mode]
	j := s.jitter
	if j <= 0 {
		j = ttl / 10
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if j > 0 {
		return ttl + time.Duration(s.rng.Int63n(int64(j)))
	}
	return ttl
}

func (s *Store) nextID() PlacementID {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idSeq++
	return PlacementID(fmt.Sprintf("p-%d", s.idSeq))
}

// Refresh rotates every expired placement in a scope: it replaces each stale
// decoy in place with freshly generated contents (a new instance at the same
// location), with no operator involvement.
func (s *Store) Refresh(scope contract.ScopeKey) error {
	for _, p := range s.reg.Expired(s.clock()) {
		if p.Scope != scope {
			continue
		}
		if err := s.rotate(p); err != nil {
			return err
		}
	}
	return nil
}

// RunAutoRefresh is the automated freshness loop: on each tick it rotates every
// expired placement across all scopes until ctx is cancelled. No operator
// hand-maintenance (docs/CANARY.md "Freshness is the seeder's job").
func (s *Store) RunAutoRefresh(ctx context.Context, every time.Duration) error {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := s.sweepExpired(s.clock()); err != nil {
				return err
			}
		}
	}
}

// sweepExpired rotates every expired placement across all scopes at time now. It
// is the deterministic core of RunAutoRefresh.
func (s *Store) sweepExpired(now time.Time) error {
	for _, p := range s.reg.Expired(now) {
		if err := s.rotate(p); err != nil {
			return err
		}
	}
	return nil
}

// rotate replaces a stale placement with a freshly generated instance of the
// same type, scope, mode, and origin AT THE SAME LOCATION (Put overwrites the
// slot). It deliberately does NOT ask the planner for a new location: under a
// broad planner that would re-propose the type's index-0 location and collapse
// sibling placements of the same type onto one slot, shrinking the surface.
// Contents rotate (defeating stale-payload fingerprinting); location variety is
// the planner's job (a future planner may offer distinct locations).
func (s *Store) rotate(p Placement) error {
	return s.place(p.Scope, p.Mode, Proposal{Location: p.Location, Type: p.Type, Origin: p.Origin})
}
