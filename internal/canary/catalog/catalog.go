// Package catalog defines canary object types and their SEED intent-strength
// weights. Seed weights are cold-start priors only; the engine's calibration
// overrides them with learned per-scope weights. Canaries must be harmless and
// must never grant real access. Do NOT build fixed chained-credential decoys
// (IP caution, docs/ARCHITECTURE.md §11). See docs/CANARY.md.
//
// The catalog carries NO scoring/tiering/decision logic. It does not import
// internal/engine, and internal/engine does not import it; the only coupling is
// the composition root passing SeedWeights() into calibration as a cold-start
// prior (an import-graph test enforces both directions).
package catalog

import (
	"fmt"
	"math/rand"
	"sync"

	"github.com/canarysting/canarysting/internal/contract"
)

// lockedRand makes a *rand.Rand safe for concurrent generator calls. The seeder
// calls Catalog.Generate from multiple goroutines (request-path Seed and the
// background RunAutoRefresh sweep), and math/rand.Rand is not concurrency-safe.
// The per-call lock keeps single-generation determinism, so reproducibility holds.
type lockedRand struct {
	mu sync.Mutex
	r  *rand.Rand
}

func (l *lockedRand) Intn(n int) int       { l.mu.Lock(); defer l.mu.Unlock(); return l.r.Intn(n) }
func (l *lockedRand) Int63n(n int64) int64 { l.mu.Lock(); defer l.mu.Unlock(); return l.r.Int63n(n) }
func (l *lockedRand) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p)
}

// Entry describes one canary type.
type Entry struct {
	Type contract.CanaryType
	// SeedWeight is the cold-start prior intent strength. NOT a live weight. The
	// engine owns the live weight (via calibration). The seeder does NOT read this
	// field — its placement density comes from its own per-mode Mix, authored to
	// mirror this intent ordering. SeedWeight is exported only through
	// SeedWeights() to seed calibration. Ordered by intent strength; magnitudes
	// chosen so the prior stays well inside calibration's weight clamp.
	SeedWeight float64
	// Generate produces a realistic, harmless instance of this decoy.
	Generate func() (Instance, error)
	// Harmless is the per-type, machine-checkable proof that an instance is
	// non-functional (docs/CANARY.md). nil result == provably harmless.
	Harmless func(Instance) error
}

// Instance is a concrete placed decoy. It holds nothing of value and grants no
// real access.
type Instance struct {
	Type    contract.CanaryType
	Payload []byte // harmless, non-functional bait
}

// Catalog is the set of registered canary types. It proves harmlessness at
// construction (an unsafe entry can never register) and enforces it again as a
// fail-closed gate on every Generate.
type Catalog struct {
	entries map[contract.CanaryType]Entry
	order   []contract.CanaryType
}

// Config configures catalog construction.
type Config struct {
	// Rand is the entropy source for generators. nil uses a fresh seeded source.
	// Tests pass a fixed source for reproducibility.
	Rand *rand.Rand
	// HarmlessSamples is how many samples per type New verifies at construction.
	// Zero uses a documented default.
	HarmlessSamples int
}

const defaultHarmlessSamples = 64

// New builds the catalog and PROVES harmlessness at construction: it generates
// HarmlessSamples instances per type and runs IsHarmless on each, returning an
// error (never silently registering) if any sample is not provably harmless.
func New(cfg Config) (*Catalog, error) {
	r := cfg.Rand
	if r == nil {
		r = rand.New(rand.NewSource(rand.Int63()))
	}
	samples := cfg.HarmlessSamples
	if samples <= 0 {
		samples = defaultHarmlessSamples
	}

	return build(defaultEntries(&lockedRand{r: r}), samples)
}

// build registers entries and proves harmlessness at construction. It is the
// seam the tests use to verify an unsafe entry can never register.
func build(defs []Entry, samples int) (*Catalog, error) {
	c := &Catalog{entries: make(map[contract.CanaryType]Entry, len(defs))}
	for _, e := range defs {
		if e.Generate == nil || e.Harmless == nil {
			return nil, fmt.Errorf("catalog: type %q missing generator or harmless predicate", e.Type)
		}
		if _, dup := c.entries[e.Type]; dup {
			return nil, fmt.Errorf("catalog: duplicate type %q", e.Type)
		}
		c.entries[e.Type] = e
		c.order = append(c.order, e.Type)
	}

	// Construction-time enforcement: no catalog is returned unless every sample
	// of every type is provably harmless.
	for _, t := range c.order {
		for i := 0; i < samples; i++ {
			inst, err := c.entries[t].Generate()
			if err != nil {
				return nil, fmt.Errorf("catalog: %q generator failed: %w", t, err)
			}
			if err := c.IsHarmless(inst); err != nil {
				return nil, fmt.Errorf("catalog: %q produced a non-harmless sample: %w", t, err)
			}
		}
	}
	return c, nil
}

// Default returns the standard catalog. It panics only on the build-time
// impossibility that the shipped generators are not harmless — a condition the
// test suite guards, so it cannot occur in a shipped binary.
func Default() *Catalog {
	c, err := New(Config{})
	if err != nil {
		panic("catalog: default catalog is not harmless: " + err.Error())
	}
	return c
}

// Entry returns the entry for a type.
func (c *Catalog) Entry(t contract.CanaryType) (Entry, bool) {
	e, ok := c.entries[t]
	return e, ok
}

// Types returns the registered canary types in a stable order.
func (c *Catalog) Types() []contract.CanaryType {
	out := make([]contract.CanaryType, len(c.order))
	copy(out, c.order)
	return out
}

// Generate produces a fresh instance of a type, running IsHarmless as a hard
// fail-closed gate: a generator regression returns an error rather than ever
// placing a functional secret.
func (c *Catalog) Generate(t contract.CanaryType) (Instance, error) {
	e, ok := c.entries[t]
	if !ok {
		return Instance{}, fmt.Errorf("catalog: unknown canary type %q", t)
	}
	inst, err := e.Generate()
	if err != nil {
		return Instance{}, err
	}
	if inst.Type != t {
		return Instance{}, fmt.Errorf("catalog: %q generator returned type %q", t, inst.Type)
	}
	if err := c.IsHarmless(inst); err != nil {
		return Instance{}, fmt.Errorf("catalog: refusing to emit non-harmless %q: %w", t, err)
	}
	return inst, nil
}

// IsHarmless runs the type's own predicate AND the universal cross-scan, so a
// decoy can never smuggle a live-shaped secret regardless of its type.
func (c *Catalog) IsHarmless(i Instance) error {
	e, ok := c.entries[i.Type]
	if !ok {
		return fmt.Errorf("catalog: unknown canary type %q", i.Type)
	}
	if err := e.Harmless(i); err != nil {
		return err
	}
	return crossScan(i.Payload)
}

// SeedWeights returns the cold-start intent-strength priors per type. This is the
// ONLY place the seed ordering is exported; the composition root feeds it into
// calibration.Config.SeedWeights as a prior. The engine reads live weights from
// calibration, never this map.
func (c *Catalog) SeedWeights() map[contract.CanaryType]float64 {
	out := make(map[contract.CanaryType]float64, len(c.entries))
	for t, e := range c.entries {
		out[t] = e.SeedWeight
	}
	return out
}

// defaultEntries builds the five canary entries, ordered by intent strength.
// Seed magnitudes are clamp-aware: with calibration's prior math (a0=seed,
// b0=1.0, w0=2·a0/(a0+1)), the strongest seed (1.8 -> w0≈1.29) stays well inside
// calibration's [0.1, 2.0] clamp, so the prior never dominates and the engine
// overrides it once the evidence floor is met. Ordering follows docs/CANARY.md
// ("planted credentials > a fake bucket listing").
func defaultEntries(r rng) []Entry {
	return []Entry{
		{Type: TypePlantedCredential, SeedWeight: 1.8, Generate: func() (Instance, error) { return genPlantedCredential(r) }, Harmless: plantedCredentialHarmless},
		{Type: TypeFakeSecret, SeedWeight: 1.5, Generate: func() (Instance, error) { return genFakeSecret(r) }, Harmless: fakeSecretHarmless},
		{Type: TypeDecoyFile, SeedWeight: 1.2, Generate: func() (Instance, error) { return genDecoyFile(r) }, Harmless: decoyFileHarmless},
		{Type: TypeFakeBucket, SeedWeight: 1.1, Generate: func() (Instance, error) { return genFakeBucket(r) }, Harmless: fakeBucketHarmless},
		{Type: TypeFakeEndpoint, SeedWeight: 1.0, Generate: func() (Instance, error) { return genFakeEndpoint(r) }, Harmless: fakeEndpointHarmless},
	}
}
