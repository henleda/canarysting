// Package integration holds cross-layer tests that legitimately wire the canary
// layer to the engine (the composition the production binary performs in
// cmd/engine). Keeping them here keeps internal/canary's own tests free of any
// engine dependency, so the layering holds even in tests.
package integration

import (
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/canary/seeder"
	"github.com/canarysting/canarysting/internal/canary/signal"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/scope"
	"github.com/canarysting/canarysting/internal/engine/scoring"
	"github.com/canarysting/canarysting/internal/engine/tiers"
)

// TestEngineDoesNotImportCanary is the reverse of the canary→engine guard in
// internal/canary/catalog: the engine must not import the canary layer either, so
// the two layers couple only through internal/contract (CLAUDE.md rule 2). With
// the canary→engine guard, this makes the "enforces both directions" claim true.
func TestEngineDoesNotImportCanary(t *testing.T) {
	fset := token.NewFileSet()
	var bad []string
	err := filepath.Walk("../../internal/engine", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, "canarysting/internal/canary") {
				bad = append(bad, path+": "+imp.Path.Value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Errorf("the engine must not import the canary layer; offenders: %v", bad)
	}
}

func TestCatalogSeedWeightsFeedCalibrationAsPriorOnly(t *testing.T) {
	cat, err := catalog.New(catalog.Config{Rand: rand.New(rand.NewSource(1)), HarmlessSamples: 8})
	if err != nil {
		t.Fatal(err)
	}
	calib := calibration.New(calibration.Config{SeedWeights: cat.SeedWeights(), EvidenceFloor: 3})

	// Below the evidence floor: uniform weight regardless of seed (cold start =
	// raw count). The seed is a prior, not a live weight.
	if w := calib.Weight("s", catalog.TypePlantedCredential); w != 1.0 {
		t.Fatalf("below floor must be uniform 1.0, got %.3f", w)
	}

	// Cross the floor with confirmed-malicious labels; the learned weight diverges
	// from the cold-start uniform — the engine overrides the prior.
	for i := 0; i < 3; i++ {
		calib.Ingest(contract.FeedbackLabel{Scope: "s", WasMalicious: true, CanariesTouched: []contract.CanaryType{catalog.TypePlantedCredential}})
	}
	if st := calib.State("s"); !st.Calibrated {
		t.Fatalf("scope should be calibrated at the floor: %+v", st)
	}
	if w := calib.Weight("s", catalog.TypePlantedCredential); w <= 1.0 {
		t.Fatalf("malicious-confirmed type must learn weight > 1, got %.3f", w)
	}
}

func TestTouchToVerdictEndToEnd(t *testing.T) {
	const scopeKey = contract.ScopeKey("scope-a")

	// Canary layer: catalog -> seeder -> a placed canary -> the signal builder.
	cat, err := catalog.New(catalog.Config{Rand: rand.New(rand.NewSource(1)), HarmlessSamples: 8})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := seeder.New(seeder.Config{Catalog: cat, Rand: rand.New(rand.NewSource(2))})
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.Seed(scopeKey, seeder.Minefield); err != nil {
		t.Fatal(err)
	}
	placed := sd.Registry().List(scopeKey)[0]
	builder := signal.NewBuilder(sd.Registry())

	// Engine: scope -> scoring (with catalog seed weights as prior) -> tiers.
	resolver, _ := scope.NewStaticResolver(scope.Config{Boundary: scopeKey})
	calib := calibration.New(calibration.Config{SeedWeights: cat.SeedWeights()})
	eng, err := engine.New(engine.Config{
		Resolver:    resolver,
		Scorer:      scoring.New(5*time.Minute, calib, nil),
		Decider:     tiers.StaticDecider{},
		Tiers:       tiers.DefaultConfig(),
		Calibration: calib,
	})
	if err != nil {
		t.Fatal(err)
	}

	// An adapter observes a flow touching the placed canary; Build -> Submit.
	ev, err := builder.Build(scopeKey, signal.Touch{
		Flow:     contract.FlowIdentity{SocketCookie: 0xC0FFEE},
		Location: placed.Location,
		At:       time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatalf("Build rejected a real canary touch: %v", err)
	}
	if ev.Canary != placed.Type {
		t.Fatalf("event canary %q != placed type %q", ev.Canary, placed.Type)
	}

	v, err := eng.Submit(ev)
	if err != nil {
		t.Fatalf("engine rejected a valid canary signal: %v", err)
	}
	if v.Scope != scopeKey {
		t.Fatalf("verdict scope = %q, want %q", v.Scope, scopeKey)
	}
	if v.Score != 1.0 || v.Tier != contract.TierObserve {
		t.Fatalf("single touch: got tier %d score %.2f, want Observe/1.0", v.Tier, v.Score)
	}
}

func TestDepthOfInteractionEscalatesAcrossSeam(t *testing.T) {
	const scopeKey = contract.ScopeKey("scope-a")
	cat, err := catalog.New(catalog.Config{Rand: rand.New(rand.NewSource(1)), HarmlessSamples: 8})
	if err != nil {
		t.Fatal(err)
	}
	sd, err := seeder.New(seeder.Config{Catalog: cat, Rand: rand.New(rand.NewSource(2))})
	if err != nil {
		t.Fatal(err)
	}
	sd.Seed(scopeKey, seeder.Minefield) // one of each of the 5 types, distinct locations
	builder := signal.NewBuilder(sd.Registry())

	resolver, _ := scope.NewStaticResolver(scope.Config{Boundary: scopeKey})
	calib := calibration.New(calibration.Config{SeedWeights: cat.SeedWeights()})
	eng, _ := engine.New(engine.Config{
		Resolver: resolver, Scorer: scoring.New(5*time.Minute, calib, nil),
		Decider: tiers.StaticDecider{}, Tiers: tiers.DefaultConfig(), Calibration: calib,
	})

	flow := contract.FlowIdentity{SocketCookie: 0xBEEF}
	placed := sd.Registry().List(scopeKey)
	at := time.Unix(1_700_000_000, 0)

	// Distinct canary touches by the same flow escalate the tier (depth of
	// interaction). Default thresholds: Tag>=1.30 (2 touches), Contain>=3.00 (3).
	var last contract.Verdict
	for i, p := range placed[:3] {
		ev, err := builder.Build(scopeKey, signal.Touch{Flow: flow, Location: p.Location, At: at.Add(time.Duration(i) * time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		last, err = eng.Submit(ev)
		if err != nil {
			t.Fatal(err)
		}
	}
	if last.Tier != contract.TierContain {
		t.Fatalf("3 distinct canary touches: got tier %d score %.1f, want Contain", last.Tier, last.Score)
	}

	// Negative arm: touching the SAME canary again does not raise the score
	// (distinct-count discipline holds across the seam).
	ev, _ := builder.Build(scopeKey, signal.Touch{Flow: flow, Location: placed[0].Location, At: at.Add(10 * time.Second)})
	v, _ := eng.Submit(ev)
	if v.Score != last.Score {
		t.Fatalf("re-touching the same canary changed the score: %.1f -> %.1f", last.Score, v.Score)
	}
}
