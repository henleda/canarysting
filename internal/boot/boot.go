// Package boot is the shared composition root for the CanarySting decision
// engine: it wires scope resolution, calibration, the baseline multiplier and
// its M7 observe-path feature source, scoring, tiers, the engine, the feedback
// intake, durable persistence, and the durable interaction EventStore — and
// returns the handles a binary needs to serve and to shut down cleanly.
//
// Two binaries call it: cmd/engine (production) and cmd/staged-range (the
// staging-only variant that additionally wires the ground-truth labeler). boot
// deliberately does NOT import internal/intelligence/stagedlabel, so the
// production engine's dependency closure cannot reach the labeler at all — the
// staged labeler is reachable only from the dedicated staging binary (an import-
// graph guard enforces this). This is gate 3 of the staged-labeler's production-
// safety defense in depth.
//
// The malicious-identity set is wired ONLY as the aggregator's baseline-of-
// normal exclusion. It is NEVER passed to the scorer as a BenignExcluder: an
// attacker must still score and escalate on a canary touch (excluding it from
// SCORING would zero its score and defeat containment). The scorer always uses
// scoring.NoExclusions here.
package boot

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine"
	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/feedback"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/engine/scope"
	"github.com/canarysting/canarysting/internal/engine/scoring"
	"github.com/canarysting/canarysting/internal/engine/tiers"
	"github.com/canarysting/canarysting/internal/intelligence/boltevents"
)

// Options configures the composition.
type Options struct {
	Boundary       string        // operator scope boundary; empty => refuse to start
	Window         time.Duration // scoring correlation window
	Aggressive     bool          // demo/eval: minimum per-tier confidence (cold-start escalation)
	BaselineDBPath string        // bbolt path; "" => no durability (in-memory baseline)
	ObserveCgroup  string        // cgroup v2 path; "" => observe disabled (touch-only, M=1)
	CoarseBucketer bool          // true => WindowBucketer (M7 window); false => DefaultBucketer (production)
	Floor          observebaseline.DataFloor
	// ResetOnSchemaMismatch, when true, DISCARDS a persisted baseline whose schema
	// version differs from this build (logged loudly) instead of refusing to start.
	// Default false: refuse, so a learning window is never silently lost.
	ResetOnSchemaMismatch bool
}

// Built holds the composed engine and the handles a binary wires further or
// closes.
type Built struct {
	Engine     contract.Engine // possibly wrapped to capture interaction events
	Intake     *feedback.Intake
	Calib      *calibration.Store
	Baseline   *baseline.Store
	Resolver   scope.Resolver
	Persist    *persist.Store                // nil if no DB
	Aggregator *observebaseline.Aggregator   // nil if observe disabled
	Malicious  *observebaseline.MaliciousSet // nil if observe disabled
	Events     *boltevents.Store             // nil if no DB

	observer observe.Observer
}

// Build wires the engine from opts and a platform observer (constructed by the
// caller via a build-tagged newObserver, so cilium/ebpf stays out of non-linux
// builds). It returns scope.ErrUnresolved (wrapped) if no scope can be resolved
// — the caller must treat that as fatal.
func Build(opts Options, observer observe.Observer) (*Built, error) {
	resolver, err := scope.NewStaticResolver(scope.Config{Boundary: contract.ScopeKey(opts.Boundary)})
	if err != nil {
		return nil, err
	}

	cat := catalog.Default()
	calib := calibration.New(calibration.Config{SeedWeights: cat.SeedWeights()})

	bucketer := baseline.DefaultBucketer
	if opts.CoarseBucketer {
		bucketer = baseline.WindowBucketer
	}
	base := baseline.New(baseline.Config{
		Bucketer:   bucketer,
		Calibrated: func(s contract.ScopeKey) bool { return calib.State(s).Calibrated },
	})

	b := &Built{
		Intake:   feedback.NewIntake(calib),
		Calib:    calib,
		Baseline: base,
		Resolver: resolver,
		observer: observer,
	}

	// Durability (bbolt) is optional. When present it backs the per-scope
	// baseline aggregate, the malicious-identity set, and the EventStore.
	if opts.BaselineDBPath != "" {
		store, found, err := persist.Open(opts.BaselineDBPath)
		if err != nil {
			return nil, fmt.Errorf("boot: open baseline db: %w", err)
		}
		// A schema mismatch means the persisted aggregates are undecodable. Refuse
		// to start rather than silently discard a (possibly multi-week) learning
		// window — fail-safe on uncertainty. An operator who genuinely wants to
		// discard sets ResetOnSchemaMismatch, which logs loudly and re-stamps so the
		// stale blobs are skipped and the scope re-accrues from empty.
		if found != persist.SchemaVersion {
			if !opts.ResetOnSchemaMismatch {
				_ = store.Close()
				return nil, fmt.Errorf("boot: baseline db %q has schema version %d but this build expects %d; the persisted baseline is undecodable. Refusing to start to avoid silently discarding a learning window — re-run with reset-on-schema-change to discard and re-accrue, or point -baseline-db at a fresh path", opts.BaselineDBPath, found, persist.SchemaVersion)
			}
			log.Printf("boot: WARNING baseline db schema mismatch (on-disk=%d build=%d); discarding the persisted baseline and re-accruing from empty", found, persist.SchemaVersion)
			if err := store.StampSchemaVersion(); err != nil {
				_ = store.Close()
				return nil, fmt.Errorf("boot: re-stamp schema: %w", err)
			}
		}
		b.Persist = store
		b.Events = boltevents.New(store)
	}

	// The OBSERVE-ONLY baseline path is wired only when a cgroup is given (i.e. on
	// the box). When disabled, M stays a forced 1.0 (touch-only) — the safe
	// cold-start behavior, and exactly the macOS/CI posture.
	if opts.ObserveCgroup != "" {
		if err := observer.Load(opts.ObserveCgroup); err != nil {
			b.closePartial()
			return nil, fmt.Errorf("boot: load observe path at %q: %w", opts.ObserveCgroup, err)
		}
		b.Malicious = observebaseline.NewMaliciousSet(b.Persist) // nil store => in-memory
		b.Aggregator = observebaseline.New(observebaseline.Config{
			Reader:   observer,
			Gates:    base,
			Resolver: resolver,
			Store:    b.Persist,
			Excluder: b.Malicious,
			Bucketer: bucketer,
			Floor:    opts.Floor,
		})
		base.UseFeatureSource(b.Aggregator)
	}

	// Scoring NEVER excludes the malicious set — NoExclusions only. The malicious
	// set is the aggregator's baseline-of-normal exclusion, not a scoring filter.
	scorer := scoring.New(opts.Window, calib, scoring.NoExclusions{}).UseMultiplier(base)

	tierCfg := tiers.DefaultConfig()
	if opts.Aggressive {
		tierCfg.ConfidenceRequired = map[contract.Tier]float64{
			contract.TierTag:     tiers.MinConfidence,
			contract.TierContain: tiers.MinConfidence,
			contract.TierJail:    tiers.MinConfidence,
		}
	}

	eng, err := engine.New(engine.Config{
		Resolver:    resolver,
		Scorer:      scorer,
		Decider:     tiers.StaticDecider{},
		Tiers:       tierCfg,
		Calibration: calib,
	})
	if err != nil {
		b.closePartial()
		return nil, err
	}

	// Capture every Tier≥Tag interaction into the durable EventStore (rule-9
	// anonymized). This is production-appropriate (D1 foundation); the labeler is
	// the only staging-specific wrapper and is added by cmd/staged-range.
	if b.Events != nil {
		b.Engine = &capturingEngine{inner: eng, events: b.Events, agg: b.Aggregator}
	} else {
		b.Engine = eng
	}
	return b, nil
}

// StartAggregator runs the observe-path fold loop until ctx is cancelled. It is
// a no-op if observe is disabled. Call it in a goroutine.
func (b *Built) StartAggregator(ctx context.Context) {
	if b.Aggregator != nil {
		b.Aggregator.Run(ctx)
	}
}

// Close shuts down: it closes the observer and the durable store. Durability is
// bbolt's — every committed write is already fsync'd, so there is nothing to
// flush on the way out beyond closing the handle.
func (b *Built) Close() error {
	var firstErr error
	if b.observer != nil {
		if err := b.observer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if b.Persist != nil {
		if err := b.Persist.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// closePartial tears down whatever was opened before a mid-Build failure.
func (b *Built) closePartial() {
	if b.observer != nil {
		_ = b.observer.Close()
	}
	if b.Persist != nil {
		_ = b.Persist.Close()
	}
}

// capturingEngine records each canary-touch verdict (Tier≥Tag) into the durable
// EventStore, attaching the derived feature vector. It is the production D1
// capture seam and contains no staging logic.
type capturingEngine struct {
	inner  contract.Engine
	events *boltevents.Store
	agg    *observebaseline.Aggregator
}

func (e *capturingEngine) Submit(ev contract.SignalEvent) (contract.Verdict, error) {
	v, err := e.inner.Submit(ev)
	if err != nil {
		return v, err
	}
	var feats map[string]float64
	if e.agg != nil {
		if f, ok := e.agg.Features(ev.Scope, ev.Flow, ev.Timestamp); ok {
			feats = observebaseline.FeaturesMap(f)
		}
	}
	_ = e.events.CaptureVerdict(ev, v, feats)
	return v, err
}
