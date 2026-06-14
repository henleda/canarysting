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
	"encoding/json"
	"fmt"
	"log"
	"sync"
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
	"github.com/canarysting/canarysting/internal/intelligence/network"
	"github.com/canarysting/canarysting/internal/intelligence/sharedset"
	"github.com/canarysting/canarysting/internal/intelligence/sharpen"
	"github.com/canarysting/canarysting/internal/intelligence/transport"
)

// Options configures the composition.
type Options struct {
	Boundary   string        // operator scope boundary; empty => refuse to start
	Window     time.Duration // scoring correlation window
	Aggressive bool          // demo/eval: minimum per-tier confidence (single-touch escalation)
	// DemoEscalation is a DEMO-ONLY middle escalation band (not single-touch
	// -aggressive, not the production default): a flow TAGS on touch 1, CONTAINS (the
	// inline attrition pump begins — tarpit/maze/poison) around touch ~3, and JAILS
	// around touch ~5 at M=1 — a credible 3-5-touch bleed BEFORE the kernel jail,
	// independent of whether the baseline multiplier is live. Mutually exclusive with
	// Aggressive. NEVER for production (jail must stay operator-elected).
	DemoEscalation bool
	// ContainInline makes Tier 2 (Contain) verdicts INLINE so the adapter runs the
	// M6 attrition pump (held tarpit + deception body, with the real attacker-cost
	// outcome reported back) instead of the default async kernel-enforced path.
	// Tier 3 (Jail) stays async (kernel-enforced). Mode is operator-choosable only
	// for the action tiers (tiers.Config.Validate), so this is a legal config.
	ContainInline bool
	// JailInline makes Tier 3 (Jail) verdicts INLINE (instead of the default async
	// kernel-jail) so the adapter runs the attrition pump for the jailed flow and
	// REPORTS its outcome — which is what drains the pending jail into RecordJail
	// (D5-2) and emits the cross-scope confirmation (D6-3). Without it an async
	// kernel jail drops the socket before any outcome is reported, so a contributing
	// scope never emits a confirmation. For STAGED CONTRIBUTOR scopes; the
	// production/server kernel-jail-precision path leaves this off. Validate()
	// permits Mode on the action tiers.
	JailInline     bool
	BaselineDBPath string // bbolt path; "" => no durability (in-memory baseline)
	ObserveCgroup  string // cgroup v2 path; "" => observe disabled (touch-only, M=1)
	CoarseBucketer bool   // true => WindowBucketer (M7 window); false => DefaultBucketer (production)
	Floor          observebaseline.DataFloor
	// ResetOnSchemaMismatch, when true, DISCARDS a persisted baseline whose schema
	// version differs from this build (logged loudly) instead of refusing to start.
	// Default false: refuse, so a learning window is never silently lost.
	ResetOnSchemaMismatch bool

	// --- D6 cross-customer network (independent opt-in toggles; default false) ---
	// Contribute opts this deployment in to CONTRIBUTE anonymized patterns: a local
	// Tier-3 jail records the jailed flow's coarse pattern into the cross-scope ledger
	// (the producer half). Nothing crosses until a pattern reaches k>=3 distinct scopes.
	Contribute bool
	// Consume opts this deployment in to CONSUME the cross-customer set: received
	// SharedPatterns sharpen M for matching local flows (detection context only, rule 8).
	Consume bool
	// SharedSpoolPath, when Consume is set, is the NDJSON spool of cleared patterns to
	// load at boot (D6f file transport). "" => consume nothing.
	SharedSpoolPath string
	// ScopeToken is this deployment's OPAQUE, random, aggregator-issued cross-scope token
	// (D63b) — NEVER the raw ScopeKey. When Contribute is set + ConfirmSpoolPath is given,
	// each local Tier-3 jail emits a confirmation under this token to the D6-3 aggregator.
	ScopeToken string
	// ConfirmSpoolPath, when Contribute is set + ScopeToken is given, is the NDJSON
	// confirmation spool (this deployment -> the central aggregator, D6-3). "" => emit none.
	ConfirmSpoolPath string
}

// Built holds the composed engine and the handles a binary wires further or
// closes.
type Built struct {
	Engine          contract.Engine // possibly wrapped to capture interaction events
	Intake          *feedback.Intake
	Calib           *calibration.Store
	Baseline        *baseline.Store
	Resolver        scope.Resolver
	Persist         *persist.Store                // nil if no DB
	Aggregator      *observebaseline.Aggregator   // nil if observe disabled
	Malicious       *observebaseline.MaliciousSet // nil if observe disabled
	Events          *boltevents.Store             // nil if no DB
	OutcomeReporter contract.OutcomeReporter      // nil if no DB (no durable event store to amend)
	Sharpen         *sharpen.Store                // D5-Phase-2 confirmed-malicious matcher; nil if no DB
	Ledger          *network.Ledger               // D6 cross-scope SeenInScopes ledger; nil if no DB
	SharedSet       *sharedset.Store              // D6 cross-customer consumer (detection context); nil if no DB

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
	// D5-Phase-2: opt into detection sharpening at the composition root. The library
	// DefaultParams stays α=0 (the safe default for callers/tests + the reconstruction
	// paths without a matcher); here we set α so a confirmed-malicious fingerprint match
	// can lift M. α is inert until BOTH a Matcher is wired (below, only with the DB) AND
	// a scope has ≥MinConfirmedJails confirmed jails — match is 0 otherwise, leaving M
	// byte-identical to the pre-D5 baseline.
	bparams := baseline.DefaultParams()
	bparams.SharpeningAlpha = baseline.DefaultSharpeningAlpha
	base := baseline.New(baseline.Config{
		Params:     bparams,
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
		// D5-Phase-2: the confirmed-malicious profile store reads flow events from the
		// durable EventStore and structurally satisfies baseline.Matcher. Wired only
		// with the DB present (it needs the event source); it is fed jail outcomes from
		// the capturingEngine (a Tier-3 verdict at Submit, recorded once the amended
		// five-axis outcome lands at ReportOutcome). Match cold-scope-short-circuits to 0
		// until a scope has confirmed jails, so the hot path is unaffected. NOTE: the
		// store is currently IN-MEMORY — the confirmed-malicious set rebuilds from new
		// jails after a restart (bbolt persistence is a documented fast-follow; the live
		// passive window has no jails, and a demo accrues the set in-session).
		b.Sharpen = sharpen.NewStore(b.Events)

		// D6 cross-customer network. The ledger is this deployment's trusted cross-scope
		// SeenInScopes source (the producer half — fed by local jails when Contribute is
		// set). The shared-set consumer holds patterns received from OTHER deployments and
		// sharpens M for matching local flows — DETECTION CONTEXT ONLY (rule 8): it feeds
		// the SAME single FingerprintMatch dimension as the local confirmed-malicious
		// store, via a composite Matcher (max of the two). An inbound pattern can never
		// trigger or count toward the local jail-floor (D6h). The shared set is empty
		// unless Consume is set, so the composite is byte-identical to D5-Phase-2 alone
		// until this deployment actually consumes the network.
		if l, err := network.NewLedger(); err != nil {
			log.Printf("boot: WARNING cross-scope ledger unavailable (%v); D6 contribution disabled (fail-closed)", err)
		} else {
			b.Ledger = l
		}
		b.SharedSet = sharedset.NewStore(b.Events)
		base.UseMatcher(matcherSet{local: b.Sharpen, shared: b.SharedSet})

		// Consume: load the received cross-customer patterns from the spool (D6f). Gated
		// on the Consume opt-in (D6g) — an un-consuming deployment loads nothing.
		if opts.Consume && opts.SharedSpoolPath != "" {
			patterns, err := transport.NewSpool(opts.SharedSpoolPath).Receive()
			if err != nil {
				log.Printf("boot: WARNING some shared patterns failed to parse (skipped): %v", err)
			}
			for _, sp := range patterns {
				b.SharedSet.Add(sp)
			}
			log.Printf("boot: D6 consume: loaded %d cross-customer pattern(s) from %s", b.SharedSet.Len(), opts.SharedSpoolPath)
		}
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
	} else if opts.DemoEscalation {
		// DEMO-ONLY middle band: at M=1 (touch-count scoring) a flow Tags on touch 1,
		// Contains (the inline pump begins) around touch ~3, and Jails around touch ~5 —
		// a credible 3-5-touch bleed before the kernel jail, not the -aggressive single
		// touch. Production strictness is untouched (this is gated behind the flag).
		tierCfg.ConfidenceRequired = map[contract.Tier]float64{
			contract.TierTag:     0.01,
			contract.TierContain: 0.30,
			contract.TierJail:    0.50,
		}
	}
	if opts.ContainInline {
		// Tier 2 inline => the adapter runs the attrition pump (M6). Tier 3 stays
		// async (kernel jail). Validate() permits Mode on the action tiers.
		tierCfg.Mode[contract.TierContain] = contract.ModeInline
	}
	if opts.JailInline {
		// Tier 3 inline => the jailed flow's attrition outcome is reported back, which
		// drains the pending jail into RecordJail (D5-2) and emits the D6-3 confirmation.
		// Without this an async kernel jail swallows the outcome and nothing crosses.
		tierCfg.Mode[contract.TierJail] = contract.ModeInline
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
		ce := &capturingEngine{inner: eng, events: b.Events, agg: b.Aggregator, sharpen: b.Sharpen, pendingJails: map[uint64]struct{}{}, ledger: b.Ledger, contribute: opts.Contribute}
		// D6-3: emit cross-scope confirmations to the central aggregator on each local
		// jail, only when contributing + a token + a spool path are all configured.
		if opts.Contribute && opts.ConfirmSpoolPath != "" && opts.ScopeToken != "" {
			ce.confirmSpool = transport.NewConfirmSpool(opts.ConfirmSpoolPath)
			ce.scopeToken = opts.ScopeToken
		}
		b.Engine = ce
		b.OutcomeReporter = ce // the same capturing layer amends the durable store
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
	inner   contract.Engine
	events  *boltevents.Store
	agg     *observebaseline.Aggregator
	sharpen *sharpen.Store // D5-Phase-2: fed jail outcomes; nil if no DB

	// pendingJails bridges the two halves of a jail (D5-2): Submit knows the TIER
	// (v.Tier==TierJail) but the flow's StingOutcome is still zero then (attrition
	// runs later, adapter-side); ReportOutcome carries the AMENDED five-axis outcome
	// but no tier. So Submit marks the jailed cookie here, and ReportOutcome — after
	// AmendOutcome has written the real outcome — drains it into RecordJail, so the
	// confirmed-malicious profile is derived from events that carry the full attrition
	// signature. Bounded (maxPendingJails) so async/kernel jails that never report an
	// outcome cannot leak it unboundedly.
	mu           sync.Mutex
	pendingJails map[uint64]struct{} // jailed flow cookies awaiting their outcome

	// D6 contribution (producer half): on a local jail, the jailed flow's coarse
	// pattern is recorded into the cross-scope ledger, gated on the Contribute opt-in.
	// Nothing crosses until that pattern reaches k>=3 distinct scopes (the egress gate).
	ledger     *network.Ledger // nil if no DB or the CSPRNG was unavailable (fail-closed)
	contribute bool

	// D6-3 cross-scope emit: on a local jail, also confirm the coarse pattern to the
	// central aggregator under this deployment's opaque token. nil/empty => no emit.
	confirmSpool *transport.ConfirmSpool
	scopeToken   string
}

// maxPendingJails bounds pendingJails: a Tier-3 jail enforced async/in-kernel may
// never report an inline outcome, leaving its cookie pending. Past this cap we stop
// marking (a missed sharpen is acceptable; an unbounded map is not).
const maxPendingJails = 4096

// matcherSet composes the local confirmed-malicious matcher (D5-Phase-2 sharpen) and the
// cross-customer shared-set matcher (D6) into the SINGLE baseline.Matcher the engine
// sees, returning the MAX of the two strengths — so a flow is sharpened by whichever of
// {a locally-confirmed repeat, a cross-customer pattern} matches it more strongly, via
// the SAME FingerprintMatch dimension and the SAME M_max cap. Both are weight context
// only (rule 8). Nil members are skipped (a partial composition contributes 0).
type matcherSet struct {
	local  baseline.Matcher
	shared baseline.Matcher
}

func (m matcherSet) Match(scope contract.ScopeKey, flow contract.FlowIdentity, at time.Time) float64 {
	best := 0.0
	if m.local != nil {
		best = m.local.Match(scope, flow, at)
	}
	if m.shared != nil {
		if s := m.shared.Match(scope, flow, at); s > best {
			best = s
		}
	}
	return best
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
	// D5-Phase-2: a Tier-3 (jail) verdict is confirmed-malicious ground truth. We do
	// NOT record the profile here — at Submit time the flow's StingOutcome is still
	// zero (attrition runs later, adapter-side), so the derived profile would lack the
	// five-axis engagement signature. Instead mark the cookie pending; ReportOutcome
	// records it once the real outcome has been amended in (the D5-2 ReportOutcome path).
	// Rule 8: this only records evidence + later moves M; it never triggers a jail —
	// the jail was the engine's own Tier-3 decision on real canary touches.
	if v.Tier == contract.TierJail && e.sharpen != nil {
		e.mu.Lock()
		if len(e.pendingJails) < maxPendingJails {
			e.pendingJails[ev.Flow.SocketCookie] = struct{}{}
		}
		e.mu.Unlock()
	}
	return v, err
}

// ReportOutcome amends the durable interaction event with a real attrition
// outcome reported by the adapter after a Tier 2/3 inline verdict (the verdict-
// time Submit stored a zero outcome; attrition runs later, adapter-side). It
// satisfies contract.OutcomeReporter so the gRPC server can route ReportOutcome
// here without importing intelligence.
func (e *capturingEngine) ReportOutcome(rec contract.OutcomeRecord) error {
	err := e.events.AmendOutcome(rec)
	// D5-Phase-2: if this outcome belongs to a flow that was jailed (marked pending by
	// Submit), the durable events now carry the amended five-axis outcome — so derive
	// and record the confirmed-malicious profile NOW (rule 8: records evidence only).
	// Only fires for a previously-jailed cookie, and AFTER AmendOutcome has run, so the
	// profile reflects the full attrition signature.
	if e.sharpen != nil {
		e.mu.Lock()
		_, jailed := e.pendingJails[rec.SocketCookie]
		if jailed {
			delete(e.pendingJails, rec.SocketCookie)
		}
		e.mu.Unlock()
		if jailed {
			p := e.sharpen.RecordJail(rec.Scope, contract.FlowIdentity{SocketCookie: rec.SocketCookie}, time.UnixMilli(rec.TimestampUnixMs))
			// D6e (contribution): a local jail is this scope's confirmed-malice ground
			// truth — record its coarse pattern into the cross-scope ledger so the SAME
			// pattern, once exhibited by k>=3 distinct scopes, may cross the egress gate.
			// Gated on the Contribute opt-in; the SAME derived profile feeds both stores
			// (no second query). Recording is NOT an export — nothing crosses here.
			if p != nil && e.contribute && e.ledger != nil {
				_, _ = e.ledger.RecordForm(string(rec.Scope), p.ToExportForm())
			}
			// D6-3 (cross-scope ingest): ALSO emit a confirmation to the central
			// aggregator under this deployment's OPAQUE token — never the raw ScopeKey
			// (D63b). The confirmation carries the same coarse cleared pattern; the
			// aggregator re-validates it + counts distinct enrolled tokens toward k.
			if p != nil && e.confirmSpool != nil && e.scopeToken != "" {
				if b, mErr := json.Marshal(p.ToExportForm()); mErr == nil {
					_ = e.confirmSpool.SendConfirmation(e.scopeToken, b)
				}
			}
		}
	}
	return err
}
