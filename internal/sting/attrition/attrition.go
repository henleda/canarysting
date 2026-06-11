// Package attrition imposes multi-dimensional cost on automated/LLM-driven
// attackers across five axes: velocity disruption (latency/tarpit), information
// poisoning (fabricated environmental state that degrades the agent's decisions),
// opportunity-cost injection (consuming finite compute capacity; subsumes
// token-burning), exploit-inventory burn, and operational exposure. The cost lands
// whether the attacker is metered, self-hosted, or on stolen compute. It is the
// platform's differentiator. The mechanisms shipped here — tarpitting,
// plausible-endless fake directory/config mazes, and token-maximizing bait — are
// the velocity/information-poisoning/opportunity-cost subset; see docs/STING.md
// for the full taxonomy. All keep the defender's cost flat.
//
// Attrition is a pull-based STREAM, not a one-shot Respond: the driver (the future
// Envoy adapter at M4, or the local scripted-attacker harness) calls Next, writes
// the bytes, waits Chunk.Delay on its OWN timer, and repeats. Delay is DATA —
// attrition never sleeps and never spawns a goroutine, so it does O(1) work per
// chunk and structurally cannot burn the defender (CLAUDE.md rule: burn the
// attacker, not the defender).
//
// Safety posture (CLAUDE.md / docs/STING.md), enforced structurally, not by comment:
//   - Attrition begins at Tier 2 (Contain); below Tier 2 Open is a no-op.
//   - The aggressive ceiling SHIPS but the operator chooses the FLOOR. The default
//     floor is conservative (passive); aggressive generators are not even
//     constructed below FloorAggressive, and no Tier value alone raises the floor.
//   - Every generator is bounded (per-flow Budget) under a shared host-wide
//     Governor (global byte ceiling + concurrent-stream cap + kill switch).
//   - All generated bait is provably harmless (harmless.CrossScan), proven at
//     construction.
//
// This package imports ONLY internal/contract, internal/harmless, and stdlib. It
// does not import engine, canary, adapters, or intelligence (an import-graph test
// enforces it). The attacker-cost meter (Outcome) mirrors intelligence.StingOutcome
// field-for-field; the composition root copies it (dependency points inward).
package attrition

import (
	"context"
	"fmt"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

// Chunk is one drip from a Stream: the bytes to write+flush now, then how long the
// driver must wait before pulling Next again. Delay is data the driver schedules,
// never a sleep inside attrition.
type Chunk struct {
	Data  []byte
	Delay time.Duration
}

// Stream is a single attrition session bound to one flow. Pull-based and
// clock-free: it holds only a tiny fixed-size cursor and never sleeps. It is NOT
// safe for concurrent use by one flow; it is safe across flows (the Governor it
// shares is concurrency-safe). The driver MUST defer Close to release the flow's
// governor slot and any reserved bytes.
type Stream interface {
	// Next yields the next chunk. A non-NotDone reason means stop: Data is empty
	// and the driver closes. Context cancellation (client gone, engine signal)
	// ends the stream with DoneKilled. Errors are values; Next never panics.
	Next(ctx context.Context) (Chunk, DoneReason, error)
	// Outcome is the running attacker-cost meter (final after the stream ends).
	Outcome() Outcome
	// Observe feeds a structured digest of the attacker's inbound interaction for
	// the future axis-4/5 reaction signals. No-op in AX0; counts/bools/enums only
	// (rule 9). The seam exists so the driver (adapter) has a stable call site.
	Observe(contract.DriverObservation)
	// Close releases the governor slot + reserved bytes. Idempotent.
	Close() error
}

// Attritor opens per-flow streams. One process-wide Attritor owns the Governor;
// the floor and budget are bound at construction from operator config — never
// passed per call, so aggressive can never be a per-call surprise.
type Attritor interface {
	// Open returns a Stream for a verdict. It is a no-op stream (first Next yields
	// DoneNoOp/DoneKilled/DoneGlobalCeiling, zero bytes) when attrition must not
	// act: below Tier 2, unattributable flow, kill switch tripped, or the
	// concurrent-stream cap is saturated. Open always returns a usable Stream so
	// the driver has one uniform code path.
	Open(v contract.Verdict) Stream
	// Governor exposes the kill switch + live counters for the operator CLI and the
	// engine's host-pressure hook.
	Governor() *Governor
}

// Config configures an Attritor. The zero value is valid and conservative: zero
// Floor is FloorPassive, and New fills every budget/drip/governor default.
type Config struct {
	// Floor is the operator-selected maximum aggressiveness. Zero == FloorPassive.
	Floor contract.StingFloor
	// Budget bounds each flow. Zero fields normalize to documented caps.
	Budget Budget
	// Drip shapes slow-drip pacing. Zero fields normalize to documented defaults.
	Drip DripParams
	// Governor is the shared host-wide accountant. If nil, New builds one from
	// GlobalCeiling + MaxConcurrentFlows so several Attritors can share one host
	// budget by passing the same *Governor.
	Governor *Governor
	// GlobalCeiling / MaxConcurrentFlows build the default Governor when Governor
	// is nil. Zero => documented defaults.
	GlobalCeiling      int64
	MaxConcurrentFlows int
	// Seed is the base seed mixed with the flow's socket cookie to derive the
	// per-flow generation seed. Zero is fine (deterministic per cookie).
	Seed uint64
}

// BoundedAttritor is the standard Attritor: a fail-closed budget accountant
// fronting deterministic, provably-bounded generators.
type BoundedAttritor struct {
	cfg    Config
	budget Budget
	params genParams
	gov    *Governor
	gens   []generator // index 0 tarpit; 1 fake_tree (>=moderate); 2 token_bait (==aggressive)
}

var _ Attritor = (*BoundedAttritor)(nil)

// New builds an Attritor and PROVES every active generator is bounded + harmless
// at construction (the catalog build() discipline): it returns an error rather
// than ever constructing one whose generator could exceed its budget or emit a
// non-harmless chunk. Aggressive generators are constructed ONLY at
// FloorAggressive, so the brand ceiling is reachable only by explicit config.
func New(cfg Config) (*BoundedAttritor, error) {
	cfg.Budget = cfg.Budget.Normalized()
	cfg.Drip = cfg.Drip.Normalized()

	gov := cfg.Governor
	if gov == nil {
		gov = NewGovernor(cfg.GlobalCeiling, cfg.MaxConcurrentFlows)
	}

	params := genParams{MaxDepth: cfg.Budget.MaxDepth, Drip: cfg.Drip}

	// Construct only generators whose axis(es) the operator floor unlocks (overlap
	// test against StingFloor.Axes()). The ladder order — tarpit, fakeMaze,
	// tokenBait — is preserved so the most-aggressive constructed generator stays
	// the headline Mechanism. Because FloorPassive.Axes() is AxisVelocity only, the
	// dedicated opportunity-cost (tokenBait) / exploit / exposure generators are not
	// even constructed below their floor — aggressive can never be a silent default.
	floorAxes := cfg.Floor.Axes()
	var gens []generator
	for _, g := range []generator{tarpit{}, fakeMaze{}, tokenBait{}} {
		if g.axis()&floorAxes != 0 {
			gens = append(gens, g)
		}
	}

	for _, g := range gens {
		if err := g.selfTest(constructionSamples, params); err != nil {
			return nil, fmt.Errorf("attrition: generator %q failed construction self-test: %w", g.mechanism(), err)
		}
	}

	return &BoundedAttritor{cfg: cfg, budget: cfg.Budget, params: params, gov: gov, gens: gens}, nil
}

// Default returns a conservative (FloorPassive) Attritor. It panics only on the
// build-time impossibility that a shipped generator is not bounded/harmless — a
// condition the test suite guards, so it cannot occur in a shipped binary.
func Default() *BoundedAttritor {
	a, err := New(Config{})
	if err != nil {
		panic("attrition: default attritor is not bounded/harmless: " + err.Error())
	}
	return a
}

// Governor returns the shared host-wide accountant + kill switch.
func (a *BoundedAttritor) Governor() *Governor { return a.gov }

// Open applies the gate ordering (each gate returns the inert value before any
// work) and, if attrition may act, returns a live Stream.
func (a *BoundedAttritor) Open(v contract.Verdict) Stream {
	// 1. Below Tier 2 attrition never acts.
	if v.Tier < contract.TierContain {
		return &noopStream{reason: DoneNoOp}
	}
	// 2. Never act on a flow we cannot attribute (docs/STING.md precision rule).
	if v.Flow.SocketCookie == 0 {
		return &noopStream{reason: DoneNoOp}
	}
	// 3. Kill switch tripped (operator or engine).
	if a.gov.Killed() {
		return &noopStream{reason: DoneKilled}
	}
	// 4. Concurrent-stream cap (fd/goroutine-exhaustion guard). A successful
	//    OpenStream is paired with the stream's Close. OpenStream returns false for
	//    EITHER a saturated cap or a kill that landed after gate 3; re-check the
	//    kill so it is reported as DoneKilled, not misattributed to the host ceiling
	//    (D1/D3 must tell a kill apart from capacity exhaustion).
	if !a.gov.OpenStream() {
		if a.gov.Killed() {
			return &noopStream{reason: DoneKilled}
		}
		return &noopStream{reason: DoneGlobalCeiling}
	}

	sel := a.selectAxes(v.Tier)
	if len(sel) == 0 {
		// Unreachable in practice — tarpit (minTier=TierContain) is always
		// constructed and Open only proceeds at Tier>=TierContain — but never return
		// a live stream with no generator. Release the slot gate 4 reserved.
		a.gov.CloseStream()
		return &noopStream{reason: DoneNoOp}
	}
	var axes contract.AttritionAxis
	for _, g := range sel {
		axes |= g.axis()
	}
	headline := sel[len(sel)-1] // most-aggressive permitted generator: the KPI Mechanism
	return &stream{
		gens:   sel,
		gov:    a.gov,
		budget: a.budget,
		params: a.params,
		cur:    cursor{seed: a.cfg.Seed ^ v.Flow.SocketCookie},
		out:    Outcome{Mechanism: headline.mechanism(), Axes: axes},
	}
}

// selectAxes returns the active generator SET for a verdict's tier: every
// constructed generator whose minTier() permits this tier. The set composes the
// floor's unlocked axes that the tier allows — velocity + information poisoning
// from TierContain, the dedicated opportunity-cost / exploit / exposure generators
// only from TierJail. The stream rotates through the set per chunk (one shared
// cursor + Budget), so cost accrues across axes while the headline Mechanism stays
// the most-aggressive member (preserving the D3 by-mechanism KPI). Because a.gens
// was already constructed per floor, no tier value alone can raise the floor.
func (a *BoundedAttritor) selectAxes(t contract.Tier) []generator {
	var sel []generator
	for _, g := range a.gens {
		if g.minTier() <= t {
			sel = append(sel, g)
		}
	}
	return sel
}

// stream is the live per-flow attrition session.
type stream struct {
	gens     []generator // the active axis set, rotated per chunk; ladder order, sel[last] is the headline
	gov      *Governor
	budget   Budget
	params   genParams
	cur      cursor
	out      Outcome
	held     time.Duration // accumulated imposed delay (clock-free duration bound)
	reserved int64         // bytes reserved on the governor, released at Close
	closed   bool
}

var _ Stream = (*stream)(nil)

func (s *stream) Next(ctx context.Context) (Chunk, DoneReason, error) {
	if s.out.Reason != NotDone {
		return Chunk{}, s.out.Reason, nil // already ended; idempotent
	}
	// Gate order (fail-closed: the safe value is "done"):
	if ctx != nil {
		select {
		case <-ctx.Done():
			return s.finish(DoneKilled)
		default:
		}
	}
	if s.gov.Killed() {
		return s.finish(DoneKilled)
	}
	if s.held >= s.budget.MaxDuration {
		return s.finish(DoneFlowBudget)
	}
	remaining := s.budget.MaxBytesPerFlow - s.out.BytesServed
	if remaining <= 0 {
		return s.finish(DoneFlowBudget)
	}

	// Rotate the active generator per chunk so a multi-axis set imposes cost across
	// all its axes on one flow, sharing ONE cursor + Budget (composition never
	// multiplies the defender's bytes/hold). The index uses chunkIdx BEFORE next()
	// advances it, so rotation is deterministic per flow.
	active := s.gens[s.cur.chunkIdx%len(s.gens)]
	data, delay, ok := active.next(&s.cur, s.params)
	if !ok {
		return s.finish(DoneComplete)
	}
	// Per-flow byte cap: trim to what fits; never emit over the cap.
	if int64(len(data)) > remaining {
		data = truncateAtLine(data, int(remaining))
		if len(data) == 0 {
			return s.finish(DoneFlowBudget)
		}
	}
	// Host-wide ceiling: reserve before emitting (fail-closed).
	if !s.gov.Reserve(int64(len(data))) {
		return s.finish(DoneGlobalCeiling)
	}
	s.reserved += int64(len(data))

	s.out.BytesServed += int64(len(data))
	s.out.RequestsAbsrb++
	s.out.TokenCostProxy += tokenProxy(active.mechanism(), len(data))
	s.held += delay
	s.out.TimeHeldSec = s.held.Seconds()
	if s.cur.depth > s.out.DepthReached {
		s.out.DepthReached = s.cur.depth
	}
	return Chunk{Data: data, Delay: delay}, NotDone, nil
}

func (s *stream) finish(r DoneReason) (Chunk, DoneReason, error) {
	s.out.Reason = r
	// DisengageReason is the adapter's to set (D7): the stream cannot tell a client
	// disconnect from the defender's max-hold deadline (both arrive as a cancelled
	// ctx → DoneKilled). It stays contract.DisengageUnknown here.
	return Chunk{}, r, nil
}

// Observe feeds a structured digest of the attacker's inbound interaction for the
// future axis-4 (exploit-inventory burn) and axis-5 (operational exposure)
// reaction signals. It is a no-op seam in AX0 — the call site exists so the driver
// (adapter) is stable; AX4/AX5 populate Outcome.ExploitsObserved/ExposureSignals
// from the digest. Counts/bools/enums only (rule 9 — DriverObservation carries no
// raw bytes/addresses).
func (s *stream) Observe(contract.DriverObservation) {}

func (s *stream) Outcome() Outcome { return s.out }

func (s *stream) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if s.reserved > 0 {
		s.gov.Release(s.reserved)
		s.reserved = 0
	}
	s.gov.CloseStream()
	if s.out.Reason == NotDone {
		s.out.Reason = DoneComplete
	}
	return nil
}

// noopStream is the inert stream returned when attrition must not act. Its first
// Next reports why; Close is a no-op (it reserved nothing).
type noopStream struct{ reason DoneReason }

var _ Stream = (*noopStream)(nil)

func (n *noopStream) Next(context.Context) (Chunk, DoneReason, error) {
	return Chunk{}, n.reason, nil
}

func (n *noopStream) Outcome() Outcome { return Outcome{Mechanism: MechNoOp, Reason: n.reason} }

func (n *noopStream) Observe(contract.DriverObservation) {}

func (n *noopStream) Close() error { return nil }
