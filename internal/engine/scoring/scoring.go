// Package scoring computes a flow's suspicion score: one windowed, weighted
// function over distinct canary interactions within a scope. Weights start
// uniform (raw count) and are learned per scope by calibration. There is no
// separate "count mode" — uniform weights ARE the count. See docs/ENGINE.md.
package scoring

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

// DefaultWindow is the correlation window default (a few minutes), per
// docs/ENGINE.md: repeated touches inside it count more than the same touches
// spread over hours.
const DefaultWindow = 5 * time.Minute

// DefaultMaxCookiesPerScope bounds the number of distinct per-flow (socket
// cookie) scoring entries kept alive for a single scope. Per-flow scoring state
// is otherwise never reclaimed, so over a multi-week pilot of real east-west
// traffic the per-cookie map would grow without bound and eventually OOM the
// engine. This is a memory-safety ceiling, NOT a learned parameter: it changes
// no flow's score (an evicted idle flow had already aged out of its correlation
// window, so it scores from scratch on its next touch exactly as a new flow
// would). The cap is generous enough to hold every flow plausibly active inside
// one window in a busy environment; once exceeded, the least-recently-touched
// flows are reaped first. See docs/ENGINE.md.
const DefaultMaxCookiesPerScope = 100_000

// Window is the correlation window; repeated touches inside it count more than
// the same touches spread over hours. Default to a few minutes via config.
type Window struct {
	Duration time.Duration
}

// Scorer holds per-scope weights and computes scores. All state is scope-keyed;
// nothing is shared across scopes. See docs/SCOPE.md.
type Scorer interface {
	// Score returns the current suspicion score for a flow in a scope, given a
	// new event. Implementations apply benign-exclusion before scoring.
	Score(scope contract.ScopeKey, ev contract.SignalEvent) (float64, error)
}

// Weights supplies the live per-scope weight for a canary type. It is satisfied
// by calibration.Store: uniform 1.0 in cold start, learned once calibrated. The
// scorer does not know or care whether a weight is uniform or learned — that
// keeps the "one weighted model whose weights evolve" rule (docs/ENGINE.md).
type Weights interface {
	Weight(contract.ScopeKey, contract.CanaryType) float64
}

// BenignExcluder is the first-class benign-exclusion input. Excluded flows
// (service accounts, monitoring, scheduled tasks) never accrue score, so a
// benign brush of a canary never escalates them. Exclusion is explicit and
// configurable, never buried in scoring internals. See docs/ENGINE.md.
type BenignExcluder interface {
	Excluded(contract.FlowIdentity) bool
}

// NoExclusions excludes nothing. It is the explicit default.
type NoExclusions struct{}

// Excluded always returns false.
func (NoExclusions) Excluded(contract.FlowIdentity) bool { return false }

// MultiplierSource yields the per-flow baseline multiplier M for a scope at
// scoring time, so the score is Score = B × M (docs/BASELINE_MULTIPLIER.md).
// M ∈ [1, M_max]; it is satisfied by baseline.Store. The scorer treats a value
// below 1 as a bug and clamps it to 1 — the floor-of-one invariant holds even if
// a source misbehaves.
type MultiplierSource interface {
	Multiplier(scope contract.ScopeKey, flow contract.FlowIdentity, at time.Time) float64
}

// NeutralMultiplier always returns 1.0 — touch-only scoring. It is the explicit
// default until a calibrated, live baseline (M7) is wired in.
type NeutralMultiplier struct{}

// Multiplier always returns 1.0.
func (NeutralMultiplier) Multiplier(contract.ScopeKey, contract.FlowIdentity, time.Time) float64 {
	return 1.0
}

// WindowedScorer is the windowed weighted-sum Scorer. For each (scope, flow) it
// remembers the last touch time of each distinct canary type and, at score time,
// sums the weights of the types touched within the trailing window. A type
// touched repeatedly counts once (distinct), but keeps the flow's score alive
// while touches stay inside the window.
//
// A flow is keyed by its socket cookie (docs/IDENTITY.md) — the cross-boundary
// join key. A real flow always carries a non-zero cookie once the kernel join
// (M5) is in place; pure-Go tests set explicit cookies.
type WindowedScorer struct {
	mu         sync.Mutex
	window     time.Duration
	weights    Weights
	excluder   BenignExcluder
	multiplier MultiplierSource
	// maxPerScope caps the live per-flow entries kept for one scope. Once a
	// scope exceeds it, the least-recently-touched flows are reaped. A flow is
	// only ever a candidate for the cap once it is idle (its newest touch has
	// aged out of the correlation window), so the cap never changes an active
	// flow's score. See DefaultMaxCookiesPerScope.
	maxPerScope int
	// state[scope][socketCookie] holds one flow's windowed scoring state.
	state map[contract.ScopeKey]map[uint64]*flowState
}

// flowState is one flow's (one socket cookie's) windowed scoring state within a
// scope: the last touch time of each distinct canary type, plus the flow's
// most-recent touch time. lastTouch is the reaper's recency key — it lets the
// reaper evict idle flows (newest touch older than the window) and, on a size
// overflow, the least-recently-touched flows first, without scanning the inner
// per-type map. lastTouch always equals the max of the per-type times, so it is
// exactly "is this flow still inside its correlation window".
type flowState struct {
	touches   map[contract.CanaryType]time.Time
	lastTouch time.Time
}

// New returns a WindowedScorer. A zero window falls back to DefaultWindow; a nil
// excluder falls back to NoExclusions. The baseline multiplier defaults to
// NeutralMultiplier (M = 1, touch-only); use UseMultiplier to wire a baseline.
// weights is required.
func New(window time.Duration, weights Weights, excluder BenignExcluder) *WindowedScorer {
	if window <= 0 {
		window = DefaultWindow
	}
	if excluder == nil {
		excluder = NoExclusions{}
	}
	return &WindowedScorer{
		window:      window,
		weights:     weights,
		excluder:    excluder,
		multiplier:  NeutralMultiplier{},
		maxPerScope: DefaultMaxCookiesPerScope,
		state:       map[contract.ScopeKey]map[uint64]*flowState{},
	}
}

// WithMaxCookiesPerScope overrides the per-scope live-flow cap (default
// DefaultMaxCookiesPerScope). A non-positive value is ignored (the cap stays at
// its current value); the cap is a memory-safety ceiling, never disabled.
// Returns the scorer for chaining.
func (s *WindowedScorer) WithMaxCookiesPerScope(n int) *WindowedScorer {
	if n > 0 {
		s.mu.Lock()
		s.maxPerScope = n
		s.mu.Unlock()
	}
	return s
}

// UseMultiplier wires the baseline multiplier source. A nil source is ignored
// (the scorer keeps its current source). Returns the scorer for chaining.
func (s *WindowedScorer) UseMultiplier(m MultiplierSource) *WindowedScorer {
	if m != nil {
		s.mu.Lock()
		s.multiplier = m
		s.mu.Unlock()
	}
	return s
}

// Score records the event's touch and returns the flow's current windowed,
// weighted score within the scope. Benign-excluded flows score 0 and accrue
// nothing. The score is always computed within a single scope, never across.
func (s *WindowedScorer) Score(scope contract.ScopeKey, ev contract.SignalEvent) (float64, error) {
	if scope == "" {
		return 0, errors.New("scoring: empty scope; resolve scope before scoring")
	}
	if s.weights == nil {
		return 0, errors.New("scoring: nil weights source")
	}
	// Benign exclusion is applied before scoring: an excluded flow never accrues.
	if s.excluder.Excluded(ev.Flow) {
		return 0, nil
	}

	key := ev.Flow.SocketCookie
	cutoff := ev.Timestamp.Add(-s.window)

	s.mu.Lock()
	defer s.mu.Unlock()

	byFlow := s.state[scope]
	if byFlow == nil {
		byFlow = map[uint64]*flowState{}
		s.state[scope] = byFlow
	}
	fs := byFlow[key]
	if fs == nil {
		fs = &flowState{touches: map[contract.CanaryType]time.Time{}}
		byFlow[key] = fs
	}
	fs.touches[ev.Canary] = ev.Timestamp
	if ev.Timestamp.After(fs.lastTouch) {
		fs.lastTouch = ev.Timestamp
	}

	// Reap idle/expired per-flow state before computing the score, so a long-
	// lived stream of distinct flows can never grow the map without bound. This
	// is driven by the event timestamp (not wall-clock), so it is deterministic
	// and race-clean under the held lock. It never touches the flow being scored
	// (key) — that flow is recomputed below from its own live touches — so an
	// active flow's score is unaffected by a reap. See docs/ENGINE.md.
	s.reap(byFlow, key, cutoff)

	// B: the windowed weighted base over distinct touches in the window.
	var base float64
	for ct, last := range fs.touches {
		if last.Before(cutoff) {
			delete(fs.touches, ct) // expired out of the window; drop it
			continue
		}
		base += s.weights.Weight(scope, ct)
	}

	// Score = B × M. M is a per-flow property (floored at one), so it multiplies
	// the whole base. If base == 0, the product is 0 for any M — the guardrail in
	// arithmetic (docs/BASELINE_MULTIPLIER.md §2). Clamp a misbehaving source up
	// to the floor of one; never let M suppress the base.
	m := s.multiplier.Multiplier(scope, ev.Flow, ev.Timestamp)
	if m < 1 {
		m = 1
	}
	return base * m, nil
}

// reap bounds the per-flow scoring map for one scope. It runs under s.mu, driven
// by the current event's window cutoff (logical time, not wall-clock). It must
// never drop the flow currently being scored (keep) and must never change an
// active (in-window) flow's score.
//
// Two passes:
//  1. TTL eviction. Any flow whose newest touch (lastTouch) is strictly before
//     the window cutoff is idle: every one of its touches has aged out of the
//     correlation window, so it would contribute a zero base on its next score
//     regardless. Dropping it is equivalent to letting it score from scratch as
//     a new flow — no active flow loses score. The boundary is strict (Before)
//     to match the score loop, which retains a touch at exactly lastTouch ==
//     cutoff; a flow on that exact boundary is kept here and reaped on the next
//     event past it. This also reclaims flows whose last touch self-expired (the
//     empty-state case).
//  2. Size cap. If the scope still exceeds maxPerScope after TTL eviction, evict
//     the least-recently-touched flows (smallest lastTouch first) until back at
//     the cap. Only flows that survived pass 1 are still in-window, so the cap
//     is a hard ceiling that bites only under a genuine flood of concurrently
//     active flows; under that load the oldest in-window flows are sacrificed
//     first to keep memory bounded — the documented memory-safety tradeoff.
//
// keep (the flow just touched) is exempt from both passes.
func (s *WindowedScorer) reap(byFlow map[uint64]*flowState, keep uint64, cutoff time.Time) {
	for cookie, fs := range byFlow {
		if cookie == keep {
			continue
		}
		// Strictly before cutoff means no touch survives the window: idle. This
		// matches the score loop's retention boundary exactly — that loop keeps a
		// touch at last == cutoff (it drops only on last.Before(cutoff)). Using
		// the same Before(cutoff) test here ensures the reaper never evicts a flow
		// the score loop would still treat as active, so an active flow's score is
		// never changed at the exact-boundary instant. A flow whose lastTouch is
		// exactly cutoff is kept now and reaped on the next event past it.
		if fs.lastTouch.Before(cutoff) {
			delete(byFlow, cookie)
		}
	}

	if s.maxPerScope <= 0 || len(byFlow) <= s.maxPerScope {
		return
	}

	// Over the cap with everything in-window: evict least-recently-touched
	// flows (never keep) until at the cap. The O(n log n) sort below runs ONLY
	// on this over-cap path (the early return above gates it), so the common
	// case — TTL eviction keeping the scope at or under maxPerScope — pays only
	// the O(n) pass-1 scan and never sorts. The sort is bounded by the current
	// scope's live-flow count and reached only under a genuine flood of
	// concurrently in-window flows, which is exactly when paying for an exact
	// LRU ordering is worth it. A cheaper partial selection is possible but not
	// warranted while this stays an over-cap-only safety valve.
	type entry struct {
		cookie uint64
		last   time.Time
	}
	candidates := make([]entry, 0, len(byFlow))
	for cookie, fs := range byFlow {
		if cookie == keep {
			continue
		}
		candidates = append(candidates, entry{cookie: cookie, last: fs.lastTouch})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].last.Before(candidates[j].last)
	})
	for i := 0; i < len(candidates) && len(byFlow) > s.maxPerScope; i++ {
		delete(byFlow, candidates[i].cookie)
	}
}
