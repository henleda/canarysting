// Package sharpen is D5-Phase-2 detection sharpening (docs/MOAT_DESIGN.md D5;
// docs/D2_D5_DESIGN.md §1.2): a per-scope store of CONFIRMED-MALICIOUS behavioral
// profiles, built from JAIL outcomes (Tier-3 verdicts — customer-reproducible ground
// truth, not analyst labels), that scores how strongly an emerging flow's behavior
// matches the confirmed set. That score is the FingerprintMatch strength the engine's
// baseline multiplier folds into M's additive sharpening term.
//
// IT MOVES M, NEVER TRIGGERS (rule 8). Match returns weight CONTEXT only — a [0,1]
// float — on a base that is zero without a canary touch; it can never manufacture a
// verdict or a jail (jail still requires the engine's own Tier-3 decision on distinct
// canary touches). The bounded cross-flow learning is intended: a jailed flow sharpens
// OTHER flows behaving like it (capped by M_max), gated so it takes hold only after the
// behavior is confirmed by ≥MinConfirmedJails DISTINCT jailed flows and is still fresh.
//
// Scope isolation is absolute (rule 5): the store is keyed by scope and never matches
// across scopes. The Store structurally satisfies baseline.Matcher (no import of
// engine/baseline — wired at the boot composition root).
//
// PERSISTENCE (deferred fast-follow): the confirmed-malicious set is held IN-MEMORY.
// MOAT_DESIGN.md D5 specifies a bbolt-persisted set rehydrated on boot; that is a
// tracked fast-follow. Until then a restart loses the set and it re-accrues from new
// jails. This is safe (losing the set only WEAKENS sharpening — it can never cause a
// trigger, rule 8) and adequate for current use: the live window runs passive (no
// jails), and a demo accrues the set in-session without a restart.
package sharpen

import (
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/profile"
)

const (
	// MinConfirmedJails is how many DISTINCT jailed flows must exhibit a behavior
	// before it sharpens OTHER flows — a confidence floor so one actor cannot, by
	// itself, sharpen the whole scope. (k=3-style; ≥2.)
	MinConfirmedJails = 3
	// FreshnessWindow ages out a confirmed behavior: a match only counts if the
	// behavior was last jailed within this window of the query time.
	FreshnessWindow = 30 * 24 * time.Hour
	// lookbackWindow bounds how far back a flow's events are gathered to derive its
	// behavioral profile (for both RecordJail and Match).
	lookbackWindow = time.Hour
)

// EventSource returns a scope's interaction events in [since, until]. Satisfied by
// intelligence/boltevents.Store.Query — per-scope, never crosses a scope (rule 5).
type EventSource interface {
	Query(scopeKey string, since, until time.Time) ([]intelligence.AdversaryInteractionEvent, error)
}

// entry is one confirmed-malicious behavior: its representative profile, the set of
// DISTINCT flows jailed exhibiting it (confirmed-jail count = len), and the freshest
// jail time.
type entry struct {
	prof     *profile.Profile
	flows    map[uint64]struct{} // distinct jailed flow cookies
	lastJail time.Time
}

// Store is the per-scope confirmed-malicious profile store. The zero value is not
// usable; construct with NewStore.
type Store struct {
	mu      sync.Mutex
	src     EventSource
	byScope map[contract.ScopeKey]map[uint64]*entry // scope -> BehavioralHash -> entry
}

// NewStore builds a Store reading flow events from src (e.g. the boltevents store).
func NewStore(src EventSource) *Store {
	return &Store{src: src, byScope: map[contract.ScopeKey]map[uint64]*entry{}}
}

// RecordJail records that flow was JAILED (Tier 3) in scope at time at — confirmed-
// malicious ground truth. It derives the flow's behavioral profile from its recent
// events and adds it to the scope's confirmed set, keyed by BehavioralHash and counting
// DISTINCT jailed flows. A no-op if the flow's profile cannot be derived (no events).
func (s *Store) RecordJail(scope contract.ScopeKey, flow contract.FlowIdentity, at time.Time) {
	p := s.deriveFlow(scope, flow, at)
	if p == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byHash := s.byScope[scope]
	if byHash == nil {
		byHash = map[uint64]*entry{}
		s.byScope[scope] = byHash
	}
	e := byHash[p.BehavioralHash]
	if e == nil {
		e = &entry{flows: map[uint64]struct{}{}}
		byHash[p.BehavioralHash] = e
	}
	e.prof = p // refresh the representative profile (whole-pointer replace; never mutated in place)
	e.flows[flow.SocketCookie] = struct{}{}
	if at.After(e.lastJail) {
		e.lastJail = at
	}
}

// Match implements baseline.Matcher: the [0,1] strength of flow's EMERGING behavior
// matching scope's confirmed-malicious set, gated by ≥MinConfirmedJails distinct jailed
// flows + freshness. It returns 0 FAST when the scope has no eligible confirmed
// behavior (cold start / the common case) — WITHOUT touching the event source — so the
// hot path (Multiplier → Match per flow) is unaffected until a scope is under
// confirmed attack. Weight context only; never a trigger (rule 8).
func (s *Store) Match(scope contract.ScopeKey, flow contract.FlowIdentity, at time.Time) float64 {
	// Snapshot the eligible confirmed profiles under the lock (cheap), then release it
	// BEFORE the event-source fetch + derive (the source takes its own lock; the
	// matcher must not hold this lock across that call — same B→A discipline the
	// baseline Multiplier uses).
	s.mu.Lock()
	var eligible []*profile.Profile
	for _, e := range s.byScope[scope] {
		if len(e.flows) >= MinConfirmedJails && at.Sub(e.lastJail) <= FreshnessWindow {
			eligible = append(eligible, e.prof)
		}
	}
	s.mu.Unlock()
	if len(eligible) == 0 {
		return 0 // cold-scope short-circuit: no confirmed behavior => no event fetch
	}
	emerging := s.deriveFlow(scope, flow, at)
	if emerging == nil {
		return 0
	}
	best := 0.0
	for _, cp := range eligible {
		if sim := emerging.Similarity(cp); sim > best {
			best = sim
		}
	}
	return best
}

// deriveFlow gathers flow's recent events in scope (within lookbackWindow of at) and
// derives its behavioral profile. nil if the source is unset, the query fails, or the
// flow has no events.
func (s *Store) deriveFlow(scope contract.ScopeKey, flow contract.FlowIdentity, at time.Time) *profile.Profile {
	if s.src == nil {
		return nil
	}
	evs, err := s.src.Query(string(scope), at.Add(-lookbackWindow), at)
	if err != nil {
		return nil
	}
	var flowEvents []intelligence.AdversaryInteractionEvent
	for _, e := range evs {
		if e.FlowID == flow.SocketCookie {
			flowEvents = append(flowEvents, e)
		}
	}
	return profile.DeriveProfile(flowEvents)
}
