// Package sharedset is the D6 cross-customer CONSUMER: it holds the anonymized patterns
// received from OTHER deployments and scores how strongly an emerging local flow matches
// any of them, as DETECTION CONTEXT ONLY (rule 8 / D6h). The score is the same single
// FingerprintMatch dimension D5-Phase-2 built — so a shared pattern sharpens M for a
// flow ALREADY touching canaries here, exactly like a local confirmed-malicious profile,
// bounded by M_max, on a base that is 0 without a touch. It can NEVER manufacture a
// jail, and an inbound pattern NEVER becomes local confirmed-malice or counts toward the
// local jail-floor: it lives in THIS separate store that Match scans but no local-jail
// path (sharpen.RecordJail / MinConfirmedJails) ever touches (§5.4).
//
// The shared patterns are already-anonymized, Clear()-ed coarse tuples — the sanctioned
// rule-5 exception for egress-cleared patterns. They are global cross-customer
// intelligence (not per-scope); the EMERGING flow's profile is always derived from its
// OWN scope's events (scope-isolated, rule 5). The Store structurally satisfies
// baseline.Matcher (no import of engine/baseline — wired at the boot composition root).
package sharedset

import (
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/network"
	"github.com/canarysting/canarysting/internal/intelligence/profile"
)

// lookbackWindow bounds how far back an emerging flow's events are gathered to derive
// its behavioral profile (mirrors sharpen).
const lookbackWindow = time.Hour

// EventSource returns a scope's interaction events in [since, until]. Satisfied by
// intelligence/boltevents.Store.Query — per-scope, never crosses a scope (rule 5).
type EventSource interface {
	Query(scopeKey string, since, until time.Time) ([]intelligence.AdversaryInteractionEvent, error)
}

// Store holds the received cross-customer shared patterns (sparse-lifted profiles, each
// with BehavioralHash==0 so a self-match fast-path can never fire — D6h). The zero value
// is not usable; construct with NewStore.
type Store struct {
	mu       sync.RWMutex
	src      EventSource
	patterns []*profile.Profile
}

// NewStore builds a Store reading emerging-flow events from src (the boltevents store).
func NewStore(src EventSource) *Store {
	return &Store{src: src}
}

// Add ingests a received SharedPattern as detection context. The caller gates on the
// Consume opt-in (D6g) — an un-consuming deployment never calls this, so its store stays
// empty and contributes nothing. Sparse-lift drops the sequence and zeroes the hash.
func (s *Store) Add(sp network.SharedPattern) {
	p := profile.FromSharedPattern(sp)
	if p == nil {
		return
	}
	s.mu.Lock()
	s.patterns = append(s.patterns, p)
	s.mu.Unlock()
}

// Len reports how many shared patterns are held (observability / tests).
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.patterns)
}

// Match implements baseline.Matcher: the [0,1] strength of flow's EMERGING behavior
// matching ANY shared cross-customer pattern. It returns 0 FAST when there are no shared
// patterns (the common case) WITHOUT touching the event source — so the per-flow
// Multiplier hot path is unaffected until this deployment has actually consumed
// patterns. Weight context only; never a trigger (rule 8). It NEVER records and NEVER
// counts toward a jail-floor (D6h).
func (s *Store) Match(scope contract.ScopeKey, flow contract.FlowIdentity, at time.Time) float64 {
	// Snapshot the shared patterns under the lock, release BEFORE the event-source fetch
	// (the source takes its own lock — same B->A discipline as sharpen / the baseline
	// Multiplier). The pointers are immutable after the lift (Add only appends).
	s.mu.RLock()
	if len(s.patterns) == 0 {
		s.mu.RUnlock()
		return 0 // cold short-circuit: nothing consumed => no event fetch
	}
	snap := make([]*profile.Profile, len(s.patterns))
	copy(snap, s.patterns)
	s.mu.RUnlock()

	emerging := s.deriveFlow(scope, flow, at)
	if emerging == nil {
		return 0
	}
	best := 0.0
	for _, sp := range snap {
		if sim := emerging.Similarity(sp); sim > best {
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
