// Package boltevents is the durable, scope-isolated implementation of
// intelligence.EventStore for the M7 window: every canary interaction in the
// live run lands as a structured, scope-keyed, append-only event that survives a
// reboot, so the higher Track-D tiers (profiling, attacker-cost, the feed) have
// real adversary-interaction history to consume.
//
// RULE 9 (docs/INTELLIGENCE.md): the stored AdversaryInteractionEvent carries
// only DERIVED, anonymized fields — the scope key, the socket cookie (an internal
// identifier, not an address), the canary type, the tier, and the structured
// baseline-feature vector. It has no field for a raw address, payload, or decoy
// content, so anonymization is structural, not a runtime check. RULE 5: events
// are partitioned per scope in the durable store and Query never crosses a scope.
package boltevents

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/intelligence"
)

// Store implements intelligence.EventStore over a persist.Store.
type Store struct {
	store        *persist.Store
	decodeErrors atomic.Uint64 // events skipped during Query because they failed to gob-decode
}

var _ intelligence.EventStore = (*Store)(nil)

// New returns a durable EventStore backed by store (required).
func New(store *persist.Store) *Store { return &Store{store: store} }

// Append durably records one interaction event under its scope, in append order.
func (s *Store) Append(ev intelligence.AdversaryInteractionEvent) error {
	if ev.ScopeKey == "" {
		return fmt.Errorf("boltevents: event has no scope; refusing to store unscoped")
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(ev); err != nil {
		return fmt.Errorf("boltevents: encode: %w", err)
	}
	_, err := s.store.AppendEvent(contract.ScopeKey(ev.ScopeKey), buf.Bytes())
	return err
}

// Query returns a scope's events whose timestamp falls in [since, until]. It is
// single-scope by construction (the durable store is partitioned per scope), so
// it can never return another scope's events.
func (s *Store) Query(scopeKey string, since, until time.Time) ([]intelligence.AdversaryInteractionEvent, error) {
	var out []intelligence.AdversaryInteractionEvent
	err := s.store.RangeEvents(contract.ScopeKey(scopeKey), func(_ uint64, blob []byte) error {
		var ev intelligence.AdversaryInteractionEvent
		if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(&ev); err != nil {
			s.decodeErrors.Add(1) // observable: skip-not-silent, append-only history is fail-soft
			return nil            // skip an undecodable record rather than fail the whole query
		}
		if (ev.Timestamp.Before(since)) || ev.Timestamp.After(until) {
			return nil
		}
		out = append(out, ev)
		return nil
	})
	return out, err
}

// DecodeErrors returns the cumulative count of event records skipped during
// Query because they could not be decoded (e.g. a schema change). Non-zero
// signals lost interaction history an operator may want to alert on.
func (s *Store) DecodeErrors() uint64 { return s.decodeErrors.Load() }

// CaptureVerdict is the single capture policy: it records a canary-touch verdict
// as an interaction event IFF the tier reached Tag or above (Tier 0/Observe is
// not retained), attaching the derived, anonymized feature vector. features may
// be nil. This keeps "what gets captured" in one place so the Tier≥Tag rule is
// testable.
func (s *Store) CaptureVerdict(ev contract.SignalEvent, v contract.Verdict, features map[string]float64) error {
	if v.Tier < contract.TierTag {
		return nil // Observe-tier touches are not retained as interaction events
	}
	return s.Append(intelligence.AdversaryInteractionEvent{
		ScopeKey:   string(ev.Scope),
		FlowID:     ev.Flow.SocketCookie,
		CanaryType: string(ev.Canary),
		Timestamp:  ev.Timestamp,
		Features:   features,
		Tier:       int(v.Tier),
		Verdict:    tierName(v.Tier),
	})
}

func tierName(t contract.Tier) string {
	switch t {
	case contract.TierObserve:
		return "observe"
	case contract.TierTag:
		return "tag"
	case contract.TierContain:
		return "contain"
	case contract.TierJail:
		return "jail"
	default:
		return "unknown"
	}
}
