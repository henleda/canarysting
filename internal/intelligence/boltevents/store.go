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

// recentScanCap bounds how many of a scope's most-recent event/outcome blobs a
// Query visits. Query is on the engine's inline Submit hot path (the D5 sharpen
// and D6 sharedset matchers each call it per Submit once a scope has accrued >=3
// jails), and its lookback window is short (sharpen/sharedset use 1h). Without a
// cap, Query scanned the ENTIRE per-scope event log every call — fine on a fresh
// box, but multiple SECONDS on a days-old window with tens of thousands of blobs,
// which blew past the adapter's inline timeout and fell the verdict closed to a
// 403. The cap turns that O(total) scan into O(recentScanCap). It is sized to
// comfortably span the 1h lookback for any realistic east-west capture rate;
// because Query already filters to [since, until], the cap is a cost ceiling, not
// a correctness boundary (a scope bursting >recentScanCap touch-events into one
// hour would undersample the matcher's emerging-flow profile — never a false
// trigger, since Rule 8 means only a canary touch arms a response regardless).
const recentScanCap = 4096

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

// outcomeRecord is a SECOND blob type stored in the same per-scope event bucket,
// carrying only the post-attrition StingOutcome the adapter reports back after a
// Tier 2/3 inline verdict (the original CaptureVerdict committed the event with a
// zero outcome; attrition runs later, adapter-side). Query merges it into the
// matching event by (SocketCookie, TimestampMs).
//
// DISCRIMINATOR INVARIANT (forward-safety): OutcomeAmendmentMarker is a gob
// discriminator that distinguishes the two blob types sharing this bucket WITHOUT
// a length/type-tag prefix on the wire (the live M7 store's blobs were written
// prefix-free; we must keep decoding them). gob is forward-compatible: it ignores
// fields present in the wire blob but absent in the target struct, and ZERO-FILLS
// fields present in the target struct but absent in the wire blob. So:
//   - an AdversaryInteractionEvent blob decoded into an outcomeRecord zero-fills
//     OutcomeAmendmentMarker to false (an event blob has no such field) => correctly
//     NOT treated as an outcome;
//   - a genuine outcome blob (written here) carries it true.
//
// This rests on AdversaryInteractionEvent having NO field named
// OutcomeAmendmentMarker. If it ever gained one (e.g. a same-named bool), every
// event blob would decode as an outcome and Query would drop them all — silent
// data-loss. The deliberately distinctive name makes an accidental collision
// improbable, and TestEventTypeHasNoOutcomeDiscriminatorField (store_test.go)
// neutralizes the trap STATICALLY: it reflects over AdversaryInteractionEvent and
// fails the build if such a field ever appears.
//
// This introduces NO persist schema-version bump and NO wire-format change — the
// live M7 window keeps running and old blobs decode unchanged. (Per the M8 build
// decision: gob discriminator now, defer a type-tag schema bump to a fresh M9
// store.)
type outcomeRecord struct {
	OutcomeAmendmentMarker bool   // discriminator: true iff this blob is an outcome amendment
	SocketCookie           uint64 // join key with the event's FlowID (rule 4)
	TimestampMs            int64  // matches the originating event's Timestamp.UnixMilli()
	Sting                  intelligence.StingOutcome
}

// AmendOutcome durably records a post-attrition StingOutcome for an already-stored
// interaction event, under the outcome's scope (rule 5). It is append-only like
// Append: a second blob in the same bucket that Query folds into the matching
// event. A missing/zero scope is refused (never store unscoped).
func (s *Store) AmendOutcome(rec contract.OutcomeRecord) error {
	if rec.Scope == "" {
		return fmt.Errorf("boltevents: outcome has no scope; refusing to store unscoped")
	}
	or := outcomeRecord{
		OutcomeAmendmentMarker: true,
		SocketCookie:           rec.SocketCookie,
		TimestampMs:            rec.TimestampUnixMs,
		Sting: intelligence.StingOutcome{
			Mechanism:      rec.Outcome.Mechanism,
			TimeHeldSec:    rec.Outcome.TimeHeldSec,
			BytesServed:    rec.Outcome.BytesServed,
			RequestsAbsrb:  rec.Outcome.RequestsAbsrb,
			TokenCostProxy: rec.Outcome.TokenCostProxy,
			DepthReached:   rec.Outcome.DepthReached,
			// Five-axis fields (AX0 spine). Persist them or they never reach
			// cost.Rollup / the D2 profiler / the dashboard. Additive on the existing
			// gob struct (no new blob type), so TestEventTypeHasNoOutcomeDiscriminator*
			// stays green and old blobs zero-fill. DoneReason stays adapter/engine-path
			// only (intentionally not persisted, as before).
			Axes:               uint32(rec.Outcome.Axes),
			TimeToDisengageSec: rec.Outcome.TimeToDisengageSec,
			PoisonClass:        rec.Outcome.PoisonClass,
			PoisonReached:      rec.Outcome.PoisonReached,
			ExploitsObserved:   rec.Outcome.ExploitsObserved,
			ExposureSignals:    rec.Outcome.ExposureSignals,
			DisengageReason:    rec.Outcome.DisengageReason,
		},
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(or); err != nil {
		return fmt.Errorf("boltevents: encode outcome: %w", err)
	}
	_, err := s.store.AppendEvent(contract.ScopeKey(rec.Scope), buf.Bytes())
	return err
}

// Query returns a scope's events whose timestamp falls in [since, until], with
// any reported attrition outcomes merged in. It is single-scope by construction
// (the durable store is partitioned per scope), so it can never return another
// scope's events.
//
// Two blob types share the bucket: interaction events and outcome amendments. We
// collect both in one scan, then merge each outcome into the matching event by
// (SocketCookie==FlowID, TimestampMs==Timestamp.UnixMilli). The outcome blob is
// tried FIRST (its OutcomeAmendmentMarker discriminator is false for an event
// blob, so a mis-decode is harmless and falls through to the event decode).
//
// The merge is O(N): outcomes are keyed into a map on the composite (cookie, ts),
// then each in-window event does a single O(1) lookup (no nested scan). The map
// is last-writer-wins by store order, so a re-reported outcome for the same
// (cookie, ts) overwrites the earlier one rather than being double-counted.
func (s *Store) Query(scopeKey string, since, until time.Time) ([]intelligence.AdversaryInteractionEvent, error) {
	sinceMs, untilMs := since.UnixMilli(), until.UnixMilli()
	var out []intelligence.AdversaryInteractionEvent
	// outcomeKey joins an outcome to its event by both halves of (cookie, ts).
	type outcomeKey struct {
		cookie uint64
		tsMs   int64
	}
	outcomes := map[outcomeKey]intelligence.StingOutcome{}
	err := s.store.RangeEventsRecent(contract.ScopeKey(scopeKey), recentScanCap, func(_ uint64, blob []byte) error {
		// Outcome blobs are distinguished by the OutcomeAmendmentMarker discriminator.
		// An event blob decoded as an outcomeRecord zero-fills the marker to false and
		// is ignored here, then decoded as an event below.
		var or outcomeRecord
		if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(&or); err == nil && or.OutcomeAmendmentMarker {
			// Skip outcomes outside the window (same bounds as events): they cannot
			// attach to any in-window event, so collecting them would only waste the map.
			if or.TimestampMs < sinceMs || or.TimestampMs > untilMs {
				return nil
			}
			// Last-writer-wins, preserved under the NEWEST-FIRST scan: the first
			// outcome we see for a (cookie, ts) has the HIGHEST seq (latest written),
			// so keep it and let an older (lower-seq) blob seen later NOT overwrite
			// it. (The prior ascending scan got last-writer-wins for free by visiting
			// the older blob first; a reverse scan must guard against the inversion.)
			k := outcomeKey{cookie: or.SocketCookie, tsMs: or.TimestampMs}
			if _, seen := outcomes[k]; !seen {
				outcomes[k] = or.Sting
			}
			return nil
		}
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
	// RangeEventsRecent visits records NEWEST-FIRST, so out is in descending
	// seq/time order. Reverse it to ascending — the order the prior full-scan
	// returned and the order the derived-profile fingerprint (ordered touch
	// sequence) depends on. The outcome merge below is order-independent (map
	// lookup), so reversing here is sufficient.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	// Merge outcomes into events by (cookie, timestamp) in a single O(1)-per-event
	// pass. An outcome whose event is outside the window (or never stored) is
	// silently dropped — it has nowhere to attach, which is correct (we never
	// fabricate an event from an outcome alone).
	if len(outcomes) > 0 {
		for i := range out {
			if sting, ok := outcomes[outcomeKey{cookie: out[i].FlowID, tsMs: out[i].Timestamp.UnixMilli()}]; ok {
				out[i].Sting = sting
			}
		}
	}
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
		Score:      v.Score, // real suspicion score (old gob blobs decode Score=0)
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
