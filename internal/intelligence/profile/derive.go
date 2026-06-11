package profile

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/stats"
)

// DeriveProfile builds a behavioral Profile from a set of interaction events. It is
// PURE and SINGLE-SCOPE (rule 5): the caller passes one scope's — or one flow's —
// events, already scope-isolated, and DeriveProfile never reaches across a boundary.
// It mirrors cost.Rollup's discipline: a single deterministic pass, imports only
// contract + intelligence. The same events always yield the same Profile (and the same
// BehavioralHash). Returns nil for no events.
func DeriveProfile(events []intelligence.AdversaryInteractionEvent) *Profile {
	if len(events) == 0 {
		return nil
	}
	// Deterministic order (timestamp, then CanaryType) — so the ordered sequence and
	// the hash do not depend on input order even for equal-timestamp events.
	ordered := append([]intelligence.AdversaryInteractionEvent(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		if a.CanaryType != b.CanaryType {
			return a.CanaryType < b.CanaryType
		}
		// Canonicalize the otherwise-ambiguous case (same timestamp AND type) so the
		// deepest-poison-stage CLASS is order-independent: deeper PoisonReached first,
		// then PoisonClass. Without this, two such events with different PoisonClass
		// would let input/arrival order decide the class — and thus the BehavioralHash
		// (which D5 keys on) and the exported PoisonClass. (PoisonReached itself, and
		// every other field, is a max/sum/OR and already order-independent.)
		if a.Sting.PoisonReached != b.Sting.PoisonReached {
			return a.Sting.PoisonReached > b.Sting.PoisonReached
		}
		return a.Sting.PoisonClass < b.Sting.PoisonClass
	})

	p := &Profile{Touches: len(ordered)}
	var axes contract.AttritionAxis
	for _, e := range ordered {
		if e.CanaryType != "" {
			p.OrderedTypes = append(p.OrderedTypes, e.CanaryType)
		}
		if e.Tier > p.PeakTier {
			p.PeakTier = e.Tier
		}
		if e.Sting.DepthReached > p.DepthReached {
			p.DepthReached = e.Sting.DepthReached
		}
		if v := e.Features[featAdjacency]; v > p.AdjacencyNov {
			p.AdjacencyNov = v
		}
		if v := e.Features[featIdentity]; v > p.IdentityNov {
			p.IdentityNov = v
		}
		// Per-axis engagement signature: OR the OVERLAPPING Axes bitset (an event lands
		// on every axis its mechanism imposed).
		axes |= contract.AttritionAxis(e.Sting.Axes)
		p.HeldSec += e.Sting.TimeHeldSec
		if e.Sting.TimeHeldSec > tarpitPersistSec {
			p.PersistsTarpit = true
		}
		// DisengagedEarly is the engagement signal and is TRUE ONLY when the attacker
		// disconnected before any defender bound (D2-2): a generator-exhausted or
		// defender-capped session must never set it, or a defender cap would be
		// mislabeled as "the attacker gave up". TimeToDisengageSec rides only on that.
		if e.Sting.DisengageReason == contract.DisengageAttacker {
			p.DisengagedEarly = true
			if e.Sting.TimeToDisengageSec > p.TimeToDisengageSec {
				p.TimeToDisengageSec = e.Sting.TimeToDisengageSec
			}
		}
		// Deepest poison stage walked + its class (read jointly with the disengage
		// class downstream — an indifferent crawler advances PoisonReached too).
		if e.Sting.PoisonReached > p.PoisonReached {
			p.PoisonReached = e.Sting.PoisonReached
			p.PoisonClass = e.Sting.PoisonClass
		}
		// Deployment-local-only reaction counts (never exported).
		p.ExploitsObserved += e.Sting.ExploitsObserved
		p.ExposureSignals += e.Sting.ExposureSignals
	}
	for i := 0; i < NumAxes; i++ {
		p.AxesEngaged[i] = axes&axisBits[i] != 0
	}

	// Cadence (median inter-arrival) + jitter (MAD), from the ordered timestamps.
	var gaps []float64
	for i := 1; i < len(ordered); i++ {
		gaps = append(gaps, ordered[i].Timestamp.Sub(ordered[i-1].Timestamp).Seconds())
	}
	p.CadenceSec = stats.Median(gaps)
	if len(gaps) >= 2 {
		p.CadenceJitter = stats.MAD(gaps)
	}

	p.BehavioralHash = behavioralHash(p)
	return p
}

// behavioralHash is a deterministic fnv-64a over the BEHAVIORAL pattern — the ordered
// probe sequence, the coarse cadence band, and the per-axis engagement / disengage /
// poison signature. It deliberately includes NO FlowID/ScopeKey/identity, so the same
// tool from different flows hashes alike and the hash carries no re-identifying data
// (the property D5's MaliciousProfileStore keys on and the property that lets the hash
// be part of an exportable pattern once aggregated).
func behavioralHash(p *Profile) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.Join(p.OrderedTypes, ",")))
	fmt.Fprintf(h, "|c%d|", cadenceBand(p.CadenceSec))
	for _, e := range p.AxesEngaged {
		if e {
			_, _ = h.Write([]byte{'1'})
		} else {
			_, _ = h.Write([]byte{'0'})
		}
	}
	fmt.Fprintf(h, "|p%s|t%d|d%t", p.PoisonClass, p.PoisonReached, p.DisengagedEarly)
	return h.Sum64()
}
