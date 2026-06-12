package network

import "sort"

// FeedK is the EXTERNAL threat-feed's k-anonymity threshold (D7a): a coarse pattern is
// eligible to appear in the feed only once >= FeedK DISTINCT scopes have independently
// confirmed it. It is deliberately HIGHER than the internal cross-customer sharpening
// threshold (aggregationK=3): the feed is a broader, less-trusted external surface, so it
// raises the corroboration floor to bound the D6 homogeneity residual (a 2-3-box world
// would otherwise let an exact-count + side-knowledge re-identify a contributor). Like
// aggregationK it is a package CONST, never request-supplied — a caller who could lower it
// would re-enable singling-out. Consequence (accepted, D7a): the feed stays HONESTLY
// EMPTY until the network is broad (>= FeedK deployments corroborate a pattern).
const FeedK = 5

// AggregatedPattern is ONE k-anonymous, cross-scope-confirmed cell, ready for an external
// read view. It carries EXACTLY the already-cleared coarse shape (the same 7 fields
// network.SharedPattern / coarseKey carry) and NOTHING else — PRESENCE-ONLY (D7a): there
// is NO prevalence count or band, because a cell's mere appearance already asserts ">=
// FeedK deployments corroborated this", and any count band over a small live population is
// a near-exact re-identifier. No raw count, no scope bucket, no hash/identity. A
// structural-guard test pins that it holds only coarse scalars (same discipline as
// TestCoarseKeyHasNoHashOrIdentity).
type AggregatedPattern struct {
	ReachedContain  bool
	EngagedVelocity bool
	EngagedPoison   bool
	DisengagedEarly bool
	HeldBand        int    // 0..3 band, never raw seconds
	CadenceBand     int    // 0..3 band, never raw cadence
	PoisonClass     string // closed enum
}

// Aggregated enumerates every ledger cell seen in >= max(minScopes, FeedK) distinct scopes
// as an anonymized aggregated pattern — the read source D7's feed consumes. minScopes is
// FLOORED at FeedK (a caller can ask for MORE corroboration but never less — fail-closed:
// the external feed never serves a sub-FeedK cell). It returns the coarse fields only,
// NEVER the raw distinct-scope count and NEVER a scopeBucket: the bucketing-to-presence
// happens HERE, inside package network, behind the unexported distinct-scope count, so the
// feed package never sees a raw count to leak. Read-only: takes RLock, mutates nothing,
// allocates a fresh slice (no aliasing into seen). Deterministically ordered so the feed
// is stable + testable. nil receiver / no eligible cells => empty.
func (l *Ledger) Aggregated(minScopes int) []AggregatedPattern {
	if l == nil {
		return nil
	}
	if minScopes < FeedK {
		minScopes = FeedK
	}
	l.mu.RLock()
	out := make([]AggregatedPattern, 0)
	for key, scopes := range l.seen {
		if len(scopes) >= minScopes {
			out = append(out, AggregatedPattern{
				ReachedContain:  key.ReachedContain,
				EngagedVelocity: key.EngagedVelocity,
				EngagedPoison:   key.EngagedPoison,
				DisengagedEarly: key.DisengagedEarly,
				HeldBand:        key.HeldBand,
				CadenceBand:     key.CadenceBand,
				PoisonClass:     key.PoisonClass,
			})
		}
	}
	l.mu.RUnlock()

	// Deterministic order (map iteration is randomized) so the read view is stable.
	sort.Slice(out, func(i, j int) bool { return aggLess(out[i], out[j]) })
	return out
}

// aggLess is a total order over the coarse fields (booleans then bands then class), so
// Aggregated's output is deterministic regardless of map iteration order.
func aggLess(a, b AggregatedPattern) bool {
	if a.ReachedContain != b.ReachedContain {
		return !a.ReachedContain
	}
	if a.EngagedVelocity != b.EngagedVelocity {
		return !a.EngagedVelocity
	}
	if a.EngagedPoison != b.EngagedPoison {
		return !a.EngagedPoison
	}
	if a.DisengagedEarly != b.DisengagedEarly {
		return !a.DisengagedEarly
	}
	if a.HeldBand != b.HeldBand {
		return a.HeldBand < b.HeldBand
	}
	if a.CadenceBand != b.CadenceBand {
		return a.CadenceBand < b.CadenceBand
	}
	return a.PoisonClass < b.PoisonClass
}
