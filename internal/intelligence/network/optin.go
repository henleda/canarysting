package network

// ContributionContext is a candidate's per-deployment sharing context. There is NO
// producer-supplied k (D5 [leak-review]): the threshold is the package constant
// aggregationK, so a producer cannot invert the gate by supplying a zero k. A
// zero-value ContributionContext denies (Contribute false, SeenInScopes 0 < k).
type ContributionContext struct {
	// Contribute is the per-deployment opt-in to CONTRIBUTE patterns. Default false:
	// an un-opted-in scope produces nothing and is therefore unidentifiable (§5.4).
	Contribute bool
	// SeenInScopes is a producer-asserted count consulted ONLY by the form-level Clear
	// (a sanity check whose carrier cannot cross). The REAL cross-deployment path,
	// ClearWithLedger, IGNORES this field and computes the count INSIDE the chokepoint
	// from the cross-scope Ledger (D6c/D6d) — and treats a non-zero value here as a
	// tripwire (a producer must not assert the count). The D6 known-gap is closed: a
	// producer-asserted count can no longer produce a transmittable carrier.
	SeenInScopes int
}

// aggregationK is the k for "a pattern crosses only if seen in >= k scopes" (D5). It
// is a package CONSTANT, never producer-supplied; k=1 would be singling-out. The
// cross-scope count is computed by D6's ledger; this gate only checks it.
const aggregationK = 3

// AggregationThreshold is the EXPORTED value of aggregationK, so a caller (e.g. the D6-3
// cross-scope aggregator) can name the crossing threshold for logging/config without the
// constant becoming mutable or producer-supplied.
const AggregationThreshold = aggregationK
