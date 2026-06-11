package network

// ContributionContext is a candidate's per-deployment sharing context. There is NO
// producer-supplied k (D5 [leak-review]): the threshold is the package constant
// aggregationK, so a producer cannot invert the gate by supplying a zero k. A
// zero-value ContributionContext denies (Contribute false, SeenInScopes 0 < k).
type ContributionContext struct {
	// Contribute is the per-deployment opt-in to CONTRIBUTE patterns. Default false:
	// an un-opted-in scope produces nothing and is therefore unidentifiable (§5.4).
	Contribute bool
	// SeenInScopes is how many distinct scopes exhibited this pattern. Today it is
	// producer-asserted; D6's cross-scope ledger will compute it. Until then the
	// k-gate is encoded but its enforcement is only as sound as the count's
	// provenance (D6 known-gap) — and nothing actually transmits a *Cleared yet, so
	// no leak can occur regardless.
	SeenInScopes int
}

// aggregationK is the k for "a pattern crosses only if seen in >= k scopes" (D5). It
// is a package CONSTANT, never producer-supplied; k=1 would be singling-out. The
// cross-scope count is computed by D6's ledger; this gate only checks it.
const aggregationK = 3
