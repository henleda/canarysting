package observebaseline

import "time"

// DataFloor defines the eBPF baseline-data thresholds that decide when a scope's
// baseline is LIVE and a time bucket is SUFFICIENT — the two gates M7 owns
// (docs/BASELINE_MULTIPLIER.md §6, ROADMAP M7/D6). They are ORTHOGONAL to
// calibration: calibrated = enough analyst feedback labels (the canary-weight
// evidence floor); live+sufficient = enough real observed traffic. Both must
// hold before the multiplier may amplify (baseline.Store.ready), so neither gate
// can launder the other — eBPF volume never mints "calibrated," and analyst
// labels never substitute for real observed data. These are documented inputs
// with published defaults (DefaultDataFloor). Today only MaxCoverageGap is wired
// from operator config (the engine -max-coverage-gap flag); a loader for the rest
// lands with the operator control plane (ROADMAP M10). Until then they are tuned
// by changing DefaultDataFloor, not via YAML.
type DataFloor struct {
	// Per-bucket sufficiency.
	MinFlowsPerBucket      uint64 // completed flows a bucket needs
	MinIdentitiesPerBucket int    // distinct source identities a bucket needs (population, not one chatty source)
	MinDaysPerBucket       int    // distinct calendar days a bucket must span
	MinP2Samples           int    // each continuous P² summary must have folded this many

	// Per-scope liveness.
	MinSufficientBuckets int           // sufficient buckets a scope needs to go live
	MinCalendarDays      int           // distinct calendar days the scope's data must span
	FreshnessTTL         time.Duration // no fold within this → stale (forces M=1)
	MaxCoverageGap       time.Duration // a downtime gap larger than this forces re-accrual (STALE on boot)
}

// DefaultDataFloor returns the documented defaults tuned for the coarse 8-bucket
// learning window over a ≥2-week span (ROADMAP D6). With ~8 buckets revisited
// many times per week, these are reachable within the window while still
// demanding a genuine, multi-day, multi-caller baseline.
func DefaultDataFloor() DataFloor {
	return DataFloor{
		MinFlowsPerBucket:      100,
		MinIdentitiesPerBucket: 2,
		MinDaysPerBucket:       3,
		MinP2Samples:           50,
		MinSufficientBuckets:   4,
		MinCalendarDays:        7,
		FreshnessTTL:           15 * time.Minute,
		MaxCoverageGap:         1 * time.Hour,
	}
}

// Normalized fills any zero/invalid field with its default.
func (df DataFloor) Normalized() DataFloor {
	d := DefaultDataFloor()
	if df.MinFlowsPerBucket > 0 {
		d.MinFlowsPerBucket = df.MinFlowsPerBucket
	}
	if df.MinIdentitiesPerBucket > 0 {
		d.MinIdentitiesPerBucket = df.MinIdentitiesPerBucket
	}
	if df.MinDaysPerBucket > 0 {
		d.MinDaysPerBucket = df.MinDaysPerBucket
	}
	if df.MinP2Samples > 0 {
		d.MinP2Samples = df.MinP2Samples
	}
	if df.MinSufficientBuckets > 0 {
		d.MinSufficientBuckets = df.MinSufficientBuckets
	}
	if df.MinCalendarDays > 0 {
		d.MinCalendarDays = df.MinCalendarDays
	}
	if df.FreshnessTTL > 0 {
		d.FreshnessTTL = df.FreshnessTTL
	}
	if df.MaxCoverageGap > 0 {
		d.MaxCoverageGap = df.MaxCoverageGap
	}
	return d
}

// MinFlowsAfterGap is the scope-wide number of fresh completed folds a scope
// must re-accrue after a coverage gap before it may go live again — enough to
// genuinely re-establish the baseline, not just touch one bucket. It is the
// per-bucket floor times the number of sufficient buckets a scope needs.
func (df DataFloor) MinFlowsAfterGap() uint64 {
	n := df.MinSufficientBuckets
	if n < 1 {
		n = 1
	}
	return df.MinFlowsPerBucket * uint64(n)
}

// bucketSufficient reports whether a single bucket has enough real data to
// amplify within it: enough flows, a population of identities, a spread of days,
// and converged continuous summaries.
func (df DataFloor) bucketSufficient(a *bucketAggregate) bool {
	if a == nil {
		return false
	}
	if a.Flows < df.MinFlowsPerBucket {
		return false
	}
	if a.distinctIdentities() < df.MinIdentitiesPerBucket {
		return false
	}
	if len(a.Days) < df.MinDaysPerBucket {
		return false
	}
	return a.LogBytes.Ready(df.MinP2Samples) &&
		a.LogPkts.Ready(df.MinP2Samples) &&
		a.LogIAT.Ready(df.MinP2Samples) &&
		a.LogDur.Ready(df.MinP2Samples)
}

// evaluateScope decides a scope's liveness and which of its buckets are
// sufficient, given the buckets, the last successful fold time, and now. A scope
// goes live only when it has enough sufficient buckets spanning enough calendar
// days AND the data is fresh — a stalled or downed window is never trusted.
func (df DataFloor) evaluateScope(buckets map[string]*bucketAggregate, lastFold, now time.Time) (live bool, sufficient map[string]bool) {
	sufficient = make(map[string]bool, len(buckets))
	days := map[string]bool{}
	nSuff := 0
	for key, a := range buckets {
		if df.bucketSufficient(a) {
			sufficient[key] = true
			nSuff++
		}
		for d := range a.Days {
			days[d] = true
		}
	}
	if lastFold.IsZero() || now.Sub(lastFold) > df.FreshnessTTL {
		return false, sufficient // stale → not live (buckets reported as-is for gate clearing)
	}
	if nSuff < df.MinSufficientBuckets {
		return false, sufficient
	}
	if len(days) < df.MinCalendarDays {
		return false, sufficient
	}
	return true, sufficient
}
