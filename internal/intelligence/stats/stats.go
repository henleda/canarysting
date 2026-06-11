// Package stats holds the small, pure summary-statistics helpers shared by the
// intelligence layer and the dashboard view layer (docs/D2_D5_DESIGN.md decision E /
// docs/MOAT_DESIGN.md §3.1: ONE source of median/MAD so D2 profiling and the dashboard
// fingerprint cannot disagree on the behavioral pattern). Stdlib-only.
package stats

import (
	"math"
	"sort"
)

// Median returns the median of xs (0 for an empty slice). Does not mutate xs.
func Median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2]
	}
	return (cp[n/2-1] + cp[n/2]) / 2
}

// MAD is the median absolute deviation from the median. 0 for fewer than 2 elements.
func MAD(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := Median(xs)
	dev := make([]float64, len(xs))
	for i, x := range xs {
		dev[i] = math.Abs(x - m)
	}
	return Median(dev)
}
