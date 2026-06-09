package observebaseline

import (
	"math"
	"sort"
	"testing"
)

// The P² markers must converge close to the true quantiles of a known stream.
func TestP2ConvergesToTrueQuantiles(t *testing.T) {
	// A deterministic but non-trivial stream: a shuffled-ish ramp.
	const n = 5000
	xs := make([]float64, n)
	for i := 0; i < n; i++ {
		// interleave to avoid feeding a sorted stream (which is P²'s easy case)
		v := float64((i*2654435761)%n) / float64(n) * 1000.0
		xs[i] = v
	}
	var p p2Quantile
	for _, x := range xs {
		p.Add(x)
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	trueQ := func(q float64) float64 { return sorted[int(q*float64(n-1))] }

	checks := []struct {
		name string
		got  float64
		want float64
	}{
		{"median", p.Median(), trueQ(0.5)},
		{"q1", p.Q[1], trueQ(0.25)},
		{"q3", p.Q[3], trueQ(0.75)},
	}
	for _, c := range checks {
		// Allow 2% of the full range (1000) tolerance — P² is an estimator.
		if math.Abs(c.got-c.want) > 20 {
			t.Errorf("%s: got %.2f want ~%.2f", c.name, c.got, c.want)
		}
	}
	if iqr := p.IQR(); iqr <= 0 {
		t.Errorf("IQR = %v, want > 0", iqr)
	}
}

// Bounded influence: a single enormous outlier must not blow up the median. With
// mean/variance the scale would explode; with P²/median it barely moves.
func TestP2OutlierBoundedInfluence(t *testing.T) {
	var clean p2Quantile
	for i := 1; i <= 1000; i++ {
		clean.Add(float64(i)) // uniform 1..1000, median ~500
	}
	medBefore := clean.Median()

	var poisoned p2Quantile
	for i := 1; i <= 1000; i++ {
		poisoned.Add(float64(i))
	}
	poisoned.Add(1e12) // a single 1-trillion outlier (a 10GB-scale exfil)
	medAfter := poisoned.Median()

	// The median must move by at most a couple of inter-sample steps, not toward
	// the outlier. (Mean would jump by ~1e9.)
	if math.Abs(medAfter-medBefore) > 5 {
		t.Fatalf("median moved %.2f under a single outlier (before=%.2f after=%.2f); not bounded-influence",
			math.Abs(medAfter-medBefore), medBefore, medAfter)
	}
}

func TestP2ReadyAndBufferedFallback(t *testing.T) {
	var p p2Quantile
	if p.Ready(1) {
		t.Fatal("empty estimator reported ready")
	}
	p.Add(10)
	p.Add(30)
	p.Add(20)
	// Count < 5: not "ready" for the markers, but Median is a best-effort buffer.
	if p.Ready(5) {
		t.Fatal("ready with <5 samples")
	}
	if m := p.Median(); m < 10 || m > 30 {
		t.Fatalf("buffered median = %v, want within [10,30]", m)
	}
	p.Add(40)
	p.Add(50)
	if !p.Ready(5) {
		t.Fatal("not ready after 5 samples")
	}
}
