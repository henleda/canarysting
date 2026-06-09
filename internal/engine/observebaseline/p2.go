package observebaseline

import "sort"

// p2Quantile is a P² (Jain & Chlamtac, 1985) running quantile estimator. It
// tracks five markers at the {0, .25, .5, .75, 1} quantiles of a stream in O(1)
// memory with NO stored samples, so it can be gob-persisted compactly and folds
// in O(1) per observation. Median() and IQR() read the three interior markers.
//
// We use P² (median/IQR) rather than a running mean/variance because the
// baseline of normal east-west traffic may be lightly contaminated during the
// learning window (a stray heavy transfer, or an attacker present before being
// labeled). Mean/variance has breakdown point 0 — one 10 GB flow inflates the
// scale without bound and DESENSITIZES the detector exactly when it matters.
// The median/IQR estimated here has breakdown ~25%, so a contaminated window
// shifts the model minimally (docs/BASELINE_MULTIPLIER.md §7).
//
// Fields are exported solely so the enclosing bucketAggregate gob-serializes
// verbatim; treat them as private to this package.
type p2Quantile struct {
	Count int        // total observations folded
	Init  [5]float64 // buffer for the first five observations (sorted on the 5th)
	Q     [5]float64 // marker heights — the quantile estimates
	N     [5]int     // actual marker positions (1-based counts)
	NP    [5]float64 // desired marker positions
	DN    [5]float64 // desired-position increments (the target quantiles)
}

// markerQuantiles are the five tracked quantiles: min, Q1, median, Q3, max.
var markerQuantiles = [5]float64{0, 0.25, 0.5, 0.75, 1}

// Add folds one observation into the estimator.
func (p *p2Quantile) Add(x float64) {
	if p.Count < 5 {
		p.Init[p.Count] = x
		p.Count++
		if p.Count == 5 {
			s := p.Init
			sort.Float64s(s[:])
			for i := 0; i < 5; i++ {
				p.Q[i] = s[i]
				p.N[i] = i + 1
				p.DN[i] = markerQuantiles[i]
				p.NP[i] = 1 + 4*markerQuantiles[i]
			}
		}
		return
	}
	p.Count++

	// 1. Find the cell k that x falls into, extending the min/max markers.
	var k int
	switch {
	case x < p.Q[0]:
		p.Q[0] = x
		k = 0
	case x < p.Q[1]:
		k = 0
	case x < p.Q[2]:
		k = 1
	case x < p.Q[3]:
		k = 2
	case x <= p.Q[4]:
		k = 3
	default:
		p.Q[4] = x
		k = 3
	}

	// 2. Increment the positions of all markers above the cell.
	for i := k + 1; i < 5; i++ {
		p.N[i]++
	}
	// 3. Advance the desired positions.
	for i := 0; i < 5; i++ {
		p.NP[i] += p.DN[i]
	}
	// 4. Adjust the three interior markers if they drift one full position from
	//    desired (parabolic prediction, falling back to linear if it would break
	//    monotonicity).
	for i := 1; i <= 3; i++ {
		d := p.NP[i] - float64(p.N[i])
		if (d >= 1 && p.N[i+1]-p.N[i] > 1) || (d <= -1 && p.N[i-1]-p.N[i] < -1) {
			di := 1
			if d < 0 {
				di = -1
			}
			qp := p.parabolic(i, float64(di))
			if p.Q[i-1] < qp && qp < p.Q[i+1] {
				p.Q[i] = qp
			} else {
				p.Q[i] = p.linear(i, di)
			}
			p.N[i] += di
		}
	}
}

func (p *p2Quantile) parabolic(i int, d float64) float64 {
	ni, nim, nip := float64(p.N[i]), float64(p.N[i-1]), float64(p.N[i+1])
	qi, qim, qip := p.Q[i], p.Q[i-1], p.Q[i+1]
	return qi + d/(nip-nim)*((ni-nim+d)*(qip-qi)/(nip-ni)+(nip-ni-d)*(qi-qim)/(ni-nim))
}

func (p *p2Quantile) linear(i, di int) float64 {
	return p.Q[i] + float64(di)*(p.Q[i+di]-p.Q[i])/float64(p.N[i+di]-p.N[i])
}

// Ready reports whether the estimator has folded at least min observations (and
// the minimum five needed to initialize the markers).
func (p *p2Quantile) Ready(min int) bool { return p.Count >= 5 && p.Count >= min }

// Median returns the estimated 0.5 quantile. For Count < 5 it returns the median
// of the buffered observations (a best effort before the markers initialize).
func (p *p2Quantile) Median() float64 {
	if p.Count >= 5 {
		return p.Q[2]
	}
	return p.bufferedQuantile(0.5)
}

// IQR returns the estimated inter-quartile range (Q3 − Q1), a robust scale. For
// Count < 5 it returns a best-effort spread from the buffer.
func (p *p2Quantile) IQR() float64 {
	if p.Count >= 5 {
		r := p.Q[3] - p.Q[1]
		if r < 0 {
			return 0
		}
		return r
	}
	hi := p.bufferedQuantile(0.75)
	lo := p.bufferedQuantile(0.25)
	if hi < lo {
		return 0
	}
	return hi - lo
}

func (p *p2Quantile) bufferedQuantile(q float64) float64 {
	if p.Count == 0 {
		return 0
	}
	buf := make([]float64, p.Count)
	copy(buf, p.Init[:p.Count])
	sort.Float64s(buf)
	idx := int(q * float64(p.Count-1))
	return buf[idx]
}
