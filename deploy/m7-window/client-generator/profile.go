package main

import "time"

// requestsPerMinute returns the per-identity request rate at UTC time t, shaping
// the benign load into a realistic diurnal + weekly profile so the coarse window
// bucketer ({weekday,weekend} x {night,morning,afternoon,evening}) accrues a
// genuinely time-conditioned baseline — the whole point of time-bucketing (a 3am
// batch job must not look anomalous merely because the baseline ignored time).
//
//   - Diurnal: a low overnight floor rising to a midday peak and easing off in
//     the evening.
//   - Weekly: weekends run lighter than weekdays.
//   - A short scheduled BATCH burst around 03:00 UTC, so the "night" bucket has a
//     real recurring high-volume adjacency (the nightly-job pattern) rather than
//     only quiet traffic.
func requestsPerMinute(t time.Time, peak float64) float64 {
	rate := peak * hourFactor(t.Hour()) * dayFactor(t.Weekday())
	if isBatchWindow(t) {
		rate += peak * 0.8 // recurring nightly batch job
	}
	return rate
}

// hourFactor is a smooth-ish diurnal curve in [0.15, 1.0].
func hourFactor(h int) float64 {
	switch {
	case h < 5: // deep night
		return 0.15
	case h < 8: // early ramp
		return 0.4
	case h < 11: // morning
		return 0.8
	case h < 15: // midday peak
		return 1.0
	case h < 18: // afternoon
		return 0.85
	case h < 22: // evening
		return 0.55
	default: // late night
		return 0.25
	}
}

func dayFactor(d time.Weekday) float64 {
	if d == time.Saturday || d == time.Sunday {
		return 0.5
	}
	return 1.0
}

// isBatchWindow is the recurring nightly-job window (03:00–03:20 UTC).
func isBatchWindow(t time.Time) bool {
	return t.Hour() == 3 && t.Minute() < 20
}
