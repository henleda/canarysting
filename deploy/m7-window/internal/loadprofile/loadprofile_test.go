package loadprofile

import (
	"testing"
	"time"
)

func TestRequestsPerMinuteShape(t *testing.T) {
	const peak = 100.0
	wedMidday := time.Date(2026, 6, 3, 13, 0, 0, 0, time.UTC) // Wed midday peak
	wedNight := time.Date(2026, 6, 3, 1, 0, 0, 0, time.UTC)   // Wed deep night
	satMidday := time.Date(2026, 6, 6, 13, 0, 0, 0, time.UTC) // Sat midday
	batch := time.Date(2026, 6, 3, 3, 10, 0, 0, time.UTC)     // Wed 03:10 (batch window)
	preBatch := time.Date(2026, 6, 3, 4, 30, 0, 0, time.UTC)  // Wed 04:30 (still night floor, no batch)

	// Midday peaks above the overnight floor.
	if RequestsPerMinute(wedMidday, peak) <= RequestsPerMinute(wedNight, peak) {
		t.Fatal("midday should exceed deep-night rate")
	}
	// Weekends run lighter than weekdays at the same hour.
	if RequestsPerMinute(satMidday, peak) >= RequestsPerMinute(wedMidday, peak) {
		t.Fatal("weekend midday should be lighter than weekday midday")
	}
	// The nightly batch burst lifts the rate above the bare night floor.
	if RequestsPerMinute(batch, peak) <= RequestsPerMinute(preBatch, peak) {
		t.Fatal("the 03:00 batch window should add a burst above the night floor")
	}
	// Zero peak yields zero load regardless of time (no divide-by-zero downstream).
	if RequestsPerMinute(wedMidday, 0) != 0 {
		t.Fatal("zero peak must yield zero rate")
	}
}
