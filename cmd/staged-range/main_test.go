package main

import "testing"

// The demo data floor relaxes ONLY the calendar-day-SPAN gates; the genuine
// volume/population/statistical gates are left zero so the aggregator's Normalized()
// fills them with the real production values (the baseline stays real, just over fewer
// days). The production floor (demo=false) leaves the day gates zero => the genuine
// 7-calendar-day floor.
func TestBuildDataFloorDemoRelaxesDaySpanOnly(t *testing.T) {
	prod := buildDataFloor(false, 0)
	if prod.MinCalendarDays != 0 || prod.MinDaysPerBucket != 0 || prod.MinSufficientBuckets != 0 {
		t.Fatalf("production floor must leave day gates zero (=> Normalized fills 7/3/4), got %+v", prod)
	}
	if prod.Normalized().MinCalendarDays != 7 {
		t.Fatalf("production floor MinCalendarDays must normalize to 7, got %d", prod.Normalized().MinCalendarDays)
	}

	demo := buildDataFloor(true, 0)
	if demo.MinCalendarDays != 2 || demo.MinDaysPerBucket != 1 || demo.MinSufficientBuckets != 1 {
		t.Fatalf("demo floor day-span gates wrong: %+v", demo)
	}
	// The volume/population/statistical gates MUST be left zero so they normalize to the
	// genuine production values — the demo floor must not weaken the realness of the data.
	if demo.MinFlowsPerBucket != 0 || demo.MinIdentitiesPerBucket != 0 || demo.MinP2Samples != 0 {
		t.Fatalf("demo floor must NOT touch the volume/population gates, got %+v", demo)
	}
	n := demo.Normalized()
	if n.MinFlowsPerBucket != 100 || n.MinIdentitiesPerBucket != 2 || n.MinP2Samples != 50 {
		t.Fatalf("demo floor must keep the GENUINE volume/population gates after Normalize, got flows=%d ids=%d p2=%d", n.MinFlowsPerBucket, n.MinIdentitiesPerBucket, n.MinP2Samples)
	}
	// And the relaxed day gates survive Normalize (they're non-zero, so kept).
	if n.MinCalendarDays != 2 {
		t.Fatalf("demo floor MinCalendarDays must stay 2 after Normalize, got %d", n.MinCalendarDays)
	}
}
