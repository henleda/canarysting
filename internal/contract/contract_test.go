package contract

import (
	"reflect"
	"testing"
)

// TestStingFloorAxesMap pins the floor→axis map (the AX0 spine's single source of
// truth): passive unlocks velocity only, moderate adds information poisoning,
// aggressive adds the opportunity-cost / exploit / exposure axes. The
// aggressive-only axes are NEVER in the passive set, so a zero-value (unset) floor
// can never silently reach them — the structural "aggressive is never the silent
// default" guard, expressed at the contract layer.
func TestStingFloorAxesMap(t *testing.T) {
	if got := FloorPassive.Axes(); got != AxisVelocity {
		t.Fatalf("passive axes = %05b, want velocity-only %05b", got, AxisVelocity)
	}
	if got, want := FloorModerate.Axes(), AxisVelocity|AxisPoison; got != want {
		t.Fatalf("moderate axes = %05b, want %05b", got, want)
	}
	wantAgg := AxisVelocity | AxisPoison | AxisOppCost | AxisExploitBurn | AxisOpExposure
	if got := FloorAggressive.Axes(); got != wantAgg {
		t.Fatalf("aggressive axes = %05b, want %05b", got, wantAgg)
	}
	for _, a := range []AttritionAxis{AxisOppCost, AxisExploitBurn, AxisOpExposure} {
		if FloorPassive.Axes()&a != 0 {
			t.Fatalf("passive floor unlocked an aggressive-only axis %05b", a)
		}
	}
	var zero StingFloor
	if zero != FloorPassive || zero.Axes() != AxisVelocity {
		t.Fatal("zero-value StingFloor must be passive / velocity-only")
	}
}

// TestDriverObservationCarriesNoRawData asserts the digest the adapter feeds into
// Stream.Observe carries scalar counts/bools/enums ONLY — no byte slice, string,
// pointer, slice, or map that could smuggle raw payload/addresses across a
// boundary (rule 9; the same "no raw payload" invariant StingOutcome holds). It
// mirrors the discipline that keeps ExploitsObserved/ExposureSignals counts, never
// captured bytes.
func TestDriverObservationCarriesNoRawData(t *testing.T) {
	dt := reflect.TypeOf(DriverObservation{})
	for i := 0; i < dt.NumField(); i++ {
		f := dt.Field(i)
		switch f.Type.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Bool, reflect.Float32, reflect.Float64:
			// scalar count / bool / enum — allowed
		default:
			t.Fatalf("DriverObservation.%s has kind %s; only scalar counts/bools/enums are allowed (rule 9)", f.Name, f.Type.Kind())
		}
	}
}
