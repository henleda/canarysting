package main

import (
	"testing"
)

// TestBuildEngineOptionsMapsInlineFlags asserts the DemoEscalation/ContainInline/
// JailInline booleans passed to buildEngineOptions land on the identically named
// boot.Options fields (boot.go:75,81,90) unchanged, in both directions (all-true
// and all-false), so cmd/engine can actually serve the inline decoy chain instead
// of always emitting the async ModeAsync verdicts the adapter short-circuits on.
func TestBuildEngineOptionsMapsInlineFlags(t *testing.T) {
	cases := []struct {
		name           string
		demoEscalation bool
		containInline  bool
		jailInline     bool
	}{
		{"all inline flags true", true, true, true},
		{"all inline flags false", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := buildEngineOptions(false, tc.demoEscalation, tc.containInline, tc.jailInline)
			if err != nil {
				t.Fatalf("buildEngineOptions returned unexpected error: %v", err)
			}
			if opts.DemoEscalation != tc.demoEscalation {
				t.Errorf("DemoEscalation = %v, want %v", opts.DemoEscalation, tc.demoEscalation)
			}
			if opts.ContainInline != tc.containInline {
				t.Errorf("ContainInline = %v, want %v", opts.ContainInline, tc.containInline)
			}
			if opts.JailInline != tc.jailInline {
				t.Errorf("JailInline = %v, want %v", opts.JailInline, tc.jailInline)
			}
		})
	}
}

// TestBuildEngineOptionsMutualExclusion asserts the NEW guard cmd/engine lacks
// today: -aggressive (single-touch escalation) and -demo-escalation (the 3-5-touch
// dwell band) cannot both be set, mirroring cmd/staged-range/main.go:137-139.
func TestBuildEngineOptionsMutualExclusion(t *testing.T) {
	cases := []struct {
		name           string
		aggressive     bool
		demoEscalation bool
		wantErr        bool
	}{
		{"aggressive and demo-escalation both set", true, true, true},
		{"aggressive only", true, false, false},
		{"demo-escalation only", false, true, false},
		{"neither set", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildEngineOptions(tc.aggressive, tc.demoEscalation, false, false)
			if tc.wantErr && err == nil {
				t.Fatalf("buildEngineOptions(aggressive=%t, demoEscalation=%t, ...) = nil error, want non-nil", tc.aggressive, tc.demoEscalation)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("buildEngineOptions(aggressive=%t, demoEscalation=%t, ...) = %v, want nil error", tc.aggressive, tc.demoEscalation, err)
			}
		})
	}
}

// TestBuildEngineOptionsDefaultsInlineOff is a regression guard for today's
// -aggressive-only behavior: with the three inline bools false, buildEngineOptions
// must still return a valid (no-error) boot.Options with all three inline fields
// false — cmd/engine's current single supported mode must not change shape.
func TestBuildEngineOptionsDefaultsInlineOff(t *testing.T) {
	opts, err := buildEngineOptions(true, false, false, false)
	if err != nil {
		t.Fatalf("buildEngineOptions returned unexpected error: %v", err)
	}
	if opts.DemoEscalation {
		t.Errorf("DemoEscalation = true, want false (regression: today's -aggressive-only behavior)")
	}
	if opts.ContainInline {
		t.Errorf("ContainInline = true, want false (regression: today's -aggressive-only behavior)")
	}
	if opts.JailInline {
		t.Errorf("JailInline = true, want false (regression: today's -aggressive-only behavior)")
	}
}
