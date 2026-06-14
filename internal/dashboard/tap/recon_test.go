package tap

import (
	"testing"

	"github.com/canarysting/canarysting/internal/engine/observebaseline"
)

// peakNovelty picks the strongest baseline-deviation dimension + its label — the
// signal that flags a non-canary flow as "looks suspicious from baseline".
func TestPeakNovelty(t *testing.T) {
	cases := []struct {
		name      string
		f         observebaseline.LiveFlow
		wantNov   float64
		wantLabel string
	}{
		{"identity dominant", observebaseline.LiveFlow{IdentityNovelty: 1.0, AdjacencyNovelty: 0.4}, 1.0, "new identity"},
		{"adjacency dominant", observebaseline.LiveFlow{IdentityNovelty: 0.3, AdjacencyNovelty: 0.9}, 0.9, "new adjacency"},
		{"volume dominant", observebaseline.LiveFlow{VolumeDeviation: 0.7, CadenceDeviation: 0.2}, 0.7, "volume deviation"},
		{"cadence dominant", observebaseline.LiveFlow{CadenceDeviation: 0.8}, 0.8, "cadence deviation"},
		{"all zero -> identity label, 0", observebaseline.LiveFlow{}, 0, "new identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nov, label := peakNovelty(tc.f)
			if nov != tc.wantNov || label != tc.wantLabel {
				t.Fatalf("peakNovelty = %v,%q want %v,%q", nov, label, tc.wantNov, tc.wantLabel)
			}
		})
	}
}
