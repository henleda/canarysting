package views

import (
	"encoding/json"
	"testing"
)

// DeriveDeviants shapes a populated tap view: rows pass through, the persistent
// honesty caption is attached, and (with simulated on) the simulated note is set.
func TestDeriveDeviantsShapeStable(t *testing.T) {
	raw := DeviantsTapView{
		Scope:        "s",
		StagedLabels: true,
		Simulated:    true,
		Rows: []DeviantRowView{
			{
				Src:             DeviantEndpointView{Label: "10.20.1.104", Kind: "unknown", Addr: "10.20.1.104", Port: 0},
				Dst:             DeviantEndpointView{Label: "api", Kind: "service", Addr: "127.0.1.2", Port: 8002},
				IdentityNovelty: 0.9, AdjacencyNovelty: 0.8, PortNovelty: 0.1, VolumeDeviation: 0.2, CadenceDeviation: 0.1,
				PeakDim: "new identity", PeakValue: 0.9, HitCount: 7,
				FirstSeen: "2026-06-09T13:30:00Z", LastSeen: "2026-06-09T13:58:12Z", Score: 0,
			},
		},
	}
	v := DeriveDeviants(raw)

	if v.Scope != "s" || !v.StagedLabels || !v.Simulated {
		t.Fatalf("scope/flags not carried: %+v", v)
	}
	if v.Caption != deviantsCaption {
		t.Fatalf("honesty caption wrong: %q", v.Caption)
	}
	if v.SimulatedNote != deviantsSimulatedNote {
		t.Fatalf("simulated note not set when simulated=true: %q", v.SimulatedNote)
	}
	if len(v.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(v.Rows))
	}
	if v.Rows[0].PeakDim != "new identity" || v.Rows[0].HitCount != 7 {
		t.Fatalf("row passthrough wrong: %+v", v.Rows[0])
	}
}

// An empty tap view yields an empty (non-null) rows slice, the honesty caption,
// and NO simulated note (simulated=false).
func TestDeriveDeviantsEmptyIsNonNull(t *testing.T) {
	v := DeriveDeviants(DeviantsTapView{Scope: "s"})
	if v.Caption != deviantsCaption {
		t.Fatalf("caption wrong: %q", v.Caption)
	}
	if v.SimulatedNote != "" {
		t.Fatalf("simulated note set when simulated=false: %q", v.SimulatedNote)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		Rows json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatal(err)
	}
	if string(probe.Rows) != "[]" {
		t.Fatalf("empty rows serialized as %s, want []", probe.Rows)
	}
}

// A shapeless row (no label and no addr on EITHER end) is dropped; a row with an
// UNKNOWN/raw-IP end is KEPT — an unfamiliar identity is the signal, not a defect.
func TestDeriveDeviantsDropsShapelessKeepsUnknown(t *testing.T) {
	raw := DeviantsTapView{
		Scope: "s",
		Rows: []DeviantRowView{
			{}, // wholly empty -> dropped
			{
				Src: DeviantEndpointView{Label: "10.20.1.104", Kind: "unknown", Addr: "10.20.1.104"},
				Dst: DeviantEndpointView{Label: "api", Kind: "service", Addr: "127.0.1.2", Port: 8002},
			},
		},
	}
	v := DeriveDeviants(raw)
	if len(v.Rows) != 1 {
		t.Fatalf("rows = %d, want 1 (shapeless dropped, unknown kept)", len(v.Rows))
	}
	if v.Rows[0].Src.Kind != "unknown" {
		t.Fatalf("kept row src kind = %q, want unknown", v.Rows[0].Src.Kind)
	}
}
