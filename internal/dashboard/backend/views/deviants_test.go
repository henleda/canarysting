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

// Management-plane rows — a loopback SRC (127.0.0.0/8) and self-talk (src.addr ==
// dst.addr) — are STABLE-pushed to the BOTTOM, below a genuine external mover, while
// the tap's existing order is preserved otherwise. DEMOTE, never drop.
func TestDeriveDeviantsDemotesManagementPlane(t *testing.T) {
	raw := DeviantsTapView{
		Scope: "s",
		// Tap order (unfamiliar-first) places the management-plane rows FIRST and the
		// genuine external mover LAST — the demote must reorder it.
		Rows: []DeviantRowView{
			{
				// loopback SRC — management plane.
				Src: DeviantEndpointView{Label: "127.0.0.1", Kind: "unknown", Addr: "127.0.0.1"},
				Dst: DeviantEndpointView{Label: "api", Kind: "service", Addr: "127.0.1.2", Port: 8002},
			},
			{
				// self-talk: src.addr == dst.addr — the box talking to itself.
				Src: DeviantEndpointView{Label: "10.20.1.24", Kind: "unknown", Addr: "10.20.1.24"},
				Dst: DeviantEndpointView{Label: "10.20.1.24", Kind: "unknown", Addr: "10.20.1.24", Port: 9000},
			},
			{
				// genuine external mover: non-loopback src, src != dst — stays a lead.
				Src: DeviantEndpointView{Label: "10.20.1.104", Kind: "unknown", Addr: "10.20.1.104"},
				Dst: DeviantEndpointView{Label: "api", Kind: "service", Addr: "127.0.1.2", Port: 8002},
			},
		},
	}
	v := DeriveDeviants(raw)
	if len(v.Rows) != 3 {
		t.Fatalf("rows = %d, want 3 (demote, never drop)", len(v.Rows))
	}
	// The genuine external mover is now first.
	if v.Rows[0].Src.Addr != "10.20.1.104" {
		t.Fatalf("row[0].src = %q, want 10.20.1.104 (genuine mover on top)", v.Rows[0].Src.Addr)
	}
	// The two management-plane rows are demoted to the bottom, preserving their
	// original relative order (loopback before self-talk).
	if v.Rows[1].Src.Addr != "127.0.0.1" {
		t.Fatalf("row[1].src = %q, want 127.0.0.1 (loopback demoted)", v.Rows[1].Src.Addr)
	}
	if v.Rows[2].Src.Addr != "10.20.1.24" {
		t.Fatalf("row[2].src = %q, want 10.20.1.24 (self-talk demoted)", v.Rows[2].Src.Addr)
	}
}

// SUPPRESS hides a row from the DEFAULT list but it is STILL COUNTED (summary.total)
// and shipped inline in v.Suppressed for the toggle. ACK marks-not-hides: the acked
// row STAYS in v.Rows (and is demoted within its group). Normal rows are untouched.
func TestDeriveDeviantsSuppressHidesAckMarks(t *testing.T) {
	raw := DeviantsTapView{
		Scope: "s",
		Rows: []DeviantRowView{
			{ // a normal, un-triaged external mover -> stays, ranks first
				Src: DeviantEndpointView{Label: "10.20.1.104", Kind: "unknown", Addr: "10.20.1.104"},
				Dst: DeviantEndpointView{Label: "api", Kind: "service", Addr: "10.20.1.9", Port: 8002},
				Key: "aa01", TriageState: "",
				HitCount: 4, FirstSeen: "2026-06-09T00:00:00Z", LastSeen: "2026-06-13T00:00:00Z",
			},
			{ // SUPPRESSED -> hidden from v.Rows, present in v.Suppressed, still counted
				Src: DeviantEndpointView{Label: "10.20.1.50", Kind: "caller", Addr: "10.20.1.50"},
				Dst: DeviantEndpointView{Label: "api", Kind: "service", Addr: "10.20.1.9", Port: 8002},
				Key: "bb02", TriageState: "suppressed",
				HitCount: 6, FirstSeen: "2026-06-09T00:00:00Z", LastSeen: "2026-06-13T00:00:00Z",
			},
			{ // ACKED -> stays in v.Rows (badged), demoted within its group
				Src: DeviantEndpointView{Label: "10.20.1.60", Kind: "unknown", Addr: "10.20.1.60"},
				Dst: DeviantEndpointView{Label: "api", Kind: "service", Addr: "10.20.1.9", Port: 8002},
				Key: "cc03", TriageState: "acked",
				HitCount: 2, FirstSeen: "2026-06-09T00:00:00Z", LastSeen: "2026-06-13T00:00:00Z",
			},
		},
	}
	v := DeriveDeviants(raw)

	// Default list: the normal + acked rows only (suppressed hidden).
	if len(v.Rows) != 2 {
		t.Fatalf("v.Rows = %d, want 2 (normal + acked; suppressed hidden)", len(v.Rows))
	}
	for _, r := range v.Rows {
		if r.TriageState == "suppressed" {
			t.Fatalf("suppressed row leaked into the default list: %+v", r)
		}
	}
	// The acked row is DEMOTED below the un-triaged one (un-acked sorts first).
	if v.Rows[0].TriageState != "" || v.Rows[1].TriageState != "acked" {
		t.Fatalf("ack not demoted: rows = [%q, %q], want ['', 'acked']", v.Rows[0].TriageState, v.Rows[1].TriageState)
	}
	// The suppressed row is shipped inline for the toggle.
	if len(v.Suppressed) != 1 || v.Suppressed[0].Key != "bb02" {
		t.Fatalf("v.Suppressed = %+v, want exactly the bb02 row", v.Suppressed)
	}
	// Summary counts over the kept-after-shapeless denominator.
	if v.Summary.Total != 3 {
		t.Fatalf("summary.total = %d, want 3 (ALL kept, suppressed counted)", v.Summary.Total)
	}
	if v.Summary.Shown != 2 {
		t.Fatalf("summary.shown = %d, want 2 (len rows)", v.Summary.Shown)
	}
	if v.Summary.Suppressed != 1 {
		t.Fatalf("summary.suppressed = %d, want 1", v.Summary.Suppressed)
	}
	if v.Summary.Acked != 1 {
		t.Fatalf("summary.acked = %d, want 1", v.Summary.Acked)
	}
	// per_day: 12 total hits over a 4-day span = 3/day.
	if v.Summary.PerDay < 2.9 || v.Summary.PerDay > 3.1 {
		t.Fatalf("summary.per_day = %v, want ~3.0 (12 hits / 4 days)", v.Summary.PerDay)
	}
}

// The honesty caption discloses that suppressed rows are HIDDEN-BUT-COUNTED (not
// silently dropped) — the load-bearing honesty fence. (Byte-identical to the Go
// const; the TS/fixture captions must match it in lockstep on the frontend side.)
func TestDeviantsCaptionDisclosesSuppression(t *testing.T) {
	if !contains(deviantsCaption, "SUPPRESSED") || !contains(deviantsCaption, "HIDDEN") || !contains(deviantsCaption, "COUNTED") {
		t.Fatalf("caption does not disclose hidden-but-counted suppression: %q", deviantsCaption)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Empty/normal: no triage => empty Suppressed slice (non-null) and a zeroed summary.
func TestDeriveDeviantsSummaryEmpty(t *testing.T) {
	v := DeriveDeviants(DeviantsTapView{Scope: "s"})
	if v.Summary.Total != 0 || v.Summary.Suppressed != 0 || v.Summary.Acked != 0 || v.Summary.PerDay != 0 {
		t.Fatalf("empty summary not zeroed: %+v", v.Summary)
	}
	b, _ := json.Marshal(v)
	var probe struct {
		Suppressed json.RawMessage `json:"suppressed"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatal(err)
	}
	if string(probe.Suppressed) != "[]" {
		t.Fatalf("empty suppressed serialized as %s, want []", probe.Suppressed)
	}
}
