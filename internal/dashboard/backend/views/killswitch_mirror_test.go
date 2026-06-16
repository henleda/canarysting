package views

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/sting/killswitch"
)

// TestKillSwitchViewMirrorsStatus guards the HAND-COPIED mirror. views.KillSwitchView
// is a local struct (the dashboard backend deliberately does NOT import killswitch — it
// HTTP-GETs the tap and json.Unmarshals), so it must stay json-tag- and field-compatible
// with killswitch.Status, which is exactly what the tap emits as `kill_switch` and what
// the dashboard-web binds to. A future tag/field change to killswitch.Status that is not
// mirrored here would silently DROP the field on the tap->backend->/api path (and the
// banner would go dark). This round-trip fails loudly instead.
func TestKillSwitchViewMirrorsStatus(t *testing.T) {
	src := killswitch.Status{
		Engaged:   true,
		Operator:  "ir",
		Reason:    "incident-42",
		EngagedAt: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 6, 15, 12, 30, 0, 0, time.UTC),
	}

	// Status -> JSON (the wire shape the tap emits) -> KillSwitchView (the backend mirror).
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	var view KillSwitchView
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("killswitch.Status JSON does not unmarshal into views.KillSwitchView — the mirror drifted: %v", err)
	}
	if view.Engaged != src.Engaged || view.Operator != src.Operator || view.Reason != src.Reason ||
		!view.EngagedAt.Equal(src.EngagedAt) || !view.ExpiresAt.Equal(src.ExpiresAt) {
		t.Fatalf("mirror drift: views.KillSwitchView %+v != killswitch.Status %+v (a field changed in one but not the other)", view, src)
	}

	// Re-marshal the view: it must produce the SAME wire bytes as the Status. This catches
	// a tag rename, a field reorder, or an added/removed field in EITHER struct (an added
	// field in Status would be dropped by the view and the bytes would differ here).
	vb, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if string(vb) != string(b) {
		t.Fatalf("mirror re-marshal drift — killswitch.Status and views.KillSwitchView no longer serialize identically:\n  Status -> %s\n  View   -> %s", b, vb)
	}
}
