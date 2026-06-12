package views

import (
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
)

// A single attacker flow escalating recon -> contain -> jail, then disengaging, yields a
// legible journey: one milestone per tier CROSSING (with the overlapping axes that fired)
// plus the closing disengage beat, latest = the disengage.
func TestBuildJourneyArc(t *testing.T) {
	velPoison := uint32(contract.AxisVelocity | contract.AxisPoison)
	allAxes := uint32(contract.AxisVelocity | contract.AxisPoison | contract.AxisOppCost | contract.AxisExploitBurn | contract.AxisOpExposure)

	events := []intelligence.AdversaryInteractionEvent{
		ev(0xA, 1, "tag", ".env", 0, intelligence.StingOutcome{}, nil),
		ev(0xA, 1, "tag", "backup/db.sql", 1, intelligence.StingOutcome{}, nil),
		ev(0xA, 2, "contain", ".git/config", 2, intelligence.StingOutcome{Axes: velPoison, TimeHeldSec: 4}, nil),
		ev(0xA, 3, "jail", "admin/metrics", 3, intelligence.StingOutcome{Axes: allAxes, TimeHeldSec: 8, DisengageReason: contract.DisengageAttacker}, nil),
	}
	ov := Derive(TapState{Scope: "s"}, events, base.Add(time.Minute))
	j := ov.Journey

	if !j.Present || j.FlowIDHex != "0xa" {
		t.Fatalf("journey present=%v flow=%q, want present 0xa", j.Present, j.FlowIDHex)
	}
	// recon (T1) -> contained (T2) -> jailed (T3) -> disengaged = 4 milestones.
	if len(j.Milestones) != 4 {
		t.Fatalf("got %d milestones, want 4: %+v", len(j.Milestones), j.Milestones)
	}
	phases := []string{j.Milestones[0].Phase, j.Milestones[1].Phase, j.Milestones[2].Phase, j.Milestones[3].Phase}
	want := []string{"recon", "contained", "jailed", "disengaged"}
	for i := range want {
		if phases[i] != want[i] {
			t.Fatalf("milestone %d phase = %q, want %q (phases=%v)", i, phases[i], want[i], phases)
		}
	}
	// The contained crossing fired velocity + poison (overlapping axes).
	contained := j.Milestones[1]
	if len(contained.AxesFiring) != 2 || contained.AxesFiring[0] != "velocity" || contained.AxesFiring[1] != "poison" {
		t.Fatalf("contained axes = %v, want [velocity poison]", contained.AxesFiring)
	}
	// The jail fired all five axes.
	if len(j.Milestones[2].AxesFiring) != 5 {
		t.Fatalf("jail axes = %v, want 5", j.Milestones[2].AxesFiring)
	}
	// The disengage is the honest attacker-gave-up beat, and is the latest.
	if j.Latest == nil || j.Latest.Phase != "disengaged" {
		t.Fatalf("latest = %+v, want the disengaged milestone", j.Latest)
	}
	if j.Latest.Title != "Attacker disengaged" {
		t.Fatalf("disengage title = %q, want 'Attacker disengaged'", j.Latest.Title)
	}
}

// No tier crossing past T1 + no disengage => just the recon milestone; no disengage beat.
func TestBuildJourneyReconOnly(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0xB, 1, "tag", ".env", 0, intelligence.StingOutcome{}, nil),
		ev(0xB, 1, "tag", ".env", 1, intelligence.StingOutcome{}, nil), // same tier, no new crossing
	}
	j := Derive(TapState{Scope: "s"}, events, base.Add(time.Minute)).Journey
	if !j.Present || len(j.Milestones) != 1 || j.Milestones[0].Phase != "recon" {
		t.Fatalf("recon-only journey wrong: %+v", j)
	}
}

// A defender-cap disengage is labeled as such (D2-2) — never relabeled "gave up".
func TestBuildJourneyDefenderCapNotRelabeled(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0xC, 2, "contain", ".env", 0, intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity), TimeHeldSec: 8, DisengageReason: contract.DisengageDefenderCapped}, nil),
	}
	j := Derive(TapState{Scope: "s"}, events, base.Add(time.Minute)).Journey
	if j.Latest == nil || j.Latest.Phase != "disengaged" || j.Latest.Title != "Defender-capped" {
		t.Fatalf("defender cap must be labeled 'Defender-capped', got %+v", j.Latest)
	}
}

// The disengage beat reports HOW THE FLOW ENDED (the terminal reason), not the worst
// across the flow: an early defender-capped hold followed by a later genuine attacker
// disengage ends as "Attacker disengaged" — the real engagement win, not under-credited.
func TestBuildJourneyTerminalDisengageWins(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		ev(0xD, 2, "contain", ".env", 0, intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity), TimeHeldSec: 8, DisengageReason: contract.DisengageDefenderCapped}, nil),
		ev(0xD, 2, "contain", ".env", 5, intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity), TimeHeldSec: 3, DisengageReason: contract.DisengageAttacker}, nil),
	}
	j := Derive(TapState{Scope: "s"}, events, base.Add(time.Minute)).Journey
	if j.Latest == nil || j.Latest.Title != "Attacker disengaged" {
		t.Fatalf("terminal attacker-disengage must win the closing beat, got %+v", j.Latest)
	}
}

// No flow => journey absent (not a fabricated arc).
func TestBuildJourneyNoFlow(t *testing.T) {
	if j := Derive(TapState{Scope: "s"}, nil, base).Journey; j.Present {
		t.Fatalf("no events => journey must be absent, got %+v", j)
	}
}
