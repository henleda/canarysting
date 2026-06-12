package transport

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/network"
	"github.com/canarysting/canarysting/internal/intelligence/profile"
)

// ledgerVerifiedCleared builds a real, transmittable carrier: a derived Profile ->
// Candidate (opted-in, no producer count) cleared through a ledger driven to k>=3.
func ledgerVerifiedCleared(t *testing.T) *network.Cleared {
	t.Helper()
	base := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	p := profile.DeriveProfile([]intelligence.AdversaryInteractionEvent{
		{CanaryType: ".env", Tier: 3, Timestamp: base, Sting: intelligence.StingOutcome{
			Axes: uint32(contract.AxisVelocity | contract.AxisPoison), TimeHeldSec: 10,
			PoisonReached: 2, PoisonClass: "topology", DisengageReason: contract.DisengageAttacker, TimeToDisengageSec: 5,
		}},
		{CanaryType: "x", Tier: 3, Timestamp: base.Add(time.Second), Sting: intelligence.StingOutcome{Axes: uint32(contract.AxisVelocity)}},
	})
	cand := p.Candidate(network.ContributionContext{Contribute: true})
	l, err := network.NewLedger()
	if err != nil {
		t.Fatal(err)
	}
	exp, _ := cand.EgressFields()
	for _, s := range []string{"a", "b", "c"} {
		if _, err := l.RecordForm(s, exp); err != nil {
			t.Fatal(err)
		}
	}
	c, err := network.ClearWithLedger(cand, network.ClearContext{Ledger: l})
	if err != nil {
		t.Fatalf("ClearWithLedger: %v", err)
	}
	return c
}

func TestSpoolSendReceiveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.ndjson")
	s := NewSpool(path)
	if err := s.Send(ledgerVerifiedCleared(t)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := s.Send(ledgerVerifiedCleared(t)); err != nil {
		t.Fatalf("Send 2: %v", err)
	}
	got, err := s.Receive()
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("received %d patterns, want 2", len(got))
	}
	if !got[0].EngagedVelocity || !got[0].EngagedPoison || got[0].PoisonClass != "topology" {
		t.Fatalf("round-tripped pattern wrong: %+v", got[0])
	}
}

// A form-only Clear() carrier (no ledger verification) must NOT be sendable — Marshal
// refuses it, so the transport cannot emit it.
func TestSpoolRejectsFormOnlyCarrier(t *testing.T) {
	formOnly, err := network.Clear(network.ReferenceCandidate())
	if err != nil {
		t.Fatal(err)
	}
	s := NewSpool(filepath.Join(t.TempDir(), "spool.ndjson"))
	if err := s.Send(formOnly); err == nil {
		t.Fatal("Send must reject a form-only (non-ledger-verified) carrier")
	}
}

func TestSpoolReceiveMissingFileIsEmpty(t *testing.T) {
	got, err := NewSpool(filepath.Join(t.TempDir(), "nope.ndjson")).Receive()
	if err != nil || got != nil {
		t.Fatalf("missing spool = (%v, %v), want (nil, nil)", got, err)
	}
}

// A malformed line is skipped (error reported) but never drops the valid ones.
func TestSpoolReceiveSkipsMalformedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.ndjson")
	s := NewSpool(path)
	if err := s.Send(ledgerVerifiedCleared(t)); err != nil {
		t.Fatal(err)
	}
	// Append a garbage line + a structurally-wrong-but-JSON line.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("this is not json\n")
	f.WriteString(`{"ReachedContain":true}` + "\n") // too few fields
	f.Close()
	if err := s.Send(ledgerVerifiedCleared(t)); err != nil {
		t.Fatal(err)
	}

	got, err := s.Receive()
	if err == nil {
		t.Fatal("Receive must report that some lines failed to parse")
	}
	if len(got) != 2 {
		t.Fatalf("received %d valid patterns, want 2 (malformed lines skipped, valid kept)", len(got))
	}
}

// An over-long line (> the 1 MiB scan cap) terminates the scan fail-closed: it errors,
// never panics, and never truncate-and-misparses the giant line into a SharedPattern.
func TestSpoolReceiveOverLongLineFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.ndjson")
	huge := make([]byte, 2*1024*1024) // 2 MiB, no newline
	for i := range huge {
		huge[i] = 'x'
	}
	if err := os.WriteFile(path, append(huge, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := NewSpool(path).Receive()
	if err == nil {
		t.Fatal("an over-long line must surface an error (fail-closed)")
	}
	if len(got) != 0 {
		t.Fatalf("an over-long line must not parse into a pattern, got %d", len(got))
	}
}
