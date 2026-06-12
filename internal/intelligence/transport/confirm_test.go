package transport

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/canarysting/canarysting/internal/intelligence/network"
)

func TestConfirmSpoolRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "confirm.ndjson")
	s := NewConfirmSpool(path)
	pat := []byte(`{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":true,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1}`)
	if err := s.SendConfirmation("tok-a", pat); err != nil {
		t.Fatal(err)
	}
	if err := s.SendConfirmation("tok-b", pat); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReceiveConfirmations()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("received %d confirmations, want 2", len(got))
	}
	if got[0].Scope != "tok-a" || string(got[0].Pattern) != string(pat) {
		t.Fatalf("round-trip wrong: scope=%q pattern=%s", got[0].Scope, got[0].Pattern)
	}
}

func TestSendConfirmationRejects(t *testing.T) {
	s := NewConfirmSpool(filepath.Join(t.TempDir(), "c.ndjson"))
	if err := s.SendConfirmation("", []byte(`{}`)); err == nil {
		t.Fatal("empty scope token must be rejected")
	}
	if err := s.SendConfirmation("tok", []byte("a\nb")); err == nil {
		t.Fatal("a pattern with a newline must be rejected (NDJSON framing)")
	}
}

// A malformed line is skipped (error reported) but the valid confirmations are kept; a
// confirmation missing scope or pattern is dropped.
func TestReceiveConfirmationsSkipsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.ndjson")
	s := NewConfirmSpool(path)
	pat := []byte(`{"ReachedContain":true}`)
	if err := s.SendConfirmation("tok-a", pat); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("not json\n")
	f.WriteString(`{"scope":"","pattern":{}}` + "\n") // missing scope
	f.Close()
	if err := s.SendConfirmation("tok-b", pat); err != nil {
		t.Fatal(err)
	}

	got, err := s.ReceiveConfirmations()
	if err == nil {
		t.Fatal("Receive must report the malformed/incomplete lines")
	}
	if len(got) != 2 {
		t.Fatalf("kept %d valid confirmations, want 2", len(got))
	}
}

func TestReceiveConfirmationsMissingFile(t *testing.T) {
	got, err := NewConfirmSpool(filepath.Join(t.TempDir(), "nope.ndjson")).ReceiveConfirmations()
	if err != nil || got != nil {
		t.Fatalf("missing spool = (%v, %v), want (nil, nil)", got, err)
	}
}

// The full D6-3 loop in one process (the aggregator's substance): 3 ENROLLED scopes + 1
// FORGED confirm the same coarse pattern -> the forged one is rejected -> at k=3 the
// pattern crosses the UNCHANGED chokepoint ONCE -> lands as exactly one SharedPattern in
// the consumer spool. The cross-customer money-shot, end to end, with the k-provenance
// guard holding (the forged token never inflates k).
func TestEndToEndCrossScopeCrossing(t *testing.T) {
	dir := t.TempDir()
	in := NewConfirmSpool(filepath.Join(dir, "confirm.ndjson"))
	out := NewSpool(filepath.Join(dir, "cleared.ndjson"))
	pat := []byte(`{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":true,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1}`)
	for _, tok := range []string{"a", "b", "c", "forged"} {
		if err := in.SendConfirmation(tok, pat); err != nil {
			t.Fatal(err)
		}
	}

	ledger, err := network.NewAggregatorLedger(func(tok string) bool { return tok == "a" || tok == "b" || tok == "c" })
	if err != nil {
		t.Fatal(err)
	}
	confs, _ := in.ReceiveConfirmations()
	sent := map[network.SharedPattern]bool{}
	for _, c := range confs {
		sp, err := network.ParseSharedPattern(c.Pattern)
		if err != nil {
			continue
		}
		if _, err := ledger.IngestConfirmation(c.Scope, sp); err != nil {
			continue // the forged token is rejected here
		}
		if cleared, err := network.ClearWithLedger(network.SharedCandidate(sp), network.ClearContext{Ledger: ledger}); err == nil && !sent[sp] {
			sent[sp] = true
			if err := out.Send(cleared); err != nil {
				t.Fatal(err)
			}
		}
	}

	got, err := out.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("consumer spool has %d patterns, want exactly 1 (crossed once at k=3; forged token rejected)", len(got))
	}
}
