package main

import (
	"path/filepath"
	"testing"

	"github.com/canarysting/canarysting/internal/intelligence/network"
	"github.com/canarysting/canarysting/internal/intelligence/transport"
)

const demoPattern = `{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":true,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1}`

// The money-shot loop integrity: a forged/un-enrolled token NEVER contributes to k, so 2
// enrolled + 1 forged stays sub-k and nothing crosses; the 3rd ENROLLED confirmation
// crosses exactly once. This is the highest-level proof the gaming attack is bounded
// end-to-end through the aggregator.
func TestAggregatorIngestCrossesOnlyAtKEnrolled(t *testing.T) {
	dir := t.TempDir()
	in := transport.NewConfirmSpool(filepath.Join(dir, "confirm.ndjson"))
	out := transport.NewSpool(filepath.Join(dir, "cleared.ndjson"))
	ledger, err := network.NewAggregatorLedger(func(tok string) bool { return tok == "a" || tok == "b" || tok == "c" })
	if err != nil {
		t.Fatal(err)
	}
	sent := map[network.SharedPattern]bool{}

	// 2 enrolled + 1 forged → sub-k, nothing crosses.
	for _, tok := range []string{"a", "b", "forged"} {
		if err := in.SendConfirmation(tok, []byte(demoPattern)); err != nil {
			t.Fatal(err)
		}
	}
	if n := ingest(in, out, ledger, sent); n != 0 {
		t.Fatalf("2 enrolled + 1 forged crossed %d patterns, want 0", n)
	}
	if got, _ := out.Receive(); len(got) != 0 {
		t.Fatalf("consumer spool has %d patterns, want 0 (sub-k)", len(got))
	}

	// The 3rd ENROLLED confirmation → k=3 → crosses exactly once.
	if err := in.SendConfirmation("c", []byte(demoPattern)); err != nil {
		t.Fatal(err)
	}
	if n := ingest(in, out, ledger, sent); n != 1 {
		t.Fatalf("the 3rd enrolled confirmation crossed %d patterns, want 1", n)
	}
	// Re-running ingest must NOT re-send the already-crossed pattern (dedup).
	if n := ingest(in, out, ledger, sent); n != 0 {
		t.Fatalf("re-ingest crossed %d, want 0 (dedup)", n)
	}
	if got, _ := out.Receive(); len(got) != 1 {
		t.Fatalf("consumer spool has %d patterns, want exactly 1", len(got))
	}
}

func TestLoadTokens(t *testing.T) {
	if m := loadTokens("", ""); len(m) != 0 {
		t.Fatalf("empty inputs => empty allowlist, got %d (the aggregator must then refuse to start)", len(m))
	}
	m := loadTokens(" a , b ,, c ", "")
	if len(m) != 3 {
		t.Fatalf("CSV parse: got %d tokens, want 3 (trimmed, empties dropped)", len(m))
	}
	for _, tok := range []string{"a", "b", "c"} {
		if _, ok := m[tok]; !ok {
			t.Fatalf("token %q missing from the allowlist", tok)
		}
	}
}
