package tap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAttackLedgerRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	src := &Source{Now: func() time.Time { return now }}
	srv := httptest.NewServer(src.Handler())
	defer srv.Close()

	// Before any PUT: GET reports not present.
	resp, err := http.Get(srv.URL + "/raw/attack-ledger")
	if err != nil {
		t.Fatal(err)
	}
	var pre map[string]any
	json.NewDecoder(resp.Body).Decode(&pre)
	resp.Body.Close()
	if present, _ := pre["present"].(bool); present {
		t.Fatalf("want present=false before any PUT, got %v", pre)
	}

	// PUT a ledger.
	body, _ := json.Marshal(AttackLedger{
		InputTokens: 45230, OutputTokens: 8110, CacheReadTokens: 31000,
		USD: 0.46, HardCapUSD: 5.0, Model: "claude-opus-4-8", Active: true,
	})
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/raw/attack-ledger", bytes.NewReader(body))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204 on PUT, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// GET returns the stored ledger with UpdatedAt stamped.
	resp, _ = http.Get(srv.URL + "/raw/attack-ledger")
	var got AttackLedger
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got.InputTokens != 45230 || got.USD != 0.46 || got.Model != "claude-opus-4-8" {
		t.Fatalf("ledger round-trip mismatch: %+v", got)
	}
	if !got.Active {
		t.Fatalf("ledger should be active immediately after PUT")
	}
	if !got.UpdatedAt.Equal(now) {
		t.Fatalf("UpdatedAt not stamped: %v", got.UpdatedAt)
	}
}

func TestAttackLedgerGoesStale(t *testing.T) {
	cur := time.Unix(1_700_000_000, 0)
	src := &Source{Now: func() time.Time { return cur }}
	_ = src.Handler() // init ledger store

	src.ledger.set(AttackLedger{USD: 1.0, Active: true}, cur)
	// advance past the stale window
	cur = cur.Add(ledgerStaleAfter + time.Second)
	led, ok := src.ledger.get(cur, ledgerStaleAfter)
	if !ok {
		t.Fatal("ledger should still be present, just stale")
	}
	if led.Active {
		t.Fatal("ledger past stale window must report Active=false")
	}
}
