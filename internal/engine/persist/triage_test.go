package persist

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/canarysting/canarysting/internal/contract"
)

// devTriageKey is a fake canonical deviantKey-shaped byte string for tests (the real
// shape is [0x01][fam][src][dst][port][peakDim]; only the BYTES matter for the
// overlay — it is opaque to the store).
func devTriageKey(b ...byte) []byte { return append([]byte{0x01}, b...) }

// Suppress/ack write an overlay row; Get/Range read it back; unsuppress (Delete)
// clears it. Round-trip + the resulting state is exactly what was written.
func TestDeviantTriageRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "triage.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	key := devTriageKey(0x02, 0x0a, 0x00, 0x01, 0x05)
	rec := DeviantTriageRecord{State: TriageSuppressed, By: "alice", When: time.Now().UTC(), Why: "known scanner", SrcAddr: "10.20.1.104"}
	if err := s.PutDeviantTriage("scopeA", key, rec); err != nil {
		t.Fatalf("PutDeviantTriage: %v", err)
	}

	got, ok, err := s.GetDeviantTriage("scopeA", key)
	if err != nil || !ok {
		t.Fatalf("GetDeviantTriage: ok=%v err=%v", ok, err)
	}
	if got.State != TriageSuppressed || got.By != "alice" || got.Why != "known scanner" || got.SrcAddr != "10.20.1.104" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Range yields exactly the one row, keyed by the same bytes.
	count := 0
	if err := s.RangeDeviantTriage("scopeA", func(k []byte, r DeviantTriageRecord) error {
		count++
		if string(k) != string(key) {
			t.Fatalf("range key = %x, want %x", k, key)
		}
		if r.State != TriageSuppressed {
			t.Fatalf("range state = %q, want suppressed", r.State)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("range count = %d, want 1", count)
	}

	// Re-ack the SAME key overwrites the state (acked replaces suppressed).
	if err := s.PutDeviantTriage("scopeA", key, DeviantTriageRecord{State: TriageAcked, By: "bob", When: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetDeviantTriage("scopeA", key)
	if got.State != TriageAcked || got.By != "bob" {
		t.Fatalf("re-write did not overwrite: %+v", got)
	}

	// Unsuppress (Delete) clears it; Get reports absent (the implicit normal state).
	if err := s.DeleteDeviantTriage("scopeA", key); err != nil {
		t.Fatalf("DeleteDeviantTriage: %v", err)
	}
	if _, ok, _ := s.GetDeviantTriage("scopeA", key); ok {
		t.Fatal("overlay row still present after delete (un-suppress)")
	}
	// Delete of an absent key is an idempotent no-op success.
	if err := s.DeleteDeviantTriage("scopeA", key); err != nil {
		t.Fatalf("idempotent delete errored: %v", err)
	}
}

// The overlay is SCOPE-ISOLATED by layout (Rule 5): a row written under scopeA is
// invisible to scopeB.
func TestDeviantTriageScopeIsolated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "triage-scope.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key := devTriageKey(0xaa)
	if err := s.PutDeviantTriage("scopeA", key, DeviantTriageRecord{State: TriageSuppressed}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetDeviantTriage("scopeB", key); ok {
		t.Fatal("scopeB sees scopeA's overlay row — scope isolation broken")
	}
	// RangeDeviantTriageScopes enumerates only the scope that has an overlay row.
	scopes := map[string]bool{}
	if err := s.RangeDeviantTriageScopes(func(sc contract.ScopeKey) error {
		scopes[string(sc)] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !scopes["scopeA"] || scopes["scopeB"] {
		t.Fatalf("RangeDeviantTriageScopes = %v, want only scopeA", scopes)
	}
}

// LIFECYCLE DECOUPLING (load-bearing): the overlay row survives "record recapture".
// The underlying DeviantFlowRecord is mutated on recapture and destroyed on
// reap/evict, but the overlay is keyed independently by the deviantKey and is NEVER
// deleted except by an explicit un-suppress. We model the bktDeviants churn by
// writing+deleting a deviant record under the SAME key while the overlay row stays
// put, then confirm the overlay still applies.
func TestDeviantTriageSurvivesRecordChurn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "triage-churn.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	key := devTriageKey(0x02, 0x0a, 0x07, 0xbb)
	if err := s.PutDeviantTriage("scopeA", key, DeviantTriageRecord{State: TriageSuppressed, By: "alice"}); err != nil {
		t.Fatal(err)
	}
	// Simulate the bktDeviants record being created, then TTL-reaped/evicted (deleted)
	// under the SAME key — the overlay store is a SEPARATE bucket and is untouched.
	if err := s.PutBucketsAndHeartbeat(nil, nil, []DeviantWrite{
		{Scope: "scopeA", Key: key, Blob: []byte("deviant-record")},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.PutBucketsAndHeartbeat(nil, nil, []DeviantWrite{
		{Scope: "scopeA", Key: key, Delete: true},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// The deviant record is gone, but the suppression overlay STILL applies — a
	// reaped-then-recurring suppressed pattern stays suppressed.
	got, ok, err := s.GetDeviantTriage("scopeA", key)
	if err != nil || !ok {
		t.Fatalf("overlay lost after deviant-record churn: ok=%v err=%v", ok, err)
	}
	if got.State != TriageSuppressed {
		t.Fatalf("overlay state after churn = %q, want suppressed", got.State)
	}
}

// PutDeviantTriage rejects a bad state and an empty key (it cannot persist a
// meaningless triage row); the read-only store refuses writes.
func TestDeviantTriageGuards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "triage-guard.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key := devTriageKey(0x01)
	if err := s.PutDeviantTriage("scopeA", key, DeviantTriageRecord{State: "bogus"}); err == nil {
		t.Fatal("expected error for invalid triage state")
	}
	if err := s.PutDeviantTriage("scopeA", nil, DeviantTriageRecord{State: TriageSuppressed}); err == nil {
		t.Fatal("expected error for empty key")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if err := ro.PutDeviantTriage("scopeA", key, DeviantTriageRecord{State: TriageSuppressed}); err != ErrReadOnly {
		t.Fatalf("read-only Put err = %v, want ErrReadOnly", err)
	}
	if err := ro.DeleteDeviantTriage("scopeA", key); err != ErrReadOnly {
		t.Fatalf("read-only Delete err = %v, want ErrReadOnly", err)
	}
}

// Back-compat: a store created BEFORE bktDeviantTriage existed (no triage bucket on
// disk, schema_version == 1) must still open cleanly — CreateBucketIfNotExists is
// tolerant and SchemaVersion is UNCHANGED, so a multi-week live baseline.db is not
// invalidated by the new overlay bucket.
func TestOpenBackCompatWithoutDeviantTriageBucket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-triage.db")
	s, ver, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if ver != SchemaVersion {
		t.Fatalf("fresh store schema = %d, want %d", ver, SchemaVersion)
	}
	if err := s.PutBucket("scopeA", "b1", []byte("legacy-baseline")); err != nil {
		t.Fatal(err)
	}
	// Simulate a pre-triage store: delete the triage bucket Open created.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bktDeviantTriage) != nil {
			return tx.DeleteBucket(bktDeviantTriage)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, ver2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen of legacy (pre-triage) store failed: %v", err)
	}
	defer s2.Close()
	if ver2 != SchemaVersion {
		t.Fatalf("legacy reopen schema = %d, want %d (must NOT bump)", ver2, SchemaVersion)
	}
	blob, ok, err := s2.GetBucket("scopeA", "b1")
	if err != nil || !ok || string(blob) != "legacy-baseline" {
		t.Fatalf("legacy baseline lost on reopen: ok=%v blob=%q err=%v", ok, blob, err)
	}
	// The triage bucket was recreated tolerantly: a write now succeeds.
	if err := s2.PutDeviantTriage("scopeA", devTriageKey(0x09), DeviantTriageRecord{State: TriageAcked}); err != nil {
		t.Fatalf("triage write after legacy reopen failed: %v", err)
	}
}
