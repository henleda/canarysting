package persist

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.db")
	s, ver, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ver != SchemaVersion {
		t.Fatalf("fresh store schema = %d, want %d", ver, SchemaVersion)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBucketRoundTrip(t *testing.T) {
	s := openTemp(t)
	if err := s.PutBucket("scopeA", "weekday-morning", []byte("agg-blob-A")); err != nil {
		t.Fatal(err)
	}
	blob, ok, err := s.GetBucket("scopeA", "weekday-morning")
	if err != nil || !ok {
		t.Fatalf("GetBucket ok=%v err=%v", ok, err)
	}
	if string(blob) != "agg-blob-A" {
		t.Fatalf("blob = %q", blob)
	}
	if _, ok, _ := s.GetBucket("scopeA", "missing"); ok {
		t.Fatal("missing bucket reported present")
	}
}

// Scope isolation (CLAUDE.md rule 5): data written under one scope is invisible
// to a read of another scope, and a range over a scope yields only that scope's
// keys. A cross-scope read is only possible by explicitly naming the other scope.
func TestScopeIsolation(t *testing.T) {
	s := openTemp(t)
	if err := s.PutBucket("tenant-A", "b1", []byte("A-data")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutBucket("tenant-B", "b1", []byte("B-data")); err != nil {
		t.Fatal(err)
	}
	// Same key, different scope -> different value, never bleeding across.
	a, _, _ := s.GetBucket("tenant-A", "b1")
	b, _, _ := s.GetBucket("tenant-B", "b1")
	if string(a) != "A-data" || string(b) != "B-data" {
		t.Fatalf("scope bleed: A=%q B=%q", a, b)
	}
	// A range over tenant-A must not surface tenant-B's keys.
	count := 0
	if err := s.RangeBuckets("tenant-A", func(k string, v []byte) error {
		count++
		if string(v) != "A-data" {
			t.Fatalf("range over tenant-A saw foreign value %q", v)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("range count = %d, want 1", count)
	}
	// RangeScopes enumerates exactly the two scopes.
	seen := map[contract.ScopeKey]bool{}
	if err := s.RangeScopes(func(sc contract.ScopeKey) error { seen[sc] = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !seen["tenant-A"] || !seen["tenant-B"] || len(seen) != 2 {
		t.Fatalf("RangeScopes = %v", seen)
	}
}

func TestMaliciousSet(t *testing.T) {
	s := openTemp(t)
	const h = uint64(0xDEADBEEF)
	if ok, _ := s.IsMalicious("scopeA", h); ok {
		t.Fatal("unset hash reported malicious")
	}
	if err := s.MarkMalicious("scopeA", h); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.IsMalicious("scopeA", h); !ok {
		t.Fatal("marked hash not malicious")
	}
	// Scope-isolated: the same hash is not malicious in another scope.
	if ok, _ := s.IsMalicious("scopeB", h); ok {
		t.Fatal("malicious mark bled across scope")
	}
	got := map[uint64]bool{}
	_ = s.RangeMalicious("scopeA", func(x uint64) error { got[x] = true; return nil })
	if !got[h] || len(got) != 1 {
		t.Fatalf("RangeMalicious = %v", got)
	}
}

func TestEventLogMonotonicAndScoped(t *testing.T) {
	s := openTemp(t)
	seq1, err := s.AppendEvent("scopeA", []byte("e1"))
	if err != nil {
		t.Fatal(err)
	}
	seq2, _ := s.AppendEvent("scopeA", []byte("e2"))
	if seq1 != 1 || seq2 != 2 {
		t.Fatalf("seqs = %d,%d want 1,2", seq1, seq2)
	}
	// A different scope's sequence is independent (starts at 1).
	seqB, _ := s.AppendEvent("scopeB", []byte("b1"))
	if seqB != 1 {
		t.Fatalf("scopeB first seq = %d, want 1", seqB)
	}
	var order []string
	_ = s.RangeEvents("scopeA", func(_ uint64, blob []byte) error {
		order = append(order, string(blob))
		return nil
	})
	if len(order) != 2 || order[0] != "e1" || order[1] != "e2" {
		t.Fatalf("event order = %v", order)
	}
}

func TestCoverageGapSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gap.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// No heartbeat yet -> no gap measurable.
	if _, ok, _ := s.CoverageGap(time.Now()); ok {
		t.Fatal("gap reported with no prior heartbeat")
	}
	hb := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := s.Heartbeat(hb); err != nil {
		t.Fatal(err)
	}
	gap, ok, err := s.CoverageGap(hb.Add(90 * time.Minute))
	if err != nil || !ok {
		t.Fatalf("CoverageGap ok=%v err=%v", ok, err)
	}
	if gap != 90*time.Minute {
		t.Fatalf("gap = %s, want 90m", gap)
	}
	// The heartbeat survives a reopen, so downtime across a restart is measurable.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	gap2, ok, err := s2.CoverageGap(hb.Add(3 * time.Hour))
	if err != nil || !ok {
		t.Fatalf("post-reopen CoverageGap ok=%v err=%v", ok, err)
	}
	if gap2 != 3*time.Hour {
		t.Fatalf("post-reopen gap = %s, want 3h", gap2)
	}
}

func TestReadOnlyRefusesWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ro.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.PutBucket("scopeA", "b1", []byte("x"))
	_ = s.Close()

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	// Reads work...
	if _, ok, _ := ro.GetBucket("scopeA", "b1"); !ok {
		t.Fatal("read-only store can't read")
	}
	// ...writes are refused, not silently dropped.
	if err := ro.PutBucket("scopeA", "b2", []byte("y")); err != ErrReadOnly {
		t.Fatalf("read-only write err = %v, want ErrReadOnly", err)
	}
	if _, err := ro.AppendEvent("scopeA", []byte("z")); err != ErrReadOnly {
		t.Fatalf("read-only append err = %v, want ErrReadOnly", err)
	}
}

func TestEmptyScopeRefused(t *testing.T) {
	s := openTemp(t)
	if err := s.PutBucket("", "b1", []byte("x")); err == nil {
		t.Fatal("empty scope accepted; must refuse to store unscoped state")
	}
}
