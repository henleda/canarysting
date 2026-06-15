package persist

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

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

// RangeEventsRecent must visit a scope's MOST-RECENT events first (reverse seq
// order) and stop at maxN — the bound that keeps the matcher hot-path query
// O(maxN) instead of O(whole log). maxN<=0 means a full reverse scan.
func TestRangeEventsRecentNewestFirstAndCapped(t *testing.T) {
	s := openTemp(t)
	for _, b := range []string{"e1", "e2", "e3", "e4", "e5"} {
		if _, err := s.AppendEvent("scopeA", []byte(b)); err != nil {
			t.Fatal(err)
		}
	}
	collect := func(maxN int) []string {
		var got []string
		if err := s.RangeEventsRecent("scopeA", maxN, func(_ uint64, blob []byte) error {
			got = append(got, string(blob))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	// Cap of 2 -> exactly the two NEWEST, newest-first.
	if got := collect(2); len(got) != 2 || got[0] != "e5" || got[1] != "e4" {
		t.Fatalf("RangeEventsRecent(2) = %v, want [e5 e4]", got)
	}
	// maxN<=0 -> full reverse scan (all five, newest-first).
	if got := collect(0); len(got) != 5 || got[0] != "e5" || got[4] != "e1" {
		t.Fatalf("RangeEventsRecent(0) = %v, want all newest-first", got)
	}
	// Cap larger than the log -> all of them, no over-read.
	if got := collect(99); len(got) != 5 {
		t.Fatalf("RangeEventsRecent(99) len = %d, want 5", len(got))
	}
	// Scope isolation: a recent scan of another scope yields nothing.
	var other []string
	_ = s.RangeEventsRecent("scopeB", 10, func(_ uint64, blob []byte) error {
		other = append(other, string(blob))
		return nil
	})
	if len(other) != 0 {
		t.Fatalf("RangeEventsRecent on empty scope = %v, want none", other)
	}
	// An fn error propagates and stops the scan.
	sentinel := errors.New("stop")
	if err := s.RangeEventsRecent("scopeA", 0, func(_ uint64, _ []byte) error {
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("fn error not propagated: %v", err)
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

// Topology writes ride PutBucketsAndHeartbeat (the single fold-tick fsync) and
// are readable back per-scope, scope-isolated. A Delete entry removes the key in
// the same transaction (how reaper evictions are persisted).
func TestTopologyWriteRangeAndDelete(t *testing.T) {
	s := openTemp(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	topo := []TopologyWrite{
		{Scope: "scopeA", Key: []byte{0x01, 0xAA}, Blob: []byte("edge-A")},
		{Scope: "scopeA", Key: []byte{0x02, 0xBB}, Blob: []byte("node-A")},
		{Scope: "scopeB", Key: []byte{0x01, 0xAA}, Blob: []byte("edge-B")},
	}
	if err := s.PutBucketsAndHeartbeat(nil, topo, nil, now); err != nil {
		t.Fatalf("PutBucketsAndHeartbeat(topology): %v", err)
	}
	// The heartbeat also committed in the same transaction.
	if _, ok, _ := s.LastObserveSeen(); !ok {
		t.Fatal("heartbeat not written alongside topology")
	}

	collect := func(sc contract.ScopeKey) map[string]string {
		out := map[string]string{}
		if err := s.RangeTopology(sc, func(k, v []byte) error {
			out[string(k)] = string(v)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	a := collect("scopeA")
	if len(a) != 2 || a[string([]byte{0x01, 0xAA})] != "edge-A" || a[string([]byte{0x02, 0xBB})] != "node-A" {
		t.Fatalf("scopeA topology = %v", a)
	}
	// Scope isolation: scopeB's same key holds its own value, never scopeA's.
	b := collect("scopeB")
	if len(b) != 1 || b[string([]byte{0x01, 0xAA})] != "edge-B" {
		t.Fatalf("scopeB topology = %v (scope bleed?)", b)
	}
	// RangeTopologyScopes enumerates exactly the two scopes that have records.
	seen := map[contract.ScopeKey]bool{}
	if err := s.RangeTopologyScopes(func(sc contract.ScopeKey) error { seen[sc] = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !seen["scopeA"] || !seen["scopeB"] || len(seen) != 2 {
		t.Fatalf("RangeTopologyScopes = %v", seen)
	}

	// A Delete entry removes the key (a reaper eviction) in the batched write.
	del := []TopologyWrite{{Scope: "scopeA", Key: []byte{0x02, 0xBB}, Delete: true}}
	if err := s.PutBucketsAndHeartbeat(nil, del, nil, now); err != nil {
		t.Fatal(err)
	}
	a = collect("scopeA")
	if len(a) != 1 || a[string([]byte{0x01, 0xAA})] != "edge-A" {
		t.Fatalf("after delete scopeA topology = %v, want only the edge", a)
	}

	// An empty scope in a topology write is refused (no unscoped state).
	if err := s.PutBucketsAndHeartbeat(nil, []TopologyWrite{{Scope: "", Key: []byte{0x01}, Blob: []byte("x")}}, nil, now); err == nil {
		t.Fatal("empty scope in topology write accepted")
	}
}

// Deviant writes ride PutBucketsAndHeartbeat (the single fold-tick fsync) and are
// readable back per-scope, scope-isolated. A Delete entry removes the key in the
// same transaction (how reaper evictions are persisted). Mirrors the topology test.
func TestDeviantWriteRangeAndDelete(t *testing.T) {
	s := openTemp(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	deviants := []DeviantWrite{
		{Scope: "scopeA", Key: []byte{0x01, 0xAA}, Blob: []byte("dev-A1")},
		{Scope: "scopeA", Key: []byte{0x01, 0xBB}, Blob: []byte("dev-A2")},
		{Scope: "scopeB", Key: []byte{0x01, 0xAA}, Blob: []byte("dev-B1")},
	}
	if err := s.PutBucketsAndHeartbeat(nil, nil, deviants, now); err != nil {
		t.Fatalf("PutBucketsAndHeartbeat(deviants): %v", err)
	}
	if _, ok, _ := s.LastObserveSeen(); !ok {
		t.Fatal("heartbeat not written alongside deviants")
	}

	collect := func(sc contract.ScopeKey) map[string]string {
		out := map[string]string{}
		if err := s.RangeDeviants(sc, func(k, v []byte) error {
			out[string(k)] = string(v)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	a := collect("scopeA")
	if len(a) != 2 || a[string([]byte{0x01, 0xAA})] != "dev-A1" || a[string([]byte{0x01, 0xBB})] != "dev-A2" {
		t.Fatalf("scopeA deviants = %v", a)
	}
	// Scope isolation: scopeB's same key holds its own value, never scopeA's.
	b := collect("scopeB")
	if len(b) != 1 || b[string([]byte{0x01, 0xAA})] != "dev-B1" {
		t.Fatalf("scopeB deviants = %v (scope bleed?)", b)
	}
	// RangeDeviantScopes enumerates exactly the two scopes that have records.
	seen := map[contract.ScopeKey]bool{}
	if err := s.RangeDeviantScopes(func(sc contract.ScopeKey) error { seen[sc] = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !seen["scopeA"] || !seen["scopeB"] || len(seen) != 2 {
		t.Fatalf("RangeDeviantScopes = %v", seen)
	}

	// A Delete entry removes the key (a reaper eviction) in the batched write.
	del := []DeviantWrite{{Scope: "scopeA", Key: []byte{0x01, 0xBB}, Delete: true}}
	if err := s.PutBucketsAndHeartbeat(nil, nil, del, now); err != nil {
		t.Fatal(err)
	}
	a = collect("scopeA")
	if len(a) != 1 || a[string([]byte{0x01, 0xAA})] != "dev-A1" {
		t.Fatalf("after delete scopeA deviants = %v, want only dev-A1", a)
	}

	// An empty scope in a deviant write is refused (no unscoped state).
	if err := s.PutBucketsAndHeartbeat(nil, nil, []DeviantWrite{{Scope: "", Key: []byte{0x01}, Blob: []byte("x")}}, now); err == nil {
		t.Fatal("empty scope in deviant write accepted")
	}
}

// Back-compat: a store created BEFORE bktDeviants existed (no deviants bucket on
// disk, schema_version == 1) must still open cleanly — CreateBucketIfNotExists is
// tolerant and SchemaVersion is UNCHANGED, so a multi-week live baseline.db is not
// invalidated. We simulate the old store by opening, deleting the deviants bucket,
// and reopening; the reopen must succeed, report the SAME SchemaVersion, and the
// pre-existing baseline data must survive.
func TestOpenBackCompatWithoutDeviantsBucket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-deviants.db")

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
	// Simulate a pre-deviants store: delete the deviants bucket that Open created.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bktDeviants) != nil {
			return tx.DeleteBucket(bktDeviants)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: must succeed, SAME schema (no bump), baseline intact, and the deviants
	// bucket recreated tolerantly.
	s2, ver2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen of legacy (pre-deviants) store failed: %v", err)
	}
	defer s2.Close()
	if ver2 != SchemaVersion {
		t.Fatalf("legacy reopen schema = %d, want %d (must NOT bump)", ver2, SchemaVersion)
	}
	blob, ok, err := s2.GetBucket("scopeA", "b1")
	if err != nil || !ok || string(blob) != "legacy-baseline" {
		t.Fatalf("legacy baseline lost on reopen: ok=%v blob=%q err=%v", ok, blob, err)
	}
	if err := s2.PutBucketsAndHeartbeat(nil, nil, []DeviantWrite{
		{Scope: "scopeA", Key: []byte{0x01, 0x01}, Blob: []byte("d")},
	}, time.Now()); err != nil {
		t.Fatalf("deviant write after legacy reopen failed: %v", err)
	}
}

// Back-compat: a store created BEFORE bktTopology existed (no topology bucket on
// disk, schema_version == 1) must still open cleanly — CreateBucketIfNotExists is
// tolerant and SchemaVersion is UNCHANGED, so a multi-week live baseline.db is not
// invalidated. We simulate the old store by opening, deleting the topology bucket,
// and reopening; the reopen must succeed, report the SAME SchemaVersion, and the
// pre-existing baseline data must survive.
func TestOpenBackCompatWithoutTopologyBucket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

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
	// Simulate a pre-topology store: delete the topology bucket that Open created.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bktTopology) != nil {
			return tx.DeleteBucket(bktTopology)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bktTopology) != nil {
			t.Fatal("topology bucket still present after delete (setup failed)")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen the legacy store: must succeed, same schema, baseline intact, and the
	// topology bucket recreated tolerantly (no refuse-to-start, no version bump).
	s2, ver2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen of legacy (pre-topology) store failed: %v", err)
	}
	defer s2.Close()
	if ver2 != SchemaVersion {
		t.Fatalf("legacy reopen schema = %d, want %d (must NOT bump)", ver2, SchemaVersion)
	}
	blob, ok, err := s2.GetBucket("scopeA", "b1")
	if err != nil || !ok || string(blob) != "legacy-baseline" {
		t.Fatalf("legacy baseline lost on reopen: ok=%v blob=%q err=%v", ok, blob, err)
	}
	// Topology now usable (the bucket was recreated on open).
	if err := s2.PutBucketsAndHeartbeat(nil, []TopologyWrite{
		{Scope: "scopeA", Key: []byte{0x01, 0x01}, Blob: []byte("e")},
	}, nil, time.Now()); err != nil {
		t.Fatalf("topology write after legacy reopen failed: %v", err)
	}
}
