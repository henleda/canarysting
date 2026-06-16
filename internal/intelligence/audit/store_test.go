package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/persist"
)

// --- raw on-disk bbolt access for the DURABLE tamper tests ------------------
//
// These constants mirror the persist layout (internal/engine/persist/store.go):
// bktAuditChain/<scope>/{ "records" sub-bucket: 8-byte seq -> blob ; "head" -> 32-
// byte head }. The durable tamper tests reach AROUND the engine and edit the file
// directly — exactly the baseline.db-write adversary the threat model is about — so
// they must use the same byte layout the persist Store writes.
var (
	rawAuditChainBkt = []byte("auditchain")
	rawRecordsSub    = []byte("records")
	rawHeadKey       = []byte("head")
)

func seqKey(seq uint64) []byte {
	var k [8]byte
	binary.BigEndian.PutUint64(k[:], seq)
	return k[:]
}

// openDurableKeyed opens a durable store keyed (or not) with key, plus the on-disk
// path so a test can close it and tamper directly. Helper for the durable tests.
func openDurableKeyed(t *testing.T, key []byte) (*Store, *persist.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.db")
	p, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewWithConfig(p, Config{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return s, p, path
}

// rawEditRecordPath decodes the on-disk record at seq, edits its Path, and writes
// the gob blob back WITHOUT updating its hash or the head — a file-only attacker who
// does not (cannot, when keyed) recompute the chain.
func rawEditRecordPath(t *testing.T, path string, scope string, seq uint64, newPath string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		recs := tx.Bucket(rawAuditChainBkt).Bucket([]byte(scope)).Bucket(rawRecordsSub)
		r, err := decodeRecord(recs.Get(seqKey(seq)))
		if err != nil {
			return err
		}
		r.Path = newPath
		blob, err := encodeRecord(r)
		if err != nil {
			return err
		}
		return recs.Put(seqKey(seq), blob)
	}); err != nil {
		t.Fatal(err)
	}
}

// rawReforgeRecordPath is the KNOWLEDGEABLE attack: edit the record at seq AND
// recompute its hash + every downstream link + the head with the PUBLIC sha256
// chain (no key). Against an unkeyed chain this produces a chain Verify accepts;
// against a keyed chain the attacker cannot compute valid MACs, so it is detected.
func rawReforgeRecordPath(t *testing.T, path string, scope string, editSeq uint64, newPath string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		recs := tx.Bucket(rawAuditChainBkt).Bucket([]byte(scope)).Bucket(rawRecordsSub)
		// Re-link the whole chain with the public sha256 link (key=nil), editing editSeq.
		// The public chain seeds from the unkeyed per-scope genesis.
		prev := genesis(nil, contract.ScopeKey(scope))
		var lastHead []byte
		c := recs.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) != 8 || v == nil {
				continue
			}
			r, err := decodeRecord(v)
			if err != nil {
				return err
			}
			if r.Seq == editSeq {
				r.Path = newPath
			}
			r.PrevHash = prev
			h, err := computeHash(nil, prev, r) // public chain: no key
			if err != nil {
				return err
			}
			r.Hash = h
			blob, err := encodeRecord(r)
			if err != nil {
				return err
			}
			if err := recs.Put(append([]byte(nil), k...), blob); err != nil {
				return err
			}
			prev = h
			lastHead = h
		}
		// Rewrite the head to match the re-forged tail.
		return tx.Bucket(rawAuditChainBkt).Bucket([]byte(scope)).Put(rawHeadKey, lastHead)
	}); err != nil {
		t.Fatal(err)
	}
}

// rawReforgeRecordWithKey is the STRONGER knowledgeable attack (FIX B): re-forge the
// whole chain with an ATTACKER-CHOSEN HMAC key, stamping each record Keyed=true /
// Algo=hmac-sha256 so the mode-marker check PASSES. To ISOLATE the MAC recompute as
// the line of defense (and not let FIX A's per-scope genesis seed catch it first at
// the prev-hash step), the forger seeds seq 1's PrevHash from the genesis the REAL
// verifier expects — genesis(seedKey, scope) with seedKey == the real key. That is the
// HARDER forgery for the attacker: they get the genesis seed right for free, yet STILL
// cannot forge the body MAC without the real key. So the ONLY thing standing between
// the forgery and an "Intact" verdict is the MAC recompute under the real key — the
// keyed verifier must break at seq 1 with "hash does not recompute", proving the KEY
// (not the marker, not the genesis seed) is what defends a keyed chain. Body MACs are
// computed with attackerKey; the chain links internally under that key so prev-hash
// passes for every record (seq 1 from the real seed, the rest from the forged links).
func rawReforgeRecordWithKey(t *testing.T, path string, scope string, seedKey, attackerKey []byte, editSeq uint64, newPath string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		recs := tx.Bucket(rawAuditChainBkt).Bucket([]byte(scope)).Bucket(rawRecordsSub)
		prev := genesis(seedKey, contract.ScopeKey(scope)) // seed seq 1 from the genesis the REAL verifier expects
		var lastHead []byte
		c := recs.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) != 8 || v == nil {
				continue
			}
			r, err := decodeRecord(v)
			if err != nil {
				return err
			}
			if r.Seq == editSeq {
				r.Path = newPath
			}
			// Stamp the KEYED mode marker so the verifier's mode-marker check passes —
			// the forgery's only remaining hurdle is the MAC recompute under the real key.
			r.Keyed = true
			r.Algo = AlgoHMACSHA256
			r.PrevHash = prev
			h, err := computeHash(attackerKey, prev, r) // forged with the attacker's key
			if err != nil {
				return err
			}
			r.Hash = h
			blob, err := encodeRecord(r)
			if err != nil {
				return err
			}
			if err := recs.Put(append([]byte(nil), k...), blob); err != nil {
				return err
			}
			prev = h
			lastHead = h
		}
		return tx.Bucket(rawAuditChainBkt).Bucket([]byte(scope)).Put(rawHeadKey, lastHead)
	}); err != nil {
		t.Fatal(err)
	}
}

// rawCopyChainAcrossScopes is the CROSS-SCOPE RELOCATION forgery (FIX A): copy every
// record blob AND the head from srcScope's bucket verbatim into dstScope's bucket on
// the same on-disk store — the attacker lifts a valid chain wholesale into another
// scope's location, hoping a fresh Store verifying dstScope accepts it. The records
// keep their original Scope field and their src-scope genesis-seeded PrevHash, so a
// scope-bound Verify must reject them.
func rawCopyChainAcrossScopes(t *testing.T, path, srcScope, dstScope string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket(rawAuditChainBkt)
		src := root.Bucket([]byte(srcScope))
		if src == nil {
			return fmt.Errorf("src scope bucket %q missing", srcScope)
		}
		// (Re)create the destination scope bucket fresh.
		if root.Bucket([]byte(dstScope)) != nil {
			if err := root.DeleteBucket([]byte(dstScope)); err != nil {
				return err
			}
		}
		dst, err := root.CreateBucket([]byte(dstScope))
		if err != nil {
			return err
		}
		// Copy the head verbatim.
		if head := src.Get(rawHeadKey); head != nil {
			if err := dst.Put(rawHeadKey, append([]byte(nil), head...)); err != nil {
				return err
			}
		}
		// Copy every record blob verbatim (same seq keys, same bytes — Scope field and
		// PrevHash carried over unchanged).
		srcRecs := src.Bucket(rawRecordsSub)
		dstRecs, err := dst.CreateBucketIfNotExists(rawRecordsSub)
		if err != nil {
			return err
		}
		return srcRecs.ForEach(func(k, v []byte) error {
			if v == nil {
				return nil
			}
			return dstRecs.Put(append([]byte(nil), k...), append([]byte(nil), v...))
		})
	}); err != nil {
		t.Fatal(err)
	}
}

// rawTruncateTailLeaveHead removes the LAST record but LEAVES the head pointing at
// the (now deleted) last record's hash — the realistic tail truncation where the
// persisted head still attests the full count. The recomputed head over the
// surviving prefix no longer equals the persisted head, so Verify's head check
// catches it. This is detected in BOTH modes (it is the head-vs-recompute mismatch),
// and the keyed mode ADDITIONALLY defeats the re-forge an unkeyed mode cannot (see
// the re-forge tests). NOTE the honest residual: truncating AND rewriting the head to
// a surviving record's (validly-keyed) hash is in the erasure-residual class — it
// needs an external witness, NOT the in-band head, so we do not claim that here.
func rawTruncateTailLeaveHead(t *testing.T, path string, scope string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		recs := tx.Bucket(rawAuditChainBkt).Bucket([]byte(scope)).Bucket(rawRecordsSub)
		var lastSeq uint64
		c := recs.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) != 8 || v == nil {
				continue
			}
			if s := binary.BigEndian.Uint64(k); s > lastSeq {
				lastSeq = s
			}
		}
		return recs.Delete(seqKey(lastSeq)) // head left pointing at the deleted tail
	}); err != nil {
		t.Fatal(err)
	}
}

func writeNDurable(t *testing.T, s *Store, scope contract.ScopeKey, n int) {
	t.Helper()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		if err := s.Capture(decision(scope, uint64(i), contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("Capture %d: %v", i, err)
		}
	}
}

func openDurable(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.db")
	p, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return New(p), path
}

func decision(scope contract.ScopeKey, cookie uint64, tier contract.Tier, method, path, src, spiffe string, now time.Time) DecisionInput {
	return DecisionInput{
		Scope:         scope,
		Canary:        "decoy_file",
		SocketCookie:  cookie,
		Verdict:       contract.Verdict{Scope: scope, Tier: tier, Mode: contract.ModeInline, Score: 2.5, Calibrated: true},
		Method:        method,
		Path:          path,
		SourceAddress: src,
		SPIFFEID:      spiffe,
		Features:      map[string]float64{"adjacency_novelty": 0.9},
		Now:           now,
	}
}

// TestCaptureThreadsL7AndActionFacts is the core slice-A guarantee: a Tier>=Tag
// decision produces ONE chained record carrying the raw L7/identity context, the
// action facts, the verdict-level posture, and the structural zero-bytes fact.
func TestCaptureThreadsL7AndActionFacts(t *testing.T) {
	s, _ := openDurable(t)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	in := decision("scope-a", 0xABCDEF, contract.TierContain, "GET", "/.env?token=abc", "203.0.113.7:54321", "spiffe://cluster/sa/scanner", now)
	if err := s.Capture(in); err != nil {
		t.Fatalf("Capture: %v", err)
	}

	recs, err := s.chainRecords("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.Seq != 1 {
		t.Fatalf("first record seq = %d, want 1", r.Seq)
	}
	if r.Method != "GET" || r.Path != "/.env?token=abc" {
		t.Fatalf("L7 request line not threaded: method=%q path=%q", r.Method, r.Path)
	}
	if r.SourceAddress != "203.0.113.7:54321" || r.SPIFFEID != "spiffe://cluster/sa/scanner" {
		t.Fatalf("identity context not threaded: src=%q spiffe=%q", r.SourceAddress, r.SPIFFEID)
	}
	if r.SocketCookie != 0xABCDEF {
		t.Fatalf("rule-4 join cookie not captured: %x", r.SocketCookie)
	}
	if r.Tier != int(contract.TierContain) || r.Verdict != "contain" || r.Action != "contain" || r.Score != 2.5 {
		t.Fatalf("action facts not captured: %+v", r)
	}
	if r.Mode != int(contract.ModeInline) || !r.Calibrated {
		t.Fatalf("posture (mode/calibrated) not captured: %+v", r)
	}
	if r.Kind != KindDecision {
		t.Fatalf("kind = %q, want %q", r.Kind, KindDecision)
	}
	if r.BytesRealDataCrossed != 0 {
		t.Fatalf("a canary touch crosses ZERO real bytes; got %d", r.BytesRealDataCrossed)
	}
	if r.Features["adjacency_novelty"] != 0.9 {
		t.Fatalf("features not captured: %+v", r.Features)
	}
	if len(r.Hash) != hashLen || len(r.PrevHash) != hashLen {
		t.Fatalf("chain hashes malformed: hash=%d prev=%d", len(r.Hash), len(r.PrevHash))
	}
	if r.EventID == "" {
		t.Fatal("event id must be set")
	}
}

// TestObserveTierNotChained mirrors the Tier>=Tag gate: a Tier-0 (Observe) touch is
// not recorded into the chain (and returns no error — not a failure).
func TestObserveTierNotChained(t *testing.T) {
	s, _ := openDurable(t)
	if err := s.Capture(decision("scope-a", 1, contract.TierObserve, "GET", "/x", "1.2.3.4:1", "", time.Now())); err != nil {
		t.Fatalf("Observe Capture should be a no-op, not an error: %v", err)
	}
	recs, _ := s.chainRecords("scope-a")
	if len(recs) != 0 {
		t.Fatalf("Observe-tier touch must not be chained, got %d records", len(recs))
	}
}

// TestChainValidatesEndToEnd: a sequence of Tier>=Tag decisions forms a chain that
// Verify reports as intact from genesis to head.
func TestChainValidatesEndToEnd(t *testing.T) {
	s, _ := openDurable(t)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= 5; i++ {
		if err := s.Capture(decision("scope-a", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("Capture %d: %v", i, err)
		}
	}
	res, err := s.Verify("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact || res.Count != 5 || res.BrokenAtSeq != 0 {
		t.Fatalf("chain should validate end-to-end: %+v", res)
	}
}

// TestVerifyDetectsEdit: editing a stored record's content (without recomputing the
// chain) makes Verify report the break at that record's seq.
func TestVerifyDetectsEdit(t *testing.T) {
	s := New(nil) // in-memory mode: we can mutate the stored records directly
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= 5; i++ {
		if err := s.Capture(decision("scope-a", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	// Tamper: alter the PATH of record at seq 3, leaving its (now stale) hash in place.
	s.mem["scope-a"].records[2].Path = "/tampered"

	res, _ := s.Verify("scope-a")
	if res.Intact {
		t.Fatal("Verify must report a break after an edit")
	}
	if res.BrokenAtSeq != 3 {
		t.Fatalf("break should be at the EDITED record seq 3, got %d (%s)", res.BrokenAtSeq, res.Reason)
	}
}

// TestVerifyDetectsRemoval: removing a record from the middle makes Verify report a
// break at the removed seq (the seq sequence jumps / the link no longer chains).
func TestVerifyDetectsRemoval(t *testing.T) {
	s := New(nil)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= 5; i++ {
		if err := s.Capture(decision("scope-a", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	// Remove the record at seq 3 (index 2): the chain now jumps 2 -> 4.
	recs := s.mem["scope-a"].records
	s.mem["scope-a"].records = append(recs[:2], recs[3:]...)

	res, _ := s.Verify("scope-a")
	if res.Intact {
		t.Fatal("Verify must report a break after a removal")
	}
	// After removing seq 3, chain position 3 holds the record whose Seq is 4 — the
	// FIRST link that no longer matches its expected position, so the break is at 4.
	if res.BrokenAtSeq != 4 {
		t.Fatalf("break should be at the first out-of-place seq 4 (seq 3 removed), got %d (%s)", res.BrokenAtSeq, res.Reason)
	}
}

// TestVerifyDetectsReorder: swapping two adjacent records makes Verify report the
// break at the first out-of-order position.
func TestVerifyDetectsReorder(t *testing.T) {
	s := New(nil)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= 5; i++ {
		if err := s.Capture(decision("scope-a", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	// Swap records at index 2 and 3 (seqs 3 and 4): position 3 now holds seq 4.
	r := s.mem["scope-a"].records
	r[2], r[3] = r[3], r[2]

	res, _ := s.Verify("scope-a")
	if res.Intact {
		t.Fatal("Verify must report a break after a reorder")
	}
	// After swapping seqs 3 and 4, chain position 3 holds the record whose Seq is 4 —
	// the FIRST out-of-place link, so the break is reported at seq 4.
	if res.BrokenAtSeq != 4 {
		t.Fatalf("break should be at the first out-of-place seq 4 (3<->4 swapped), got %d (%s)", res.BrokenAtSeq, res.Reason)
	}
}

// TestVerifyDetectsTailTruncation: removing the LAST record leaves every remaining
// link valid and the seq contiguous, so it is caught only against the persisted
// head — Verify must still report a break.
func TestVerifyDetectsTailTruncation(t *testing.T) {
	s := New(nil)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= 5; i++ {
		if err := s.Capture(decision("scope-a", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	// Drop the last record but LEAVE the head pointing at seq 5's hash.
	s.mem["scope-a"].records = s.mem["scope-a"].records[:4]

	res, _ := s.Verify("scope-a")
	if res.Intact {
		t.Fatal("Verify must report a break after a tail truncation")
	}
}

// TestPerScopeChainsIndependent (rule 5): each scope keeps its own chain; tampering
// one scope's chain does not affect another's verify result, and the chains do not
// share heads/seqs.
func TestPerScopeChainsIndependent(t *testing.T) {
	s := New(nil)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= 3; i++ {
		if err := s.Capture(decision("scope-a", i, contract.TierContain, "GET", "/a", "1.1.1.1:1", "", now)); err != nil {
			t.Fatal(err)
		}
		if err := s.Capture(decision("scope-b", i, contract.TierJail, "POST", "/b", "2.2.2.2:2", "", now)); err != nil {
			t.Fatal(err)
		}
	}
	// Each scope's seqs start at 1 independently.
	a, _ := s.chainRecords("scope-a")
	b, _ := s.chainRecords("scope-b")
	if len(a) != 3 || len(b) != 3 || a[0].Seq != 1 || b[0].Seq != 1 {
		t.Fatalf("per-scope chains not independent: a=%d b=%d", len(a), len(b))
	}
	// The chains have different heads (different scope/content).
	if string(s.heads["scope-a"]) == string(s.heads["scope-b"]) {
		t.Fatal("two scopes' chain heads collided — chains are not independent")
	}
	// Tamper scope-a; scope-b must still verify intact.
	s.mem["scope-a"].records[1].Score = 999
	if ra, _ := s.Verify("scope-a"); ra.Intact {
		t.Fatal("scope-a should be broken after tamper")
	}
	if rb, _ := s.Verify("scope-b"); !rb.Intact {
		t.Fatalf("scope-b must remain intact when scope-a is tampered: %+v", rb)
	}
}

// TestPersistRehydrateContinuesValidChain: the chain survives a reboot — a new Store
// over the SAME db continues the existing chain (new record chains from the
// rehydrated head) and the whole chain still validates.
func TestPersistRehydrateContinuesValidChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.db")
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	p1, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1 := New(p1)
	for i := uint64(1); i <= 3; i++ {
		if err := s1.Capture(decision("scope-a", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	headBefore := append([]byte(nil), s1.heads["scope-a"]...)
	if err := p1.Close(); err != nil {
		t.Fatal(err)
	}

	// Reboot: reopen the SAME db and rehydrate.
	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2 := New(p2)
	if string(s2.heads["scope-a"]) != string(headBefore) {
		t.Fatal("head not rehydrated across reboot")
	}
	// Append AFTER reboot: it must chain from the rehydrated head.
	if err := s2.Capture(decision("scope-a", 4, contract.TierJail, "POST", "/q", "9.9.9.9:9", "", now.Add(10*time.Second))); err != nil {
		t.Fatal(err)
	}
	res, err := s2.Verify("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Intact || res.Count != 4 {
		t.Fatalf("rehydrated chain must continue and validate (4 records): %+v", res)
	}
	recs, _ := s2.chainRecords("scope-a")
	if recs[3].Seq != 4 || string(recs[3].PrevHash) != string(headBefore) {
		t.Fatalf("post-reboot record did not chain from the rehydrated head: seq=%d", recs[3].Seq)
	}
}

// TestExportRoundTrips: Export emits stable JSON that round-trips into a CaseReport
// carrying the full chain + the verify result.
func TestExportRoundTrips(t *testing.T) {
	s, _ := openDurable(t)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= 3; i++ {
		if err := s.Capture(decision("scope-a", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "spiffe://x", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	blob, err := s.Export("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	var got CaseReport
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("export JSON did not round-trip: %v", err)
	}
	if got.Scope != "scope-a" || len(got.Records) != 3 {
		t.Fatalf("case report wrong shape: scope=%q records=%d", got.Scope, len(got.Records))
	}
	if !got.Verify.Intact || got.Verify.Count != 3 {
		t.Fatalf("case report verify should be intact/3: %+v", got.Verify)
	}
	if got.Records[0].Path != "/p" || got.Records[0].SPIFFEID != "spiffe://x" {
		t.Fatalf("case report dropped the local-rich context: %+v", got.Records[0])
	}
}

// TestAppendOperatorActionSharesChain: the slice-B operator-action Append writes
// into the SAME per-scope chain as decision records, and the merged chain validates.
func TestAppendOperatorActionSharesChain(t *testing.T) {
	s, _ := openDurable(t)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if err := s.Capture(decision("scope-a", 1, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now)); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(OperatorAction{Scope: "scope-a", Action: "kill_switch_on", Now: now.Add(time.Second)}); err != nil {
		t.Fatalf("operator Append: %v", err)
	}
	recs, _ := s.chainRecords("scope-a")
	if len(recs) != 2 {
		t.Fatalf("operator action should share the chain: got %d records", len(recs))
	}
	if recs[1].Kind != KindOperator || recs[1].Action != "kill_switch_on" {
		t.Fatalf("operator action record wrong: %+v", recs[1])
	}
	res, _ := s.Verify("scope-a")
	if !res.Intact || res.Count != 2 {
		t.Fatalf("merged decision+operator chain must validate: %+v", res)
	}
}

// TestVerifyDetectsOperatorRecordTamper: an operator-action record (e.g. a kill-
// switch toggle) is a first-class chain link, so editing one — here the recorded
// Action label and a Posture fact — breaks Verify at that record's seq exactly like
// a decision-record edit. This proves the kill-switch's engage/revive trail is
// tamper-evident, not just appended.
func TestVerifyDetectsOperatorRecordTamper(t *testing.T) {
	s := New(nil) // in-memory mode so we can mutate the stored record directly
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if err := s.Capture(decision("scope-a", 1, contract.TierJail, "GET", "/p", "1.2.3.4:1", "", now)); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(OperatorAction{
		Scope:   "scope-a",
		Action:  "kill_switch_engage",
		Posture: map[string]string{"operator": "ir", "reason": "incident-42"},
		Now:     now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	// Tamper with the operator-action record at seq 2: forge the reason and downgrade
	// the action, leaving its (now stale) hash in place.
	rec := s.mem["scope-a"].records[1]
	if rec.Kind != KindOperator {
		t.Fatalf("seq 2 should be the operator record, got kind %q", rec.Kind)
	}
	rec.Action = "kill_switch_revive"
	rec.Posture["reason"] = "routine"

	res, _ := s.Verify("scope-a")
	if res.Intact {
		t.Fatal("Verify must report a break after an operator-action record is tampered")
	}
	if res.BrokenAtSeq != 2 {
		t.Fatalf("break should be at the tampered operator record seq 2, got %d (%s)", res.BrokenAtSeq, res.Reason)
	}
}

// TestConcurrentSameScopeAppendsDoNotFork: concurrent Submits in the SAME scope hit
// the seam concurrently (Submit is serial per flow, NOT per scope). The read-prev-
// head + seq-reserve + head-write happen in ONE bbolt transaction, so the chain must
// not fork: after N concurrent appends the chain has exactly N records with
// contiguous seqs 1..N and Verify is intact. Run under -race to catch the head race.
func TestConcurrentSameScopeAppendsDoNotFork(t *testing.T) {
	s, _ := openDurable(t)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(cookie uint64) {
			defer wg.Done()
			_ = s.Capture(decision("scope-a", cookie, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now))
		}(uint64(i + 1))
	}
	wg.Wait()

	recs, err := s.chainRecords("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != n {
		t.Fatalf("concurrent appends forked/lost: got %d records, want %d", len(recs), n)
	}
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			t.Fatalf("seq not contiguous after concurrent appends: position %d has seq %d", i, r.Seq)
		}
	}
	res, _ := s.Verify("scope-a")
	if !res.Intact || res.Count != n {
		t.Fatalf("chain must validate after %d concurrent appends: %+v", n, res)
	}
}

// TestUnscopedRefused: Capture on an empty scope is a no-op (no error); Append on an
// empty scope is refused (rule 5).
func TestUnscopedRefused(t *testing.T) {
	s, _ := openDurable(t)
	if err := s.Capture(decision("", 1, contract.TierContain, "GET", "/x", "", "", time.Now())); err != nil {
		t.Fatalf("Capture on empty scope should be a silent no-op: %v", err)
	}
	if err := s.Append(OperatorAction{Scope: "", Action: "x", Now: time.Now()}); err == nil {
		t.Fatal("Append on empty scope must be refused")
	}
}

// --- FIX 1 — keyed anchor: the keyed/unkeyed marker -------------------------

// TestKeyedUnkeyedMarker: the chain stamps its mode (Keyed flag + Algo) on each
// record AND surfaces it on Verify, so a reader knows which threat model applies.
func TestKeyedUnkeyedMarker(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	unkeyed := New(nil)
	if unkeyed.Keyed() {
		t.Fatal("New(nil) must be unkeyed")
	}
	if err := unkeyed.Capture(decision("s", 1, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now)); err != nil {
		t.Fatal(err)
	}
	recs, _ := unkeyed.chainRecords("s")
	if recs[0].Keyed || recs[0].Algo != AlgoSHA256 {
		t.Fatalf("unkeyed record marker wrong: keyed=%v algo=%q", recs[0].Keyed, recs[0].Algo)
	}
	if vr, _ := unkeyed.Verify("s"); vr.Keyed || vr.Algo != AlgoSHA256 || !vr.Intact {
		t.Fatalf("unkeyed verify marker wrong: %+v", vr)
	}

	keyed, err := NewWithConfig(nil, Config{HMACKey: []byte("super-secret-anthropic-key")})
	if err != nil {
		t.Fatal(err)
	}
	if !keyed.Keyed() {
		t.Fatal("NewWithConfig with a key must be keyed")
	}
	if err := keyed.Capture(decision("s", 1, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now)); err != nil {
		t.Fatal(err)
	}
	krecs, _ := keyed.chainRecords("s")
	if !krecs[0].Keyed || krecs[0].Algo != AlgoHMACSHA256 {
		t.Fatalf("keyed record marker wrong: keyed=%v algo=%q", krecs[0].Keyed, krecs[0].Algo)
	}
	if vr, _ := keyed.Verify("s"); !vr.Keyed || vr.Algo != AlgoHMACSHA256 || !vr.Intact {
		t.Fatalf("keyed verify marker wrong: %+v", vr)
	}
	// The keyed and unkeyed first-record hashes must differ (different link function),
	// proving the key actually participates.
	if bytes.Equal(recs[0].Hash, krecs[0].Hash) {
		t.Fatal("keyed and unkeyed chains produced the same link hash — the key did not participate")
	}
}

// TestVerifyWrongKeyDetected: a chain built with one key does not verify under
// another key — the keyed anchor's whole point (a verifier without the producing
// key recomputes different MACs).
func TestVerifyWrongKeyDetected(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	prod, _ := NewWithConfig(nil, Config{HMACKey: []byte("key-A")})
	for i := uint64(1); i <= 3; i++ {
		if err := prod.Capture(decision("s", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	recs, _ := prod.chainRecords("s")

	// A verifier with the WRONG key: replay the same records into a store keyed
	// differently and verify — must report a break at the first record.
	wrong, _ := NewWithConfig(nil, Config{HMACKey: []byte("key-B")})
	wrong.mem["s"] = &memChain{records: recs}
	wrong.heads["s"] = recs[len(recs)-1].Hash
	vr, _ := wrong.Verify("s")
	if vr.Intact {
		t.Fatal("a chain produced under key-A must NOT verify under key-B")
	}
	if vr.BrokenAtSeq != 1 {
		t.Fatalf("wrong-key break should surface at seq 1, got %d (%s)", vr.BrokenAtSeq, vr.Reason)
	}
}

// --- FIX 3 — non-finite Score/Feature must not silently drop a record -------

// TestNaNScoreSurfacedNotDropped: a NaN Score on a real Tier>=Tag decision must
// produce a HARD surfaced error from Capture (never a silent no-op that loses the
// record). Same for an Inf feature.
func TestNaNScoreSurfacedNotDropped(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		score float64
		feats map[string]float64
	}{
		{"nan-score", math.NaN(), nil},
		{"posinf-score", math.Inf(1), nil},
		{"neginf-score", math.Inf(-1), nil},
		{"nan-feature", 2.5, map[string]float64{"adjacency_novelty": math.NaN()}},
		{"inf-feature", 2.5, map[string]float64{"adjacency_novelty": math.Inf(1)}},
	} {
		t.Run(tc.name+"/durable", func(t *testing.T) {
			s, _ := openDurable(t)
			in := decision("scope-a", 1, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now)
			in.Verdict.Score = tc.score
			if tc.feats != nil {
				in.Features = tc.feats
			}
			err := s.Capture(in)
			if err == nil {
				t.Fatal("a non-finite Score/Feature must be a HARD surfaced error, not a silent drop")
			}
			// And no partial record landed: the chain is still empty + intact.
			recs, _ := s.chainRecords("scope-a")
			if len(recs) != 0 {
				t.Fatalf("non-finite Capture left %d records on disk (must be a clean failure, no partial append)", len(recs))
			}
			if vr, _ := s.Verify("scope-a"); !vr.Intact {
				t.Fatalf("chain must remain intact after a refused non-finite Capture: %+v", vr)
			}
		})
		t.Run(tc.name+"/in-memory", func(t *testing.T) {
			s := New(nil)
			in := decision("scope-a", 1, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now)
			in.Verdict.Score = tc.score
			if tc.feats != nil {
				in.Features = tc.feats
			}
			if err := s.Capture(in); err == nil {
				t.Fatal("in-memory: a non-finite Score/Feature must be a hard surfaced error")
			}
			if recs, _ := s.chainRecords("scope-a"); len(recs) != 0 {
				t.Fatalf("in-memory non-finite Capture left %d records", len(recs))
			}
		})
	}

	// A finite Score still records cleanly (the guard does not over-reject).
	s, _ := openDurable(t)
	if err := s.Capture(decision("scope-a", 1, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now)); err != nil {
		t.Fatalf("a finite-score decision must record cleanly: %v", err)
	}
	if recs, _ := s.chainRecords("scope-a"); len(recs) != 1 {
		t.Fatalf("finite decision should produce 1 record, got %d", len(recs))
	}
}

// --- FIX 2 — records present but no tracked head is a BREAK -----------------

// TestVerifyRecordsButNoHeadIsBreak: a scope that holds records but has NO tracked
// head must be reported as a BREAK (not Intact, not skipped) — an absent head once a
// chain has records is itself evidence of head loss/tampering, and would otherwise
// silently disable the tail-truncation check.
func TestVerifyRecordsButNoHeadIsBreak(t *testing.T) {
	s := New(nil)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= 3; i++ {
		if err := s.Capture(decision("scope-a", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate the head being lost while the records remain (a rehydrate that failed to
	// read the head for this scope / a head deletion).
	s.mu.Lock()
	delete(s.heads, "scope-a")
	s.mu.Unlock()

	vr, _ := s.Verify("scope-a")
	if vr.Intact {
		t.Fatal("records-present-but-no-head must be reported as a BREAK, not Intact")
	}
}

// TestRehydrateSurfacesEmptyScopeNoHead: a freshly empty scope (no records, no head)
// is trivially intact — the FIX-2 break is specifically records-WITHOUT-head, not
// the legitimate empty-scope case.
func TestRehydrateSurfacesEmptyScopeNoHead(t *testing.T) {
	s, _ := openDurable(t)
	vr, err := s.Verify("never-touched")
	if err != nil {
		t.Fatal(err)
	}
	if !vr.Intact || vr.Count != 0 {
		t.Fatalf("an empty/untouched scope must verify intact with 0 records: %+v", vr)
	}
}

// --- DURABLE on-disk tamper tests (the baseline.db-write adversary) ---------

// TestDurableForgeDetectedKeyed: write N records to a real persist.Store keyed with
// an HMAC key, tamper ON DISK with a naive edit (no recompute), reopen a fresh keyed
// Store — Verify reports the break. This is the file-only adversary the keyed anchor
// is for.
func TestDurableNaiveEditDetectedKeyed(t *testing.T) {
	key := []byte("anthropic-audit-key")
	s, p, path := openDurableKeyed(t, key)
	writeNDurable(t, s, "scope-a", 5)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	rawEditRecordPath(t, path, "scope-a", 3, "/tampered")

	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2, err := NewWithConfig(p2, Config{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	vr, _ := s2.Verify("scope-a")
	if vr.Intact {
		t.Fatal("KEYED: an on-disk edit must be detected after reopen")
	}
	if vr.BrokenAtSeq != 3 {
		t.Fatalf("KEYED: break should be at the edited seq 3, got %d (%s)", vr.BrokenAtSeq, vr.Reason)
	}
}

// TestDurableReforgeDetectedKeyed: the KNOWLEDGEABLE attack — edit a record AND
// recompute the entire downstream chain + head with the PUBLIC sha256 link, then
// reopen a KEYED store. The keyed verifier recomputes HMAC-SHA256 with its key, which
// the attacker could not produce, so the full re-forge is DETECTED at the edited seq.
//
// NOTE this re-forge uses the PUBLIC sha256 chain, so the records carry the unkeyed
// mode marker (Keyed=false / sha256) — the keyed verifier trips the MODE-MARKER check
// (check (2) in Verify) BEFORE the MAC recompute. This test therefore proves the
// MARKER stops a public re-forge; TestDurableKeyedReforgeWithAttackerKeyDetected
// (FIX B) proves the KEY itself is the line of defense.
func TestDurableReforgeDetectedKeyed(t *testing.T) {
	key := []byte("anthropic-audit-key")
	s, p, path := openDurableKeyed(t, key)
	writeNDurable(t, s, "scope-a", 5)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// Attacker re-forges with the public sha256 chain (no key) and rewrites the head.
	rawReforgeRecordPath(t, path, "scope-a", 3, "/reforged")

	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2, err := NewWithConfig(p2, Config{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	vr, _ := s2.Verify("scope-a")
	if vr.Intact {
		t.Fatal("KEYED: a full public-chain re-forge must be DETECTED (the attacker lacks the key)")
	}
	// The re-forge stamps the records with the wrong mode marker (Keyed=false/sha256)
	// AND wrong MACs; either way the keyed verifier breaks at the first record it
	// recomputes — assert the break lands within the chain.
	if vr.BrokenAtSeq == 0 {
		t.Fatalf("KEYED: re-forge break must report a seq, got %+v", vr)
	}
}

// TestDurableKeyedReforgeWithAttackerKeyDetected (FIX B — strengthen the keyed-reforge
// proof): the attacker re-forges the WHOLE chain with their OWN HMAC key AND stamps
// each record Keyed=true / Algo=hmac-sha256, so the verifier's mode-MARKER check
// PASSES — the marker is no longer the line of defense. To isolate the KEY itself (and
// not let FIX A's per-scope genesis seed catch the forgery first at the prev-hash
// step), the forge also gets seq 1's PrevHash RIGHT — it seeds from genesis(realKey,
// scope), the seed the real verifier expects — so checks (0)-(3) all pass. The ONLY
// thing standing between the forgery and an "Intact" verdict is then the MAC recompute
// (check (4)) under the REAL key, which the attacker does not have. The keyed verifier
// must therefore break at seq 1 with the "hash does not recompute" reason — proving the
// KEY (not the marker, not the genesis seed) is what defends a keyed chain against a
// knowledgeable file-only adversary. (FIX A's genesis seed is independently proven to
// stop a relocation in TestVerifyDetectsCrossScopeRelocationViaGenesisSeed.)
func TestDurableKeyedReforgeWithAttackerKeyDetected(t *testing.T) {
	realKey := []byte("anthropic-audit-key-REAL")
	attackerKey := []byte("attacker-chosen-key-WRONG")

	s, p, path := openDurableKeyed(t, realKey)
	writeNDurable(t, s, "scope-a", 5)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-forge with the attacker's key, stamping the KEYED marker so the mode-marker
	// check cannot be what catches it, and seeding seq 1's PrevHash from the genesis the
	// REAL verifier expects (realKey) so the per-scope-seed/prev-hash check passes too —
	// this ISOLATES the MAC recompute (check 4) as what breaks the forgery. NOTE: this is
	// a deliberately-constructed forgery the real threatened attacker CANNOT mount: a
	// file-only attacker lacking realKey cannot derive genesis(realKey, scope), so in the
	// real keyed threat model the forgery is ALSO caught at the prev-hash check (3) at
	// seq 1. The chain is strictly more defended than this test isolates; the test only
	// proves the MAC (the KEY), independent of the marker and the genesis seed, is a line
	// of defense (the genesis seed is proven independently by
	// TestVerifyDetectsCrossScopeRelocationViaGenesisSeed).
	rawReforgeRecordWithKey(t, path, "scope-a", realKey, attackerKey, 3, "/reforged-with-attacker-key")

	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2, err := NewWithConfig(p2, Config{HMACKey: realKey})
	if err != nil {
		t.Fatal(err)
	}
	vr, _ := s2.Verify("scope-a")
	if vr.Intact {
		t.Fatal("KEYED: a re-forge with the ATTACKER's key (correct marker) must still be DETECTED — the real key is the defense")
	}
	// The marker matches and PrevHash chains internally under the attacker's key, so the
	// FIRST thing that fails for the real-key verifier is the MAC recompute at seq 1.
	if vr.BrokenAtSeq != 1 {
		t.Fatalf("FIX B: attacker-key re-forge must break at seq 1 on the MAC recompute, got %d (%s)", vr.BrokenAtSeq, vr.Reason)
	}
	if !bytes.Contains([]byte(vr.Reason), []byte("does not recompute")) {
		t.Fatalf("FIX B: the break must be the MAC recompute (the KEY), not the marker; reason=%q", vr.Reason)
	}
}

// TestVerifyDetectsCrossScopeRelocation (FIX A — DURABLE, the headline relocation
// fix): build a valid KEYED chain for scope-B, copy its records + head bytes verbatim
// into scope-A's bucket on a real persist.Store, reopen a FRESH Store, and assert
// Verify(scope-A) reports a BREAK (not Intact). The relocated records carry scope-B in
// their Scope field and chain from scope-B's genesis, so the scope-bound verifier
// rejects them — the cross-scope relocation forgery is closed.
func TestVerifyDetectsCrossScopeRelocation(t *testing.T) {
	key := []byte("anthropic-audit-key")
	s, p, path := openDurableKeyed(t, key)
	// A valid chain for scope-B only.
	writeNDurable(t, s, "scope-b", 4)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// Attacker lifts scope-B's entire chain (records + head) into scope-A's bucket.
	rawCopyChainAcrossScopes(t, path, "scope-b", "scope-a")

	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2, err := NewWithConfig(p2, Config{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}

	// scope-A now holds scope-B's relocated chain. A scope-bound Verify must break.
	vr, _ := s2.Verify("scope-a")
	if vr.Intact {
		t.Fatal("FIX A: a chain relocated from scope-B into scope-A's bucket MUST NOT verify Intact under scope-A")
	}
	// The very first relocated record carries Scope=\"scope-b\" and chains from scope-B's
	// genesis, so the break lands at seq 1.
	if vr.BrokenAtSeq != 1 {
		t.Fatalf("FIX A: cross-scope relocation must break at seq 1, got %d (%s)", vr.BrokenAtSeq, vr.Reason)
	}
	// And the relocated chain still verifies intact under its ORIGINAL scope (the copy
	// did not corrupt scope-B itself — the defense is the scope binding, not damage).
	if vrB, _ := s2.Verify("scope-b"); !vrB.Intact || vrB.Count != 4 {
		t.Fatalf("FIX A: scope-B's original chain must remain intact: %+v", vrB)
	}
}

// TestVerifyDetectsCrossScopeRelocationViaGenesisSeed (FIX A defense-in-depth): prove
// the per-scope GENESIS SEED alone would catch the relocation even if the per-record
// Scope field-check were removed. We relocate scope-B's chain into scope-A's bucket
// then OVERWRITE each relocated record's Scope field to "scope-a" (simulating an
// attacker who also rewrote the field, or a world where check (0) was deleted) WITHOUT
// the key, and confirm Verify still breaks — because the records chain from scope-B's
// genesis, not scope-A's, so seq 1's PrevHash does not match scope-A's seed.
func TestVerifyDetectsCrossScopeRelocationViaGenesisSeed(t *testing.T) {
	key := []byte("anthropic-audit-key")
	s, p, path := openDurableKeyed(t, key)
	writeNDurable(t, s, "scope-b", 4)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	rawCopyChainAcrossScopes(t, path, "scope-b", "scope-a")

	// Rewrite the relocated records' Scope field to "scope-a" so the per-record field
	// check (0) would PASS — leaving the per-scope genesis seed as the only defense.
	// The attacker cannot recompute valid keyed hashes, so they leave the (now stale)
	// hashes in place; the genesis-seed mismatch at seq 1 is what we are isolating.
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		recs := tx.Bucket(rawAuditChainBkt).Bucket([]byte("scope-a")).Bucket(rawRecordsSub)
		c := recs.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(k) != 8 || v == nil {
				continue
			}
			r, derr := decodeRecord(v)
			if derr != nil {
				return derr
			}
			r.Scope = "scope-a" // field-check (0) would now pass; genesis seed must still catch it
			blob, eerr := encodeRecord(r)
			if eerr != nil {
				return eerr
			}
			if perr := recs.Put(append([]byte(nil), k...), blob); perr != nil {
				return perr
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2, err := NewWithConfig(p2, Config{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	vr, _ := s2.Verify("scope-a")
	if vr.Intact {
		t.Fatal("FIX A defense-in-depth: even with the Scope field rewritten, the per-scope genesis seed must break the relocated chain")
	}
	if vr.BrokenAtSeq != 1 {
		t.Fatalf("FIX A defense-in-depth: relocated chain must break at seq 1 (genesis-seed mismatch), got %d (%s)", vr.BrokenAtSeq, vr.Reason)
	}
}

// TestDurableTailTruncationDetectedKeyed: truncate the last record on disk, leaving
// the persisted head attesting the full count — under a KEYED chain Verify reports
// the break (the recomputed keyed head over the surviving prefix no longer matches
// the persisted head). The honest residual (truncate AND rewrite the head to a
// surviving record's validly-keyed hash) is in the erasure-residual class and is
// asserted as a documented limit in the erasure test below.
func TestDurableTailTruncationDetectedKeyed(t *testing.T) {
	key := []byte("anthropic-audit-key")
	s, p, path := openDurableKeyed(t, key)
	writeNDurable(t, s, "scope-a", 5)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	rawTruncateTailLeaveHead(t, path, "scope-a")

	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2, err := NewWithConfig(p2, Config{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	vr, _ := s2.Verify("scope-a")
	if vr.Intact {
		t.Fatal("KEYED: tail truncation (record removed, head still attesting the full count) must be detected")
	}
}

// TestDurableNaiveEditUnkeyedDocumentedLimit: the DOCUMENTED unkeyed boundary. An
// on-disk NAIVE edit (no recompute) IS caught even unkeyed (it does not re-run the
// public chain). But a KNOWLEDGEABLE re-forge (recompute the public chain + head) is
// NOT detected by an unkeyed verifier — we assert BOTH so the limit is captured in
// the suite, not hidden.
func TestDurableUnkeyedReforgeNotDetectedDocumentedLimit(t *testing.T) {
	s, p, path := openDurableKeyed(t, nil) // nil key => unkeyed
	if s.Keyed() {
		t.Fatal("nil key must be unkeyed")
	}
	writeNDurable(t, s, "scope-a", 5)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// (a) A naive edit (no recompute) IS caught even unkeyed.
	rawEditRecordPath(t, path, "scope-a", 3, "/naive-edit")
	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s2 := New(p2)
	if vr, _ := s2.Verify("scope-a"); vr.Intact {
		t.Fatal("UNKEYED: even a naive edit (no recompute) must be caught")
	}
	if err := p2.Close(); err != nil {
		t.Fatal(err)
	}

	// (b) THE DOCUMENTED LIMIT: a knowledgeable re-forge (recompute the public sha256
	// chain + head) is NOT detected by an unkeyed verifier. This is the gap the keyed
	// anchor closes; we assert it so the boundary is explicit, not silently deleted.
	rawReforgeRecordPath(t, path, "scope-a", 3, "/reforged-undetectable-unkeyed")
	p3, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p3.Close()
	s3 := New(p3)
	vr, _ := s3.Verify("scope-a")
	if !vr.Intact {
		t.Fatalf("DOCUMENTED LIMIT: an unkeyed chain CANNOT detect a knowledgeable public-chain re-forge; expected Intact, got %+v. If this now fails the unkeyed threat model changed — update the docs.", vr)
	}
}

// TestDurableWholeScopeErasureNotDetectedDocumentedLimit: deleting a scope's ENTIRE
// chain (records + head) is NOT detected in EITHER mode — there is nothing left to
// recompute, so a fresh Store sees an empty scope and reports Intact. This needs an
// external witness (roadmap). Asserted so the erasure limit is explicit in the suite.
func TestDurableWholeScopeErasureNotDetectedDocumentedLimit(t *testing.T) {
	key := []byte("anthropic-audit-key")
	s, p, path := openDurableKeyed(t, key)
	writeNDurable(t, s, "scope-a", 5)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// Attacker deletes the entire per-scope chain bucket.
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(rawAuditChainBkt).DeleteBucket([]byte("scope-a"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2, err := NewWithConfig(p2, Config{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	vr, _ := s2.Verify("scope-a")
	if !vr.Intact || vr.Count != 0 {
		t.Fatalf("DOCUMENTED LIMIT: whole-scope erasure is NOT detected (no records left to recompute); expected Intact/0, got %+v. Detecting it needs an external witness (roadmap).", vr)
	}
	// And the scope no longer enumerates — there is no in-band trace of the deletion.
	for _, sc := range s2.Scopes() {
		if sc == "scope-a" {
			t.Fatal("erased scope should not enumerate after whole-chain deletion")
		}
	}
}

// TestDurableReopenContinuesKeyedChain: a keyed chain rehydrates + continues across a
// reopen and still verifies (the keyed analogue of TestPersistRehydrateContinuesValidChain).
func TestDurableReopenContinuesKeyedChain(t *testing.T) {
	key := []byte("anthropic-audit-key")
	s, p, path := openDurableKeyed(t, key)
	writeNDurable(t, s, "scope-a", 3)
	headBefore := append([]byte(nil), s.heads["scope-a"]...)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	p2, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	s2, err := NewWithConfig(p2, Config{HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s2.heads["scope-a"], headBefore) {
		t.Fatal("keyed head not rehydrated across reopen")
	}
	now := time.Date(2026, 6, 15, 12, 0, 10, 0, time.UTC)
	if err := s2.Capture(decision("scope-a", 4, contract.TierJail, "POST", "/q", "9.9.9.9:9", "", now)); err != nil {
		t.Fatal(err)
	}
	vr, _ := s2.Verify("scope-a")
	if !vr.Intact || vr.Count != 4 || !vr.Keyed {
		t.Fatalf("rehydrated keyed chain must continue + validate (4 records, keyed): %+v", vr)
	}
}

// --- EXTERNAL-WITNESS high-water-mark accessor ------------------------------

// TestHighWaterMarkDurableReflectsChain: the durable HighWaterMark returns the right
// head/count/latestSeq for a known chain — and the head equals the chain's last
// record's Hash (the witness tuple the SOC compares against).
func TestHighWaterMarkDurableReflectsChain(t *testing.T) {
	s, _ := openDurable(t)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	const n = 5
	for i := uint64(1); i <= n; i++ {
		if err := s.Capture(decision("scope-a", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("capture %d: %v", i, err)
		}
	}
	hwm, ok := s.HighWaterMark("scope-a")
	if !ok {
		t.Fatal("HighWaterMark(scope-a) ok=false for a populated chain")
	}
	if hwm.Count != n {
		t.Fatalf("Count = %d, want %d", hwm.Count, n)
	}
	if hwm.LatestSeq != n {
		t.Fatalf("LatestSeq = %d, want %d (append-only intact chain: latestSeq==count)", hwm.LatestSeq, n)
	}
	if hwm.Scope != "scope-a" {
		t.Fatalf("Scope = %q, want scope-a", hwm.Scope)
	}
	if hwm.Keyed {
		t.Fatalf("unkeyed store reported Keyed=true")
	}
	if hwm.Algo != AlgoSHA256 {
		t.Fatalf("Algo = %q, want %q", hwm.Algo, AlgoSHA256)
	}
	// Head must equal the chain's last-record Hash (the in-memory mirror) and the
	// store's tracked head.
	recs, err := s.chainRecords("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	last := recs[len(recs)-1]
	if !bytes.Equal(hwm.Head, last.Hash) {
		t.Fatalf("Head %x != last record Hash %x", hwm.Head, last.Hash)
	}
	headTracked, _ := s.headFor("scope-a")
	if !bytes.Equal(hwm.Head, headTracked) {
		t.Fatalf("Head %x != tracked head %x", hwm.Head, headTracked)
	}
	// An unknown / empty scope has no witness yet.
	if _, ok := s.HighWaterMark("nope"); ok {
		t.Fatal("HighWaterMark(unknown scope) ok=true, want false (no chain => nothing to witness)")
	}
	if _, ok := s.HighWaterMark(""); ok {
		t.Fatal("HighWaterMark(\"\") ok=true, want false")
	}
}

// TestHighWaterMarkInMemoryReflectsChain: the no-DB path reads Count/LatestSeq off the
// in-memory chain and never touches a nil DB.
func TestHighWaterMarkInMemoryReflectsChain(t *testing.T) {
	s := New(nil) // in-memory, no DB
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= 3; i++ {
		if err := s.Capture(decision("s", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now)); err != nil {
			t.Fatal(err)
		}
	}
	hwm, ok := s.HighWaterMark("s")
	if !ok || hwm.Count != 3 || hwm.LatestSeq != 3 {
		t.Fatalf("in-memory HighWaterMark = %+v ok=%v, want count=3 latestSeq=3", hwm, ok)
	}
	recs, _ := s.chainRecords("s")
	if !bytes.Equal(hwm.Head, recs[2].Hash) {
		t.Fatalf("in-memory Head %x != last record Hash %x", hwm.Head, recs[2].Hash)
	}
	if _, ok := s.HighWaterMark("never-touched"); ok {
		t.Fatal("in-memory HighWaterMark(empty scope) ok=true, want false")
	}
}

// TestHighWaterMarkKeyedMarkers: a keyed store reports Keyed=true + the hmac algo, so
// the published anchor states the threat model the chain was built under.
func TestHighWaterMarkKeyedMarkers(t *testing.T) {
	s, err := NewWithConfig(nil, Config{HMACKey: []byte("k")})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if err := s.Capture(decision("s", 1, contract.TierJail, "POST", "/p", "1.2.3.4:1", "", now)); err != nil {
		t.Fatal(err)
	}
	hwm, ok := s.HighWaterMark("s")
	if !ok || !hwm.Keyed || hwm.Algo != AlgoHMACSHA256 {
		t.Fatalf("keyed HighWaterMark = %+v ok=%v, want Keyed=true algo=%q", hwm, ok, AlgoHMACSHA256)
	}
}

// TestHighWaterMarkTracksTruncationSignal: after a chain grows, the LatestSeq advances
// monotonically — the signal the SOC compares against the last-seen anchor. (Erasure /
// truncation is detected OFF-BOX by comparing a later, smaller/absent high-water-mark
// to the witness the SOC already holds; this asserts the live side that the SOC reads.)
func TestHighWaterMarkTracksTruncationSignal(t *testing.T) {
	s, _ := openDurable(t)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if err := s.Capture(decision("scope-a", 1, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now)); err != nil {
		t.Fatal(err)
	}
	hwm1, _ := s.HighWaterMark("scope-a")
	if hwm1.LatestSeq != 1 || hwm1.Count != 1 {
		t.Fatalf("after 1 record: %+v, want count=1 latestSeq=1", hwm1)
	}
	for i := uint64(2); i <= 4; i++ {
		if err := s.Capture(decision("scope-a", i, contract.TierContain, "GET", "/p", "1.2.3.4:1", "", now.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	hwm2, _ := s.HighWaterMark("scope-a")
	if hwm2.LatestSeq != 4 || hwm2.Count != 4 {
		t.Fatalf("after 4 records: %+v, want count=4 latestSeq=4", hwm2)
	}
	if hwm2.LatestSeq <= hwm1.LatestSeq {
		t.Fatalf("LatestSeq did not advance: %d -> %d", hwm1.LatestSeq, hwm2.LatestSeq)
	}
	if bytes.Equal(hwm1.Head, hwm2.Head) {
		t.Fatal("Head did not change as the chain grew (the head is the per-scope tip)")
	}
}
