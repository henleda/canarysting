// Package persist is the single durable backing store for the M7 learning
// window. It is the ONLY importer of go.etcd.io/bbolt in the tree (pure-Go, no
// CGO, so the clean cross-compile holds). It stores opaque byte blobs in a
// scope-partitioned layout; the owning packages own their own serialization
// (observebaseline gob-encodes its per-bucket aggregate, boltevents gob-encodes
// the AdversaryInteractionEvent). persist itself knows nothing about the
// baseline math or the event shape — it is a transactional, scope-isolated
// key-value store plus the window-lifecycle metadata (the observe heartbeat and
// the schema version) the durability protocol needs. Downtime is detected from
// the heartbeat (CoverageGap), not a shutdown marker — bbolt commits are fsync'd,
// so a crash loses nothing already committed.
//
// SCOPE ISOLATION (CLAUDE.md rule 5) is structural here: every scope's data
// lives in its own nested bbolt sub-bucket, so a cross-scope read is impossible
// without explicitly naming the other scope's sub-bucket. There is no global
// bucket that mixes scopes. See internal/engine/persist/store_test.go for the
// isolation invariant.
//
// RULE 9 (docs/INTELLIGENCE.md): nothing here crosses a deployment boundary, and
// the durable records hold only derived state (hashed identity counts, bounded
// distribution summaries, structured features) — never raw addresses, payloads,
// or decoy contents. Identity is persisted only as an FNV hash, never as a raw
// source IP.
package persist
