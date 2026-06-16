// Package siem is the deployment-LOCAL, one-way SIEM/SOAR emitter: a thin serializer
// over the slice-1 l7events.EnrichedTouchRecord that ships a stable, correlatable
// "a decoy was touched" event to the OPERATOR'S OWN SIEM/SOAR.
//
// LOCAL-RICH, NOT THE CROSS-CUSTOMER FEED (docs/INTELLIGENCE.md rule 9): the event is
// un-anonymized — it carries the RAW source address, :method/:path (query included),
// and SPIFFE id straight off the local-rich record. It is the deployment's own alert
// stream, NOT the cross-customer anonymized pattern feed (D7/feed), which crosses the
// single default-deny egress filter in internal/intelligence/network. These two are
// DIFFERENT product lines: this emitter MUST NEVER import or route through
// internal/intelligence/network. importguard_test.go enforces that structurally; the
// egress filter's own guard (network/egress_importguard_test.go) keeps the inverse
// edge (the egress filter cannot reach l7events). An operator may point the webhook at
// their own off-box SIEM — that is their choice for THEIR data; the payload is
// un-anonymized, so it must not be pointed at a shared/third-party endpoint that
// expects anonymization.
//
// RULE 8 (emit-only): the emitter is a poll-snapshot DRAIN off the capture hot path.
// It never hooks capturingEngine.Submit, never arms a response, never changes a score.
// It reads l7events.Snapshot(scope) on a ticker and pushes each new/bumped touch ONCE.
//
// RULE 5 (scope isolation): it drains PER SCOPE (Source.Scopes + Snapshot(scope)) and
// stamps every event with its resolved scope; it never merges scopes into one
// unlabeled stream.
package siem

import (
	"context"
	"log"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/audit"
	"github.com/canarysting/canarysting/internal/intelligence/l7events"
)

// Source is the read side the emitter drains. It is exactly the subset of
// *l7events.Store the emitter needs — Scopes() to discover the partitions, Snapshot
// to read one scope's records (copy-out), and Reap to drive the TTL on the tick. A
// narrow interface keeps the emitter testable with an in-process fake (no real store,
// no real net) and documents that the emitter is READ-ONLY against the store.
type Source interface {
	Scopes() []contract.ScopeKey
	Snapshot(scope contract.ScopeKey) []l7events.EnrichedTouchRecord
	Reap(now time.Time) int
}

// AuditWitnessSource is the narrow READ-ONLY view the drain needs to publish the
// EXTERNAL-WITNESS anchor (the per-scope audit-chain high-water-mark). It mirrors the
// Source pattern: a narrow interface keeps the drain testable with an in-process fake
// and documents that the publisher is READ-ONLY against the audit store — it never
// calls Verify/Export/append, only the cheap HighWaterMark tuple. *audit.Store
// satisfies it (Scopes + HighWaterMark).
//
// It imports the audit package only for the HighWaterMark return type. That edge is
// leak-safe: audit's only internal imports are contract + engine/persist (no
// intelligence/network), so siem -> audit -> {contract, persist} keeps
// importguard_test.go (siem MUST NOT import network) green. The anchor is LOCAL
// operator data (rule 9): it rides this local SIEM path, never the cross-customer feed.
type AuditWitnessSource interface {
	Scopes() []contract.ScopeKey
	HighWaterMark(contract.ScopeKey) (audit.HighWaterMark, bool)
}

// Config wires one emitter. Sink and Source are required; Interval defaults to
// DefaultInterval when zero. ExtraScopes lets the caller guarantee at least the
// boundary scope is drained even before any record exists in it (Snapshot of an empty
// scope is a harmless nil), so a single-scope deployment works without depending on
// Scopes() having observed a touch yet.
type Config struct {
	Source      Source
	Sink        Emitter
	Interval    time.Duration
	ExtraScopes []contract.ScopeKey
	// AuditSrc, when non-nil, enables the EXTERNAL-WITNESS anchor: the drain publishes
	// each scope's audit-chain high-water-mark on a COARSE cadence (anchorInterval, like
	// the reap — NOT every tick, NOT on the verdict hot path). nil => no anchor work
	// (the live posture is byte-unchanged). It is the operator's OWN local audit
	// metadata on the operator's OWN SIEM path (rule 9), never the cross-customer feed.
	AuditSrc AuditWitnessSource
	// Now overrides the clock (tests); nil => time.Now.
	Now func() time.Time
	// ReapEnabled drives l7events.Reap(now) on each tick (the slice-2 emitter is the
	// documented owner of the 30d TTL reap). Default true via New when unset is not
	// distinguishable, so Config carries it explicitly; New leaves it as given.
	ReapEnabled bool
}

// DefaultInterval is the poll cadence. Short relative to a spray so a record is
// emitted before the per-scope cap (4096) can evict it unseen.
const DefaultInterval = 5 * time.Second

// shutdownDrainBudget bounds the final flush on ctx cancellation so shutdown cannot
// hang on a slow/unreachable sink (each HTTP POST is additionally bounded by the
// emitter's own timeout). A touch that landed just before shutdown is flushed within
// this budget or dropped — shutdown never blocks.
const shutdownDrainBudget = 10 * time.Second

// maxRetries bounds the per-event retry on a transport error. A SIEM outage must
// never block the drain, so after this many failures the event is logged + DROPPED
// and the cursor advances (so it is not retried forever, flooding on recovery).
const maxRetries = 2

// reapInterval is how often the drain drives the l7events 30d TTL reap. It is much
// coarser than the emit poll (a TTL boundary is crossed at most once per record per
// ~30d), so the full-store scan under the Capture lock runs ~hourly, not every tick.
const reapInterval = time.Hour

// anchorInterval is how often the drain publishes the per-scope external-witness
// anchor (the audit-chain high-water-mark). It is COARSE (hourly, like the reap) by
// design: a witness only needs to be fresh-ish — the residuals (truncate-to-valid-
// prefix / whole-scope-erasure) are detected by COMPARISON at the SOC against the
// last-seen high-water-mark, not by anchor frequency. The rule-8 trade-off: anything
// appended after the last anchor and then erased is below the witness's resolution; if
// a tighter bound is wanted, lower this — but NEVER put the publish on the verdict hot
// path. Reading the head/count is a read-only stat, off the decision path entirely.
const anchorInterval = time.Hour

// cursorEntry is the per-record emit cursor: the (HitCount, LastSeen) last emitted for
// an EventID. A record re-emits when its EventID is unseen OR its recurrence advanced
// (so a repeat touch on the same key emits an UPDATE, not a silent drop and not a dup).
type cursorEntry struct {
	hitCount uint64
	lastSeen time.Time
}

// Drainer is the background emitter: it polls the Source per scope on a ticker and
// pushes each new/bumped touch to the Sink exactly once per touch event.
type Drainer struct {
	src         Source
	sink        Emitter
	interval    time.Duration
	extraScopes []contract.ScopeKey
	now         func() time.Time
	reap        bool
	lastReap    time.Time // last time the TTL reap ran (coarse cadence; see reapInterval)

	// auditSrc is the optional external-witness source; nil => no anchor publish.
	// lastAnchor tracks the coarse anchor cadence (sibling to lastReap; see
	// anchorInterval). Both are touched only from Run's single goroutine (no lock).
	auditSrc   AuditWitnessSource
	lastAnchor time.Time

	// cursor is keyed by EventID -> last-emitted recurrence. It lives in the emitter
	// (the store stays the authoritative read side). It is only touched from Run's
	// single goroutine, so it needs no lock. drainOnce prunes it to the live store each
	// tick so it stays bounded; it is in-memory, so a process restart re-emits each
	// still-retained touch once (at-least-once; downstream dedups on the stable EventID).
	cursor map[string]cursorEntry
}

// New builds the drain from cfg. It does not start anything; call Run(ctx) in a
// goroutine. Sink defaults to a NopEmitter (inert) when nil — fail-safe.
func New(cfg Config) *Drainer {
	sink := cfg.Sink
	if sink == nil {
		sink = NopEmitter{}
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Drainer{
		src:         cfg.Source,
		sink:        sink,
		interval:    interval,
		extraScopes: cfg.ExtraScopes,
		now:         now,
		reap:        cfg.ReapEnabled,
		auditSrc:    cfg.AuditSrc,
		cursor:      map[string]cursorEntry{},
	}
}

// Run drains on each tick until ctx is cancelled, draining once more on shutdown
// (mirrors observebaseline.Aggregator.Run: a final drain on ctx.Done so a touch that
// landed just before shutdown is not lost). It is a no-op-safe goroutine: a nil Source
// makes it return immediately. Call it in a goroutine.
func (d *Drainer) Run(ctx context.Context) {
	if d == nil || d.src == nil {
		return
	}
	t := time.NewTicker(d.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final drain on shutdown so a touch that landed just before cancellation is
			// not lost (mirrors Aggregator.Run's fold-on-Done). Use a fresh bounded
			// context: the parent ctx is already cancelled, so emitting under it would
			// abort the flush immediately. The HTTP emitter still bounds itself by its
			// own per-request timeout, so this cannot hang shutdown unboundedly.
			fctx, cancel := context.WithTimeout(context.Background(), shutdownDrainBudget)
			d.drainOnce(fctx)
			cancel()
			return
		case <-t.C:
			d.drainOnce(ctx)
		}
	}
}

// drainOnce enumerates scopes, snapshots each, and emits every new/bumped record once.
// It also drives the TTL reap (on a coarse cadence) and prunes the cursor against the
// live store. Per-scope (rule 5): each scope is drained independently and every event
// is stamped with its scope.
func (d *Drainer) drainOnce(ctx context.Context) {
	now := d.now()
	if d.reap && now.Sub(d.lastReap) >= reapInterval {
		// The slice-2 emitter is the documented owner of the 30d TTL reap (l7events
		// store.go). Reap before the snapshot so an aged-out record is not emitted on
		// the same tick it is reaped. The TTL boundary is crossed at most once per
		// record per ~30d, so reap on a coarse cadence — NOT every emit poll — to avoid
		// frequent full-store scans under the lock the Capture hot path also takes.
		_ = d.src.Reap(now)
		d.lastReap = now
	}
	if d.auditSrc != nil && now.Sub(d.lastAnchor) >= anchorInterval {
		// EXTERNAL-WITNESS anchor: publish each scope's audit-chain high-water-mark on
		// the SAME one-way emit path (bounded retry + drop-on-outage), on a COARSE
		// cadence (anchorInterval, like the reap — NOT every tick). Rule 8: this runs
		// only on the hourly tick inside the background drain, off the verdict hot path
		// entirely; reading the head/count is a read-only stat. Iterate d.auditScopes()
		// — the AUDIT store's OWN scope set (union ExtraScopes), NOT the l7events touch
		// scopes — so the witness covers EVERY chain, including a scope that has audit
		// records but has emitted no SIEM touch (otherwise such a chain would never be
		// anchored, the exact coverage gap the witness exists to prevent). HighWaterMark
		// returns ok=false for an empty/genesis scope, so an un-chained scope is harmlessly
		// skipped. nil auditSrc (no audit store / no DB) skips all of this, so the live
		// posture is byte-unchanged until the witness is wired.
		for _, sc := range d.auditScopes() {
			hwm, ok := d.auditSrc.HighWaterMark(sc)
			if !ok {
				continue
			}
			hwm.Timestamp = now // stamp the publish wall-clock (the store owns no clock)
			d.emit(ctx, FromHighWaterMark(hwm))
		}
		d.lastAnchor = now
	}
	// live collects every EventID currently retained in the store this tick, so the
	// cursor can be pruned to the live set below — otherwise it would grow without
	// bound (one entry per distinct touch EVER emitted), defeating the store's own
	// cap+TTL bounding under a multi-week spray. A reaped/evicted record's EventID
	// never recurs (a fresh touch mints a new EventID), so dropping its cursor entry
	// is safe.
	live := make(map[string]struct{})
	for _, sc := range d.scopes() {
		for _, r := range d.src.Snapshot(sc) {
			live[r.EventID] = struct{}{}
			if !d.shouldEmit(r) {
				continue
			}
			if d.emit(ctx, FromRecord(r)) {
				d.cursor[r.EventID] = cursorEntry{hitCount: r.HitCount, lastSeen: r.LastSeen}
			}
		}
	}
	for k := range d.cursor {
		if _, ok := live[k]; !ok {
			delete(d.cursor, k)
		}
	}
}

// auditScopes is the union of the AUDIT store's OWN scopes and any configured
// ExtraScopes (deduped) — the set the external-witness anchor must cover. It is keyed
// off the audit store, NOT the l7events touch scopes scopes() uses, so a scope that has
// an audit chain but has produced no SIEM touch still gets an anchor (the witness must
// cover every chain). nil auditSrc => only ExtraScopes (each skipped by HighWaterMark
// until it has a chain).
func (d *Drainer) auditScopes() []contract.ScopeKey {
	seen := map[contract.ScopeKey]bool{}
	var out []contract.ScopeKey
	if d.auditSrc != nil {
		for _, sc := range d.auditSrc.Scopes() {
			if sc != "" && !seen[sc] {
				seen[sc] = true
				out = append(out, sc)
			}
		}
	}
	for _, sc := range d.extraScopes {
		if sc != "" && !seen[sc] {
			seen[sc] = true
			out = append(out, sc)
		}
	}
	return out
}

// scopes is the union of the store's live scopes and any configured ExtraScopes
// (deduped), so the boundary scope is always drained even before it holds a record.
func (d *Drainer) scopes() []contract.ScopeKey {
	seen := map[contract.ScopeKey]bool{}
	var out []contract.ScopeKey
	if d.src != nil {
		for _, sc := range d.src.Scopes() {
			if !seen[sc] {
				seen[sc] = true
				out = append(out, sc)
			}
		}
	}
	for _, sc := range d.extraScopes {
		if sc != "" && !seen[sc] {
			seen[sc] = true
			out = append(out, sc)
		}
	}
	return out
}

// shouldEmit reports whether a record is new or has advanced since last emitted. A
// record emits when its EventID is unseen, OR its HitCount grew, OR its LastSeen
// advanced (a recurrence re-emits as an update; an unchanged record is skipped, so a
// naive "emit every snapshot row" flood is avoided).
func (d *Drainer) shouldEmit(r l7events.EnrichedTouchRecord) bool {
	prev, ok := d.cursor[r.EventID]
	if !ok {
		return true
	}
	return r.HitCount > prev.hitCount || r.LastSeen.After(prev.lastSeen)
}

// emit pushes one event with a bounded retry. It returns true when the event was
// HANDLED — either accepted by the sink OR permanently DROPPED after maxRetries
// (logged) — so the caller advances the cursor in BOTH cases. Advancing on a drop is
// deliberate: a record is attempted a bounded number of times and then given up, so a
// sustained sink outage does NOT re-hammer every un-acked record every tick and does
// NOT stampede a flood on recovery (at-least-once while the sink is healthy; best-effort
// during an outage — acceptable for a forensic alert stream). It returns false ONLY when
// ctx is cancelled before a real attempt (shutdown); then the cursor is left unadvanced
// so the record is retried on the next run.
func (d *Drainer) emit(ctx context.Context, ev SiemEvent) bool {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return false // ctx-aborted (shutdown) — not handled; do not advance the cursor
		}
		if err := d.sink.Emit(ctx, ev); err != nil {
			lastErr = err
			continue
		}
		return true // accepted
	}
	// Permanently failed after a bounded number of attempts: log + DROP, and report
	// HANDLED so the cursor advances — no every-tick re-hammer, no recovery flood.
	log.Printf("siem: dropping event %s after %d attempts via %s sink: %v", ev.EventID, maxRetries+1, d.sink.Name(), lastErr)
	return true
}
