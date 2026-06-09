// Package observebaseline turns the OBSERVE-ONLY eBPF flow-stats path into a
// real, per-scope, time-bucketed baseline of normal east-west traffic, and feeds
// it to the frozen bounded multiplier as a baseline.FeatureSource. It is the M7
// learning-window engine: it folds completed flows into bounded per-bucket
// aggregates, flips the baseline-LIVE and bucket-SUFFICIENT gates when enough
// real traffic has accrued, derives a flow's deviation feature vector at scoring
// time, and persists everything durably so a ≥2-week window survives a reboot.
//
// It NEVER triggers anything (CLAUDE.md rule 8): it only shapes the multiplier
// M on a base that is zero without a canary touch, and the observe path it reads
// from cannot enforce. Confirmed-malicious source identities are excluded from
// the baseline-of-normal (but NOT from scoring) so an attacker cannot teach the
// baseline that its own behavior is normal. All state is scope-isolated (rule 5)
// and identity is only ever hashed, never stored raw (rule 9).
package observebaseline

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/engine/scope"
)

// DefaultInterval is the fold-loop tick: how often the aggregator reads the
// kernel map, folds completed flows, and re-evaluates the gates.
const DefaultInterval = 10 * time.Second

// gateSink is the slice of baseline.Store the aggregator drives. *baseline.Store
// satisfies it.
type gateSink interface {
	SetLive(scope contract.ScopeKey, live bool)
	SetBucketSufficient(scope contract.ScopeKey, bucket string, ok bool)
}

// Config wires an Aggregator.
type Config struct {
	Reader   observe.Reader    // the OBSERVE-ONLY kernel map reader (required)
	Gates    gateSink          // the baseline.Store whose two gates we drive (required)
	Resolver scope.Resolver    // resolves an observed cookie to exactly one scope (required)
	Store    *persist.Store    // durable backing; nil = in-memory only (tests)
	Excluder excluder          // baseline-of-normal exclusion; nil = exclude nothing
	Bucketer baseline.Bucketer // MUST be the same bucketer the baseline.Store uses
	Floor    DataFloor         // the eBPF data floor (zero => DefaultDataFloor)
	Interval time.Duration     // fold tick (zero => DefaultInterval)
	Now      func() time.Time  // injectable clock (nil => time.Now)
}

// liveFlow records the attribution of one tracked cookie (the scope/bucket/day
// captured when the aggregator first observed it open), so a flow is folded into
// the bucket it started in regardless of when it completes.
type liveFlow struct {
	scope  contract.ScopeKey
	bucket string // window bucket at first observation
	day    string // calendar day at first observation
}

// AggStats are the aggregator's observability counters.
type AggStats struct {
	CompletedFolds   uint64 // flows folded into the baseline-of-normal
	ExcludedFolds    uint64 // flows skipped because their source is confirmed-malicious
	UnresolvedFolds  uint64 // flows dropped because their scope could not be resolved
	RehydrateSkipped uint64 // persisted aggregate blobs that failed to decode on rehydrate (lost history)
}

// Aggregator implements baseline.FeatureSource.
type Aggregator struct {
	reader   observe.Reader
	gates    gateSink
	resolver scope.Resolver
	store    *persist.Store
	excluder excluder
	bucketer baseline.Bucketer
	floor    DataFloor
	interval time.Duration
	clock    func() time.Time

	mu             sync.RWMutex
	aggregates     map[contract.ScopeKey]map[string]*bucketAggregate
	live           map[uint64]*liveFlow // open cookies: attribution, awaiting close
	folded         map[uint64]bool      // cookies already folded, lingering until LRU-evicted
	lastFold       map[contract.ScopeKey]time.Time
	freshFolds     map[contract.ScopeKey]uint64          // completed folds since this process started
	recoveryQuorum map[contract.ScopeKey]uint64          // freshFolds target before re-live after a coverage gap
	dirty          map[contract.ScopeKey]map[string]bool // (scope,bucket) changed since the last persist
	stats          AggStats
}

var _ baseline.FeatureSource = (*Aggregator)(nil)

// New constructs an Aggregator. Reader, Gates, and Resolver are required.
func New(cfg Config) *Aggregator {
	if cfg.Bucketer == nil {
		cfg.Bucketer = baseline.WindowBucketer
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Aggregator{
		reader:         cfg.Reader,
		gates:          cfg.Gates,
		resolver:       cfg.Resolver,
		store:          cfg.Store,
		excluder:       cfg.Excluder,
		bucketer:       cfg.Bucketer,
		floor:          cfg.Floor.Normalized(),
		interval:       cfg.Interval,
		clock:          cfg.Now,
		aggregates:     map[contract.ScopeKey]map[string]*bucketAggregate{},
		live:           map[uint64]*liveFlow{},
		folded:         map[uint64]bool{},
		lastFold:       map[contract.ScopeKey]time.Time{},
		freshFolds:     map[contract.ScopeKey]uint64{},
		recoveryQuorum: map[contract.ScopeKey]uint64{},
		dirty:          map[contract.ScopeKey]map[string]bool{},
	}
}

// Run rehydrates from durable storage (forcing every scope STALE) and then folds
// on each tick until ctx is cancelled, folding once more on shutdown. Durability
// is bbolt's: each fold's writes are already committed, so cancellation needs no
// special flush.
func (a *Aggregator) Run(ctx context.Context) {
	a.Rehydrate()
	t := time.NewTicker(a.interval)
	defer t.Stop()
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			a.foldOnce(a.clock())
			return
		case <-t.C:
			a.foldOnce(a.clock())
			ticks++
			// Periodic accrual heartbeat for operating the window (observability,
			// not a decision input — the healthcheck reads it). Logs the open
			// flow count and the cumulative fold/exclude/unresolved counters.
			if ticks%6 == 0 {
				s := a.Stats()
				a.mu.RLock()
				open := len(a.live)
				a.mu.RUnlock()
				log.Printf("observebaseline: open=%d folds=%d excluded=%d unresolved=%d rehydrate-skipped=%d",
					open, s.CompletedFolds, s.ExcludedFolds, s.UnresolvedFolds, s.RehydrateSkipped)
			}
		}
	}
}

// Rehydrate loads persisted aggregates into memory and forces every scope to a
// STALE (not-live) state: a persisted baseline is never trusted across a restart
// until a fresh in-process fold re-confirms it. If the durable store shows a
// coverage gap larger than the floor's tolerance (a crash/reboot/long pause) —
// OR the heartbeat is unreadable, which could mask an arbitrarily long hole —
// the affected scope must additionally re-accrue a fresh recovery quorum of real
// flows before it can go live again, so a downtime hole is never silently
// treated as if traffic had been normal throughout.
//
// It is STARTUP-ONLY: called once at the top of Run before the fold loop and
// before the hot path is served. It holds the write lock across bbolt reads,
// which is fine exactly because nothing else is running yet — do not call it on a
// live aggregator.
func (a *Aggregator) Rehydrate() {
	if a.store == nil {
		return
	}
	// Force re-accrual on a real downtime gap, OR on a non-nil error reading the
	// heartbeat (a corrupt marker cannot prove traffic was normal). A genuinely
	// fresh store returns ok=false with err=nil and must NOT be forced.
	largeGap := false
	if gap, ok, err := a.store.CoverageGap(a.clock()); err != nil {
		largeGap = true
	} else if ok && gap > a.floor.MaxCoverageGap {
		largeGap = true
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.store.RangeScopes(func(sc contract.ScopeKey) error {
		buckets := map[string]*bucketAggregate{}
		_ = a.store.RangeBuckets(sc, func(key string, blob []byte) error {
			agg, err := decodeAggregate(blob)
			if err != nil {
				a.stats.RehydrateSkipped++ // observable: lost-history, not silent
				return nil                 // skip an undecodable blob rather than fail the whole window
			}
			buckets[key] = agg
			return nil
		})
		a.aggregates[sc] = buckets
		a.lastFold[sc] = time.Time{} // not fresh until a real fold
		a.gates.SetLive(sc, false)   // force STALE
		if largeGap {
			// freshFolds[sc] is 0 at startup, so this is folds-since-gap. The target
			// is scope-wide (MinFlowsPerBucket per the MinSufficientBuckets a scope
			// needs to relive), not the per-bucket count the old code wrongly used.
			a.recoveryQuorum[sc] = a.freshFolds[sc] + a.floor.MinFlowsAfterGap()
		}
		return nil
	})
	// Rehydrate the malicious exclusion set INDEPENDENTLY of baseline-bucket
	// presence: a scope marked malicious before it ever folded a flow must still
	// restore its exclusion across a reboot (the two accrue via separate paths).
	if ms, ok := a.excluder.(*MaliciousSet); ok {
		_ = a.store.RangeMaliciousScopes(func(sc contract.ScopeKey) error {
			return ms.Rehydrate(sc)
		})
	}
}

// foldOnce reads the kernel map, folds completed flows into the baseline-of-
// normal, re-evaluates the two gates per scope, and persists. The in-memory work
// runs under the lock; the durable write runs AFTER the lock is released, so the
// hot-path Features/Multiplier is never blocked on disk I/O.
func (a *Aggregator) foldOnce(now time.Time) {
	writes := a.foldLocked(now)
	if a.store != nil {
		// One transaction (one fsync) for all dirtied buckets plus the heartbeat.
		_ = a.store.PutBucketsAndHeartbeat(writes, now)
	}
}

// foldLocked does the lock-held in-memory fold + gate re-evaluation and returns
// the encoded blobs for the buckets dirtied this tick (encoding is cheap and in
// memory, so it stays under the lock; the bbolt write does not).
//
// Fold-on-CLOSED: the kernel marks a flow Closed on sock_release (it does NOT
// delete the entry), so every completed flow is still present on the next poll
// and is folded EXACTLY ONCE — even a flow that opened and closed between two
// ticks. `live` holds open cookies' attribution; `folded` remembers folded
// cookies so a closed entry that lingers (until the LRU evicts it) is not
// double-counted. Both are pruned when a cookie leaves the map.
func (a *Aggregator) foldLocked(now time.Time) []persist.BucketWrite {
	a.mu.Lock()
	defer a.mu.Unlock()

	seen := make(map[uint64]struct{})
	_ = a.reader.IterStats(func(cookie uint64, fs observe.FlowStats) error {
		if cookie == 0 {
			return nil // unattributable flow: refuse to bucket it (fail-safe)
		}
		seen[cookie] = struct{}{}
		if a.folded[cookie] {
			return nil // already folded; awaiting LRU eviction
		}
		lf := a.live[cookie]
		if lf == nil {
			sc, err := a.resolver.Resolve(contract.FlowIdentity{SocketCookie: cookie})
			if err != nil {
				a.stats.UnresolvedFolds++
				return nil // never fold into a global/guessed scope (rule 5, fail-safe)
			}
			// A flow is attributed to its FIRST-observation bucket/day, with its
			// whole-flow totals folded once on completion. The kernel map exposes
			// only cumulative totals (no per-bucket deltas), so a boundary-spanning
			// flow is counted in a single bucket and skews toward the earlier one —
			// intentional, and harmless (it only shapes the baseline distribution; a
			// flow with no canary touch still scores 0 regardless of bucket).
			lf = &liveFlow{scope: sc, bucket: a.bucketer(now), day: dayKey(now)}
			a.live[cookie] = lf
		}
		if fs.Closed != 0 {
			a.foldCompleted(lf, fs, now)
			a.folded[cookie] = true
			delete(a.live, cookie)
		}
		return nil
	})

	// Prune cookies that left the map (LRU-evicted): an open one evicted before it
	// closed is lost (rare; the map is large); a folded one is just cleaned up.
	for cookie := range a.live {
		if _, ok := seen[cookie]; !ok {
			delete(a.live, cookie)
		}
	}
	for cookie := range a.folded {
		if _, ok := seen[cookie]; !ok {
			delete(a.folded, cookie)
		}
	}

	// Re-evaluate the gates for every scope with accrued data.
	for sc, buckets := range a.aggregates {
		live, sufficient := a.floor.evaluateScope(buckets, a.lastFold[sc], now)
		if q := a.recoveryQuorum[sc]; q > 0 {
			if a.freshFolds[sc] < q {
				live = false // still recovering from a coverage gap
			} else {
				delete(a.recoveryQuorum, sc) // quorum met; re-arms cleanly on a future Rehydrate
			}
		}
		for bucketKey := range buckets {
			a.gates.SetBucketSufficient(sc, bucketKey, sufficient[bucketKey])
		}
		a.gates.SetLive(sc, live)
	}

	// Encode only the buckets dirtied since the last persist.
	var writes []persist.BucketWrite
	for sc, keys := range a.dirty {
		buckets := a.aggregates[sc]
		for key := range keys {
			if buckets != nil {
				if agg := buckets[key]; agg != nil {
					if blob, err := agg.encode(); err == nil {
						writes = append(writes, persist.BucketWrite{Scope: sc, Key: key, Blob: blob})
					}
				}
			}
		}
	}
	a.dirty = map[contract.ScopeKey]map[string]bool{}
	return writes
}

func (a *Aggregator) foldCompleted(lf *liveFlow, fs observe.FlowStats, now time.Time) {
	if a.excluder != nil && a.excluder.excludedFlow(lf.scope, fs) {
		a.stats.ExcludedFolds++
		return // confirmed-malicious: keep out of the baseline-of-normal
	}
	buckets := a.aggregates[lf.scope]
	if buckets == nil {
		buckets = map[string]*bucketAggregate{}
		a.aggregates[lf.scope] = buckets
	}
	agg := buckets[lf.bucket]
	if agg == nil {
		agg = newBucketAggregate()
		buckets[lf.bucket] = agg
	}
	agg.foldFlow(fs, lf.day)
	a.markDirty(lf.scope, lf.bucket)
	a.lastFold[lf.scope] = now
	a.freshFolds[lf.scope]++
	a.stats.CompletedFolds++
}

func (a *Aggregator) markDirty(sc contract.ScopeKey, bucket string) {
	d := a.dirty[sc]
	if d == nil {
		d = map[string]bool{}
		a.dirty[sc] = d
	}
	d[bucket] = true
}

// Features implements baseline.FeatureSource: it derives the flow's deviation
// feature vector against the live per-scope baseline slice for the current time
// bucket. ok=false when the flow has no observed kernel stats or the scope/
// bucket has no accrued baseline — in which case the multiplier falls back to
// neutral (and the gating in baseline.Store still forces M=1 unless the scope is
// calibrated, live, and bucket-sufficient). It never excludes — even a known-
// malicious flow gets real (high-novelty) features so the multiplier sharpens
// the response to its canary touch.
func (a *Aggregator) Features(sc contract.ScopeKey, flow contract.FlowIdentity, at time.Time) (baseline.Features, bool) {
	if flow.SocketCookie == 0 {
		return baseline.Features{}, false
	}
	fs, ok, err := a.reader.ReadStats(flow.SocketCookie)
	if err != nil || !ok {
		return baseline.Features{}, false
	}
	bucket := a.bucketer(at)

	a.mu.RLock()
	defer a.mu.RUnlock()
	byBucket := a.aggregates[sc]
	if byBucket == nil {
		return baseline.Features{}, false
	}
	agg := byBucket[bucket]
	if agg == nil {
		return baseline.Features{}, false
	}
	return deriveFeatures(agg, fs, a.floor.MinP2Samples), true
}

// Stats returns a snapshot of the observability counters.
func (a *Aggregator) Stats() AggStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.stats
}

// dayKey is the UTC calendar-day key used for per-bucket day coverage.
func dayKey(t time.Time) string { return t.UTC().Format("2006-01-02") }
