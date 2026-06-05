// Package baseline implements the bounded baseline weight multiplier M that the
// per-scope eBPF baseline contributes to a canary touch's score:
//
//	Score = B × M,  M ∈ [1, M_max]
//
// where B is the windowed weighted base from scoring. M is floored at one (a
// poisoned baseline can fail to amplify but never suppress), capped at a small
// constant (the baseline never dominates the touch count), built from per-feature
// contributions that are each capped then combined by a bounded function (no
// single outlier blows up the score), and multiplicative (no touch => B = 0 =>
// Score = 0, the guardrail in arithmetic). The full specification and the IP
// framing are in docs/BASELINE_MULTIPLIER.md, which governs this package.
//
// HARD RULE: M never triggers anything. Deviation alone — d, M, novelty, volume
// or cadence change — must never tag, contain, tarpit, or attrit a flow. Only a
// canary touch enters the response pipeline. See docs/BASELINE_MULTIPLIER.md §1, §8.
package baseline

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

// Default multiplier parameters (docs/BASELINE_MULTIPLIER.md §6). These are
// documented inputs, not hidden constants; config/ carries operator overrides.
const (
	DefaultMMax = 3.0 // multiplier cap (asymptotic); keep conservative
	DefaultK    = 0.5 // saturation knee: the d at which g = 0.5
	DefaultCMax = 1.0 // per-feature contribution cap
)

// Features is a flow's deviation feature vector against the scope baseline for
// the current time bucket, each a raw non-negative contribution before capping.
// Real values are derived from the eBPF observation path (bpf/loader, M5/M7);
// novelty features are 0..1, volume/cadence are normalized distances. See
// docs/BASELINE_MULTIPLIER.md §3.1.
type Features struct {
	AdjacencyNovelty float64 // strongest single feature: unseen src->dst pair
	IdentityNovelty  float64 // initiating identity never made this connection
	PortNovelty      float64 // port/protocol abnormal for this adjacency
	VolumeDeviation  float64 // byte/packet envelope distance from baseline
	CadenceDeviation float64 // timing/frequency distance from baseline
}

func (f Features) contributions() [5]float64 {
	return [5]float64{
		f.AdjacencyNovelty,
		f.IdentityNovelty,
		f.PortNovelty,
		f.VolumeDeviation,
		f.CadenceDeviation,
	}
}

// Params are the multiplier parameters. Zero fields fall back to the documented
// defaults via Normalized.
type Params struct {
	MMax float64 // multiplier cap, >= 1
	K    float64 // saturation knee, > 0
	CMax float64 // per-feature cap, > 0
}

// DefaultParams returns the documented defaults.
func DefaultParams() Params { return Params{MMax: DefaultMMax, K: DefaultK, CMax: DefaultCMax} }

// Normalized fills zero/invalid fields with defaults. MMax is floored at 1 (the
// multiplier floor-of-one invariant: M can never suppress a base score).
func (p Params) Normalized() Params {
	if p.MMax < 1 {
		p.MMax = DefaultMMax
	}
	if p.K <= 0 {
		p.K = DefaultK
	}
	if p.CMax <= 0 {
		p.CMax = DefaultCMax
	}
	return p
}

// Deviation computes the bounded scalar d from features: each contribution is
// capped at CMax (§3.2), then combined by the Euclidean norm (§3.3). The result
// is bounded because every contribution is bounded.
func Deviation(f Features, p Params) float64 {
	p = p.Normalized()
	var sumSq float64
	for _, raw := range f.contributions() {
		c := raw
		if c < 0 {
			c = 0
		}
		if c > p.CMax {
			c = p.CMax
		}
		sumSq += c * c
	}
	return math.Sqrt(sumSq)
}

// G is the saturating Hill function g(d) = d/(d+k) on [0,1): g(0)=0, g→1 as
// d→∞, continuous and monotonic. See docs/BASELINE_MULTIPLIER.md §4.
func G(d, k float64) float64 {
	if d <= 0 {
		return 0
	}
	if k <= 0 {
		k = DefaultK
	}
	return d / (d + k)
}

// MFromD maps a deviation d to the bounded multiplier M = 1 + (M_max−1)·g(d),
// so M ∈ [1, M_max]. d ≤ 0 yields exactly 1.0 (neutral).
func MFromD(d float64, p Params) float64 {
	p = p.Normalized()
	return 1 + (p.MMax-1)*G(d, p.K)
}

// MFromFeatures composes the full pipeline: features → capped contributions →
// bounded d → saturating M. The returned M is always in [1, M_max].
func MFromFeatures(f Features, p Params) float64 {
	return MFromD(Deviation(f, p), p)
}

// Bucketer maps a time to the baseline time-bucket key (§3.4). The baseline is
// conditioned on the bucket so a nightly batch job is not flagged anomalous at
// 3am only because the baseline was not conditioned on time. Default: day-of-
// week × hour.
type Bucketer func(time.Time) string

// DefaultBucketer keys on day-of-week crossed with the hour.
func DefaultBucketer(t time.Time) string {
	return fmt.Sprintf("%s-%02d", t.UTC().Weekday(), t.UTC().Hour())
}

// Store owns the per-scope baseline state and produces M for a flow, gating to a
// neutral 1.0 whenever the scope is uncalibrated, the baseline is stale, or the
// current time bucket is sparse — "when in doubt, the multiplier is neutral"
// (docs/BASELINE_MULTIPLIER.md §6). It holds only scope-isolated state.
//
// The real per-scope baseline (and the per-flow Features derived from it) come
// from the eBPF observation path in M5/M7. Until a scope's baseline is marked
// live, every flow in it gets M = 1.0 — the engine reduces to touch-only
// scoring, which is the safe cold-start behavior.
type Store struct {
	mu         sync.Mutex
	params     Params
	bucketer   Bucketer
	calibrated func(contract.ScopeKey) bool // ties M to the SAME evidence floor as weights
	scopes     map[contract.ScopeKey]*scopeBaseline
}

type scopeBaseline struct {
	live    bool            // accrued and fresh (set by the loader path / M7); stale => false
	buckets map[string]bool // time-bucket key -> has sufficient baseline data
}

// Config configures a Store.
type Config struct {
	Params Params
	// Bucketer keys the time bucket; nil uses DefaultBucketer.
	Bucketer Bucketer
	// Calibrated reports whether a scope has crossed the shared evidence floor.
	// The multiplier and the canary weights go live together, never one without
	// the other (docs/ENGINE.md, docs/BASELINE_MULTIPLIER.md §6). Nil means the
	// scope is treated as never calibrated, so M stays 1.0.
	Calibrated func(contract.ScopeKey) bool
}

// New returns a Store with defaults filled in.
func New(cfg Config) *Store {
	b := cfg.Bucketer
	if b == nil {
		b = DefaultBucketer
	}
	return &Store{
		params:     cfg.Params.Normalized(),
		bucketer:   b,
		calibrated: cfg.Calibrated,
		scopes:     map[contract.ScopeKey]*scopeBaseline{},
	}
}

// SetLive marks a scope's baseline as accrued-and-fresh (live=true) or stale
// (live=false). Called by the eBPF/loader refresh path (M7); used by tests to
// exercise the calibrated path. A stale baseline forces M = 1.0.
func (s *Store) SetLive(scope contract.ScopeKey, live bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scope(scope).live = live
}

// SetBucketSufficient marks whether a time bucket has enough baseline data. A
// sparse bucket forces M = 1.0 for flows in that bucket.
func (s *Store) SetBucketSufficient(scope contract.ScopeKey, bucket string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scope(scope).buckets[bucket] = ok
}

func (s *Store) scope(k contract.ScopeKey) *scopeBaseline {
	sb := s.scopes[k]
	if sb == nil {
		sb = &scopeBaseline{buckets: map[string]bool{}}
		s.scopes[k] = sb
	}
	return sb
}

// ready reports whether the scope's baseline may amplify at time t: it must be
// calibrated, live (fresh), and have sufficient data in t's bucket.
func (s *Store) ready(scope contract.ScopeKey, t time.Time) bool {
	if s.calibrated == nil || !s.calibrated(scope) {
		return false
	}
	sb := s.scopes[scope]
	if sb == nil || !sb.live {
		return false
	}
	return sb.buckets[s.bucketer(t)]
}

// M returns the gated multiplier for an explicit feature vector in a scope at
// time t. It returns exactly 1.0 unless the scope's baseline is ready, in which
// case it returns the bounded MFromFeatures. This is the tested core of the
// gating + math.
func (s *Store) M(scope contract.ScopeKey, f Features, t time.Time) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready(scope, t) {
		return 1.0
	}
	return MFromFeatures(f, s.params)
}

// Multiplier implements scoring.MultiplierSource. In M2 the per-flow Features are
// not yet derivable without the eBPF baseline, so this returns the gated M for
// neutral features — which is 1.0 in every case until M5/M7 supply both a live
// baseline and real per-flow feature derivation. The gating and the math are
// already exercised through M.
//
// TODO(M5/M7): derive Features for the flow from the live per-scope baseline
// slice (adjacency/identity/port/volume/cadence vs the time-bucketed baseline),
// then return s.M(scope, derived, at).
func (s *Store) Multiplier(scope contract.ScopeKey, _ contract.FlowIdentity, at time.Time) float64 {
	return s.M(scope, Features{}, at)
}
