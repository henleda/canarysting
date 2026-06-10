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
	// DefaultSharpeningAlpha is the D5 detection-sharpening coefficient α: how
	// much a maximal confirmed-malicious fingerprint match adds to M, as a
	// bounded ADDITIVE term (docs/D2_D5_DESIGN.md §1.2). α ∈ [0, MMax−1]; 0
	// disables D5. At α=0.5 a pure match on an otherwise-normal flow lifts M to
	// 1.5; combined with novelty it saturates toward MMax (final clamp).
	DefaultSharpeningAlpha = 0.5
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

	// FingerprintMatch is the D5 detection-sharpening signal: [0,1] strength of a
	// match between the flow's emerging behavior and a CONFIRMED-MALICIOUS profile
	// in this scope (docs/D2_D5_DESIGN.md §1.2). It is DELIBERATELY NOT a
	// contributions() / novelty-norm dimension — confirmed-malice is orthogonal to
	// baseline-deviation and is applied as a separate bounded ADDITIVE term in
	// MFromFeatures, so it is neither diluted by nor double-counted against the
	// five novelty features. Weight context only: it shapes M, never triggers
	// anything (rule 8); a base that is zero without a canary touch stays zero.
	FingerprintMatch float64
}

// contributions returns the FIVE baseline-novelty/deviation features that form
// the bounded Euclidean norm d. FingerprintMatch is intentionally excluded (it is
// an additive sharpening term, not a norm dimension — see the field comment), so
// d — and therefore M for any flow without a fingerprint match — is unchanged.
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
	// SharpeningAlpha is the D5 additive sharpening coefficient α (the amount a
	// maximal confirmed-malicious fingerprint match adds to M). Clamped to
	// [0, MMax−1] by Normalized; 0 disables D5. Zero value = off (operator-elective),
	// so it is NOT default-filled — DefaultParams sets the documented default.
	SharpeningAlpha float64
}

// DefaultParams returns the documented defaults. SharpeningAlpha is 0 here in
// PHASE 1 — D5 is off everywhere (the engine AND the dashboard's M
// reconstruction, which both reach for DefaultParams) until Phase 2 wires the
// matcher and flips this to DefaultSharpeningAlpha (and sets α in boot's baseline
// Params). Keeping α=0 here makes Phase-1 neutrality unconditional, not merely a
// consequence of match=0.
func DefaultParams() Params {
	return Params{MMax: DefaultMMax, K: DefaultK, CMax: DefaultCMax, SharpeningAlpha: 0}
}

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
	// α is operator-elective (0 = D5 off, a valid choice, so not default-filled),
	// but it must stay in [0, MMax−1] so the additive term cannot push M past MMax
	// before the final clamp.
	if p.SharpeningAlpha < 0 {
		p.SharpeningAlpha = 0
	}
	if max := p.MMax - 1; p.SharpeningAlpha > max {
		p.SharpeningAlpha = max
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

// MFromFeatures composes the full pipeline: the five novelty features → capped
// contributions → bounded d → saturating baseline term, PLUS the D5 additive
// sharpening term for a confirmed-malicious fingerprint match:
//
//	M = clamp( 1 + (M_max−1)·g(d)  +  α·match , 1, M_max )
//
// The sharpening term is ADDITIVE and separate from the novelty norm (so a
// confirmed match is neither diluted by low novelty nor double-counted against
// adjacency/identity; docs/D2_D5_DESIGN.md §1.2). It is still inside M, so the
// guardrail holds in arithmetic: a base that is zero without a canary touch stays
// zero (Score = 0 × M = 0; rule 8). The returned M is always in [1, M_max].
// FingerprintMatch=0 (the default, and all of Phase 1) makes this byte-identical
// to the pre-D5 MFromD(Deviation(f)).
func MFromFeatures(f Features, p Params) float64 {
	p = p.Normalized()
	m := MFromD(Deviation(f, p), p)
	if p.SharpeningAlpha > 0 {
		match := f.FingerprintMatch
		if match < 0 {
			match = 0
		}
		if match > 1 {
			match = 1
		}
		m += p.SharpeningAlpha * match
		if m > p.MMax {
			m = p.MMax
		}
	}
	return m
}

// Bucketer maps a time to the baseline time-bucket key (§3.4). The baseline is
// conditioned on the bucket so a nightly batch job is not flagged anomalous at
// 3am only because the baseline was not conditioned on time. Default: day-of-
// week × hour.
type Bucketer func(time.Time) string

// DefaultBucketer keys on day-of-week crossed with the hour. This is the
// PRODUCTION default: 168 buckets give full diurnal/weekly resolution.
func DefaultBucketer(t time.Time) string {
	return fmt.Sprintf("%s-%02d", t.UTC().Weekday(), t.UTC().Hour())
}

// WindowBucketer is the COARSE bucketer used to run a bounded learning window
// (docs/ROADMAP.md M7, decision D6): {weekday,weekend} × {night,morning,
// afternoon,evening} = 8 buckets. With only 8 buckets a bucket is revisited
// many times per week, so bucket-sufficiency is reachable within a ≤2-week
// window — whereas the 168-bucket DefaultBucketer revisits each (weekday,hour)
// only ~once/week and would leave most buckets sparse (and M neutral) for the
// whole window. An operator graduates from WindowBucketer to DefaultBucketer as
// more weeks of real data accrue; granularity is operator config, not a hidden
// constant. Time conditioning is preserved either way (a 3am batch job is not
// flagged anomalous merely because the baseline ignored time).
func WindowBucketer(t time.Time) string {
	t = t.UTC()
	day := "weekday"
	if wd := t.Weekday(); wd == time.Saturday || wd == time.Sunday {
		day = "weekend"
	}
	var part string
	switch h := t.Hour(); {
	case h < 6:
		part = "night" // 00:00–05:59 UTC
	case h < 12:
		part = "morning" // 06:00–11:59
	case h < 18:
		part = "afternoon" // 12:00–17:59
	default:
		part = "evening" // 18:00–23:59
	}
	return day + "-" + part
}

// FeatureSource derives a flow's deviation feature vector against the live
// per-scope baseline for the current time bucket. It is the M7 seam: the
// observe-path aggregator (internal/engine/observebaseline) implements it,
// reading the flow's kernel-observed stats and comparing them to the accrued
// baseline slice. Keeping it an interface here means internal/engine/baseline
// takes NO dependency on the eBPF/observe packages (no import cycle; the engine
// stays proxy-agnostic).
//
// ok=false means no features could be derived (no observed stats for the
// cookie, or the baseline slice is not ready), in which case the Store falls
// back to neutral features — and the same three gates still force M to 1.0
// unless the scope is calibrated, live, and bucket-sufficient. A FeatureSource
// can never make M trigger anything: it only shapes the multiplier on a base
// that is zero without a canary touch.
type FeatureSource interface {
	Features(scope contract.ScopeKey, flow contract.FlowIdentity, at time.Time) (f Features, ok bool)
}

// Matcher is the D5 detection-sharpening seam: it returns how strongly a flow's
// EMERGING behavior matches a CONFIRMED-MALICIOUS profile in its scope — the
// fingerprint-match strength [0,1] that feeds M's additive sharpening term
// (docs/D2_D5_DESIGN.md §1.2). The confirmed-malicious profile set is built from
// T3/jail outcomes (decision C / Option 3): customer-reproducible ground truth,
// gated by a per-fingerprint jail-count floor + freshness inside the matcher.
//
// Like FeatureSource, this is an interface so internal/engine/baseline takes NO
// dependency on the intelligence/profile packages (no import cycle). The result
// is WEIGHT CONTEXT only: it can never trigger anything (rule 8) — it shapes M on
// a base that is zero without a canary touch. 0 = no match / under the jail floor
// / stale / not ready. A nil Matcher (the default, and all of Phase 1) means no
// sharpening, so M is exactly the pre-D5 baseline multiplier.
type Matcher interface {
	Match(scope contract.ScopeKey, flow contract.FlowIdentity, at time.Time) float64
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
	features   FeatureSource                // M7: derives per-flow Features; nil => neutral
	matcher    Matcher                      // D5: confirmed-malicious fingerprint matcher; nil => no sharpening
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

// UseFeatureSource wires the M7 per-flow feature derivation. A nil source is
// ignored (the Store keeps its current source; default is none → neutral
// features → touch-only scoring). Returns the Store for chaining. Safe to call
// once at composition time.
func (s *Store) UseFeatureSource(fs FeatureSource) *Store {
	if fs != nil {
		s.mu.Lock()
		s.features = fs
		s.mu.Unlock()
	}
	return s
}

// UseMatcher wires the D5 fingerprint Matcher (the per-scope confirmed-malicious
// profile store; see internal/intelligence/profile + the engine malicious-profile
// store in Phase 2). A nil matcher is ignored (default: none → match 0 → no
// sharpening, so M is exactly the baseline multiplier). Returns the Store for
// chaining. Safe to call once at composition time.
func (s *Store) UseMatcher(m Matcher) *Store {
	if m != nil {
		s.mu.Lock()
		s.matcher = m
		s.mu.Unlock()
	}
	return s
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

// GateState reports a scope's baseline gate state for observability/dashboards.
type GateState struct {
	Live             bool // baseline accrued and fresh (the eBPF data floor met)
	BucketSufficient bool // the time bucket for t has enough data
	Calibrated       bool // the analyst-evidence floor is met (same gate as canary weights)
}

// State returns the baseline gate state for a scope at time t. It does not
// amplify or mutate anything — it surfaces the same three gates ready() ANDs, so
// a dashboard can show why M is or is not amplifying. Read-only.
func (s *Store) State(scope contract.ScopeKey, t time.Time) GateState {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := GateState{Calibrated: s.calibrated != nil && s.calibrated(scope)}
	if sb := s.scopes[scope]; sb != nil {
		g.Live = sb.live
		g.BucketSufficient = sb.buckets[s.bucketer(t)]
	}
	return g
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

// Multiplier implements scoring.MultiplierSource. It derives the flow's Features
// from the wired FeatureSource (the M7 observe-path aggregator) and returns the
// gated multiplier s.M(scope, derived, at). With no source wired, or when the
// source cannot derive features for this flow, it falls back to neutral Features
// — and the gating in M still forces 1.0 unless the scope is calibrated, live,
// and bucket-sufficient. Either way M ∈ [1, M_max] and multiplies a base that is
// zero without a canary touch, so this can never trigger anything (rule 8).
func (s *Store) Multiplier(scope contract.ScopeKey, flow contract.FlowIdentity, at time.Time) float64 {
	// LOCK ORDER (do not "simplify" to a deferred unlock): release this Store's
	// mutex (B) BEFORE calling fs.Features(), which takes the aggregator's mutex
	// (A). The aggregator's fold loop holds A while calling SetLive/
	// SetBucketSufficient, which take B (order A→B). Holding B across fs.Features()
	// would make this path B→A and deadlock. So: snapshot the source under B,
	// unlock, then call out.
	s.mu.Lock()
	fs := s.features
	mt := s.matcher
	s.mu.Unlock()

	f := Features{} // neutral by default
	if fs != nil {
		if derived, ok := fs.Features(scope, flow, at); ok {
			f = derived
		}
	}
	// D5 sharpening: fold in the confirmed-malicious fingerprint-match strength as
	// weight context (it lands in M's additive term inside s.M → MFromFeatures).
	// Called OUTSIDE the Store lock — the matcher may take its own lock, same B→A
	// deadlock discipline as fs.Features() above. The match is still subject to
	// s.M's readiness gate (uncalibrated/stale/sparse ⇒ M=1.0, match ignored) and
	// to the matcher's own jail-evidence/freshness floor (it returns 0 otherwise).
	if mt != nil {
		f.FingerprintMatch = mt.Match(scope, flow, at)
	}
	return s.M(scope, f, at)
}
