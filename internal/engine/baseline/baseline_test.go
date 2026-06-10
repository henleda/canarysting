package baseline

import (
	"math"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

const eps = 1e-9

func approx(t *testing.T, got, want, tol float64, msg string) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s: got %.4f, want %.4f (±%.4f)", msg, got, want, tol)
	}
}

// --- The math (the guardrail expressed in arithmetic) ---

func TestM_NeutralAtZeroDeviation(t *testing.T) {
	// Invariant: g(0)=0, so a flow that matches the baseline gets M = 1 exactly.
	if m := MFromD(0, DefaultParams()); m != 1.0 {
		t.Fatalf("M(0) = %.6f, want exactly 1.0", m)
	}
	if m := MFromFeatures(Features{}, DefaultParams()); m != 1.0 {
		t.Fatalf("M(neutral features) = %.6f, want 1.0", m)
	}
}

func TestM_KneeIsHalfRange(t *testing.T) {
	// At d = k, g = 0.5, so M sits at the middle of [1, M_max].
	p := DefaultParams()
	approx(t, MFromD(p.K, p), 1+(p.MMax-1)*0.5, eps, "M at the knee d=k")
}

func TestM_BoundedAndFlooredAndMonotonic(t *testing.T) {
	p := DefaultParams()
	prev := MFromD(0, p)
	for d := 0.0; d <= 50; d += 0.1 {
		m := MFromD(d, p)
		if m < 1.0-eps {
			t.Fatalf("M(%.2f) = %.4f fell below the floor of 1", d, m)
		}
		if m > p.MMax+eps {
			t.Fatalf("M(%.2f) = %.4f exceeded the cap M_max=%.1f", d, m, p.MMax)
		}
		if m < prev-eps {
			t.Fatalf("M not monotonic: M(%.2f)=%.4f < previous %.4f", d, m, prev)
		}
		prev = m
	}
	// Saturates toward, but never reaches, the cap.
	if m := MFromD(1e9, p); m >= p.MMax {
		t.Fatalf("M(huge) = %.6f must approach but not reach M_max", m)
	}
}

func TestDeviation_PerFeatureCapPreventsOutlierDomination(t *testing.T) {
	p := DefaultParams()
	// One enormous feature is capped at CMax, so it cannot out-contribute a
	// single maxed feature, and cannot reach the all-features-maxed deviation.
	oneWild := MFromFeatures(Features{VolumeDeviation: 1e6}, p)
	oneCapped := MFromFeatures(Features{VolumeDeviation: p.CMax}, p)
	approx(t, oneWild, oneCapped, eps, "wild single feature must equal one capped feature")

	allMaxed := MFromFeatures(abnormal, p)
	if oneWild >= allMaxed {
		t.Fatalf("a single wild feature (%.4f) dominated the score vs all-features (%.4f)", oneWild, allMaxed)
	}
}

func TestDeviation_EuclideanNormOfCappedContributions(t *testing.T) {
	p := DefaultParams()
	d := Deviation(Features{AdjacencyNovelty: 1, IdentityNovelty: 1}, p)
	approx(t, d, math.Sqrt(2), eps, "d for two maxed features")
}

// --- The four worked examples (docs/BASELINE_MULTIPLIER.md §5) ---

func TestWorkedExample_NormalFlowOneTouch(t *testing.T) {
	// d ≈ 0 -> M ≈ 1.0 -> Score = base. The baseline did nothing.
	m := MFromFeatures(Features{}, DefaultParams())
	if m != 1.0 {
		t.Fatalf("normal flow M = %.4f, want 1.0", m)
	}
	const base = 1.0
	if score := base * m; score != 1.0 {
		t.Fatalf("normal-flow score = %.4f, want 1.0", score)
	}
}

func TestWorkedExample_AbnormalFlowOneTouch(t *testing.T) {
	p := DefaultParams()
	// Never-before-seen adjacency + identity that never initiated: strongly
	// abnormal. The same single touch escalates substantially faster (~2.5x).
	m := MFromFeatures(Features{AdjacencyNovelty: 1, IdentityNovelty: 1}, p)
	if m <= 2.0 || m > p.MMax {
		t.Fatalf("abnormal-flow M = %.4f, want in (2.0, %.1f]", m, p.MMax)
	}
	// Maximally abnormal in every feature lands near the spec's ~2.6.
	mMax := MFromFeatures(abnormal, p)
	approx(t, mMax, 2.63, 0.03, "maximally-abnormal M (spec ~2.6)")
}

func TestWorkedExample_MaximallyAbnormalNoTouchScoresZero(t *testing.T) {
	// B = 0 (no canary touched) -> Score = 0 for ANY M. The guardrail.
	mMax := MFromFeatures(abnormal, DefaultParams())
	const base = 0.0
	if score := base * mMax; score != 0.0 {
		t.Fatalf("no-touch score = %.4f with M=%.4f, want 0 (deviation alone triggers nothing)", score, mMax)
	}
}

func TestWorkedExample_PoisonedBaselineRealAttacker(t *testing.T) {
	// An attacker present during learning taught the baseline they are normal:
	// d ≈ 0 -> M ≈ 1.0. They still score the full base from the touch. The
	// poisoning cost the amplification, never the detection (floor-of-one).
	m := MFromFeatures(Features{}, DefaultParams())
	if m != 1.0 {
		t.Fatalf("poisoned-baseline attacker M = %.4f, want 1.0 (still scores, never suppressed)", m)
	}
}

// --- Gating: force M = 1.0 when uncalibrated / stale / bucket-sparse ---

func calibratedSet(scopes ...contract.ScopeKey) func(contract.ScopeKey) bool {
	set := map[contract.ScopeKey]bool{}
	for _, s := range scopes {
		set[s] = true
	}
	return func(s contract.ScopeKey) bool { return set[s] }
}

var abnormal = Features{AdjacencyNovelty: 1, IdentityNovelty: 1, PortNovelty: 1, VolumeDeviation: 1, CadenceDeviation: 1}

func TestGate_UncalibratedForcesNeutral(t *testing.T) {
	// No Calibrated func => scope never calibrated => M = 1 even when live.
	b := New(Config{})
	b.SetLive("s", true)
	b.SetBucketSufficient("s", DefaultBucketer(time.Unix(0, 0)), true)
	if m := b.M("s", abnormal, time.Unix(0, 0)); m != 1.0 {
		t.Fatalf("uncalibrated scope must force M=1.0, got %.4f", m)
	}
}

func TestGate_StaleBaselineForcesNeutral(t *testing.T) {
	b := New(Config{Calibrated: calibratedSet("s")})
	// Calibrated, but baseline not marked live (stale/never accrued).
	b.SetBucketSufficient("s", DefaultBucketer(time.Unix(0, 0)), true)
	if m := b.M("s", abnormal, time.Unix(0, 0)); m != 1.0 {
		t.Fatalf("stale baseline must force M=1.0, got %.4f", m)
	}
}

func TestGate_SparseBucketForcesNeutral(t *testing.T) {
	b := New(Config{Calibrated: calibratedSet("s")})
	b.SetLive("s", true)
	// Bucket for this time has insufficient data (never marked sufficient).
	if m := b.M("s", abnormal, time.Unix(0, 0)); m != 1.0 {
		t.Fatalf("sparse time bucket must force M=1.0, got %.4f", m)
	}
}

func TestGate_AmplifiesOnlyWhenCalibratedLiveAndBucketCovered(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	b := New(Config{Calibrated: calibratedSet("s")})
	b.SetLive("s", true)
	b.SetBucketSufficient("s", DefaultBucketer(at), true)
	if m := b.M("s", abnormal, at); m <= 1.0 {
		t.Fatalf("ready baseline must amplify an abnormal flow, got M=%.4f", m)
	}
	// A different scope shares nothing: still neutral.
	if m := b.M("other", abnormal, at); m != 1.0 {
		t.Fatalf("scope isolation: other scope must be neutral, got %.4f", m)
	}
}

func TestMultiplierSource_NeutralInM2EvenWhenReady(t *testing.T) {
	// The scoring-facing Multiplier returns 1.0 in M2 (no eBPF feature derivation
	// yet) even on a ready baseline — touch-only until M5/M7.
	at := time.Unix(1_700_000_000, 0)
	b := New(Config{Calibrated: calibratedSet("s")})
	b.SetLive("s", true)
	b.SetBucketSufficient("s", DefaultBucketer(at), true)
	if m := b.Multiplier("s", contract.FlowIdentity{SocketCookie: 1}, at); m != 1.0 {
		t.Fatalf("M2 scoring-path multiplier must be 1.0, got %.4f", m)
	}
}

// --- D5 detection sharpening: the additive confirmed-malicious match term ---

type fakeMatcher struct{ v float64 }

func (m fakeMatcher) Match(contract.ScopeKey, contract.FlowIdentity, time.Time) float64 { return m.v }

// sharpParams is DefaultParams with D5 sharpening enabled (the documented Phase-2
// α). Phase 1 ships DefaultParams with α=0 (D5 off everywhere), so tests that
// exercise sharpening opt in here.
func sharpParams() Params { p := DefaultParams(); p.SharpeningAlpha = DefaultSharpeningAlpha; return p }

// Phase-1 no-op proof: at FingerprintMatch=0 (the default) the additive term is
// byte-identical to the pre-D5 baseline multiplier, for any features and params.
func TestD5_ZeroMatchIsByteIdenticalNoOp(t *testing.T) {
	params := []Params{
		DefaultParams(),
		{MMax: 2, K: 0.3, CMax: 1, SharpeningAlpha: 1},
		{MMax: 5, K: 1, CMax: 0.5, SharpeningAlpha: 0.5},
	}
	feats := []Features{{}, {AdjacencyNovelty: 1, IdentityNovelty: 1}, abnormal, {VolumeDeviation: 0.3, CadenceDeviation: 0.7}}
	for _, p := range params {
		for _, f := range feats {
			preD5 := MFromD(Deviation(f, p), p) // the exact pre-D5 formula
			f.FingerprintMatch = 0
			if got := MFromFeatures(f, p); got != preD5 { // exact: adding 0.0 is exact in IEEE-754
				t.Fatalf("zero-match not a no-op: got %v want %v (p=%+v f=%+v)", got, preD5, p, f)
			}
		}
	}
}

// A confirmed match raises M, stays ≤ M_max, and — the anti-dilution property the
// rejected norm approach failed — a match on a LOW-novelty flow still lifts M.
func TestD5_MatchRaisesMBoundedAndUndiluted(t *testing.T) {
	p := sharpParams()
	noMatch := MFromFeatures(Features{}, p)                        // 1.0
	lowNovMatch := MFromFeatures(Features{FingerprintMatch: 1}, p) // 1 + α
	if lowNovMatch <= noMatch {
		t.Fatalf("anti-dilution: a match on a normal-looking flow must raise M (%.4f) above no-match (%.4f)", lowNovMatch, noMatch)
	}
	approx(t, lowNovMatch, 1+p.SharpeningAlpha, eps, "low-novelty full match = 1 + α")
	// Same flow with vs without a match: the match always raises M.
	base := Features{AdjacencyNovelty: 0.5}
	withMatch := base
	withMatch.FingerprintMatch = 1
	if MFromFeatures(withMatch, p) <= MFromFeatures(base, p) {
		t.Fatalf("a match must raise M above the same flow without a match")
	}
	// High novelty + full match saturates and is clamped to exactly M_max.
	maxed := abnormal
	maxed.FingerprintMatch = 1
	m := MFromFeatures(maxed, p)
	if m > p.MMax+eps {
		t.Fatalf("match + high novelty must stay ≤ M_max=%.2f, got %.6f", p.MMax, m)
	}
	approx(t, m, p.MMax, eps, "match + high novelty clamps to M_max")
}

// FingerprintMatch is clamped to [0,1] and α to [0, M_max−1], so out-of-range
// inputs can never push M past M_max.
func TestD5_MatchAndAlphaClamped(t *testing.T) {
	p := sharpParams()
	over := MFromFeatures(Features{FingerprintMatch: 5}, p)
	at1 := MFromFeatures(Features{FingerprintMatch: 1}, p)
	approx(t, over, at1, eps, "match>1 clamped to 1")
	if over > p.MMax+eps {
		t.Fatalf("clamped match must stay ≤ M_max, got %.6f", over)
	}
	// match<0 clamps to 0 (no suppression, never below the baseline term).
	neg := MFromFeatures(Features{FingerprintMatch: -5}, p)
	approx(t, neg, MFromFeatures(Features{}, p), eps, "match<0 clamped to 0")
	pBig := Params{MMax: 3, K: 0.5, CMax: 1, SharpeningAlpha: 100}
	if m := MFromFeatures(Features{FingerprintMatch: 1}, pBig); m > pBig.MMax+eps {
		t.Fatalf("α clamp failed: M=%.6f exceeds M_max=%.2f", m, pBig.MMax)
	}
}

// α=0 (the zero value, and the boot default in Phase 1) disables D5 entirely:
// even a full match leaves M as the pure baseline multiplier. This guards the
// production-neutral posture until Phase 2 sets α in boot.
func TestD5_AlphaZeroDisablesSharpening(t *testing.T) {
	p := Params{MMax: 3, K: 0.5, CMax: 1} // SharpeningAlpha defaults to 0
	full := MFromFeatures(Features{FingerprintMatch: 1}, p)
	none := MFromFeatures(Features{}, p)
	if full != none {
		t.Fatalf("α=0 must disable D5: match M=%v vs no-match M=%v", full, none)
	}
}

// The additive term is gated by the SAME readiness as the baseline term: an
// uncalibrated/stale/sparse scope forces M=1.0 even with a full match (rule 8).
func TestD5_MatchGatedByReadiness(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	// Uncalibrated (and α on): a full match is still forced neutral.
	if m := New(Config{Params: sharpParams()}).M("s", Features{FingerprintMatch: 1}, at); m != 1.0 {
		t.Fatalf("uncalibrated scope must force M=1.0 even with a match, got %.4f", m)
	}
	// Ready scope: the match now sharpens.
	b := New(Config{Params: sharpParams(), Calibrated: calibratedSet("s")})
	b.SetLive("s", true)
	b.SetBucketSufficient("s", DefaultBucketer(at), true)
	if m := b.M("s", Features{FingerprintMatch: 1}, at); m <= 1.0 {
		t.Fatalf("ready scope must sharpen on a match, got M=%.4f", m)
	}
}

// The scoring-facing Multiplier folds the matcher's strength into M when ready;
// a nil matcher (the Phase-1 default) leaves M as the pure baseline multiplier,
// an unready scope ignores the match, and the matcher value is clamped.
func TestD5_MultiplierWiresMatcher(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	flow := contract.FlowIdentity{SocketCookie: 1}
	newReady := func() *Store {
		b := New(Config{Params: sharpParams(), Calibrated: calibratedSet("s")})
		b.SetLive("s", true)
		b.SetBucketSufficient("s", DefaultBucketer(at), true)
		return b
	}
	if m := newReady().Multiplier("s", flow, at); m != 1.0 {
		t.Fatalf("nil matcher + no source must be neutral, got %.4f", m)
	}
	if m := newReady().UseMatcher(fakeMatcher{v: 1}).Multiplier("s", flow, at); m <= 1.0 {
		t.Fatalf("wired matcher must sharpen M, got %.4f", m)
	}
	if m := newReady().UseMatcher(fakeMatcher{v: 99}).Multiplier("s", flow, at); m > sharpParams().MMax+eps {
		t.Fatalf("matcher value must be clamped; M=%.6f exceeds M_max", m)
	}
	// Matcher on an UNREADY scope (not live / no bucket) is ignored.
	unready := New(Config{Params: sharpParams(), Calibrated: calibratedSet("s")}).UseMatcher(fakeMatcher{v: 1})
	if m := unready.Multiplier("s", flow, at); m != 1.0 {
		t.Fatalf("matcher on an unready scope must be ignored, got %.4f", m)
	}
}
