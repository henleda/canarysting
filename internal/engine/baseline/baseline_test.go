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

	allMaxed := MFromFeatures(Features{1, 1, 1, 1, 1}, p)
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
	mMax := MFromFeatures(Features{1, 1, 1, 1, 1}, p)
	approx(t, mMax, 2.63, 0.03, "maximally-abnormal M (spec ~2.6)")
}

func TestWorkedExample_MaximallyAbnormalNoTouchScoresZero(t *testing.T) {
	// B = 0 (no canary touched) -> Score = 0 for ANY M. The guardrail.
	mMax := MFromFeatures(Features{1, 1, 1, 1, 1}, DefaultParams())
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
