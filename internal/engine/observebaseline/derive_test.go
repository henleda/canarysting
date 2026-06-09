package observebaseline

import (
	"math"
	"math/rand"
	"net/netip"
	"testing"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/engine/baseline"
)

func TestNoveltyShape(t *testing.T) {
	cases := []struct {
		count uint32
		want  float64
	}{{0, 1.0}, {1, 0.5}, {3, 0.25}, {9, 0.1}, {99, 0.01}}
	for _, c := range cases {
		if got := novelty(c.count); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("novelty(%d) = %v, want %v", c.count, got, c.want)
		}
	}
	// Monotonically decreasing.
	prev := 2.0
	for c := uint32(0); c < 50; c++ {
		n := novelty(c)
		if n >= prev {
			t.Fatalf("novelty not strictly decreasing at %d: %v >= %v", c, n, prev)
		}
		prev = n
	}
}

func TestSquashShape(t *testing.T) {
	if squash(0, zKnee) != 0 {
		t.Error("squash(0) != 0")
	}
	if got := squash(zKnee, zKnee); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("squash(knee) = %v, want 0.5", got)
	}
	if got := squash(1e9, zKnee); got <= 0.99 || got >= 1.0 {
		t.Errorf("squash(huge) = %v, want ~1 (and < 1)", got)
	}
	// Monotone increasing, bounded in [0,1).
	prev := -1.0
	for z := 0.0; z < 100; z += 0.5 {
		v := squash(z, zKnee)
		if v < 0 || v >= 1 {
			t.Fatalf("squash(%v) = %v out of [0,1)", z, v)
		}
		if v < prev {
			t.Fatalf("squash not monotone at %v", z)
		}
		prev = v
	}
}

func TestRobustZAtCenterIsZero(t *testing.T) {
	if z := robustZ(5.0, 5.0, 2.0); z != 0 {
		t.Errorf("robustZ at median = %v, want 0", z)
	}
	// Same absolute deviation, smaller IQR -> larger z (tighter baseline, more abnormal).
	zWide := robustZ(10, 5, 4)
	zTight := robustZ(10, 5, 1)
	if !(zTight > zWide) {
		t.Errorf("expected tighter IQR to yield larger z: tight=%v wide=%v", zTight, zWide)
	}
}

// Property: for any FlowStats against any aggregate, every derived feature is in
// [0,1] — so the frozen CMax=1.0 cap never bites (no silent truncation of signal).
func TestDeriveFeaturesAlwaysInUnitRange(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	// Build a random-ish but realistic aggregate.
	agg := newBucketAggregate()
	for i := 0; i < 500; i++ {
		fs := randomFlow(rng)
		agg.foldFlow(fs, "2026-06-01")
	}
	for i := 0; i < 2000; i++ {
		fs := randomFlow(rng)
		f := deriveFeatures(agg, fs, 5)
		for name, v := range map[string]float64{
			"adj": f.AdjacencyNovelty, "id": f.IdentityNovelty, "port": f.PortNovelty,
			"vol": f.VolumeDeviation, "cad": f.CadenceDeviation,
		} {
			if v < 0 || v > 1 {
				t.Fatalf("feature %s = %v out of [0,1] for %+v", name, v, fs)
			}
		}
	}
}

// A flow on a never-seen adjacency from a never-seen identity is maximally novel
// in those features, and the resulting M lands in the spec's "abnormal" band.
func TestDeriveNovelFlowAmplifies(t *testing.T) {
	agg := newBucketAggregate()
	// Accrue a baseline of one legit identity (10.0.1.7) reaching one service.
	legit := flowFromIPs(7, 1, 1500, 12, 2_000_000)
	for i := 0; i < 200; i++ {
		agg.foldFlow(legit, "2026-06-01")
	}
	// The attacker: a brand-new source identity and adjacency.
	attacker := flowFromIPs(199, 1, 1500, 12, 2_000_000)
	f := deriveFeatures(agg, attacker, 5)
	if f.IdentityNovelty != 1.0 {
		t.Errorf("attacker IdentityNovelty = %v, want 1.0", f.IdentityNovelty)
	}
	if f.AdjacencyNovelty != 1.0 {
		t.Errorf("attacker AdjacencyNovelty = %v, want 1.0", f.AdjacencyNovelty)
	}
	// The legit flow itself is familiar -> low novelty.
	lf := deriveFeatures(agg, legit, 5)
	if lf.IdentityNovelty > 0.02 {
		t.Errorf("legit IdentityNovelty = %v, want small", lf.IdentityNovelty)
	}
	// Through the frozen multiplier, the attacker amplifies, the legit does not.
	mAtt := baseline.MFromFeatures(f, baseline.DefaultParams())
	mLegit := baseline.MFromFeatures(lf, baseline.DefaultParams())
	if !(mAtt > 2.0 && mAtt <= 3.0) {
		t.Errorf("attacker M = %v, want in (2.0, 3.0]", mAtt)
	}
	if !(mLegit < 1.2) {
		t.Errorf("legit M = %v, want ~1", mLegit)
	}
}

func TestHashConsistencyObserveVsDeclared(t *testing.T) {
	// A v4 source observed by the kernel and the same address declared as a
	// string must hash identically, so a declared attacker IP excludes its
	// observed flows.
	fs := flowFromIPs(42, 1, 100, 2, 1000)
	observed := hashIdentity(fs)
	declared := hashAddrCanonical(netip.MustParseAddr("10.0.1.42"))
	if observed != declared {
		t.Fatalf("observed identity hash %d != declared %d for the same v4 address", observed, declared)
	}
}

// --- helpers ---------------------------------------------------------------

func flowFromIPs(srcLast, dstLast byte, bytes, pkts, durNs uint64) observe.FlowStats {
	var src, dst [16]byte
	src[0], src[1], src[2], src[3] = 10, 0, 1, srcLast
	dst[0], dst[1], dst[2], dst[3] = 10, 0, 2, dstLast
	return observe.FlowStats{
		Family: observe.AFInet, SrcIP: src, DstIP: dst, SrcPort: 40000, DstPort: 8080,
		IngressBytes: bytes, EgressBytes: bytes, IngressPackets: pkts, EgressPackets: pkts,
		FirstSeenNs: 1_000, LastSeenNs: 1_000 + durNs,
	}
}

func randomFlow(rng *rand.Rand) observe.FlowStats {
	dur := uint64(rng.Int63n(5_000_000_000))
	return flowFromIPs(
		byte(rng.Intn(8)+1), byte(rng.Intn(4)+1),
		uint64(rng.Int63n(1_000_000)+1), uint64(rng.Int63n(1000)+1), dur,
	)
}
