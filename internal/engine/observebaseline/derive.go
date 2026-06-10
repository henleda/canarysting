package observebaseline

import (
	"encoding/binary"
	"hash/fnv"
	"math"
	"net/netip"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/engine/baseline"
)

// Normalization constants (docs/BASELINE_MULTIPLIER.md §3, M7 decision D-norm).
const (
	// alphaNovelty is the additive-smoothing (Good–Turing) pseudo-count for the
	// three novelty features. novelty(count)=α/(count+α): never-seen→1.0,
	// seen-once→0.5, decaying as the value becomes familiar. α=1 puts the
	// half-novel point at a single prior observation.
	alphaNovelty = 1.0
	// zKnee is the robust-z at which the continuous squash reaches 0.5 — a flow
	// ~3 robust-sigma off the baseline center counts as moderately abnormal.
	zKnee = 3.0
	// zEps guards the robust scale against a degenerate zero IQR.
	zEps = 1e-9
)

// novelty maps a baseline frequency count to a [0,1] novelty contribution. It is
// bounded, smooth, monotonically decreasing, and bounded-influence (a single new
// observation can only LOWER novelty). See docs/BASELINE_MULTIPLIER.md §3.1.
func novelty(count uint32) float64 {
	return alphaNovelty / (float64(count) + alphaNovelty)
}

// squash is the saturating Hill map z/(z+knee) on [0,1): 0 at z=0, 0.5 at the
// knee, →1 as z→∞. It reuses the same saturating shape the frozen multiplier's
// G(d)=d/(d+k) uses, so the two compose rather than fight.
func squash(z, knee float64) float64 {
	if z <= 0 {
		return 0
	}
	return z / (z + knee)
}

// robustZ is the robust standardized distance of x from a baseline center: the
// absolute deviation from the median, scaled by the IQR converted to a sigma-
// equivalent (0.7413 = 1/1.349, the IQR→σ consistency constant for a normal).
// Robust center+scale means a contaminated baseline barely shifts the distance.
func robustZ(x, median, iqr float64) float64 {
	scale := 0.7413*iqr + zEps
	return math.Abs(x-median) / scale
}

// contContribution is the continuous-feature contribution for one P² summary at
// value x. It returns 0 (neutral) until the summary has folded minSamples — an
// un-converged distribution must not manufacture deviation; the bucket is not
// sufficient then anyway, so the multiplier gating already forces M=1.
func contContribution(p *p2Quantile, x float64, minSamples int) float64 {
	if !p.Ready(minSamples) {
		return 0
	}
	return squash(robustZ(x, p.Median(), p.IQR()), zKnee)
}

// deriveFeatures computes the flow's deviation feature vector against the per-
// (scope,bucket) baseline aggregate. Every returned field is in [0,1] by
// construction, so the frozen CMax=1.0 per-feature cap in baseline.Deviation is
// a guardrail that never actually bites — it never silently truncates signal.
//
// Volume/cadence are folded in LOG space (bytes/packets/inter-arrival/duration
// are heavy-tailed and multiplicative, so log makes the IQR a meaningful scale
// and the distribution roughly symmetric). Each continuous feature takes the max
// over its two component distances so a flow abnormal in either dimension
// surfaces.
func deriveFeatures(agg *bucketAggregate, fs observe.FlowStats, minSamples int) baseline.Features {
	f := baseline.Features{
		IdentityNovelty:  novelty(agg.Identity[hashIdentity(fs)]),
		AdjacencyNovelty: novelty(agg.Adjacency[hashAdjacency(fs)]),
		PortNovelty:      novelty(agg.PortProto[hashPort(fs)]),
	}
	f.VolumeDeviation = math.Max(
		contContribution(&agg.LogBytes, log1p(float64(fs.TotalBytes())), minSamples),
		contContribution(&agg.LogPkts, log1p(float64(fs.TotalPackets())), minSamples),
	)
	f.CadenceDeviation = math.Max(
		contContribution(&agg.LogIAT, log1p(meanInterArrivalNs(fs)), minSamples),
		contContribution(&agg.LogDur, log1p(float64(fs.DurationNs())), minSamples),
	)
	return f
}

// FeaturesMap converts a derived feature vector into the named map the
// intelligence EventStore records. It is rule-9 clean by construction: only
// derived [0,1] deviations, never raw traffic, addresses, or decoy content.
func FeaturesMap(f baseline.Features) map[string]float64 {
	return map[string]float64{
		"adjacency_novelty": f.AdjacencyNovelty,
		"identity_novelty":  f.IdentityNovelty,
		"port_novelty":      f.PortNovelty,
		"volume_deviation":  f.VolumeDeviation,
		"cadence_deviation": f.CadenceDeviation,
		// D5 sharpening signal (0 in Phase 1). Persisted so an event's stored
		// Features round-trip the value and the dashboard's M reconstruction
		// matches the engine once Phase 2 sets the match non-zero.
		"fingerprint_match": f.FingerprintMatch,
	}
}

func log1p(x float64) float64 {
	if x < 0 {
		x = 0
	}
	return math.Log1p(x)
}

// meanInterArrivalNs estimates the mean packet inter-arrival for a flow: its
// observed duration spread over its packet gaps. A flow with one packet has no
// gap and contributes 0 (neutral).
func meanInterArrivalNs(fs observe.FlowStats) float64 {
	pkts := fs.TotalPackets()
	if pkts < 2 {
		return 0
	}
	return float64(fs.DurationNs()) / float64(pkts-1)
}

// --- canonical identity / adjacency / port hashing -------------------------
//
// The same canonicalization must be reachable from a kernel-observed FlowStats
// AND from an operator-declared IP string (the staged ground-truth registry), so
// the malicious-exclusion set and the identity-novelty count agree on what "the
// same source identity" means. We canonicalize to (family, raw-address-bytes):
// IPv4 → AFInet + 4 bytes, IPv6 → AFInet6 + 16 bytes. This matches how the eBPF
// program writes the address (v4 in the first four bytes, not v4-mapped) and how
// netip.Addr.Is4 distinguishes a v4 address — so a v4 source hashes identically
// whichever side computes it.
//
// Only the FNV hash is ever persisted or counted; the raw address never is
// (CLAUDE.md rule 9).

func hashIdentity(fs observe.FlowStats) uint64 {
	h := fnv.New64a()
	writeAddr(h, fs.Family, fs.SrcIP)
	return h.Sum64()
}

func hashAdjacency(fs observe.FlowStats) uint64 {
	h := fnv.New64a()
	writeAddr(h, fs.Family, fs.SrcIP) // initiator
	writeAddr(h, fs.Family, fs.DstIP) // reached workload
	writePort(h, fs.DstPort)
	return h.Sum64()
}

func hashPort(fs observe.FlowStats) uint64 {
	h := fnv.New64a()
	var fam [2]byte
	binary.BigEndian.PutUint16(fam[:], fs.Family)
	h.Write(fam[:])
	writePort(h, fs.DstPort)
	return h.Sum64()
}

func writeAddr(h interface{ Write([]byte) (int, error) }, family uint16, ip [16]byte) {
	var fam [2]byte
	binary.BigEndian.PutUint16(fam[:], family)
	_, _ = h.Write(fam[:])
	if family == observe.AFInet {
		_, _ = h.Write(ip[0:4])
	} else {
		_, _ = h.Write(ip[0:16])
	}
}

func writePort(h interface{ Write([]byte) (int, error) }, port uint16) {
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	_, _ = h.Write(p[:])
}

// hashAddrCanonical hashes an operator-declared address with the SAME scheme the
// observe path uses, so a declared attacker IP excludes its kernel-observed
// flows from the baseline-of-normal. It is the bridge between the staged
// ground-truth registry (IP strings) and the FlowStats identity hash.
func hashAddrCanonical(a netip.Addr) uint64 {
	var ip [16]byte
	var family uint16
	if a.Is4() {
		b := a.As4()
		copy(ip[0:4], b[:])
		family = observe.AFInet
	} else {
		b := a.As16()
		copy(ip[0:16], b[:])
		family = observe.AFInet6
	}
	h := fnv.New64a()
	writeAddr(h, family, ip)
	return h.Sum64()
}
