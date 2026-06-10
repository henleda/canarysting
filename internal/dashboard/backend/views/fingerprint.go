package views

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"

	"github.com/canarysting/canarysting/internal/intelligence"
)

// FlowFingerprint is the adversary behavioral fingerprint for one flow. It shows
// only what the stored events can support: the canary probe sequence, real
// inter-arrival cadence, the strongest novelty features, and whether the flow
// persisted through the tarpit. Hash is a DETERMINISTIC fnv-64a over
// (flowID|join(orderedTypes)) — no time, no random — so the same actor probing
// the same sequence on a different day gets the same fingerprint identity.
type FlowFingerprint struct {
	FlowID         uint64   `json:"flow_id"`
	FlowIDHex      string   `json:"flow_id_hex"`     // "0x%x" — deep-link with THIS, not flow_id (uint64 > 2^53 loses precision as a JS number)
	OrderedTypes   []string `json:"ordered_types"`   // CanaryType sequence in timestamp order (with dupes)
	CadenceSec     float64  `json:"cadence_sec"`     // median inter-arrival; 0 if < 2 events
	CadenceJitter  float64  `json:"cadence_jitter"`  // MAD of inter-arrivals; 0 if < 3 events
	AdjacencyNov   float64  `json:"adjacency_nov"`   // max adjacency_novelty across events
	IdentityNov    float64  `json:"identity_nov"`    // max identity_novelty across events
	PersistsTarpit bool     `json:"persists_tarpit"` // any event with Sting.TimeHeldSec > threshold
	Hash           string   `json:"hash"`            // "fp:%04x·%04x·%04x"
}

// DeriveFingerprint builds a stable fingerprint from a flow's events. Returns
// nil for no events. Deterministic: same events => same Hash.
func DeriveFingerprint(flowID uint64, events []intelligence.AdversaryInteractionEvent) *FlowFingerprint {
	if len(events) == 0 {
		return nil
	}
	ordered := append([]intelligence.AdversaryInteractionEvent(nil), events...)
	// Sort by timestamp, then by CanaryType as a secondary key. The secondary key
	// makes the order — and therefore the hash — fully deterministic even when two
	// events share an identical timestamp (without it, equal-timestamp events keep
	// input order and the hash would depend on how the events arrived).
	sort.SliceStable(ordered, func(i, j int) bool {
		if !ordered[i].Timestamp.Equal(ordered[j].Timestamp) {
			return ordered[i].Timestamp.Before(ordered[j].Timestamp)
		}
		return ordered[i].CanaryType < ordered[j].CanaryType
	})

	orderedTypes := make([]string, 0, len(ordered))
	var adjNov, idNov float64
	persists := false
	for _, e := range ordered {
		// Skip events with no canary type (consistency with buildFlowView, which
		// filters empties): an empty string would pollute the ordered sequence and
		// the hash without naming a real probe.
		if e.CanaryType != "" {
			orderedTypes = append(orderedTypes, e.CanaryType)
		}
		if v := e.Features[featAdjacency]; v > adjNov {
			adjNov = v
		}
		if v := e.Features[featIdentity]; v > idNov {
			idNov = v
		}
		if e.Sting.TimeHeldSec > tarpitPersistSec {
			persists = true
		}
	}

	var gaps []float64
	for i := 1; i < len(ordered); i++ {
		gaps = append(gaps, ordered[i].Timestamp.Sub(ordered[i-1].Timestamp).Seconds())
	}
	cadence := median(gaps)
	var jitter float64
	if len(gaps) >= 2 {
		jitter = mad(gaps)
	}

	return &FlowFingerprint{
		FlowID:         flowID,
		FlowIDHex:      fmt.Sprintf("0x%x", flowID),
		OrderedTypes:   orderedTypes,
		CadenceSec:     cadence,
		CadenceJitter:  jitter,
		AdjacencyNov:   adjNov,
		IdentityNov:    idNov,
		PersistsTarpit: persists,
		Hash:           fingerprintHash(flowID, orderedTypes),
	}
}

// fingerprintHash is a deterministic fnv-64a hash of the canonical
// (flowID|join(orderedTypes)) string. It intentionally renders only the LOW 48
// bits of the 64-bit digest as three 4-hex groups ("fp:xxxx·xxxx·xxxx") to match
// the prototype's fingerprint format; the top 16 bits are not emitted. The full
// 64-bit value is still computed, so two distinct sequences are extremely
// unlikely to collide within the displayed 48 bits.
func fingerprintHash(flowID uint64, orderedTypes []string) string {
	input := fmt.Sprintf("%d|%s", flowID, strings.Join(orderedTypes, ","))
	h := fnv.New64a()
	_, _ = h.Write([]byte(input))
	v := h.Sum64()
	a := (v >> 32) & 0xFFFF
	b := (v >> 16) & 0xFFFF
	c := v & 0xFFFF
	return fmt.Sprintf("fp:%04x·%04x·%04x", a, b, c)
}

// median returns the median of xs (0 for empty/single-element-aware callers).
func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2]
	}
	return (cp[n/2-1] + cp[n/2]) / 2
}

// mad is the median absolute deviation from the median.
func mad(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := median(xs)
	dev := make([]float64, len(xs))
	for i, x := range xs {
		dev[i] = math.Abs(x - m)
	}
	return median(dev)
}
