package observebaseline

import (
	"bytes"
	"encoding/gob"
	"math"

	"github.com/canarysting/canarysting/bpf/observe"
)

// freqCapDefault bounds each frequency map's cardinality so a high-cardinality
// scan (an attacker sweeping ports or spoofing source addresses) cannot blow up
// memory. When full, the lowest-count entry is evicted — keeping the frequent,
// normal values and discarding rare ones. An evicted value, looked up later,
// reads count 0 → novelty 1.0, which correctly flags a rare value as novel.
const freqCapDefault = 4096

// bucketAggregate is the per-(scope, time-bucket) baseline summary. It holds NO
// raw flows and NO raw addresses — only FNV-hashed value counts and bounded
// distribution summaries — so it is compact, gob-persistable, and rule-9 clean
// (nothing here could identify an environment if it somehow leaked). All fields
// are exported solely for gob; treat the type as package-private.
type bucketAggregate struct {
	// Frequency of each hashed value, capped. The novelty features read these.
	Adjacency map[uint64]uint32 // hashed (srcIP, dstIP, dstPort)
	Identity  map[uint64]uint32 // hashed source IP (the initiator)
	PortProto map[uint64]uint32 // hashed (family, dstPort)

	// Robust distribution summaries (log space) for the continuous features.
	LogBytes p2Quantile
	LogPkts  p2Quantile
	LogIAT   p2Quantile // mean inter-arrival
	LogDur   p2Quantile // flow duration

	// Sufficiency bookkeeping.
	Flows uint64          // completed flows folded into this bucket
	Days  map[string]bool // distinct calendar days (UTC YYYY-MM-DD) with data
}

func newBucketAggregate() *bucketAggregate {
	return &bucketAggregate{
		Adjacency: map[uint64]uint32{},
		Identity:  map[uint64]uint32{},
		PortProto: map[uint64]uint32{},
		Days:      map[string]bool{},
	}
}

// foldFlow folds one COMPLETED flow into the aggregate as a single sample. The
// aggregator folds a flow exactly once (when it observes the flow has ended), so
// a long-lived flow read on many ticks is never double-counted — the idempotent-
// folding requirement (docs/BASELINE_MULTIPLIER.md, M7 risk register).
func (a *bucketAggregate) foldFlow(fs observe.FlowStats, day string) {
	bumpCapped(a.Identity, hashIdentity(fs), freqCapDefault)
	bumpCapped(a.Adjacency, hashAdjacency(fs), freqCapDefault)
	bumpCapped(a.PortProto, hashPort(fs), freqCapDefault)
	a.LogBytes.Add(log1p(float64(fs.TotalBytes())))
	a.LogPkts.Add(log1p(float64(fs.TotalPackets())))
	a.LogIAT.Add(log1p(meanInterArrivalNs(fs)))
	a.LogDur.Add(log1p(float64(fs.DurationNs())))
	a.Flows++
	if day != "" {
		a.Days[day] = true
	}
}

// distinctIdentities reports how many distinct source identities have been seen
// in this bucket — used to require that a baseline reflects a population of
// callers, not one chatty source.
func (a *bucketAggregate) distinctIdentities() int { return len(a.Identity) }

// bumpCapped increments m[key], evicting the lowest-count entry first if the map
// is at cap and key is new.
func bumpCapped(m map[uint64]uint32, key uint64, cap int) {
	if _, ok := m[key]; ok {
		m[key]++
		return
	}
	if len(m) >= cap {
		var evictK uint64
		var evictV uint32 = math.MaxUint32
		for k, v := range m {
			if v < evictV {
				evictK, evictV = k, v
			}
		}
		delete(m, evictK)
	}
	m[key] = 1
}

// encode gob-serializes the aggregate for durable storage.
func (a *bucketAggregate) encode() ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(a); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeAggregate restores an aggregate from its gob blob, ensuring all maps are
// non-nil so a decoded value is immediately foldable.
func decodeAggregate(blob []byte) (*bucketAggregate, error) {
	a := &bucketAggregate{}
	if err := gob.NewDecoder(bytes.NewReader(blob)).Decode(a); err != nil {
		return nil, err
	}
	if a.Adjacency == nil {
		a.Adjacency = map[uint64]uint32{}
	}
	if a.Identity == nil {
		a.Identity = map[uint64]uint32{}
	}
	if a.PortProto == nil {
		a.PortProto = map[uint64]uint32{}
	}
	if a.Days == nil {
		a.Days = map[string]bool{}
	}
	return a, nil
}
