package attrition

import "time"

// Budget bounds a SINGLE flow's attrition so the sting burns the attacker, not
// the defender. Every generator and the stream respect it. The host-wide ceiling
// and the concurrent-stream cap are NOT here — they belong on the shared Governor,
// because a per-flow value type cannot enforce a host-wide invariant.
//
// A zero/negative field is never "unbounded": Normalized() floors it to the
// documented conservative default. A misconfiguration can remove aggressiveness
// but can never remove a bound.
type Budget struct {
	MaxBytesPerFlow int64         // total real bytes served to one flow
	MaxDepth        int           // maze / nested-structure depth cap (iterative, never recursion)
	MaxDuration     time.Duration // wall-time a flow may be held (imposed-delay bound)
}

// Documented defaults. These are inputs, not hidden constants; config/ carries
// operator overrides and these match config/canarysting.example.yaml.
const (
	DefaultMaxBytesPerFlow    int64         = 5 << 20           // 5 MiB per flow
	DefaultMaxDepth           int           = 8                 // maze/nesting depth
	DefaultMaxDuration        time.Duration = 120 * time.Second // 2 min held per flow
	DefaultGlobalCeiling      int64         = 500 << 20         // 500 MiB host-wide (Governor)
	DefaultMaxConcurrentFlows int           = 1024              // concurrent-stream cap (Governor)
)

// DefaultBudget returns the documented conservative per-flow budget.
func DefaultBudget() Budget {
	return Budget{
		MaxBytesPerFlow: DefaultMaxBytesPerFlow,
		MaxDepth:        DefaultMaxDepth,
		MaxDuration:     DefaultMaxDuration,
	}
}

// Normalized floors every zero/negative field to its documented default — a
// missing bound is the conservative cap, never infinity.
func (b Budget) Normalized() Budget {
	if b.MaxBytesPerFlow <= 0 {
		b.MaxBytesPerFlow = DefaultMaxBytesPerFlow
	}
	if b.MaxDepth <= 0 {
		b.MaxDepth = DefaultMaxDepth
	}
	if b.MaxDuration <= 0 {
		b.MaxDuration = DefaultMaxDuration
	}
	return b
}

// DripParams shapes the slow-drip pacing every generator streams over. Delay is
// returned to the driver as data (Chunk.Delay); attrition itself never sleeps.
// The min bounds the floor so a drip always imposes cost; the max stays under the
// crawler-disconnect timeout so the attacker stays trapped, not released.
type DripParams struct {
	ChunkBytes int           // tarpit per-chunk byte count
	MinDelay   time.Duration // never 0 (an unpaced drip imposes no cost)
	MaxDelay   time.Duration // stays under the ~60s crawler-disconnect timeout
}

// Documented drip defaults.
const (
	DefaultDripChunkBytes               = 64
	DefaultDripMinDelay   time.Duration = 2 * time.Second
	DefaultDripMaxDelay   time.Duration = 45 * time.Second
)

// DefaultDrip returns the documented conservative drip pacing.
func DefaultDrip() DripParams {
	return DripParams{ChunkBytes: DefaultDripChunkBytes, MinDelay: DefaultDripMinDelay, MaxDelay: DefaultDripMaxDelay}
}

// Normalized floors zero/negative fields to defaults, caps ChunkBytes at the
// per-chunk hard cap, and guarantees MaxDelay >= MinDelay. A 0/negative drip can
// never become a no-cost (0-delay) or unbounded drip.
func (d DripParams) Normalized() DripParams {
	if d.ChunkBytes <= 0 {
		d.ChunkBytes = DefaultDripChunkBytes
	}
	if d.ChunkBytes > maxChunkBytes {
		d.ChunkBytes = maxChunkBytes
	}
	if d.MinDelay <= 0 {
		d.MinDelay = DefaultDripMinDelay
	}
	if d.MaxDelay <= 0 {
		d.MaxDelay = DefaultDripMaxDelay
	}
	if d.MaxDelay < d.MinDelay {
		d.MaxDelay = d.MinDelay
	}
	return d
}
