package attrition

// DoneReason discriminates WHY an attrition stream ended. The driver stops on any
// non-NotDone value; the intelligence layer (D1/D3) records the reason, so the
// three "we stopped ourselves" cases (per-flow budget, host ceiling, kill) are
// distinguished from the natural end and the never-started no-op.
type DoneReason int

const (
	NotDone           DoneReason = iota // more chunks available
	DoneNoOp                            // never started: below Tier 2, unattributable, or killed at Open
	DoneFlowBudget                      // per-flow MaxBytes/MaxDuration reached
	DoneGlobalCeiling                   // host-wide ceiling or concurrent-stream cap reached
	DoneKilled                          // kill switch tripped, or context cancelled
	DoneComplete                        // generator reached its natural bounded end / stream closed
)

func (r DoneReason) String() string {
	switch r {
	case NotDone:
		return "not_done"
	case DoneNoOp:
		return "noop"
	case DoneFlowBudget:
		return "flow_budget"
	case DoneGlobalCeiling:
		return "global_ceiling"
	case DoneKilled:
		return "killed"
	case DoneComplete:
		return "complete"
	default:
		return "unknown"
	}
}

// Stable mechanism labels. NEVER change once shipped: intelligence.StingOutcome.
// Mechanism and the D3 attacker-cost KPI aggregate by these exact strings.
const (
	MechNoOp      = "noop"
	MechTarpit    = "tarpit"
	MechFakeTree  = "fake_tree"
	MechTokenBait = "token_bait"
)

// Token-cost proxy multipliers. These are documented estimates over emitted
// bytes, never a materialized allocation (we never tokenize our own output — that
// would make us our own victim). Plain filler/maze text tokenizes at roughly
// chars/4 (ASCII); token_bait carries a higher, structurally-justified ratio
// because its multi-byte / merge-breaking content forces tokenizer byte-fallback.
// Pricing (tokens -> dollars) is D3's job; attrition emits only the raw proxy, so
// the number stays defensible and never over-claims.
const (
	plainTokenDivisor = 4.0 // ~chars/4 for plain ASCII
	baitTokenRatio    = 3.0 // conservative lower bound for byte-fallback/merge-break inflation
)

// tokenProxy estimates the attacker tokens imposed by n emitted bytes for a
// mechanism. Cheap (one float op); imposed on the attacker's LLM, never our CPU.
func tokenProxy(mechanism string, n int) float64 {
	if mechanism == MechTokenBait {
		return float64(n) * baitTokenRatio
	}
	return float64(n) / plainTokenDivisor
}

// Outcome is the running attacker-cost meter for one flow. Its cost fields
// (Mechanism, TimeHeldSec, BytesServed, RequestsAbsrb, TokenCostProxy,
// DepthReached) map onto intelligence.StingOutcome and are copied by the
// composition root WITHOUT attrition importing intelligence (dependency points
// inward). Reason is attrition-internal control flow (why the stream ended); D1
// records it as event metadata, not as part of StingOutcome. Outcome carries NO
// raw payload/decoy bytes, only structured proxies, matching the event-store "no
// raw payloads" invariant.
type Outcome struct {
	Mechanism      string     // one of the Mech* labels
	TimeHeldSec    float64    // attacker wall-time imposed (sum of Chunk.Delay)
	BytesServed    int64      // real bytes emitted (== charged against budget + ceiling)
	RequestsAbsrb  int64      // Next calls that returned data (requests absorbed)
	TokenCostProxy float64    // estimated attacker tokens imposed
	Reason         DoneReason // why the stream ended (NotDone while live)
	DepthReached   int        // deepest maze/nesting level the attacker reached (D2 reaction signal)
}
