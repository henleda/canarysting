// The attrition generators. Each turns a tiny, fixed-size per-flow cursor into an
// endless-looking but provably-bounded stream of deception, returning a Delay the
// DRIVER waits (attrition never sleeps). Every generator is:
//   - O(1) time and space per chunk: one deterministic mix/hash + a bounded fill,
//     no stored tree, no growing cache — so the defender's cost stays flat while
//     the attacker's climbs.
//   - iteratively depth-bounded: depth is an explicit counter capped at MaxDepth
//     and reset, never recursion — so a generator can never become its own
//     billion-laughs/zip-bomb victim.
//   - provably harmless: every emitted chunk passes harmless.CrossScan (no live
//     secret, no routable host), proven over samples at construction.
//
// Determinism is keyed by the per-flow seed (derived from the socket cookie), so
// the same flow re-fetching the same maze path gets identical bytes (defeats
// crawler dedup) while different flows get different content. See docs/STING.md.
package attrition

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/harmless"
	"github.com/canarysting/canarysting/internal/harmless/decoy"
)

// stingMarker is a non-secret correlation marker embedded in attrition output. It
// is DISTINCT from the canary marker so an adapter never mistakes a maze page for
// a placed canary. It is a label, not the harmlessness guarantee.
const stingMarker = "CSTING-STING-"

// Per-chunk and per-structure bounds. maxChunkBytes is the universal per-chunk
// hard cap (a defensive backstop the construction self-test enforces); each
// generator self-limits well below it.
const (
	maxChunkBytes       = 16 << 10 // 16 KiB universal per-chunk cap
	mazePageCap         = 4 << 10  // 4 KiB per maze page
	baitBlobCap         = 8 << 10  // 8 KiB per token-bait blob
	mazeFanOut          = 12       // child links per maze page
	constructionSamples = 32       // sampled flows per generator at construction
	selfTestIters       = 256      // chunks pulled per sampled flow in the self-test
)

const (
	lowerAlnum  = "abcdefghijklmnopqrstuvwxyz0123456789"
	upperAlnum  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	base32Alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	secretAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+"
)

// genParams are the bounding inputs a generator needs. The per-flow byte budget
// and the host-wide ceiling are enforced by the stream, not the generator; a
// generator self-limits only its per-chunk size and its iterative depth.
type genParams struct {
	MaxDepth int
	Drip     DripParams
}

// cursor is the per-flow generation state: counter-only and fixed-size, so the
// defender holds O(1) memory per flow no matter how deep or long the attacker
// walks. There is no stored tree and no cache.
type cursor struct {
	seed        uint64
	chunkIdx    int
	depth       int
	poisonStage int // AX2: poison_field's stage counter (its own, so rotation with fakeMaze/tokenBait doesn't clobber depth). Fixed-size; never a stored slice.
}

// generator produces a bounded, harmless deception stream. Implementations are
// pure functions of the cursor + params: no I/O, no sleep, no unbounded recursion.
type generator interface {
	mechanism() string
	// axis reports which attrition axis(es) this generator imposes — a bitset,
	// since one generator can land on more than one (fake_tree is BOTH information
	// poisoning and opportunity cost). The Attritor unions the active set's axes
	// into Outcome.Axes; the per-axis cost rollup reads that bitset.
	axis() contract.AttritionAxis
	// minTier is the lowest engine tier at which this generator may run. The
	// gentler axes (velocity, information poisoning) act from TierContain; the
	// dedicated opportunity-cost / exploit / exposure generators gate at TierJail.
	minTier() contract.Tier
	// next advances the cursor and returns the next chunk plus the delay the
	// driver should wait before pulling again. ok=false signals the generator's
	// natural bounded end (the tarpit/maze/bait are "endless", so they return true
	// and the stream bounds them by bytes/duration/ceiling).
	next(cur *cursor, p genParams) (data []byte, delay time.Duration, ok bool)
	// selfTest proves boundedness + harmlessness over sampled flows; New refuses
	// to construct an attritor whose generator fails it.
	selfTest(samples int, p genParams) error
}

// --- deterministic mixing (no global state; no time/random, which the harness
// forbids and which would break reproducibility) ---

// mix is a splitmix64-style deterministic mixer.
func mix(a, b uint64) uint64 {
	x := a + 0x9e3779b97f4a7c15 + (b << 6) + (b >> 2)
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func hashPath(seed uint64, path string) uint64 {
	h := fnv.New64a()
	var sb [8]byte
	binary.LittleEndian.PutUint64(sb[:], seed)
	_, _ = h.Write(sb[:])
	_, _ = h.Write([]byte(path))
	return h.Sum64()
}

func randToken(h uint64, n int, alphabet string) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		h = mix(h, uint64(i))
		b.WriteByte(alphabet[h%uint64(len(alphabet))])
	}
	return b.String()
}

func stingMarkerToken(h uint64) string { return stingMarker + randToken(h, 12, base32Alpha) }

// ramp is the AX1 linear escalation of the delay floor at a given persistence:
// 0 at persist<=0, the full span at persist>=saturate, linear in between. Pure,
// O(1), and division-safe (saturate is normalized positive by DripParams, and
// re-guarded here). The multiply runs only for 0<persist<saturate — a small bound —
// so it cannot overflow int64 for any real drip span.
func ramp(persist, saturate int, span time.Duration) time.Duration {
	if persist <= 0 || span <= 0 {
		return 0
	}
	if saturate <= 0 {
		saturate = DefaultRampSaturate
	}
	if persist >= saturate {
		return span
	}
	return time.Duration(int64(span) * int64(persist) / int64(saturate))
}

// adaptiveDelay returns the AX1 escalating drip delay. The FLOOR ramps from
// MinDelay toward MaxDelay as persistence (the per-flow chunk count) grows, then
// jitters deterministically within [floor, MaxDelay] — so a persistent flow is
// punished with monotonically rising latency (velocity disruption; the cost is
// wall-clock time, which lands whoever owns the GPU) while early chunks keep the
// original band. Delay is DATA: the driver waits it; attrition never sleeps. At
// persist<=0 it is byte-identical to the pre-AX1 fixed-band drip.
func adaptiveDelay(seed uint64, idx int, d DripParams, persist int) time.Duration {
	span := d.MaxDelay - d.MinDelay
	if span <= 0 {
		return d.MinDelay
	}
	floor := d.MinDelay + ramp(persist, d.RampSaturate, span)
	if floor > d.MaxDelay {
		floor = d.MaxDelay // ramp caps at span, so this is defensive
	}
	jitterSpan := d.MaxDelay - floor
	if jitterSpan <= 0 {
		return floor
	}
	h := mix(seed, uint64(idx)+0xd31)
	return floor + time.Duration(h%uint64(jitterSpan))
}

// truncateAtLine caps b at most cap bytes, cutting only at a newline so a chunk
// can never end on a partial line (and thus never on a partial key/host/PEM).
func truncateAtLine(b []byte, cap int) []byte {
	if len(b) <= cap {
		return b
	}
	cut := cap
	for cut > 0 && b[cut-1] != '\n' {
		cut--
	}
	return b[:cut] // empty if no newline within cap — emit nothing over a partial line
}

// --- tarpit (FloorPassive): slow-drip inert filler. Cost is DURATION. ---

type tarpit struct{}

func (tarpit) mechanism() string            { return MechTarpit }
func (tarpit) axis() contract.AttritionAxis { return contract.AxisVelocity }
func (tarpit) minTier() contract.Tier       { return contract.TierContain }

func (tarpit) next(cur *cursor, p genParams) ([]byte, time.Duration, bool) {
	data := fillerChunk(cur.seed, cur.chunkIdx, p.Drip.ChunkBytes)
	delay := adaptiveDelay(cur.seed, cur.chunkIdx, p.Drip, cur.chunkIdx)
	cur.chunkIdx++
	return data, delay, true
}

func (g tarpit) selfTest(samples int, p genParams) error { return genSelfTest(g, samples, p) }

// fillerChunk produces ~n bytes of marker-tagged, ASCII-only inert filler. ASCII
// only (lowercase padding) so it can never form a URL (scheme://) or an uppercase
// AKIA key id — harmless.CrossScan passes by construction.
func fillerChunk(seed uint64, idx, n int) []byte {
	if n <= 0 {
		n = DefaultDripChunkBytes
	}
	h := mix(seed, uint64(idx))
	b := []byte(fmt.Sprintf("# %s scanning segment %d ...\n", stingMarkerToken(h), idx))
	for len(b) < n {
		h = mix(h, uint64(len(b)))
		b = append(b, byte('a'+h%26))
	}
	if len(b) > n {
		b = b[:n]
	}
	return b
}

// --- fake_tree (FloorModerate): deterministic link-back directory/config maze ---

type fakeMaze struct{}

func (fakeMaze) mechanism() string            { return MechFakeTree }
func (fakeMaze) axis() contract.AttritionAxis { return contract.AxisPoison | contract.AxisOppCost }
func (fakeMaze) minTier() contract.Tier       { return contract.TierContain }

func (fakeMaze) next(cur *cursor, p genParams) ([]byte, time.Duration, bool) {
	path := mazePathFor(cur.seed, cur.depth, cur.chunkIdx)
	data := mazeNode(cur.seed, path)
	delay := adaptiveDelay(cur.seed, cur.chunkIdx, p.Drip, cur.chunkIdx)
	cur.depth++
	if cur.depth > p.MaxDepth {
		cur.depth = 0 // endless to the crawler, bounded to us
	}
	cur.chunkIdx++
	return data, delay, true
}

func (g fakeMaze) selfTest(samples int, p genParams) error { return genSelfTest(g, samples, p) }

func mazePathFor(seed uint64, depth, idx int) string {
	var b strings.Builder
	h := mix(seed, uint64(idx))
	for i := 0; i <= depth; i++ {
		h = mix(h, uint64(i))
		b.WriteByte('/')
		b.WriteString(randToken(h, 8, lowerAlnum))
	}
	return b.String()
}

// mazeNode renders one fake directory page as a pure function of (seed, path):
// same seed+path => identical bytes (idempotent, defeats crawler dedup), different
// seed => different content. The page lists fan-out child links (relative paths,
// not URLs) and a plausible inert .env leaf drawn from reserved/EXAMPLE namespaces.
// Bounded at mazePageCap.
func mazeNode(seed uint64, path string) []byte {
	h := hashPath(seed, path)
	var b strings.Builder
	fmt.Fprintf(&b, "# %s listing of %s\n", stingMarkerToken(h), path)
	for i := 0; i < mazeFanOut; i++ {
		ch := mix(h, uint64(i))
		fmt.Fprintf(&b, "drwxr-xr-x  2 svc svc  4096  %s/\n", randToken(ch, 10, lowerAlnum))
	}
	b.WriteString(envLeaf(h))
	return truncateAtLine([]byte(b.String()), mazePageCap)
}

// envLeaf is a plausible-but-inert .env: EXAMPLE-namespace AWS credentials (which
// authenticate to nothing) and a reserved-domain database URL (which routes
// nowhere). Passes harmless.CrossScan by construction.
func envLeaf(h uint64) string {
	return fmt.Sprintf(
		"-rw-------  1 svc svc   512  .env\nAWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nDATABASE_URL=postgres://svc:decoy@db.payments.example:5432/payments\n# %s\n",
		decoy.ExampleAWSKeyID(h), decoy.ExampleAWSSecret(mix(h, 1)), stingMarkerToken(mix(h, 2)))
}

// --- token_bait (FloorAggressive): token-maximizing, parser-hostile bait ---
//
// The patent-flagged differentiator. It emits content that is cheap for us to
// write (bytes) but expensive for an LLM/automated parser to consume (tokens /
// parse work): dense multi-byte Unicode runs that force tokenizer byte-fallback,
// zero-width separators that break BPE merges, and a bounded-depth nested JSON
// structure that looks like plausible config but is parse-expensive. It is
// DEFENSIVE decoy text only — never prompt-injection, never a routable beacon
// (docs/STING.md "not hack-back"). FTO framing: see docs/AI_BAIT.md; the novelty
// is isolated behind this generator and the FloorAggressive gate so the patent is
// framed around the integrated, bounded, attributed system.

type tokenBait struct{}

func (tokenBait) mechanism() string            { return MechTokenBait }
func (tokenBait) axis() contract.AttritionAxis { return contract.AxisOppCost }
func (tokenBait) minTier() contract.Tier       { return contract.TierJail }

func (tokenBait) next(cur *cursor, p genParams) ([]byte, time.Duration, bool) {
	data := baitBlob(cur.seed, cur.chunkIdx, cur.depth, p.MaxDepth)
	delay := adaptiveDelay(cur.seed, cur.chunkIdx, p.Drip, cur.chunkIdx)
	cur.depth++
	if cur.depth > p.MaxDepth {
		cur.depth = 0
	}
	cur.chunkIdx++
	return data, delay, true
}

func (g tokenBait) selfTest(samples int, p genParams) error { return genSelfTest(g, samples, p) }

// baitRunes is a fixed adversarial alphabet of multi-byte runes (2-, 3-, and
// 4-byte UTF-8) selected to inflate token counts via byte-fallback.
var baitRunes = []rune("文字化けをぐめゐゑ한글ыؤœ𐍈𐎀😀🜔")

const baitRuneRun = 192

func baitBlob(seed uint64, idx, depth, maxDepth int) []byte {
	h := mix(seed, uint64(idx)*1000003+uint64(depth))
	var b strings.Builder
	b.WriteString("# " + stingMarkerToken(h) + "\n")
	// Dense multi-byte run with merge-breaking zero-width separators.
	for i := 0; i < baitRuneRun; i++ {
		h = mix(h, uint64(i))
		b.WriteRune(baitRunes[h%uint64(len(baitRunes))])
		if i%3 == 2 {
			b.WriteRune('​') // zero-width space breaks BPE merges
		}
	}
	b.WriteByte('\n')
	// Bounded-depth nested JSON, built ITERATIVELY (never recursion). Depth is
	// hard-capped at MaxDepth so we never blow our own stack/heap.
	d := depth
	if d > maxDepth {
		d = maxDepth
	}
	if d < 1 {
		d = 1
	}
	for i := 0; i < d; i++ {
		fmt.Fprintf(&b, "{\"k%d\":", i)
	}
	b.WriteString("\"" + randToken(mix(h, 7), 16, lowerAlnum) + "\"")
	for i := 0; i < d; i++ {
		b.WriteByte('}')
	}
	b.WriteByte('\n')
	return truncateAtLine([]byte(b.String()), baitBlobCap)
}

// --- poison_field (FloorModerate): a single internally-consistent fabricated
// environment. AX2 — information poisoning, the core differentiator. ---
//
// Distinct from fake_tree (an endless directory MAZE): poison_field serves a small,
// FIXED set of pages — a credential set, a service inventory/topology, and a
// "successful" result — that all reference the SAME fabricated reserved hosts, so
// the environment is INTERNALLY CONSISTENT under inspection (re-fetching any page is
// idempotent and agrees with the others). The cost is not compute; it is that an
// autonomous agent acts on bad intelligence. The host set is RECOMPUTED from the
// seed every chunk (NEVER stored — the cursor stays fixed-size), and the stage
// counter loops, so it is "endless" and budget/hold-bounded like the other
// generators. (It loops rather than self-ending on purpose: under the rotated stream
// a single generator returning ok=false would end the WHOLE stream and cut off the
// other axes; re-serving the consistent environment is itself plausible-under-
// inspection. See docs/ATTRITION_FIVE_AXIS_DESIGN.md §4.)

type poisonField struct{}

func (poisonField) mechanism() string            { return MechPoison }
func (poisonField) axis() contract.AttritionAxis { return contract.AxisPoison }
func (poisonField) minTier() contract.Tier       { return contract.TierContain }

func (poisonField) next(cur *cursor, p genParams) ([]byte, time.Duration, bool) {
	data := poisonPage(cur.seed, cur.poisonStage%len(poisonClasses))
	delay := adaptiveDelay(cur.seed, cur.chunkIdx, p.Drip, cur.chunkIdx)
	cur.poisonStage++
	cur.chunkIdx++
	return data, delay, true
}

func (g poisonField) selfTest(samples int, p genParams) error { return genSelfTest(g, samples, p) }

// poisonClasses names the stages of the fabricated environment, in walk order. The
// reached index is carried out as Outcome.PoisonClass / PoisonReached — how far into
// the deception the actor walked (a D2 reaction signal, NOT time-to-disengage).
var poisonClasses = [...]string{"credential", "topology", "success"}

// poisonClassForStage maps the deepest stage REACHED (a 1-based count of stages
// walked) to its class label; "" when no poison page was served.
func poisonClassForStage(reached int) string {
	if reached <= 0 {
		return ""
	}
	if reached > len(poisonClasses) {
		reached = len(poisonClasses)
	}
	return poisonClasses[reached-1]
}

// poisonPage renders ONE page of the fabricated environment for a stage, as a pure
// function of (seed, stage). Every page references the SAME three fabricated hosts
// (recomputed here, never stored), all under RFC-reserved domains, with
// EXAMPLE-namespace credentials — so it is provably harmless (harmless.CrossScan,
// proven at construction) yet internally consistent across stages. Bounded at
// mazePageCap.
func poisonPage(seed uint64, stage int) []byte {
	h0 := decoy.ReservedHost(mix(seed, 0))
	h1 := decoy.ReservedHost(mix(seed, 1))
	h2 := decoy.ReservedHost(mix(seed, 2))
	mk := stingMarkerToken(mix(seed, uint64(100+stage)))
	var b strings.Builder
	switch stage {
	case 0: // credential set referencing the same hosts
		fmt.Fprintf(&b, "# %s service credentials\n[default]\n", mk)
		fmt.Fprintf(&b, "aws_access_key_id = %s\naws_secret_access_key = %s\n", decoy.ExampleAWSKeyID(mix(seed, 3)), decoy.ExampleAWSSecret(mix(seed, 4)))
		fmt.Fprintf(&b, "db_primary = postgres://svc:decoy@%s:5432/payments\n", h0)
		fmt.Fprintf(&b, "session_cache = redis://%s:6379\n", h1)
	case 1: // topology / inventory listing the SAME hosts
		fmt.Fprintf(&b, "# %s service inventory\n", mk)
		fmt.Fprintf(&b, "payments-db    %s    role=primary\n", h0)
		fmt.Fprintf(&b, "session-cache  %s    role=cache\n", h1)
		fmt.Fprintf(&b, "internal-api   %s    role=gateway\n", h2)
	default: // a fake "successful" result referencing the same environment
		fmt.Fprintf(&b, "# %s\n{\"status\":\"ok\",\"authenticated\":true,\"primary\":\"%s\",\"records\":4821}\n", mk, h0)
	}
	return truncateAtLine([]byte(b.String()), mazePageCap)
}

// --- exploit_bait (FloorAggressive): attractive harmless decoy services that burn
// the attacker's exploit inventory. AX4 — exploit-inventory burn. ---
//
// Serves an endless-looking stream of attractive-but-INERT fake service surfaces
// (vulnerable-looking banners + enticing "exposed" endpoints + reserved-host object
// stores), so a decoy is juicy enough that an attacker spends a REAL exploit on it.
// The exploit fires at this bounded generator (it reaches nothing — no real service,
// no routable host) and, captured in-perimeter via Stream.Observe, reveals the
// attacker's tooling as Outcome.ExploitsObserved. The cost is the attacker's finite,
// non-replenishable exploit inventory + the OPSEC of burning it on a fake. NEVER fires
// back (docs/STING.md "not hack-back") — capture is passive observation inside the
// perimeter only. Bounded/harmless exactly like the others (decoy.ExploitBaitService
// is CrossScan-clean for all seeds; proven at construction). It LOOPS (ok always true),
// varying the surface per chunk, like poison_field — under the rotated stream a
// self-end would cut off the other axes. Cross-boundary use of ExploitsObserved is
// gated on the egress filter (rule 9; §6). See docs/ATTRITION_FIVE_AXIS_DESIGN.md §6.

type exploitBait struct{}

func (exploitBait) mechanism() string            { return MechExploitBait }
func (exploitBait) axis() contract.AttritionAxis { return contract.AxisExploitBurn }
func (exploitBait) minTier() contract.Tier       { return contract.TierJail }

func (exploitBait) next(cur *cursor, p genParams) ([]byte, time.Duration, bool) {
	data := exploitBaitPage(cur.seed, cur.chunkIdx)
	delay := adaptiveDelay(cur.seed, cur.chunkIdx, p.Drip, cur.chunkIdx)
	cur.chunkIdx++
	return data, delay, true
}

func (g exploitBait) selfTest(samples int, p genParams) error { return genSelfTest(g, samples, p) }

// exploitBaitPage renders one attractive fake-service surface as a pure function of
// (seed, idx), varied per chunk so the surface looks endless, tagged with the sting
// marker, and bounded at mazePageCap. All content is provably harmless (relative
// paths, reserved hosts, EXAMPLE creds) via decoy.ExploitBaitService.
func exploitBaitPage(seed uint64, idx int) []byte {
	h := mix(seed, uint64(idx))
	body := "# " + stingMarkerToken(h) + "\n" + decoy.ExploitBaitService(h) + "\n"
	return truncateAtLine([]byte(body), mazePageCap)
}

// --- op_exposure (FloorAggressive): attractive internal-operations surface whose
// passive job is to elicit the attacker's recon TOOLING fingerprint. AX5 —
// operational exposure. ---
//
// Serves an endless-looking stream of attractive-but-INERT internal-ops surfaces
// (deploy manifests, monitoring, service-mesh topology, a secrets backend), so the
// attacker keeps ENUMERATING — and in doing so reveals their tooling/C2 fingerprint
// in the SHAPE of the requests they make to us (user-agent, header set, cadence). That
// fingerprint is captured PASSIVELY, in-perimeter, via Stream.Observe ->
// Outcome.ExposureSignals — the platform NEVER dials out, beacons, or runs a callback
// sink (docs/STING.md no-hack-back; the live in-perimeter sink is DEFERRED behind the
// F4 predicate, docs/AX5_HARMLESSNESS_DESIGN.md). Bounded/harmless exactly like the
// others (decoy.OpsSurface is CrossScan-clean for all seeds; proven at construction),
// LOOPS (ok always true) like poison_field/exploit_bait. minTier=TierJail,
// FloorAggressive only.

type opExposure struct{}

func (opExposure) mechanism() string            { return MechOpExposure }
func (opExposure) axis() contract.AttritionAxis { return contract.AxisOpExposure }
func (opExposure) minTier() contract.Tier       { return contract.TierJail }

func (opExposure) next(cur *cursor, p genParams) ([]byte, time.Duration, bool) {
	data := opExposurePage(cur.seed, cur.chunkIdx)
	delay := adaptiveDelay(cur.seed, cur.chunkIdx, p.Drip, cur.chunkIdx)
	cur.chunkIdx++
	return data, delay, true
}

func (g opExposure) selfTest(samples int, p genParams) error { return genSelfTest(g, samples, p) }

// opExposurePage renders one attractive internal-ops surface as a pure function of
// (seed, idx), varied per chunk, marker-tagged, bounded at mazePageCap. Provably
// harmless (relative paths, reserved hosts, EXAMPLE creds) via decoy.OpsSurface.
func opExposurePage(seed uint64, idx int) []byte {
	h := mix(seed, uint64(idx))
	body := "# " + stingMarkerToken(h) + "\n" + decoy.OpsSurface(h) + "\n"
	return truncateAtLine([]byte(body), mazePageCap)
}

// --- shared construction self-test ---

// genSelfTest drives each generator over sampled flows and asserts every chunk is
// within the per-chunk cap, the cursor depth never exceeds MaxDepth, the delay is
// non-negative, and the emitted bytes are provably harmless. A generator that can
// violate any of these is caught at construction (New errors; Default panics) —
// the bound is a property of the binary, not a comment.
func genSelfTest(g generator, samples int, p genParams) error {
	if samples <= 0 {
		samples = constructionSamples
	}
	for s := 0; s < samples; s++ {
		cur := cursor{seed: mix(uint64(s), 0x5eed)}
		for i := 0; i < selfTestIters; i++ {
			data, delay, ok := g.next(&cur, p)
			if !ok {
				break
			}
			if cur.depth > p.MaxDepth {
				return fmt.Errorf("%s: cursor depth %d exceeds MaxDepth %d", g.mechanism(), cur.depth, p.MaxDepth)
			}
			if len(data) > maxChunkBytes {
				return fmt.Errorf("%s: chunk %d bytes exceeds per-chunk cap %d", g.mechanism(), len(data), maxChunkBytes)
			}
			if delay < 0 {
				return fmt.Errorf("%s: negative delay %s", g.mechanism(), delay)
			}
			if err := harmless.CrossScan(data); err != nil {
				return fmt.Errorf("%s: emitted bait is not provably harmless: %w", g.mechanism(), err)
			}
		}
	}
	return nil
}
