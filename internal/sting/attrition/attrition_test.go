package attrition

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/harmless"
	"github.com/canarysting/canarysting/internal/intelligence"
)

// testBudget is a long-running budget so a test can pull many chunks without
// hitting the duration bound; individual tests override fields to exercise a bound.
func testBudget() Budget {
	return Budget{MaxBytesPerFlow: 1 << 30, MaxDepth: DefaultMaxDepth, MaxDuration: 1000 * time.Hour}
}

func fastDrip() DripParams {
	return DripParams{ChunkBytes: 64, MinDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}
}

func verdict(tier contract.Tier, cookie uint64) contract.Verdict {
	return contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: cookie}, Tier: tier}
}

// drive pulls a stream to completion (clock-free: Delay is data, never slept) and
// returns the chunk count and final outcome. It models the scripted attacker.
func drive(t *testing.T, s Stream, maxChunks int) (chunks int, out Outcome) {
	t.Helper()
	defer s.Close()
	for i := 0; i < maxChunks; i++ {
		c, done, err := s.Next(context.Background())
		if err != nil {
			t.Fatalf("Next returned error: %v", err)
		}
		if len(c.Data) > 0 {
			chunks++
		}
		if done != NotDone {
			return chunks, s.Outcome()
		}
	}
	return chunks, s.Outcome()
}

func mustNew(t *testing.T, cfg Config) *BoundedAttritor {
	t.Helper()
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return a
}

// --- gating ---

func TestOpenIsNoOpBelowTier2(t *testing.T) {
	a := mustNew(t, Config{Floor: contract.FloorAggressive, Budget: testBudget(), Drip: fastDrip()})
	for _, tier := range []contract.Tier{contract.TierObserve, contract.TierTag} {
		s := a.Open(verdict(tier, 0xC0FFEE))
		c, done, err := s.Next(context.Background())
		if err != nil {
			t.Fatalf("tier %d: unexpected error %v", tier, err)
		}
		if done != DoneNoOp {
			t.Fatalf("tier %d: expected DoneNoOp, got %v", tier, done)
		}
		if len(c.Data) != 0 {
			t.Fatalf("tier %d: attrition emitted %d bytes below Tier 2", tier, len(c.Data))
		}
		_ = s.Close()
	}
}

func TestNoOpOnUnattributableFlow(t *testing.T) {
	a := mustNew(t, Config{Floor: contract.FloorAggressive, Budget: testBudget(), Drip: fastDrip()})
	s := a.Open(verdict(contract.TierJail, 0)) // SocketCookie 0 => unattributable
	c, done, _ := s.Next(context.Background())
	if done != DoneNoOp || len(c.Data) != 0 {
		t.Fatalf("attrition acted on an unattributable flow: done=%v bytes=%d", done, len(c.Data))
	}
}

func TestOpenAtTier2BeginsAttrition(t *testing.T) {
	a := mustNew(t, Config{Budget: testBudget(), Drip: fastDrip()}) // FloorPassive
	s := a.Open(verdict(contract.TierContain, 0xABCD))
	c, done, err := s.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if done != NotDone || len(c.Data) == 0 {
		t.Fatalf("attrition did not begin at Tier 2: done=%v bytes=%d", done, len(c.Data))
	}
	if c.Delay <= 0 {
		t.Fatal("tarpit returned a non-positive delay (imposes no cost)")
	}
	_ = s.Close()
}

// --- per-flow and host bounds ---

func TestNeverExceedsPerFlowBudget(t *testing.T) {
	for _, floor := range []contract.StingFloor{contract.FloorPassive, contract.FloorModerate, contract.FloorAggressive} {
		b := testBudget()
		b.MaxBytesPerFlow = 4096 // tight byte cap, generous duration
		a := mustNew(t, Config{Floor: floor, Budget: b, Drip: fastDrip()})
		s := a.Open(verdict(contract.TierJail, 0x1111))
		_, out := drive(t, s, 1_000_000)
		if out.BytesServed > b.MaxBytesPerFlow {
			t.Fatalf("floor %d: served %d bytes > per-flow cap %d", floor, out.BytesServed, b.MaxBytesPerFlow)
		}
		if out.DepthReached > b.MaxDepth {
			t.Fatalf("floor %d: depth %d > MaxDepth %d", floor, out.DepthReached, b.MaxDepth)
		}
		if out.Reason != DoneFlowBudget {
			t.Fatalf("floor %d: expected DoneFlowBudget, got %v", floor, out.Reason)
		}
	}
}

func TestStreamTerminatesByMaxDuration(t *testing.T) {
	b := testBudget()
	b.MaxDuration = 10 * time.Second // small duration, huge byte budget
	a := mustNew(t, Config{Budget: b, Drip: DripParams{ChunkBytes: 64, MinDelay: 2 * time.Second, MaxDelay: 3 * time.Second}})
	s := a.Open(verdict(contract.TierContain, 0x2222))
	_, out := drive(t, s, 1_000_000)
	if out.TimeHeldSec < b.MaxDuration.Seconds() {
		t.Fatalf("stream ended before MaxDuration: held %.1fs < %.1fs", out.TimeHeldSec, b.MaxDuration.Seconds())
	}
	if out.BytesServed >= b.MaxBytesPerFlow {
		t.Fatalf("stream ended on bytes, not duration: served %d", out.BytesServed)
	}
	if out.Reason != DoneFlowBudget {
		t.Fatalf("stream did not terminate by the duration bound: reason=%v", out.Reason)
	}
}

func TestGlobalByteCeilingHaltsFlow(t *testing.T) {
	// Teeth: a single flow whose per-flow byte budget far exceeds the host ceiling
	// must be stopped BY the ceiling (DoneGlobalCeiling) with bytes <= ceiling.
	// (The prior multi-flow test read usedBytes only AFTER Close drained it to 0, so
	// it could not observe a ceiling breach — this one observes the rejection live.)
	const ceiling = 256 << 10
	gov := NewGovernor(ceiling, 4096)
	b := testBudget()
	b.MaxBytesPerFlow = 4 << 20 // 4 MiB per flow, 16x the host ceiling
	a := mustNew(t, Config{Floor: contract.FloorModerate, Budget: b, Drip: fastDrip(), Governor: gov})
	s := a.Open(verdict(contract.TierJail, 0xCEED))
	_, out := drive(t, s, 1_000_000)
	if out.Reason != DoneGlobalCeiling {
		t.Fatalf("flow over the host byte ceiling did not stop with DoneGlobalCeiling: %v", out.Reason)
	}
	if out.BytesServed > ceiling {
		t.Fatalf("served %d bytes over the host ceiling %d", out.BytesServed, ceiling)
	}
}

func TestGlobalCeilingHaltsAllFlows(t *testing.T) {
	const ceiling = 256 << 10 // 256 KiB host-wide
	gov := NewGovernor(ceiling, 4096)
	b := testBudget()
	b.MaxBytesPerFlow = 1 << 20 // each flow alone could exceed the ceiling
	a := mustNew(t, Config{Floor: contract.FloorModerate, Budget: b, Drip: fastDrip(), Governor: gov})

	// Sample the aggregate in-flight bytes WHILE flows run; Reserve guarantees the
	// peak never exceeds the ceiling, so this asserts the host-exhaustion backstop
	// (and fails if Reserve ever stops honoring the ceiling).
	stop := make(chan struct{})
	peakCh := make(chan int64, 1)
	go func() {
		var peak int64
		for {
			select {
			case <-stop:
				peakCh <- peak
				return
			default:
				if u, _, _ := gov.Snapshot(); u > peak {
					peak = u
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a.Open(verdict(contract.TierJail, uint64(i)+1))
			drive(t, s, 1_000_000)
		}(i)
	}
	wg.Wait()
	close(stop)
	peak := <-peakCh

	if peak > ceiling {
		t.Fatalf("aggregate in-flight bytes peaked at %d, over the host ceiling %d", peak, ceiling)
	}
	if _, active, _ := gov.Snapshot(); active != 0 {
		t.Fatalf("active streams not released after Close: %d", active)
	}
}

func TestActiveFlowCapRefusesNewStreams(t *testing.T) {
	gov := NewGovernor(DefaultGlobalCeiling, 2) // cap at 2 concurrent
	a := mustNew(t, Config{Budget: testBudget(), Drip: fastDrip(), Governor: gov})
	s1 := a.Open(verdict(contract.TierContain, 1))
	s2 := a.Open(verdict(contract.TierContain, 2))
	s3 := a.Open(verdict(contract.TierContain, 3)) // over the cap
	if _, done, _ := s3.Next(context.Background()); done != DoneGlobalCeiling {
		t.Fatalf("expected DoneGlobalCeiling at the active-flow cap, got %v", done)
	}
	_ = s1.Close() // frees a slot
	s4 := a.Open(verdict(contract.TierContain, 4))
	if _, done, _ := s4.Next(context.Background()); done != NotDone {
		t.Fatalf("a freed slot did not admit a new stream: %v", done)
	}
	_ = s2.Close()
	_ = s4.Close()
}

func TestKillSwitchStopsImmediately(t *testing.T) {
	a := mustNew(t, Config{Floor: contract.FloorModerate, Budget: testBudget(), Drip: fastDrip()})
	s := a.Open(verdict(contract.TierJail, 0x9999))
	if _, done, _ := s.Next(context.Background()); done != NotDone {
		t.Fatalf("stream should be live before kill, got %v", done)
	}
	a.Governor().Kill()
	if _, done, _ := s.Next(context.Background()); done != DoneKilled {
		t.Fatalf("kill did not stop the in-flight stream, got %v", done)
	}
	if _, done, _ := a.Open(verdict(contract.TierJail, 0x8888)).Next(context.Background()); done != DoneKilled {
		t.Fatalf("kill did not no-op a fresh Open, got %v", done)
	}
	a.Governor().Revive()
	if _, done, _ := a.Open(verdict(contract.TierJail, 0x7777)).Next(context.Background()); done != NotDone {
		t.Fatalf("Revive did not restore attrition, got %v", done)
	}
}

// --- floor / tier discipline (aggressive never silent) ---

func TestFloorIsRespected(t *testing.T) {
	cases := []struct {
		floor   contract.StingFloor
		allowed map[string]bool
	}{
		{contract.FloorPassive, map[string]bool{MechTarpit: true}},
		{contract.FloorModerate, map[string]bool{MechTarpit: true, MechFakeTree: true}},
		{contract.FloorAggressive, map[string]bool{MechTarpit: true, MechFakeTree: true, MechTokenBait: true}},
	}
	for _, tc := range cases {
		a := mustNew(t, Config{Floor: tc.floor, Budget: testBudget(), Drip: fastDrip()})
		for _, tier := range []contract.Tier{contract.TierContain, contract.TierJail} {
			for _, g := range a.selectAxes(tier) {
				if !tc.allowed[g.mechanism()] {
					t.Fatalf("floor %d tier %d ran disallowed mechanism %q", tc.floor, tier, g.mechanism())
				}
			}
		}
	}
}

func TestGeneratorSelectionTable(t *testing.T) {
	// Pins the EXACT active axis SET per (floor, tier) AND the headline mechanism
	// (the most-aggressive member — the D3 by-mechanism KPI). Under the five-axis
	// model a tier composes a SET (velocity+poison from TierContain), but a higher
	// tier must never raise the floor's ceiling, and the headline must equal the old
	// single-generator selection so the KPI stays stable: FloorAggressive Tier 2 is
	// the gentler form (fake_tree), Tier 3 the full adversarial form (token_bait).
	mechSet := func(gs []generator) map[string]bool {
		m := map[string]bool{}
		for _, g := range gs {
			m[g.mechanism()] = true
		}
		return m
	}
	for _, tc := range []struct {
		floor    contract.StingFloor
		tier     contract.Tier
		set      []string
		headline string
	}{
		{contract.FloorPassive, contract.TierContain, []string{MechTarpit}, MechTarpit},
		{contract.FloorPassive, contract.TierJail, []string{MechTarpit}, MechTarpit},
		{contract.FloorModerate, contract.TierContain, []string{MechTarpit, MechFakeTree}, MechFakeTree},
		{contract.FloorModerate, contract.TierJail, []string{MechTarpit, MechFakeTree}, MechFakeTree},
		{contract.FloorAggressive, contract.TierContain, []string{MechTarpit, MechFakeTree}, MechFakeTree},
		{contract.FloorAggressive, contract.TierJail, []string{MechTarpit, MechFakeTree, MechTokenBait}, MechTokenBait},
	} {
		a := mustNew(t, Config{Floor: tc.floor, Budget: testBudget(), Drip: fastDrip()})
		sel := a.selectAxes(tc.tier)
		got := mechSet(sel)
		if len(got) != len(tc.set) {
			t.Fatalf("floor %d tier %d: set %v, want exactly %v", tc.floor, tc.tier, got, tc.set)
		}
		for _, m := range tc.set {
			if !got[m] {
				t.Fatalf("floor %d tier %d: set %v missing %q", tc.floor, tc.tier, got, m)
			}
		}
		if h := sel[len(sel)-1].mechanism(); h != tc.headline {
			t.Fatalf("floor %d tier %d: headline %q, want %q", tc.floor, tc.tier, h, tc.headline)
		}
	}
}

func TestAggressiveIsNeverSilentDefault(t *testing.T) {
	def := mustNew(t, Config{Budget: testBudget(), Drip: fastDrip()}) // zero Floor == passive
	for _, tier := range []contract.Tier{contract.TierObserve, contract.TierTag, contract.TierContain, contract.TierJail} {
		s := def.Open(verdict(tier, 0xDEAD))
		_, out := drive(t, s, 64)
		if out.Mechanism == MechTokenBait {
			t.Fatalf("default (passive) config emitted token_bait at tier %d — aggressive went silent", tier)
		}
	}
	// Teeth: the only way to reach token_bait is explicit FloorAggressive + Tier 3.
	agg := mustNew(t, Config{Floor: contract.FloorAggressive, Budget: testBudget(), Drip: fastDrip()})
	s := agg.Open(verdict(contract.TierJail, 0xBEEF))
	_, out := drive(t, s, 4)
	if out.Mechanism != MechTokenBait {
		t.Fatalf("explicit aggressive + Tier 3 did not reach token_bait (test would be vacuous): %q", out.Mechanism)
	}
}

func TestNoTierAloneRaisesFloor(t *testing.T) {
	// At a floor below aggressive, NO tier — however high — may surface token_bait
	// (the aggressive-only generator), and every selected generator's axes must be
	// unlocked by the floor. The set is constructed per floor.Axes(), so a tier can
	// only NARROW it (by minTier), never add a higher generator.
	for _, floor := range []contract.StingFloor{contract.FloorPassive, contract.FloorModerate} {
		a := mustNew(t, Config{Floor: floor, Budget: testBudget(), Drip: fastDrip()})
		for _, tier := range []contract.Tier{contract.TierContain, contract.TierJail} {
			for _, g := range a.selectAxes(tier) {
				if g.mechanism() == MechTokenBait {
					t.Fatalf("floor %d tier %d reached token_bait — a tier raised the floor", floor, tier)
				}
				if g.axis()&floor.Axes() == 0 {
					t.Fatalf("floor %d tier %d selected %q whose axes (%05b) are not unlocked by the floor (%05b)",
						floor, tier, g.mechanism(), g.axis(), floor.Axes())
				}
			}
		}
	}
}

func TestSelectAxesComposition(t *testing.T) {
	// FloorAggressive at TierJail composes ALL three generators on one flow, so the
	// stream's Outcome.Axes unions velocity + information-poisoning + opportunity-cost
	// (an OVERLAPPING set — fake_tree carries both poison and opp-cost — never a
	// partition). FloorPassive imposes velocity only. Axes is set at Open and must
	// survive driving the rotation.
	agg := mustNew(t, Config{Floor: contract.FloorAggressive, Budget: testBudget(), Drip: fastDrip()})
	s := agg.Open(verdict(contract.TierJail, 0xA11))
	defer s.Close()
	_, out := drive(t, s, 6) // enough chunks for the rotation to visit each generator
	if want := contract.AxisVelocity | contract.AxisPoison | contract.AxisOppCost; out.Axes != want {
		t.Fatalf("aggressive+jail Outcome.Axes = %05b, want %05b (velocity|poison|oppcost)", out.Axes, want)
	}

	pas := mustNew(t, Config{Budget: testBudget(), Drip: fastDrip()}) // zero Floor == passive
	ps := pas.Open(verdict(contract.TierContain, 0xB22))
	defer ps.Close()
	_, pout := drive(t, ps, 4)
	if pout.Axes != contract.AxisVelocity {
		t.Fatalf("passive Outcome.Axes = %05b, want velocity-only %05b", pout.Axes, contract.AxisVelocity)
	}
}

func TestTokenProxyKeysOffRotatedGenerator(t *testing.T) {
	// Per-chunk TokenCostProxy must bill the CURRENTLY-ACTIVE (rotated) generator,
	// not the frozen headline Mechanism. At FloorAggressive+TierJail the set is
	// {tarpit, fakeMaze, tokenBait}; only token_bait bills at baitTokenRatio (3.0),
	// tarpit/fake_tree at the plain divisor (1/4). A regression freezing it to the
	// headline (token_bait) would bill EVERY chunk at 3.0x — a ~12x over-attribution
	// into the attacker-cost hero / D3 KPI. Bracket the accumulated proxy STRICTLY
	// between the all-plain and all-bait bounds to prove a genuine per-generator mix.
	a := mustNew(t, Config{Floor: contract.FloorAggressive, Budget: testBudget(), Drip: fastDrip()})
	s := a.Open(verdict(contract.TierJail, 0xF00D))
	_, out := drive(t, s, 90) // many chunks so the 3-way rotation is well sampled
	if out.BytesServed == 0 {
		t.Fatal("no bytes served")
	}
	allBait := float64(out.BytesServed) * baitTokenRatio
	allPlain := float64(out.BytesServed) / plainTokenDivisor
	if out.TokenCostProxy >= allBait {
		t.Fatalf("TokenCostProxy %.0f >= all-bait bound %.0f: proxy is frozen to the bait headline, not keyed per rotated generator", out.TokenCostProxy, allBait)
	}
	if out.TokenCostProxy <= allPlain {
		t.Fatalf("TokenCostProxy %.0f <= all-plain bound %.0f: the token_bait chunks are not billed at the bait ratio", out.TokenCostProxy, allPlain)
	}
}

func TestTokenBaitNotConstructedBelowAggressive(t *testing.T) {
	for _, tc := range []struct {
		floor contract.StingFloor
		gens  int
	}{
		{contract.FloorPassive, 1},
		{contract.FloorModerate, 2},
		{contract.FloorAggressive, 3},
	} {
		a := mustNew(t, Config{Floor: tc.floor, Budget: testBudget(), Drip: fastDrip()})
		if len(a.gens) != tc.gens {
			t.Fatalf("floor %d: expected %d generators, got %d", tc.floor, tc.gens, len(a.gens))
		}
		for _, g := range a.gens {
			if g.mechanism() == MechTokenBait && tc.floor != contract.FloorAggressive {
				t.Fatalf("floor %d constructed token_bait", tc.floor)
			}
		}
	}
}

// --- determinism / harmlessness ---

func TestGeneratorsAreReproducible(t *testing.T) {
	cfg := Config{Floor: contract.FloorAggressive, Budget: testBudget(), Drip: fastDrip(), Seed: 0x1234}
	a, b := mustNew(t, cfg), mustNew(t, cfg)
	sa := a.Open(verdict(contract.TierJail, 0x55))
	sb := b.Open(verdict(contract.TierJail, 0x55))
	defer sa.Close()
	defer sb.Close()
	for i := 0; i < 200; i++ {
		ca, da, _ := sa.Next(context.Background())
		cb, db, _ := sb.Next(context.Background())
		if string(ca.Data) != string(cb.Data) || da != db {
			t.Fatalf("chunk %d differs for identical seed+cookie (not deterministic)", i)
		}
	}
}

func TestMazeIdempotentSamePathSameBytes(t *testing.T) {
	if string(mazeNode(7, "/a/b/c")) != string(mazeNode(7, "/a/b/c")) {
		t.Fatal("mazeNode is not idempotent for the same seed+path")
	}
	if string(mazeNode(7, "/a/b/c")) == string(mazeNode(8, "/a/b/c")) {
		t.Fatal("mazeNode does not differ across flows (same content for different seeds)")
	}
}

func TestGeneratedBaitIsProvablyHarmless(t *testing.T) {
	a := mustNew(t, Config{Floor: contract.FloorAggressive, Budget: testBudget(), Drip: fastDrip()})
	for _, tier := range []contract.Tier{contract.TierContain, contract.TierJail} {
		s := a.Open(verdict(tier, 0x4242))
		for i := 0; i < 500; i++ {
			c, done, _ := s.Next(context.Background())
			if len(c.Data) > 0 {
				if err := harmless.CrossScan(c.Data); err != nil {
					t.Fatalf("tier %d chunk %d is not harmless: %v", tier, i, err)
				}
				if !strings.Contains(string(c.Data), stingMarker) {
					t.Fatalf("tier %d chunk %d missing sting marker", tier, i)
				}
			}
			if done != NotDone {
				break
			}
		}
		_ = s.Close()
	}
}

func TestTruncatedChunksRemainHarmless(t *testing.T) {
	// stream.Next emits truncateAtLine(data, remaining) when the per-flow byte cap
	// clips a chunk. The construction self-test only CrossScans FULL chunks, so this
	// covers the runtime truncation path: a newline-bounded prefix must still be
	// provably harmless (no half-line that hides a routable host or live key).
	p := genParams{MaxDepth: DefaultMaxDepth, Drip: DefaultDrip()}
	for _, g := range []generator{tarpit{}, fakeMaze{}, tokenBait{}} {
		for s := 0; s < 8; s++ {
			cur := cursor{seed: mix(uint64(s), 0xC0FFEE)}
			for i := 0; i < 16; i++ {
				data, _, ok := g.next(&cur, p)
				if !ok {
					break
				}
				// Sample truncation offsets across the chunk (incl. 0 and full len).
				for _, rem := range []int{0, 1, len(data) / 4, len(data) / 2, 3 * len(data) / 4, len(data) - 1, len(data)} {
					if rem < 0 {
						continue
					}
					out := truncateAtLine(data, rem)
					if len(out) > rem {
						t.Fatalf("%s: truncateAtLine returned %d bytes over the %d cap", g.mechanism(), len(out), rem)
					}
					if err := harmless.CrossScan(out); err != nil {
						t.Fatalf("%s s=%d i=%d rem=%d: truncated chunk not harmless: %v", g.mechanism(), s, i, rem, err)
					}
				}
			}
		}
	}
}

func TestGenSelfTestCatchesUnboundedGenerator(t *testing.T) {
	p := genParams{MaxDepth: 8, Drip: DefaultDrip()}
	if err := genSelfTest(unboundedGen{}, 4, p); err == nil {
		t.Fatal("construction self-test accepted an unbounded generator")
	}
	if err := genSelfTest(harmfulGen{}, 4, p); err == nil {
		t.Fatal("construction self-test accepted a generator emitting a routable host")
	}
	// The real generators pass.
	for _, g := range []generator{tarpit{}, fakeMaze{}, tokenBait{}} {
		if err := g.selfTest(8, p); err != nil {
			t.Fatalf("%s failed its own self-test: %v", g.mechanism(), err)
		}
	}
}

type unboundedGen struct{}

func (unboundedGen) mechanism() string            { return "unbounded" }
func (unboundedGen) axis() contract.AttritionAxis { return contract.AxisVelocity }
func (unboundedGen) minTier() contract.Tier       { return contract.TierContain }
func (unboundedGen) next(cur *cursor, _ genParams) ([]byte, time.Duration, bool) {
	cur.chunkIdx++
	return make([]byte, maxChunkBytes+1), time.Second, true // one byte over the per-chunk cap
}
func (g unboundedGen) selfTest(n int, p genParams) error { return genSelfTest(g, n, p) }

type harmfulGen struct{}

func (harmfulGen) mechanism() string            { return "harmful" }
func (harmfulGen) axis() contract.AttritionAxis { return contract.AxisVelocity }
func (harmfulGen) minTier() contract.Tier       { return contract.TierContain }
func (harmfulGen) next(cur *cursor, _ genParams) ([]byte, time.Duration, bool) {
	cur.chunkIdx++
	return []byte("beacon https://attacker.evil.com/exfil\n"), time.Second, true // routable host
}
func (g harmfulGen) selfTest(n int, p genParams) error { return genSelfTest(g, n, p) }

// --- the exit bar: attacker cost climbs while defender cost stays flat ---

func TestAttackerCostClimbsWhileDefenderFlat(t *testing.T) {
	a := mustNew(t, Config{Floor: contract.FloorAggressive, Budget: testBudget(), Drip: fastDrip()})
	s := a.Open(verdict(contract.TierJail, 0xC0DE))
	defer s.Close()

	pull := func(n int) Outcome {
		for i := 0; i < n; i++ {
			if _, done, _ := s.Next(context.Background()); done != NotDone {
				t.Fatalf("stream ended early at pull %d", i)
			}
		}
		return s.Outcome()
	}
	early := pull(50)
	late := pull(5000)
	if !(late.BytesServed > early.BytesServed && late.TimeHeldSec > early.TimeHeldSec && late.TokenCostProxy > early.TokenCostProxy) {
		t.Fatalf("attacker cost did not climb: early=%+v late=%+v", early, late)
	}

	// Defender flatness: per-Next allocations are bounded and position-independent.
	allocsAt := func() float64 {
		return testing.AllocsPerRun(200, func() { s.Next(context.Background()) })
	}
	first := allocsAt()
	for i := 0; i < 5000; i++ {
		s.Next(context.Background())
	}
	later := allocsAt()
	if later > first*2+8 {
		t.Fatalf("defender per-chunk allocations grew with attacker progress: %.0f -> %.0f", first, later)
	}
}

func BenchmarkNextAllocsFlat(b *testing.B) {
	a, _ := New(Config{Floor: contract.FloorAggressive, Budget: testBudget(), Drip: fastDrip()})
	s := a.Open(verdict(contract.TierJail, 0xBEEF))
	defer s.Close()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Next(ctx)
	}
}

// --- safety plumbing ---

func TestContextCancellationStopsStream(t *testing.T) {
	a := mustNew(t, Config{Floor: contract.FloorModerate, Budget: testBudget(), Drip: fastDrip()})
	gov := a.Governor()
	ctx, cancel := context.WithCancel(context.Background())
	s := a.Open(verdict(contract.TierJail, 0x33))
	if _, done, _ := s.Next(ctx); done != NotDone {
		t.Fatalf("stream not live before cancel: %v", done)
	}
	cancel()
	if _, done, err := s.Next(ctx); done != DoneKilled || err != nil {
		t.Fatalf("cancel did not stop the stream cleanly: done=%v err=%v", done, err)
	}
	_ = s.Close()
	if _, active, _ := gov.Snapshot(); active != 0 {
		t.Fatalf("Close after cancel did not release the governor slot: active=%d", active)
	}
}

func TestStreamIsConcurrencySafe(t *testing.T) {
	gov := NewGovernor(64<<20, 4096)
	a := mustNew(t, Config{Floor: contract.FloorAggressive, Budget: testBudget(), Drip: fastDrip(), Governor: gov})
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a.Open(verdict(contract.TierJail, uint64(i)+1))
			defer s.Close()
			for j := 0; j < 20; j++ {
				if _, done, _ := s.Next(context.Background()); done != NotDone {
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if _, active, _ := gov.Snapshot(); active != 0 {
		t.Fatalf("streams leaked governor slots under concurrency: active=%d", active)
	}
}

func TestDelayIsClamped(t *testing.T) {
	d := DripParams{ChunkBytes: 0, MinDelay: 0, MaxDelay: 0, RampSaturate: 0}.Normalized()
	if d.MinDelay <= 0 || d.MaxDelay < d.MinDelay || d.ChunkBytes <= 0 || d.RampSaturate <= 0 {
		t.Fatalf("zero drip did not normalize to a sane band: %+v", d)
	}
	// adaptiveDelay must stay within [MinDelay, MaxDelay] at EVERY persistence —
	// persist=0 (the pre-AX1 band), mid-ramp, at saturation, and well beyond it.
	for _, persist := range []int{0, 1, d.RampSaturate / 2, d.RampSaturate, d.RampSaturate * 5} {
		for i := 0; i < 1000; i++ {
			got := adaptiveDelay(uint64(i), i, d, persist)
			if got < d.MinDelay || got > d.MaxDelay {
				t.Fatalf("persist %d: delay %s out of band [%s,%s]", persist, got, d.MinDelay, d.MaxDelay)
			}
		}
	}
}

func TestDrivenStreamDelayEscalatesToCap(t *testing.T) {
	// End-to-end (not just the pure ramp): drive a real stream and confirm the
	// per-chunk delay floor escalates with persistence and, past RampSaturate, pins at
	// MaxDelay — so a persistent flow's imposed hold genuinely grows (AX1 velocity).
	d := DripParams{ChunkBytes: 64, MinDelay: time.Millisecond, MaxDelay: 100 * time.Millisecond, RampSaturate: 4}
	a := mustNew(t, Config{Budget: testBudget(), Drip: d}) // FloorPassive => tarpit only (no rotation noise)
	s := a.Open(verdict(contract.TierContain, 0x7A19))
	defer s.Close()
	var delays []time.Duration
	for i := 0; i < 12; i++ {
		c, done, err := s.Next(context.Background())
		if err != nil || done != NotDone {
			break
		}
		delays = append(delays, c.Delay)
	}
	dn := d.Normalized()
	if len(delays) <= dn.RampSaturate || dn.MinDelay >= dn.MaxDelay {
		t.Fatalf("escalation test vacuous: drove %d chunks, band [%s,%s]", len(delays), dn.MinDelay, dn.MaxDelay)
	}
	// Every chunk at idx >= RampSaturate has a saturated floor (== MaxDelay, no jitter
	// room), proving the delay climbed to the ceiling under persistence.
	for i := dn.RampSaturate; i < len(delays); i++ {
		if delays[i] != dn.MaxDelay {
			t.Fatalf("chunk %d delay = %s, want saturated MaxDelay %s (floor must escalate to the cap)", i, delays[i], dn.MaxDelay)
		}
	}
	// The first chunk's floor is MinDelay, so the early delay can be below the cap —
	// escalation is real, not a constant max.
	if delays[0] > dn.MaxDelay {
		t.Fatalf("first chunk delay %s exceeds MaxDelay %s", delays[0], dn.MaxDelay)
	}
}

func TestAdaptiveDelayEscalatesWithPersistence(t *testing.T) {
	// AX1: the delay FLOOR rises monotonically with persistence and saturates at
	// MaxDelay, so a persistent flow pays growing latency. ramp() is the floor
	// (jitter sits on top); check it directly.
	d := DripParams{ChunkBytes: 64, MinDelay: 500 * time.Millisecond, MaxDelay: 2 * time.Second, RampSaturate: 8}.Normalized()
	span := d.MaxDelay - d.MinDelay
	prev := time.Duration(-1)
	for persist := 0; persist <= d.RampSaturate; persist++ {
		floor := d.MinDelay + ramp(persist, d.RampSaturate, span)
		if floor < prev {
			t.Fatalf("floor decreased at persist %d: %s < %s", persist, floor, prev)
		}
		prev = floor
	}
	if got := d.MinDelay + ramp(0, d.RampSaturate, span); got != d.MinDelay {
		t.Fatalf("ramp(0) floor = %s, want MinDelay %s", got, d.MinDelay)
	}
	if got := d.MinDelay + ramp(d.RampSaturate, d.RampSaturate, span); got != d.MaxDelay {
		t.Fatalf("ramp(saturate) floor = %s, want MaxDelay %s", got, d.MaxDelay)
	}
	if got := d.MinDelay + ramp(d.RampSaturate*100, d.RampSaturate, span); got != d.MaxDelay {
		t.Fatalf("ramp beyond saturate floor = %s, want clamped to MaxDelay %s", got, d.MaxDelay)
	}
	// Division-safe / no panic on a zero or negative saturate (defensive; Normalized
	// prevents it from reaching here in production).
	if ramp(5, 0, span) < 0 || ramp(5, -3, span) < 0 {
		t.Fatal("ramp with non-positive saturate must not be negative")
	}
	// persist<=0 reproduces the pre-AX1 fixed band: floor == MinDelay.
	if got := adaptiveDelay(7, 7, d, 0); got < d.MinDelay || got > d.MaxDelay {
		t.Fatalf("persist=0 delay %s out of band", got)
	}
}

func TestZeroBudgetNormalizesToCapNotUnbounded(t *testing.T) {
	if got := (Budget{}).Normalized(); got != DefaultBudget() {
		t.Fatalf("zero budget did not normalize to the conservative default: %+v", got)
	}
}

func TestNoPanicsOnEdgeCases(t *testing.T) {
	// Zero-value config, killed governor, out-of-range tier, nil context.
	a := Default()
	a.Governor().Kill()
	s := a.Open(verdict(contract.TierJail, 1))
	if _, done, _ := s.Next(nil); done == NotDone { //nolint:staticcheck // nil ctx is a deliberate edge
		t.Fatal("killed attritor produced a live chunk")
	}
	a.Governor().Revive()
	s2 := a.Open(contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: 9}, Tier: contract.Tier(99)})
	if _, _, err := s2.Next(context.Background()); err != nil {
		t.Fatalf("out-of-range tier panicked/errored: %v", err)
	}
	_ = s2.Close()
}

// --- intelligence mapping + import discipline ---

func TestOutcomeMapsToStingOutcome(t *testing.T) {
	out := Outcome{Mechanism: MechTokenBait, TimeHeldSec: 12.5, BytesServed: 4096, RequestsAbsrb: 7, TokenCostProxy: 99, DepthReached: 5, Reason: DoneFlowBudget}
	// The composition root copies these cost fields; assert ALL of them transfer
	// (a transposition bug in any one must fail the test).
	so := intelligence.StingOutcome{
		Mechanism:      out.Mechanism,
		TimeHeldSec:    out.TimeHeldSec,
		BytesServed:    out.BytesServed,
		RequestsAbsrb:  out.RequestsAbsrb,
		TokenCostProxy: out.TokenCostProxy,
		DepthReached:   out.DepthReached,
	}
	if so.Mechanism != out.Mechanism || so.TimeHeldSec != out.TimeHeldSec || so.BytesServed != out.BytesServed ||
		so.RequestsAbsrb != out.RequestsAbsrb || so.TokenCostProxy != out.TokenCostProxy || so.DepthReached != out.DepthReached {
		t.Fatal("Outcome did not map cleanly onto intelligence.StingOutcome")
	}
	// Drift guard: every exported field of StingOutcome must have a same-named field
	// on Outcome, so a producer/consumer addition cannot silently go unmapped.
	// Reason is deliberately attrition-internal (not part of StingOutcome).
	ot := reflect.TypeOf(Outcome{})
	st := reflect.TypeOf(intelligence.StingOutcome{})
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if _, ok := ot.FieldByName(f.Name); !ok {
			t.Fatalf("intelligence.StingOutcome.%s has no counterpart on attrition.Outcome", f.Name)
		}
	}
}

func TestAttritionImportsOnlyContractAndHarmless(t *testing.T) {
	forbidden := []string{
		"canarysting/internal/engine",
		"canarysting/internal/canary",
		"canarysting/adapters",
		"canarysting/internal/intelligence",
	}
	fset := token.NewFileSet()
	var bad []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			for _, sub := range forbidden {
				if strings.Contains(imp.Path.Value, sub) {
					bad = append(bad, path+": "+imp.Path.Value)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Errorf("attrition production code imports forbidden packages: %v", bad)
	}
}
