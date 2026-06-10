package attacker

import (
	"math"
	"testing"

	sdk "github.com/anthropics/anthropic-sdk-go"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestBudgetCostMath checks the dollar math at the verified Opus 4.8 rates:
// $5/1M input, $25/1M output, $0.5/1M cache-read.
func TestBudgetCostMath(t *testing.T) {
	b := NewBudget(5.0, 5.0, 25.0, 0.5)
	// 1M input = $5, 1M output = $25, 1M cache = $0.5
	got := b.Accumulate(sdk.Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000, CacheReadInputTokens: 1_000_000})
	want := 5.0 + 25.0 + 0.5
	if !approx(got, want) {
		t.Fatalf("cost math: want $%.4f, got $%.4f", want, got)
	}
	snap := b.Snapshot()
	if snap.InputTokens != 1_000_000 || snap.OutputTokens != 1_000_000 || snap.CacheReadTokens != 1_000_000 {
		t.Fatalf("snapshot token totals wrong: %+v", snap)
	}
	if !approx(snap.USD, want) {
		t.Fatalf("snapshot USD wrong: %.4f", snap.USD)
	}
}

// TestBudgetAccumulates confirms repeated Accumulate calls sum correctly.
func TestBudgetAccumulates(t *testing.T) {
	b := NewBudget(100.0, 5.0, 25.0, 0.5)
	b.Accumulate(sdk.Usage{InputTokens: 100_000, OutputTokens: 10_000})
	got := b.Accumulate(sdk.Usage{InputTokens: 100_000, OutputTokens: 10_000})
	// 200k input = $1.00, 20k output = $0.50
	want := 1.0 + 0.5
	if !approx(got, want) {
		t.Fatalf("accumulate: want $%.4f, got $%.4f", want, got)
	}
}

// TestBudgetExceeded confirms the hard cap trips at exactly the ceiling.
func TestBudgetExceeded(t *testing.T) {
	b := NewBudget(1.0, 5.0, 25.0, 0.5) // $1.00 cap
	if b.Exceeded() {
		t.Fatal("fresh budget should not be exceeded")
	}
	// 100k input = $0.50 — under cap
	b.Accumulate(sdk.Usage{InputTokens: 100_000})
	if b.Exceeded() {
		t.Fatal("at $0.50 of a $1.00 cap, should not be exceeded")
	}
	// another 100k input = $1.00 total — at cap, Exceeded uses >=
	b.Accumulate(sdk.Usage{InputTokens: 100_000})
	if !b.Exceeded() {
		t.Fatalf("at exactly $1.00 cap, Exceeded must fire; snap=%+v", b.Snapshot())
	}
}

// TestBudgetCountsCacheCreation verifies cache-CREATION tokens are billed (at
// 1.25x input) — the loop caches the system prompt, so turn 0 writes the cache,
// and omitting it would understate cost and trip the cap late.
func TestBudgetCountsCacheCreation(t *testing.T) {
	b := NewBudget(100.0, 5.0, 25.0, 0.5)
	// 1M cache-creation tokens at 5.0 * 1.25 = $6.25
	got := b.Accumulate(sdk.Usage{CacheCreationInputTokens: 1_000_000})
	if !approx(got, 6.25) {
		t.Fatalf("cache-creation must bill at 1.25x input ($6.25/1M); got $%.4f", got)
	}
	snap := b.Snapshot()
	if snap.CacheCreationTokens != 1_000_000 {
		t.Fatalf("cache-creation tokens not tracked: %+v", snap)
	}
	if !approx(snap.CacheCreationUSD, 6.25) {
		t.Fatalf("cache-creation USD breakdown wrong: %.4f", snap.CacheCreationUSD)
	}
}

// TestBudgetBreakdownReconciles confirms the per-category USD sums to the total.
func TestBudgetBreakdownReconciles(t *testing.T) {
	b := NewBudget(100.0, 5.0, 25.0, 0.5)
	b.Accumulate(sdk.Usage{InputTokens: 200_000, OutputTokens: 30_000, CacheReadInputTokens: 500_000, CacheCreationInputTokens: 1000})
	s := b.Snapshot()
	sum := s.InputUSD + s.OutputUSD + s.CacheReadUSD + s.CacheCreationUSD
	if !approx(sum, s.USD) {
		t.Fatalf("breakdown $%.6f != total $%.6f", sum, s.USD)
	}
}

// TestBudgetDefaultsGuardZeroPrices ensures a partial/zero override can't
// silently disable cost accounting.
func TestBudgetDefaultsGuardZeroPrices(t *testing.T) {
	b := NewBudget(5.0, 0, 0, 0) // all zero -> fall back to verified defaults
	got := b.Accumulate(sdk.Usage{InputTokens: 1_000_000})
	if !approx(got, 5.0) {
		t.Fatalf("zero input price must fall back to $5/1M; got $%.4f", got)
	}
}
