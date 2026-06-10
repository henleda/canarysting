package attacker

import (
	"sync"

	sdk "github.com/anthropics/anthropic-sdk-go"
)

// cacheWriteMultiplier is the Anthropic surcharge for writing the 5-minute
// ephemeral cache: cache-creation tokens bill at 1.25x the base input rate.
// (1-hour cache is 2x, but the loop uses the default 5m TTL.)
const cacheWriteMultiplier = 1.25

// Budget tracks real token spend and enforces a hard dollar ceiling. Prices are
// per MILLION tokens. The verified Opus 4.8 rates are $5.00 input / $25.00
// output / $0.50 cache-read per 1M tokens (cache-read ~= 10% of input);
// cache-CREATION bills at 1.25x input ($6.25/1M) — counted here because the loop
// caches the system prompt, so the first turn writes the cache.
//
// Two-layer enforcement (see the agent loop): Exceeded() is checked BEFORE each
// API call (so once tripped, no further spend), and Accumulate() runs AFTER
// each response. The external dollar cap — not any model-visible countdown — is
// the real ceiling.
type Budget struct {
	hardCapUSD    float64
	inPerMTok     float64
	outPerMTok    float64
	cachePerMTok  float64 // cache-read rate
	cacheWPerMTok float64 // cache-creation rate (= input * 1.25)

	mu        sync.Mutex
	inTok     int64
	outTok    int64
	cacheTok  int64 // cache-read
	cacheWTok int64 // cache-creation
	usd       float64
}

// NewBudget builds a Budget with the verified Opus 4.8 defaults unless the
// caller overrides. A non-positive price falls back to the default for that
// dimension so a partial override can't silently zero out cost accounting. The
// cache-creation rate is always derived as input * 1.25.
func NewBudget(hardCapUSD, inPerMTok, outPerMTok, cachePerMTok float64) *Budget {
	if inPerMTok <= 0 {
		inPerMTok = 5.0
	}
	if outPerMTok <= 0 {
		outPerMTok = 25.0
	}
	if cachePerMTok <= 0 {
		cachePerMTok = 0.5
	}
	return &Budget{
		hardCapUSD:    hardCapUSD,
		inPerMTok:     inPerMTok,
		outPerMTok:    outPerMTok,
		cachePerMTok:  cachePerMTok,
		cacheWPerMTok: inPerMTok * cacheWriteMultiplier,
	}
}

// Accumulate adds one response's usage and returns the running dollar total.
// Uses the verified int64 Usage fields. The four token classes the API reports
// separately (input, output, cache-read, cache-creation) are each billed at
// their own rate and never double-counted.
func (b *Budget) Accumulate(u sdk.Usage) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inTok += u.InputTokens
	b.outTok += u.OutputTokens
	b.cacheTok += u.CacheReadInputTokens
	b.cacheWTok += u.CacheCreationInputTokens
	b.usd = b.computeUSD()
	return b.usd
}

// computeUSD recomputes the running total from the token counters. Caller holds mu.
func (b *Budget) computeUSD() float64 {
	return float64(b.inTok)/1e6*b.inPerMTok +
		float64(b.outTok)/1e6*b.outPerMTok +
		float64(b.cacheTok)/1e6*b.cachePerMTok +
		float64(b.cacheWTok)/1e6*b.cacheWPerMTok
}

// Exceeded reports whether the running cost has reached the hard cap.
func (b *Budget) Exceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.usd >= b.hardCapUSD
}

// Snapshot is an immutable view of the ledger for logging, the run summary, and
// the live cost meter the attacker POSTs to the dashboard tap. It carries the
// per-category dollar breakdown so callers never recompute cost from
// (possibly-overridden) prices.
type Snapshot struct {
	InputTokens         int64   `json:"input_tokens"`
	OutputTokens        int64   `json:"output_tokens"`
	CacheReadTokens     int64   `json:"cache_read_tokens"`
	CacheCreationTokens int64   `json:"cache_creation_tokens"`
	InputUSD            float64 `json:"input_usd"`
	OutputUSD           float64 `json:"output_usd"`
	CacheReadUSD        float64 `json:"cache_read_usd"`
	CacheCreationUSD    float64 `json:"cache_creation_usd"`
	USD                 float64 `json:"usd"`
	HardCapUSD          float64 `json:"hard_cap_usd"`
}

// Snapshot returns the current ledger totals with the per-category breakdown.
func (b *Budget) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Snapshot{
		InputTokens:         b.inTok,
		OutputTokens:        b.outTok,
		CacheReadTokens:     b.cacheTok,
		CacheCreationTokens: b.cacheWTok,
		InputUSD:            float64(b.inTok) / 1e6 * b.inPerMTok,
		OutputUSD:           float64(b.outTok) / 1e6 * b.outPerMTok,
		CacheReadUSD:        float64(b.cacheTok) / 1e6 * b.cachePerMTok,
		CacheCreationUSD:    float64(b.cacheWTok) / 1e6 * b.cacheWPerMTok,
		USD:                 b.usd,
		HardCapUSD:          b.hardCapUSD,
	}
}
