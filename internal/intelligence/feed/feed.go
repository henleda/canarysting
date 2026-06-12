package feed

import (
	"time"

	"github.com/canarysting/canarysting/internal/intelligence/network"
)

// Source is the narrow, read-only seam the feed consumes — satisfied by *network.Ledger.
// It is an interface (not the concrete ledger) so the feed package imports network for
// ONE value type + ONE method and takes NO engine/scope/boltevents/profile/contract
// dependency: the feed is structurally INCAPABLE of reaching a raw event, Profile,
// baseline, or scope-state, which is the rule-9 "never a second egress" guarantee made
// by the type system, not convention. Trivially testable with a fake seeded to >= FeedK.
type Source interface {
	Aggregated(minScopes int) []network.AggregatedPattern
}

// FeedEntry is one row of the external threat-intel feed: a coarse, already-anonymized
// adversary pattern. It is a pure value copy of a network.AggregatedPattern — the feed
// adds NO field the ledger did not already vet, and PRESENCE-ONLY (D7a): no prevalence
// count/band, no scope identity, no hash. Each entry's mere presence asserts ">= FeedK
// deployments independently corroborated this behavior."
type FeedEntry struct {
	ReachedContain  bool   `json:"reachedContain"`
	EngagedVelocity bool   `json:"engagedVelocity"`
	EngagedPoison   bool   `json:"engagedPoison"`
	DisengagedEarly bool   `json:"disengagedEarly"`
	HeldBand        int    `json:"heldBand"`
	CadenceBand     int    `json:"cadenceBand"`
	PoisonClass     string `json:"poisonClass"`
}

// FeedView is the materialized read view: the entries + a coarse build stamp. A pure
// value — it holds no Source/Ledger reference, no events, no scope state — so it is safe
// to hand to a (future, deferred) authenticated HTTP handler to serialize.
type FeedView struct {
	Entries     []FeedEntry `json:"entries"`
	Count       int         `json:"count"`       // number of patterns (coarse, non-identifying)
	GeneratedAt string      `json:"generatedAt"` // RFC3339 build time, NOT an observation timestamp
}

// BuildFeed is the pure read-view builder (mirrors cost.Rollup / DeriveReconTimeline): it
// snapshots the >= FeedK cross-scope-confirmed cells and projects each to a FeedEntry. It
// performs NO egress (no Clear, no Marshal), reads ONLY the Source's already-aggregated
// coarse output, mutates nothing, and is deterministic given src. The serving/auth/
// rate-limit surface (D7c-D7j) is deferred to a real external consumer — this is the
// read-view DATA layer the moat needs; a future handler simply serializes a FeedView.
func BuildFeed(src Source, now time.Time) FeedView {
	stamp := now.UTC().Format(time.RFC3339)
	if src == nil {
		return FeedView{Entries: []FeedEntry{}, Count: 0, GeneratedAt: stamp}
	}
	patterns := src.Aggregated(network.FeedK)
	entries := make([]FeedEntry, 0, len(patterns))
	for _, p := range patterns {
		entries = append(entries, FeedEntry{
			ReachedContain:  p.ReachedContain,
			EngagedVelocity: p.EngagedVelocity,
			EngagedPoison:   p.EngagedPoison,
			DisengagedEarly: p.DisengagedEarly,
			HeldBand:        p.HeldBand,
			CadenceBand:     p.CadenceBand,
			PoisonClass:     p.PoisonClass,
		})
	}
	return FeedView{Entries: entries, Count: len(entries), GeneratedAt: stamp}
}
