package feed

import (
	"go/build"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/intelligence/network"
)

type fakeSource struct {
	patterns []network.AggregatedPattern
	gotMin   int
}

func (f *fakeSource) Aggregated(minScopes int) []network.AggregatedPattern {
	f.gotMin = minScopes
	return f.patterns
}

func TestBuildFeedProjectsPatterns(t *testing.T) {
	src := &fakeSource{patterns: []network.AggregatedPattern{
		{ReachedContain: true, EngagedVelocity: true, EngagedPoison: true, HeldBand: 2, DisengagedEarly: true, PoisonClass: "topology", CadenceBand: 1},
	}}
	v := BuildFeed(src, time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC))

	if src.gotMin != network.FeedK {
		t.Fatalf("BuildFeed must request the feed threshold FeedK=%d, got %d", network.FeedK, src.gotMin)
	}
	if v.Count != 1 || len(v.Entries) != 1 {
		t.Fatalf("want 1 entry, got count=%d entries=%d", v.Count, len(v.Entries))
	}
	e := v.Entries[0]
	if !e.ReachedContain || !e.EngagedVelocity || !e.EngagedPoison || !e.DisengagedEarly || e.HeldBand != 2 || e.CadenceBand != 1 || e.PoisonClass != "topology" {
		t.Fatalf("entry projection wrong: %+v", e)
	}
	if v.GeneratedAt == "" {
		t.Fatal("GeneratedAt must be stamped")
	}
}

func TestBuildFeedNilAndEmpty(t *testing.T) {
	if v := BuildFeed(nil, time.Now()); v.Count != 0 || v.Entries == nil {
		t.Fatalf("nil source => empty (non-nil) entries, got %+v", v)
	}
	if v := BuildFeed(&fakeSource{}, time.Now()); v.Count != 0 {
		t.Fatalf("empty source => 0 entries, got %d", v.Count)
	}
}

// D7a presence-only: a FeedEntry must carry NO count/prevalence/scope/identity.
func TestFeedEntryHasNoCountOrIdentity(t *testing.T) {
	rt := reflect.TypeOf(FeedEntry{})
	for i := 0; i < rt.NumField(); i++ {
		n := strings.ToLower(rt.Field(i).Name)
		for _, banned := range []string{"count", "prevalence", "scope", "bucket", "hash", "flow", "cookie", "ip", "identity", "seen", "salt"} {
			if strings.Contains(n, banned) {
				t.Fatalf("FeedEntry.%s leaks a count/identity (D7a presence-only)", rt.Field(i).Name)
			}
		}
	}
}

// The rule-9 "never a second egress" guarantee, enforced structurally: the feed package
// may reach the codebase through NOTHING but internal/intelligence/network — so it is
// incapable of importing a raw event store, profile, baseline, engine, or contract type.
func TestFeedImportDiscipline(t *testing.T) {
	const allowed = "github.com/canarysting/canarysting/internal/intelligence/network"
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkg.Imports { // non-test imports only
		if strings.Contains(p, "canarysting") && p != allowed {
			t.Fatalf("feed imports %q; the ONLY canarysting import allowed is %q (rule-9 structural — the feed must not reach raw data)", p, allowed)
		}
	}
}
