package tap

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/engine/persist"
	"github.com/canarysting/canarysting/internal/engine/scope"
	"github.com/canarysting/canarysting/internal/intelligence"
	"github.com/canarysting/canarysting/internal/intelligence/boltevents"
	"github.com/canarysting/canarysting/internal/topology/identity"
)

const topoTestScope = contract.ScopeKey("topo-scope")

// fakeTopoReader is a minimal observe.Reader for driving the aggregator's fold in
// a tap test (the aggregator's own fold loop is unexported, so we pre-load a
// closed flow and let one fold tick consume it).
type fakeTopoReader struct {
	flows map[uint64]observe.FlowStats
}

func (r *fakeTopoReader) ReadStats(cookie uint64) (observe.FlowStats, bool, error) {
	fs, ok := r.flows[cookie]
	return fs, ok, nil
}

func (r *fakeTopoReader) IterStats(fn func(uint64, observe.FlowStats) error) error {
	for c, fs := range r.flows {
		if err := fn(c, fs); err != nil {
			return err
		}
	}
	return nil
}

// foldedAggregator builds an aggregator, pre-loads one CLOSED demo-mesh flow
// (caller 10.20.1.101 -> service on the api port 8002), and folds it once by
// running Run with an already-cancelled context (Run folds once on ctx.Done).
func foldedAggregator(t *testing.T, now time.Time) *observebaseline.Aggregator {
	t.Helper()
	var src, dst [16]byte
	src[0], src[1], src[2], src[3] = 10, 20, 1, 101
	dst[0], dst[1], dst[2], dst[3] = 10, 20, 1, 24
	r := &fakeTopoReader{flows: map[uint64]observe.FlowStats{
		0x118: {
			Family: observe.AFInet, SrcIP: src, DstIP: dst,
			SrcPort: 40000, DstPort: 8002,
			IngressBytes: 1400, EgressBytes: 1400, IngressPackets: 10, EgressPackets: 10,
			FirstSeenNs: 1000, LastSeenNs: 2_000_000, Closed: 1,
		},
	}}
	res, err := scope.NewStaticResolver(scope.Config{Boundary: topoTestScope})
	if err != nil {
		t.Fatal(err)
	}
	gates := baseline.New(baseline.Config{})
	agg := observebaseline.New(observebaseline.Config{
		Reader: r, Gates: gates, Resolver: res,
		Bucketer: baseline.WindowBucketer, Now: func() time.Time { return now },
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	agg.Run(ctx) // rehydrate (no store) + one fold on the cancelled ctx
	return agg
}

// demoResolver labels the demo mesh: api on port 8002 (service) and the caller IP
// (caller). Mirrors deploy/m7-window/topology-identities.json.
func demoResolver(t *testing.T) *identity.Resolver {
	t.Helper()
	cfg, err := identity.LoadConfig(strings.NewReader(`{"entries":[
		{"port":8002,"name":"api","kind":"service"},
		{"ip":"10.20.1.101","name":"reporting-worker","kind":"caller"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	return identity.NewResolver(cfg)
}

// The endpoint resolves learned-node labels from the operator registry and reports
// staged_labels=true; the learned edge carries the real observed shape/volume.
func TestTopologyResolvesLabelsAndShape(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	src := &Source{
		Scope:      topoTestScope,
		Aggregator: foldedAggregator(t, now),
		Resolver:   demoResolver(t),
		Now:        func() time.Time { return now },
	}
	view := src.buildTopology(now)

	if !view.StagedLabels {
		t.Fatal("staged_labels = false, want true (a resolver is loaded)")
	}
	// Exactly one learned edge: the api-port flow we folded.
	learned := edgesOfClass(view, edgeClassLearned)
	if len(learned) != 1 {
		t.Fatalf("learned edges = %d, want 1", len(learned))
	}
	if learned[0].Port != 8002 || learned[0].FlowCount != 1 || learned[0].Bytes != 2800 {
		t.Fatalf("learned edge wrong: %+v", learned[0])
	}
	// Both endpoints resolve to their operator-declared names and kinds.
	byID := nodesByID(view)
	svc, ok := byID[learned[0].DstID]
	if !ok || svc.Label != "api" || svc.Kind != "service" {
		t.Fatalf("service node = %+v (ok=%v), want api/service", svc, ok)
	}
	caller, ok := byID[learned[0].SrcID]
	if !ok || caller.Label != "reporting-worker" || caller.Kind != "caller" {
		t.Fatalf("caller node = %+v (ok=%v), want reporting-worker/caller", caller, ok)
	}
}

// With NO resolver, staged_labels is false and learned nodes degrade to IP labels
// (the engine knows only hashed adjacency — it never invents a service name).
func TestTopologyNilResolverDegradesToIP(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	src := &Source{
		Scope:      topoTestScope,
		Aggregator: foldedAggregator(t, now),
		Now:        func() time.Time { return now },
	}
	view := src.buildTopology(now)
	if view.StagedLabels {
		t.Fatal("staged_labels = true with no resolver, want false")
	}
	learned := edgesOfClass(view, edgeClassLearned)
	if len(learned) != 1 {
		t.Fatalf("learned edges = %d, want 1", len(learned))
	}
	byID := nodesByID(view)
	svc := byID[learned[0].DstID]
	// 10.20.1.24 is private => Unknown kind, labeled by IP.
	if svc.Label != "10.20.1.24" || svc.Kind != "unknown" {
		t.Fatalf("degraded service node = %+v, want IP label / unknown", svc)
	}
}

// The five canary catalog types are injected as decoy nodes in the negative space.
func TestTopologyInjectsDecoyNodes(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	src := &Source{
		Scope:   topoTestScope,
		Catalog: catalog.Default(),
		Now:     func() time.Time { return now },
	}
	view := src.buildTopology(now)

	decoys := map[string]bool{}
	for _, n := range view.Nodes {
		if n.Kind == "decoy" {
			decoys[n.Label] = true
		}
	}
	for _, want := range []contract.CanaryType{
		catalog.TypePlantedCredential, catalog.TypeFakeSecret, catalog.TypeDecoyFile,
		catalog.TypeFakeBucket, catalog.TypeFakeEndpoint,
	} {
		if !decoys[string(want)] {
			t.Fatalf("decoy node for %q missing; got decoys=%v", want, decoys)
		}
	}
	if len(decoys) != 5 {
		t.Fatalf("decoy node count = %d, want 5", len(decoys))
	}
	// With no aggregator and no touches there are no edges at all.
	if len(view.Edges) != 0 {
		t.Fatalf("edges = %d on a decoy-only graph, want 0", len(view.Edges))
	}
}

// A recent real canary-touch event (Tier>=1) lights a source->decoy edge; repeat
// touches of the same decoy by the same flow are deduped (FlowCount bumps).
func TestTopologyTouchEdgeFromRealEvent(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "events.db")
	pstore, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer pstore.Close()
	events := boltevents.New(pstore)

	// Two touches of the SAME decoy by the SAME flow + one OTHER decoy touch.
	mustAppend(t, events, intelligence.AdversaryInteractionEvent{
		ScopeKey: string(topoTestScope), FlowID: 0x118, CanaryType: string(catalog.TypePlantedCredential),
		Tier: 2, Timestamp: now.Add(-2 * time.Minute),
	})
	mustAppend(t, events, intelligence.AdversaryInteractionEvent{
		ScopeKey: string(topoTestScope), FlowID: 0x118, CanaryType: string(catalog.TypePlantedCredential),
		Tier: 3, Timestamp: now.Add(-1 * time.Minute),
	})
	mustAppend(t, events, intelligence.AdversaryInteractionEvent{
		ScopeKey: string(topoTestScope), FlowID: 0x222, CanaryType: string(catalog.TypeFakeBucket),
		Tier: 1, Timestamp: now.Add(-30 * time.Second),
	})

	src := &Source{
		Scope:   topoTestScope,
		Events:  events,
		Catalog: catalog.Default(),
		Now:     func() time.Time { return now },
	}
	view := src.buildTopology(now)

	touches := edgesOfClass(view, edgeClassDecoyTouch)
	if len(touches) != 2 {
		t.Fatalf("decoy_touch edges = %d, want 2 (deduped by (cookie,decoy))", len(touches))
	}
	byID := nodesByID(view)
	for _, e := range touches {
		// Each touch edge must terminate on a decoy node.
		if byID[e.DstID].Kind != "decoy" {
			t.Fatalf("touch edge dst %q is not a decoy node: %+v", e.DstID, byID[e.DstID])
		}
		// And its source node must exist (the touching identity).
		if _, ok := byID[e.SrcID]; !ok {
			t.Fatalf("touch edge source node %q not injected", e.SrcID)
		}
		if e.DstID == decoyNodeID(catalog.TypePlantedCredential) && e.FlowCount != 2 {
			t.Fatalf("planted_credential touch FlowCount = %d, want 2 (two touches deduped)", e.FlowCount)
		}
	}
}

// helpers ---------------------------------------------------------------------

func mustAppend(t *testing.T, s *boltevents.Store, ev intelligence.AdversaryInteractionEvent) {
	t.Helper()
	if err := s.Append(ev); err != nil {
		t.Fatal(err)
	}
}

func edgesOfClass(v TopologyView, class string) []TopologyEdge {
	var out []TopologyEdge
	for _, e := range v.Edges {
		if e.Class == class {
			out = append(out, e)
		}
	}
	return out
}

func nodesByID(v TopologyView) map[string]TopologyNode {
	m := make(map[string]TopologyNode, len(v.Nodes))
	for _, n := range v.Nodes {
		m[n.ID] = n
	}
	return m
}
