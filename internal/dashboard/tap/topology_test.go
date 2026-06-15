package tap

import (
	"context"
	"net/netip"
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

// flow4 builds a closed observe.FlowStats for a v4 (srcA.B.C.D -> dstA.B.C.D:port)
// hop the aggregator will fold into one learned edge.
func flow4(src, dst [4]byte, dstPort uint16) observe.FlowStats {
	var s, d [16]byte
	copy(s[:], src[:])
	copy(d[:], dst[:])
	return observe.FlowStats{
		Family: observe.AFInet, SrcIP: s, DstIP: d,
		SrcPort: 40000, DstPort: dstPort,
		IngressBytes: 1400, EgressBytes: 1400, IngressPackets: 10, EgressPackets: 10,
		FirstSeenNs: 1000, LastSeenNs: 2_000_000, Closed: 1,
	}
}

// aggregatorWith builds an aggregator pre-loaded with the given closed flows and
// folds them once (Run on an already-cancelled ctx folds once on ctx.Done).
func aggregatorWith(t *testing.T, now time.Time, flows map[uint64]observe.FlowStats) *observebaseline.Aggregator {
	t.Helper()
	r := &fakeTopoReader{flows: flows}
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

// foldedAggregator pre-loads one CLOSED demo-mesh flow: caller 10.20.1.101 dialing
// the api service at its distinct loopback identity 127.0.1.2:8002.
func foldedAggregator(t *testing.T, now time.Time) *observebaseline.Aggregator {
	t.Helper()
	return aggregatorWith(t, now, map[uint64]observe.FlowStats{
		0x118: flow4([4]byte{10, 20, 1, 101}, [4]byte{127, 0, 1, 2}, 8002),
	})
}

// demoResolver labels the demo mesh in the DISTINCT-IDENTITY scheme: each service
// is named by its 127.0.1.<K> IP (so its egress[port 0] and listen[port N] sides
// coalesce), and the caller by IP. Mirrors deploy/m7-window/topology-identities.json.
func demoResolver(t *testing.T) *identity.Resolver {
	t.Helper()
	cfg, err := identity.LoadConfig(strings.NewReader(`{"entries":[
		{"ip":"127.0.1.1","name":"frontend","kind":"service"},
		{"ip":"127.0.1.2","name":"api","kind":"service"},
		{"ip":"127.0.1.3","name":"auth","kind":"service"},
		{"ip":"10.20.1.101","name":"reporting-worker","kind":"caller"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	return identity.NewResolver(cfg)
}

// The endpoint resolves learned-node labels from the operator registry and reports
// staged_labels=true; the learned edge carries the real observed shape/volume, and
// both endpoints carry the new IDENTITY-keyed coalesced node ids.
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
	// Both endpoints resolve to their operator-declared names and kinds, keyed by
	// the new IDENTITY-coalesced id scheme.
	byID := nodesByID(view)
	svc, ok := byID[learned[0].DstID]
	if !ok || svc.Label != "api" || svc.Kind != "service" {
		t.Fatalf("service node = %+v (ok=%v), want api/service", svc, ok)
	}
	if learned[0].DstID != "id:service:api" {
		t.Fatalf("service node id = %q, want id:service:api", learned[0].DstID)
	}
	caller, ok := byID[learned[0].SrcID]
	if !ok || caller.Label != "reporting-worker" || caller.Kind != "caller" {
		t.Fatalf("caller node = %+v (ok=%v), want reporting-worker/caller", caller, ok)
	}
}

// A service that appears as BOTH an edge source (its egress) and an edge
// destination (its listen side) coalesces to ONE node.
func TestTopologyCoalescesDualRoleService(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	// frontend (127.0.1.1) -> api (127.0.1.2:8002), then api -> auth (127.0.1.3:8003).
	// api is a DESTINATION on the first edge and a SOURCE on the second.
	agg := aggregatorWith(t, now, map[uint64]observe.FlowStats{
		0x1: flow4([4]byte{127, 0, 1, 1}, [4]byte{127, 0, 1, 2}, 8002),
		0x2: flow4([4]byte{127, 0, 1, 2}, [4]byte{127, 0, 1, 3}, 8003),
	})
	src := &Source{Scope: topoTestScope, Aggregator: agg, Resolver: demoResolver(t), Now: func() time.Time { return now }}
	view := src.buildTopology(now)

	byID := nodesByID(view)
	if _, ok := byID["id:service:api"]; !ok {
		t.Fatalf("api node missing; nodes=%v", nodeIDs(view))
	}
	// Count distinct api nodes — must be exactly one despite the dual role.
	apiCount := 0
	for _, n := range view.Nodes {
		if n.Label == "api" {
			apiCount++
		}
	}
	if apiCount != 1 {
		t.Fatalf("api appears as %d nodes, want 1 (dual-role must coalesce); nodes=%v", apiCount, nodeIDs(view))
	}
}

// frontend -> api -> auth renders as a connected named chain: three distinct nodes
// joined by two learned edges that share the api node.
func TestTopologyNamedChainConnects(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	agg := aggregatorWith(t, now, map[uint64]observe.FlowStats{
		0x1: flow4([4]byte{127, 0, 1, 1}, [4]byte{127, 0, 1, 2}, 8002),
		0x2: flow4([4]byte{127, 0, 1, 2}, [4]byte{127, 0, 1, 3}, 8003),
	})
	src := &Source{Scope: topoTestScope, Aggregator: agg, Resolver: demoResolver(t), Now: func() time.Time { return now }}
	view := src.buildTopology(now)

	learned := edgesOfClass(view, edgeClassLearned)
	if len(learned) != 2 {
		t.Fatalf("learned edges = %d, want 2", len(learned))
	}
	byID := nodesByID(view)
	for _, want := range []string{"id:service:frontend", "id:service:api", "id:service:auth"} {
		if _, ok := byID[want]; !ok {
			t.Fatalf("chain node %q missing; nodes=%v", want, nodeIDs(view))
		}
	}
	// The two edges must share the api node: frontend->api and api->auth.
	var fa, aa bool
	for _, e := range learned {
		if e.SrcID == "id:service:frontend" && e.DstID == "id:service:api" {
			fa = true
		}
		if e.SrcID == "id:service:api" && e.DstID == "id:service:auth" {
			aa = true
		}
	}
	if !fa || !aa {
		t.Fatalf("chain not connected through api: frontend->api=%v api->auth=%v; edges=%+v", fa, aa, learned)
	}
}

// An edge to an UNKNOWN endpoint (not in the resolver — e.g. a management-plane
// flow) is DROPPED by the clean-fabric filter.
func TestTopologyDropsUnknownEndpointEdge(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	// frontend (named) -> 127.0.0.9:50051 (the engine gRPC port, NOT in the map).
	agg := aggregatorWith(t, now, map[uint64]observe.FlowStats{
		0x1: flow4([4]byte{127, 0, 1, 1}, [4]byte{127, 0, 0, 9}, 50051),
	})
	src := &Source{Scope: topoTestScope, Aggregator: agg, Resolver: demoResolver(t), Now: func() time.Time { return now }}
	view := src.buildTopology(now)

	if got := len(edgesOfClass(view, edgeClassLearned)); got != 0 {
		t.Fatalf("learned edges = %d, want 0 (edge to unnamed infra endpoint must be dropped)", got)
	}
	// And the unnamed endpoint must not have been added as a node.
	for _, n := range view.Nodes {
		if n.Kind == "unknown" {
			t.Fatalf("unknown infra node leaked into the graph: %+v", n)
		}
	}
}

// The two ingress endpoints (the accept address 127.0.0.1:8080 and the
// upstream-bind source 127.0.2.1) both named "ingress-gateway" coalesce to ONE
// ingress node — even appearing on different edges.
func TestTopologyCoalescesIngressEndpoints(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	cfg, err := identity.LoadConfig(strings.NewReader(`{"entries":[
		{"ip":"127.0.1.1","name":"frontend","kind":"service"},
		{"ip":"127.0.0.1","port":8080,"name":"ingress-gateway","kind":"external"},
		{"ip":"127.0.2.1","name":"ingress-gateway","kind":"external"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	resolver := identity.NewResolver(cfg)

	// Two flows that both involve the ingress under its two addresses:
	//   - a caller hits the ingress accept address 127.0.0.1:8080,
	//   - the ingress (originating 127.0.2.1) reaches the frontend.
	// Both ingress endpoints must collapse to the same node id.
	if got := coalescedNodeID(resolver.Resolve(netip.MustParseAddr("127.0.0.1"), 8080, "", ""), netip.MustParseAddr("127.0.0.1"), 8080); got != "id:external:ingress-gateway" {
		t.Fatalf("ingress accept id = %q, want id:external:ingress-gateway", got)
	}
	if got := coalescedNodeID(resolver.Resolve(netip.MustParseAddr("127.0.2.1"), 0, "", ""), netip.MustParseAddr("127.0.2.1"), 0); got != "id:external:ingress-gateway" {
		t.Fatalf("ingress source id = %q, want id:external:ingress-gateway", got)
	}

	agg := aggregatorWith(t, now, map[uint64]observe.FlowStats{
		0x1: flow4([4]byte{127, 0, 2, 1}, [4]byte{127, 0, 1, 1}, 8001), // ingress -> frontend
	})
	src := &Source{Scope: topoTestScope, Aggregator: agg, Resolver: resolver, Now: func() time.Time { return now }}
	view := src.buildTopology(now)
	ingressCount := 0
	for _, n := range view.Nodes {
		if n.Label == "ingress-gateway" {
			ingressCount++
		}
	}
	if ingressCount != 1 {
		t.Fatalf("ingress appears as %d nodes, want 1 (the two endpoints must coalesce); nodes=%v", ingressCount, nodeIDs(view))
	}
}

// With NO resolver, staged_labels is false and EVERY learned endpoint degrades to
// unknown — so the clean-fabric filter drops every learned edge (the engine knows
// only hashed adjacency; it never invents a name). The decoy ring still renders.
func TestTopologyNilResolverDegradesToEmptyFabric(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	src := &Source{
		Scope:      topoTestScope,
		Aggregator: foldedAggregator(t, now),
		Catalog:    catalog.Default(),
		Now:        func() time.Time { return now },
	}
	view := src.buildTopology(now)
	if view.StagedLabels {
		t.Fatal("staged_labels = true with no resolver, want false")
	}
	if got := len(edgesOfClass(view, edgeClassLearned)); got != 0 {
		t.Fatalf("learned edges = %d with no resolver, want 0 (all unnamed -> filtered)", got)
	}
	// The decoy ring is still injected (filter-exempt).
	decoys := 0
	for _, n := range view.Nodes {
		if n.Kind == "decoy" {
			decoys++
		}
	}
	if decoys != 5 {
		t.Fatalf("decoy nodes = %d with no resolver, want 5 (ring is filter-exempt)", decoys)
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

// A recent real canary-touch event (Tier>=1) lights a source->decoy edge; the
// touch is filter-EXEMPT even though the touch-src is an unknown-kind node. FIX-2:
// all touching flows AGGREGATE into ONE shared synthesized source node, with one
// edge per touched CanaryType (FlowCount = total touches of that type). Two
// distinct cookies touching planted_credential collapse to one edge of FlowCount=2.
func TestTopologyTouchEdgeFromRealEvent(t *testing.T) {
	now := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "events.db")
	pstore, _, err := persist.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer pstore.Close()
	events := boltevents.New(pstore)

	// Two touches of the SAME decoy by the SAME flow + one OTHER decoy touch by a
	// DIFFERENT flow. Under the aggregate shape: planted_credential edge FlowCount=2
	// (summed), fake_bucket edge FlowCount=1, and BOTH originate from one shared
	// synthesized source node representing the 2 distinct touching flows.
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
		t.Fatalf("decoy_touch edges = %d, want 2 (one per touched CanaryType)", len(touches))
	}
	byID := nodesByID(view)
	// All touch edges must originate from the SINGLE aggregated source node.
	sharedSrc := touchSourceNodeID()
	for _, e := range touches {
		if e.SrcID != sharedSrc {
			t.Fatalf("touch edge src = %q, want the single aggregated node %q", e.SrcID, sharedSrc)
		}
		// Each touch edge must terminate on a decoy node.
		if byID[e.DstID].Kind != "decoy" {
			t.Fatalf("touch edge dst %q is not a decoy node: %+v", e.DstID, byID[e.DstID])
		}
		if e.DstID == decoyNodeID(catalog.TypePlantedCredential) && e.FlowCount != 2 {
			t.Fatalf("planted_credential touch FlowCount = %d, want 2 (two touches summed)", e.FlowCount)
		}
		if e.DstID == decoyNodeID(catalog.TypeFakeBucket) && e.FlowCount != 1 {
			t.Fatalf("fake_bucket touch FlowCount = %d, want 1", e.FlowCount)
		}
	}
	// The single aggregated source node exists, is unknown-kind, and SURVIVES the
	// clean-fabric filter (touch edges are exempt).
	srcNode, ok := byID[sharedSrc]
	if !ok {
		t.Fatalf("aggregated touch-src node %q not injected", sharedSrc)
	}
	if srcNode.Kind != "unknown" {
		t.Fatalf("touch-src node kind = %q, want unknown", srcNode.Kind)
	}
	// Its label reports the distinct-flow count (2 distinct cookies: 0x118, 0x222),
	// honest about WHAT was observed — never "confirmed adversaries".
	if !strings.Contains(srcNode.Label, "2") {
		t.Fatalf("touch-src label = %q, want it to report 2 distinct flows", srcNode.Label)
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

func nodeIDs(v TopologyView) []string {
	out := make([]string, 0, len(v.Nodes))
	for _, n := range v.Nodes {
		out = append(out, n.ID)
	}
	return out
}
