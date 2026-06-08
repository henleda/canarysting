// Command envoy-adapter is the out-of-process composition root for the M4 Envoy
// ext_proc adapter: it dials the engine over gRPC (presenting it back as a
// contract.Engine), wires the placement registry and the kernel CookieResolver,
// builds the thin adapter, and serves the ext_proc service Envoy connects to.
// This binary runs on the demo host (Linux); the kernel-backed CookieResolver is
// build-tagged and lands in the M4 on-box phase. The local pure-Go path is proven
// by cmd/envoy-selfcheck.
package main

import (
	"flag"
	"log"
	"net"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/canarysting/canarysting/adapters/envoy"
	"github.com/canarysting/canarysting/api/enginegrpc"
	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/canary/seeder"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

// enforcer programs kernel containment for an attributed flow. Its construction
// is build-tagged (real on Linux, no-op elsewhere) so cilium/ebpf stays out of
// the adapter's import closure — only this composition root touches it.
type enforcer interface {
	Apply(contract.Verdict, containment.Action) error
	Close() error
}

// demoCanaryPaths pins canary types to negative-space HTTP paths — paths a
// legitimate flow never requests, so a touch is almost certainly hostile
// (docs/ROADMAP §1). The M3 seeder places real harmless decoys at these
// locations; the adapter recognizes a touch by the path.
var demoCanaryPaths = map[contract.CanaryType][]seeder.Location{
	catalog.TypePlantedCredential: {"/.aws/credentials"},
	catalog.TypeFakeSecret:        {"/.env"},
	catalog.TypeDecoyFile:         {"/backup/db.sql"},
	catalog.TypeFakeBucket:        {"/internal/buckets"},
	catalog.TypeFakeEndpoint:      {"/admin/metrics"},
}

// seedCanaries places the demo canaries in the negative space and returns the
// registry the adapter looks up against.
func seedCanaries(scope contract.ScopeKey) (seeder.Registry, error) {
	sd, err := seeder.New(seeder.Config{
		Catalog: catalog.Default(),
		Planner: seeder.BroadPlanner{Locations: demoCanaryPaths},
	})
	if err != nil {
		return nil, err
	}
	if err := sd.Seed(scope, seeder.Minefield); err != nil {
		return nil, err
	}
	return sd.Registry(), nil
}

func main() {
	var (
		listen     = flag.String("listen", ":50051", "ext_proc gRPC listen address (Envoy connects here)")
		engineAddr = flag.String("engine", "localhost:50052", "engine gRPC address (cmd/engine -grpc-addr)")
		scopeFlag  = flag.String("scope", "", "resolved scope key; REQUIRED — never a global scope")
		inline     = flag.Bool("inline", true, "inline enforcement (hold canary touches for the verdict)")
	)
	flag.Parse()
	if *scopeFlag == "" {
		log.Fatal("envoy-adapter: -scope is required (the adapter never falls back to a global scope)")
	}

	cc, err := grpc.NewClient(*engineAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("envoy-adapter: dialing engine %s: %v", *engineAddr, err)
	}
	defer cc.Close()
	eng := enginegrpc.NewClient(cc, 200*time.Millisecond)

	// Seed the negative-space canaries into the registry the adapter looks up.
	reg, err := seedCanaries(contract.ScopeKey(*scopeFlag))
	if err != nil {
		log.Fatalf("envoy-adapter: seeding canaries: %v", err)
	}

	resolver, err := newResolver()
	if err != nil {
		log.Fatalf("envoy-adapter: cookie resolver: %v", err)
	}
	defer resolver.Close()

	enf, err := newEnforcer()
	if err != nil {
		log.Fatalf("envoy-adapter: kernel enforcer: %v", err)
	}
	defer enf.Close()

	a, err := envoy.New(envoy.Config{
		Engine:   eng,
		Registry: reg,
		Resolver: resolver,
		Scope:    contract.ScopeKey(*scopeFlag),
		Inline:   *inline,
		OnVerdict: func(ev contract.SignalEvent, v contract.Verdict) {
			log.Printf("CANARY TOUCH scope=%s canary=%s cookie=%#x tier=%d mode=%d score=%.2f",
				ev.Scope, ev.Canary, ev.Flow.SocketCookie, v.Tier, v.Mode, v.Score)
			// The verdict->kernel seam lives HERE (not in the thin adapter). Async
			// Tier 2/3 is enforced in the kernel keyed by the SAME socket cookie;
			// inline tiers were already actioned at the proxy (verdict.go).
			if v.Mode != contract.ModeAsync || v.Flow.SocketCookie == 0 {
				return
			}
			act, ok := containment.ActionForTier(v.Tier)
			if !ok {
				return
			}
			if err := enf.Apply(v, act); err != nil {
				log.Printf("containment: %v", err)
			}
		},
	})
	if err != nil {
		log.Fatalf("envoy-adapter: %v", err)
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("envoy-adapter: listen %s: %v", *listen, err)
	}
	s := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(s, a)
	log.Printf("envoy-adapter: ext_proc on %s -> engine %s, scope %q, inline=%t", *listen, *engineAddr, *scopeFlag, *inline)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("envoy-adapter: serve: %v", err)
	}
}
