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
	"github.com/canarysting/canarysting/internal/canary/seeder"
	"github.com/canarysting/canarysting/internal/contract"
)

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

	// The placement registry is shared with the canary seeder in the full demo
	// (M4 on-box / M7 continuous seeding); here it is the live lookup surface.
	reg := seeder.NewMemRegistry()

	resolver, err := newResolver()
	if err != nil {
		log.Fatalf("envoy-adapter: cookie resolver: %v", err)
	}
	defer resolver.Close()

	a, err := envoy.New(envoy.Config{
		Engine:   eng,
		Registry: reg,
		Resolver: resolver,
		Scope:    contract.ScopeKey(*scopeFlag),
		Inline:   *inline,
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
