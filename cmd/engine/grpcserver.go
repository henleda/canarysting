package main

import (
	"log"
	"net"

	"google.golang.org/grpc"

	"github.com/canarysting/canarysting/api/enginegrpc"
	"github.com/canarysting/canarysting/internal/contract"
)

// serveGRPC exposes the engine over the api/proto Engine service so an
// out-of-process adapter (the Envoy ext_proc adapter, M4) can submit signals and
// receive verdicts. It wraps the UNCHANGED engine via the contract — the engine
// package itself gains no transport code (CLAUDE.md rule 2). Blocks until the
// listener errors.
func serveGRPC(addr string, eng contract.Engine) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := grpc.NewServer()
	enginegrpc.Register(s, eng)
	log.Printf("engine: gRPC Engine service listening on %s", addr)
	return s.Serve(lis)
}
