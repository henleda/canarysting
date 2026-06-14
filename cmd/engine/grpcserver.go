package main

import (
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	"github.com/canarysting/canarysting/api/enginegrpc"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/transport/grpccreds"
)

// serveGRPC exposes the engine over the api/proto Engine service so an
// out-of-process adapter (the Envoy ext_proc adapter, M4) can submit signals and
// receive verdicts. It wraps the UNCHANGED engine via the contract — the engine
// package itself gains no transport code (CLAUDE.md rule 2). reporter is the
// optional adapter-side attrition-outcome intake (nil when no EventStore is
// wired; the server acks without durable capture).
//
// SECURITY: this surface drives kernel containment (rules 4 + 8). When tls names
// a cert/key/client-CA it serves mTLS (RequireAndVerifyClientCert) so only a
// holder of a CA-signed client cert can submit. When TLS is NOT configured it
// refuses to serve a routable address in plaintext (fail-closed); bare loopback
// is allowed only with a loud WARNING. Blocks until the listener errors.
func serveGRPC(addr string, eng contract.Engine, reporter contract.OutcomeReporter, tls grpccreds.ServerConfig) error {
	opts, posture, bareLoopback, err := grpccreds.ServerOption(addr, tls)
	if err != nil {
		return fmt.Errorf("engine: gRPC transport: %w", err)
	}
	if bareLoopback {
		log.Printf("engine: WARNING serving gRPC in PLAINTEXT on loopback %s — no mTLS. Anyone on this host can forge a SignalEvent and drive a kernel jail. Configure -grpc-tls-cert/-key/-client-ca for any non-loopback or shared-host deployment.", addr)
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := grpc.NewServer(opts...)
	enginegrpc.Register(s, eng, reporter)
	log.Printf("engine: gRPC Engine service listening on %s (%s)", addr, posture)
	return s.Serve(lis)
}
