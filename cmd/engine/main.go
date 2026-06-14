// Command engine runs the CanarySting decision engine service: it ingests
// signal events over the contract, scores and tiers flows, calibrates from
// feedback, learns a per-scope baseline from the OBSERVE-ONLY eBPF path (M7),
// and emits verdicts. It is proxy-agnostic. See docs/ENGINE.md.
//
// Composition lives in internal/boot (shared with the staging-only
// cmd/staged-range binary). This binary deliberately does NOT import the staged
// ground-truth labeler — a production engine cannot construct one.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/boot"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/engine/scoring"
	"github.com/canarysting/canarysting/internal/transport/grpccreds"
)

func main() {
	var (
		boundary       = flag.String("scope-boundary", "", "operator-defined scope boundary; required where no cluster identity is derivable (standalone). Empty => refuse to start.")
		window         = flag.Duration("window", scoring.DefaultWindow, "scoring correlation window")
		selfcheck      = flag.Bool("selfcheck", false, "submit one synthetic signal event, print the verdict, and exit")
		grpcAddr       = flag.String("grpc-addr", "", "if set, serve the Engine over gRPC at this address for an out-of-process adapter (M4)")
		aggressive     = flag.Bool("aggressive", false, "demo/eval: minimum per-tier confidence so a flow escalates to Jail on fewer distinct touches (uncalibrated cold-start)")
		baselineDB     = flag.String("baseline-db", "", "bbolt path for the durable baseline + interaction event store; empty => in-memory (no durability)")
		observeCgroup  = flag.String("observe-cgroup", "", "cgroup v2 path to attach the OBSERVE-ONLY baseline path (e.g. /sys/fs/cgroup); empty => observe disabled (touch-only)")
		windowBucketer = flag.Bool("window-bucketer", false, "use the coarse M7 learning-window bucketer (8 buckets) instead of the production 168-bucket default")
		maxGap         = flag.Duration("max-coverage-gap", 0, "downtime longer than this forces baseline re-accrual on boot (0 => default)")
		resetSchema    = flag.Bool("baseline-db-reset-on-schema-change", false, "DISCARD the persisted baseline (logged) if its schema version differs from this build, instead of refusing to start")

		// mTLS for the engine gRPC surface (the only out-of-process seam). The
		// surface drives kernel containment, so it is mTLS or fail-closed: set all
		// three to serve mTLS; leave all three empty to serve bare loopback (warned)
		// only — a routable plaintext addr is refused at startup.
		grpcTLSCert     = flag.String("grpc-tls-cert", "", "engine gRPC server certificate (PEM); requires -grpc-tls-key and -grpc-tls-client-ca")
		grpcTLSKey      = flag.String("grpc-tls-key", "", "engine gRPC server private key (PEM)")
		grpcTLSClientCA = flag.String("grpc-tls-client-ca", "", "CA bundle (PEM) every adapter client certificate must chain to (enables mTLS RequireAndVerifyClientCert)")
	)
	flag.Parse()

	built, err := boot.Build(boot.Options{
		Boundary:              *boundary,
		Window:                *window,
		Aggressive:            *aggressive,
		BaselineDBPath:        *baselineDB,
		ObserveCgroup:         *observeCgroup,
		CoarseBucketer:        *windowBucketer,
		Floor:                 observebaseline.DataFloor{MaxCoverageGap: *maxGap},
		ResetOnSchemaMismatch: *resetSchema,
	}, observe.PlatformObserver())
	if err != nil {
		// The refuse-to-start contract: never default to a global scope.
		log.Fatalf("engine: refusing to start: %v", err)
	}
	defer built.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go built.StartAggregator(ctx)

	if *selfcheck {
		runSelfcheck(built.Engine, contract.ScopeKey(*boundary))
		return
	}

	if *grpcAddr != "" {
		tls := grpccreds.ServerConfig{CertFile: *grpcTLSCert, KeyFile: *grpcTLSKey, ClientCAFile: *grpcTLSClientCA}
		if err := serveGRPC(*grpcAddr, built.Engine, built.OutcomeReporter, tls); err != nil {
			log.Fatalf("engine: gRPC server: %v", err)
		}
		return
	}

	log.Printf("engine: ready (scope boundary %q, window %s, observe=%t, db=%q). Pass -grpc-addr to serve the M4 transport.",
		*boundary, *window, *observeCgroup != "", *baselineDB)
	waitForSignal()
	log.Printf("engine: shutting down")
}

func runSelfcheck(eng contract.Engine, scopeKey contract.ScopeKey) {
	v, err := eng.Submit(contract.SignalEvent{
		Flow:      contract.FlowIdentity{SocketCookie: 0xC0FFEE},
		Canary:    contract.CanaryType("selfcheck.decoy"),
		Scope:     scopeKey,
		Timestamp: time.Now(),
	})
	if err != nil {
		log.Fatalf("engine: selfcheck failed: %v", err)
	}
	fmt.Printf("selfcheck verdict: scope=%q tier=%d mode=%d score=%.2f calibrated=%t\n",
		v.Scope, v.Tier, v.Mode, v.Score, v.Calibrated)
}

func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
