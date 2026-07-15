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
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/boot"
	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/dashboard/tap"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/engine/scoring"
	"github.com/canarysting/canarysting/internal/transport/grpccreds"
)

// buildEngineOptions maps the three inline demo/escalation flags onto the
// identically named boot.Options fields (boot.go:75,81,90) and enforces the
// same -aggressive/-demo-escalation mutual exclusion cmd/staged-range/main.go:137-139
// already guards. The caller merges the returned fields into the Options it
// builds from the remaining flags (Boundary, Window, BaselineDBPath, etc).
func buildEngineOptions(aggressive, demoEscalation, containInline, jailInline bool) (boot.Options, error) {
	if aggressive && demoEscalation {
		return boot.Options{}, errors.New("engine: -aggressive and -demo-escalation are mutually exclusive (single-touch vs the 3-5-touch dwell band)")
	}
	return boot.Options{
		Aggressive:     aggressive,
		DemoEscalation: demoEscalation,
		ContainInline:  containInline,
		JailInline:     jailInline,
	}, nil
}

func main() {
	var (
		boundary       = flag.String("scope-boundary", "", "operator-defined scope boundary; required where no cluster identity is derivable (standalone). Empty => refuse to start.")
		window         = flag.Duration("window", scoring.DefaultWindow, "scoring correlation window")
		selfcheck      = flag.Bool("selfcheck", false, "submit one synthetic signal event, print the verdict, and exit")
		grpcAddr       = flag.String("grpc-addr", "", "if set, serve the Engine over gRPC at this address for an out-of-process adapter (M4)")
		aggressive     = flag.Bool("aggressive", false, "demo/eval: minimum per-tier confidence so a flow escalates to Jail on fewer distinct touches (uncalibrated cold-start)")
		demoEscalation = flag.Bool("demo-escalation", false, "DEMO ONLY: a middle escalation band (Tag@~touch-1, Contain@~3, Jail@~5 at M=1) so a flow DWELLS in the inline attrition (tarpit/maze/poison) for 3-5 touches before the jail — a credible bleed, not the -aggressive single touch. Mutually exclusive with -aggressive; NEVER for production.")
		containInline  = flag.Bool("contain-inline", false, "Tier 2 (Contain) runs INLINE attrition (held tarpit + deception body, real attacker-cost reported) instead of async kernel enforce; Tier 3 stays async kernel-jail")
		jailInline     = flag.Bool("jail-inline", false, "make Tier 3 (Jail) INLINE so the jailed flow's attrition outcome is reported back — which drains the pending jail into RecordJail and emits the D6-3 cross-scope confirmation. Default off (async kernel jail). For STAGED CONTRIBUTOR scopes that must emit confirmations (an async kernel jail drops the socket before any outcome is reported).")
		baselineDB     = flag.String("baseline-db", "", "bbolt path for the durable baseline + interaction event store; empty => in-memory (no durability)")
		observeCgroup  = flag.String("observe-cgroup", "", "cgroup v2 path to attach the OBSERVE-ONLY baseline path (e.g. /sys/fs/cgroup); empty => observe disabled (touch-only)")
		windowBucketer = flag.Bool("window-bucketer", false, "use the coarse M7 learning-window bucketer (8 buckets) instead of the production 168-bucket default")
		maxGap         = flag.Duration("max-coverage-gap", 0, "downtime longer than this forces baseline re-accrual on boot (0 => default)")
		resetSchema    = flag.Bool("baseline-db-reset-on-schema-change", false, "DISCARD the persisted baseline (logged) if its schema version differs from this build, instead of refusing to start")

		tapAddr = flag.String("dashboard-tap-addr", "", "if set, serve the read-only M8 dashboard data tap (raw JSON) at this HTTP address")

		// mTLS for the engine gRPC surface (the only out-of-process seam). The
		// surface drives kernel containment, so it is mTLS or fail-closed: set all
		// three to serve mTLS; leave all three empty to serve bare loopback (warned)
		// only — a routable plaintext addr is refused at startup.
		grpcTLSCert     = flag.String("grpc-tls-cert", "", "engine gRPC server certificate (PEM); requires -grpc-tls-key and -grpc-tls-client-ca")
		grpcTLSKey      = flag.String("grpc-tls-key", "", "engine gRPC server private key (PEM)")
		grpcTLSClientCA = flag.String("grpc-tls-client-ca", "", "CA bundle (PEM) every adapter client certificate must chain to (enables mTLS RequireAndVerifyClientCert)")
	)
	flag.Parse()

	inlineOpts, err := buildEngineOptions(*aggressive, *demoEscalation, *containInline, *jailInline)
	if err != nil {
		log.Fatalf("engine: refusing to start: %v", err)
	}

	built, err := boot.Build(boot.Options{
		Boundary:              *boundary,
		Window:                *window,
		Aggressive:            inlineOpts.Aggressive,
		DemoEscalation:        inlineOpts.DemoEscalation,
		ContainInline:         inlineOpts.ContainInline,
		JailInline:            inlineOpts.JailInline,
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

	// Read-only data tap for the M8 dashboard-backend (the engine owns the live
	// state + the locked EventStore). Mirrors cmd/staged-range's wiring; serves
	// raw JSON only, all presentation lives in the separate dashboard-backend.
	if *tapAddr != "" {
		src := &tap.Source{
			Scope:      contract.ScopeKey(*boundary),
			Calib:      built.Calib,
			Baseline:   built.Baseline,
			Events:     built.Events,
			Aggregator: built.Aggregator,
			SharedSet:  built.SharedSet,
			Catalog:    catalog.Default(),
			KillSwitch: built.KillSwitch,
		}
		if built.Persist != nil {
			src.Triage = built.Persist
		}
		go func() {
			log.Printf("engine: dashboard tap on %s", *tapAddr)
			if err := http.ListenAndServe(*tapAddr, src.Handler()); err != nil {
				log.Printf("engine: dashboard tap: %v", err)
			}
		}()
	}

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
