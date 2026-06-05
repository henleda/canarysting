// Command engine runs the CanarySting decision engine service: it ingests
// signal events over the contract, scores and tiers flows, calibrates from
// feedback, and emits verdicts. It is proxy-agnostic. See docs/ENGINE.md.
//
// M1 wires the in-process engine and the refuse-to-start path. The out-of-
// process transport (api/proto) lands with the Envoy adapter (M4); until then
// the engine is consumed in-process and this command validates configuration,
// reports readiness, and (with -selfcheck) exercises one end-to-end verdict.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine"
	"github.com/canarysting/canarysting/internal/engine/baseline"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/feedback"
	"github.com/canarysting/canarysting/internal/engine/scope"
	"github.com/canarysting/canarysting/internal/engine/scoring"
	"github.com/canarysting/canarysting/internal/engine/tiers"
)

func main() {
	var (
		boundary  = flag.String("scope-boundary", "", "operator-defined scope boundary; required where no cluster identity is derivable (standalone). Empty => refuse to start.")
		window    = flag.Duration("window", scoring.DefaultWindow, "scoring correlation window")
		selfcheck = flag.Bool("selfcheck", false, "submit one synthetic signal event, print the verdict, and exit")
	)
	flag.Parse()

	eng, intake, err := build(*boundary, *window)
	if err != nil {
		// The refuse-to-start contract: never default to a global scope. A
		// standalone deployment with no boundary fails loud here.
		log.Fatalf("engine: refusing to start: %v", err)
	}
	_ = intake // wired for the feedback path; used by the transport (M4) and tests.

	if *selfcheck {
		runSelfcheck(eng, contract.ScopeKey(*boundary))
		return
	}

	log.Printf("engine: ready (scope boundary %q, window %s). Awaiting transport (M4); in-process engine live.", *boundary, *window)
	waitForSignal()
	log.Printf("engine: shutting down")
}

// build wires the engine from operator config and returns the engine and the
// feedback intake. It returns scope.ErrUnresolved (wrapped) if no scope can be
// resolved — the caller must treat that as fatal.
func build(boundary string, window time.Duration) (*engine.Service, *feedback.Intake, error) {
	resolver, err := scope.NewStaticResolver(scope.Config{
		// M1: no mesh/k8s cluster identity source yet, so a standalone
		// deployment must set an operator boundary or we refuse to start.
		Boundary: contract.ScopeKey(boundary),
	})
	if err != nil {
		return nil, nil, err
	}

	calib := calibration.New(calibration.Config{})
	// The baseline multiplier is gated to the SAME evidence floor as the canary
	// weights, so M and the learned weights go live together (never one without
	// the other). Until the eBPF baseline accrues (M7), every scope is not-live
	// and M stays 1.0 — touch-only scoring.
	base := baseline.New(baseline.Config{
		Calibrated: func(s contract.ScopeKey) bool { return calib.State(s).Calibrated },
	})
	scorer := scoring.New(window, calib, scoring.NoExclusions{}).UseMultiplier(base)

	eng, err := engine.New(engine.Config{
		Resolver:    resolver,
		Scorer:      scorer,
		Decider:     tiers.StaticDecider{},
		Tiers:       tiers.DefaultConfig(),
		Calibration: calib,
	})
	if err != nil {
		return nil, nil, err
	}
	return eng, feedback.NewIntake(calib), nil
}

func runSelfcheck(eng *engine.Service, scopeKey contract.ScopeKey) {
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
