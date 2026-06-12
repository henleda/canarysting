// Command staged-range is the STAGING-ONLY variant of the decision engine for the
// M7 learning window. It is identical to cmd/engine except that it additionally
// wires the staged ground-truth labeler: it turns canary-touch verdicts from
// declared identities into real feedback labels, so a scope legitimately reaches
// calibrated mode during the window without a human in the loop and without
// fabricated data. See internal/intelligence/stagedlabel for the honesty
// argument and the production-safety design.
//
// This is a SEPARATE binary from cmd/engine on purpose: the production engine's
// dependency closure never reaches the labeler (an import-graph guard enforces
// it), so it cannot construct one. To run this binary you must pass a self-
// incriminating flag AND a ground-truth registry; without both it refuses to
// start. These are gates 1, 3, and the loud banner of the labeler's defense in
// depth (gates 2 and 4 — enabled-by-default-off and label-only-on-a-real-verdict
// — live in the package itself).
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"

	"github.com/canarysting/canarysting/api/enginegrpc"
	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/boot"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/dashboard/tap"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/engine/scoring"
	"github.com/canarysting/canarysting/internal/intelligence/stagedlabel"
)

func main() {
	var (
		boundary       = flag.String("scope-boundary", "", "operator-defined scope boundary; required (refuse to start if empty)")
		window         = flag.Duration("window", scoring.DefaultWindow, "scoring correlation window")
		grpcAddr       = flag.String("grpc-addr", ":50052", "serve the Engine over gRPC at this address")
		aggressive     = flag.Bool("aggressive", false, "demo/eval: minimum per-tier confidence (cold-start escalation)")
		containInline  = flag.Bool("contain-inline", false, "Tier 2 (Contain) runs INLINE attrition (held tarpit + deception body, real attacker-cost reported) instead of async kernel enforce; Tier 3 stays async kernel-jail")
		baselineDB     = flag.String("baseline-db", "", "bbolt path for the durable baseline + interaction event store")
		observeCgroup  = flag.String("observe-cgroup", "", "cgroup v2 path to attach the OBSERVE-ONLY baseline path")
		windowBucketer = flag.Bool("window-bucketer", true, "use the coarse M7 learning-window bucketer (8 buckets)")
		maxGap         = flag.Duration("max-coverage-gap", 0, "downtime longer than this forces baseline re-accrual on boot")
		resetSchema    = flag.Bool("baseline-db-reset-on-schema-change", false, "DISCARD the persisted baseline (logged) if its schema version differs from this build")
		demoFloor      = flag.Bool("demo-data-floor", false, "DEMO ONLY: relax the baseline data floor's calendar-DAY-SPAN gates (MinCalendarDays 7->2, MinDaysPerBucket 3->1, MinSufficientBuckets 4->1) so the multiplier goes live before the production 7-calendar-day floor. The genuine VOLUME/POPULATION gates (MinFlowsPerBucket=100, MinIdentitiesPerBucket=2, MinP2Samples=50) are UNCHANGED — the baseline is still real, just accrued over fewer days. Logs loudly; NEVER for production.")

		tapAddr = flag.String("dashboard-tap-addr", "", "if set, serve the read-only M8 dashboard data tap (raw JSON) at this HTTP address")

		registryPath = flag.String("ground-truth-registry", "", "REQUIRED: JSON file declaring legit vs attacker source IPs per scope")
		iAmStaged    = flag.Bool("i-am-running-a-staged-range", false, "REQUIRED acknowledgement: this binary auto-labels from declared ground truth and must NEVER run in production")

		// D6 cross-customer network (independent opt-in toggles; default off). Producer half:
		// -contribute records each local Tier-3 jail's coarse pattern into the cross-scope
		// ledger and, with -scope-token + -confirm-spool, emits a confirmation to the central
		// D6-3 aggregator under the OPAQUE token (never the raw scope key). Consumer half:
		// -consume loads cleared cross-customer patterns from -shared-spool to sharpen M for
		// matching local flows (detection context only, rule 8 — never a trigger on its own).
		contribute   = flag.Bool("contribute", false, "D6: record each local Tier-3 jail's coarse pattern into the cross-scope ledger AND (with -scope-token + -confirm-spool) emit a confirmation to the central aggregator. Default off.")
		scopeToken   = flag.String("scope-token", "", "D6-3: this deployment's OPAQUE aggregator-issued cross-scope token (NEVER the scope key). Required with -contribute.")
		confirmSpool = flag.String("confirm-spool", "", "D6-3: NDJSON confirmation spool written on each local jail (this deployment -> central aggregator). Required with -contribute.")
		consume      = flag.Bool("consume", false, "D6: load cleared cross-customer patterns from -shared-spool to sharpen M for matching local flows (detection context only, rule 8). Default off.")
		sharedSpool  = flag.String("shared-spool", "", "D6: NDJSON spool of cleared cross-customer patterns to load at boot. Required with -consume.")
	)
	flag.Parse()

	if !*iAmStaged {
		log.Fatal("staged-range: refusing to start — pass -i-am-running-a-staged-range to acknowledge this binary auto-labels feedback from declared ground truth (it must never run in production)")
	}
	if *registryPath == "" {
		log.Fatal("staged-range: refusing to start — -ground-truth-registry is required (no registry => nothing to label, and a fail-safe against silent production labeling)")
	}
	// D6-3 fail-closed: mirror boot.go's three-condition emit gate so a misconfig can't
	// silently jail-locally-but-emit-nothing (the boot gate fails open by not wiring the spool).
	if *contribute && (*scopeToken == "" || *confirmSpool == "") {
		log.Fatal("staged-range: refusing to start — -contribute requires BOTH -scope-token and -confirm-spool (else local jails record but emit no confirmation to the aggregator)")
	}
	if *consume && *sharedSpool == "" {
		log.Fatal("staged-range: refusing to start — -consume requires -shared-spool (else there is nothing to consume; refuse rather than silently no-op)")
	}

	reg, err := stagedlabel.LoadRegistryFile(*registryPath)
	if err != nil {
		log.Fatalf("staged-range: %v", err)
	}

	floor := buildDataFloor(*demoFloor, *maxGap)
	if *demoFloor {
		log.Printf("staged-range: ⚠ DEMO DATA FLOOR ACTIVE — calendar-day-span gates relaxed (MinCalendarDays=2, MinDaysPerBucket=1, MinSufficientBuckets=1); the volume/population gates are UNCHANGED. This is NOT the production 7-calendar-day floor; demo only.")
	}

	built, err := boot.Build(boot.Options{
		Boundary:              *boundary,
		Window:                *window,
		Aggressive:            *aggressive,
		ContainInline:         *containInline,
		BaselineDBPath:        *baselineDB,
		ObserveCgroup:         *observeCgroup,
		CoarseBucketer:        *windowBucketer,
		Floor:                 floor,
		ResetOnSchemaMismatch: *resetSchema,
		Contribute:            *contribute,
		ScopeToken:            *scopeToken,
		ConfirmSpoolPath:      *confirmSpool,
		Consume:               *consume,
		SharedSpoolPath:       *sharedSpool,
	}, observe.PlatformObserver())
	if err != nil {
		log.Fatalf("staged-range: refusing to start: %v", err)
	}
	defer built.Close()

	// Mark every declared attacker source into the baseline-of-normal exclusion
	// BEFORE the aggregator starts folding, so an attacker can never teach the
	// baseline that its behavior is normal. (Requires observe enabled.)
	if built.Malicious != nil {
		for _, sc := range reg.Scopes() {
			for _, addr := range reg.AttackerAddrs(sc) {
				if err := built.Malicious.MarkAddr(sc, addr); err != nil {
					log.Fatalf("staged-range: marking attacker %s: %v", addr, err)
				}
			}
		}
	} else {
		log.Printf("staged-range: WARNING observe is disabled (no -observe-cgroup); the attacker will be labeled but NOT excluded from the baseline-of-normal")
	}

	// The labeler fires on each real canary-touch verdict and submits a real
	// feedback label through the engine's single feedback seam.
	labeler := stagedlabel.NewLabeler(reg, built.Intake, true)
	labeler.OnUndeclared(func(addr string) {
		log.Printf("staged-range: verdict from UNDECLARED source %q — not labeled (fail-safe)", addr)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go built.StartAggregator(ctx)

	// Read-only data tap for the M8 dashboard-backend (the engine owns the live
	// state + the locked EventStore). It serves raw JSON only; all presentation is
	// in the separate dashboard-backend.
	if *tapAddr != "" {
		src := &tap.Source{
			Scope: contract.ScopeKey(*boundary), Calib: built.Calib,
			Baseline: built.Baseline, Events: built.Events, Aggregator: built.Aggregator,
		}
		go func() {
			log.Printf("staged-range: dashboard tap on %s", *tapAddr)
			if err := http.ListenAndServe(*tapAddr, src.Handler()); err != nil {
				log.Printf("staged-range: dashboard tap: %v", err)
			}
		}()
	}

	log.Printf("staged-range: ███ STAGED RANGE — AUTO-LABELING ENABLED ███ scope=%q registry=%q observe=%t db=%q",
		*boundary, *registryPath, *observeCgroup != "", *baselineDB)

	eng := labelingEngine{inner: built.Engine, labeler: labeler}
	if err := serveGRPC(*grpcAddr, eng, built.OutcomeReporter); err != nil {
		log.Fatalf("staged-range: gRPC server: %v", err)
	}
}

// labelingEngine wraps the composed engine to fire the staged labeler after each
// real verdict. A label is only ever produced in response to a real canary-touch
// verdict (rule 8) — there is no path here that fabricates a decision.
type labelingEngine struct {
	inner   contract.Engine
	labeler *stagedlabel.Labeler
}

func (e labelingEngine) Submit(ev contract.SignalEvent) (contract.Verdict, error) {
	v, err := e.inner.Submit(ev)
	if err == nil {
		e.labeler.OnVerdict(ev, v)
	}
	return v, err
}

func serveGRPC(addr string, eng contract.Engine, reporter contract.OutcomeReporter) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := grpc.NewServer()
	enginegrpc.Register(s, eng, reporter)
	log.Printf("staged-range: gRPC Engine service listening on %s", addr)
	return s.Serve(lis)
}

// buildDataFloor returns the eBPF data floor for this run. The zero fields are filled
// with the genuine production defaults by DataFloor.Normalized() in the aggregator
// (MinFlowsPerBucket=100, MinIdentitiesPerBucket=2, MinP2Samples=50, MinCalendarDays=7).
// When demo is true it relaxes ONLY the calendar-DAY-SPAN gates so the multiplier can go
// live before the production 7-calendar-day floor — the VOLUME/POPULATION/statistical
// gates are left zero (=> genuine defaults), so the baseline is still real (100+ flows,
// 2+ callers, 50+ P² samples per bucket), just accrued over fewer days. Demo only.
func buildDataFloor(demo bool, maxGap time.Duration) observebaseline.DataFloor {
	f := observebaseline.DataFloor{MaxCoverageGap: maxGap}
	if demo {
		f.MinCalendarDays = 2
		f.MinDaysPerBucket = 1
		f.MinSufficientBuckets = 1
	}
	return f
}
