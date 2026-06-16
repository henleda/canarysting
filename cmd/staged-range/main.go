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
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/canarysting/canarysting/api/enginegrpc"
	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/boot"
	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/dashboard/tap"
	"github.com/canarysting/canarysting/internal/engine/observebaseline"
	"github.com/canarysting/canarysting/internal/engine/scoring"
	"github.com/canarysting/canarysting/internal/intelligence/stagedlabel"
	"github.com/canarysting/canarysting/internal/topology/identity"
	"github.com/canarysting/canarysting/internal/transport/grpccreds"
)

// simulatedSpoolMarker reports whether the consumed shared spool is flagged as
// SIMULATED peer data via a sibling "<spool>.simulated" marker (written by
// run-sim-peers.sh). This makes the dashboard's "simulated" disclosure travel
// WITH the data, so a forgotten -sim-peers-demo flag can never silently present
// synthetic peers as real customers (honesty hardening). Empty spool -> false.
func simulatedSpoolMarker(spool string) bool {
	if spool == "" {
		return false
	}
	_, err := os.Stat(spool + ".simulated")
	return err == nil
}

func main() {
	var (
		boundary = flag.String("scope-boundary", "", "operator-defined scope boundary; required (refuse to start if empty)")
		window   = flag.Duration("window", scoring.DefaultWindow, "scoring correlation window")
		grpcAddr = flag.String("grpc-addr", ":50052", "serve the Engine over gRPC at this address")

		// mTLS for the engine gRPC surface — same fail-closed posture as cmd/engine.
		grpcTLSCert     = flag.String("grpc-tls-cert", "", "engine gRPC server certificate (PEM); requires -grpc-tls-key and -grpc-tls-client-ca")
		grpcTLSKey      = flag.String("grpc-tls-key", "", "engine gRPC server private key (PEM)")
		grpcTLSClientCA = flag.String("grpc-tls-client-ca", "", "CA bundle (PEM) every adapter client certificate must chain to (enables mTLS RequireAndVerifyClientCert)")
		aggressive      = flag.Bool("aggressive", false, "demo/eval: minimum per-tier confidence (single-touch escalation)")
		demoEscalation  = flag.Bool("demo-escalation", false, "DEMO ONLY: a middle escalation band (Tag@~touch-1, Contain@~3, Jail@~5 at M=1) so a flow DWELLS in the inline attrition (tarpit/maze/poison) for 3-5 touches before the jail — a credible bleed, not the -aggressive single touch. Mutually exclusive with -aggressive; NEVER for production.")
		containInline   = flag.Bool("contain-inline", false, "Tier 2 (Contain) runs INLINE attrition (held tarpit + deception body, real attacker-cost reported) instead of async kernel enforce; Tier 3 stays async kernel-jail")
		jailInline      = flag.Bool("jail-inline", false, "make Tier 3 (Jail) INLINE so the jailed flow's attrition outcome is reported back — which drains the pending jail into RecordJail and emits the D6-3 cross-scope confirmation. Default off (async kernel jail). For STAGED CONTRIBUTOR scopes that must emit confirmations (an async kernel jail drops the socket before any outcome is reported).")
		baselineDB      = flag.String("baseline-db", "", "bbolt path for the durable baseline + interaction event store")
		observeCgroup   = flag.String("observe-cgroup", "", "cgroup v2 path to attach the OBSERVE-ONLY baseline path")
		windowBucketer  = flag.Bool("window-bucketer", true, "use the coarse M7 learning-window bucketer (8 buckets)")
		maxGap          = flag.Duration("max-coverage-gap", 0, "downtime longer than this forces baseline re-accrual on boot")
		resetSchema     = flag.Bool("baseline-db-reset-on-schema-change", false, "DISCARD the persisted baseline (logged) if its schema version differs from this build")
		auditHMACKey    = flag.String("audit-hmac-key", "", "SLICE-A audit chain: path to an HMAC key FILE (read at boot, held OUTSIDE baseline.db, like /etc/canarysting/anthropic.key) that KEYS the tamper-evident audit chain with HMAC-SHA256 — a file-only attacker with DB write access but WITHOUT this key cannot forge a chain Verify accepts (edit/removal/reorder/tail-truncate-then-rewrite-head all detected). EMPTY (default) => the UNKEYED sha256 chain, which catches accidental corruption + naive edits ONLY, not a knowledgeable DB-write adversary; whole-scope erasure is undetected in either mode (needs an external witness; roadmap). Do not commit a key.")
		demoFloor       = flag.Bool("demo-data-floor", false, "DEMO ONLY: relax the baseline data floor's calendar-DAY-SPAN gates (MinCalendarDays 7->2, MinDaysPerBucket 3->1, MinSufficientBuckets 4->1) so the multiplier goes live before the production 7-calendar-day floor. The genuine VOLUME/POPULATION gates (MinFlowsPerBucket=100, MinIdentitiesPerBucket=2, MinP2Samples=50) are UNCHANGED — the baseline is still real, just accrued over fewer days. Logs loudly; NEVER for production.")

		tapAddr = flag.String("dashboard-tap-addr", "", "if set, serve the read-only M8 dashboard data tap (raw JSON) at this HTTP address")

		// Operator KILL-SWITCH admin (token-gated, loopback-only, OFF by default). The
		// deployment-wide enforcement DISARM: engaging it floors every emitted verdict
		// to observe so the adapter halts BOTH attrition and the async kernel jail and
		// releases existing containment. Requires EITHER -killswitch-token-file (legacy
		// single shared token; advisory X-Operator) OR -killswitch-principals-file
		// (B2 PER-IDENTITY TOKEN RBAC: token_sha256 -> {name, role}; verified identity,
		// role gating); principals-file takes precedence if both are set. With neither
		// the endpoint refuses to start (never an unauthenticated kill-switch).
		// Engage/revive are recorded into the tamper-evident audit chain (verified
		// identity + role + auth_via in principals mode). mTLS client-cert identity is
		// the further B2 step (audit SPIFFEID reserved for it).
		ksAdminAddr      = flag.String("killswitch-admin-addr", "", "if set, serve the token-gated operator KILL-SWITCH admin (POST /killswitch/engage|revive, GET /killswitch) at this LOOPBACK address. Requires one of -killswitch-token-file or -killswitch-principals-file. OFF by default; loopback-only.")
		ksTokenFile      = flag.String("killswitch-token-file", "", "LEGACY single-shared-token mode: path to the bearer-token FILE that gates the kill-switch admin (held OUTSIDE baseline.db, like -audit-hmac-key). One of this or -killswitch-principals-file is REQUIRED to enable -killswitch-admin-addr; an empty/missing file refuses to start. The audited operator is the ADVISORY X-Operator header. Ignored if -killswitch-principals-file is also set (principals file wins).")
		ksPrincipalsFile = flag.String("killswitch-principals-file", "", "path to a JSON principals file (token_sha256 -> {name, role}) for PER-IDENTITY kill-switch RBAC; takes precedence over -killswitch-token-file. Expected 0o600, held OUTSIDE baseline.db (like /etc/canarysting/anthropic.key). When set, the kill-switch admin resolves the VERIFIED operator/role from the presented bearer token and X-Operator is IGNORED; viewer role => status only, operator role => status+engage+revive. Tokens are stored HASHED (sha256); issue each operator their raw token out-of-band. Empty/missing/malformed refuses to start (no unauthenticated kill-switch).")
		simPeersDemo     = flag.Bool("sim-peers-demo", false, "DEMO ONLY: mark the consumed cross-customer patterns as SIMULATED (cmd/sim-peers) so the dashboard discloses they came from synthetic peers we operate, not real customers. Auto-detected too if a <shared-spool>.simulated marker is present, so a forgotten flag can't silently present simulated data as real.")
		topoIdents       = flag.String("topology-identities", "", "F1 learned-topology: JSON operator-declared node-identity map (IP/CIDR/port -> name) used to LABEL the topology nodes on /raw/topology (internal/topology/identity). Operator metadata, NOT an engine verdict; the engine knows only hashed adjacency. Nil-tolerant: with no file the topology nodes fall back to IP labels and staged_labels=false. Demo: deploy/m7-window/topology-identities.json.")

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

		// SLICE 2 one-way SIEM/SOAR emitter (operator-facing LOCAL alert stream; OFF by
		// default). It drains the LOCAL-RICH l7events store per scope and pushes one event
		// per canary touch to the operator's OWN SIEM/SOAR. It is NOT the cross-customer
		// feed and never routes through internal/intelligence/network (rule 9).
		siemFormat   = flag.String("siem-format", "off", "SLICE 2 one-way SIEM emitter format: off (default, inert) | stdout (NDJSON to the log) | json|webhook (HTTP POST to -siem-endpoint) | cef (CEF single line). The event is LOCAL-RICH (raw src/path/SPIFFE) and goes to YOUR OWN SIEM — never the cross-customer feed; do not point a webhook at a shared/third-party endpoint expecting anonymization.")
		siemEndpoint = flag.String("siem-endpoint", "", "SLICE 2: webhook / Splunk-HEC URL for -siem-format json|webhook (one-way POST). Empty with a network format fails safe back to off.")
		siemHECToken = flag.String("siem-hec-token", "", "SLICE 2: optional Splunk HEC token sent as 'Authorization: Splunk <token>' on the webhook POST.")
		siemInterval = flag.Duration("siem-interval", 0, "SLICE 2: SIEM emitter poll cadence (0 => default 5s). Keep short relative to a touch spray so a record is emitted before the per-scope cap can evict it.")
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
	if *aggressive && *demoEscalation {
		log.Fatal("staged-range: refusing to start — -aggressive and -demo-escalation are mutually exclusive (single-touch vs the 3-5-touch dwell band)")
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
		DemoEscalation:        *demoEscalation,
		ContainInline:         *containInline,
		JailInline:            *jailInline,
		BaselineDBPath:        *baselineDB,
		ObserveCgroup:         *observeCgroup,
		CoarseBucketer:        *windowBucketer,
		Floor:                 floor,
		ResetOnSchemaMismatch: *resetSchema,
		AuditHMACKeyPath:      *auditHMACKey,
		Contribute:            *contribute,
		ScopeToken:            *scopeToken,
		ConfirmSpoolPath:      *confirmSpool,
		Consume:               *consume,
		SharedSpoolPath:       *sharedSpool,
		SIEMFormat:            *siemFormat,
		SIEMEndpoint:          *siemEndpoint,
		SIEMHECToken:          *siemHECToken,
		SIEMInterval:          *siemInterval,
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
	// SLICE 2: the one-way SIEM/SOAR drain. Off unless -siem-format selects a real
	// sink; otherwise the Built.SIEM handle is nil and this is a no-op. It runs OFF the
	// verdict hot path (rule 8) and never reaches the cross-customer egress path (rule 9).
	go built.StartSIEMEmitter(ctx)

	// Read-only data tap for the M8 dashboard-backend (the engine owns the live
	// state + the locked EventStore). It serves raw JSON only; all presentation is
	// in the separate dashboard-backend.
	if *tapAddr != "" {
		// F1 topology node labeler (internal/topology/identity). NIL-TOLERANT: with
		// no -topology-identities file the resolver is left nil and the tap degrades
		// every node to its IP label (staged_labels=false). A present-but-unparseable
		// file is a fatal misconfig — an operator map with a typo must not silently
		// mis-name (or drop) a node.
		var topoResolver *identity.Resolver
		if *topoIdents != "" {
			cfg, err := identity.LoadConfigFile(*topoIdents)
			if err != nil {
				log.Fatalf("staged-range: -topology-identities: %v", err)
			}
			topoResolver = identity.NewResolver(cfg)
			log.Printf("staged-range: topology node labeler loaded from %q (%d entries)", *topoIdents, len(cfg.Entries))
		}
		src := &tap.Source{
			Scope: contract.ScopeKey(*boundary), Calib: built.Calib,
			Baseline: built.Baseline, Events: built.Events, Aggregator: built.Aggregator,
			SharedSet: built.SharedSet, SimulatedPeers: *simPeersDemo || simulatedSpoolMarker(*sharedSpool),
			Resolver: topoResolver,
			// Drive the decoy ring from the authoritative catalog (same source the
			// seeder plants from) instead of the tap's hardcoded nil-tolerance
			// fallback, so the rendered decoys can never silently diverge from the
			// canary types actually in play. cmd/envoy-adapter wires this too.
			Catalog: catalog.Default(),
			// SLICE B1: surface the deployment-wide enforcement-disarm status read-only
			// (the dashboard renders "ENFORCEMENT HALTED by <op>"). The tap NEVER mutates
			// it — the only write path is the token-gated admin endpoint above.
			KillSwitch: built.KillSwitch,
		}
		// DEVIANT ACK/SUPPRESS: the READ-ONLY operator triage overlay so the deviants
		// surface can join+badge acked/suppressed state per row. Set ONLY when a durable
		// store exists — assigning a typed-nil *persist.Store into the interface would
		// make the field non-nil-interface-over-nil-pointer (s.Triage != nil but a nil
		// receiver), which would panic in RangeDeviantTriage. Leaving it the nil
		// interface keeps the tap's nil-tolerant path (every row reads normal). The tap
		// only READS it; the only write path is the token-gated admin endpoint above.
		if built.Persist != nil {
			src.Triage = built.Persist
		}
		go func() {
			log.Printf("staged-range: dashboard tap on %s", *tapAddr)
			if err := http.ListenAndServe(*tapAddr, src.Handler()); err != nil {
				log.Printf("staged-range: dashboard tap: %v", err)
			}
		}()
	}

	// SLICE B1/B2: the operator KILL-SWITCH admin (loopback-only). OFF unless
	// -killswitch-admin-addr is set; when set it REQUIRES one of -killswitch-token-file
	// (B1 single shared token, advisory operator) or -killswitch-principals-file (B2
	// per-identity token RBAC + roles, verified operator) and a loopback bind, else it
	// refuses to start (fail-closed — never an unauthenticated or off-box kill-switch).
	// A bind/auth misconfig is fatal so the operator learns at boot, not on the first
	// failed engage. The handler couples each engage/revive to the tamper-evident audit
	// chain via boot.Built.
	if *ksAdminAddr != "" {
		// Validate the bind + auth source BEFORE backgrounding so a misconfig is a clean
		// boot failure (not a goroutine that dies silently). newKillSwitchAdmin applies
		// the precedence (principals-file > token-file > fail-closed-if-neither) and
		// surfaces a missing/empty/malformed source synchronously. serveKillSwitchAdmin
		// re-checks.
		if _, err := newKillSwitchAdmin(built, *ksTokenFile, *ksPrincipalsFile); err != nil {
			log.Fatalf("staged-range: %v", err)
		}
		if err := requireLoopback(*ksAdminAddr); err != nil {
			log.Fatalf("staged-range: %v", err)
		}
		go func() {
			if err := serveKillSwitchAdmin(*ksAdminAddr, *ksTokenFile, *ksPrincipalsFile, built); err != nil {
				log.Printf("staged-range: killswitch admin: %v", err)
			}
		}()
	}

	log.Printf("staged-range: ███ STAGED RANGE — AUTO-LABELING ENABLED ███ scope=%q registry=%q observe=%t db=%q",
		*boundary, *registryPath, *observeCgroup != "", *baselineDB)

	eng := labelingEngine{inner: built.Engine, labeler: labeler}
	tls := grpccreds.ServerConfig{CertFile: *grpcTLSCert, KeyFile: *grpcTLSKey, ClientCAFile: *grpcTLSClientCA}
	if err := serveGRPC(*grpcAddr, eng, built.OutcomeReporter, tls); err != nil {
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
		// B1: feed the labeler the RESOLVED scope (v.Scope), never the raw wire
		// ev.Scope. The inner engine resolves the scope from the flow and ignores a
		// disagreeing wire scope; the labeler keys its disposition lookup AND the
		// feedback label it writes on ev.Scope, so a forged wire scope would land a
		// cross-scope learned-state write (defeats rule 5). Correct the event first.
		ev.Scope = v.Scope
		e.labeler.OnVerdict(ev, v)
	}
	return v, err
}

// serveGRPC mirrors cmd/engine's transport posture: mTLS when tls names a
// cert/key/client-CA, else fail-closed on a routable addr (bare loopback warned).
// The staged range still exposes the same containment-driving surface, so it gets
// the same protection.
func serveGRPC(addr string, eng contract.Engine, reporter contract.OutcomeReporter, tls grpccreds.ServerConfig) error {
	opts, posture, bareLoopback, err := grpccreds.ServerOption(addr, tls)
	if err != nil {
		return fmt.Errorf("staged-range: gRPC transport: %w", err)
	}
	if bareLoopback {
		log.Printf("staged-range: WARNING serving gRPC in PLAINTEXT on loopback %s — no mTLS. Configure -grpc-tls-cert/-key/-client-ca for any non-loopback or shared-host deployment.", addr)
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := grpc.NewServer(opts...)
	enginegrpc.Register(s, eng, reporter)
	log.Printf("staged-range: gRPC Engine service listening on %s (%s)", addr, posture)
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
