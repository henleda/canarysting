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
	"github.com/canarysting/canarysting/internal/sting/attrition"
	"github.com/canarysting/canarysting/internal/sting/containment"
)

// enforcer programs kernel containment for an attributed flow. Its construction
// is build-tagged (real on Linux, no-op elsewhere) so cilium/ebpf stays out of
// the adapter's import closure — only this composition root touches it.
type enforcer interface {
	Apply(contract.Verdict, containment.Action) error
	Close() error
}

// enforceVerdict is the testable core of the OnVerdict->kernel seam. It programs
// kernel containment ONLY for an async (kernel-enforced) Tier-2/3 verdict on an
// attributable flow: inline tiers were actioned at the proxy, Tiers 0-1 never
// contain, and a cookie-0 flow is unattributable. It returns the action it
// applied (applied=true) so the caller can emit positive containment evidence.
func enforceVerdict(enf enforcer, v contract.Verdict) (act containment.Action, applied bool, err error) {
	if v.Mode != contract.ModeAsync || v.Flow.SocketCookie == 0 {
		return 0, false, nil
	}
	a, ok := containment.ActionForTier(v.Tier)
	if !ok {
		return 0, false, nil
	}
	return a, true, enf.Apply(v, a)
}

// demoCanaryPaths pins canary types to negative-space HTTP paths — paths a
// legitimate flow never requests, so a touch is almost certainly hostile
// (docs/ROADMAP §1). The M3 seeder places real harmless decoys at these
// locations; the adapter recognizes a touch by the path.
//
// Each type carries an EXACT leaf AND a DIRECTORY canary (trailing "/"). The
// directory canary matches any path at or below it (signal.Builder prefix walk),
// so an LLM attacker's natural enumeration — GET /admin/, /backup/, /config/,
// /secrets/, /internal/ (and anything under them) — registers as a touch without
// spoon-feeding exact leaves. Each directory maps to a DISTINCT canary type
// because the scorer dedups by type: hitting three distinct hostile directories
// is three distinct types → crosses Contain → inline attrition maze.
//
// SAFETY: every path here is negative space, disjoint from the legit generator
// paths (/shop,/search,/products,/account,/cart,/checkout,/orders) — rule 8.
var demoCanaryPaths = map[contract.CanaryType][]seeder.Location{
	catalog.TypePlantedCredential: {"/.aws/credentials", "/secrets/"},
	catalog.TypeFakeSecret:        {"/.env", "/config/"},
	catalog.TypeDecoyFile:         {"/backup/db.sql", "/backup/"},
	catalog.TypeFakeBucket:        {"/internal/buckets", "/internal/"},
	catalog.TypeFakeEndpoint:      {"/admin/metrics", "/admin/"},
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
		stingFloor = flag.Int("sting-floor", 0, "attrition floor for inline Tier 2/3: 0=passive(tarpit), 1=moderate(fake_tree), 2=aggressive(token_bait). 0 => no fake-resource deception (tarpit only)")
		bodyCap    = flag.Int("attrition-body-cap", 64<<10, "max deception-body bytes assembled into the single ext_proc ImmediateResponse")
		maxHold    = flag.Duration("attrition-max-hold", 8*time.Second, "max wall-time to hold ONE inline attrition flow before returning the deception body. MUST be < the proxy's ext_proc message_timeout (Envoy's is 10s here) so the body is actually delivered (else the proxy returns a gateway timeout) and the imposed-time number reflects what the attacker really waited")
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

	// engineCallTimeout bounds each engine Submit gRPC call. ORDERING INVARIANT:
	// the adapter's inline-submit hold (envoy.Config.InlineTimeout, default 50ms)
	// must be <= this engine call timeout, so the engine call returns (a verdict or
	// its own deadline) before the adapter's inline timeout fires. The adapter's
	// submit goroutine is buffered, so even a late engine reply is received and
	// discarded — not a leak; but if InlineTimeout fired first the adapter would
	// fall closed on a flow the engine would have decided, so the ordering matters.
	// The adapter is constructed below with its default InlineTimeout; guard the
	// relationship here so a future retune of either value surfaces a mismatch.
	const engineCallTimeout = 200 * time.Millisecond
	const inlineSubmitHold = 50 * time.Millisecond // mirrors envoy.Config InlineTimeout default
	if inlineSubmitHold > engineCallTimeout {
		log.Printf("envoy-adapter: WARNING inline hold %v > engine call timeout %v; the inline timeout may fire before the engine call returns (adapter falls closed on a decidable flow)", inlineSubmitHold, engineCallTimeout)
	}
	eng := enginegrpc.NewClient(cc, engineCallTimeout)

	// The attritor imposes the real inline hold at Tier 2/3 (the operator picks the
	// FLOOR; a higher tier never raises it). It PROVES every active generator is
	// bounded + harmless at construction, so a bad floor refuses to start here.
	// Bound the per-flow hold to fit the inline transport: the deception body is
	// returned as ONE ext_proc ImmediateResponse, so the whole hold must complete
	// inside the proxy's ext_proc message_timeout or the proxy times the stream out
	// and the attacker gets a gateway error instead of the bait (and TimeHeldSec
	// over-reports the hold). DefaultBudget's MaxDuration (120s) is for an async/
	// streamed transport; cap it to -attrition-max-hold for the inline path.
	budget := attrition.DefaultBudget()
	budget.MaxDuration = *maxHold
	// SHORT inline drip: small per-chunk delays so the hold is paced finely within
	// -attrition-max-hold and Outcome.TimeHeldSec (the sum of delays actually
	// pulled) tracks REAL elapsed wall-time rather than over-counting one long
	// DefaultDrip chunk (up to 45s) that the deadline cuts mid-sleep. The hold is
	// hard-bounded by AttritionMaxHold on the adapter side regardless.
	// RampSaturate 8 ≈ the inline hold budget (AttritionMaxHold 8s over a 0.5–1s
	// drip ⇒ ~8–16 chunks), so the AX1 delay floor ramps MinDelay→MaxDelay within a
	// single held flow — persistence is punished with visibly rising latency.
	drip := attrition.DripParams{ChunkBytes: 64, MinDelay: 500 * time.Millisecond, MaxDelay: 1 * time.Second, RampSaturate: 8}
	attr, err := attrition.New(attrition.Config{
		Floor:  contract.StingFloor(*stingFloor),
		Budget: budget,
		Drip:   drip,
	})
	if err != nil {
		log.Fatalf("envoy-adapter: building attritor (floor=%d): %v", *stingFloor, err)
	}

	// The outcome reporter ships the post-attrition cost meter back to the engine
	// for durable capture, over the SAME gRPC conn. Fire-and-forget from the
	// response path; a short timeout bounds a hung engine. A nil engine-side
	// reporter (no EventStore) simply acks, so this never blocks the adapter.
	outcomeReporter := enginegrpc.NewOutcomeClient(cc, 500*time.Millisecond)

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
		Engine:           eng,
		Registry:         reg,
		Resolver:         resolver,
		Scope:            contract.ScopeKey(*scopeFlag),
		Inline:           *inline,
		Attritor:         attr,
		AttritionBodyCap: *bodyCap,
		AttritionMaxHold: *maxHold,
		OnVerdict: func(ev contract.SignalEvent, v contract.Verdict) {
			log.Printf("CANARY TOUCH scope=%s canary=%s cookie=%#x tier=%d mode=%d score=%.2f",
				ev.Scope, ev.Canary, ev.Flow.SocketCookie, v.Tier, v.Mode, v.Score)
			// The verdict->kernel seam lives HERE (not in the thin adapter).
			act, applied, err := enforceVerdict(enf, v)
			if err != nil {
				// A confirmed Tier-2/3 verdict that we FAILED to program is a
				// containment miss — surface it prominently, never swallow it.
				log.Printf("KERNEL CONTAINMENT FAILED action=%s cookie=%#x tier=%d: %v", act, v.Flow.SocketCookie, v.Tier, err)
				return
			}
			if applied {
				// Positive evidence that the kernel verdict_map was programmed (the
				// demo gate keys on this — silence alone is not proof of a jail).
				log.Printf("KERNEL CONTAINMENT applied action=%s cookie=%#x tier=%d", act, v.Flow.SocketCookie, v.Tier)
			}
		},
		// OnOutcome runs after the inline Tier 2/3 attrition hold completes. This is
		// the composition root, so the copy from attrition.Outcome to the contract
		// type happens HERE — the thin adapter never imports internal/intelligence
		// (rule 1). It is invoked fire-and-forget by the adapter, so the ReportOutcome
		// gRPC round-trip never extends the inline response.
		OnOutcome: func(ev contract.SignalEvent, v contract.Verdict, out attrition.Outcome) {
			log.Printf("ATTRITION scope=%s cookie=%#x tier=%d mech=%s bytes=%d held=%.1fs tokens=%.0f depth=%d reason=%s",
				ev.Scope, ev.Flow.SocketCookie, v.Tier, out.Mechanism, out.BytesServed, out.TimeHeldSec, out.TokenCostProxy, out.DepthReached, out.Reason)
			rec := contract.OutcomeRecord{
				SocketCookie:    ev.Flow.SocketCookie,
				Scope:           ev.Scope,
				TimestampUnixMs: ev.Timestamp.UnixMilli(),
				Outcome: contract.StingOutcome{
					Mechanism:      out.Mechanism,
					TimeHeldSec:    out.TimeHeldSec,
					BytesServed:    out.BytesServed,
					RequestsAbsrb:  out.RequestsAbsrb,
					TokenCostProxy: out.TokenCostProxy,
					DepthReached:   out.DepthReached,
					DoneReason:     int(out.Reason),
					// Five-axis fields. Copy ALL of them at the composition root — a field
					// missed here silently drops on the way to the durable store. attrition
					// sets Axes (at Open); DisengageReason + TimeToDisengageSec are set by the
					// adapter's classifyDisengage from the hold context (AX1/D7, in
					// attritionOrDeny, before this fires); AX2-AX5 populate the rest.
					Axes:               out.Axes,
					TimeToDisengageSec: out.TimeToDisengageSec,
					PoisonClass:        out.PoisonClass,
					PoisonReached:      out.PoisonReached,
					ExploitsObserved:   out.ExploitsObserved,
					ExposureSignals:    out.ExposureSignals,
					DisengageReason:    out.DisengageReason,
				},
			}
			if err := outcomeReporter.ReportOutcome(rec); err != nil {
				// A missed outcome means one event shows zero cost in the dashboard —
				// surface it, but never block or retry (advisory to the cost meter).
				log.Printf("ATTRITION OUTCOME REPORT FAILED cookie=%#x: %v", ev.Flow.SocketCookie, err)
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
