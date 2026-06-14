// Command envoy-adapter is the out-of-process composition root for the M4 Envoy
// ext_proc adapter: it dials the engine over gRPC (presenting it back as a
// contract.Engine), wires the placement registry and the kernel CookieResolver,
// builds the thin adapter, and serves the ext_proc service Envoy connects to.
// This binary runs on the demo host (Linux); the kernel-backed CookieResolver is
// build-tagged and lands in the M4 on-box phase. The local pure-Go path is proven
// by cmd/envoy-selfcheck.
package main

import (
	"errors"
	"flag"
	"log"
	"net"
	"sync"
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

// enforcer programs and lifts kernel containment for an attributed flow. Its
// construction is build-tagged (real on Linux, no-op elsewhere) so cilium/ebpf
// stays out of the adapter's import closure — only this composition root touches it.
type enforcer interface {
	Apply(contract.Verdict, containment.Action) error
	// Release lifts containment for a flow (de-escalation / false-positive /
	// operator clear). Idempotent; a cookie-0 flow is a no-op.
	Release(contract.Verdict) error
	Close() error
}

// enforceVerdict is the testable core of the OnVerdict->kernel seam. It reconciles
// the kernel containment state to the latest async verdict for an attributable
// flow:
//
//   - Tier 2/3 -> Apply the matching containment action (rate-limit / jail).
//   - Tier 0/1 -> Release any containment the flow previously had (DE-ESCALATION:
//     a flow that fell back below TierContain must not stay jailed — without this
//     a Tier-3 jail is never lifted in production and the delete-on-close eBPF is
//     the ONLY thing that ever frees it).
//
// It acts only on async (kernel-enforced) verdicts: inline tiers were actioned at
// the proxy, and a cookie-0 flow is unattributable (never enforced, nothing to
// release). It returns the action it applied (applied=true) so the caller can emit
// positive containment evidence; a de-escalation reports released=true.
func enforceVerdict(enf enforcer, v contract.Verdict) (act containment.Action, applied, released bool, err error) {
	if v.Mode != contract.ModeAsync || v.Flow.SocketCookie == 0 {
		return 0, false, false, nil
	}
	a, ok := containment.ActionForTier(v.Tier)
	if !ok {
		// Below TierContain: lift any containment this flow previously had.
		// Release is idempotent, so a never-contained flow is a cheap no-op.
		return 0, false, true, enf.Release(v)
	}
	return a, true, false, enf.Apply(v, a)
}

// verdictSequencer enforces per-flow verdict ordering so a STALE async verdict can
// never undo a newer one for the same cookie. Async verdicts are decided and
// delivered out of band; under concurrency a later high-tier (jail) verdict and an
// earlier low-tier verdict for the same flow can arrive at this seam out of order.
// Without ordering, the stale low-tier verdict's Release would lift a jail the newer
// verdict programmed — re-opening a contained flow. The sequencer records, per
// cookie, the highest ordinal applied so far and DROPS any verdict whose ordinal is
// older-or-equal (last-writer-wins by ordinal, not by arrival order).
//
// The ordinal is the originating SignalEvent's timestamp (a later event ⇒ a later
// verdict). It is monotonic per flow at the source and needs no engine change. Ties
// (equal ordinal) are dropped: a verdict no newer than the last applied carries no
// new information and must not flip state. Concurrency-safe (the adapter delivers
// verdicts from multiple request goroutines).
type verdictSequencer struct {
	mu   sync.Mutex
	high map[uint64]int64 // cookie -> highest applied ordinal
}

func newVerdictSequencer() *verdictSequencer {
	return &verdictSequencer{high: make(map[uint64]int64)}
}

// admit reports whether a verdict at the given ordinal for cookie is the newest seen
// and should be applied. It records the ordinal as the new high-water mark when it
// admits. A cookie-0 (unattributable) verdict is always admitted: enforceVerdict
// no-ops it anyway, and it never carries per-flow state to protect. Stale or
// duplicate (ordinal <= the recorded high) verdicts for an attributed cookie are
// rejected.
// seqStaleNanos: a cookie with no verdict for this long is a finished flow whose
// high-water mark can be reaped to bound the map. It is far larger than the scoring
// correlation window, so a legitimately out-of-order verdict (which arrives within
// seconds) is still rejected as stale long before its mark could be reaped.
const (
	seqStaleNanos    = int64(30 * time.Minute)
	seqReapThreshold = 4096 // only sweep once the map has actually grown
)

func (s *verdictSequencer) admit(cookie uint64, ordinal int64) bool {
	if cookie == 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Bound the map: a finished flow's mark would otherwise linger forever. Sweep
	// long-idle cookies, but only once the map has grown past a threshold so the
	// common path stays O(1).
	if len(s.high) > seqReapThreshold {
		cutoff := ordinal - seqStaleNanos
		for c, o := range s.high {
			if o < cutoff {
				delete(s.high, c)
			}
		}
	}
	if prev, seen := s.high[cookie]; seen && ordinal <= prev {
		return false
	}
	s.high[cookie] = ordinal
	return true
}

// enforceVerdictOrdered gates enforceVerdict behind the per-flow sequencer: a
// verdict older-or-equal to the last applied for its cookie is DROPPED (stale=true),
// touching the enforcer not at all, so a stale low-tier verdict cannot Release a jail
// a newer verdict programmed. A fresh (newest-seen) verdict flows through to
// enforceVerdict unchanged.
func enforceVerdictOrdered(enf enforcer, seq *verdictSequencer, v contract.Verdict, ordinal int64) (act containment.Action, applied, released, stale bool, err error) {
	if !seq.admit(v.Flow.SocketCookie, ordinal) {
		return 0, false, false, true, nil
	}
	act, applied, released, err = enforceVerdict(enf, v)
	return act, applied, released, false, err
}

// releaseVerdictForLabel lifts containment for a flow an analyst confirmed was a
// false positive (FeedbackLabel{WasMalicious:false}). A confirmed-malicious label
// leaves containment in place. It is the second de-escalation trigger alongside the
// verdict-drop path, and the building block the operator clear path reuses. It
// returns released=true when it actually issued a Release (an attributable,
// not-malicious label).
func releaseVerdictForLabel(enf enforcer, l contract.FeedbackLabel) (released bool, err error) {
	if l.WasMalicious || l.Flow.SocketCookie == 0 {
		return false, nil
	}
	return true, enf.Release(contract.Verdict{Flow: l.Flow, Scope: l.Scope, Tier: l.Tier})
}

// feedbackReleaseSink is the adapter-side delivery seam for analyst labels. It
// implements contract.FeedbackSink so the SAME FeedbackLabel that calibrates the
// engine ALSO lifts adapter/kernel containment for a false positive — releasing a
// jail is the adapter's job because containment is enforced node-side, not in the
// engine (rules 1/2). Without this seam releaseVerdictForLabel is unreachable in
// production (a label can never lift a jail).
//
// How a label is delivered: the staged labeler / operator feedback path calls
// FeedbackSink.Label (see internal/intelligence/stagedlabel and
// internal/engine/feedback). Phase-2's composition root wraps the kernel enforcer in
// a feedbackReleaseSink that Releases on WasMalicious:false, leaves containment on a
// confirmed-malicious label, then forwards the label to the engine's calibration
// intake (next) so one analyst action both frees the bystander and feeds calibration.
//
// STATUS: this type + releaseVerdictForLabel are built and unit-tested, but DORMANT
// in Phase-1 — the adapter binary has no label source (the engine runs the labeler;
// an engine->adapter label transport is Phase-2 / B5, docs/IDENTITY.md "Lifting
// containment"). It is intentionally not instantiated in main() so nothing reads as
// wired-but-unreachable. The ACTIVE Phase-1 un-jail is the de-escalation path
// (enforceVerdictOrdered Releases when a later verdict drops below TierContain).
type feedbackReleaseSink struct {
	enf  enforcer
	next contract.FeedbackSink // optional downstream (calibration); may be nil
}

var _ contract.FeedbackSink = (*feedbackReleaseSink)(nil)

// Label lifts containment for a false-positive label and forwards every label to the
// downstream sink. A release failure is returned (the caller must see a jail that did
// not lift); a downstream error is returned too. Both are attempted regardless so a
// release failure never silently drops calibration and vice versa.
func (s *feedbackReleaseSink) Label(l contract.FeedbackLabel) error {
	_, relErr := releaseVerdictForLabel(s.enf, l)
	var fwdErr error
	if s.next != nil {
		fwdErr = s.next.Label(l)
	}
	return errors.Join(relErr, fwdErr)
}

// operatorClear is the operator clear seam: lift containment for a single
// attributed flow by cookie, on demand (the full CLI/RPC surface can come later).
// It returns errClearUnattributable for a cookie-0 request so an operator typo
// cannot silently no-op against "every unattributable flow". Release itself is
// idempotent, so clearing an already-clear flow is safe.
func operatorClear(enf enforcer, cookie uint64) error {
	if cookie == 0 {
		return errClearUnattributable
	}
	return enf.Release(contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: cookie}})
}

// errClearUnattributable guards the operator clear path against a cookie-0 request.
var errClearUnattributable = errors.New("operator clear: cookie 0 is unattributable; refusing to clear")

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
		stingFloor = flag.Int("sting-floor", 0, "attrition floor for inline Tier 2/3: 0=passive(tarpit/velocity), 1=moderate(+poison_field/fake_tree), 2=aggressive(+token_bait). 0 => no fake-resource deception (tarpit only)")
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
	// the adapter's inline-submit hold (envoy.Config.InlineTimeout) must be >= this
	// engine call timeout, so the engine call returns (a verdict or its own deadline)
	// BEFORE the inline hold fires. If the hold is shorter it fires first and the
	// adapter falls closed (403) on a flow the engine WOULD have decided — exactly the
	// bug that made every inline canary touch a flat 403 instead of running the
	// attrition pump (the hold defaulted to 50ms while the engine call is 200ms, and
	// this binary never wired InlineTimeout). We now wire InlineTimeout from
	// inlineSubmitHold below and guard the relationship so a future retune surfaces a
	// mismatch. Keep inlineSubmitHold strictly < the Envoy ext_proc message_timeout
	// (envoy.yaml) and AttritionMaxHold < message_timeout so the proxy never times the
	// stream out and 5xx-es the attacker instead of serving the deception body.
	// Generous bounds: the engine Submit can take >200ms (scoring + baseline + the D6
	// matcher querying the durable event store), so an inline canary-touch verdict
	// needs real headroom or the adapter falls closed to a flat 403. Both stay well
	// under the Envoy ext_proc message_timeout (10s) and AttritionMaxHold (8s).
	const engineCallTimeout = 2 * time.Second
	const inlineSubmitHold = 2500 * time.Millisecond // wired into envoy.Config.InlineTimeout; MUST be >= engineCallTimeout
	log.Printf("envoy-adapter: inline submit hold %v, engine call timeout %v", inlineSubmitHold, engineCallTimeout)
	if inlineSubmitHold < engineCallTimeout {
		log.Printf("envoy-adapter: WARNING inline hold %v < engine call timeout %v; the inline timeout may fire before the engine call returns (adapter falls closed on a decidable flow)", inlineSubmitHold, engineCallTimeout)
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

	// Per-flow verdict ordering: a stale concurrent async verdict must not undo a
	// newer one for the same cookie (a late low-tier Release re-opening a jail a
	// later verdict programmed). The originating event timestamp is the per-flow
	// ordinal; last-writer-wins by ordinal.
	verdictSeq := newVerdictSequencer()

	// Un-jail recovery. The ACTIVE Phase-1 path is de-escalation: when a later verdict
	// for a flow drops below TierContain, enforceVerdictOrdered (below) Releases the
	// jail — so a Tier-3 jail is no longer permanent. A SECOND trigger — an analyst
	// false-positive label (FeedbackLabel{WasMalicious:false}) lifting containment via
	// feedbackReleaseSink / releaseVerdictForLabel — is built and unit-tested but
	// DORMANT: this binary has no label source (the engine runs the labeler; an
	// engine->adapter label transport is Phase-2 / B5, docs/IDENTITY.md "Lifting
	// containment"). It is intentionally NOT instantiated here, so nothing reads as
	// wired-but-unreachable; Phase-2 builds feedbackReleaseSink{enf, next: calibration
	// intake} and feeds it the label stream.

	a, err := envoy.New(envoy.Config{
		Engine:           eng,
		Registry:         reg,
		Resolver:         resolver,
		Scope:            contract.ScopeKey(*scopeFlag),
		Inline:           *inline,
		Attritor:         attr,
		AttritionBodyCap: *bodyCap,
		AttritionMaxHold: *maxHold,
		// Hold long enough for the engine verdict (>= engineCallTimeout) so a canary
		// touch runs the attrition pump instead of falling closed to a flat 403.
		InlineTimeout: inlineSubmitHold,
		OnVerdict: func(ev contract.SignalEvent, v contract.Verdict) {
			log.Printf("CANARY TOUCH scope=%s canary=%s cookie=%#x tier=%d mode=%d score=%.2f",
				ev.Scope, ev.Canary, ev.Flow.SocketCookie, v.Tier, v.Mode, v.Score)
			// The verdict->kernel seam lives HERE (not in the thin adapter). It both
			// PROGRAMS containment at Tier 2/3 and RELEASES it when a later verdict for
			// the same flow drops below TierContain (de-escalation — without this a
			// Tier-3 jail is never lifted in production). The per-flow sequencer DROPS a
			// stale async verdict (one older than the last applied for this cookie) so a
			// late low-tier Release cannot lift a jail a newer verdict programmed.
			act, applied, released, stale, err := enforceVerdictOrdered(enf, verdictSeq, v, ev.Timestamp.UnixNano())
			if stale {
				log.Printf("VERDICT DROPPED (stale, out-of-order) cookie=%#x tier=%d", v.Flow.SocketCookie, v.Tier)
				return
			}
			if err != nil {
				// A confirmed Tier-2/3 verdict we FAILED to program, OR a de-escalation
				// we FAILED to release, is a containment miss — surface it prominently,
				// never swallow it (a failed release leaves a flow jailed too long).
				if released {
					log.Printf("KERNEL CONTAINMENT RELEASE FAILED cookie=%#x tier=%d: %v", v.Flow.SocketCookie, v.Tier, err)
				} else {
					log.Printf("KERNEL CONTAINMENT FAILED action=%s cookie=%#x tier=%d: %v", act, v.Flow.SocketCookie, v.Tier, err)
				}
				return
			}
			if applied {
				// Positive evidence that the kernel verdict_map was programmed (the
				// demo gate keys on this — silence alone is not proof of a jail).
				log.Printf("KERNEL CONTAINMENT applied action=%s cookie=%#x tier=%d", act, v.Flow.SocketCookie, v.Tier)
			}
			if released {
				// Positive evidence the kernel entry was lifted (de-escalation).
				log.Printf("KERNEL CONTAINMENT released cookie=%#x tier=%d (de-escalated below contain)", v.Flow.SocketCookie, v.Tier)
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
