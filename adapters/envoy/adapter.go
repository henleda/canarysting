// Package envoy is the thin Envoy adapter: an ext_proc external processor that
// observes canary touches, stamps the kernel socket cookie onto every signal
// event, submits over the engine contract, and applies the verdict. It contains
// NO scoring, tiering, or decision logic and imports neither internal/engine nor
// cilium/ebpf (an import-graph test enforces both). See docs/ADAPTERS.md and
// docs/IDENTITY.md.
//
// One Process stream is one HTTP request. Non-canary requests CONTINUE
// immediately with no engine round-trip (the common path). A canary touch is
// emitted as a contract.SignalEvent; in inline mode the adapter holds the request
// for the verdict and enforces at the proxy per tier/mode, in async mode it fires
// the signal and continues, leaving kernel enforcement (M5, keyed by the same
// cookie) to act. Tiers 0-1 never block (CLAUDE.md rule 6).
package envoy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
	"github.com/canarysting/canarysting/internal/canary/seeder"
	"github.com/canarysting/canarysting/internal/canary/signal"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/attrition"
)

// errInlineTimeout is returned when an inline Submit exceeds InlineTimeout.
var errInlineTimeout = errors.New("envoy: inline engine submit timed out")

// errAsyncSaturated reports that an async submit was dropped at the in-flight cap
// (the host-protection backstop) rather than spawned.
var errAsyncSaturated = errors.New("envoy: async submit queue saturated; signal dropped")

// resolveAttempts bounds the cookie re-lookup that absorbs the
// establish-vs-first-byte race; total wait ~= ResolveRetry.
const resolveAttempts = 4

// Config configures the Envoy adapter. Engine, Registry, Resolver, and a non-empty
// Scope are required; the rest default in Normalized.
type Config struct {
	Engine   contract.Engine         // the (possibly remote) engine, via the contract only
	Registry seeder.Registry         // placement registry: what is a canary, per scope
	Resolver identity.CookieResolver // the L7<->kernel cookie join
	Scope    contract.ScopeKey       // this deployment's resolved scope
	Fail     FailPolicy              // per-tier inline fail behavior (contract-typed)
	Attritor attrition.Attritor      // optional M6 attrition seam; nil = no inline deception
	Mapper   LocationMapper          // request -> candidate location; nil uses StripQueryPathMapper

	// Inline selects inline enforcement (hold a canary touch for the verdict and
	// act at the proxy). Default false: async — fire the signal and CONTINUE, the
	// kernel enforces. In async mode Tiers 0-1 are trivially never on the hot path.
	Inline bool

	InlineTimeout time.Duration    // max hold for an inline Submit; default 50ms
	ResolveRetry  time.Duration    // bounded cookie re-lookup window; default 5ms
	Clock         func() time.Time // injectable; default time.Now

	// AsyncMaxInflight bounds concurrent async Submits so a flood of canary touches
	// cannot exhaust the host with goroutines; excess async signals are DROPPED
	// (reported via OnAsyncError), not spawned. Default 256.
	AsyncMaxInflight int
	// OnAsyncError is called when an async Submit fails or is dropped at capacity.
	// Default logs; set a metric hook in production. An async failure means no
	// record and no signal, so it must never be silently discarded.
	OnAsyncError func(error)

	sleep func(time.Duration)
}

// Normalized fills defaults (house idiom). It does not mutate required fields.
func (c Config) Normalized() Config {
	if c.Mapper == nil {
		c.Mapper = StripQueryPathMapper{}
	}
	if c.InlineTimeout <= 0 {
		c.InlineTimeout = 50 * time.Millisecond
	}
	if c.ResolveRetry <= 0 {
		c.ResolveRetry = 5 * time.Millisecond
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.sleep == nil {
		c.sleep = time.Sleep
	}
	if c.Fail.FailClosed == nil {
		c.Fail = DefaultFailPolicy()
	}
	if c.AsyncMaxInflight <= 0 {
		c.AsyncMaxInflight = 256
	}
	if c.OnAsyncError == nil {
		c.OnAsyncError = func(err error) { log.Printf("envoy: async submit: %v", err) }
	}
	return c
}

// Adapter is the ext_proc ExternalProcessor server.
type Adapter struct {
	cfg     Config
	builder *signal.Builder
	sem     chan struct{} // bounds concurrent async submits (AsyncMaxInflight)
}

var _ extprocv3.ExternalProcessorServer = (*Adapter)(nil)

// New validates the required config and constructs the adapter. It refuses to
// start (returns an error, never panics) if a required dependency is missing or
// the scope is empty — mirroring the engine/seeder refuse-to-start discipline.
func New(cfg Config) (*Adapter, error) {
	if cfg.Engine == nil {
		return nil, errors.New("envoy: nil Engine")
	}
	if cfg.Registry == nil {
		return nil, errors.New("envoy: nil Registry")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("envoy: nil Resolver")
	}
	if cfg.Scope == "" {
		return nil, errors.New("envoy: empty Scope; refusing to start (never a global scope)")
	}
	cfg = cfg.Normalized()
	return &Adapter{
		cfg:     cfg,
		builder: signal.NewBuilder(cfg.Registry),
		sem:     make(chan struct{}, cfg.AsyncMaxInflight),
	}, nil
}

// Process is the ext_proc gRPC server method: one stream per HTTP request. It
// handles the request-headers phase (M4 uses body NONE / response SKIP) and
// CONTINUEs every other phase.
func (a *Adapter) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	for {
		req, err := stream.Recv()
		if err != nil {
			// EOF or client cancellation ends the stream cleanly — not a server error.
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		var resp *extprocv3.ProcessingResponse
		switch r := req.GetRequest().(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			resp = a.onRequestHeaders(ctx, req, r.RequestHeaders)
		default:
			resp = continuePhase(req) // phase-correct CONTINUE (mirror the request oneof)
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// onRequestHeaders observes the request, stamps the cookie, and either CONTINUEs
// (non-canary, unattributable, or async) or holds for the verdict (inline).
func (a *Adapter) onRequestHeaders(ctx context.Context, req *extprocv3.ProcessingRequest, hh *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	obs := observationFromHeaders(hh.GetHeaders())
	loc, ok := a.cfg.Mapper.ToLocation(obs)
	if !ok {
		return continueResp(nil)
	}

	flow := contract.FlowIdentity{SPIFFEID: spiffeFromAttributes(req.GetAttributes())}
	if ft, ok := tupleFromAttributes(req.GetAttributes()); ok {
		if res, hit := a.resolveCookie(ft); hit {
			flow.SocketCookie = res.Cookie
			flow.CgroupID = res.CgroupID
			flow.PID = res.PID
		}
	}

	ev, err := a.builder.Build(a.cfg.Scope, signal.Touch{Flow: flow, Location: loc, At: a.cfg.Clock()})
	switch {
	case errors.Is(err, signal.ErrNoPlacement):
		return continueResp(nil) // not a canary touch — the common path
	case errors.Is(err, signal.ErrNoSocketCookie):
		return continueResp(nil) // canary touched but unattributable: observe-only, never enforce
	case err != nil:
		return continueResp(nil) // ErrNoScope is impossible (New refuses empty); fail safe
	}

	if !a.cfg.Inline {
		// Async: fire the signal, never block the request; the kernel (M5) enforces.
		a.fireAsync(ev)
		return continueResp(nil)
	}

	v, serr := a.submit(ctx, ev)
	if serr != nil {
		// Engine unavailable for an inline decision; the tier is unknown, so use the
		// most-conservative inline posture (fail-closed by default for a canary touch).
		if a.cfg.Fail.Allow(contract.TierJail) {
			return continueResp(nil)
		}
		return immediateDeny(typev3.StatusCode_Forbidden, "forbidden\n")
	}
	return responseForVerdict(v)
}

// fireAsync submits a signal off the request path, bounded by AsyncMaxInflight so
// a flood of canary touches cannot exhaust the host with goroutines. At capacity
// the signal is DROPPED (reported), not spawned — the kernel and subsequent
// requests still observe escalation. A submit error is reported, never discarded.
func (a *Adapter) fireAsync(ev contract.SignalEvent) {
	select {
	case a.sem <- struct{}{}:
		go func() {
			defer func() { <-a.sem }()
			if _, err := a.cfg.Engine.Submit(ev); err != nil {
				a.cfg.OnAsyncError(fmt.Errorf("submit failed: %w", err))
			}
		}()
	default:
		a.cfg.OnAsyncError(errAsyncSaturated)
	}
}

// resolveCookie looks up the socket cookie, retrying within ResolveRetry to absorb
// the establish-vs-first-byte race. A persistent MISS leaves the flow
// unattributable (the caller then never enforces).
func (a *Adapter) resolveCookie(ft identity.FourTuple) (identity.Resolution, bool) {
	interval := a.cfg.ResolveRetry / resolveAttempts
	for i := 0; i < resolveAttempts; i++ {
		if res, ok := a.cfg.Resolver.Resolve(ft); ok {
			return res, true
		}
		if i < resolveAttempts-1 && interval > 0 {
			a.cfg.sleep(interval)
		}
	}
	return identity.Resolution{}, false
}

// submit runs an inline Submit bounded by InlineTimeout and the stream context.
// contract.Engine.Submit has no context, so the call runs in a goroutine (its
// buffered channel lets it finish and exit even after a timeout — no leak).
func (a *Adapter) submit(ctx context.Context, ev contract.SignalEvent) (contract.Verdict, error) {
	type result struct {
		v   contract.Verdict
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := a.cfg.Engine.Submit(ev)
		ch <- result{v, err}
	}()
	select {
	case <-ctx.Done():
		return contract.Verdict{}, fmt.Errorf("envoy: inline submit cancelled: %w", ctx.Err())
	case <-time.After(a.cfg.InlineTimeout):
		return contract.Verdict{}, errInlineTimeout
	case r := <-ch:
		return r.v, r.err
	}
}
