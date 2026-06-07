package envoy

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/canarysting/canarysting/adapters/envoy/identity"
	"github.com/canarysting/canarysting/internal/canary/seeder"
	"github.com/canarysting/canarysting/internal/contract"
)

// --- fakes ---

type recEngine struct {
	mu    sync.Mutex
	last  contract.SignalEvent
	calls int
	out   contract.Verdict
	err   error
	block chan struct{} // if non-nil, Submit blocks until it is closed (timeout test)
	got   chan struct{} // if non-nil, Submit signals here after recording (async test)
}

func (e *recEngine) Submit(ev contract.SignalEvent) (contract.Verdict, error) {
	if e.block != nil {
		<-e.block
	}
	e.mu.Lock()
	e.last = ev
	e.calls++
	e.mu.Unlock()
	if e.got != nil {
		e.got <- struct{}{}
	}
	return e.out, e.err
}

func (e *recEngine) count() int { e.mu.Lock(); defer e.mu.Unlock(); return e.calls }
func (e *recEngine) event() contract.SignalEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.last
}

type fakeStream struct {
	grpc.ServerStream
	ctx  context.Context
	reqs []*extprocv3.ProcessingRequest
	i    int
	sent []*extprocv3.ProcessingResponse
}

func (f *fakeStream) Context() context.Context { return f.ctx }
func (f *fakeStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if f.i >= len(f.reqs) {
		return nil, io.EOF
	}
	r := f.reqs[f.i]
	f.i++
	return r, nil
}
func (f *fakeStream) Send(r *extprocv3.ProcessingResponse) error {
	f.sent = append(f.sent, r)
	return nil
}

// headersReq builds a request_headers ProcessingRequest with a path and optional
// source/destination address attributes.
func headersReq(path, srcAddr, dstAddr string) *extprocv3.ProcessingRequest {
	req := &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: ":path", Value: path},
				{Key: ":method", Value: "GET"},
			}}},
		},
	}
	if srcAddr != "" {
		attrs, _ := structpb.NewStruct(map[string]interface{}{
			"source.address":      srcAddr,
			"destination.address": dstAddr,
		})
		req.Attributes = map[string]*structpb.Struct{"conn": attrs}
	}
	return req
}

const (
	canaryPath = "/.env"
	srcAddr    = "203.0.113.7:54321"
	dstAddr    = "10.0.0.2:8443"
)

// fixture wires an adapter with a registered canary placement, a resolver that
// hits with the given cookie (0 = make it miss), and a fake engine.
func fixture(t *testing.T, inline bool, eng *recEngine, cookie uint64) (*Adapter, *identity.FakeResolver) {
	t.Helper()
	reg := seeder.NewMemRegistry()
	if err := reg.Put(seeder.Placement{Scope: "scope-a", Type: "decoy_file", Location: canaryPath}); err != nil {
		t.Fatal(err)
	}
	res := identity.NewFakeResolver()
	if cookie != 0 {
		ft, _ := identity.TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)
		res.Set(ft, identity.Resolution{Cookie: cookie, PID: 1234})
	}
	a, err := New(Config{
		Engine: eng, Registry: reg, Resolver: res, Scope: "scope-a", Inline: inline,
		InlineTimeout: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a, res
}

func run(t *testing.T, a *Adapter, reqs ...*extprocv3.ProcessingRequest) []*extprocv3.ProcessingResponse {
	t.Helper()
	fs := &fakeStream{ctx: context.Background(), reqs: reqs}
	if err := a.Process(fs); err != nil {
		t.Fatalf("Process: %v", err)
	}
	return fs.sent
}

func isContinue(r *extprocv3.ProcessingResponse) bool { return r.GetRequestHeaders() != nil }
func immediate(r *extprocv3.ProcessingResponse) (int, bool) {
	ir := r.GetImmediateResponse()
	if ir == nil {
		return 0, false
	}
	return int(ir.GetStatus().GetCode()), true
}

// --- tests ---

func TestNewValidatesRequiredConfig(t *testing.T) {
	reg := seeder.NewMemRegistry()
	res := identity.NewFakeResolver()
	eng := &recEngine{}
	cases := map[string]Config{
		"nil engine":   {Registry: reg, Resolver: res, Scope: "s"},
		"nil registry": {Engine: eng, Resolver: res, Scope: "s"},
		"nil resolver": {Engine: eng, Registry: reg, Scope: "s"},
		"empty scope":  {Engine: eng, Registry: reg, Resolver: res, Scope: ""},
	}
	for name, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Fatalf("%s: New should have refused to start", name)
		}
	}
}

func TestProcessNonCanaryContinuesWithoutSubmit(t *testing.T) {
	eng := &recEngine{out: contract.Verdict{Tier: contract.TierJail, Mode: contract.ModeInline}}
	a, _ := fixture(t, true, eng, 0xC0FFEE)
	sent := run(t, a, headersReq("/orders", srcAddr, dstAddr))
	if len(sent) != 1 || !isContinue(sent[0]) {
		t.Fatalf("non-canary should CONTINUE: %+v", sent)
	}
	if eng.count() != 0 {
		t.Fatalf("non-canary must not submit to the engine, got %d submits", eng.count())
	}
}

func TestProcessCanaryTouchInlineAppliesVerdictAndCarriesCookie(t *testing.T) {
	eng := &recEngine{out: contract.Verdict{Tier: contract.TierJail, Mode: contract.ModeInline}}
	a, _ := fixture(t, true, eng, 0xABCDEF)
	sent := run(t, a, headersReq(canaryPath, srcAddr, dstAddr))
	code, ok := immediate(sent[0])
	if !ok || code != int(typev3.StatusCode_Forbidden) {
		t.Fatalf("Tier 3 inline should 403-deny, got %+v", sent[0])
	}
	if eng.count() != 1 {
		t.Fatalf("canary touch should submit once, got %d", eng.count())
	}
	if got := eng.event().Flow.SocketCookie; got != 0xABCDEF {
		t.Fatalf("socket cookie not carried to the engine: got %x", got)
	}
	if eng.event().Canary != "decoy_file" || eng.event().Scope != "scope-a" {
		t.Fatalf("canary type/scope came from the registry, got %+v", eng.event())
	}
}

func TestProcessTier2InlineRateLimits(t *testing.T) {
	eng := &recEngine{out: contract.Verdict{Tier: contract.TierContain, Mode: contract.ModeInline}}
	a, _ := fixture(t, true, eng, 0x11)
	sent := run(t, a, headersReq(canaryPath, srcAddr, dstAddr))
	if code, ok := immediate(sent[0]); !ok || code != int(typev3.StatusCode_TooManyRequests) {
		t.Fatalf("Tier 2 inline should 429, got %+v", sent[0])
	}
}

func TestProcessAsyncTierContinues(t *testing.T) {
	// Tier 3 but Mode async: the kernel enforces; the adapter must CONTINUE at L7.
	eng := &recEngine{out: contract.Verdict{Tier: contract.TierJail, Mode: contract.ModeAsync}}
	a, _ := fixture(t, true, eng, 0x22)
	sent := run(t, a, headersReq(canaryPath, srcAddr, dstAddr))
	if !isContinue(sent[0]) {
		t.Fatalf("async tier must CONTINUE at L7 (kernel enforces), got %+v", sent[0])
	}
}

func TestProcessUnattributableObservesOnly(t *testing.T) {
	// Canary path but the resolver MISSES: no cookie -> Build refuses -> CONTINUE,
	// and crucially NO enforcement and NO submit (unattributable, IDENTITY.md).
	eng := &recEngine{out: contract.Verdict{Tier: contract.TierJail, Mode: contract.ModeInline}}
	a, _ := fixture(t, true, eng, 0) // cookie 0 => resolver misses
	sent := run(t, a, headersReq(canaryPath, srcAddr, dstAddr))
	if !isContinue(sent[0]) {
		t.Fatalf("unattributable touch must CONTINUE (never enforce), got %+v", sent[0])
	}
	if eng.count() != 0 {
		t.Fatalf("unattributable touch must not submit, got %d", eng.count())
	}
}

func TestProcessAsyncModeFiresAndContinues(t *testing.T) {
	eng := &recEngine{out: contract.Verdict{Tier: contract.TierJail, Mode: contract.ModeAsync}, got: make(chan struct{}, 1)}
	a, _ := fixture(t, false, eng, 0x33) // async mode
	sent := run(t, a, headersReq(canaryPath, srcAddr, dstAddr))
	if !isContinue(sent[0]) {
		t.Fatalf("async mode must CONTINUE immediately, got %+v", sent[0])
	}
	select {
	case <-eng.got:
	case <-time.After(time.Second):
		t.Fatal("async mode did not fire the signal to the engine")
	}
	if got := eng.event().Flow.SocketCookie; got != 0x33 {
		t.Fatalf("async signal lost the cookie: %x", got)
	}
}

func TestProcessInlineTimeoutFailsClosed(t *testing.T) {
	eng := &recEngine{block: make(chan struct{}), out: contract.Verdict{Tier: contract.TierJail}}
	defer close(eng.block) // unblock the leaked Submit goroutine at test end
	a, _ := fixture(t, true, eng, 0x44)
	sent := run(t, a, headersReq(canaryPath, srcAddr, dstAddr))
	if code, ok := immediate(sent[0]); !ok || code != int(typev3.StatusCode_Forbidden) {
		t.Fatalf("inline timeout with default fail-closed should 403, got %+v", sent[0])
	}
}

func TestProcessInlineTimeoutFailsOpenWhenConfigured(t *testing.T) {
	eng := &recEngine{block: make(chan struct{}), out: contract.Verdict{Tier: contract.TierJail}}
	defer close(eng.block)
	reg := seeder.NewMemRegistry()
	_ = reg.Put(seeder.Placement{Scope: "scope-a", Type: "decoy_file", Location: canaryPath})
	res := identity.NewFakeResolver()
	ft, _ := identity.TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)
	res.Set(ft, identity.Resolution{Cookie: 0x55})
	a, err := New(Config{
		Engine: eng, Registry: reg, Resolver: res, Scope: "scope-a", Inline: true,
		InlineTimeout: 20 * time.Millisecond,
		Fail:          FailPolicy{FailClosed: map[contract.Tier]bool{}}, // nothing fail-closed
	})
	if err != nil {
		t.Fatal(err)
	}
	sent := run(t, a, headersReq(canaryPath, srcAddr, dstAddr))
	if !isContinue(sent[0]) {
		t.Fatalf("inline timeout with fail-open config should CONTINUE, got %+v", sent[0])
	}
}

func respHeadersReq() *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{}},
	}}
}

func TestProcessMirrorsResponsePhase(t *testing.T) {
	// A response_headers phase must be answered with a response_headers oneof, not
	// a request_headers one (ext_proc protocol). The default branch must be
	// phase-correct.
	eng := &recEngine{}
	a, _ := fixture(t, true, eng, 0x1)
	sent := run(t, a, respHeadersReq())
	if sent[0].GetResponseHeaders() == nil {
		t.Fatalf("response_headers phase must get a response_headers CONTINUE, got %+v", sent[0])
	}
	if sent[0].GetRequestHeaders() != nil {
		t.Fatal("response_headers phase wrongly answered with a request_headers oneof")
	}
}

func TestProcessMultiPhaseStreamAndEOF(t *testing.T) {
	// One stream, multiple phases: each gets a phase-correct response, then EOF
	// ends the stream cleanly (Process returns nil).
	eng := &recEngine{}
	a, _ := fixture(t, true, eng, 0x1)
	sent := run(t, a, headersReq("/orders", srcAddr, dstAddr), respHeadersReq())
	if len(sent) != 2 {
		t.Fatalf("expected one response per phase, got %d", len(sent))
	}
	if sent[0].GetRequestHeaders() == nil || sent[1].GetResponseHeaders() == nil {
		t.Fatalf("phases not mirrored: %+v", sent)
	}
}

func TestResolveAttemptsArePinned(t *testing.T) {
	// The bounded re-lookup must make exactly resolveAttempts tries: a tuple that
	// misses (resolveAttempts-1) times then hits is resolved; one that misses
	// resolveAttempts times is NOT (stays unattributable). This pins the constant
	// so a regression that shrinks it is caught.
	mk := func(misses int) *recEngine {
		eng := &recEngine{out: contract.Verdict{Tier: contract.TierObserve}}
		reg := seeder.NewMemRegistry()
		_ = reg.Put(seeder.Placement{Scope: "scope-a", Type: "decoy_file", Location: canaryPath})
		res := identity.NewFakeResolver()
		ft, _ := identity.TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)
		res.MissThenHit(ft, identity.Resolution{Cookie: 0x99}, misses)
		a, err := New(Config{Engine: eng, Registry: reg, Resolver: res, Scope: "scope-a", Inline: true})
		if err != nil {
			t.Fatal(err)
		}
		a.cfg.sleep = func(time.Duration) {} // deterministic: no real waiting
		run(t, a, headersReq(canaryPath, srcAddr, dstAddr))
		return eng
	}
	if eng := mk(resolveAttempts - 1); eng.count() != 1 || eng.event().Flow.SocketCookie != 0x99 {
		t.Fatalf("a cookie appearing within resolveAttempts must resolve: calls=%d cookie=%x", eng.count(), eng.event().Flow.SocketCookie)
	}
	if eng := mk(resolveAttempts); eng.count() != 0 {
		t.Fatalf("a cookie that never appears within resolveAttempts must stay unattributable (no submit), got %d submits", eng.count())
	}
}

func TestProcessInlineContextCancelFailsClosed(t *testing.T) {
	eng := &recEngine{block: make(chan struct{}), out: contract.Verdict{Tier: contract.TierJail}}
	defer close(eng.block)
	a, _ := fixture(t, true, eng, 0x77)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the inline submit
	fs := &fakeStream{ctx: ctx, reqs: []*extprocv3.ProcessingRequest{headersReq(canaryPath, srcAddr, dstAddr)}}
	_ = a.Process(fs)
	if len(fs.sent) != 1 {
		t.Fatalf("expected one response, got %d", len(fs.sent))
	}
	if code, ok := immediate(fs.sent[0]); !ok || code != int(typev3.StatusCode_Forbidden) {
		t.Fatalf("a cancelled inline submit should fail-closed (403), got %+v", fs.sent[0])
	}
}

func TestResolveCookieBoundedRetryAbsorbsRace(t *testing.T) {
	eng := &recEngine{out: contract.Verdict{Tier: contract.TierObserve}}
	reg := seeder.NewMemRegistry()
	_ = reg.Put(seeder.Placement{Scope: "scope-a", Type: "decoy_file", Location: canaryPath})
	res := identity.NewFakeResolver()
	ft, _ := identity.TupleFromAddrs("203.0.113.7", 54321, "10.0.0.2", 8443)
	res.MissThenHit(ft, identity.Resolution{Cookie: 0x66}, 2) // miss twice, then hit
	a, err := New(Config{Engine: eng, Registry: reg, Resolver: res, Scope: "scope-a", Inline: true, ResolveRetry: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	run(t, a, headersReq(canaryPath, srcAddr, dstAddr))
	if eng.count() != 1 || eng.event().Flow.SocketCookie != 0x66 {
		t.Fatalf("bounded retry did not resolve the cookie after the race: calls=%d cookie=%x", eng.count(), eng.event().Flow.SocketCookie)
	}
}
