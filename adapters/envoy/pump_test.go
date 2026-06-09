package envoy

import (
	"context"
	"testing"
	"time"

	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/attrition"
)

// recordingSleep is a fake hold timer: it records each delay it WOULD wait and
// returns immediately, so a test proves the pump imposes the delays without
// actually sleeping seconds. It honors ctx cancellation like realSleep.
type recordingSleep struct {
	delays []time.Duration
	total  time.Duration
}

func (r *recordingSleep) fn(ctx context.Context, d time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r.delays = append(r.delays, d)
	r.total += d
	return nil
}

// liveAttritor builds a moderate-floor attritor with fast, deterministic drip so
// the pump produces a real (non-noop) stream quickly.
func liveAttritor(t *testing.T) *attrition.BoundedAttritor {
	t.Helper()
	a, err := attrition.New(attrition.Config{
		Floor:  contract.FloorModerate,
		Budget: attrition.Budget{MaxBytesPerFlow: 1 << 20, MaxDepth: attrition.DefaultMaxDepth, MaxDuration: 1000 * time.Hour},
		Drip:   attrition.DripParams{ChunkBytes: 64, MinDelay: 2 * time.Second, MaxDelay: 2 * time.Second},
	})
	if err != nil {
		t.Fatalf("building attritor: %v", err)
	}
	return a
}

func t2Verdict() contract.Verdict {
	return contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: 0xC0FFEE}, Tier: contract.TierContain, Mode: contract.ModeInline}
}

// The pump produces a non-empty body and a cost meter whose BytesServed equals
// the bytes actually emitted. With a tight per-flow byte budget (4 KiB) and a
// generous body cap (64 KiB), the whole stream fits under the cap, so every byte
// served lands in the body and BytesServed == len(body).
func TestPumpStreamBytesAccumulate(t *testing.T) {
	a, err := attrition.New(attrition.Config{
		Floor:  contract.FloorModerate,
		Budget: attrition.Budget{MaxBytesPerFlow: 4096, MaxDepth: attrition.DefaultMaxDepth, MaxDuration: 1000 * time.Hour},
		Drip:   attrition.DripParams{ChunkBytes: 64, MinDelay: 2 * time.Second, MaxDelay: 2 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := a.Open(t2Verdict())
	defer s.Close()
	rs := &recordingSleep{}
	body, out := pumpStream(context.Background(), s, 64<<10, rs.fn)
	if len(body) == 0 {
		t.Fatal("pump produced an empty body for a live stream")
	}
	if out.BytesServed != int64(len(body)) {
		t.Fatalf("BytesServed = %d, want %d (== body len, whole stream under the cap)", out.BytesServed, len(body))
	}
	if out.Mechanism != attrition.MechFakeTree {
		t.Fatalf("mechanism = %q, want %q (moderate floor, T2)", out.Mechanism, attrition.MechFakeTree)
	}
}

// The pump IMPOSES THE REAL HOLD: it calls sleep once per pulled chunk with that
// chunk's delay, so the recorded total equals the outcome's TimeHeldSec. With the
// fake sleep this is proven without waiting any wall-clock time.
func TestPumpStreamImposesRealHold(t *testing.T) {
	a := liveAttritor(t)
	s := a.Open(t2Verdict())
	defer s.Close()
	rs := &recordingSleep{}
	_, out := pumpStream(context.Background(), s, 4096, rs.fn)

	if len(rs.delays) == 0 {
		t.Fatal("pump never slept — the hold was not imposed")
	}
	// Every recorded delay is the drip's fixed 2s, and the sum equals the meter.
	if rs.total.Seconds() != out.TimeHeldSec {
		t.Fatalf("slept total %.1fs != outcome TimeHeldSec %.1fs", rs.total.Seconds(), out.TimeHeldSec)
	}
	if out.TimeHeldSec <= 0 {
		t.Fatalf("TimeHeldSec = %v, want > 0 (real hold)", out.TimeHeldSec)
	}
}

// The body is capped: past the cap the pump keeps draining + sleeping (the hold
// is the cost) but stops appending, so the defender's buffer stays bounded while
// the attacker still pays full bytes/time.
func TestPumpStreamBodyCapRespected(t *testing.T) {
	a := liveAttritor(t)
	s := a.Open(t2Verdict())
	defer s.Close()
	rs := &recordingSleep{}
	const cap = 128
	body, out := pumpStream(context.Background(), s, cap, rs.fn)
	if len(body) > cap {
		t.Fatalf("body len = %d, want <= cap %d", len(body), cap)
	}
	// The attacker's meter exceeds the frozen body: bytes kept being served past
	// the cap, so the cost is real even though the buffer is tiny.
	if out.BytesServed <= int64(len(body)) {
		t.Fatalf("BytesServed = %d, want > body len %d (drained past the cap)", out.BytesServed, len(body))
	}
}

// A noop stream (verdict below Tier 2) yields zero bytes and the noop reason.
func TestPumpStreamNoopAttritor(t *testing.T) {
	a := liveAttritor(t)
	s := a.Open(contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: 1}, Tier: contract.TierTag})
	defer s.Close()
	rs := &recordingSleep{}
	body, out := pumpStream(context.Background(), s, 4096, rs.fn)
	if len(body) != 0 {
		t.Fatalf("noop stream produced %d body bytes, want 0", len(body))
	}
	if out.Reason != attrition.DoneNoOp {
		t.Fatalf("noop reason = %v, want DoneNoOp", out.Reason)
	}
	if len(rs.delays) != 0 {
		t.Fatal("noop stream should never sleep")
	}
}

// A cancelled context ends the hold promptly: the pump stops and the outcome
// reports DoneKilled (attrition's Next sees the cancelled ctx).
func TestPumpStreamContextCancel(t *testing.T) {
	a := liveAttritor(t)
	s := a.Open(t2Verdict())
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before the first pull
	body, out := pumpStream(ctx, s, 4096, realSleep)
	if len(body) != 0 {
		t.Fatalf("cancelled pump produced %d body bytes, want 0", len(body))
	}
	// The finalize-the-cost-meter Next (pump.go) must move the meter off the
	// non-terminal NotDone: NotDone is never a valid terminal Outcome.Reason.
	if out.Reason == attrition.NotDone {
		t.Fatalf("cancel reason = NotDone, want a terminal reason (finalize Next not applied)")
	}
	if out.Reason != attrition.DoneKilled {
		t.Fatalf("cancel reason = %v, want DoneKilled", out.Reason)
	}
}

// A mid-stream cancel (the fake sleep cancels the ctx after the first hold) stops
// the pump with a partial body and DoneKilled — the hold is cut short cleanly.
func TestPumpStreamCancelMidHold(t *testing.T) {
	a := liveAttritor(t)
	s := a.Open(t2Verdict())
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	cancelOnFirstSleep := func(c context.Context, d time.Duration) error {
		if c.Err() != nil {
			return c.Err()
		}
		calls++
		cancel() // simulate the client disconnecting during the first hold
		return c.Err()
	}
	body, out := pumpStream(ctx, s, 1<<20, cancelOnFirstSleep)
	if calls != 1 {
		t.Fatalf("sleep called %d times, want exactly 1 (cancelled mid-hold)", calls)
	}
	// One chunk was emitted before the cancel landed.
	if len(body) == 0 {
		t.Fatal("expected a partial body from the one chunk pulled before cancel")
	}
	if out.Reason != attrition.DoneKilled {
		t.Fatalf("reason = %v, want DoneKilled", out.Reason)
	}
}

// nil sleep defaults to realSleep; a zero-delay drip then returns instantly.
func TestPumpStreamNilSleepDefaultsReal(t *testing.T) {
	a, err := attrition.New(attrition.Config{
		Floor:  contract.FloorModerate,
		Budget: attrition.Budget{MaxBytesPerFlow: 4096, MaxDepth: attrition.DefaultMaxDepth, MaxDuration: 1000 * time.Hour},
		Drip:   attrition.DripParams{ChunkBytes: 64, MinDelay: time.Nanosecond, MaxDelay: time.Nanosecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := a.Open(t2Verdict())
	defer s.Close()
	body, out := pumpStream(context.Background(), s, 4096, nil) // nil => realSleep
	if len(body) == 0 || out.BytesServed == 0 {
		t.Fatal("nil-sleep pump produced no body/bytes")
	}
}

// --- adapter-level wiring: attritionOrDeny ---

// A live attritor at T2 inline produces a 429 with a non-empty deception body.
func TestAttritionOrDenyLiveStream(t *testing.T) {
	a := adapterWithAttritor(t, liveAttritor(t), nil)
	r := a.attritionOrDeny(context.Background(), contract.SignalEvent{}, t2Verdict(), typev3.StatusCode_TooManyRequests, "rate limited\n")
	ir := r.GetImmediateResponse()
	if ir == nil || ir.GetStatus().GetCode() != typev3.StatusCode_TooManyRequests {
		t.Fatalf("want 429 immediate, got %+v", r)
	}
	if len(ir.GetBody()) == 0 {
		t.Fatal("attrition deny carried an empty body; want a deception payload")
	}
}

// A nil attritor falls back to the plain deny (existing immediateDeny body).
func TestAttritionOrDenyNilAttritorFallsBack(t *testing.T) {
	a := adapterWithAttritor(t, nil, nil)
	r := a.attritionOrDeny(context.Background(), contract.SignalEvent{}, contract.Verdict{Tier: contract.TierJail, Mode: contract.ModeInline}, typev3.StatusCode_Forbidden, "forbidden\n")
	ir := r.GetImmediateResponse()
	if ir == nil || ir.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("want 403 immediate, got %+v", r)
	}
	if string(ir.GetBody()) != "forbidden\n" {
		t.Fatalf("nil-attritor body = %q, want plain fallback", ir.GetBody())
	}
}

// A noop stream (verdict below Tier 2 reaching the pump) falls back to plain deny.
func TestAttritionOrDenyNoopFallsBack(t *testing.T) {
	a := adapterWithAttritor(t, liveAttritor(t), nil)
	// Tier 1 verdict => Open returns a noop stream => empty body => fallback.
	v := contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: 9}, Tier: contract.TierTag, Mode: contract.ModeInline}
	r := a.attritionOrDeny(context.Background(), contract.SignalEvent{}, v, typev3.StatusCode_TooManyRequests, "rate limited\n")
	ir := r.GetImmediateResponse()
	if ir == nil || string(ir.GetBody()) != "rate limited\n" {
		t.Fatalf("noop should fall back to plain body, got %+v", r)
	}
}

// OnOutcome fires (exactly once) with a non-zero cost meter; it is fire-and-
// forget (a goroutine), so the test waits on a channel.
func TestAttritionOrDenyOnOutcomeFires(t *testing.T) {
	got := make(chan attrition.Outcome, 1)
	a := adapterWithAttritor(t, liveAttritor(t), func(_ contract.SignalEvent, _ contract.Verdict, out attrition.Outcome) {
		got <- out
	})
	a.attritionOrDeny(context.Background(), contract.SignalEvent{Scope: "s", Flow: contract.FlowIdentity{SocketCookie: 0xC0FFEE}}, t2Verdict(), typev3.StatusCode_TooManyRequests, "rate limited\n")
	select {
	case out := <-got:
		if out.BytesServed == 0 {
			t.Fatalf("OnOutcome fired with zero BytesServed: %+v", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnOutcome never fired")
	}
}

// OnOutcome is fire-and-forget STRUCTURALLY, not just eventually: attritionOrDeny
// returns the assembled ImmediateResponse while the OnOutcome callback is still
// blocked. We inject a callback that blocks on a barrier, call attritionOrDeny in a
// goroutine, and assert the response is ready within a short timeout BEFORE
// unblocking the callback. Then we unblock it and confirm the body was present.
func TestAttritionOrDenyOnOutcomeDoesNotBlockResponse(t *testing.T) {
	barrier := make(chan struct{})
	a := adapterWithAttritor(t, liveAttritor(t), func(_ contract.SignalEvent, _ contract.Verdict, _ attrition.Outcome) {
		<-barrier // block until the test releases us — must NOT hold up the response
	})

	type result struct{ body []byte }
	done := make(chan result, 1)
	go func() {
		r := a.attritionOrDeny(context.Background(), contract.SignalEvent{Scope: "s", Flow: contract.FlowIdentity{SocketCookie: 0xC0FFEE}}, t2Verdict(), typev3.StatusCode_TooManyRequests, "rate limited\n")
		done <- result{body: r.GetImmediateResponse().GetBody()}
	}()

	// The response must be ready while the callback is STILL blocked.
	select {
	case r := <-done:
		if len(r.body) == 0 {
			t.Fatal("response returned but carried an empty deception body")
		}
	case <-time.After(2 * time.Second):
		close(barrier) // unblock to avoid a stuck goroutine before failing
		t.Fatal("attritionOrDeny blocked on the OnOutcome callback (not fire-and-forget)")
	}
	// Now release the still-blocked callback so its goroutine exits cleanly.
	close(barrier)
}

// End to end through Process: a T2-inline canary touch with a wired attritor
// returns a 429 with a deception body, and OnOutcome fires with the cookie+scope
// the composition root needs to report the outcome.
func TestProcessTier2InlineAttritionBodyAndOutcome(t *testing.T) {
	// The verdict must carry the resolved flow (the real engine copies it from the
	// event); the attritor refuses an unattributable cookie-0 flow (rule: precision).
	eng := &recEngine{out: contract.Verdict{Flow: contract.FlowIdentity{SocketCookie: 0x4242}, Tier: contract.TierContain, Mode: contract.ModeInline}}
	a, _ := fixture(t, true, eng, 0x4242)
	got := make(chan attrition.Outcome, 1)
	gotEv := make(chan contract.SignalEvent, 1)
	cfg := a.cfg
	cfg.Attritor = liveAttritor(t)
	cfg.OnOutcome = func(ev contract.SignalEvent, _ contract.Verdict, out attrition.Outcome) {
		gotEv <- ev
		got <- out
	}
	cfg.attritionSleep = func(ctx context.Context, _ time.Duration) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	a.cfg = cfg

	sent := run(t, a, headersReq(canaryPath, srcAddr, dstAddr))
	code, ok := immediate(sent[0])
	if !ok || code != int(typev3.StatusCode_TooManyRequests) {
		t.Fatalf("T2 inline with attritor should 429, got %+v", sent[0])
	}
	if len(sent[0].GetImmediateResponse().GetBody()) == 0 {
		t.Fatal("attrition 429 carried an empty body; want a deception payload")
	}
	select {
	case out := <-got:
		if out.BytesServed == 0 || out.TimeHeldSec == 0 {
			t.Fatalf("outcome has zero cost: %+v", out)
		}
		ev := <-gotEv
		if ev.Flow.SocketCookie != 0x4242 {
			t.Fatalf("outcome event cookie = %#x, want 0x4242", ev.Flow.SocketCookie)
		}
		if ev.Scope != "scope-a" {
			t.Fatalf("outcome event scope = %q, want scope-a", ev.Scope)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnOutcome never fired for a T2-inline attrition touch")
	}
}

// A Tier-1 inline verdict never reaches the pump: responseWithAttrition routes it
// through the unchanged responseForVerdict path (CONTINUE + tag), even with an
// attritor wired.
func TestResponseWithAttritionTier1NeverPumps(t *testing.T) {
	a := adapterWithAttritor(t, liveAttritor(t), func(contract.SignalEvent, contract.Verdict, attrition.Outcome) {
		t.Fatal("OnOutcome must not fire for a Tier-1 verdict")
	})
	r := a.responseWithAttrition(context.Background(), contract.SignalEvent{}, contract.Verdict{Tier: contract.TierTag, Mode: contract.ModeInline})
	if r.GetImmediateResponse() != nil {
		t.Fatalf("Tier 1 must CONTINUE, got immediate %+v", r)
	}
	if r.GetRequestHeaders() == nil {
		t.Fatal("Tier 1 should be a request-headers CONTINUE")
	}
	// Give any (erroneous) fire-and-forget goroutine a beat to run and fail.
	time.Sleep(20 * time.Millisecond)
}

// An async Tier-2/3 verdict never reaches the pump (kernel enforces): CONTINUE.
func TestResponseWithAttritionAsyncNeverPumps(t *testing.T) {
	a := adapterWithAttritor(t, liveAttritor(t), func(contract.SignalEvent, contract.Verdict, attrition.Outcome) {
		t.Fatal("OnOutcome must not fire for an async verdict")
	})
	r := a.responseWithAttrition(context.Background(), contract.SignalEvent{}, contract.Verdict{Tier: contract.TierJail, Mode: contract.ModeAsync})
	if r.GetImmediateResponse() != nil {
		t.Fatalf("async tier must CONTINUE at L7, got immediate %+v", r)
	}
	time.Sleep(20 * time.Millisecond)
}

// adapterWithAttritor builds an Adapter (reusing the package fakes) with an
// injected fast (record-only) sleep so attrition tests never wait wall-clock
// seconds, plus the given attritor and outcome hook.
func adapterWithAttritor(t *testing.T, attr attrition.Attritor, onOutcome func(contract.SignalEvent, contract.Verdict, attrition.Outcome)) *Adapter {
	t.Helper()
	a, _ := fixture(t, true, &recEngine{}, 0)
	cfg := a.cfg
	cfg.Attritor = attr
	cfg.OnOutcome = onOutcome
	cfg.attritionSleep = func(ctx context.Context, _ time.Duration) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	a.cfg = cfg
	return a
}
