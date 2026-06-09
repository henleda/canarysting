package envoy

import (
	"context"
	"time"

	"github.com/canarysting/canarysting/internal/sting/attrition"
)

// defaultAttritionBodyCap bounds the deception body assembled into a single
// ext_proc ImmediateResponse. It must be << the attrition per-flow byte budget
// (DefaultMaxBytesPerFlow = 5 MiB): the attacker's cost is the real hold + the
// full byte/token meter (we keep draining past the cap), but the DEFENDER only
// ever buffers up to this cap at once. 64 KiB is enough to look like a plausible
// config/maze page while staying tiny relative to the budget.
const defaultAttritionBodyCap = 64 << 10 // 64 KiB

// sleepFunc waits d, returning early with ctx.Err() if ctx is cancelled first.
// It is the injection seam that makes the pump's REAL hold testable: production
// uses realSleep (an actual timer); tests pass a fake that records-but-does-not-
// wait, so the suite proves the pump WOULD impose the delays without sleeping
// seconds.
type sleepFunc func(ctx context.Context, d time.Duration) error

// realSleep is the production hold: a timer that fires after d, cancellable by
// ctx (a client disconnect / Envoy ext_proc timeout ends the hold cleanly).
func realSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		// Still honor cancellation even with a zero delay.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// pumpStream drives the attrition stream and IMPOSES THE REAL HOLD: after each
// chunk it sleeps that chunk's Delay (via sleep), so the attacker's wall-time is
// real, not read off a clock-free meter. It accumulates chunk bytes into the
// response body up to bodyCap; once the cap is hit it KEEPS pulling + sleeping
// (the hold itself is the cost) but stops appending bytes, so the defender's
// buffer stays bounded while the attacker still pays full time/tokens.
//
// It selects on ctx.Done() at every wait, so a client disconnect or an Envoy
// ext_proc message_timeout cancels the hold promptly: attrition's own Next sees
// the cancelled ctx and finishes the stream with DoneKilled, and any in-progress
// sleep returns immediately. The returned outcome reflects the REAL elapsed hold
// (sum of the delays actually waited before stream-end/cancel).
//
// This is the ONLY adapter logic that touches attrition: it calls the public
// Stream interface, makes no decisions, and imports nothing from internal/engine
// or internal/intelligence (the import-graph guard holds). The caller owns
// s.Close().
func pumpStream(ctx context.Context, s attrition.Stream, bodyCap int, sleep sleepFunc) (body []byte, outcome attrition.Outcome) {
	if sleep == nil {
		sleep = realSleep
	}
	if bodyCap <= 0 {
		bodyCap = defaultAttritionBodyCap
	}
	var buf []byte
	for {
		chunk, done, err := s.Next(ctx)
		if err != nil || done != attrition.NotDone {
			break
		}
		// Append up to the cap; past it the body is frozen but the hold continues.
		if len(buf) < bodyCap {
			room := bodyCap - len(buf)
			if len(chunk.Data) <= room {
				buf = append(buf, chunk.Data...)
			} else {
				buf = append(buf, chunk.Data[:room]...)
			}
		}
		// Impose the real hold: wait this chunk's delay before pulling the next.
		// A cancelled ctx ends the hold. We then pull once more so attrition's own
		// ctx gate finishes the stream as DoneKilled (the meter must report the
		// cancel, not stay NotDone); that extra Next does no work and never sleeps.
		if err := sleep(ctx, chunk.Delay); err != nil {
			// FINALIZE THE COST METER: this extra Next lets the attrition stream observe
			// the cancelled ctx and set Outcome.Reason=DoneKilled. NotDone is a non-
			// terminal state and is never a valid Outcome.Reason reported to the engine;
			// without this call the meter would stay NotDone after a ctx-cancel exit.
			_, _, _ = s.Next(ctx)
			break
		}
	}
	return buf, s.Outcome()
}
