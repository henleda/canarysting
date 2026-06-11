package envoy

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/sting/attrition"
)

// exploitMarkers are FIXED, documented structural byte-shapes a request carries when
// an automated exploit is fired at it (path traversal, known exposed-config probes,
// JNDI/SQLi/LFI/XSS shapes). They are a closed, hand-maintained set of TRANSPORT-SHAPE
// facts — not a learned or scored detector — so matching them here is a transport-fact
// digest, NOT engine detection logic (rule 1). The shapes are deliberately SPECIFIC to
// keep the count honest: bare "${" / "{{" / " union " / " select " were dropped because
// they over-match benign query strings; the kept SQLi/JNDI shapes ("union select",
// "' or '", "${jndi:") are specific enough not to fire on ordinary traffic. Matched
// against the full lowercased :path (query included — probes commonly live in the query).
var exploitMarkers = []string{
	"../", "..%2f", "..\\", "%00", // path traversal / null byte
	"/.git/", "/actuator", "/.env", "/.aws/", "/cgi-bin/", "/wp-admin", // exposed-config / common automated targets
	"${jndi:",                               // JNDI injection (specific)
	"/etc/passwd", "union select", "' or '", // LFI / SQLi (specific shapes)
	"<script", "onerror=", // XSS shapes
}

// digestObservation maps a request's TRANSPORT SHAPE (the method + path the adapter
// already extracted) into the structured contract.DriverObservation the attrition
// stream's Observe seam consumes — counts/bools ONLY, never raw bytes/addresses
// (rule 9). SuspectedExploit is true iff the lowercased path carries a fixed
// structural exploit marker. Like classifyDisengage, this is a transport-fact digest,
// NOT detection logic (rule 1): the engine already decided the tier; this only
// annotates the inbound shape so AX4 can COUNT exploits fired at the decoy
// (Outcome.ExploitsObserved). It NEVER reaches back at the attacker (docs/STING.md
// "not hack-back").
func digestObservation(obs RequestObservation) contract.DriverObservation {
	p := strings.ToLower(obs.Path)
	suspected := false
	for _, m := range exploitMarkers {
		if strings.Contains(p, m) {
			suspected = true
			break
		}
	}
	return contract.DriverObservation{
		RequestCount:     1, // one inbound request drives this attrition stream
		DistinctDecoys:   1, // this canary touch; flow-level enumeration breadth aggregates downstream
		SuspectedExploit: suspected,
	}
}

// classifyDisengage maps how an inline attrition hold ended to a
// contract.DisengageReason + the attacker-initiated disengage time (AX1 / D7).
// ONLY the adapter can do this: attrition.Stream.Next sees a cancelled context as
// DoneKilled and cannot tell a client disconnect (the attacker gave up) from the
// defender's own AttritionMaxHold deadline. The hold context disambiguates them —
// context.Canceled is a downstream/attacker disconnect, context.DeadlineExceeded is
// our max-hold cap. This is a transport-fact mapping, not detection logic (rule 1).
// timeToDisengageSec is the real imposed hold, reported ONLY when the attacker
// disengaged first (the engagement signal); every defender-stop reports 0.
func classifyDisengage(reason attrition.DoneReason, holdErr error, timeHeldSec float64) (disengageReason int, timeToDisengageSec float64) {
	switch {
	case errors.Is(holdErr, context.Canceled):
		return contract.DisengageAttacker, timeHeldSec
	case errors.Is(holdErr, context.DeadlineExceeded):
		return contract.DisengageDefenderCapped, 0
	}
	// holdErr == nil: the stream ended on its own terms (or the kill switch tripped).
	switch reason {
	case attrition.DoneComplete:
		return contract.DisengageGeneratorDone, 0
	case attrition.DoneFlowBudget, attrition.DoneGlobalCeiling, attrition.DoneKilled:
		return contract.DisengageDefenderCapped, 0
	default:
		return contract.DisengageUnknown, 0
	}
}

// defaultAttritionBodyCap bounds the deception body assembled into a single
// ext_proc ImmediateResponse. It must be << the attrition per-flow byte budget
// (DefaultMaxBytesPerFlow = 5 MiB): the attacker's cost is the real hold + the
// full byte/token meter (we keep draining past the cap), but the DEFENDER only
// ever buffers up to this cap at once. 64 KiB is enough to look like a plausible
// config/maze page while staying tiny relative to the budget.
const defaultAttritionBodyCap = 64 << 10 // 64 KiB

// defaultAttritionMaxHold hard-bounds one inline flow's hold. It MUST be < the
// proxy's ext_proc message_timeout (Envoy's is 10s in deploy/m7-window/envoy.yaml)
// so the deception body is delivered within the proxy's window and the defender
// releases the goroutine promptly. Enforced as a context deadline on the pump.
const defaultAttritionMaxHold = 8 * time.Second

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
