package stagedlabel

import (
	"net/netip"

	"github.com/canarysting/canarysting/internal/contract"
)

// Labeler turns a real canary-touch verdict into a real feedback label, using
// the declared staged ground truth, and submits it through the engine's single
// feedback seam (contract.FeedbackSink → feedback.Intake → calibration). This is
// how a scope legitimately crosses the calibration evidence floor during the M7
// window. STAGING ONLY — see the package doc for the four production-safety
// gates.
type Labeler struct {
	reg     *Registry
	sink    contract.FeedbackSink
	enabled bool
	// onUndeclared, if set, is notified when an enabled labeler sees a verdict
	// from a source it cannot attribute (no source address, or not in the
	// registry). It produces NO label; the hook is purely for staging visibility.
	onUndeclared func(addr string)
}

// NewLabeler constructs a Labeler. It is a no-op unless enabled is true AND a
// non-nil sink and registry are provided — the safe default is to do nothing.
func NewLabeler(reg *Registry, sink contract.FeedbackSink, enabled bool) *Labeler {
	return &Labeler{reg: reg, sink: sink, enabled: enabled}
}

// OnUndeclared sets a visibility hook for verdicts from undeclared sources.
func (l *Labeler) OnUndeclared(fn func(addr string)) { l.onUndeclared = fn }

// OnVerdict matches the adapter's OnVerdict hook signature exactly, so it wires
// in with no change to the hook. It is invoked ONLY after a real canary touch
// produced a real verdict — there is no path here that fabricates a decision
// (rule 8). It attributes the verdict to a declared identity via the source
// address the adapter stamped into L7Attributes, and emits exactly one label:
// malicious for the declared attacker, benign for a declared legit caller (a
// real false-positive-correction signal). An undeclared or unattributable source
// yields NO label (fail-safe / production-safe).
func (l *Labeler) OnVerdict(ev contract.SignalEvent, v contract.Verdict) {
	if l == nil || !l.enabled || l.sink == nil || l.reg == nil {
		return
	}
	addrStr := ev.Flow.L7Attributes[contract.AttrSourceAddress]
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		l.notifyUndeclared(addrStr)
		return // no attributable source identity → no label
	}
	disp := l.reg.Lookup(ev.Scope, addr)
	if disp == DispUnknown {
		l.notifyUndeclared(addrStr)
		return // undeclared identity → never label (the production-safety fail-safe)
	}
	// No tier floor here, deliberately: the labeler models an analyst confirming
	// ground truth about a REAL canary touch, which is meaningful at any tier
	// (even a Tier-0/Observe touch by the declared attacker is a true malicious
	// interaction worth calibrating on). This is intentionally distinct from the
	// EventStore's Tier≥Tag RETENTION policy (boltevents.CaptureVerdict) — that
	// governs which interactions are durably kept, a different question.
	_ = l.sink.Label(contract.FeedbackLabel{
		Flow:            ev.Flow,
		Scope:           ev.Scope,
		Tier:            v.Tier,
		WasMalicious:    disp == DispAttacker,
		CanariesTouched: []contract.CanaryType{ev.Canary},
		Timestamp:       ev.Timestamp,
	})
}

func (l *Labeler) notifyUndeclared(addr string) {
	if l.onUndeclared != nil {
		l.onUndeclared(addr)
	}
}
