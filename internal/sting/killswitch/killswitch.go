// Package killswitch is the deployment-wide, operator-tripped, timed ENFORCEMENT
// DISARM control (SLICE B1). It is a single, thread-safe, lazily-evaluated flag
// that the engine emit-seam (internal/boot capturingEngine.Submit) consults to
// decide whether to FLOOR an emitted verdict's enforceable tier to the
// observe/no-action level before returning it to the gRPC caller (the adapter).
//
// WHAT IT IS (and is NOT):
//   - It is a DISARM control. Engaging it only ever REDUCES enforcement: it floors
//     verdict tiers so the downstream adapter takes NO containment action and
//     RELEASES any existing containment for a flow. It is the operator's "stop the
//     stings" lever.
//   - It is NOT an arm. There is NO code path here, or reachable from here, that
//     RAISES a tier, opens a sting, or escalates anything. This is CLAUDE.md
//     RULE 8 made structural: a flag that can only floor a verdict can never be a
//     trigger. The type exposes Engage/Revive/Active/Status and nothing that
//     returns a higher tier or an enforcement action. Fail-safety is therefore
//     trivial: whatever its state, applying it can only make the system act LESS,
//     never more — so it is ALWAYS safe to apply (a stuck-engaged kill-switch
//     halts enforcement; a stuck-disengaged one is just the normal posture).
//
// LAZY / DETERMINISTIC EXPIRY: a timed engagement auto-expires by COMPARISON
// against an injected clock at read time (Active(now) / Status(now)), NOT via a
// background goroutine. This keeps the component deterministic and race-clean
// (the seam already calls it serially per flow, and the clock is the same logical
// time the audit/capture calls use), and trivially testable. A non-positive
// duration means "until revived" (INDEFINITE) — there is no auto-expire, only an
// explicit Revive clears it. That rule is documented and tested.
//
// LAYER SEAM: this package imports ONLY the standard library (sync, time) — not
// even contract. It does not import the engine, the adapters, attrition, or
// containment, so wiring it into the boot
// composition root creates no import cycle and leaks no enforcement internals into
// a disarm control. The audit append (the tamper-evident record of each
// engage/revive) is done by the CALLER (internal/boot), which holds the audit
// store — this package returns the facts to record and never reaches into a store
// itself.
package killswitch

import (
	"sync"
	"time"
)

// Status is the read-only view of the kill-switch for the IR/operator surface
// (the dashboard tap renders it as "ENFORCEMENT HALTED by <operator>, expires
// <t>"). It is a value snapshot; mutating it does not affect the switch.
type Status struct {
	// Engaged reports whether enforcement is currently disarmed (true iff the
	// switch was Engaged AND, for a timed engagement, the evaluation `now` has not
	// passed ExpiresAt). It is the SAME predicate Active(now) returns.
	Engaged bool `json:"engaged"`
	// Operator is who engaged it (free-form, recorded for the audit trail). "" when
	// never engaged or after a revive.
	Operator string `json:"operator,omitempty"`
	// Reason is the operator-supplied justification. "" when never engaged.
	Reason string `json:"reason,omitempty"`
	// EngagedAt is when it was tripped (zero when never engaged / revived).
	EngagedAt time.Time `json:"engaged_at,omitempty"`
	// ExpiresAt is when a TIMED engagement auto-expires. ZERO means INDEFINITE
	// (duration<=0 => until revived) — it never auto-expires. Read it together with
	// Engaged: a zero ExpiresAt with Engaged=true is an indefinite halt.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// KillSwitch is the thread-safe, timed enforcement-disarm flag. The zero value is
// NOT usable (its clock is nil); construct one with New. All state access is under
// a mutex — this is a control-plane control, never on the per-packet hot path
// (the seam consults it once per emitted verdict).
type KillSwitch struct {
	mu sync.Mutex
	// now is the injected clock (for deterministic tests). New defaults it to
	// time.Now. The seam passes its own logical clock to Active/Status, so this
	// internal clock is only used where a caller does not supply a `now`.
	now func() time.Time

	engaged   bool
	operator  string
	reason    string
	engagedAt time.Time
	// expiresAt is the auto-expire instant for a TIMED engagement; the zero value
	// means INDEFINITE (no auto-expire). Only meaningful while engaged.
	expiresAt time.Time
}

// New returns a disengaged KillSwitch using clock for any internal time reads. A
// nil clock defaults to time.Now (so a caller that does not need a fake clock can
// pass nil). The switch starts DISENGAGED — the safe, normal posture (enforcement
// active); it never starts engaged, mirroring the rule that nothing here arms or
// changes posture on its own.
func New(clock func() time.Time) *KillSwitch {
	if clock == nil {
		clock = time.Now
	}
	return &KillSwitch{now: clock}
}

// Engage trips the switch as of `now`, recording who/when/why and computing the
// expiry. A duration d > 0 sets an auto-expire at now+d; a duration d <= 0 means
// INDEFINITE (no auto-expire — only Revive clears it). Re-engaging an already-
// engaged switch is allowed and simply replaces the operator/reason/expiry (e.g.
// to extend a window), recorded as a fresh engagement. It returns the resulting
// Status so the caller (boot) can audit-append the exact recorded facts.
//
// RULE 8: this only ever moves the switch toward "disarm enforcement". It cannot
// raise a tier or open a sting — it has no such field to set.
func (k *KillSwitch) Engage(now time.Time, d time.Duration, operator, reason string) Status {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.engaged = true
	k.operator = operator
	k.reason = reason
	k.engagedAt = now
	if d > 0 {
		k.expiresAt = now.Add(d)
	} else {
		k.expiresAt = time.Time{} // indefinite (until revived)
	}
	return k.statusLocked(now)
}

// Revive clears the switch as of `now`, recording who/why for the audit trail. It
// is idempotent: reviving an already-disengaged switch is a no-op that still
// returns a (disengaged) Status, so the caller may still audit the operator
// action. It returns the resulting (disengaged) Status.
func (k *KillSwitch) Revive(now time.Time, operator, reason string) Status {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.engaged = false
	// Keep operator/reason cleared so a stale "engaged by" cannot linger on the
	// IR surface after a revive. The audit chain holds the historical record.
	k.operator = ""
	k.reason = ""
	k.engagedAt = time.Time{}
	k.expiresAt = time.Time{}
	// operator/reason are not stored on a disengaged switch (the live IR status must
	// not show a stale "engaged by"); the audit chain holds the historical who/why.
	return k.statusLocked(now)
}

// Active reports whether enforcement is currently DISARMED as of `now`: true iff
// the switch is engaged AND (the engagement is indefinite OR now is before the
// expiry). Auto-expiry is evaluated lazily here — once now reaches expiresAt the
// switch reads as inactive, with no background goroutine. nil-receiver safe: a nil
// *KillSwitch is never active (so the seam's `k != nil && k.Active(now)` guard is
// belt-and-suspenders, not required).
//
// SAFETY — the caller MUST pass a TRUSTED server-side clock (the engine's own wall
// clock), NEVER an event/request-supplied timestamp. The disarm window is an operator
// concept; gating it on an adapter-supplied wire timestamp would let a skewed or
// hostile adapter date a touch past the expiry and slip a verdict through an active
// halt. The boot emit-seam (killSwitchEngine) passes the injected engine clock for
// exactly this reason.
func (k *KillSwitch) Active(now time.Time) bool {
	if k == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.activeLocked(now)
}

// activeLocked is the engaged-and-not-expired predicate. Caller holds k.mu.
func (k *KillSwitch) activeLocked(now time.Time) bool {
	if !k.engaged {
		return false
	}
	if k.expiresAt.IsZero() {
		return true // indefinite engagement
	}
	return now.Before(k.expiresAt)
}

// Status returns the IR/operator snapshot as of `now`. The Engaged field reflects
// the SAME lazy auto-expire as Active(now): an expired timed engagement reports
// Engaged=false (and the operator/reason/timestamps are reported as the snapshot
// the caller can show — but Engaged is the authoritative "is enforcement halted"
// bit). nil-receiver safe (returns the zero, disengaged Status).
func (k *KillSwitch) Status(now time.Time) Status {
	if k == nil {
		return Status{}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.statusLocked(now)
}

// statusLocked builds the snapshot under the held lock. Caller holds k.mu.
func (k *KillSwitch) statusLocked(now time.Time) Status {
	active := k.activeLocked(now)
	return Status{
		Engaged:   active,
		Operator:  k.operator,
		Reason:    k.reason,
		EngagedAt: k.engagedAt,
		ExpiresAt: k.expiresAt,
	}
}
