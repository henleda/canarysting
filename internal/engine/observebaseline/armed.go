package observebaseline

import "github.com/canarysting/canarysting/internal/contract"

// armedSet decides whether a flow has touched a canary and so ARMED a response
// (entered the response pipeline, Tier>=1). The F2 deviant capture consults it to
// keep canary-touchers OUT of the deviant log: a deviant record is, by definition,
// a flow that touched NO canary (Rule 8 — observing/logging is not a response; the
// deviants surface is human-hunting with evidence, never an auto-trigger). This is
// the SAME armed/non-armed discrimination the dashboard recon/bystander surfaces
// draw (internal/dashboard/tap/tap.go armedCookies), pushed engine-side to the
// fold seam.
//
// The discrimination is keyed on the SOCKET COOKIE — the L7/kernel join key
// (Rule 4) and the same key boltevents records a canary touch under. A nil armedSet
// degrades gracefully to "nothing is armed" (capture is then gated by the deviant
// floor alone); the engine wires a boltevents-backed implementation in a later
// slice, and tests supply a fake. Like excluder, this records nothing and arms
// nothing — it only filters what is captured.
type armedSet interface {
	// armed reports whether the flow identified by cookie touched a canary within
	// scope (so it belongs to escalation/containment, not the deviant log).
	armed(scope contract.ScopeKey, cookie uint64) bool
}
