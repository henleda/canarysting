// Package network is the SINGLE default-deny egress chokepoint through which any
// derived intelligence may cross a CanarySting deployment boundary (CLAUDE.md rule 9;
// docs/INTELLIGENCE.md §2/§5.4/§7). Design + the formal "cannot re-identify"
// definition: docs/EGRESS_FILTER_DESIGN.md (§5; INTELLIGENCE.md §9 RESOLVED).
//
// The entire public surface is Clear(Candidate) (*Cleared, error) and the opaque
// carrier *Cleared. Cleared has unexported fields and Clear is its only constructor,
// so "everything crossing must pass Clear" is enforced by the Go type system, not by
// convention: a future cross-boundary transport (D6) accepts ONLY *Cleared, and you
// cannot obtain one except through the gate. Clear.Marshal re-validates the carrier
// before emitting wire bytes — the carrier is inside the chokepoint, not a second
// egress surface.
//
// DEFAULT DENY by explicitly-marked-and-justified FIELD: a field crosses only if it
// carries egress:"safe,<reason>", is an allowlisted scalar kind (String only against a
// closed enum), is not on the identity/semantic name denylist, and passes the
// re-identify predicate — recursively, at every struct level. A NEW/untagged field is
// dropped and the candidate rejected whole (fail closed). Coarsening lives UPSTREAM
// (profile.ExportForm, D2); this is the independent second gate.
//
// This MVP ships the GATE + the field-justification model + the formal predicate + the
// AX4/AX5 hard block + the candidate-type denylist + opt-in/k-anonymity + the invariant
// suite. It does NOT ship transport, aggregation, the real coarsening body, or a second
// deployment — those are D6/D7; *Cleared is the seam they consume.
//
// Guardrails that never relax (docs/INTELLIGENCE.md §8): the canary touch is the only
// trigger (the shared set returns as detection CONTEXT only, never an inbound trigger),
// learned state is scope-isolated (docs/SCOPE.md — cost.Summary/baselines/scope state
// are denylisted as candidates outright), and only anonymized patterns cross (§2).
package network
