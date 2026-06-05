// Package network implements docs/INTELLIGENCE.md section 5.4 — cross-customer network. The egress filter here is the single default-deny chokepoint for anything crossing a deployment boundary (see section 2). Build it first and most carefully.
//
// Guardrails that never relax (docs/INTELLIGENCE.md section 8): the canary touch
// is the only trigger (docs/BASELINE_MULTIPLIER.md), learned state is
// scope-isolated (docs/SCOPE.md), and only anonymized patterns cross a boundary
// (docs/INTELLIGENCE.md section 2).
package network
