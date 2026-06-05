// Package cost implements docs/INTELLIGENCE.md section 5.3 — attacker-cost metric; reporting view over the event store.
//
// Guardrails that never relax (docs/INTELLIGENCE.md section 8): the canary touch
// is the only trigger (docs/BASELINE_MULTIPLIER.md), learned state is
// scope-isolated (docs/SCOPE.md), and only anonymized patterns cross a boundary
// (docs/INTELLIGENCE.md section 2).
package cost
