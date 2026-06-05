// Package feed implements docs/INTELLIGENCE.md section 5.5 — external threat-intel feed; read view over the anonymized, aggregated set.
//
// Guardrails that never relax (docs/INTELLIGENCE.md section 8): the canary touch
// is the only trigger (docs/BASELINE_MULTIPLIER.md), learned state is
// scope-isolated (docs/SCOPE.md), and only anonymized patterns cross a boundary
// (docs/INTELLIGENCE.md section 2).
package feed
