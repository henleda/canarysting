// Package profile implements docs/INTELLIGENCE.md section 4 — fingerprints and AI-attacker profiling; emits training-ready profiles for Model 2.
//
// Guardrails that never relax (docs/INTELLIGENCE.md section 8): the canary touch
// is the only trigger (docs/BASELINE_MULTIPLIER.md), learned state is
// scope-isolated (docs/SCOPE.md), and only anonymized patterns cross a boundary
// (docs/INTELLIGENCE.md section 2).
package profile
