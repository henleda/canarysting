// Package evaluation ingests CanaryAttacker ground truth for bounded
// CanaryView correlation-laboratory evaluation.
//
// It is an outer laboratory boundary: ground truth remains in its native
// declared schema while independently built CanaryView traces remain unchanged.
// The package never creates an Observation, correlation Record, trace hop, or
// production-store input from attacker intent or action records.
package evaluation
