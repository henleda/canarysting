// Package planner coordinates untrusted model proposals with the reviewed
// CanaryAttacker executor. The model sees only opaque, zero-argument action
// handles; target, fixture, credential, operation, policy, and budget values
// remain outside the model boundary.
package planner
