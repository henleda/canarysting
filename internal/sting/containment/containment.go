// Package containment stops egress and holds an actor: rate-limit, hard deny,
// jail socket/cgroup. Kernel-enforced via bpf/. Fail-closed at Tier 3. Acts
// ONLY on flows attributable by socket cookie / cgroup / PID — a jailed
// bystander is a critical failure. See docs/STING.md and docs/IDENTITY.md.
package containment

import "github.com/canarysting/canarysting/internal/contract"

// Action is a containment action keyed to a flow.
type Action int

const (
	RateLimit Action = iota
	HardDeny
	Jail
)

// Container applies containment for a verdict.
type Container interface {
	// Apply enforces containment for a flow. Returns an error and applies
	// nothing if the flow lacks a socket cookie (unattributable).
	Apply(contract.Verdict, Action) error
}

// TODO: drive bpf/loader maps keyed by socket cookie; refuse to act on
// unattributable flows.
