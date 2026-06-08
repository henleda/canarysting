// Package containment stops egress and holds an actor: rate-limit, hard deny,
// jail socket/cgroup. Kernel-enforced via bpf/ (the loader.Loader), driven here.
// Fail-closed at Tier 3. Acts ONLY on flows attributable by socket cookie — a
// jailed bystander is a critical failure, so an unattributable flow (cookie 0) is
// refused. This package is pure Go over the loader interface (no cilium/ebpf), so
// it is unit-testable anywhere. See docs/STING.md and docs/IDENTITY.md.
package containment

import (
	"errors"
	"fmt"

	"github.com/canarysting/canarysting/bpf/loader"
	"github.com/canarysting/canarysting/internal/contract"
)

// Action is a containment action keyed to a flow. Values match
// loader.Action* and the enforce.bpf.c #defines.
type Action int

const (
	RateLimit Action = iota // Tier 2: token-bucket throttle (actor stays unaware)
	HardDeny                // hard egress deny
	Jail                    // Tier 3: drop the offending socket's egress
)

// ErrUnattributable is returned (and nothing is applied) when a flow has no
// socket cookie — containment never acts on an unattributable flow.
var ErrUnattributable = errors.New("containment: flow has no socket cookie; refusing to contain (unattributable)")

// Documented default Tier-2 token-bucket sizing (a visible but gentle throttle).
const (
	DefaultRateBytesPerSec uint64 = 16 << 10 // 16 KiB/s
	DefaultBurstBytes      uint64 = 32 << 10 // 32 KiB
)

// Container applies and releases containment for a flow.
type Container interface {
	// Apply enforces containment for a flow. Returns ErrUnattributable and applies
	// nothing if the flow lacks a socket cookie.
	Apply(contract.Verdict, Action) error
	// Release lifts containment for a flow (de-escalation / operator clear).
	// Idempotent; a cookie-0 flow is a no-op.
	Release(contract.Verdict) error
}

// ActionForTier maps an engine tier to a containment action. Tiers 0-1 are never
// contained; Tier 2 throttles (gentler, actor unaware); Tier 3 jails.
func ActionForTier(t contract.Tier) (Action, bool) {
	switch {
	case t >= contract.TierJail:
		return Jail, true
	case t == contract.TierContain:
		return RateLimit, true
	default:
		return 0, false
	}
}

// Config configures a KernelContainer.
type Config struct {
	Loader loader.Loader
	// Tier-2 token-bucket sizing; zero uses the documented defaults.
	RateLimitBytesPerSec uint64
	RateLimitBurstBytes  uint64
}

// KernelContainer drives the kernel verdict map via a loader.Loader.
type KernelContainer struct {
	l     loader.Loader
	rate  uint64
	burst uint64
}

var _ Container = (*KernelContainer)(nil)

// New builds a KernelContainer over a loader, filling rate-limit defaults.
func New(cfg Config) (*KernelContainer, error) {
	if cfg.Loader == nil {
		return nil, errors.New("containment: nil loader")
	}
	rate, burst := cfg.RateLimitBytesPerSec, cfg.RateLimitBurstBytes
	if rate == 0 {
		rate = DefaultRateBytesPerSec
	}
	if burst == 0 {
		burst = DefaultBurstBytes
	}
	return &KernelContainer{l: cfg.Loader, rate: rate, burst: burst}, nil
}

// Apply programs the kernel verdict for the flow's socket cookie.
func (c *KernelContainer) Apply(v contract.Verdict, action Action) error {
	if v.Flow.SocketCookie == 0 {
		return ErrUnattributable
	}
	switch action {
	case RateLimit:
		return c.l.Program(v.Flow.SocketCookie, loader.ActionRateLimit, c.rate, c.burst)
	case HardDeny:
		return c.l.Program(v.Flow.SocketCookie, loader.ActionHardDeny, 0, 0)
	case Jail:
		return c.l.Program(v.Flow.SocketCookie, loader.ActionJail, 0, 0)
	default:
		return fmt.Errorf("containment: unknown action %d", action)
	}
}

// Release lifts containment for the flow (no-op for an unattributable flow).
func (c *KernelContainer) Release(v contract.Verdict) error {
	if v.Flow.SocketCookie == 0 {
		return nil
	}
	return c.l.Release(v.Flow.SocketCookie)
}
