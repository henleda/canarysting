package observebaseline

import (
	"net/netip"
	"sync"

	"github.com/canarysting/canarysting/bpf/observe"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/persist"
)

// excluder decides whether an observed flow must be kept OUT of the baseline-of-
// normal. The aggregator consults it before folding; a confirmed-malicious
// source can never teach the baseline that its own behavior is normal
// (docs/BASELINE_MULTIPLIER.md §5 "poisoned baseline", M7/D4).
//
// CRITICAL: this is a BASELINE-of-normal exclusion ONLY. It is NEVER wired into
// the scorer's BenignExcluder — an excluded attacker still scores and still
// escalates on a canary touch. Excluding the attacker from SCORING would make it
// score zero and defeat containment; excluding it only from the BASELINE keeps
// the multiplier honest. The two are different mechanisms with opposite intent.
type excluder interface {
	excludedFlow(scope contract.ScopeKey, fs observe.FlowStats) bool
}

// MaliciousSet is the scope-isolated set of confirmed-malicious source
// identities, keyed by the FNV hash of the source address (never the raw
// address — rule 9). It is populated from the staged ground-truth registry (an
// operator declares which source IPs are the attacker) and is durably backed so
// the exclusion survives a reboot. It satisfies excluder.
type MaliciousSet struct {
	mu     sync.RWMutex
	scopes map[contract.ScopeKey]map[uint64]bool
	store  *persist.Store // optional; nil = in-memory only (tests)
}

var _ excluder = (*MaliciousSet)(nil)

// NewMaliciousSet returns a set backed by store (may be nil for in-memory use).
func NewMaliciousSet(store *persist.Store) *MaliciousSet {
	return &MaliciousSet{scopes: map[contract.ScopeKey]map[uint64]bool{}, store: store}
}

// MarkAddr records an operator-declared source address as confirmed-malicious in
// scope. The address is canonicalized and hashed the same way the observe path
// hashes a flow's source identity, so the kernel-observed attacker flows match
// and are excluded. Persisted if a store is wired.
func (m *MaliciousSet) MarkAddr(scope contract.ScopeKey, addr netip.Addr) error {
	return m.markHash(scope, hashAddrCanonical(addr))
}

func (m *MaliciousSet) markHash(scope contract.ScopeKey, idHash uint64) error {
	m.mu.Lock()
	s := m.scopes[scope]
	if s == nil {
		s = map[uint64]bool{}
		m.scopes[scope] = s
	}
	s[idHash] = true
	m.mu.Unlock()
	if m.store != nil {
		return m.store.MarkMalicious(scope, idHash)
	}
	return nil
}

// Rehydrate loads a scope's persisted malicious set into memory on startup.
func (m *MaliciousSet) Rehydrate(scope contract.ScopeKey) error {
	if m.store == nil {
		return nil
	}
	return m.store.RangeMalicious(scope, func(idHash uint64) error {
		m.mu.Lock()
		s := m.scopes[scope]
		if s == nil {
			s = map[uint64]bool{}
			m.scopes[scope] = s
		}
		s[idHash] = true
		m.mu.Unlock()
		return nil
	})
}

func (m *MaliciousSet) excludedFlow(scope contract.ScopeKey, fs observe.FlowStats) bool {
	idHash := hashIdentity(fs)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scopes[scope][idHash]
}
