package executor

import (
	"context"
	"sync"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

// Ledger is the mandatory audit boundary. An intent must be durably accepted
// before an approved action can reach a resolver or dialer.
type Ledger interface {
	AppendIntent(context.Context, groundtruth.AttackerIntent) error
	AppendAction(context.Context, groundtruth.AttackerAction) error
}

// MemoryLedger is a bounded-run reference ledger for tests and laboratory
// composition. Production persistence can implement Ledger without changing
// executor authority.
type MemoryLedger struct {
	mu      sync.Mutex
	intents []groundtruth.AttackerIntent
	actions []groundtruth.AttackerAction
}

func (l *MemoryLedger) AppendIntent(_ context.Context, intent groundtruth.AttackerIntent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.intents = append(l.intents, intent)
	return nil
}

func (l *MemoryLedger) AppendAction(_ context.Context, action groundtruth.AttackerAction) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.actions = append(l.actions, action)
	return nil
}

func (l *MemoryLedger) Intents() []groundtruth.AttackerIntent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]groundtruth.AttackerIntent(nil), l.intents...)
}

func (l *MemoryLedger) Actions() []groundtruth.AttackerAction {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]groundtruth.AttackerAction(nil), l.actions...)
}
