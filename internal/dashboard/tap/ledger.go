package tap

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// AttackLedger is the M9 attacker's live real-cost ledger. It is the ONE write
// surface on this otherwise read-only tap (founder-signed-off D5: a live
// "tokens burning" meter on the CISO screen). The M9 llm-attacker PUTs its
// running token totals here each turn; the dashboard-backend polls it and the
// frontend renders the live meter.
//
// SCOPE / RULE NOTES: this carries only the attacker's OWN token counts and the
// model id — no scope state, no baselines, no decoy contents, nothing that
// crosses a deployment boundary (rules 5/9 untouched). It is in-memory only
// (never persisted, never folded into the EventStore) and is deliberately kept
// SEPARATE from the defender-derived proxy estimate (TokenCostProxy) — the two
// numbers are shown side by side, never merged.
type AttackLedger struct {
	InputTokens         int64     `json:"input_tokens"`
	OutputTokens        int64     `json:"output_tokens"`
	CacheReadTokens     int64     `json:"cache_read_tokens"`
	CacheCreationTokens int64     `json:"cache_creation_tokens"`
	USD                 float64   `json:"usd"`
	HardCapUSD          float64   `json:"hard_cap_usd"`
	Model               string    `json:"model"`
	Active              bool      `json:"active"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// ledgerStore holds the most recent attacker ledger, mutex-guarded.
type ledgerStore struct {
	mu     sync.RWMutex
	latest AttackLedger
	seen   bool
}

func (l *ledgerStore) set(a AttackLedger, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a.UpdatedAt = now
	l.latest = a
	l.seen = true
}

// get returns the latest ledger and whether one has ever been posted. A ledger
// older than staleAfter is reported with Active=false (an attack that ended or
// crashed shouldn't leave the meter pinned "live").
func (l *ledgerStore) get(now time.Time, staleAfter time.Duration) (AttackLedger, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if !l.seen {
		return AttackLedger{}, false
	}
	out := l.latest
	if now.Sub(out.UpdatedAt) > staleAfter {
		out.Active = false
	}
	return out, true
}

// ledgerStaleAfter bounds how long a posted ledger is considered live.
const ledgerStaleAfter = 30 * time.Second

func (s *Source) handleAttackLedger(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var in AttackLedger
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
			http.Error(w, "bad ledger json", http.StatusBadRequest)
			return
		}
		s.ledger.set(in, s.now())
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		led, ok := s.ledger.get(s.now(), ledgerStaleAfter)
		if !ok {
			// No attack has run yet — 200 with a null-ish empty body so the
			// backend can distinguish "never seen" from a transport error.
			writeJSON(w, map[string]any{"present": false})
			return
		}
		writeJSON(w, led)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
