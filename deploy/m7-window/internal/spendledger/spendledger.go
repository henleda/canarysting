// Package spendledger is the hard, fail-closed daily spend ceiling for the
// simdriver's Tier-C live LLM-attacker runs (the only tier that costs real $).
// It persists cumulative USD spent per UTC day to a file and refuses any further
// spend once a configured cap is reached.
//
// FAIL-CLOSED is the whole point and the non-negotiable invariant: any ambiguity
// — a corrupt/unparseable ledger file, a failed write, a clock the day-key can't
// be derived from — must DENY spend, never permit it. The only states that permit
// spend are (a) a missing file (a legitimate first run today) or (b) a cleanly
// parsed ledger with headroom under the cap. A bug that fails OPEN here would
// uncap real money, so the tests assert the closed direction explicitly.
package spendledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"
)

// dayKey is the UTC calendar day a spend is attributed to.
func dayKey(t time.Time) string { return t.UTC().Format("2006-01-02") }

type record struct {
	Day      string  `json:"day"`
	SpentUSD float64 `json:"spent_usd"`
}

// Ledger is a per-UTC-day spend ceiling backed by a file. Safe for concurrent
// use; the simdriver serializes Tier-C runs but the mutex keeps it honest.
type Ledger struct {
	path   string
	capUSD float64

	mu      sync.Mutex
	day     string
	spent   float64
	corrupt bool // sticky: once set, every CanSpend denies for the process lifetime
}

// Open loads the ledger at path for capUSD. A MISSING file is a legitimate fresh
// start (spent=0). A file that EXISTS but cannot be read or parsed is treated as
// CORRUPT and the ledger fails closed (CanSpend always denies) — we never reset a
// damaged ledger to zero, because that is exactly the fail-open that would uncap
// spend. capUSD <= 0 also fails closed (no budget configured = no live spend).
func Open(path string, capUSD float64, now time.Time) *Ledger {
	l := &Ledger{path: path, capUSD: capUSD, day: dayKey(now)}
	if capUSD <= 0 {
		l.corrupt = true // not literally corrupt, but "no budget" must deny like one
		return l
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return l // fresh: no spend recorded yet today
	}
	if err != nil {
		l.corrupt = true // unreadable -> fail closed
		return l
	}
	var rec record
	if len(data) == 0 || json.Unmarshal(data, &rec) != nil || rec.Day == "" {
		l.corrupt = true // empty/garbled -> fail closed (likely a botched write)
		return l
	}
	// A persisted PRIOR day is a legitimate rollover: today starts fresh at 0.
	if rec.Day == l.day {
		l.spent = rec.SpentUSD
	}
	return l
}

// CanSpend reports whether a run whose worst-case cost is estUSD may proceed
// without breaching the daily cap. It is the gate the simdriver must consult
// BEFORE launching a Tier-C run. Fails closed on corruption, a non-positive
// estimate, or a day it cannot reconcile.
func (l *Ledger) CanSpend(now time.Time, estUSD float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.corrupt || estUSD <= 0 {
		return false
	}
	l.rolloverLocked(now)
	return l.spent+estUSD <= l.capUSD
}

// Record adds actualUSD (>=0) to today's spend and persists atomically. A persist
// failure marks the ledger corrupt so subsequent CanSpend calls fail closed — we
// would rather wrongly deny future spend than lose track of money already spent.
func (l *Ledger) Record(now time.Time, actualUSD float64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if actualUSD < 0 {
		return fmt.Errorf("spendledger: negative spend %.4f", actualUSD)
	}
	l.rolloverLocked(now)
	l.spent += actualUSD
	if err := l.persistLocked(); err != nil {
		l.corrupt = true // can't durably account for spend -> deny going forward
		return err
	}
	return nil
}

// Remaining is today's headroom under the cap (0 when corrupt or over).
func (l *Ledger) Remaining(now time.Time) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.corrupt {
		return 0
	}
	l.rolloverLocked(now)
	if r := l.capUSD - l.spent; r > 0 {
		return r
	}
	return 0
}

// rolloverLocked resets the running total when the UTC day advances, and
// persists the zeroed new-day record immediately. The persist matters: a
// long-running process that crosses midnight in memory would otherwise leave
// yesterday's file on disk, so a crash after the rollover but before the next
// Record could reload it on restart — fixing the day boundary as a hard cap edge.
// A persist failure marks the ledger corrupt (fail closed), same as Record.
func (l *Ledger) rolloverLocked(now time.Time) {
	if d := dayKey(now); d != l.day {
		l.day = d
		l.spent = 0
		if err := l.persistLocked(); err != nil {
			l.corrupt = true
		}
	}
}

// persistLocked writes the current day/spent via a temp file + atomic rename, so
// a crash mid-write cannot leave a half-written (corrupt) ledger that would then
// fail closed forever.
func (l *Ledger) persistLocked() error {
	blob, err := json.Marshal(record{Day: l.day, SpentUSD: l.spent})
	if err != nil {
		return err
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, l.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
