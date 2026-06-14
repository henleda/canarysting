package spendledger

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var noon = time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "sl.json")
}

func TestFreshStartAllowsUnderCap(t *testing.T) {
	l := Open(tmpPath(t), 20.0, noon)
	if !l.CanSpend(noon, 0.5) {
		t.Fatal("fresh ledger should allow a sub-cap run")
	}
	if r := l.Remaining(noon); r != 20.0 {
		t.Fatalf("remaining = %v, want 20", r)
	}
}

func TestRecordPersistsAndReloads(t *testing.T) {
	p := tmpPath(t)
	l := Open(p, 20.0, noon)
	if err := l.Record(noon, 5.0); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(noon, 3.0); err != nil {
		t.Fatal(err)
	}
	// A fresh handle on the same file sees the persisted spend.
	l2 := Open(p, 20.0, noon)
	if r := l2.Remaining(noon); r != 12.0 {
		t.Fatalf("reloaded remaining = %v, want 12", r)
	}
}

func TestCapEnforcedExactlyAtBoundary(t *testing.T) {
	l := Open(tmpPath(t), 1.0, noon)
	_ = l.Record(noon, 0.8)
	if !l.CanSpend(noon, 0.2) {
		t.Fatal("0.8+0.2 == cap should be allowed (<=)")
	}
	if l.CanSpend(noon, 0.3) {
		t.Fatal("0.8+0.3 > cap MUST be denied")
	}
}

func TestDayRolloverResets(t *testing.T) {
	p := tmpPath(t)
	d1 := time.Date(2026, 6, 14, 23, 0, 0, 0, time.UTC)
	l := Open(p, 20.0, d1)
	_ = l.Record(d1, 15.0)
	d2 := d1.Add(2 * time.Hour) // crosses into the next UTC day
	if r := l.Remaining(d2); r != 20.0 {
		t.Fatalf("new UTC day must reset spend; remaining = %v, want 20", r)
	}
	if !l.CanSpend(d2, 18.0) {
		t.Fatal("new day should allow a sub-cap run")
	}
}

// A long-running process that crosses midnight in memory must PERSIST the zeroed
// new day, so a crash before the next Record cannot reload yesterday's total.
func TestRolloverPersistsNewDay(t *testing.T) {
	p := tmpPath(t)
	d1 := time.Date(2026, 6, 14, 23, 0, 0, 0, time.UTC)
	l := Open(p, 20.0, d1)
	_ = l.Record(d1, 15.0)
	d2 := d1.Add(2 * time.Hour) // crosses into the next UTC day
	_ = l.CanSpend(d2, 1.0)     // a query crossing midnight rolls over AND persists
	if r := Open(p, 20.0, d2).Remaining(d2); r != 20.0 {
		t.Fatalf("rollover not persisted; a fresh handle sees remaining = %v, want 20", r)
	}
}

func TestPriorDayFileStartsFreshToday(t *testing.T) {
	p := tmpPath(t)
	yesterday := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	l1 := Open(p, 20.0, yesterday)
	_ = l1.Record(yesterday, 19.0)
	// Reopen "today": the persisted prior-day total must NOT count against today.
	l2 := Open(p, 20.0, noon)
	if r := l2.Remaining(noon); r != 20.0 {
		t.Fatalf("prior-day spend leaked into today; remaining = %v, want 20", r)
	}
}

func TestMissingFileIsFresh(t *testing.T) {
	l := Open(filepath.Join(t.TempDir(), "does-not-exist.json"), 20.0, noon)
	if !l.CanSpend(noon, 1.0) {
		t.Fatal("a missing ledger file is a legitimate fresh start, not corruption")
	}
}

// The fail-CLOSED invariant: every ambiguous state must DENY spend.
func TestCorruptFileFailsClosed(t *testing.T) {
	p := tmpPath(t)
	if err := os.WriteFile(p, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := Open(p, 20.0, noon)
	if l.CanSpend(noon, 0.01) {
		t.Fatal("a corrupt ledger file MUST fail closed (deny spend), never reset to 0")
	}
	if r := l.Remaining(noon); r != 0 {
		t.Fatalf("corrupt remaining = %v, want 0", r)
	}
}

func TestEmptyFileFailsClosed(t *testing.T) {
	p := tmpPath(t)
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if Open(p, 20.0, noon).CanSpend(noon, 0.01) {
		t.Fatal("an empty ledger file (likely a botched write) MUST fail closed")
	}
}

func TestZeroOrNegativeCapFailsClosed(t *testing.T) {
	if Open(tmpPath(t), 0, noon).CanSpend(noon, 0.01) {
		t.Fatal("a zero cap means no budget configured -> deny")
	}
	if Open(tmpPath(t), -5, noon).CanSpend(noon, 0.01) {
		t.Fatal("a negative cap must deny")
	}
}

func TestNonPositiveEstimateDenied(t *testing.T) {
	l := Open(tmpPath(t), 20.0, noon)
	if l.CanSpend(noon, 0) || l.CanSpend(noon, -1) {
		t.Fatal("a non-positive cost estimate must deny (callers must pass a real worst-case)")
	}
}

func TestNegativeRecordRejected(t *testing.T) {
	l := Open(tmpPath(t), 20.0, noon)
	if err := l.Record(noon, -1.0); err == nil {
		t.Fatal("recording a negative spend must error")
	}
}
