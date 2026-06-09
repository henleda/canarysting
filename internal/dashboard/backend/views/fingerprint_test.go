package views

import (
	"math"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/intelligence"
)

func fpEv(flowID uint64, canary string, offsetSec int, held float64, adj, id float64) intelligence.AdversaryInteractionEvent {
	return intelligence.AdversaryInteractionEvent{
		FlowID:     flowID,
		CanaryType: canary,
		Timestamp:  base.Add(time.Duration(offsetSec) * time.Second),
		Features:   map[string]float64{featAdjacency: adj, featIdentity: id},
		Sting:      intelligence.StingOutcome{TimeHeldSec: held},
	}
}

func TestFingerprintEmptyOrSingle(t *testing.T) {
	if fp := DeriveFingerprint(0x1, nil); fp != nil {
		t.Fatalf("empty events => fp = %+v, want nil", fp)
	}
	single := []intelligence.AdversaryInteractionEvent{fpEv(0x1, "a", 0, 0, 0, 0)}
	fp := DeriveFingerprint(0x1, single)
	if fp == nil {
		t.Fatal("single event => nil fp")
	}
	if fp.CadenceSec != 0 || fp.CadenceJitter != 0 {
		t.Fatalf("single event cadence/jitter = %v/%v, want 0/0", fp.CadenceSec, fp.CadenceJitter)
	}
	if len(fp.OrderedTypes) != 1 || fp.OrderedTypes[0] != "a" {
		t.Fatalf("OrderedTypes = %v", fp.OrderedTypes)
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		fpEv(0x118, ".aws/credentials", 0, 5, 0.3, 0.2),
		fpEv(0x118, ".env", 12, 5, 0.4, 0.2),
		fpEv(0x118, "backup/db.sql", 25, 5, 0.5, 0.2),
	}
	a := DeriveFingerprint(0x118, events)
	b := DeriveFingerprint(0x118, events)
	if a.Hash != b.Hash {
		t.Fatalf("hash not deterministic: %q vs %q", a.Hash, b.Hash)
	}
	if a.Hash == "" || a.Hash[:3] != "fp:" {
		t.Fatalf("hash format = %q, want fp:-prefixed", a.Hash)
	}
}

func TestFingerprintOrderingInvariant(t *testing.T) {
	e0 := fpEv(0x9, "a", 0, 0, 0, 0)
	e1 := fpEv(0x9, "b", 10, 0, 0, 0)
	e2 := fpEv(0x9, "c", 20, 0, 0, 0)
	inOrder := []intelligence.AdversaryInteractionEvent{e0, e1, e2}
	shuffled := []intelligence.AdversaryInteractionEvent{e2, e0, e1}

	a := DeriveFingerprint(0x9, inOrder)
	b := DeriveFingerprint(0x9, shuffled)
	if a.Hash != b.Hash {
		t.Fatalf("hash not ordering-invariant: %q vs %q", a.Hash, b.Hash)
	}
	for i := range a.OrderedTypes {
		if a.OrderedTypes[i] != b.OrderedTypes[i] {
			t.Fatalf("OrderedTypes differ after sort: %v vs %v", a.OrderedTypes, b.OrderedTypes)
		}
	}
	want := []string{"a", "b", "c"}
	for i := range want {
		if a.OrderedTypes[i] != want[i] {
			t.Fatalf("OrderedTypes = %v, want %v", a.OrderedTypes, want)
		}
	}
}

func TestFingerprintDifferentSequenceDifferentHash(t *testing.T) {
	seq1 := []intelligence.AdversaryInteractionEvent{
		fpEv(0x1, "a", 0, 0, 0, 0), fpEv(0x1, "b", 10, 0, 0, 0),
	}
	seq2 := []intelligence.AdversaryInteractionEvent{
		fpEv(0x1, "b", 0, 0, 0, 0), fpEv(0x1, "a", 10, 0, 0, 0),
	}
	if DeriveFingerprint(0x1, seq1).Hash == DeriveFingerprint(0x1, seq2).Hash {
		t.Fatal("different ordered-type sequences should hash differently")
	}
}

func TestFingerprintCadence(t *testing.T) {
	// gaps: 12s and 13s => median 12.5
	events := []intelligence.AdversaryInteractionEvent{
		fpEv(0x1, "a", 0, 0, 0, 0),
		fpEv(0x1, "b", 12, 0, 0, 0),
		fpEv(0x1, "c", 25, 0, 0, 0),
	}
	fp := DeriveFingerprint(0x1, events)
	if math.Abs(fp.CadenceSec-12.5) > 1e-9 {
		t.Fatalf("CadenceSec = %v, want 12.5", fp.CadenceSec)
	}
	// MAD of {12,13} about median 12.5 => {0.5,0.5} => 0.5
	if math.Abs(fp.CadenceJitter-0.5) > 1e-9 {
		t.Fatalf("CadenceJitter = %v, want 0.5", fp.CadenceJitter)
	}
}

func TestFingerprintPersistsTarpit(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		fpEv(0x1, "a", 0, 5, 0, 0),
		fpEv(0x1, "b", 10, 35, 0, 0), // > 30s threshold
	}
	if !DeriveFingerprint(0x1, events).PersistsTarpit {
		t.Fatal("PersistsTarpit = false, want true (TimeHeldSec 35 > 30)")
	}

	short := []intelligence.AdversaryInteractionEvent{fpEv(0x1, "a", 0, 5, 0, 0)}
	if DeriveFingerprint(0x1, short).PersistsTarpit {
		t.Fatal("PersistsTarpit = true, want false (held 5 < 30)")
	}
}

func TestFingerprintSameTimestampDeterministic(t *testing.T) {
	// Two events for one flow with IDENTICAL timestamps but different CanaryType.
	// The secondary sort key (CanaryType) must make the hash invariant to input
	// order even though the timestamps tie.
	a0 := fpEv(0x5, "zebra", 10, 0, 0, 0)
	a1 := fpEv(0x5, "alpha", 10, 0, 0, 0) // same offset => same timestamp
	if !a0.Timestamp.Equal(a1.Timestamp) {
		t.Fatal("test setup: timestamps must be equal")
	}
	fwd := DeriveFingerprint(0x5, []intelligence.AdversaryInteractionEvent{a0, a1})
	rev := DeriveFingerprint(0x5, []intelligence.AdversaryInteractionEvent{a1, a0})
	if fwd.Hash != rev.Hash {
		t.Fatalf("hash not invariant to input order on equal timestamps: %q vs %q", fwd.Hash, rev.Hash)
	}
	// And the canonical order is by CanaryType: alpha before zebra.
	if len(fwd.OrderedTypes) != 2 || fwd.OrderedTypes[0] != "alpha" || fwd.OrderedTypes[1] != "zebra" {
		t.Fatalf("OrderedTypes = %v, want [alpha zebra] (secondary sort key)", fwd.OrderedTypes)
	}
}

func TestFingerprintEmptyCanaryTypeSkipped(t *testing.T) {
	// An event with CanaryType=="" mixed with real events must be excluded from
	// OrderedTypes, and the hash must match the no-empty-event case.
	withEmpty := []intelligence.AdversaryInteractionEvent{
		fpEv(0x7, "a", 0, 0, 0, 0),
		fpEv(0x7, "", 5, 0, 0, 0), // empty type => skipped
		fpEv(0x7, "b", 10, 0, 0, 0),
	}
	noEmpty := []intelligence.AdversaryInteractionEvent{
		fpEv(0x7, "a", 0, 0, 0, 0),
		fpEv(0x7, "b", 10, 0, 0, 0),
	}
	fpE := DeriveFingerprint(0x7, withEmpty)
	fpN := DeriveFingerprint(0x7, noEmpty)
	for _, ty := range fpE.OrderedTypes {
		if ty == "" {
			t.Fatalf("OrderedTypes contains empty string: %v", fpE.OrderedTypes)
		}
	}
	if len(fpE.OrderedTypes) != 2 {
		t.Fatalf("OrderedTypes len = %d, want 2 (empty excluded)", len(fpE.OrderedTypes))
	}
	if fpE.Hash != fpN.Hash {
		t.Fatalf("hash differs when empty CanaryType present: %q vs %q", fpE.Hash, fpN.Hash)
	}
}

func TestFingerprintNoveltyMax(t *testing.T) {
	events := []intelligence.AdversaryInteractionEvent{
		fpEv(0x1, "a", 0, 0, 0.2, 0.1),
		fpEv(0x1, "b", 10, 0, 0.9, 0.7),
		fpEv(0x1, "c", 20, 0, 0.5, 0.3),
	}
	fp := DeriveFingerprint(0x1, events)
	if math.Abs(fp.AdjacencyNov-0.9) > 1e-9 {
		t.Fatalf("AdjacencyNov = %v, want 0.9 (max)", fp.AdjacencyNov)
	}
	if math.Abs(fp.IdentityNov-0.7) > 1e-9 {
		t.Fatalf("IdentityNov = %v, want 0.7 (max)", fp.IdentityNov)
	}
}
