package recon

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/intelligence"
)

var base = time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

func ev(flowID uint64, canary string, tier, offsetSec int, adj float64) intelligence.AdversaryInteractionEvent {
	e := intelligence.AdversaryInteractionEvent{
		FlowID:     flowID,
		CanaryType: canary,
		Tier:       tier,
		Timestamp:  base.Add(time.Duration(offsetSec) * time.Second),
	}
	if adj > 0 {
		e.Features = map[string]float64{"adjacency_novelty": adj}
	}
	return e
}

func TestDeriveReconSignalOnlyTier1(t *testing.T) {
	// Only Tier-1 (quiet negative-space) touches are recon; T0/T2/T3 are excluded.
	sigs := DeriveReconSignal([]intelligence.AdversaryInteractionEvent{
		ev(1, ".env", 0, 0, 0),
		ev(1, ".env", 1, 1, 0),
		ev(1, ".env", 2, 2, 0),
		ev(1, ".env", 3, 3, 0),
	})
	if len(sigs) != 1 || sigs[0].Severity != SeverityRecon {
		t.Fatalf("expected exactly 1 recon signal, got %+v", sigs)
	}
}

func TestReconSeverityFromAdjacency(t *testing.T) {
	hi := DeriveReconSignal([]intelligence.AdversaryInteractionEvent{ev(1, ".env", 1, 0, 0.9)})
	if hi[0].Severity != SeveritySurfaced {
		t.Fatalf("adjacency >= threshold must surface, got %q", hi[0].Severity)
	}
	lo := DeriveReconSignal([]intelligence.AdversaryInteractionEvent{ev(1, ".env", 1, 0, 0.3)})
	if lo[0].Severity != SeverityRecon {
		t.Fatalf("low adjacency stays recon, got %q", lo[0].Severity)
	}
}

func TestReconCluster(t *testing.T) {
	// ClusterMin touches from one flow within ClusterWindowSec => all surfaced as a cluster.
	var evs []intelligence.AdversaryInteractionEvent
	for i := 0; i < ClusterMin; i++ {
		evs = append(evs, ev(7, ".env", 1, i*10, 0)) // 10s apart, well within the window
	}
	for _, s := range DeriveReconSignal(evs) {
		if !s.Cluster || s.Severity != SeveritySurfaced {
			t.Fatalf("cluster member not surfaced: %+v", s)
		}
	}
	// Fewer than ClusterMin => not a cluster.
	for _, s := range DeriveReconSignal([]intelligence.AdversaryInteractionEvent{ev(8, ".env", 1, 0, 0), ev(8, ".env", 1, 10, 0)}) {
		if s.Cluster {
			t.Fatal("sub-ClusterMin touches wrongly clustered")
		}
	}
}

func TestReconClusterRespectsWindow(t *testing.T) {
	// ClusterMin touches but spread BEYOND ClusterWindowSec => not a cluster.
	for _, s := range DeriveReconSignal([]intelligence.AdversaryInteractionEvent{
		ev(9, ".env", 1, 0, 0), ev(9, ".env", 1, 100, 0), ev(9, ".env", 1, 200, 0),
	}) {
		if s.Cluster {
			t.Fatalf("touches outside the %.0fs window wrongly clustered: %+v", ClusterWindowSec, s)
		}
	}
}

func TestReconNeverTriggers(t *testing.T) {
	// Rule 8: recon is a LABELING signal, never an enforcement decision. Structurally,
	// ReconSignal exposes only context (severity/cluster/adjacency) — no tier/verdict/
	// action/score field — and severity is only ever recon/surfaced, never "detected".
	rt := reflect.TypeOf(ReconSignal{})
	for i := 0; i < rt.NumField(); i++ {
		n := strings.ToLower(rt.Field(i).Name)
		for _, banned := range []string{"tier", "verdict", "action", "score"} {
			if strings.Contains(n, banned) {
				t.Fatalf("ReconSignal.%s makes recon look like an enforcement decision (rule 8)", rt.Field(i).Name)
			}
		}
	}
	for _, s := range DeriveReconSignal([]intelligence.AdversaryInteractionEvent{ev(1, ".env", 1, 0, 0.9)}) {
		if s.Severity != SeverityRecon && s.Severity != SeveritySurfaced {
			t.Fatalf("recon emitted severity %q — must be recon/surfaced, never 'detected'", s.Severity)
		}
	}
}

func TestDeriveReconSignalDeterministic(t *testing.T) {
	mk := func() []ReconSignal {
		return DeriveReconSignal([]intelligence.AdversaryInteractionEvent{ev(1, ".env", 1, 0, 0.9), ev(1, "x", 1, 5, 0)})
	}
	a, b := mk(), mk()
	if !reflect.DeepEqual(a, b) {
		t.Fatal("DeriveReconSignal is not deterministic")
	}
	// oldest-first
	if len(a) == 2 && a[0].Timestamp.After(a[1].Timestamp) {
		t.Fatal("signals are not oldest-first")
	}
}

func TestDeriveReconSignalEmpty(t *testing.T) {
	if DeriveReconSignal(nil) != nil {
		t.Fatal("no events => nil")
	}
	if DeriveReconSignal([]intelligence.AdversaryInteractionEvent{ev(1, ".env", 2, 0, 0)}) != nil {
		t.Fatal("no Tier-1 touches => nil")
	}
}
