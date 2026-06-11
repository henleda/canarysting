// Package recon is the D2-sibling D4 reconnaissance early-warning layer
// (docs/INTELLIGENCE.md §5.1; docs/MOAT_DESIGN.md D4): it derives the quiet
// pre-attack probing signal from a scope's interaction events — which Tier-1
// (negative-space) canary touches are part of a repeated-probing cluster, and the
// resulting severity.
//
// IT IS A LABELING SIGNAL, NEVER AN ENFORCEMENT TRIGGER (rule 8 / docs/
// BASELINE_MULTIPLIER.md §5). The canary touch already entered the pipeline; this only
// surfaces the pre-attack recon for the operator EARLIER and more legibly. It emits no
// tier/verdict/action; adjacency novelty is carried as CONTEXT only. Severity is
// "recon" (quiet) or "surfaced" (high adjacency novelty or cluster membership), NEVER
// "detected". Pure + single-scope (rule 5); stdlib + intelligence only.
//
// This is the intelligence-layer source of truth: the dashboard recon feed + recon
// timeline are thin views over DeriveReconSignal (decision E — one signal, no
// disagreement between the home wall and the drill-down).
package recon

import (
	"fmt"
	"sort"
	"time"

	"github.com/canarysting/canarysting/internal/intelligence"
)

const (
	// AdjacencyThreshold escalates a recon touch from "recon" to "surfaced".
	AdjacencyThreshold = 0.8
	// ClusterWindowSec / ClusterMin define a recon cluster: ClusterMin+ Tier-1 touches
	// from ONE flow within ClusterWindowSec are all "surfaced".
	ClusterWindowSec = 90.0
	ClusterMin       = 3

	SeverityRecon    = "recon"    // quiet negative-space probe
	SeveritySurfaced = "surfaced" // high adjacency novelty OR cluster membership

	// featAdjacency is the baseline feature key read as CONTEXT (never a trigger).
	featAdjacency = "adjacency_novelty"
)

// ReconSignal is one early-warning datum: a Tier-1 (quiet, negative-space) canary
// touch annotated with cluster membership + severity. Derived CONTEXT only.
type ReconSignal struct {
	FlowID       uint64
	CanaryType   string
	Timestamp    time.Time
	AdjacencyNov float64 // adjacency-novelty CONTEXT (from the baseline features; never a trigger)
	Cluster      bool    // part of a repeated-probing cluster
	Severity     string  // SeverityRecon | SeveritySurfaced
	Description  string
}

// Key is the stable per-signal key (flowID:tsNanos), so a view consumer can join a
// signal back to its event/session without re-deriving it.
func (s ReconSignal) Key() string { return signalKey(s.FlowID, s.Timestamp) }

// DeriveReconSignal extracts the recon early-warning signal from a scope's events:
// every Tier-1 touch (the lowest stored tier = quiet probing in the negative space),
// OLDEST-FIRST, with cluster membership + severity. Pure, single-scope, clock-free. It
// NEVER emits a tier/verdict/action — a labeling signal only (rule 8). Returns nil for
// no Tier-1 touches.
func DeriveReconSignal(events []intelligence.AdversaryInteractionEvent) []ReconSignal {
	var t1 []intelligence.AdversaryInteractionEvent
	for _, e := range events {
		if e.Tier == 1 {
			t1 = append(t1, e)
		}
	}
	if len(t1) == 0 {
		return nil
	}
	clustered := clusterMembers(t1)
	sort.SliceStable(t1, func(i, j int) bool { return t1[i].Timestamp.Before(t1[j].Timestamp) }) // oldest first
	out := make([]ReconSignal, 0, len(t1))
	for _, e := range t1 {
		adj := e.Features[featAdjacency]
		isCluster := clustered[signalKey(e.FlowID, e.Timestamp)]
		sev := SeverityRecon
		if adj >= AdjacencyThreshold || isCluster {
			sev = SeveritySurfaced
		}
		out = append(out, ReconSignal{
			FlowID:       e.FlowID,
			CanaryType:   e.CanaryType,
			Timestamp:    e.Timestamp,
			AdjacencyNov: adj,
			Cluster:      isCluster,
			Severity:     sev,
			Description:  describe(e, adj, isCluster),
		})
	}
	return out
}

// signalKey is the per-event membership key. A composite "flowID:tsNanos" (not
// ts^flowID) because XOR can collide across distinct flows/timestamps, which would
// mislabel an unrelated touch as clustered.
func signalKey(flowID uint64, ts time.Time) string {
	return fmt.Sprintf("%d:%d", flowID, ts.UnixNano())
}

// clusterMembers returns the set of T1 events (keyed by signalKey) that belong to a
// cluster: ClusterMin+ touches from one flow within ClusterWindowSec.
func clusterMembers(t1 []intelligence.AdversaryInteractionEvent) map[string]bool {
	byFlow := map[uint64][]intelligence.AdversaryInteractionEvent{}
	for _, e := range t1 {
		byFlow[e.FlowID] = append(byFlow[e.FlowID], e)
	}
	out := map[string]bool{}
	for _, grp := range byFlow {
		sort.SliceStable(grp, func(i, j int) bool { return grp[i].Timestamp.Before(grp[j].Timestamp) })
		for i := range grp {
			j := i
			for j < len(grp) && grp[j].Timestamp.Sub(grp[i].Timestamp).Seconds() <= ClusterWindowSec {
				j++
			}
			if j-i >= ClusterMin {
				for k := i; k < j; k++ {
					out[signalKey(grp[k].FlowID, grp[k].Timestamp)] = true
				}
			}
		}
	}
	return out
}

func describe(e intelligence.AdversaryInteractionEvent, adj float64, cluster bool) string {
	switch {
	case adj >= AdjacencyThreshold:
		return fmt.Sprintf("new adjacency · 0x%x→%s", e.FlowID, e.CanaryType)
	case cluster:
		return fmt.Sprintf("cluster · 0x%x repeated probing", e.FlowID)
	case e.CanaryType != "":
		return "quiet probe · " + e.CanaryType
	default:
		return fmt.Sprintf("touch · 0x%x", e.FlowID)
	}
}
