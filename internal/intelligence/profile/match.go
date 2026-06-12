package profile

// Similarity is the behavioral-similarity kernel D5-Phase-2 consumes: how alike two
// profiles' BEHAVIOR is, in [0,1] (1.0 == behaviorally identical; 0 == nothing in
// common). It keys on behavioral evidence only — the probe-type set, the per-axis
// engagement signature, the cadence band, and the reaction (poison class + disengage) —
// never on identity. D5 uses it to sharpen M for an emerging flow that behaves like a
// confirmed-jailed one (bounded by M_max; it can never manufacture a jail — rule 8).
//
// Weights: the probe sequence + the axes signature dominate (the strongest
// discriminators); cadence + reaction are softer corroborators.
func (p *Profile) Similarity(o *Profile) float64 {
	if p == nil || o == nil {
		return 0
	}
	// Behaviorally identical => 1.0 (the self==1.0 invariant D5 relies on). The
	// BehavioralHash IS the canonical behavioral identity, so this holds for the same
	// object AND for two distinct profiles with the same behavior — including profiles
	// with no probe sequence, which the evidence-based kernel below would otherwise
	// score < 1.0.
	//
	// The hash fast-path requires a NON-ZERO hash (D6h): a sparse-lifted inbound
	// cross-customer SharedPattern carries BehavioralHash==0 as a deliberate sentinel
	// ("not a real behavioral identity"), so it must NEVER short-circuit to 1.0 against
	// another zero-hash profile — it is scored only by the evidence kernel below. A
	// real DeriveProfile hash is fnv-64a over a non-empty string and is never 0.
	if p == o || (p.BehavioralHash != 0 && p.BehavioralHash == o.BehavioralHash) {
		return 1
	}
	typeSim := jaccard(typeSet(p.OrderedTypes), typeSet(o.OrderedTypes))
	axisSim := axisJaccard(p.AxesEngaged, o.AxesEngaged)

	cadSim := 0.0
	if cadenceBand(p.CadenceSec) == cadenceBand(o.CadenceSec) {
		cadSim = 1.0
	}

	// Reaction agreement is EVIDENCE-BASED: only a SHARED reaction counts. Two profiles
	// that both have no poison reaction ("") or both did not disengage early are not
	// "similar" on those axes — crediting mutual absence would let a benign flow match
	// a malicious profile via what neither did.
	reactSim := 0.0
	if p.PoisonClass != "" && p.PoisonClass == o.PoisonClass {
		reactSim += 0.5
	}
	if p.DisengagedEarly && o.DisengagedEarly {
		reactSim += 0.5
	}

	return clamp01(0.40*typeSim + 0.30*axisSim + 0.15*cadSim + 0.15*reactSim)
}

// axisJaccard is the Jaccard overlap of the two ENGAGED-axis sets: |both engaged| /
// |either engaged|. It credits only shared engagement — two profiles that engaged
// nothing score 0 (no shared evidence), never the spurious 1.0 a count-of-agreements
// over the mostly-zero five-axis vector would give.
func axisJaccard(a, b [NumAxes]bool) float64 {
	inter, union := 0, 0
	for i := 0; i < NumAxes; i++ {
		if a[i] && b[i] {
			inter++
		}
		if a[i] || b[i] {
			union++
		}
	}
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func typeSet(types []string) map[string]bool {
	s := make(map[string]bool, len(types))
	for _, t := range types {
		s[t] = true
	}
	return s
}

// jaccard is |A∩B| / |A∪B|. Two empty sets => 0 (no shared behavioral evidence — never
// over-match two no-probe profiles), not 1.
func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if b[k] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
