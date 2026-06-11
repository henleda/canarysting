package network

// referenceExport is the hand-written stand-in for the shape profile.ExportForm (D2)
// must produce: a fully-COARSENED, fully-TAGGED adversary pattern. It exercises the
// gate today and is the contract D2 must satisfy — when profile.ExportForm lands it
// implements Candidate and slots in with zero network change, and a test asserts its
// output is Clear-able. Every field is a coarse scalar / closed enum with an
// egress:"safe,<reason>" justification next to it; NONE is a raw value, sequence,
// timestamp, hash, identity, or AX4/AX5 signal.
type referenceExport struct {
	ReachedContain  bool   `egress:"safe,coarse tier bucket (reached T2+); not a raw tier or threshold"`
	EngagedVelocity bool   `egress:"safe,per-axis engaged boolean; not the raw Axes bitset (which leaks floor config)"`
	EngagedPoison   bool   `egress:"safe,per-axis engaged boolean"`
	HeldBand        int    `egress:"safe,band=0..3,imposed-hold band 0..3 (bucketed seconds); not a raw duration"`
	DisengagedEarly bool   `egress:"safe,attacker-disengaged-before-cap boolean (the engagement signal)"`
	PoisonClass     string `egress:"safe,coarse poison reaction class from the closed vocab; stage taxonomy dropped"`
}

type referenceCandidate struct {
	export referenceExport
	ctx    ContributionContext
}

func (r referenceCandidate) EgressFields() (any, ContributionContext) { return r.export, r.ctx }

// ReferenceCandidate returns a clearable reference candidate: opted-in, k-satisfied,
// and fully coarse. It is the contract D2's ExportForm must satisfy, and the happy-path
// fixture for the invariant suite.
func ReferenceCandidate() Candidate {
	return referenceCandidate{
		export: referenceExport{
			ReachedContain:  true,
			EngagedVelocity: true,
			EngagedPoison:   true,
			HeldBand:        2,
			DisengagedEarly: true,
			PoisonClass:     "topology",
		},
		ctx: ContributionContext{Contribute: true, SeenInScopes: aggregationK},
	}
}
