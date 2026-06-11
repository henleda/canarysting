package profile

// Profile is a derived adversary behavioral profile, anonymized by construction.
type Profile struct {
	// --- behavioral probe pattern (from the event sequence) ---
	OrderedTypes  []string // canary-type touch sequence in timestamp order (decoy taxonomy — LOCAL-only; dropped on export, it leaks decoy placement)
	Touches       int      // total interactions in the profiled set
	PeakTier      int      // highest engine tier reached (0..3)
	DepthReached  int      // deepest maze/nesting level the actor descended
	CadenceSec    float64  // median inter-arrival (seconds); 0 if < 2 events
	CadenceJitter float64  // MAD of inter-arrivals; 0 if < 3 events
	AdjacencyNov  float64  // peak adjacency novelty (scoring context, never a trigger)
	IdentityNov   float64  // peak identity novelty

	// --- per-axis engagement signature (the five-axis reaction; from StingOutcome) ---
	AxesEngaged        [NumAxes]bool // per-axis engaged booleans (from the OVERLAPPING Axes bitset; never the raw bitset, which leaks floor config)
	HeldSec            float64       // total imposed hold across the set
	PersistsTarpit     bool          // any event held > tarpitPersistSec
	DisengagedEarly    bool          // the attacker disengaged BEFORE any defender bound (DisengageAttacker ONLY — a defender-cap is never mislabeled, D2-2)
	TimeToDisengageSec float64       // attacker-initiated disengage time (0 unless DisengagedEarly)
	PoisonClass        string        // deepest information-poisoning reaction class ("" | credential | topology | success)
	PoisonReached      int           // deepest poison-field stage walked

	// --- deployment-local-only (rule 9; NEVER exported — the egress filter
	// hard-blocks the *exploit*/*exposure* names, and ExportForm omits these) ---
	ExploitsObserved int64 // AX4: exploits fired at decoys, captured in-perimeter
	ExposureSignals  int64 // AX5: tooling/C2 fingerprints exposed, captured in-perimeter

	// BehavioralHash is a deterministic fnv-64a over the BEHAVIORAL pattern (ordered
	// types + cadence band + the axes/disengage/poison signature) — NEVER over
	// FlowID/ScopeKey/identity. Same behavior => same hash; carries no identity.
	BehavioralHash uint64
}
