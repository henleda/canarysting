// Command engine runs the CanarySting decision engine service: it ingests
// signal events over the contract, scores and tiers flows, calibrates from
// feedback, and emits verdicts. It is proxy-agnostic. See docs/ENGINE.md.
package main

func main() {
	// TODO: wire scope.Resolver, scoring.Scorer, tiers.Decider,
	// calibration.Calibrator, feedback.Intake; serve the contract.Engine
	// interface (in-process and/or over api/proto). Refuse to start if scope
	// identity cannot be resolved (scope.ErrUnresolved).
}
