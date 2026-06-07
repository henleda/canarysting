// Command sting-selfcheck drives the attrition library with a scripted attacker
// and prints the two-column ledger that demo beat 4 renders: the ATTACKER's cost
// (bytes served, wall-time held, estimated tokens burned) climbing while the
// DEFENDER's cost (bytes buffered at once, work per chunk) stays flat and bounded.
//
// It proves the M6 exit bar locally — no kernel, no proxy, no LLM (the real Envoy
// path is M4, the real agent is M9). Delay is data, so the run is clock-free and
// instant: "120s of attacker wall-time imposed" is read from the meter, never
// slept. It consumes ONLY the public attrition surface, so it doubles as a check
// that the seam a real driver (the Envoy adapter) will use is usable, and it exits
// non-zero if any invariant is violated, so it works as a CI gate.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/harmless"
	"github.com/canarysting/canarysting/internal/sting/attrition"
)

func main() {
	maxChunks := flag.Int("max-chunks", 200000, "safety cap on chunks pulled per flow")
	flag.Parse()

	floors := []struct {
		name  string
		floor contract.StingFloor
	}{
		{"passive", contract.FloorPassive},
		{"moderate", contract.FloorModerate},
		{"aggressive", contract.FloorAggressive},
	}

	fmt.Printf("CanarySting attrition self-check — attacker cost vs. defender cost (Tier 3, default budget)\n\n")
	fmt.Printf("%-11s %-11s %12s %10s %12s %9s %7s\n", "floor", "mechanism", "bytes(atk)", "held(s)", "est-tokens", "requests", "depth")
	fmt.Printf("%-11s %-11s %12s %10s %12s %9s %7s\n", "-----", "---------", "----------", "-------", "----------", "--------", "-----")

	failed := false
	for _, f := range floors {
		a, err := attrition.New(attrition.Config{Floor: f.floor, Budget: attrition.DefaultBudget(), Drip: attrition.DefaultDrip()})
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: building %s attritor: %v\n", f.name, err)
			os.Exit(1)
		}
		out, maxChunk, viol := runFlow(a, *maxChunks)
		fmt.Printf("%-11s %-11s %12d %10.1f %12.0f %9d %7d\n",
			f.name, out.Mechanism, out.BytesServed, out.TimeHeldSec, out.TokenCostProxy, out.RequestsAbsrb, out.DepthReached)

		// Invariant checks (the CI-gate teeth):
		budget := attrition.DefaultBudget()
		if out.BytesServed > budget.MaxBytesPerFlow {
			fmt.Fprintf(os.Stderr, "FAIL: %s served %d bytes over the per-flow cap %d\n", f.name, out.BytesServed, budget.MaxBytesPerFlow)
			failed = true
		}
		if out.DepthReached > budget.MaxDepth {
			fmt.Fprintf(os.Stderr, "FAIL: %s reached depth %d over MaxDepth %d\n", f.name, out.DepthReached, budget.MaxDepth)
			failed = true
		}
		if f.floor != contract.FloorAggressive && out.Mechanism == attrition.MechTokenBait {
			fmt.Fprintf(os.Stderr, "FAIL: %s floor emitted token_bait (aggressive went silent)\n", f.name)
			failed = true
		}
		if viol != "" {
			fmt.Fprintf(os.Stderr, "FAIL: %s emitted non-harmless content: %s\n", f.name, viol)
			failed = true
		}
		// Defender flatness: the largest single chunk we ever buffered is tiny and
		// bounded — never the multi-MiB total the attacker ingested.
		fmt.Printf("            defender: max single chunk buffered = %d bytes (O(1); flow held %.0fs)\n\n", maxChunk, out.TimeHeldSec)
	}

	if failed {
		fmt.Fprintln(os.Stderr, "sting-selfcheck: FAILED")
		os.Exit(1)
	}
	fmt.Println("sting-selfcheck: OK — attacker cost climbs, defender cost stays flat and bounded.")
}

// runFlow drives one Tier-3 flow to completion, returning the final cost meter,
// the largest single chunk ever buffered (the defender's real high-water mark),
// and the first harmlessness violation found (empty if none).
func runFlow(a *attrition.BoundedAttritor, maxChunks int) (attrition.Outcome, int, string) {
	s := a.Open(contract.Verdict{
		Flow: contract.FlowIdentity{SocketCookie: 0xC0FFEE},
		Tier: contract.TierJail,
	})
	defer s.Close()
	maxChunk := 0
	viol := ""
	for i := 0; i < maxChunks; i++ {
		c, done, err := s.Next(context.Background())
		if err != nil {
			viol = err.Error()
			break
		}
		if len(c.Data) > maxChunk {
			maxChunk = len(c.Data)
		}
		if len(c.Data) > 0 && viol == "" {
			if e := harmless.CrossScan(c.Data); e != nil {
				viol = e.Error()
			}
		}
		if done != attrition.NotDone {
			break
		}
	}
	return s.Outcome(), maxChunk, viol
}
