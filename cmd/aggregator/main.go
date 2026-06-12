// Command aggregator is the D6-3 central cross-scope aggregator (docs/D6_3_INGEST_DESIGN.md).
// It holds THE shared ledger for the cross-customer network: the N contributing deployments
// file-spool confirmations (an opaque enrolled scope TOKEN + a coarse cleared pattern) to
// its -confirm-in spool; when a pattern reaches k>=aggregationK DISTINCT ENROLLED tokens it
// re-clears the pattern through the UNCHANGED egress chokepoint (network.ClearWithLedger)
// and appends it to the -cleared-out spool, which a consuming deployment loads into its
// shared-set matcher.
//
// It is OPERATOR-TRUSTED infrastructure (vendor- or design-partner-hosted), NOT
// attacker-reachable: the confirmation channel is a file spool (D63g), same trust class as
// the egress spool; a networked authenticated listener for an UNTRUSTED contributor is D7.
// The k it produces is "k distinct ENROLLED tokens" = "k deployments the operator vouches
// for" (D63f) — the enrolled-token allowlist (a constructor dependency) is what stops a
// forged/un-enrolled token from fabricating distinct scopes to force a sub-k crossing.
//
// Import rule: this binary imports only internal/intelligence/{network,transport} — never
// engine/sting/adapter/contract.
package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/intelligence/network"
	"github.com/canarysting/canarysting/internal/intelligence/transport"
)

func main() {
	var (
		confirmIn  = flag.String("confirm-in", "", "REQUIRED: NDJSON confirmation spool (scope->aggregator) to ingest")
		clearedOut = flag.String("cleared-out", "", "REQUIRED: NDJSON cleared-pattern spool (aggregator->consumer) to append crossings to")
		tokensCSV  = flag.String("enrolled-tokens", "", "comma-separated allowlist of enrolled scope tokens (D63e)")
		tokensFile = flag.String("enrolled-tokens-file", "", "file with one enrolled token per line (alternative to -enrolled-tokens)")
		once       = flag.Bool("once", false, "ingest the spool once and exit (else poll)")
		interval   = flag.Duration("interval", 5*time.Second, "poll interval when not -once")
	)
	flag.Parse()

	if *confirmIn == "" || *clearedOut == "" {
		log.Fatal("aggregator: -confirm-in and -cleared-out are required")
	}
	allow := loadTokens(*tokensCSV, *tokensFile)
	if len(allow) == 0 {
		// Refuse to start with an empty allowlist: with no enrolled tokens the k-count
		// has no sound provenance (anything could be counted). Fail closed (D63e/D63f).
		log.Fatal("aggregator: no enrolled tokens (refusing to start — k would be unprovable; set -enrolled-tokens or -enrolled-tokens-file)")
	}
	log.Printf("aggregator: %d enrolled tokens; k=%d to cross", len(allow), network.AggregationThreshold)

	enrolled := func(t string) bool { _, ok := allow[t]; return ok }
	ledger, err := network.NewAggregatorLedger(enrolled)
	if err != nil {
		log.Fatalf("aggregator: %v", err)
	}
	in := transport.NewConfirmSpool(*confirmIn)
	out := transport.NewSpool(*clearedOut)
	sent := map[network.SharedPattern]bool{} // dedup: a crossed pattern is sent once

	if *once {
		ingest(in, out, ledger, sent)
		return
	}
	log.Printf("aggregator: polling %s every %s", *confirmIn, *interval)
	for {
		ingest(in, out, ledger, sent)
		time.Sleep(*interval)
	}
}

// ingest runs one aggregation cycle: read every confirmation, count each ENROLLED token's
// confirmation into the ledger, and for any pattern that reaches k>=aggregationK distinct
// enrolled tokens, re-clear it through the UNCHANGED chokepoint and send it ONCE to the
// cleared-out spool. Returns how many patterns newly crossed this cycle (for tests/metrics).
// A forged/un-enrolled token is rejected (never counted); a malformed pattern is skipped.
func ingest(in *transport.ConfirmSpool, out *transport.Spool, ledger *network.Ledger, sent map[network.SharedPattern]bool) int {
	confs, err := in.ReceiveConfirmations()
	if err != nil {
		log.Printf("aggregator: some confirmations skipped: %v", err)
	}
	crossed := 0
	for _, c := range confs {
		sp, err := network.ParseSharedPattern(c.Pattern)
		if err != nil {
			log.Printf("aggregator: bad pattern in a confirmation: %v", err)
			continue
		}
		n, err := ledger.IngestConfirmation(c.Scope, sp)
		if err != nil {
			log.Printf("aggregator: skip confirmation: %v", err)
			continue
		}
		// Re-clear through the UNCHANGED chokepoint; it authoritatively re-checks
		// k>=aggregationK from the ledger (the n above is observability only).
		cleared, err := network.ClearWithLedger(network.SharedCandidate(sp), network.ClearContext{Ledger: ledger})
		if err != nil {
			continue // sub-k (not yet 3 distinct enrolled tokens) — nothing crosses
		}
		if sent[sp] {
			continue // already crossed; don't re-send the same pattern
		}
		if err := out.Send(cleared); err != nil {
			log.Printf("aggregator: send cleared: %v", err)
			continue
		}
		sent[sp] = true
		crossed++
		log.Printf("aggregator: pattern CROSSED at k=%d distinct enrolled scopes -> sent to consumer spool", n)
	}
	return crossed
}

// loadTokens builds the enrolled-token set from the CSV flag and/or a one-per-line file.
func loadTokens(csv, file string) map[string]struct{} {
	allow := map[string]struct{}{}
	for _, t := range strings.Split(csv, ",") {
		if t = strings.TrimSpace(t); t != "" {
			allow[t] = struct{}{}
		}
	}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			log.Fatalf("aggregator: open tokens file %q: %v", file, err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if t := strings.TrimSpace(sc.Text()); t != "" && !strings.HasPrefix(t, "#") {
				allow[t] = struct{}{}
			}
		}
	}
	return allow
}
