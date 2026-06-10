package attacker

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"time"
)

// hrefRe extracts child-link paths from a deception directory listing
// (fake_tree pages render anchor hrefs). Used to follow the maze deterministically.
var hrefRe = regexp.MustCompile(`href=["']([^"']+)["']`)

// runScripted drives the HTTP loop deterministically with NO Messager and NO
// API spend. It touches the configured canary paths in order over the single
// keepalive connection, then follows up to MazeDepth child links discovered in
// the first deception body. It produces real engine events and a real
// StingOutcome (so proxy numbers show on the dashboard) at $0 — the reference
// trace run before burning real credits, and the make-check safety net.
func (a *Agent) runScripted(ctx context.Context) (RunResult, error) {
	paths := a.cfg.CanaryPaths
	if len(paths) == 0 {
		paths = DefaultCanaryPaths
	}
	// Pin the resolved set so record() counts only real canary touches as hits;
	// maze children are probes, not canary hits.
	a.cfg.CanaryPaths = paths
	depth := a.cfg.MazeDepth
	if depth < 0 {
		depth = 0
	}

	log.Printf("[scripted] zero-API run: %d canary touches, maze-depth=%d", len(paths), depth)

	var firstBody string
	for i, p := range paths {
		if err := ctx.Err(); err != nil {
			a.result.StopReason = "cancelled"
			a.finalize()
			return a.result, nil
		}
		out, isErr, probe := a.tool.Execute(ctx, fmt.Sprintf(`{"method":"GET","path":%q}`, p))
		a.record(probe)
		a.result.TurnsCompleted = i + 1
		tier := inferTier(probe)
		log.Printf("[scripted] touch %d %s -> status=%d bytes=%d tier~%s err=%q",
			i+1, p, probe.StatusCode, probe.Bytes, tier, probe.Err)
		if firstBody == "" && !isErr && probe.Bytes > 0 {
			firstBody = out
		}
		a.emitProgress()
		// small gap so distinct touches are observable in the engine fold cadence
		a.sleep(50 * time.Millisecond)
	}

	// Follow up to `depth` child links discovered in the first deception body —
	// this exercises the self-feeding maze on the SAME connection.
	if firstBody != "" && depth > 0 {
		links := extractLinks(firstBody, depth)
		for i, link := range links {
			if err := ctx.Err(); err != nil {
				break
			}
			out, _, probe := a.tool.Execute(ctx, fmt.Sprintf(`{"method":"GET","path":%q}`, link))
			a.record(probe)
			log.Printf("[scripted] maze %d %s -> status=%d bytes=%d", i+1, link, probe.StatusCode, probe.Bytes)
			_ = out
			a.emitProgress()
			a.sleep(50 * time.Millisecond)
		}
	}

	a.result.StopReason = "scripted_complete"
	a.finalize()
	return a.result, nil
}

// inferTier gives a coarse, presentational hint at the response tier from the
// observable (status / body size / connection error). Not authoritative — the
// engine assigns the real tier; this is just for the scripted trace log.
func inferTier(p ProbeResult) string {
	switch {
	case p.Err != "":
		return "3?(jail/drop)"
	case p.Bytes > 1024:
		return "2(attrition body)"
	case p.StatusCode == 403:
		return "2/3(deny)"
	default:
		return "0/1(observe/tag)"
	}
}

// extractLinks pulls up to n unique child-link paths from a directory-listing
// body, skipping parent/self links.
func extractLinks(body string, n int) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		link := m[1]
		if link == "" || link == "." || link == ".." || link == "/" || seen[link] {
			continue
		}
		if link[0] != '/' {
			continue // keep on-target; the executor only takes absolute paths
		}
		seen[link] = true
		out = append(out, link)
		if len(out) >= n {
			break
		}
	}
	return out
}
