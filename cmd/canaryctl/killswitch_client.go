package main

// killswitch_client.go is the canaryctl side of the SLICE-B1 operator
// enforcement KILL-SWITCH. It is a plain net/http client (stdlib only — NOT
// gRPC, NOT api/enginegrpc; the admin surface is deliberately out-of-band, with
// no proto/wire change) that talks to the token-gated admin endpoint mirrored in
// cmd/staged-range/killswitch_admin.go:
//
//	POST /killswitch/engage  {duration_seconds, reason}  -> Status JSON
//	POST /killswitch/revive  {reason}                    -> Status JSON
//	GET  /killswitch                                     -> Status JSON
//
// Every route (including GET status) requires the bearer token — the surface is
// not public. The admin endpoint is LOOPBACK-bound on the server, so canaryctl
// runs alongside the engine or over an SSH tunnel, pointing -killswitch-admin-addr
// at 127.0.0.1 (B2 adds mTLS for a remote operator).
//
// FAIL-CLOSED: an empty/missing token file aborts before any request. AUTH-GAP
// CAVEAT: an engage/revive whose safety action succeeded but whose audit append
// FAILED still returns 200 + Status — only the server logs the tamper-evidence
// gap, so a canaryctl success is NOT a tamper-evidence guarantee.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/sting/killswitch"
)

// httpTimeout bounds every admin request. The admin endpoint is loopback/local,
// so a few seconds is generous.
const httpTimeout = 10 * time.Second

// engageRequest mirrors the server's POST /killswitch/engage body
// (cmd/staged-range/killswitch_admin.go). DurationSeconds<=0 => INDEFINITE
// (until an explicit revive).
type engageRequest struct {
	DurationSeconds int64  `json:"duration_seconds"`
	Reason          string `json:"reason"`
}

// reviveRequest mirrors the server's POST /killswitch/revive body.
type reviveRequest struct {
	Reason string `json:"reason"`
}

// runKillSwitch dispatches "canaryctl killswitch <action> [flags]". args is
// os.Args[2:] (action + its flags). Each action parses its own flags from
// args[1:] with a dedicated flag.NewFlagSet so each owns its flags.
func runKillSwitch(args []string) {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, killSwitchUsage)
		os.Exit(2)
	}
	action := args[0]
	rest := args[1:]
	switch action {
	case "engage":
		killSwitchEngage(rest)
	case "revive":
		killSwitchRevive(rest)
	case "status":
		killSwitchStatus(rest)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stderr, killSwitchUsage)
	default:
		fmt.Fprintf(os.Stderr, "canaryctl: killswitch: unknown action %q\n\n%s", action, killSwitchUsage)
		os.Exit(2)
	}
}

const killSwitchUsage = `canaryctl killswitch — operate the deployment-wide enforcement DISARM

Usage:
  canaryctl killswitch engage -killswitch-admin-addr <host:port> -killswitch-token-file <path> [-duration <dur>] [-reason <text>] [-operator <name>] [-json]
  canaryctl killswitch revive -killswitch-admin-addr <host:port> -killswitch-token-file <path> [-reason <text>] [-operator <name>] [-json]
  canaryctl killswitch status -killswitch-admin-addr <host:port> -killswitch-token-file <path> [-json]

The admin endpoint is loopback-bound on the engine box; point -killswitch-admin-addr
at 127.0.0.1 (run alongside the engine or over an SSH tunnel). A duration <= 0 (or
omitted) on engage means INDEFINITE (halted until an operator revives). Pass -json to
emit the raw status (engaged/operator/reason/engaged_at/expires_at) for scripts/agents.
`

// addCommonFlags registers the address + token-file + output-format flags shared by
// every action. -json makes the action emit the raw killswitch.Status as a single line
// of JSON (machine-readable, the SAME shape the dashboard consumes) so an agent or
// script reads structured fields rather than scraping prose — agent-native parity with
// the dashboard's structured view.
func addCommonFlags(fs *flag.FlagSet, addr, tokenFile *string, jsonOut *bool) {
	fs.StringVar(addr, "killswitch-admin-addr", "", "loopback host:port of the token-gated kill-switch admin endpoint (e.g. 127.0.0.1:9090); mirrors the server -killswitch-admin-addr")
	fs.StringVar(tokenFile, "killswitch-token-file", "", "path to the bearer-token FILE that gates the admin endpoint; mirrors the server -killswitch-token-file (fail-closed: empty/missing aborts)")
	fs.BoolVar(jsonOut, "json", false, "emit the raw kill-switch status as one line of JSON (engaged/operator/reason/engaged_at/expires_at — the same shape the dashboard consumes) instead of human prose; for scripts/agents")
}

// emitStatus prints the result: the raw killswitch.Status JSON when asJSON (so a script
// reads exit-code for transport/auth success AND the `engaged` bool for posture,
// independently), else the human prose. The JSON is the wire shape the dashboard
// backend also mirrors, so canaryctl and the UI report identical structured fields.
func emitStatus(st killswitch.Status, asJSON bool, prose string) {
	if asJSON {
		b, err := json.Marshal(st)
		if err != nil {
			log.Fatalf("canaryctl: killswitch: marshal status json: %v", err)
		}
		fmt.Println(string(b))
		return
	}
	fmt.Println(prose)
}

func killSwitchEngage(args []string) {
	fs := flag.NewFlagSet("killswitch engage", flag.ExitOnError)
	var addr, tokenFile, reason, operator string
	var duration time.Duration
	var jsonOut bool
	addCommonFlags(fs, &addr, &tokenFile, &jsonOut)
	fs.DurationVar(&duration, "duration", 0, "how long to halt enforcement (e.g. 30m, 2h); <= 0 means INDEFINITE (until revived)")
	fs.StringVar(&reason, "reason", "", "operator-supplied justification, recorded in the audit trail")
	fs.StringVar(&operator, "operator", "", "advisory operator identity, sent as the X-Operator header for the audit trail")
	_ = fs.Parse(args)

	tok := readToken(tokenFile)
	// duration<=0 => indefinite (DurationSeconds<=0); otherwise whole seconds.
	durSec := int64(duration / time.Second)
	body, err := json.Marshal(engageRequest{DurationSeconds: durSec, Reason: reason})
	if err != nil {
		log.Fatalf("canaryctl: killswitch engage: marshal body: %v", err)
	}
	// Engage is NOT EOF-tolerant server-side — an empty body 400s. json.Marshal of a
	// struct always yields at least `{}`, so this is safe by construction.
	st := doRequest(http.MethodPost, addr, "/killswitch/engage", tok, operator, body, "engage")
	emitStatus(st, jsonOut, formatEngaged(st))
}

func killSwitchRevive(args []string) {
	fs := flag.NewFlagSet("killswitch revive", flag.ExitOnError)
	var addr, tokenFile, reason, operator string
	var jsonOut bool
	addCommonFlags(fs, &addr, &tokenFile, &jsonOut)
	fs.StringVar(&reason, "reason", "", "operator-supplied justification, recorded in the audit trail")
	fs.StringVar(&operator, "operator", "", "advisory operator identity, sent as the X-Operator header for the audit trail")
	_ = fs.Parse(args)

	tok := readToken(tokenFile)
	// Revive IS EOF-tolerant server-side, but we still send {"reason":...} so a given
	// -reason is recorded. Revive is idempotent (reviving a disengaged switch is a 200 no-op).
	body, err := json.Marshal(reviveRequest{Reason: reason})
	if err != nil {
		log.Fatalf("canaryctl: killswitch revive: marshal body: %v", err)
	}
	st := doRequest(http.MethodPost, addr, "/killswitch/revive", tok, operator, body, "revive")
	emitStatus(st, jsonOut, formatResumed(st))
}

func killSwitchStatus(args []string) {
	fs := flag.NewFlagSet("killswitch status", flag.ExitOnError)
	var addr, tokenFile string
	var jsonOut bool
	addCommonFlags(fs, &addr, &tokenFile, &jsonOut)
	_ = fs.Parse(args)

	tok := readToken(tokenFile)
	// GET status also requires the bearer token (the surface is not public). No body.
	st := doRequest(http.MethodGet, addr, "/killswitch", tok, "", nil, "status")
	emitStatus(st, jsonOut, formatStatus(st))
}

// readToken reads the bearer token from path, trims whitespace, and fail-closes
// (log.Fatalf with the binary prefix) on a missing path, an unreadable file, or
// an empty token — mirroring newKillSwitchAdmin: there is never an
// unauthenticated kill-switch.
func readToken(path string) string {
	if strings.TrimSpace(path) == "" {
		log.Fatalf("canaryctl: killswitch: -killswitch-token-file is REQUIRED (no unauthenticated kill-switch)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("canaryctl: killswitch: read token file %q: %v", path, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		log.Fatalf("canaryctl: killswitch: token file %q is empty; refusing to send an empty bearer token", path)
	}
	return tok
}

// adminURL builds the admin request URL from a bare host:port (mirroring the server
// -killswitch-admin-addr flag) and a path. net/url needs a SCHEME: without one,
// "127.0.0.1:9610/killswitch" parses with "127.0.0.1" mistaken for the scheme ("first
// path segment in URL cannot contain colon"). We default to http (the B1 admin is
// plaintext loopback) and honor an explicit http(s):// if the operator supplied one.
func adminURL(addr, path string) string {
	base := strings.TrimSpace(addr)
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	return strings.TrimRight(base, "/") + path
}

// doRequest performs one admin call and returns the decoded Status. It fail-closes
// (log.Fatalf, binary-prefixed) on a missing address, a transport error, a non-2xx
// response (surfacing the status line + body), or a decode error. It branches on the
// status code BEFORE decoding: only 200 is application/json; 401/405/400 are plain
// text via http.Error.
func doRequest(method, addr, path, tok, operator string, body []byte, action string) killswitch.Status {
	if strings.TrimSpace(addr) == "" {
		log.Fatalf("canaryctl: killswitch %s: -killswitch-admin-addr is REQUIRED (loopback host:port, e.g. 127.0.0.1:9090)", action)
	}
	url := adminURL(addr, path)

	var reqBody *bytes.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		log.Fatalf("canaryctl: killswitch %s: build request: %v", action, err)
	}
	// Bearer with a capital B and a single trailing space — the server's TrimPrefix is
	// an exact match ("Bearer "); "bearer " or a double space would not strip cleanly.
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(operator) != "" {
		req.Header.Set("X-Operator", operator)
	}

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("canaryctl: killswitch %s: request to %s: %v", action, url, err)
	}
	defer resp.Body.Close()

	// Branch on status BEFORE decoding: only 200 is JSON; errors are plain text.
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		log.Fatalf("canaryctl: killswitch %s: %s: %s", action, resp.Status, strings.TrimSpace(string(errBody)))
	}

	var st killswitch.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		log.Fatalf("canaryctl: killswitch %s: decode status: %v", action, err)
	}
	return st
}

// expiry renders the ExpiresAt sentinel: a zero ExpiresAt means INDEFINITE.
func expiry(st killswitch.Status) string {
	if st.ExpiresAt.IsZero() {
		return "indefinite (until revived)"
	}
	return st.ExpiresAt.UTC().Format(time.RFC3339)
}

// engagedAtStr renders the EngagedAt sentinel: a zero EngagedAt means "not set".
func engagedAtStr(st killswitch.Status) string {
	if st.EngagedAt.IsZero() {
		return "not set"
	}
	return st.EngagedAt.UTC().Format(time.RFC3339)
}

// formatEngaged prints the halted posture after an engage. It trusts the
// authoritative Engaged bit (a duration so short it has already lapsed could read
// back disengaged), not the presence of operator/expiry.
func formatEngaged(st killswitch.Status) string {
	if !st.Engaged {
		return "kill-switch: NOT engaged (the engagement may have already expired) — enforcement is ACTIVE"
	}
	op := st.Operator
	if op == "" {
		op = "operator"
	}
	return fmt.Sprintf("kill-switch: ENFORCEMENT HALTED (disarmed deployment-wide)\n  operator: %s\n  reason:   %s\n  engaged:  %s\n  expires:  %s",
		op, reasonOrNone(st.Reason), engagedAtStr(st), expiry(st))
}

// formatResumed prints the disengaged posture after a revive.
func formatResumed(st killswitch.Status) string {
	if st.Engaged {
		// Should not happen on a successful revive, but report honestly off the bit.
		return "kill-switch: still ENGAGED after revive (unexpected) — re-check status"
	}
	return "kill-switch: ENFORCEMENT RESUMED (enforcement is ACTIVE)"
}

// formatStatus prints the full posture for the status action, gating on Engaged.
func formatStatus(st killswitch.Status) string {
	if !st.Engaged {
		return "kill-switch: DISENGAGED — enforcement is ACTIVE (normal posture)"
	}
	op := st.Operator
	if op == "" {
		op = "operator"
	}
	return fmt.Sprintf("kill-switch: ENGAGED — ENFORCEMENT HALTED\n  operator: %s\n  reason:   %s\n  engaged:  %s\n  expires:  %s",
		op, reasonOrNone(st.Reason), engagedAtStr(st), expiry(st))
}

func reasonOrNone(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "(none)"
	}
	return reason
}
