package main

// deviant_client.go is the canaryctl side of the operator DEVIANT ACK/SUPPRESS
// triage. It is a plain net/http client (stdlib only — NOT gRPC, NOT
// api/enginegrpc; the admin surface is deliberately out-of-band, with no proto/wire
// change) that talks to the SAME token-gated, loopback-bound kill-switch admin
// endpoint mirrored in cmd/staged-range/killswitch_admin.go:
//
//	POST /deviant/suppress    {key, reason}  -> {key, state:"suppressed", scope}
//	POST /deviant/unsuppress  {key, reason}  -> {key, state:"normal",     scope}
//	POST /deviant/ack         {key, reason}  -> {key, state:"acked",      scope}
//
// All three are MUTATING and require the OPERATOR role (the same gate as
// engage/revive). It reuses the kill-switch client's common flags (-killswitch-
// admin-addr / -killswitch-token-file / -json), readToken, adminURL, and the
// Bearer/Content-Type/X-Operator request shape (doDeviantRequest mirrors doRequest).
//
// The <key> is the canonical deviant recurrence key the dashboard shows per row,
// HEX-encoded (the ONE pinned encoding — the value matches the overlay key
// byte-for-byte). The DASHBOARD STAYS READ-ONLY: suppress/ack is performed here (or
// a direct admin POST), never from the page.

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
)

// deviantTriageRequest mirrors the server's POST /deviant/* body
// (cmd/staged-range/killswitch_admin.go). Key is the HEX canonical deviant key.
type deviantTriageRequest struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// deviantTriageResponse mirrors the server's small JSON response.
type deviantTriageResponse struct {
	Key   string `json:"key"`
	State string `json:"state"`
	Scope string `json:"scope"`
}

const deviantUsage = `canaryctl deviant — operator ACK/SUPPRESS triage of a deviant hunting-log pattern

Usage:
  canaryctl deviant suppress   -killswitch-admin-addr <host:port> -killswitch-token-file <path> -key <hexKey> [-reason <text>] [-operator <name>] [-json]
  canaryctl deviant unsuppress -killswitch-admin-addr <host:port> -killswitch-token-file <path> -key <hexKey> [-reason <text>] [-operator <name>] [-json]
  canaryctl deviant ack        -killswitch-admin-addr <host:port> -killswitch-token-file <path> -key <hexKey> [-reason <text>] [-operator <name>] [-json]

suppress   hides a KNOWN-BENIGN pattern from the default deviants list (still counted, still viewable via the toggle)
unsuppress clears any triage state (un-suppress / un-ack -> normal)
ack        marks a pattern SEEN-but-KEEP-SHOWING (stays in the list, badged + demoted), never hidden

All three are MUTATING and require the OPERATOR role. -key is the HEX canonical
deviant key shown per row on the deviants page (copy it from the dashboard). The
admin endpoint is loopback-bound on the engine box; point -killswitch-admin-addr at
127.0.0.1 (run alongside the engine or over an SSH tunnel). Pass -json to emit the
raw {key,state,scope} response for scripts/agents.
`

// runDeviant dispatches "canaryctl deviant <action> [flags]". args is os.Args[2:]
// (action + its flags). Each action parses its own flags with a dedicated FlagSet.
func runDeviant(args []string) {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, deviantUsage)
		os.Exit(2)
	}
	action := args[0]
	rest := args[1:]
	switch action {
	case "suppress":
		deviantTriage(rest, "suppress", "/deviant/suppress")
	case "unsuppress":
		deviantTriage(rest, "unsuppress", "/deviant/unsuppress")
	case "ack":
		deviantTriage(rest, "ack", "/deviant/ack")
	case "-h", "--help", "help":
		fmt.Fprint(os.Stderr, deviantUsage)
	default:
		fmt.Fprintf(os.Stderr, "canaryctl: deviant: unknown action %q\n\n%s", action, deviantUsage)
		os.Exit(2)
	}
}

// deviantTriage parses the action's flags, marshals {key,reason}, POSTs to path, and
// gates output on -json. It reuses addCommonFlags / readToken / adminURL from the
// kill-switch client (same loopback admin, same token).
func deviantTriage(args []string, action, path string) {
	fs := flag.NewFlagSet("deviant "+action, flag.ExitOnError)
	var addr, tokenFile, key, reason, operator string
	var jsonOut bool
	addCommonFlags(fs, &addr, &tokenFile, &jsonOut)
	fs.StringVar(&key, "key", "", "the HEX canonical deviant recurrence key (copy it from the deviants page row)")
	fs.StringVar(&reason, "reason", "", "operator-supplied justification, recorded in the audit trail")
	fs.StringVar(&operator, "operator", "", "advisory operator identity, sent as the X-Operator header for the audit trail")
	_ = fs.Parse(args)

	if strings.TrimSpace(key) == "" {
		log.Fatalf("canaryctl: deviant %s: -key is REQUIRED (the HEX canonical deviant key shown per row on the deviants page)", action)
	}
	tok := readToken(tokenFile)
	body, err := json.Marshal(deviantTriageRequest{Key: key, Reason: reason})
	if err != nil {
		log.Fatalf("canaryctl: deviant %s: marshal body: %v", action, err)
	}
	resp := doDeviantRequest(addr, path, tok, operator, body, action)
	emitDeviant(resp, jsonOut, action)
}

// doDeviantRequest performs one deviant admin POST and returns the decoded response.
// It mirrors doRequest's Bearer/Content-Type/X-Operator shape and fail-closed
// handling (log.Fatalf on a missing address, transport error, non-2xx, or decode
// error). Only 200 is JSON; 401/403/405/400/500 are plain text via http.Error.
func doDeviantRequest(addr, path, tok, operator string, body []byte, action string) deviantTriageResponse {
	if strings.TrimSpace(addr) == "" {
		log.Fatalf("canaryctl: deviant %s: -killswitch-admin-addr is REQUIRED (loopback host:port, e.g. 127.0.0.1:9090)", action)
	}
	url := adminURL(addr, path)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Fatalf("canaryctl: deviant %s: build request: %v", action, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(operator) != "" {
		req.Header.Set("X-Operator", operator)
	}

	client := &http.Client{Timeout: httpTimeout}
	httpResp, err := client.Do(req)
	if err != nil {
		log.Fatalf("canaryctl: deviant %s: request to %s: %v", action, url, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4<<10))
		log.Fatalf("canaryctl: deviant %s: %s: %s", action, httpResp.Status, strings.TrimSpace(string(errBody)))
	}

	var resp deviantTriageResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		log.Fatalf("canaryctl: deviant %s: decode response: %v", action, err)
	}
	return resp
}

// emitDeviant prints the result: the raw JSON when asJSON (for scripts/agents), else
// human prose stating the resulting state.
func emitDeviant(resp deviantTriageResponse, asJSON bool, action string) {
	if asJSON {
		b, err := json.Marshal(resp)
		if err != nil {
			log.Fatalf("canaryctl: deviant %s: marshal response json: %v", action, err)
		}
		fmt.Println(string(b))
		return
	}
	switch resp.State {
	case "suppressed":
		fmt.Printf("deviant: SUPPRESSED (hidden from the default list, still counted) — key=%s scope=%s\n", resp.Key, resp.Scope)
	case "acked":
		fmt.Printf("deviant: ACKED (kept in the list, badged + demoted) — key=%s scope=%s\n", resp.Key, resp.Scope)
	case "normal":
		fmt.Printf("deviant: CLEARED to normal (no triage state) — key=%s scope=%s\n", resp.Key, resp.Scope)
	default:
		fmt.Printf("deviant: state=%s key=%s scope=%s\n", resp.State, resp.Key, resp.Scope)
	}
}
