// Command attacker is the M5 demo's scripted attacker + exit-bar gate. It holds
// ONE keepalive TCP connection to Envoy (one socket => one cookie), brushes the
// negative-space canaries to escalate the flow to Tier 3 (Jail), then proves the
// kernel jailed exactly that flow: a follow-up request on the SAME connection
// hangs (Envoy's egress to it is dropped in-kernel) while a separate BYSTANDER
// connection keeps getting 200s. Exits non-zero on any violation.
//
// Run from deploy/m5-demo/run-demo.sh after the stack is up. A raw socket (not
// net/http's pooled transport) is deliberate: http.Transport would retry a
// jailed request on a FRESH connection (new cookie, not jailed) and mask the jail.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const addr = "127.0.0.1:8080"

// canary paths must match cmd/envoy-adapter's demoCanaryPaths.
var canaries = []string{"/.aws/credentials", "/.env", "/backup/db.sql", "/internal/buckets", "/admin/metrics"}

// conn is a single keepalive HTTP/1.1 connection (one socket, one cookie).
type conn struct {
	c  net.Conn
	br *bufio.Reader
}

func dial() (*conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &conn{c: c, br: bufio.NewReader(c)}, nil
}

// get sends a keepalive GET and reads the response within timeout. A read timeout
// (Envoy's egress dropped) returns an error — that is the jail.
func (k *conn) get(path string, timeout time.Duration) (int, error) {
	if _, err := fmt.Fprintf(k.c, "GET %s HTTP/1.1\r\nHost: demo\r\nConnection: keep-alive\r\n\r\n", path); err != nil {
		return 0, err
	}
	_ = k.c.SetReadDeadline(time.Now().Add(timeout))
	resp, err := http.ReadResponse(k.br, nil)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func (k *conn) close() { _ = k.c.Close() }

func main() {
	fmt.Println("M5 demo — kernel jail precision: attacker escalates on one connection, gets jailed; bystander unaffected.")

	atk, err := dial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: attacker dial: %v\n", err)
		os.Exit(1)
	}
	defer atk.close()

	// Escalate: brush each canary on the SAME connection (score climbs to Tier 3).
	// Count REAL responses — silence is only credible as a jail if the flow first
	// escalated through genuine 200s. A connection that dies immediately (engine
	// down, Envoy error) is NOT a jail and must fail the gate, not pass it.
	escalated := 0
	for _, p := range canaries {
		code, err := atk.get(p, 3*time.Second)
		if err != nil {
			fmt.Printf("  attacker GET %-20s -> no response (%v)\n", p, err)
			break // possibly jailed mid-escalation; the escalated-count guard verifies
		}
		fmt.Printf("  attacker GET %-20s -> %d\n", p, code)
		if code == http.StatusOK {
			escalated++
		}
	}
	if escalated < 3 {
		fmt.Fprintf(os.Stderr, "FAIL: flow never escalated through real responses (%d 200s) — cannot attribute silence to a kernel jail\n", escalated)
		os.Exit(1)
	}

	// Probe: after escalation the flow should be jailed — its requests now hang.
	jailed := false
	for i := 0; i < 6; i++ {
		if _, err := atk.get("/orders", 1500*time.Millisecond); err != nil {
			jailed = true
			fmt.Printf("  attacker probe %d -> JAILED (no response: %v)\n", i, err)
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Bystander: a SEPARATE connection (different cookie) must keep working.
	bys, err := dial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: bystander dial: %v\n", err)
		os.Exit(1)
	}
	defer bys.close()
	bystanderOK := true
	for i := 0; i < 6; i++ {
		code, err := bys.get("/orders", 2*time.Second)
		if err != nil || code != http.StatusOK {
			bystanderOK = false
			fmt.Printf("  bystander req %d -> FAIL (code=%d err=%v)\n", i, code, err)
			break
		}
	}
	if bystanderOK {
		fmt.Println("  bystander: 6/6 requests -> 200 (unaffected)")
	}

	fmt.Println("\n=== exit bar ===")
	fail := false
	if !jailed {
		fmt.Fprintln(os.Stderr, "FAIL: attacker flow was never jailed (kernel enforcement did not trigger)")
		fail = true
	} else {
		fmt.Println("OK: the attacker's flow was jailed in-kernel after escalating to Tier 3")
	}
	if !bystanderOK {
		fmt.Fprintln(os.Stderr, "FAIL: a BYSTANDER on the same host was affected — the critical failure")
		fail = true
	} else {
		fmt.Println("OK: a bystander on the same host kept working throughout (precision)")
	}
	if fail {
		fmt.Fprintln(os.Stderr, "\nm5-demo: EXIT BAR FAILED")
		os.Exit(1)
	}
	fmt.Println("\nm5-demo: OK — real attacker jailed in-kernel by socket cookie; bystander untouched.")
}
