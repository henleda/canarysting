package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/contract"
)

// Emitter is the ONE-WAY sink for a SiemEvent. Implementations PUSH only — there is
// no return channel, no response-driven control: a SIEM/SOAR receiver can never
// steer the engine (rule 8 — nothing here arms; the emitter is emit-only). An Emit
// error is the transport's own (a network/IO failure); the caller logs and drops it
// after a bounded retry. A SIEM outage MUST NEVER block or fail a verdict closed, so
// Emit is called only off the hot path (the Run drain), never inline on Submit.
type Emitter interface {
	// Emit pushes one event. It must be safe to call repeatedly and must return
	// promptly (bounded by its own timeout); it never reads a response that changes
	// engine behavior.
	Emit(ctx context.Context, ev SiemEvent) error
	// Name identifies the transport for logging.
	Name() string
}

// SinkConfig selects a transport at the composition root. Format is one of
// "off"/"" (NopEmitter, inert), "stdout" (NDJSON to stdout — the default when no
// endpoint), "json"/"webhook" (HTTP POST to Endpoint), or "cef" (CEF single line to
// stdout). Endpoint is the webhook/HEC URL (required for json/webhook). HECToken is
// the optional Splunk HEC token.
type SinkConfig struct {
	Format   string
	Endpoint string
	HECToken string
}

// NewSink builds the Emitter for a SinkConfig, fail-safe: an unknown format or a
// json/webhook format with no endpoint falls back to OFF (NopEmitter) so a misconfig
// can never silently send to the wrong place. It returns the chosen emitter and a
// human note for the boot log.
func NewSink(cfg SinkConfig) (Emitter, string) {
	switch cfg.Format {
	case "", "off":
		return NopEmitter{}, "off (inert)"
	case "stdout":
		return NewStdoutEmitter(nil), "stdout NDJSON"
	case "cef":
		return NewCEFEmitter(nil), "cef single-line to stdout"
	case "json", "webhook":
		if cfg.Endpoint == "" {
			return NopEmitter{}, "off (json/webhook selected but no -siem-endpoint; refusing to guess a destination)"
		}
		return NewWebhookEmitter(cfg.Endpoint, cfg.HECToken), "webhook POST -> " + cfg.Endpoint
	default:
		return NopEmitter{}, "off (unknown -siem-format " + cfg.Format + ")"
	}
}

// --- no-op / stdout default --------------------------------------------------

// StdoutEmitter writes each event as one NDJSON line to an io.Writer (os.Stdout by
// default). It is the safe DEFAULT format ("stdout"): off-box nothing is sent, the
// operator just sees the events in the engine log, so enabling the emitter without a
// real endpoint can never leak to a third party.
type StdoutEmitter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdoutEmitter returns a stdout emitter. A nil writer defaults to os.Stdout.
func NewStdoutEmitter(w io.Writer) *StdoutEmitter {
	if w == nil {
		w = os.Stdout
	}
	return &StdoutEmitter{w: w}
}

func (e *StdoutEmitter) Emit(_ context.Context, ev SiemEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("siem: marshal event: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("siem: write event: %w", err)
	}
	return nil
}

func (e *StdoutEmitter) Name() string { return "stdout" }

// NopEmitter discards every event. It is the hard off-switch (no endpoint, no
// output) — used when the emitter is constructed but the operator wants it inert.
type NopEmitter struct{}

func (NopEmitter) Emit(context.Context, SiemEvent) error { return nil }
func (NopEmitter) Name() string                          { return "off" }

// --- webhook / HTTP (JSON, one-way POST) -------------------------------------

// defaultHTTPTimeout bounds a single POST so a hung SIEM receiver can never stall the
// emitter's drain goroutine (and thus never back-pressure the store).
const defaultHTTPTimeout = 5 * time.Second

// WebhookEmitter POSTs the canonical event as a JSON body to a configured endpoint —
// usable as a generic SIEM webhook and a Splunk-HEC event. It is ONE-WAY: the response
// body is drained and discarded, only the status is inspected for retry; no field of
// the response can influence the engine.
type WebhookEmitter struct {
	url    string
	client *http.Client
	// hecToken, when set, is sent as the Splunk HEC "Authorization: Splunk <token>"
	// header. Empty => a plain webhook POST with no auth header.
	hecToken string
}

// NewWebhookEmitter returns an HTTP webhook emitter for url with a bounded timeout.
// hecToken is optional (Splunk HEC); empty for a plain webhook.
func NewWebhookEmitter(url, hecToken string) *WebhookEmitter {
	return &WebhookEmitter{
		url:      url,
		hecToken: hecToken,
		client:   &http.Client{Timeout: defaultHTTPTimeout},
	}
}

func (e *WebhookEmitter) Emit(ctx context.Context, ev SiemEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("siem: marshal event: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("siem: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.hecToken != "" {
		req.Header.Set("Authorization", "Splunk "+e.hecToken)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem: post: %w", err)
	}
	// ONE-WAY: drain + discard the body (so the connection can be reused) but never
	// parse it for control — the receiver cannot steer the engine.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("siem: post %s: status %d", e.url, resp.StatusCode)
	}
	return nil
}

func (e *WebhookEmitter) Name() string { return "webhook" }

// --- CEF / syslog (single line) ----------------------------------------------

// cefVendor / cefProduct / cefVersion identify the device in the CEF header.
const (
	cefVendor  = "CanarySting"
	cefProduct = "CanarySting"
	cefVersion = "1.0"
)

// CEFEmitter formats each event as one ArcSight CEF single line and writes it to an
// io.Writer (a syslog destination, a file tailed by Filebeat, or os.Stdout). CEF is
// the classic SIEM ingest line; it is a VIEW over the same SiemEvent struct (the JSON
// emitter stays the canonical form). One-way by construction (it only writes).
type CEFEmitter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewCEFEmitter returns a CEF emitter. A nil writer defaults to os.Stdout.
func NewCEFEmitter(w io.Writer) *CEFEmitter {
	if w == nil {
		w = os.Stdout
	}
	return &CEFEmitter{w: w}
}

func (e *CEFEmitter) Emit(_ context.Context, ev SiemEvent) error {
	line := FormatCEF(ev)
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := io.WriteString(e.w, line+"\n"); err != nil {
		return fmt.Errorf("siem: write cef: %w", err)
	}
	return nil
}

func (e *CEFEmitter) Name() string { return "cef" }

// cefSeverity maps the engine tier (0..3) onto the CEF 0..10 severity scale. The
// fixed table keeps the line stable for a SOC severity rule.
func cefSeverity(tier int) int {
	// Key on the contract tier constants (not bare 0..3 literals) so a future tier-enum
	// shift is a compile error here, not a silent severity desync — the same
	// constant-keyed discipline the ATT&CK map uses.
	switch tier {
	case int(contract.TierObserve):
		return 2
	case int(contract.TierTag):
		return 5
	case int(contract.TierContain):
		return 7
	case int(contract.TierJail):
		return 10
	default:
		return 5
	}
}

// FormatCEF renders a SiemEvent as a single ArcSight CEF line. The header is
// CEF:0|vendor|product|version|signatureId|name|severity| and the extension carries
// the record fields as key=value pairs. Header fields escape '|' and '\'; extension
// VALUES escape '=', '\', and newlines (CEF rules). A field the record lacks is
// OMITTED from the extension (never faked). Exported so a test can assert the line
// shape and a future formatter can reuse it.
func FormatCEF(ev SiemEvent) string {
	// signatureId: the canary type keys the touch-of-decoy signature.
	sig := ev.CanaryType
	if sig == "" {
		sig = "canary-touch"
	}
	name := ev.EventType
	header := strings.Join([]string{
		"CEF:0",
		cefEscapeHeader(cefVendor),
		cefEscapeHeader(cefProduct),
		cefEscapeHeader(cefVersion),
		cefEscapeHeader(sig),
		cefEscapeHeader(name),
		strconv.Itoa(cefSeverity(ev.Tier)),
	}, "|")

	var ext []string
	add := func(k, v string) {
		if v == "" {
			return
		}
		ext = append(ext, k+"="+cefEscapeValue(v))
	}
	// Stable, documented extension keys (CEF dictionary keys where one fits; custom
	// cs* labels otherwise). ADD-ONLY, matching the JSON schema's stability contract.
	add("externalId", ev.EventID)
	add("cs1Label", "scope")
	add("cs1", ev.Scope)
	add("rt", strconv.FormatInt(ev.Timestamp.UnixMilli(), 10))
	add("src", ev.SourceAddress)
	add("suser", ev.SPIFFEID)
	add("requestMethod", ev.Method)
	add("request", ev.Path)
	add("cs2Label", "socket_cookie")
	add("cs2", strconv.FormatUint(ev.SocketCookie, 10))
	add("cs3Label", "canary_type")
	add("cs3", ev.CanaryType)
	if len(ev.AttackTechniques) > 0 {
		add("cs4Label", "att_ck")
		add("cs4", strings.Join(ev.AttackTechniques, ","))
	}
	add("cs5Label", "verdict")
	add("cs5", ev.Verdict)
	add("cnt", strconv.FormatUint(ev.HitCount, 10))
	// Numeric facts that are always present (including the load-bearing zero) — added
	// unconditionally via the raw slice so the 0 is not dropped by the empty guard.
	ext = append(ext, "cn1Label=score")
	ext = append(ext, "cn1="+cefEscapeValue(strconv.FormatFloat(ev.Score, 'f', -1, 64)))
	ext = append(ext, "cn2Label=bytes_real_data_crossed")
	ext = append(ext, "cn2="+strconv.FormatInt(ev.BytesRealDataCrossed, 10))

	return header + "|" + strings.Join(ext, " ")
}

// cefEscapeHeader escapes the CEF header field separators: backslash and pipe.
func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	return s
}

// cefEscapeValue escapes a CEF extension value: backslash, equals, and newlines.
func cefEscapeValue(s string) string {
	// Escaping '=' is the load-bearing guard against extension-key injection from
	// attacker-influenced values (e.g. a decoy path): a CEF parser delimits keys on an
	// UNescaped '=', so an escaped '\=' inside a value can never start a spurious key,
	// even after a space. (Spaces themselves are legal in CEF extension values.) JSON is
	// the recommended canonical transport; CEF is a convenience view.
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
