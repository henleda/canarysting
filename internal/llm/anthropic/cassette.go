package anthropic

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	sdk "github.com/anthropics/anthropic-sdk-go"
)

// cassetteVersion is the on-disk cassette schema version.
const cassetteVersion = 1

// cassette is the on-disk record of an attacker run's LLM exchange: the ordered
// raw API response docs (each carries the REAL Usage). A replay reproduces the
// attacker's exact tool-call DECISIONS — which the agent still executes against
// the LIVE target, so the replay drives real engine events + attrition — while
// the recorded Usage drives the real cost meter, $0 and deterministic. Only the
// assistant responses are stored (they drive the loop + the cost); the request
// params are not needed to replay.
type cassette struct {
	Version   int               `json:"version"`
	Model     string            `json:"model,omitempty"`
	Note      string            `json:"note,omitempty"`
	Responses []json.RawMessage `json:"responses"`
}

// RecordingClient wraps a real Messager and captures each response's RAW API
// JSON (msg.RawJSON() — the exact bytes the SDK decoded, so a replay re-decodes
// faithfully) into an ordered cassette. It is transparent: New returns the inner
// response unchanged, so a recording run behaves identically to a normal run.
type RecordingClient struct {
	inner Messager
	model string
	mu    sync.Mutex
	raws  []json.RawMessage
}

// NewRecordingClient wraps inner; model is recorded as cassette metadata.
func NewRecordingClient(inner Messager, model string) *RecordingClient {
	return &RecordingClient{inner: inner, model: model}
}

// New calls the inner client, captures the response's raw JSON, and returns the
// response unchanged.
func (r *RecordingClient) New(ctx context.Context, p sdk.MessageNewParams) (*sdk.Message, error) {
	msg, err := r.inner.New(ctx, p)
	if err != nil || msg == nil {
		return msg, err
	}
	raw := msg.RawJSON()
	if raw == "" || raw == "null" {
		// Defensive: a synthesized message with no decode buffer; re-marshal so
		// the cassette still round-trips (MessageFromJSON re-decodes it).
		if b, mErr := json.Marshal(msg); mErr == nil {
			raw = string(b)
		}
	}
	if raw != "" {
		r.mu.Lock()
		r.raws = append(r.raws, json.RawMessage(raw))
		r.mu.Unlock()
	}
	return msg, err
}

// Count returns how many responses have been captured so far.
func (r *RecordingClient) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.raws)
}

// Save writes the captured cassette to path (0600). Errors if nothing was
// recorded (an empty cassette would replay into an immediate terminal).
func (r *RecordingClient) Save(path, note string) error {
	r.mu.Lock()
	c := cassette{Version: cassetteVersion, Model: r.model, Note: note, Responses: append([]json.RawMessage(nil), r.raws...)}
	r.mu.Unlock()
	if len(c.Responses) == 0 {
		return fmt.Errorf("anthropic: cassette is empty (nothing recorded)")
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("anthropic: marshal cassette: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("anthropic: write cassette %q: %w", path, err)
	}
	return nil
}

// ReplayClient is a Messager that returns recorded responses in order — zero
// API, zero cost, deterministic — carrying the real recorded Usage. When the
// recorded responses are exhausted it returns a synthesized terminal end_turn
// (no tool-use, zero usage) so the agent loop ALWAYS ends cleanly, even if the
// recording ended on a budget cap / max-turns rather than a natural final text.
type ReplayClient struct {
	mu        sync.Mutex
	responses []*sdk.Message
	i         int
}

// replayTerminal is the clean end_turn returned once the cassette is exhausted —
// no tool-use block (so the agent loop stops) and zero usage (so it adds no cost).
const replayTerminal = `{"id":"replay-end","type":"message","role":"assistant","model":"replay","content":[{"type":"text","text":"(replay complete)"}],"stop_reason":"end_turn","usage":{"input_tokens":0,"output_tokens":0,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}`

// New returns the next recorded response, or a terminal end_turn once exhausted.
func (r *ReplayClient) New(_ context.Context, _ sdk.MessageNewParams) (*sdk.Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.i < len(r.responses) {
		m := r.responses[r.i]
		r.i++
		return m, nil
	}
	return MessageFromJSON(replayTerminal)
}

// Remaining reports how many recorded responses have not yet been replayed.
func (r *ReplayClient) Remaining() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.responses) - r.i
}

var _ Messager = (*ReplayClient)(nil)

// LoadCassette reads a recorded cassette and returns a ReplayClient that replays
// its responses in order ($0, deterministic, carrying the real recorded Usage).
// The replayed responses drive the agent's tool-call decisions; the agent still
// executes those calls against the live target, so a replay produces real engine
// events + attrition while costing nothing.
func LoadCassette(path string) (*ReplayClient, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("anthropic: read cassette %q: %w", path, err)
	}
	var c cassette
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("anthropic: parse cassette %q: %w", path, err)
	}
	if c.Version != cassetteVersion {
		return nil, fmt.Errorf("anthropic: cassette %q version %d != expected %d", path, c.Version, cassetteVersion)
	}
	if len(c.Responses) == 0 {
		return nil, fmt.Errorf("anthropic: cassette %q has no responses", path)
	}
	rc := &ReplayClient{}
	for i, raw := range c.Responses {
		msg, err := MessageFromJSON(string(raw))
		if err != nil {
			return nil, fmt.Errorf("anthropic: cassette %q response %d: %w", path, i, err)
		}
		rc.responses = append(rc.responses, msg)
	}
	return rc, nil
}
