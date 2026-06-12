package anthropic

import (
	"context"
	"path/filepath"
	"testing"

	sdk "github.com/anthropics/anthropic-sdk-go"
)

// a recorded assistant turn that USES a tool (the agent must be able to re-decode
// the tool-use block on replay) + carries real Usage (drives the cost meter).
const toolUseDoc = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8",` +
	`"content":[{"type":"text","text":"probing"},{"type":"tool_use","id":"tu_1","name":"http_request","input":{"method":"GET","path":"/.env"}}],` +
	`"stop_reason":"tool_use","usage":{"input_tokens":1200,"output_tokens":340,"cache_read_input_tokens":80,"cache_creation_input_tokens":0}}`

// a final assistant turn (no tool-use) that ends the loop naturally.
const finalDoc = `{"id":"msg_2","type":"message","role":"assistant","model":"claude-opus-4-8",` +
	`"content":[{"type":"text","text":"giving up"}],` +
	`"stop_reason":"end_turn","usage":{"input_tokens":900,"output_tokens":50,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}`

// Record a run through a RecordingClient (over a FakeClient standing in for the
// real SDK), Save it, LoadCassette, and confirm the replay reproduces the same
// responses faithfully — the tool-use block re-decodes and the real Usage survives.
func TestCassetteRoundTrip(t *testing.T) {
	m1, err := MessageFromJSON(toolUseDoc)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := MessageFromJSON(finalDoc)
	if err != nil {
		t.Fatal(err)
	}
	inner := &FakeClient{Responses: []*sdk.Message{m1, m2}}
	rec := NewRecordingClient(inner, "claude-opus-4-8")

	// Drive both turns through the recorder (as the agent loop would).
	for i := 0; i < 2; i++ {
		if _, err := rec.New(context.Background(), sdk.MessageNewParams{}); err != nil {
			t.Fatalf("record turn %d: %v", i, err)
		}
	}
	if rec.Count() != 2 {
		t.Fatalf("recorded %d responses, want 2", rec.Count())
	}

	path := filepath.Join(t.TempDir(), "cassette.json")
	if err := rec.Save(path, "test"); err != nil {
		t.Fatalf("save: %v", err)
	}

	rc, err := LoadCassette(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if rc.Remaining() != 2 {
		t.Fatalf("loaded %d responses, want 2", rc.Remaining())
	}

	// First replayed response: the tool-use must re-decode + Usage must survive.
	r1, err := rc.New(context.Background(), sdk.MessageNewParams{})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Usage.InputTokens != 1200 || r1.Usage.OutputTokens != 340 || r1.Usage.CacheReadInputTokens != 80 {
		t.Fatalf("replayed Usage lost: %+v", r1.Usage)
	}
	var sawToolUse bool
	for _, b := range r1.Content {
		if tu := b.AsToolUse(); tu.Name == "http_request" {
			sawToolUse = true
			// the tool input must also survive the round-trip
			if string(tu.Input) == "" || string(tu.Input) == "null" {
				t.Fatalf("replayed tool-use lost its input: %q", string(tu.Input))
			}
		}
	}
	if !sawToolUse {
		t.Fatal("replayed response lost its tool-use block (AsToolUse failed — raw buffer not repopulated)")
	}

	// Second replayed response: the natural end_turn.
	r2, err := rc.New(context.Background(), sdk.MessageNewParams{})
	if err != nil {
		t.Fatal(err)
	}
	if r2.StopReason != sdk.StopReasonEndTurn {
		t.Fatalf("second response stop_reason = %q, want end_turn", r2.StopReason)
	}
}

// Once the recorded responses are exhausted, the replay returns a synthesized
// terminal end_turn (no tool-use, zero usage) so the agent loop ALWAYS ends
// cleanly — never a fatal queue-exhausted error like the bare FakeClient.
func TestReplayTerminalAfterExhaustion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	rec := NewRecordingClient(&FakeClient{Responses: mustMsgs(t, toolUseDoc)}, "m")
	rec.New(context.Background(), sdk.MessageNewParams{})
	if err := rec.Save(path, "t"); err != nil {
		t.Fatal(err)
	}
	rc, err := LoadCassette(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = rc.New(context.Background(), sdk.MessageNewParams{}) // consume the one recorded response

	// Exhausted: must NOT error; must return a no-tool-use, zero-usage terminal.
	term, err := rc.New(context.Background(), sdk.MessageNewParams{})
	if err != nil {
		t.Fatalf("exhausted replay must return a terminal, not error: %v", err)
	}
	if term.Usage.InputTokens != 0 || term.Usage.OutputTokens != 0 {
		t.Fatalf("terminal must carry zero usage, got %+v", term.Usage)
	}
	for _, b := range term.Content {
		if b.AsToolUse().Name != "" {
			t.Fatal("terminal must have NO tool-use (so the loop ends)")
		}
	}
	if term.StopReason != sdk.StopReasonEndTurn {
		t.Fatalf("terminal stop_reason = %q, want end_turn", term.StopReason)
	}
}

func TestLoadCassetteErrors(t *testing.T) {
	if _, err := LoadCassette(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing cassette must error")
	}
}

func mustMsgs(t *testing.T, docs ...string) []*sdk.Message {
	t.Helper()
	var out []*sdk.Message
	for _, d := range docs {
		m, err := MessageFromJSON(d)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}
