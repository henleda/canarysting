package anthropic

import (
	"context"
	"testing"

	sdk "github.com/anthropics/anthropic-sdk-go"
)

// TestFakeClientSatisfiesMessager is a compile-and-run check that the fake is a
// drop-in for the real client in the agent loop.
func TestFakeClientSatisfiesMessager(t *testing.T) {
	var m Messager = &FakeClient{}
	_ = m
}

// TestFakeClientPopsResponsesInOrder verifies queued responses are returned
// FIFO and that the params are recorded.
func TestFakeClientPopsResponsesInOrder(t *testing.T) {
	first, err := MessageFromJSON(`{
		"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8",
		"stop_reason":"end_turn",
		"content":[{"type":"text","text":"hello"}],
		"usage":{"input_tokens":100,"output_tokens":50,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}
	}`)
	if err != nil {
		t.Fatalf("build first: %v", err)
	}
	second, err := MessageFromJSON(`{
		"id":"msg_2","type":"message","role":"assistant","model":"claude-opus-4-8",
		"stop_reason":"end_turn",
		"content":[{"type":"text","text":"world"}],
		"usage":{"input_tokens":7,"output_tokens":3,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}
	}`)
	if err != nil {
		t.Fatalf("build second: %v", err)
	}

	fake := &FakeClient{Responses: []*sdk.Message{first, second}}

	r1, err := fake.New(context.Background(), sdk.MessageNewParams{Model: sdk.ModelClaudeOpus4_8})
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	if r1.ID != "msg_1" {
		t.Fatalf("want msg_1, got %q", r1.ID)
	}
	r2, err := fake.New(context.Background(), sdk.MessageNewParams{})
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	if r2.ID != "msg_2" {
		t.Fatalf("want msg_2, got %q", r2.ID)
	}
	// queue now empty
	if _, err := fake.New(context.Background(), sdk.MessageNewParams{}); err != ErrFake {
		t.Fatalf("want ErrFake on exhausted queue, got %v", err)
	}
	if fake.CallCount() != 3 {
		t.Fatalf("want 3 calls recorded, got %d", fake.CallCount())
	}
	if fake.Calls[0].Model != sdk.ModelClaudeOpus4_8 {
		t.Fatalf("params not recorded: %+v", fake.Calls[0])
	}
}

// TestUsageDecodes confirms the verified int64 Usage fields decode from API
// JSON — these are the numbers the Budget accumulates into real dollars.
func TestUsageDecodes(t *testing.T) {
	m, err := MessageFromJSON(`{
		"id":"msg_u","type":"message","role":"assistant","model":"claude-opus-4-8",
		"stop_reason":"end_turn",
		"content":[{"type":"text","text":"ok"}],
		"usage":{"input_tokens":1234,"output_tokens":567,"cache_read_input_tokens":890,"cache_creation_input_tokens":12}
	}`)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if m.Usage.InputTokens != 1234 || m.Usage.OutputTokens != 567 ||
		m.Usage.CacheReadInputTokens != 890 || m.Usage.CacheCreationInputTokens != 12 {
		t.Fatalf("usage decode mismatch: %+v", m.Usage)
	}
}

// TestToolUseBlockDecodes is the load-bearing check for the agent loop: a
// tool_use response block must round-trip through MessageFromJSON so that
// AsAny() returns a populated ToolUseBlock with a readable Input. (A hand-built
// literal would not — AsToolUse re-decodes from the internal raw buffer.)
func TestToolUseBlockDecodes(t *testing.T) {
	m, err := MessageFromJSON(`{
		"id":"msg_t","type":"message","role":"assistant","model":"claude-opus-4-8",
		"stop_reason":"tool_use",
		"content":[{"type":"tool_use","id":"toolu_1","name":"http_request","input":{"method":"GET","path":"/.env"}}],
		"usage":{"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}
	}`)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if m.StopReason != sdk.StopReasonToolUse {
		t.Fatalf("want tool_use stop reason, got %q", m.StopReason)
	}
	if len(m.Content) != 1 {
		t.Fatalf("want 1 content block, got %d", len(m.Content))
	}
	tu, ok := m.Content[0].AsAny().(sdk.ToolUseBlock)
	if !ok {
		t.Fatalf("want ToolUseBlock, got %T", m.Content[0].AsAny())
	}
	if tu.Name != "http_request" || tu.ID != "toolu_1" {
		t.Fatalf("tool block fields wrong: name=%q id=%q", tu.Name, tu.ID)
	}
	if len(tu.Input) == 0 {
		t.Fatalf("tool Input not populated — fake construction is wrong")
	}
}
