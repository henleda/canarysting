package anthropic

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	sdk "github.com/anthropics/anthropic-sdk-go"
)

// FakeClient is a Messager that pops pre-queued responses instead of calling
// the API. It records the params it was called with so tests can assert on the
// message history, tool wiring, and turn count. Zero network, zero cost.
//
// Each queued *sdk.Message should carry a non-zero Usage so budget-accounting
// tests are meaningful.
type FakeClient struct {
	mu sync.Mutex

	// Responses are returned in order, one per New call. When the queue is
	// empty, New returns ErrFake (the loop treats a transport error as fatal,
	// so tests should queue exactly the responses they expect to consume).
	Responses []*sdk.Message

	// Err, if set, is returned by every New call (to exercise error paths).
	Err error

	// Calls records every params passed to New, in order.
	Calls []sdk.MessageNewParams
}

// ErrFake is returned when the response queue is exhausted.
var ErrFake = fmt.Errorf("anthropic.FakeClient: response queue exhausted")

// New pops the next queued response (or returns Err if set).
func (f *FakeClient) New(_ context.Context, p sdk.MessageNewParams) (*sdk.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, p)
	if f.Err != nil {
		return nil, f.Err
	}
	if len(f.Responses) == 0 {
		return nil, ErrFake
	}
	resp := f.Responses[0]
	f.Responses = f.Responses[1:]
	return resp, nil
}

// CallCount returns how many times New was invoked.
func (f *FakeClient) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Calls)
}

// compile-time check that the fake satisfies the interface.
var _ Messager = (*FakeClient)(nil)

// MessageFromJSON builds an *sdk.Message by unmarshalling an API-shaped JSON
// document. This is the ONLY correct way to construct a fake response that the
// agent loop can read: the SDK's content-block unions (e.g. ToolUseBlock)
// re-decode from an internal raw-JSON buffer that is populated only during
// UnmarshalJSON — a hand-built struct literal leaves that buffer empty and
// AsAny()/AsToolUse() return zero values. Tests and dev harnesses use this to
// queue deterministic responses with realistic Usage and tool-use blocks.
func MessageFromJSON(doc string) (*sdk.Message, error) {
	var m sdk.Message
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		return nil, fmt.Errorf("anthropic.MessageFromJSON: %w", err)
	}
	return &m, nil
}
