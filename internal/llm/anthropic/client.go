// Package anthropic is a thin seam over the official Anthropic Go SDK.
//
// It exists so the attacker loop (internal/llm/attacker) depends on a small
// interface — Messager — rather than the concrete SDK client. That keeps the
// loop unit-testable offline against a fake (fake.go) with zero network.
//
// Import-graph rule (CLAUDE.md rule scope for internal/llm): nothing here may
// import internal/engine, internal/intelligence, internal/sting, or any
// adapter/proxy package. The attacker is conceptually the adversary; it does
// its own cost accounting and never touches the engine's stores.
package anthropic

import (
	"context"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// Messager is the one method the agent loop needs from the SDK. The real
// Client and the test FakeClient both implement it, so the loop runs with no
// network in tests.
type Messager interface {
	New(ctx context.Context, p sdk.MessageNewParams) (*sdk.Message, error)
}

// Client wraps the SDK's Messages endpoint. sdk.NewClient returns a value (not
// a pointer), so inner is held by value.
type Client struct{ inner sdk.Client }

// New builds a Client. The SDK's anthropic.NewClient() reads ANTHROPIC_API_KEY
// from the environment automatically; pass apiKey explicitly only when we
// already hold it (the -key-file path). An empty apiKey falls through to the
// env-var behavior.
func New(apiKey string) *Client {
	if apiKey == "" {
		return &Client{inner: sdk.NewClient()}
	}
	return &Client{inner: sdk.NewClient(option.WithAPIKey(apiKey))}
}

// New issues one Messages request. It satisfies Messager.
func (c *Client) New(ctx context.Context, p sdk.MessageNewParams) (*sdk.Message, error) {
	return c.inner.Messages.New(ctx, p)
}

// compile-time check that the real client satisfies the interface.
var _ Messager = (*Client)(nil)
