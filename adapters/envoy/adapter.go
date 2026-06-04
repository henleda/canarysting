// Package envoy is the thin Envoy adapter. It observes canary interactions and
// the socket cookie, emits signal events on the contract, and applies verdicts
// (ext_proc/ext_authz inline; dynamic metadata async). It contains NO scoring
// or decision logic and must not import internal/engine. See docs/ADAPTERS.md.
package envoy

import "github.com/canarysting/canarysting/internal/contract"

// Adapter bridges Envoy to the engine via the contract.
type Adapter struct {
	Engine contract.Engine // talk to the contract, never the concrete engine
}

// TODO: ext_proc/ext_authz integration; stamp socket cookie on every event;
// honor per-tier fail behavior (fail-open T1, fail-closed T3).
