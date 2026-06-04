// Package nginx is the thin nginx adapter (njs/Lua + auth-subrequest). Same
// contract as Envoy; nginx's thinner flow-state primitives mean more glue here,
// but the engine stays unchanged. No scoring or decision logic. See
// docs/ADAPTERS.md.
package nginx

import "github.com/canarysting/canarysting/internal/contract"

// Adapter bridges nginx to the engine via the contract.
type Adapter struct {
	Engine contract.Engine
}

// TODO: njs/Lua glue + auth subrequest; stamp socket cookie on every event.
