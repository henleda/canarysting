# docs/ADAPTERS.md — Proxy adapter guidance

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` first. This governs `adapters/`.

Adapters connect a specific proxy to CanarySting. **Envoy first, nginx second.** An adapter is *thin*: it observes canary interactions at the proxy, emits signal events on the contract, and applies verdicts the engine returns. It contains **no scoring, tiering, or decision logic.** Adding a new proxy must mean writing one adapter with zero engine changes — that property is the whole reason the engine is proxy-agnostic.

## What every adapter does

1. **Observe** interactions with canaries in the traffic it proxies, and the socket cookie for each connection (see `docs/IDENTITY.md`).
2. **Emit** interaction events on the contract (`internal/contract/`): canary type, flow identity incl. socket cookie, scope (or enough to resolve it), timestamp.
3. **Apply** verdicts:
   - Tier 0–1: no blocking; at most tag the flow / surface a richer canary surface (async).
   - Tier 2–3 inline: hold the request for the verdict and act at the proxy, *or* defer to kernel enforcement per config.
   - Tier 2–3 async: do not hold; kernel enforcement handles it.

## Envoy adapter (`adapters/envoy/`)

- Use Envoy's external processing / external authorization extension points (ext_proc / ext_authz) for inline verdicts, and dynamic metadata / access logging for async signal emission.
- Carry the engine's "suspicious" tag as flow state so downstream filters can see it.
- Inline verdicts must honor the per-tier fail behavior: fail-open at Tier 1, fail-closed at Tier 3 (see `docs/ENGINE.md`).

## nginx adapter (`adapters/nginx/`)

- Use njs / Lua (OpenResty) plus the auth-subrequest pattern for inline verdicts; emit async signals out of band.
- nginx's flow-state primitives are thinner than Envoy's; the adapter carries the glue, the engine stays unchanged.

## Hard rules

- An adapter must **not** import `internal/engine/`. It speaks only to `internal/contract/`.
- An adapter must stamp the **socket cookie** on every event (see `docs/IDENTITY.md`). No socket cookie → the flow is unattributable downstream.
- An adapter must not make a tier decision. If it ever needs to "decide" something, the contract is missing a field — raise it.
- Honor the inline/async setting and the per-tier fail behavior exactly; do not invent fallback behavior.

## What adapters must never do

- Score, tier, or calibrate.
- Import the engine or hold engine-only state.
- Emit an event without a socket cookie or a resolvable scope.
- Apply an aggressive sting on their own — the sting layer and operator config own response level.
