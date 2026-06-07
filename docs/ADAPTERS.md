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

## Implementation status (M4 — Envoy adapter, local half)

The Envoy ext_proc adapter is implemented in pure Go (`adapters/envoy`); the
kernel socket-cookie resolver is the on-box half (sockops eBPF + `bpf/loader`),
still to land. The full local stack passes `make check` (go 1.22).

**ext_proc, one stream per request.** `Adapter.Process` (the `ExternalProcessor`
gRPC server) handles the request-headers phase (M4 uses `body_mode: NONE`,
`response: SKIP`) and CONTINUEs every other phase. Per request it: maps the path
to a candidate `seeder.Location` (a non-deciding transform), builds the
host-canonical 4-tuple from the `source.address`/`destination.address` ext_proc
attributes, resolves the socket cookie via a `CookieResolver` (with a bounded
re-lookup that absorbs the establish-vs-first-byte race), and calls
`signal.Builder.Build`. The three sentinels drive the branch: `ErrNoPlacement` →
not a canary, CONTINUE (the common path, no engine round-trip); `ErrNoSocketCookie`
→ unattributable, CONTINUE observe-only (never enforce); `nil` → a real touch.

**Inline vs async.** `Config.Inline=false` (default) fires the signal and CONTINUEs
— the kernel (M5) enforces; Tiers 0-1 are trivially never on the hot path.
`Config.Inline=true` holds a canary-touched request for the verdict and acts at the
proxy: Tier 0/1 → CONTINUE (+ a `canarysting` dynamic-metadata suspicious tag at
T1); Tier 2/3 async → CONTINUE (kernel enforces); Tier 2 inline → 429; Tier 3
inline → 403. Per-tier inline fail behavior is a contract-typed `FailPolicy`
injected at the composition root (fail-open T1, fail-closed T3) so the adapter
imports no engine; on a Submit error the tier is unknown, so the conservative
inline posture (fail-closed) applies.

**Attrition seam (M6):** the `Attritor` injection point exists; M4 ships the seam,
not the live streamed-deception pump (the exit bar needs a real verdict). It flips
on with a composition-root change (M5/M9).

**Out-of-process.** The adapter speaks only to `contract.Engine`; in the demo that
is a gRPC client (`api/enginegrpc`) to a separate engine process (`cmd/engine
-grpc-addr`). `cmd/envoy-selfcheck` proves the whole local path end-to-end against
a real in-process engine + a `FakeResolver`, and gates CI.

**Dependency note:** the ext_proc protos live in the *separately-versioned*
`github.com/envoyproxy/go-control-plane/envoy` submodule (not the root module);
`v1.32.4` is the newest that holds the repo on go 1.22 and is wire-compatible with
a newer patched Envoy binary in the demo.
