# docs/IDENTITY.md — Identity join guidance

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` first. This governs how a flow is identified consistently across the L7 (proxy) and kernel (eBPF) boundary. It constrains `adapters/`, `bpf/loader/`, `internal/sting/`, and any engine code that attributes a verdict to a flow for enforcement.

## The problem

A verdict is computed with L7 context (the proxy sees mTLS SPIFFE ID, headers, JWT, request semantics). Enforcement for async mode and containment happens in the kernel (eBPF sees socket cookie, cgroup, netns, PID). These two layers do not share an identity unless we give them one. Without a shared key, a verdict from one layer cannot enforce in the other — and a mis-attributed verdict means jailing a bystander.

## The join key: socket cookie

**The socket cookie is the join key.** Both an Envoy/nginx adapter and an eBPF program at the cgroup/TC hook can observe the socket cookie for the *same* connection. It is stable for the life of the socket and available on both sides on Linux.

Rules:
- Every canary-interaction signal and every verdict carries the socket cookie.
- The kernel enforcement map (`bpf/enforce/` ↔ `bpf/loader/`) is keyed by socket cookie.
- Containment and async attrition attribute the offending flow by socket cookie (falling back to cgroup / PID where the action is naturally coarser, e.g. cgroup-wide throttling).
- **Do not invent a second join mechanism.** No correlating by L7 logs, timing, or heuristics across the boundary. If the socket cookie is unavailable for a flow, treat the flow as unattributable and do not enforce against it.

## Precision requirement

Because enforcement can jail a flow, attribution must be exact:
- If a flow cannot be attributed by socket cookie / cgroup / PID, **do not contain it.** A jailed legitimate flow is a critical failure.
- Coarser attribution (cgroup, PID) is acceptable only for actions that are intentionally coarse and where the blast radius is understood. Per-flow blocking must use the socket cookie.

## Where each piece lives

- Adapters (`adapters/`) observe the socket cookie at the proxy and stamp it onto interaction events and the flow identity on the contract.
- `bpf/loader/` programs the kernel map keyed by socket cookie and reads counters back.
- `internal/sting/` consumes verdicts that already carry the socket cookie; it never re-derives identity.
- `internal/contract/` defines the flow-identity type that carries the socket cookie alongside L7 identity.

## What identity handling must never do

- Enforce against a flow with no socket cookie.
- Bridge L7 and kernel identity by anything other than the socket cookie.
- Use per-flow blocking with only coarse (cgroup/PID) attribution.
