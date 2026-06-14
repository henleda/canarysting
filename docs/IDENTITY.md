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

## One cookie, three touchpoints (M4 + M5, on-box proven)

The same 8-byte cookie is observed at three points with **no second join**:
1. **Capture (M4, `bpf/sockops`)** — a `sockops` program captures the cookie for the
   accepted downstream socket on `PASSIVE_ESTABLISHED`, keyed by the 4-tuple, so the
   Envoy adapter (which has the tuple from ext_proc but not the cookie) can resolve
   it. A MISS means unattributable → observe-only, never enforce.
2. **Verdict (`internal/contract`)** — the resolved cookie rides
   `Verdict.Flow.SocketCookie` across the contract.
3. **Enforce (M5, `bpf/enforce`)** — `enforce_egress` reads the cookie directly via
   `bpf_get_socket_cookie(skb)` on the offending socket's **egress** and looks it up
   in the verdict map. Enforcement is egress-only: on cgroup **ingress** `skb->sk` is
   frequently NULL (cookie 0 → unattributable → PASS), so an ingress-hold is a
   deliberate follow-on; egress (dropping the socket's outbound bytes) stops exfil
   and is reliably attributable. The cookie is per-socket and host-local — capture
   and enforcement are node-local (K8s inherits this per ROADMAP §7).

## Staleness guard (the real generation, not a stub)

The `flow_cookies` LRU map is keyed by the 4-tuple, so a **missed `TCP_CLOSE` plus a
reused ephemeral port** can leave a stale entry that resolves a NEW (possibly
legitimate) connection to the OLD connection's cookie until the new
`PASSIVE_ESTABLISHED` capture overwrites it. Acting on that resolution misattributes
a verdict. Delete-on-close is best-effort (a belt); the generation is the suspenders.

The guard has two halves:

1. **Kernel half (`bpf/sockops/sockops.bpf.c`).** Each `PASSIVE_ESTABLISHED` capture
   stamps a **real, monotonic, host-global `generation`** (from the `gen_seq` array
   map) into `flow_val` — replacing the previous hardcoded `1`. A fresh capture for a
   reused tuple therefore always carries a strictly higher generation than any stale
   entry, giving userspace a freshness ordinal it can compare.
2. **Userspace half (`adapters/envoy/identity.StaleGuardResolver`).** A pure-Go
   decorator over the `CookieResolver` that hands a resolution to enforcement only if
   it can confirm the entry is the CURRENT capture: it re-reads the tuple and refuses
   (returns a MISS → unattributable → never enforce) if the entry vanished, changed
   cookie, advanced its generation between the reads, or carries a zero generation (no
   ordinal to confirm against — the fail-safe default). A refuse-to-jail is always
   preferable to a possibly-misattributed jail (fail safe on uncertainty). The
   composition root (`cmd/envoy-adapter`) wraps the real `MapResolver` in this guard.

Why this is enough rather than re-keying enforcement: the enforce path
(`enforce_egress`) reads the live socket's cookie **directly** and Linux socket
cookies are monotonic and never reused, so a stale cookie programmed into the verdict
map is usually inert. The guard protects the *attribution* itself — scoring,
evidence, the operator's view, and any future ingress-hold enforcement that does not
read the cookie live.

## Lifting containment (de-escalation, false-positive, operator clear)

Programming a jail is only half a lifecycle; a Tier-3 jail that is never lifted is its
own failure. The verdict→enforce seam in `cmd/envoy-adapter` reconciles kernel state
to the LATEST async verdict for a flow:

- **De-escalation:** a later async verdict that drops below `TierContain` calls
  `enforcer.Release` (idempotent), so a flow that fell back to Tier 0/1 does not stay
  jailed.
- **False positive:** a `FeedbackLabel{WasMalicious:false}` releases the flow
  (`releaseVerdictForLabel`); a confirmed-malicious label leaves containment in place.
- **Operator clear:** `operatorClear(cookie)` is the on-demand seam to lift one
  attributed flow; it refuses cookie 0 (the full CLI/RPC surface can come later).

The kernel `enforce_release` (delete-on-close) remains the backstop, but it is no
longer the *only* thing that frees a jail.

## What identity handling must never do

- Enforce against a flow with no socket cookie.
- Bridge L7 and kernel identity by anything other than the socket cookie.
- Use per-flow blocking with only coarse (cgroup/PID) attribution.
- Hand a resolution to enforcement without confirming it is the current capture for
  the tuple (the staleness guard).
