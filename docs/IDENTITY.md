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

## Staleness guard (what actually protects a bystander)

The `flow_cookies` LRU map is keyed by the 4-tuple, so a **missed `TCP_CLOSE` plus a
reused ephemeral port** can leave a stale entry that resolves a NEW (possibly
legitimate) connection to the OLD connection's cookie until the new
`PASSIVE_ESTABLISHED` capture overwrites it. Two independent properties keep that
from jailing a bystander:

1. **Enforcement keys on the LIVE, never-reused socket cookie — so a stale
   verdict-map entry is inert.** The enforce path (`enforce_egress`) reads the
   offending socket's cookie **directly** via `bpf_get_socket_cookie(skb)` and Linux
   socket cookies are monotonic and **never reused**. A cookie left over from a closed
   connection is therefore carried by **no** live socket: it cannot match a live
   flow's egress, so it cannot jail a bystander even if it lingers in the map. This is
   the primary guarantee and it holds with no extra machinery. (Delete-on-close in the
   sockops program is a best-effort tidy-up of the resolution map, not the safety
   property.)

2. **A userspace cookie-change re-read guards the ATTRIBUTION.** Attribution drives
   scoring, evidence, the operator's view, and any future ingress-hold enforcement
   that does NOT read the cookie live — so a stale *resolution* there would charge the
   wrong flow. `adapters/envoy/identity.StaleGuardResolver` is a pure-Go decorator
   over the `CookieResolver` that re-reads the tuple and hands a resolution onward
   only if the socket cookie is **the same across both reads**. If the entry vanished
   (eviction/close) or the cookie **changed** — a newer connection captured on the
   same 4-tuple, the reused-ephemeral-port churn — it returns a MISS → unattributable
   → never enforce. Because cookies are never reused, a changed cookie is unambiguous
   proof the entry churned; the comparison needs no kernel cooperation. A refuse-to-
   attribute is always preferable to a possible misattribution (fail safe on
   uncertainty). The composition root (`cmd/envoy-adapter`) wraps the real
   `MapResolver` in this guard.

The kernel `flow_val.generation` field is a **layout-only vestige** (kept so the C
value struct stays byte-for-byte identical to the bpf2go-generated `sockopsFlowVal`
and `identity.Resolution`, asserted by the sockops layout test); the committed object
does not stamp a real monotonic generation, so the guard does **not** key on it. The
socket-cookie-change comparison is the actual freshness signal.

## Lifting containment (de-escalation, false-positive, operator clear)

Programming a jail is only half a lifecycle; a Tier-3 jail that is never lifted is its
own failure. The verdict→enforce seam in `cmd/envoy-adapter` reconciles kernel state
to the LATEST async verdict for a flow:

- **De-escalation:** a later async verdict that drops below `TierContain` calls
  `enforcer.Release` (idempotent), so a flow that fell back to Tier 0/1 does not stay
  jailed.
- **False positive:** a `FeedbackLabel{WasMalicious:false}` releases the flow
  (`releaseVerdictForLabel`); a confirmed-malicious label leaves containment in place.
  Delivery: the adapter composition root wires a `feedbackReleaseSink` (implements
  `contract.FeedbackSink`) over the kernel enforcer. The feedback path / staged
  labeler calls `FeedbackSink.Label`, which Releases on a false-positive label and
  then forwards the label to the engine's calibration intake — one analyst action
  both frees the bystander (node-side, where containment is enforced) and feeds
  calibration. A full out-of-process label transport (an RPC the engine pushes labels
  over) is future work; the in-process sink closes the dead-seam gap today.
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
