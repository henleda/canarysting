# Fail-Open & Blast Radius — the deployment-risk answer

The objection that turns a curious CISO into a "no" has nothing to do with the
demo: *"You want me to put an inline ext_proc filter and a kernel packet-dropper
on my production east-west path — from a small team. What happens when it fails?"*
Here is the answer, and where it's proven in code.

## 1. Inline fail behavior is per-tier — and conservative by default

The adapter's failure policy (CLAUDE.md Rule 6) is **fail-open where a mistake
would hurt, fail-closed only where it's safe**:

| Tier | meaning | on engine failure / timeout | why |
|---|---|---|---|
| 0 Observe / 1 Tag | never blocks | **fail-open (CONTINUE)** | Tiers 0–1 are non-blocking by design — a tag is not enforcement. |
| 2 Contain | attrition | **fail-open by default** (operator-configurable) | a contain mistake should not drop traffic unless the operator opts in. |
| 3 Jail | kernel drop | **fail-closed** (operator-configurable) | the most conservative inline posture for a confirmed multi-touch attacker. |

This table is the ADAPTER's inline `FailPolicy` (`adapters/envoy/policy.go`) — what
the proxy does on a *canary touch* when the engine is unreachable/slow. It is the
authoritative answer to "what happens to a request when the engine is down,"
because the proxy is the thing in the request path. (Note: the engine's own
`tiers.DefaultConfig` independently defaults Tier-2 fail-CLOSED — a different,
internal decision point; the adapter policy above is what governs the live request.)

**Proven, not asserted:** `adapters/envoy/policy_test.go::TestFailPolicyDefault`
(adapter: T0/T1 fail-open, T2 fail-open by default, T3 fail-closed) and
`TestFailPolicyConfigurable` (the operator can flip T2/T3). The fail-closed path
for a **Tier-3** inline timeout is pinned by
`adapter_test.go::TestProcessInlineTimeoutFailsClosed`.

Crucially: **only a canary touch ever reaches the inline decision at all.** Every
non-canary request CONTINUEs immediately with **no engine round-trip** (the common
path) — so a slow or dead engine cannot affect legitimate traffic, which never
consults it.

## 2. Bounded latency — the inline hold can't run long

An inline canary-touch hold is bounded by `InlineTimeout` (the adapter's
configured ceiling). On exceed, it takes the per-tier fail policy above — it never
hangs the request. So the worst-case added latency on the *only* requests that
consult the engine (canary touches — which legitimate workloads never make) is
`InlineTimeout`, and on legitimate traffic it is **zero** (no round-trip). The T1
bounded-scan fix (`persist.RangeEventsRecent`) keeps the **per-scope event-log
scan** sub-second even on a days-old store (that unbounded scan was the prior
bottleneck), so the verdict returns well inside the hold and `InlineTimeout` is a
backstop, not the norm.

## 3. Default async — the kernel enforces, the proxy doesn't block

The recommended posture is **async**: the adapter fires the signal and CONTINUEs;
the eBPF layer enforces a jail in the kernel by socket cookie. In async mode Tiers
0–1 are trivially never on the hot path, and the request path never waits on the
engine at all. Inline is an operator opt-in for those who want the proxy to hold.

## 4. eBPF blast radius + the sev-1 / bus-factor story

- The kernel programs (`bpf/enforce/`) are minimal, **verifier-checked**, and
  scoped to drop **by socket cookie** — never by host/IP/service. A bug drops, at
  most, the specific cookies it was told to; it cannot take down a host.
- **On program-load failure the system fails OPEN** — no enforcement, the proxy
  CONTINUEs; you lose protection, not traffic.
- **Containment is precise by attribution:** the engine refuses to act on any flow
  it cannot attribute by socket cookie / cgroup / PID (CLAUDE.md safety rules), so
  there is no "act on a guess" path.
- **Operational:** units are `Restart=always`; the enforcement layer has a kill
  switch (stop the adapter/engine → enforcement stops, traffic flows). The honest
  answer on bus-factor for a small team shipping kernel code: start **async + Tier-3
  fail-open** in a pilot, watch the precision funnel ("0 legitimate flows actioned")
  accumulate, and only tighten to fail-closed once the team trusts it — the posture
  is the operator's dial, not our default.

## On-box chaos verification (what to run in a pilot)

1. **Kill the engine mid-traffic** → legitimate east-west keeps flowing (fail-open;
   it never consulted the engine) and a Tier-3 canary touch fails **closed** (the
   conservative inline posture). 
2. **Pressure the box** → confirm the inline hold stays bounded by `InlineTimeout`
   (legit p99 unaffected — legit traffic has no round-trip).
3. **Unload the eBPF program** → enforcement stops, the proxy CONTINUEs (fail-open),
   no traffic dropped.

These are the operator-side proofs; the per-tier *logic* is locked by the unit
tests cited in §1.
