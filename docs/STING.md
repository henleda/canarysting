# docs/STING.md — Sting layer guidance

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` first. This governs `internal/sting/` and the eBPF enforcement it drives (`bpf/`).

Sting is the response. It takes a tier verdict from the engine and acts on the offending flow. It splits into two intents that share mechanisms but differ in purpose.

## Subpackages

- `containment/` — stop egress, hold the actor. Kernel-enforced.
- `attrition/` — impose economic cost. Tarpit, adversarial responses, token-burning.

## Containment (`containment/`)

Goal: prevent exfiltration and lateral progress.
- Mechanisms: rate-limit, hard egress deny, jail the socket or cgroup.
- Enforced in the **kernel** via eBPF (`bpf/enforce/`), driven by the Go loader (`bpf/loader/`).
- High-confidence, **fail-closed at Tier 3.**
- **Precision is mandatory.** Containment acts only on a flow attributable by socket cookie / cgroup / PID (see `docs/IDENTITY.md`). A jailed bystander is a critical failure. If attribution is uncertain, do not contain.
- Containment at Tier 2 is the gentler form (rate-limit / tarpit-by-throttle) so the actor stays unaware; Tier 3 is hard deny / jail.

## Attrition (`attrition/`)

Goal: raise the attacker's cost per operation. This is the platform's differentiator.
- Mechanisms: tarpitting (slow responses to a crawl), serving plausible-but-endless fake resources, deep fake directory trees, recursive fake structures, and bait crafted to trigger expensive parsing — all aimed at making an automated or LLM-driven attacker burn time, compute, and tokens.
- **Can begin at Tier 2.** Attrition-stinging a false positive is cheap (a slightly slower response to one legitimate flow), unlike containment-stinging a false positive. So attrition tolerates a more permissive strictness setting than containment.

### Aggressive by brand, elective by deployment

- The platform **ships the aggressive ceiling** — that is the brand. But the operator chooses the **floor**:
  - **Passive:** slow responses / tarpit only.
  - **Moderate:** serve plausible fake resources that keep a crawler looping.
  - **Aggressive:** full adversarial — deep recursive fake structures, token-maximizing bait.
- **The default floor is conservative.** Code must never make an aggressive response the silent default. The aggressive level is reached only by explicit operator configuration.

### The sting must bound its own cost

Attrition burns the *attacker's* compute. It must not burn the *defender's*. Every fake-resource generator needs:
- A hard ceiling on generated size / depth / duration per flow.
- A global resource budget so a flood of suspicious flows cannot exhaust the host.
- A kill switch the operator and the engine can trip.
Treat unbounded generation as a bug, not a feature.

## Driven by the verdict, attributed by socket cookie

- Sting actions key off the engine's tier verdict delivered over the contract.
- Every action is attributed to the offending flow by socket cookie / cgroup / PID. Sting never acts on a flow it cannot attribute.
- Kernel enforcement is independent of which proxy fired the original signal.

## eBPF (`bpf/`)

- `bpf/enforce/` holds the eBPF C programs (TC / cgroup hooks) that do rate-limit, drop, redirect. Keep the C minimal — only what must run in-kernel.
- `bpf/loader/` is Go (cilium/ebpf): loads programs, manages maps, pushes per-flow verdict state keyed by socket cookie, reads counters back.
- The map schema (keyed by socket cookie) is the contract between the loader and the kernel programs. Changing it is deliberate and reviewed.

## Implementation status (M6 — attrition)

`internal/sting/attrition` is implemented (M6, the differentiator). Containment is
still deferred to M5 (it is kernel-enforced and cannot run on macOS). Attrition is
pure Go, developed and tested locally.

**Pull-based stream, delay-as-data.** Attrition is a stream, not a one-shot
`Respond`: a driver calls `Stream.Next`, writes `Chunk.Data`, waits `Chunk.Delay`
on its OWN timer, and repeats. Delay is data — attrition never sleeps and never
spawns a goroutine, so it does O(1) work per chunk and structurally cannot burn
the defender. The same `Stream` interface is driven by the local scripted-attacker
harness today and by the real Envoy adapter (chunked transfer-encoding +
`http.Flusher`) at M4, with zero attrition changes.

- `Chunk{Data, Delay}` — bytes to flush now, then how long the driver waits.
- `Stream.Next(ctx) (Chunk, DoneReason, error)` / `Outcome()` / `Close()`.
- `Attritor.Open(verdict) Stream` — binds floor + budget at construction, never per
  call; `Governor()` exposes the kill switch + counters.

**Three generators, each provably bounded by an iterative depth counter (never
recursion, so attrition can never become its own zip-bomb victim):**
- `tarpit` (floor passive) — slow-drip inert filler; cost is duration.
- `fake_tree` (floor moderate) — deterministic link-back directory/config maze;
  `mazeNode(seed,path)` is a pure function so re-fetching a path is idempotent
  (defeats crawler dedup), keyed by the per-flow seed (from the socket cookie).
- `token_bait` (floor aggressive) — token-maximizing, parser-hostile bait
  (multi-byte Unicode byte-fallback + BPE-merge-breaking + bounded nested JSON).
  Defensive decoy text only — never prompt-injection or a beacon. See
  `docs/AI_BAIT.md` for the FTO framing; the novelty is isolated behind this one
  generator and the `FloorAggressive` gate.

**Bounds.** Per-flow `Budget` (`MaxBytesPerFlow`, `MaxDepth`, `MaxDuration`) under
a shared host-wide `Governor` (atomic byte ceiling + concurrent-stream cap + kill
switch). A zero/missing budget field normalizes to the conservative cap, never to
unbounded. Every emitted chunk passes `harmless.CrossScan` — the same shared
safety predicates the canary catalog uses — proven over samples at construction
(`New` errors / `Default` panics on a non-harmless or unbounded generator).

**Aggressive is never the silent default**, enforced three structurally-independent
ways: (1) `FloorPassive` is the zero value, so an unset config is passive; (2)
generators above the floor are not even *constructed* (`token_bait` only at
`FloorAggressive`); (3) generator selection is `min(tierIntensity, floorMax)` with
no `default` arm that lands on a higher generator, so no Tier value alone raises
the floor.

**The attacker-cost meter** (`Outcome`) maps its cost fields (mechanism, time
held, bytes served, requests absorbed, est. tokens, depth reached) onto
`intelligence.StingOutcome`, copied at the composition root — attrition imports
neither intelligence nor engine (enforced by an import-graph test). `Outcome.Reason`
is attrition-internal control flow (why the stream ended), recorded by D1 as event
metadata rather than on `StingOutcome`. This is what feeds the D1 event store and
the D3 attacker-cost KPI.

**Verification.** A scripted-attacker test suite proves the exit bar locally: the
cost meter climbs while per-chunk defender allocations stay flat (a benchmark
asserts O(1) allocs/op). `cmd/sting-selfcheck` prints the attacker-vs-defender
ledger (the demo beat-4 numbers) and exits non-zero on any invariant violation, so
it doubles as a CI gate.

## What the sting layer must never do

- Make an aggressive attrition level the silent default.
- Generate fake resources without a ceiling and a global budget.
- Act on a flow it cannot attribute by socket cookie / cgroup / PID.
- Reach back into the attacker's own systems. Attrition imposes cost on traffic *inside your perimeter that is touching things it never should* — it is not outbound retaliation / hack-back.
- Contain at Tier 3 in fail-open mode (Tier 3 is fail-closed).
