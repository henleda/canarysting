# docs/STING.md — Sting layer guidance

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` first. This governs `internal/sting/` and the eBPF enforcement it drives (`bpf/`).

Sting is the response. It takes a tier verdict from the engine and acts on the offending flow. It has two intents: **containment** (stop the actor) and **attrition** (impose cost). Attrition is multi-dimensional: it imposes cost across five axes, not one. This matters because the attacker may be running metered API inference, self-hosted open-weight models, or stolen compute, and a single-axis "burn their tokens" approach only bites the first case. The five-axis model imposes cost that lands regardless of how the attacker is hosted.

## Subpackages

- `containment/` — stop egress, hold the actor. Kernel-enforced. The floor under everything else.
- `attrition/` — impose multi-dimensional cost. The platform's differentiator.

## Containment (`containment/`)

Goal: prevent exfiltration and lateral progress.
- Mechanisms: rate-limit, hard egress deny, jail the socket or cgroup.
- Enforced in the **kernel** via eBPF (`bpf/enforce/`), driven by the Go loader (`bpf/loader/`).
- High-confidence, **fail-closed at Tier 3.**
- **Precision is mandatory.** Containment acts only on a flow attributable by socket cookie / cgroup / PID (see `docs/IDENTITY.md`). A jailed bystander is a critical failure. If attribution is uncertain, do not contain.
- Containment at Tier 2 is the gentler form (rate-limit / tarpit-by-throttle) so the actor stays unaware; Tier 3 is hard deny / jail.

### Implementation status (M5 — containment)

Implemented and proven on the box. `bpf/enforce/enforce.bpf.c` holds ONE
`LRU_HASH` `verdict_map` keyed by the `__u64` socket cookie → `{action, drop
counters, token-bucket}`, with two programs sharing it: `cgroup_skb/egress`
(`enforce_egress`: hard-deny/jail → DROP; rate-limit → per-cookie token-bucket
throttle) and `cgroup/sock_release` (`enforce_release`: delete the entry on socket
close — the dedicated, strictly-map-owned lifecycle, so a stale jail can never
outlive its socket). The datapath is **fail-OPEN by construction**: cookie 0 →
PASS, map-miss → PASS, only an explicitly-programmed deny/jail drops; the verdict
path stays fail-closed at Tier 3.

`bpf/loader` is the `Loader` contract (a `KernelLoader` over cilium/ebpf on Linux,
a `NoopLoader` elsewhere). `internal/sting/containment` is pure-Go over that
interface: `ActionForTier` (Tier 2 → rate-limit, Tier 3 → jail), refuses cookie 0,
`Release` to de-escalate. It is driven from the composition root
(`cmd/envoy-adapter`) via the adapter's `OnVerdict` hook for **async** Tier 2/3
only (inline tiers were actioned at the proxy) — so the thin adapter imports no
cilium/ebpf or containment (the import-graph guard holds). Enforcement keys on the
**same** socket cookie the M4 sockops bridge resolves.

Scope: **egress-only** jail (drops the offending socket's outbound bytes — stops
exfil / Envoy's responses to the attacker); an ingress-hold is a documented
follow-on (`skb->sk` is frequently NULL on cgroup ingress). The in-kernel Tier-2
rate-limit ships now; the L7 token-wasting attrition (M6) is the other, richer
Tier-2 response. Proven by a root oracle (`bpf/enforce/loader_linux_test.go`:
jail-precise + bystander-untouched, fail-open, cookie-0-refused, close-delete,
throttle-not-jail) and the `deploy/m5-demo` end-to-end run.

## Attrition (`attrition/`)

Goal: raise the attacker's cost per operation across five axes. This is the platform's differentiator. The framing is **opportunity cost on a velocity-dependent adversary**, not "make them pay a cloud bill." An autonomous attacker's edge is speed and scale; every axis below attacks that edge and lands whether the attacker's inference is metered, self-hosted, or running on stolen compute.

The five axes, with the first three carrying the most weight:

### 1. Velocity disruption (highlighted)

Attack the speed advantage directly. Tarpit at the protocol and application layer: hold connections open, drip-feed bytes, slow-roll responses so each interaction costs seconds or minutes instead of milliseconds. Adaptive latency that increases the more a flow probes, so persistence is punished. Velocity is the AI attacker's whole advantage; injecting latency and dead ends is self-hosting-proof because it costs the attacker wall-clock time no matter who owns the GPU.

### 2. Information poisoning (highlighted)

Degrade the quality of the attacker's model of reality. Serve plausible-but-false environmental state: fake credentials, fabricated internal hostnames, bogus network topology, decoy secrets that look real, fake "successful" results. The cost is not compute; it is that the agent acts on bad intelligence — pivots toward controlled environments, exfiltrates fabricated data, burns real exploits against targets that do not exist, makes decisions that lead deeper into the deception. This is uniquely devastating to autonomous agents, which lack the human intuition to sense the environment is wrong, and it composes directly with the intelligence layer: the same fabricated environment that misleads the attacker generates the adversary-interaction data the platform monetizes (see `docs/INTELLIGENCE.md`). Treat this as the core differentiated mechanism.

### 3. Opportunity-cost injection (highlighted)

Consume the attacker's finite capacity. A self-hosted attacker has a fixed token-per-second ceiling on a fixed GPU fleet; every cycle spent parsing a fake directory tree or reasoning about bogus state is a cycle not spent on a real target. This subsumes the original "token-burning" mechanism (deep fake directory trees, recursive structures, bait crafted to trigger expensive parsing) but frames it correctly: the cost imposed is opportunity cost on constrained capacity, which lands against metered, self-hosted, and stolen-compute attackers alike. Against a metered attacker it is also a direct dollar cost; do not lead with that, since it is the weakest framing.

### 4. Exploit-inventory burn

Make decoys attractive enough that the attacker spends real exploits on them. Exploits and novel chains have real cost — developed, sometimes purchased, and burned once revealed. A fresh exploit fired at a fake service is both intelligence (the platform learns it) and a forced choice for the attacker: reveal it or waste it. This cost is independent of compute entirely.

### 5. Operational exposure

When a flow is confirmed hostile, raise the attacker's operational risk: force infrastructure to reveal itself (callbacks to controlled endpoints), fingerprint the tooling, capture command-and-control patterns. This feeds the intelligence asset and imposes attribution/opsec cost, which a sophisticated actor values highly. Independent of how the attacker is hosted.

### Mechanisms map to the engine tiers

- **Can begin at Tier 2.** Attrition-stinging a false positive is cheap (a slightly slower response, or a fake credential served to one legitimate flow), unlike containment-stinging a false positive. So attrition tolerates a more permissive strictness setting than containment.
- Velocity disruption and information poisoning are the natural Tier 2 actions (low error cost, stay-unaware). Opportunity-cost injection and exploit-inventory baiting escalate at Tier 2→3. Operational exposure is a Tier 3 action on a confirmed-hostile flow.

### Aggressive by brand, elective by deployment

- The platform **ships the aggressive ceiling** — that is the brand. But the operator chooses the **floor**:
  - **Passive:** velocity disruption only (slow responses / tarpit).
  - **Moderate:** add information poisoning and fake resources that keep the attacker looping on false state.
  - **Aggressive:** full adversarial — opportunity-cost injection, exploit-baiting, and operational-exposure actions on confirmed-hostile flows.
- **The default floor is conservative.** Code must never make an aggressive response the silent default. The aggressive level is reached only by explicit operator configuration.

### The engagement contest (design consideration)

Every attrition axis depends on keeping the attacker engaged long enough for the cost to be meaningful, and a capable attacker will try to detect deception and disengage cheaply. The real engineering contest is keeping the agent engaged and believing longer than it takes to detect the trap. Design fake state and responses to be internally consistent and plausible under an agent's inspection, and measure time-to-disengage as a core attrition metric. This is an open research area, not a solved one (see `docs/INTELLIGENCE.md` profiling, which sharpens the bait over time).

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
