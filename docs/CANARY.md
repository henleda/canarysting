# docs/CANARY.md — Canary layer guidance

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` first. This governs `internal/canary/` and informs the adapters that emit canary-interaction signals.

The Canary layer is the detection surface. It generates decoy objects, places them within reach of east-west traffic, and ensures every interaction becomes a signal event on the contract. It carries **no scoring or decision logic** — that is the engine's job.

## Subpackages

- `catalog/` — the canary object types and their seed intent-strength weights.
- `seeder/` — placement of canaries into reach of traffic, and freshness.

## The catalog (`catalog/`)

A canary type is a kind of decoy: a fake secret, a fake cloud bucket, planted credentials, a decoy file, a fake internal endpoint, etc. Each type has:
- An identifier (stable; used as the key the engine weights against).
- A generator that produces realistic, harmless instances.
- A **seed intent-strength weight** — a prior, not a learned value.

The seed weight encodes intuition that some decoys signal stronger intent when touched (planted credentials > a fake bucket listing). This is a **cold-start prior only.** The engine's calibration overrides it with learned, per-scope weights once the evidence floor is met (see `docs/ENGINE.md`). Do not hardcode the seed ordering anywhere the engine reads weights — the engine owns the live weight; the catalog only provides the starting prior.

Canaries must be **harmless.** A canary is bait that produces nothing of value when touched. It never grants real access, never holds real data, never enables a real action. Generators must be unable to produce a functional credential or a real secret.

### IP caution (freedom-to-operate)

Do **not** build the catalog around chained decoy credentials where canary A's purpose is to hand out credentials that unlock canary B in a fixed enumerated chain. A granted patent covers that specific mechanism (see `docs/ARCHITECTURE.md` §11). The depth-of-interaction model does not need it: score independent canaries by count and weight instead. Keep canaries independent.

## The seeder (`seeder/`)

- Places canaries where east-west traffic can reach them, per the active mode:
  - **Minefield (passive):** broad seeding across the environment. Any flow may encounter a canary.
  - **Active deception (targeted):** richer canary surface fed to a flow the engine has already tagged suspicious.
- **Freshness is the seeder's job.** Stale or obviously-fake decoys lose value and were a major reason earlier deception products failed. Rotate and refresh placements as the environment changes. Automate it; do not require operators to hand-maintain decoys.
- Placement is **scope-aware.** Canaries and the events they produce belong to exactly one scope (see `docs/SCOPE.md`).

## Signal emission

When a flow interacts with a canary, an interaction event must reach the engine over the contract (`internal/contract/`). The event carries:
- The canary type identifier (so the engine can weight it).
- The flow identity, including the **socket cookie** (the L7↔kernel join key — see `docs/IDENTITY.md`).
- The scope key (or enough to resolve it).
- A timestamp (the engine windows on it).

The adapter is what physically observes the interaction at the proxy and emits the event; the canary layer defines what a valid event is and what a canary is.

## What the canary layer must never do

- Score, tier, or decide. It emits signals; the engine decides.
- Produce a functional credential, a real secret, or anything that grants real access.
- Build a fixed chained-credential decoy graph (IP caution above).
- Emit an event without a resolvable scope and a socket cookie.

## Baseline-informed placement

When a per-scope baseline exists (see `TECHNICAL_ARCHITECTURE.md`), the seeder uses it to place canaries in the **negative space** of normal traffic — paths, ports, and workload adjacencies that legitimate flows never traverse. A canary in the negative space has an even lower false-positive rate by construction: benign traffic does not go there, so a touch is almost certainly hostile. The seeder also places decoys near the paths an attacker performing lateral movement would plausibly probe. Placement remains scope-aware. The baseline informs WHERE bait goes; it never decides whether a flow is stung — only a canary touch does that.

**Layering note:** the seeder MUST NOT import `internal/engine`. The M7 negative-space planner receives the baseline-derived hint from the composition root as a `internal/contract` value (engine → contract → seeder), never by reading the engine directly. See `internal/canary/seeder/planner.go`.

## Implementation status (M3)

The canary layer is implemented and tested in `internal/canary/` (ROADMAP M3):

- **catalog** — the five types with stable ids, seed-weight priors, generators, and a per-type `Harmless` predicate:

  | Type (id) | Seed weight | Generator | Provably harmless because |
  |---|---|---|---|
  | `planted_credential` | 1.8 | AWS `~/.aws/credentials` stanza | id/secret are in the AWS-documented EXAMPLE namespace (authenticate to nothing) |
  | `fake_secret` | 1.5 | inert PEM key or unsigned JWT | a real key parses → fails `isInertPrivateKey`; JWT is `alg:none` + empty signature |
  | `decoy_file` | 1.2 | `.env` honeyfile | EXAMPLE keys + all hosts in RFC 2606 reserved domains |
  | `fake_bucket` | 1.1 | S3 `ListBucketResult` XML | owner id `000000000000`, reserved endpoint host, no presigned signature |
  | `fake_endpoint` | 1.0 | internal service locator | host is an RFC 2606 reserved domain or RFC 5737/3849 reserved IP |

  Seed weights are cold-start **priors** (ordered by intent strength), exported only via `SeedWeights()` and fed once into `calibration.Config.SeedWeights`. Harmlessness is enforced three ways: a per-type predicate, a construction-time check in `catalog.New` (an unsafe entry never registers), and a fail-closed gate in `Catalog.Generate`. A universal `crossScan` runs on every check (no live AWS key / parseable-or-encrypted private key / routable host can be smuggled regardless of type). Generators are pure and concurrency-safe.
- **seeder** — scope-keyed `MemRegistry`, `BroadPlanner` (the M7 negative-space seam; explicit no-op default), Minefield vs Active density, and automated jittered freshness/rotation (`RunAutoRefresh`) — contents rotate in place, preserving per-type cardinality.
- **signal** — `Builder` is the only sanctioned path from an observed touch to a `contract.SignalEvent`, with three guards (no scope / no socket cookie / no placement) and never a partial event.

Independence (ARCH §11) is structural: the placement registry is flat with no inter-placement reference field. The canary layer and the engine do not import each other (import-graph tests both directions). The eBPF-fed real placement locations and the live negative-space planner arrive with M4/M7.
