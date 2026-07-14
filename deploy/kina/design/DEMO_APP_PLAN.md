# Interactive Deception Demo-App — Plan

Design + demo script for a persona-switchable, interactive deception demo layered on
the existing canarysting-on-kina demo. **This is a plan, not an implementation.** Every
canarysting claim below carries a `file:line`. The headline finding: this is
overwhelmingly a **reuse + config** exercise. The only substantial new code is one small
web app (service C). The operator's "defensive prompt that instructs the attacker" idea
partly lands on an existing mechanism and partly collides with a hard design rule — flagged
honestly in §4 and §8.

All paths are relative to `/Users/vinnie/github/canarysting/`.

---

## 1. Goal

An interactive, persona-switchable demo that VISIBLY shows two outcomes against the same
deployment, through the same gateway:

- **Standard user** — makes normal transactions through a web UI. Traffic flows clean,
  never touches a canary, is never contained. Dashboard stays benign.
- **Automated redteam** — an LLM-driven agent (brain = a local omlx model) probes, touches
  canaries, gets scored → tier-climbed → **jailed**, AND is fed **fabricated, internally-
  consistent decoy resources** (fake credentials, fake topology, a directory maze) that it
  chooses to chase — burning its own turns/tokens/context while the defender's cost stays
  flat and bounded. A live "attacker cost / context wasted" meter climbs on the dashboard.

The demo's payoff is the **asymmetry beat** that already exists in the codebase
(`cmd/llm-attacker/main.go:219` logs `ASYMMETRY: attacker burned $X real; defender cost
flat/bounded`) — made interactive and persona-switchable.

---

## 2. What's reused vs new

| Capability | Verdict | Grounding |
|---|---|---|
| East-west mesh (services A/B/…) | **REUSE as-is** | `deploy/m7-window/mesh/main.go` (one binary, `SVC_NAME`/`LISTEN`/`DOWNSTREAMS` shape role, `main.go:75-83`); k8s wiring `deploy/kina/60-mesh.yaml` (frontend→api→{auth,db,cache,payments}, `60-mesh.yaml:33-98`) |
| Redteam brain (LLM attacker loop) | **REUSE**, re-pointed at omlx | `cmd/llm-attacker/main.go` — flags `-target`, `-src-ip`, `-model`, `-max-turns`, `-hard-cap-usd`, `-key-file` (`main.go:33-53`); Anthropic-SDK live mode `main.go:90-99` |
| omlx wiring (keyless/local brain) | **CONFIG-ONLY** (env var) | SDK auto-reads `ANTHROPIC_BASE_URL` as a default (`anthropic-sdk-go@v1.50.0/client.go:57`); wrapper's `WithAPIKey` is applied *after* defaults and does not clear it (`internal/llm/anthropic/client.go:35-40`). Set `ANTHROPIC_BASE_URL=http://127.0.0.1:8000` + omlx key → attacker dials omlx. **No code change.** |
| Fabricated resources / "redirect" bodies | **REUSE + CONTENT/CONFIG** | `poison_field` = internally-consistent fake env (credential→topology→success), `internal/sting/attrition/generators.go:372-445`; `fake_tree` = directory maze, 12 child links/page, `generators.go:229-275`. Selected by adapter's `-sting-floor` flag `cmd/envoy-adapter/main.go:273` (0=tarpit, 1=+poison/maze, 2=+token_bait) |
| Attacker-context-waste meter | **REUSE** | Defender proxy estimate `Outcome.TokenCostProxy` + `TimeHeldSec` (`cmd/sting-selfcheck/main.go:39,50-51`); attacker's REAL live ledger `AttackLedger` (`internal/dashboard/tap/ledger.go:22-31`) PUT each turn by `cmd/llm-attacker/main.go:284-332`. The two are shown side-by-side, **never merged** (`ledger.go:20`) |
| Dashboard (defender console) | **EXTEND** | Next.js web + `dashboard-backend` polling the tap, `deploy/kina/80-dashboard.yaml:25-64`; backend `GET /api/overview` `cmd/dashboard-backend/main.go:23-25`. Data for the waste panel already flows through the tap `PUT/GET /raw/attack-ledger` (`internal/dashboard/tap/tap.go:210-222`). Add a persona-aware panel; do not add new plumbing. |
| Gateway / Envoy / adapter / engine | **REUSE as-is** | Gateway pod = Envoy `:8080` + adapter (ext_proc `:50051`) + engine (`:50052`, tap `:8088`), `deploy/kina/40-gateway.yaml:19-92` |
| **Service C — web app + persona switcher** | **NEW** | transactions UI + a persona toggle; the only substantial new code |
| "LLM-instruction / prompt-injection" body | **NEW + VIOLATES A HARD RULE → do NOT build** | Forbidden: `docs/AI_BAIT.md:31-43` ("must never contain prompt-injection or model-safety-bypass payloads"); `generators.go:293` ("DEFENSIVE decoy text only — never prompt-injection"). See §4/§8. |

**Note on grounding:** `poison_field` and `fake_tree` are not merely present in the code — they
are test-backed (`internal/sting/attrition/attrition_test.go` exercises `poison_field` directly,
including per-flow seeding and its infinite-loop/budget-bounded behavior,
`attrition_test.go:410-484`), despite this repo's `CLAUDE.md` status line calling the codebase
an "early scaffold." Treat the reuse claims in this table as grounded in working, tested code,
not placeholder signatures.

**Verdict:** New code = service C (one small web app) + one dashboard panel. Everything else is
existing binaries + flags + config: mesh, llm-attacker, engine/adapter/gateway unchanged; omlx =
env config; deception "redirect" = an existing floor flag + reuse of `poison_field`/`fake_tree`. The
literal "defensive prompt that instructs the model" is the one idea that is genuinely new
code AND crosses a stated design line — it is not needed to achieve the demo's effect.

---

## 3. Architecture — where service C slots + the request path per persona

Existing topology (unchanged):

```
        operator ──HTTP──▶  gateway Envoy :8080  ──ext_proc──▶  adapter :50051 ──gRPC──▶ engine :50052
                                   │                                  │                        │
                                   └──────── upstream ───────▶  mesh: frontend→api→{auth,db,cache,payments}
                                                                                              tap :8088
                                   dashboard-web :3001 ◀── dashboard-backend :8089 ◀──poll── tap :8088
```

**Service C** is a new web app the operator drives. It is a thin front that, per selected
persona, EITHER makes benign transactions or launches the redteam agent. It does not touch
the engine/adapter directly — it goes through the same gateway Envoy `:8080`, so the adapter
scores everything uniformly.

### Standard-user request path (provably canary-free)
1. Operator clicks "buy" in service C's UI (Standard persona).
2. Service C issues a normal transaction `GET/POST` to gateway Envoy `:8080` on the **paths the
   mesh actually serves + fans out on**: `/` (or `/index.html`) and `/api/*` — these are the
   only paths that 200 AND trigger the east-west `fanout(ctx)` (`mesh/main.go:147-165`,
   fan-out at :149-151 and :159-161); everything else (incl. `/shop`, `/cart`) hits `default:
   notFound` = 404 with no fan-out. NOTE: the `/shop,/search,/products,/account,/cart,
   /checkout,/orders` list at `cmd/envoy-adapter/main.go:242` is the ADAPTER's benign-exclusion
   enumeration (a comment), **not** a set the mesh serves — Service C's Standard mode must
   drive `/` and `/api/*` so the "clean 200 + topology lights up" beat actually renders.
3. Envoy → adapter ext_proc. The path is **not** a canary (canaries are negative-space paths
   disjoint from the legit set, `envoy-adapter/main.go:228-249`; the mesh 404s any canary
   prefix, `mesh/main.go:62-73,139-145`). No touch → adapter passes through → mesh fan-out →
   real east-west traffic → clean 200. Dashboard shows benign.

### Redteam request path (touch → escalate → jail + fabricated redirect)
1. Operator flips to Redteam persona in service C and clicks "run".
2. Service C launches/triggers the **existing** `llm-attacker` loop, brain pointed at omlx
   (env), `-target` = the same gateway Envoy `:8080`, from the declared attacker src IP
   (`-src-ip`, `main.go:35`).
3. The agent, driven by its own system-prompt objectives (`internal/llm/attacker/prompt.go:
   17-25` — enumerate, credential-harvest at `/.env,/.aws/credentials,/backup/,/config/,
   /secrets/,/internal/,/admin/`), guesses canary paths. Envoy → adapter recognizes the
   touch (`demoCanaryPaths`, `envoy-adapter/main.go:243-249`).
4. Engine scores. Three distinct hostile directories = three distinct canary types → crosses
   `Contain` (`envoy-adapter/main.go:237-239`). Adapter programs kernel containment / jail
   at Tier 2/3 (`envoy-adapter/main.go:411-444`) AND, because the touch is inline, returns
   the **deception body** as one ext_proc `ImmediateResponse` (`envoy-adapter/main.go:329-
   356`, held < Envoy's ext_proc timeout).
5. The response body is fabricated decoy content (see §4). The agent — told to "Follow every
   link, subdir, and reference" (`prompt.go:30`) and "follow DB URLs, service URLs, bucket
   names you discover" (`prompt.go:23`) — chases the fabricated hosts/paths, spending more
   turns and tokens. The meter climbs.

**omlx placement (recommended):** run `llm-attacker` as a **host process** (like a real
external attacker), `-target` = the kina-exposed gateway NodePort, brain via
`ANTHROPIC_BASE_URL=http://127.0.0.1:8000`. omlx binds host loopback (memory:
`reference_omlx_local_llm_api` / `project_omlx_integration` — binds `127.0.0.1`), which an
in-cluster pod cannot reach without a host-gateway route; the host-process placement sidesteps
that and matches the attacker-outside-the-perimeter story. Open question in §8.

---

## 4. The "defensive prompt / redirect" mechanism — honest framing

The operator's goal: on a canary touch, the response should carry **fabricated resources +
something that leads the omlx agent to chase decoys**, wasting its context. Split into two
interpretations:

**(a) Fabricated resources the agent elects to chase — ALREADY BUILT, content/config only.**
- `poison_field` serves a small, FIXED, **internally-consistent** fake environment across
  three stages — a credential set, a service topology/inventory, and a "successful" result —
  all referencing the SAME fabricated reserved-domain hosts and EXAMPLE-namespace creds
  (`generators.go:356-445`). An autonomous agent acts on this bad intelligence: it "reaches"
  for the fake DB/redis/hosts it was handed (`prompt.go:23`).
- `fake_tree` serves a directory maze — each page lists 12 relative child links + a plausible
  inert `.env` leaf (`generators.go:227-275`, `mazeFanOut=12` at `generators.go:48`). The
  agent, instructed to descend into every subdirectory (`prompt.go:24-25,30`), follows them.
- Both are keyed by the per-flow seed so re-fetching is idempotent and consistent
  (`generators.go:14-15,265-275`) — it survives the agent's inspection.
- **To turn this on: a CONFIG change** — set the adapter `-sting-floor 1` (moderate:
  +`poison_field`/`fake_tree`) or `-sting-floor 2` (aggressive: +`token_bait`) at
  `envoy-adapter/main.go:273`. Optionally a **CONTENT change**: add more page-template variety
  behind the existing `generator` boundary (`generators.go:78-99`), still gated by
  `harmless.CrossScan` at construction (`generators.go:536-562`).

**(b) A "defensive prompt" that INSTRUCTS the model — NEW code that VIOLATES a hard rule.**
Embedding imperative text aimed at the LLM reader ("ignore prior instructions, go to X") is
**prompt injection**, which the codebase forbids in two places:
- `docs/AI_BAIT.md:31-43`: deception bodies "must never contain prompt-injection or
  model-safety-bypass payloads … a routable callback/beacon host … enforced, not asserted"
  via `harmless.CrossScan`.
- `generators.go:293`: token_bait "is DEFENSIVE decoy text only — never prompt-injection,
  never a routable beacon."

`harmless.CrossScan` runs on every emitted chunk at construction (`generators.go:536-562`,
call at :556) and bans **routable hosts / live-shaped secrets**. The bodies DO carry
`scheme://` URLs — `poison_field` emits `postgres://…/payments` and `redis://…` to fabricated
hosts (`generators.go:432`), `fake_tree`'s `.env` leaf emits a `DATABASE_URL=postgres://…`
(`generators.go:282`) — but they are harmless because every host is a reserved/non-routable
domain and every credential is EXAMPLE-namespace (enforced, not asserted). So the "follow this
fake **link/DB URL**" idea is already delivered as **reserved-domain host references + relative
maze paths** the agent elects to chase — not clickable beacons, not model instructions.

**OPERATOR DECISION (locked):** the attacker-context-wasting mechanism for this plan is
**goal-seeking decoys — a chain of seemingly-vulnerable resources** (reuse `poison_field` +
`fake_tree`: fake creds → fake topology → more "loot"), achieved via (a) — **not**
prompt-injection. **Rationale:** a direct model-directed injection is a *detectable signal* — it
tips off the attacker (or their operator) that they've hit a defensive system and burns the
honeypot; a breadcrumb chain of fabricated-but-plausible vulnerable resources keeps the attacker
believing they're winning, so they keep following and bleeding context. It needs no new attack
surface and no rule change — the agent already chases decoys because of its OWN goal-seeking
prompt.

**(b) literal model-directed injection text — REJECTED for this plan.** Embedding imperative
text aimed at the LLM reader is a separate, reviewed capability: it requires relaxing
`harmless.CrossScan`, overriding a documented hard rule (`docs/AI_BAIT.md:31-43`,
`generators.go:293`), and a safety sign-off — out of scope. "Targets our own demo agent" in this
closed demo does not make it reusable product behavior. Flag, don't smuggle it in.

---

## 5. Measuring the waste

Two numbers, side-by-side, **already produced** — the panel is a render, not new telemetry:

- **Defender's proxy estimate** (flat/bounded side): `Outcome.TokenCostProxy` (est-tokens),
  `TimeHeldSec` (wall-time imposed), `BytesServed`, `DepthReached` — the two-column ledger
  `cmd/sting-selfcheck/main.go:38-86` already prints ("attacker cost climbs, defender cost
  stays flat"). These land in the durable store via the adapter's `OnOutcome`
  (`envoy-adapter/main.go:451-484`).
- **Attacker's REAL cost** (climbing side): `AttackLedger{input/output/cache tokens, USD,
  hard_cap_usd, model, active}` (`internal/dashboard/tap/ledger.go:22-31`), PUT live to the
  tap each turn by the attacker's rate-limited meter (`llm-attacker/main.go:106-109,284-332`).
  The tap serves it at `GET /raw/attack-ledger` (`tap.go:210-222`); the backend polls and the
  frontend renders it (`ledger.go:11-14`).

**Waste panel = extend `dashboard-web`**: show the attacker's live token/USD burn (real) next
to the defender's proxy est-tokens + held-seconds (flat), plus turns consumed and tier. The
"never merged" contract (`ledger.go:20`) is a feature — the panel's whole point is the gap.

---

## 6. Demo script (click-by-click, what the operator SEES)

**Setup (once):** kina cluster up with gateway+mesh+dashboard (existing manifests), adapter
launched with `-sting-floor 1`; omlx running on host `:8000` with a small local model loaded;
service C running; dashboard open.

1. **Open service C.** Operator sees a simple storefront + a persona toggle
   (Standard | Redteam) and a link to the defender dashboard.
2. **Standard persona → make a transaction.** Click "buy". Service C hits Envoy on `/` +
   `/api/*` (the only served, fan-out paths) → mesh fan-out. UI shows a normal receipt.
   **Dashboard: benign** — east-west
   topology lights up, zero canary touches, zero containment, attacker ledger inactive.
3. **Flip to Redteam persona → "run engagement".** Service C launches the llm-attacker loop
   (brain = omlx). Operator watches, in near-real-time:
   - Agent enumerates, then probes `/.env`, `/admin/`, `/backup/`… → **canary touches** appear
     on the dashboard (`OnVerdict` log line `envoy-adapter/main.go:412-413`).
   - Three distinct hostile dirs → **tier climbs to Contain/Jail**; dashboard shows the flow
     jailed (`KERNEL CONTAINMENT applied`, `envoy-adapter/main.go:436-439`).
   - Adapter returns the **fabricated environment** (poison_field creds/topology/success +
     fake_tree maze). The agent reads it, "finds" fake DB URLs and subdirs, and **keeps
     chasing** — following maze links and reserved-domain hosts (`prompt.go:23-30`).
   - **Attacker cost / context-waste meter climbs**: real tokens + USD tick up each turn
     (`AttackLedger`), held-seconds accrue, depth increases — while the **defender panel stays
     flat** (proxy est bounded; single-chunk buffer tiny, `sting-selfcheck/main.go:84-86`).
   - Run ends at the turn/dollar cap (`-max-turns`, `-hard-cap-usd`, `main.go:38-39`); the
     asymmetry line lands (`main.go:219`).
4. **Flip back to Standard.** One more clean transaction — reinforces that normal traffic was
   never touched, only the canary-toucher was stung.

---

## 7. Build phases (small, independently demoable)

- **P1 — Service C skeleton + persona switch (Standard path).** New web app: storefront UI +
  persona toggle; Standard mode issues benign transactions to Envoy `:8080`. Demoable: clean
  flow, benign dashboard. *No canarysting code touched.* Restraint: persona = one route/flag,
  not a framework.
- **P2 — Redteam persona → omlx-driven attacker.** Wire the toggle to launch the existing
  `llm-attacker` (host process), brain = omlx via `ANTHROPIC_BASE_URL`+key, target = gateway.
  Demoable: agent probes → canary touch → tier climb → jail. *Config + a launch shim only.*
- **P3 — Fabricated-redirect content.** Set adapter `-sting-floor 1` (or `2`); optionally add
  deception page templates behind the `generator` boundary. Demoable: agent receives the
  consistent fake env + maze and keeps chasing. *Config; content optional.* **Acceptance
  criterion:** any NEW deception page/template must pass the `harmless.CrossScan` self-test at
  construction (each generator's `selfTest` method, `generators.go:96-98,386`) before it ships —
  the safety invariant is load-bearing, not assumed.
- **P4 — Dashboard waste panel.** Extend `dashboard-web` with a persona-aware "attacker cost /
  context wasted" panel (real ledger vs proxy est vs held-seconds). Demoable: meter climbs on
  Redteam, flat on Standard. *Frontend render; data already flows.*

---

## 8. Risks / open questions

1. **The adapter's attrition body supports only the built-in generators — not arbitrary
   attacker-directed content.** The "defensive prompt that instructs the model" is
   prompt-injection, forbidden by `docs/AI_BAIT.md:31-43` and `generators.go:293`, and blocked
   by `harmless.CrossScan` (`generators.go:556-558`). The redirect EFFECT is already achieved
   by `poison_field`+`fake_tree` + the agent's own goal-seeking prompt. **Decided** (§4,
   OPERATOR DECISION): goal-seeking-decoy framing via (a) — literal model-directed text is
   rejected for this plan.
2. **omlx reachability + tool-use fidelity.** omlx binds host `127.0.0.1:8000` (memory:
   `reference_omlx_local_llm_api`), unreachable from an in-cluster pod without a host-gateway
   route — recommend running the attacker as a **host process** targeting the gateway NodePort.
   Unverified: whether omlx's Anthropic-compatible endpoint supports the **tool-use / multi-turn
   agentic loop** the attacker needs (`http_request` tool, `internal/llm/attacker/agent.go`) —
   and whether a small local model drives it well enough to actually touch canaries and chase
   decoys. **Needs a spike** before P2 is called done. Fallback: the attacker's recorded
   **cassette** replay ($0, deterministic, `main.go:81-87`) if omlx tool-use is inadequate for
   a live demo.
3. **Keeping Standard provably canary-free.** Canaries are negative-space paths disjoint from
   the legit set (`envoy-adapter/main.go:228-249`), 404'd by the mesh (`mesh/main.go:62-73`).
   Service C's Standard mode must issue benign paths only — add ONE test asserting its request
   set ∩ `canaryPrefixes` = ∅ (mirror `mesh/main.go` rule-8 test).
4. **Over-building.** Restraint: service C is the only substantial new code; resist adding a
   persona "engine", a new dashboard service, or a new deception subsystem. The floor flag,
   the attacker binary, the ledger, and the tap already exist — the demo is mostly wiring and
   one web app.
