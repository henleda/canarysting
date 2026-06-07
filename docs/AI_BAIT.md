# docs/AI_BAIT.md — token-maximizing bait: scope, FTO framing, and the isolation seam

Read `docs/STING.md` and `CLAUDE.md` first. This governs the `token_bait` generator
in `internal/sting/attrition` (`generators.go`). It exists because token-bait is
both the sharpest part of the differentiator and the most freedom-to-operate (FTO)
sensitive, so we keep it deliberately isolated and deliberately framed.

## What token_bait is

Content engineered to be **cheap for us to generate (bytes)** but **expensive for
an LLM/automated parser to consume (tokens / parse work)**, served only at the
operator-selected `FloorAggressive` and only at Tier 3:

- **Multi-byte Unicode runs** drawn from a fixed adversarial rune set, chosen so a
  tokenizer falls back to per-byte tokens (inflating the token-to-byte ratio).
- **BPE-merge-breaking separators** (zero-width spaces) inserted between runs so
  adjacent text cannot merge into single tokens.
- **Bounded-depth nested JSON** that looks like plausible config/secrets and is
  token-dense and parse-expensive — built **iteratively** with an explicit depth
  counter capped at `MaxDepth`, so the structure is parser-hostile to the attacker
  but provably bounded for us (we never recurse, never materialize the imposed
  cost, never become our own billion-laughs victim).

The asymmetry it creates: **our** cost is the emitted bytes (bounded by the per-flow
`Budget` and the host-wide `Governor`); the **attacker's** cost is `tokens × model
price`. `Outcome.TokenCostProxy` reports an honest, documented lower-bound estimate
over emitted bytes; pricing (tokens → dollars) is D3's job, so attrition never
over-claims.

## What it is NOT (hard line — `docs/STING.md`)

token_bait is **defensive decoy text only**. It is parser-hostile, not
weaponized. It must never contain:

- prompt-injection or model-safety-bypass payloads,
- a routable callback/beacon host or any outbound locator,
- a live-shaped secret or a real credential.

This is enforced, not asserted: every emitted blob passes `harmless.CrossScan`
(no routable host, no live-shaped AWS key, no parseable/encrypted PEM), proven
over samples at construction. Attrition imposes cost on traffic **inside the
perimeter that is touching things it never should** — it is not outbound
retaliation / hack-back.

## FTO framing (why the novelty is the system, not the bait)

Token-maximizing / adversarial-tokenization content as a standalone idea sits in
**dense prior art** (AI-maze tools — Cloudflare AI Labyrinth, Nepenthes, Iocaine,
Quixotic, Spigot; adversarial-tokenization research; zip-bomb-style amplification).
A patent claim framed narrowly around "token bait" is weak and exposed.

The defensible, novel combination CanarySting practices is the **integrated
pipeline**, none of which the prior art couples:

1. a **canary touch is the only trigger** (a learned baseline never triggers a
   sting on its own — `docs/BASELINE_MULTIPLIER.md`), so the bait is served only to
   flows that touched a decoy in the negative space;
2. an engine **tier verdict** drives it, **attributed to the exact flow** by socket
   cookie (`docs/IDENTITY.md`);
3. it runs under a **provably-bounded per-flow + host-wide budget** with a kill
   switch (the defender's cost is flat by construction);
4. the cost is **metered and fed into a compounding intelligence asset**
   (`docs/INTELLIGENCE.md` — the attacker-cost KPI, the adversary profile).

Frame the provisional patent around that integrated, bounded, attributed,
canary-triggered system — not around token-bait per se. (See `INTELLIGENCE.md` §6,
which routes the future learned bait model — Model 2 — to its own review.)

## The isolation seam

So the FTO-sensitive part is contained and replaceable:

- token_bait lives behind a single `generator` boundary (`tokenBait` in
  `generators.go`) and the `FloorAggressive` construction gate — it is not even
  built below that floor.
- It shares the same bounding + harmlessness machinery as the other generators, so
  removing or swapping it changes nothing else.
- A future **learned** bait model (Model 2, `INTELLIGENCE.md` §6) slots in behind
  the same boundary and is gated on its own FTO review before shipping. The current
  generator is a **fixed, deterministic** construction — no learned component — which
  is the conservative starting point.
