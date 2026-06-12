# D6-3 Live Cross-Customer Crossing — Runbook (k=3)

The live demonstration that a confirmed-malicious **coarse pattern crosses the
egress boundary only at k≥3 distinct enrolled scopes** — rejected at k=2, crossed
at k=3 — and that a fourth, independently-calibrated deployment then **sharpens its
own detection** on the crossed pattern. Designed + adversarially safety-reviewed
2026-06-12 (verdict: SHIP_WITH_FIXES; all must-fixes folded in here).

This is a **staged range we operate end-to-end**. The honesty disclosure in
§6 is mandatory and non-optional — it is the control against overclaim.

## Topology (founder-locked 2026-06-12)

| Role | Host | Setup | Why |
|---|---|---|---|
| **scope-1/2/3 — contributors** | 3 NEW `t4g.small` (10.20.1.120/130/140) | light **cold-start** (M=1.0), Envoy + 1 backend + seeded canaries, `-contribute -scope-token <opaque> -confirm-spool …` | each independently jails the same coarse pattern and emits one confirmation. Cold-start keeps all three on the **identical 7-field coarse key** (no multiplier drift to desync them) and is fastest. |
| **consumer (box B)** | the **live M7 server** (10.20.1.24) | already **calibrated + live**; add `-consume -shared-spool <cleared-out>` (one restart; calibration re-accrues in ~8 min) | the "caught it faster" payoff is a numeric **M-lift**, which only moves on a calibrated deployment (D6j honesty gate). Reusing the genuinely-calibrated, days-old server is the most compelling **and** honest consumer — it's a real deployment, not a freshly-staged box. |
| **aggregator** | one of the new boxes (distinct inbox path) | `cmd/aggregator` with the 3-token enrolled allowlist | operator-trusted file channel (D63a/D63g); the server is **not** a contributor, so its scope-1 role is never created. |

The **live M7 learning window's contributor/scope state is never touched** — the
three contributors are all new boxes. The server is touched **only** as the
consumer (one `-consume` restart; baseline DB persists, calibration re-accrues).

## Why this needed code first (PHASE 0 — in this PR)

The D6 emit/consume paths are wired in `internal/boot/boot.go` (the emit gate, the
per-jail `SendConfirmation`, the shared-set load) but **no binary plumbed the
flags into `boot.Build`** — so every deployment would jail yet emit/consume
nothing, and the crossing is impossible. This PR adds to `cmd/staged-range`:

- `-contribute`, `-scope-token`, `-confirm-spool` (producer half)
- `-consume`, `-shared-spool` (consumer half)
- a **fail-closed guard** mirroring boot.go's emit gate: `-contribute` without both
  `-scope-token` and `-confirm-spool` (and `-consume` without `-shared-spool`)
  refuses to start, so a misconfig can't silently jail-but-emit-nothing.

Tokens are opaque 128-bit values (`openssl rand -hex 16`) — **never** the raw
ScopeKey or any hash of it (D63b).

## Runbook (PHASE 1+ — executed live, after this PR merges)

1. **Provision** — a NEW `deploy/k3-boxes/terraform` module using **read-only data
   sources** for the existing VPC/subnet/SG (modeled on `deploy/m7-window/terraform`).
   3× `t4g.small`, Ubuntu 24.04 arm64 (BTF), 20 GiB gp3, SSH from the operator IP.
   **NEVER** `terraform apply`/`destroy` in `deploy/dev-box` — its `most_recent=true`
   AMI data source would force-replace and destroy the live server.
2. **Install** per box: the rebuilt `staged-range` + `envoy-adapter`, a per-box
   `ground-truth-registry.json` (scope name = that box's boundary; attacker = that
   box's local attacker IP), a per-box `m7.env` with a **distinct** `SCOPE`,
   `SCOPE_TOKEN`, `CONFIRM_SPOOL`. Distinct `-scope-boundary` ⇒ distinct ScopeKey ⇒
   rule-5-partitioned state. **Byte-identical canary catalog + bucketer across all
   three** (or the 7-field tuple diverges and `distinctScopes` silently stays < 3).
3. **Aggregator host**: `enrolled-tokens.txt` = exactly the 3 tokens, one per line,
   `chmod 0600`, **byte-for-byte** equal to each box's `SCOPE_TOKEN` (a trailing
   space/CR is silently dropped → k never reaches 3). Empty allowlist is fatal.
4. **Drive the same pattern**: record ONE attacker cassette (a single paid run),
   then **replay it ($0, deterministic) against each box's own canaries**. Identical
   decisions + identical canaries + identical cold-start M ⇒ identical coarse key.
   **Verify a real Tier-3 verdict fired + a `confirm.ndjson` line appeared before
   any rsync** (don't assume the cassette trips the jail threshold on every box).
5. **Deliver**: rsync each box's `confirm.ndjson` to the aggregator inbox under a
   **distinct filename** (`scope-1/2/3.ndjson` — same local path on every box, so a
   single inbox name would overwrite and lose distinctness), then `cat` into the
   ingest spool.
6. **DEMO-1 — REJECT at k=2**: merge scope-1 + scope-2 only; `aggregator -once`;
   `wc -l cleared-out` ⇒ **0**, log shows sub-k, nothing crosses.
7. **DEMO-2 — CROSS at k=3**: add scope-3; re-merge; `aggregator -once`;
   `wc -l cleared-out` ⇒ **1**, log "CROSSED at k=3"; re-running does not re-send
   (dedup). Point the server (box B, `-consume -shared-spool <cleared-out>`) at the
   crossed pattern → its sharedset matches and **M lifts on a matching local flow**
   (detection context only, never a jail — rule 8 / D6h).
8. **Privacy proof**: `cat confirm.ndjson` — the `scope` field is an opaque token,
   the `pattern` is 7 coarse fields. No raw data, baseline, scope key, or reversible
   hash crosses. `ledgerVerified` gates the marshal so a producer-asserted count
   can never force a sub-k crossing.

## §6 Honesty disclosure (MANDATORY, verbatim — D63j)

State on the record, every run:

1. **Staged range** — all scopes are deployments **we** operate, **not** three customers.
2. **The identical pattern is by construction** — one recorded cassette replayed
   against each box; it is the mechanism, **not** independent corroboration of a threat.
3. **k≥3 means 3 distinct *enrolled* tokens the operator vouches for** — it proves
   the threshold is **enforced and cannot be lowered**, **NOT** Sybil-resistance (one
   operator holds all three tokens). Authenticated enrollment / per-token auth /
   rate-limiting / an inbound listener for untrusted contributors are **D7**.
4. **The crossing reaches the internal cross-customer consume surface only — NOT the
   external threat feed** (`FeedK=5` is not met by k=3).

Never narrate this as "an attacker can't fake the network" or "three customers
independently saw this." Both are material overclaims.

## Cost & teardown

~$2 total for the demo window: 3× `t4g.small` ≈ $1.21/day, one cassette recording
≈ $0.50, all crossings replay at $0. Tear down immediately after:

- `terraform -chdir=deploy/k3-boxes/terraform destroy` — removes ONLY the 3 new boxes.
  **Never** touch `deploy/dev-box`.
- Revert the server consumer: remove `-consume -shared-spool` from its unit +
  `m7.env`, `daemon-reload && restart`; then `set-demo-posture.sh default` (sequence
  so the server ends in its intended posture with one clean restart).
- Drain aggregator state: `rm` the inbox spools; `shred -u enrolled-tokens.txt`
  (D63h — do not retain token↔pattern pairs); truncate each box's `confirm.ndjson`.

## Known foot-guns (verify before the live beats)

- **Token byte-match**: `enrolled-tokens.txt` ≡ each `SCOPE_TOKEN` exactly, else the
  token is silently not counted ("scope token not enrolled") and k never reaches 3.
- **Filename collision**: rsync to distinct `scope-N.ndjson` names.
- **Coarse-key alignment**: diff canary config + bucketer across boxes; all cold-start
  M=1.0; confirm all three land on the same key before the crossing beat.
- **Tier-3 reachability**: confirm each replay actually jails (3–6 distinct touches at
  the cold-start 5.1 threshold) before relying on its confirmation.
- **In-memory ledger**: use `aggregator -once` per beat (no bbolt persistence yet; a
  long-poll crash between beats would re-cross).
