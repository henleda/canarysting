# CanarySting — CISO Demo Script V2 (reframed, one screen)

> **This SUPERSEDES `DEMO_SCRIPT.md` (the Option-B dual-dashboard script).** The
> rebuild (PRs #33/#34/#35/#36/#37) made the two-box split unnecessary: one box now
> runs **observe ON** (calibrated, M live) **and** serves sub-second verdicts (the
> bounded-scan fix, T1), driven by a continuous traffic simulator (T2). Everything
> below is **one box, one screen.**

## The wedge (north star — lead with this, in these words)

> **"A zero-false-positive-by-construction east-west tripwire you can safely
> auto-respond on — that contains the flow, not the host."**

DETECT (only a decoy touch arms a response — no anomaly classifier, zero FP *by
construction*, Rule 8) → safe-DENY (eBPF kernel jail, socket-cookie precise) →
"reached zero real data" → INTEL (anonymized cross-customer fingerprint). The
economic-attrition / "burn their compute" story is a **bonus appendix** (§ Appendix),
never the headline — a capable attacker detects a *safe* deception, so the bleed
only fully lands on dumb scanners; the durable value is the trustworthy auto-block.

## The one screen (top → bottom, the T3 reframe)

1. **TopBar** — scope, env, `CALIBRATED` + `BASELINE LIVE` pills (observe ON, M live).
2. **LiveEscalation | AttackerCost** — the acquired flow + the cost meter.
3. **KernelContainment | BystanderHealth** *(side by side — the WOW)* — the jailed socket next to same-host workloads still serving 200.
4. **Journey** — the attacker's arc (recon → contain → jail → ended).
5. **ReconLive** — "Recon — watching, not acting": anomalous-from-baseline flows that touched no decoy (we see them, we don't act).
6. **Credibility | AdversaryIntelligence** — M/baseline novelty + the cross-customer network (simulated peers, disclosed).

The traffic simulator (T2) keeps this **alive on its own** — benign east-west fills
the observed funnel, a recon scanner populates ReconLive, and a malicious flow drives
the escalation. No scripted puppetry; you narrate a live system.

## Pre-flight (the one-box staging recipe)

1. **Network/IP:** `curl ifconfig.me` matches the box SG `:22` CIDR; re-authorize if drifted.
2. **Engine — observe ON, M live, fast verdicts:** the demo-box engine runs with `-observe-cgroup` (M live; the T1 bounded scan keeps Submit sub-second), `-baseline-db`, `-contain-inline`, `-demo-escalation`, `-consume -shared-spool <spool> -sim-peers-demo`, `-dashboard-tap-addr 0.0.0.0:8088`. Confirm `/raw/state` shows `Calibrated:true`, `baseline_live:true`, and `base_m > 1`.
3. **Traffic sim (T2):** `deploy/m7-window/sim-setup.sh` (benign + recon `.112` + malicious `.111`, %-malicious, fail-closed `$20/day` cap, live Tier-C OFF by default). Confirm `canarysting-simdriver` is active.
4. **Simulated peers (T4):** `deploy/k3-boxes/run-sim-peers.sh` → ships crossed patterns + the `.simulated` marker to the shared spool; the engine auto-discloses "simulated" on the cross-customer panel.
5. **Tunnel:** `ssh -i ~/.ssh/canarysting-dev -L 3001:127.0.0.1:3001 ubuntu@<box>` → `localhost:3001`. Keep a warm spare SSH session.
6. **Cassette fallback present:** `/tmp/m9-demo3.cassette` on the box (the $0 deterministic spine if a live run flakes).
7. **HARD RULE (whole window):** never `terraform` in `deploy/dev-box` (it manages the live M7 host); do not rotate `/etc/canarysting/anthropic.key`.

## Run-of-show (~5 min, one screen)

| beat | on screen | say |
|---|---|---|
| **0 · Observe (0:00–0:40)** | The box at rest, **calibrated** (green pills), a **large observed-normal funnel**, nothing escalating. | "This has been learning normal east-west traffic, and right now it's doing nothing to anyone — that's the point. The only thing that can ever arm a response is a touch on a decoy no real workload would reach. Not anomaly, not deviation. **Zero false positives, by construction, not by tuning.**" |
| **1 · We see the recon (0:40–1:20)** | **ReconLive** lights with anomalous non-canary flows ("surfaced, not actioned"). | "We *do* see suspicious activity — scanning in the negative space, identities the baseline has never seen. Watch: we surface it, and we take **no action.** Nothing here armed a response, because none of it touched a decoy. That restraint **is** the zero-FP guarantee." |
| **2 · The trigger is a decoy touch (1:20–2:00)** | A flow touches a decoy → escalates **against live M (>1)** T0→T1→T2; attrition begins (poison_field). | "The instant it touches a decoy, it's evidence. It escalates — and notice M is live: the learned baseline *sharpens* the score, it never triggers. The response arms automatically, in the kernel, on this one socket cookie." |
| **3 · THE WOW — flow-precise jail (2:00–2:55)** | **KernelContainment** (jailed cookie) **beside BystanderHealth** (same-host workloads still serving 200), one frame. | "We dropped exactly one socket in the kernel, by its cookie. Same host, real workloads — **still 200, untouched.** We contain the flow, not the host, not the IP, not the service. Zero legitimate flows actioned. That's not a tuning number; it's the architecture." |
| **4 · Reached zero real data (2:55–3:35)** | Journey ends; AttackerCost RealMeter ($, replay or live). | "It reached **zero real data** — credentials and hosts that don't exist. And it cost it real time and money to get nothing. *(If asked about the bleed: see the appendix — but the headline is the alarm + the precision, not the dollars.)*" |
| **5 · The compounding moat (3:35–4:30)** | **AdversaryIntelligence** cross-customer: "consuming N patterns confirmed by ≥3 deployments — **⚠ simulated peer data**"; then a terminal `cat` of one crossed pattern (opaque + 7 coarse fields). | "Every interaction becomes an anonymized fingerprint. Confirmed across enough deployments, it crosses the network. **To be straight: these peers are simulated — synthetic deployments we operate, the art of the possible — not real customers yet.** Here's the wire: seven coarse fields, no traffic, no credentials, by construction. We'd like you to be one of the first real ones." |
| **6 · The ask (4:30–5:00)** | — | "Don't take my word for any of it. **Point your red team at it** — see § RED_TEAM_HARNESS. Two challenges: arm a response without touching a decoy, or jail a legitimate flow. If they can't, the zero-FP-and-precise-containment claim is yours to verify, not mine to assert." |

## Honesty card (say these; never say the others)

**SAY:**
- Zero FP is **structural** (only a decoy touch arms a response — no classifier to tune), not a rate. Pin to the code path, never a percentage.
- The baseline multiplier **sharpens** the score; it **never triggers** (Rule 8). M>1 here is real (observe ON).
- The recon surface is **observe-only** — "none has *armed* a response"; we see and choose not to act.
- The bystander panel proves **flow precision** — "the kernel dropped only the attacker's socket; these are untouched and still serving" (not a categorical "legitimate").
- Cross-customer peers are **SIMULATED** — synthetic scopes we operate, the "art of the possible," not real customers. The wire is 7 coarse fields (no raw data, Rule 9).
- If shown: the attacker is **our own declared-IP harness** (real Opus), not a captured wild attacker; a replay's dollars are real but the run is a recording.

**NEVER claim:**
- ❌ a false-positive **percentage** / any FP rate to tune.
- ❌ baseline deviation / anomaly **arms** anything.
- ❌ the bystanders are provably "legitimate" (claim *not-actioned / still-serving*).
- ❌ "**N real customers** confirmed this" — the peers are simulated; disclose it every time.
- ❌ we **fool a sophisticated attacker** — a capable attacker detects a safe deception; that's the harmlessness floor, and the win is detect+deny+intel.
- ❌ lead with the **$-bleed** — it's the appendix, bonus-vs-dumb-scanners.

## Failure runbook

| trigger | do |
|---|---|
| A live attacker run flakes / hits the cyber-safeguard refusal | fall back to the $0 cassette (`run-attack.sh --cassette /tmp/m9-demo3.cassette`); narrate it as the recording. |
| Tunnel drops / tab stale | warm-spare SSH; `curl ifconfig.me` + re-authorize `:22`; reload the tab. |
| A sim/engine process died | restart just that unit; do NOT re-run setup live (it wipes warm state). |
| Cross-customer panel doesn't say "simulated" | the `.simulated` marker is missing — re-run `run-sim-peers.sh` (it writes the marker) or add `-sim-peers-demo`. NEVER demo the panel without the disclosure. |
| CISO presses on deployment risk | § FAIL_OPEN.md — fail-open at Tier 1, fail-closed at Tier 3, bounded inline hold; the proof is the unit tests, cited there. |

## Appendix — economic attrition (only if asked)

The Tier-2 attrition (poison_field over a tarpit) imposes real time + token cost and feeds a fabricated, internally-consistent environment. It **fully bleeds unsophisticated/automated attackers** (they don't detect it) and **delays + denies + intel's** sophisticated ones. It is a bonus, not the headline: a capable attacker detects the *provably-safe* (= provably-fake) decoys fast, so do not pitch "we bleed every attacker." Show the per-axis overlapping cost bars + the RealMeter only if a technical buyer asks for the economics.

## Teardown

`set-demo-posture.sh default` (if used) · stop the sim units · revert the dashboard drop-in/`-m7` pair (see `DASHBOARD_WIRING.md`) · `terraform -chdir=deploy/k3-boxes/terraform destroy` (k3 boxes only) · leave the M7 learning window running.
