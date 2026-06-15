# CanarySting — CISO Demo Script V2 (reframed, one screen)

> **This SUPERSEDES `DEMO_SCRIPT.md` (the Option-B dual-dashboard script).** The
> rebuild (PRs #33/#34/#35/#36/#37) made the two-box split unnecessary: one box now
> runs **observe ON** (calibrated, M live) **and** serves a fast inline verdict (the
> T1 bounded-scan fix removed the days-old-store scan bottleneck; the adapter
> bounds the inline hold), driven by a continuous traffic simulator (T2). Everything
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

## The one screen (top → bottom, the FleetWall reframe)

1. **TopBar** — scope, env, `CALIBRATED` + `BASELINE LIVE` pills (observe ON, M live). *(A `RECONNECTING` pill appears if the SSE feed goes stale — expected on tab-resume, not an error.)*
2. **FleetSafety** *(the fleet hero, FULL WIDTH)* — the structural-zero claim (giant **0** + "actioned by anything other than a decoy touch" + the "placement is careful, not infallible" caveat), a data-gated **⚠ simulated** badge, then the cumulative-reach **DISTINCT-flow funnel** (observed › decoy-touched › contained › jailed), a blast-radius line, the two-rails caption, and a subordinate per-EVENT fraction line linking to `/cost`.
3. **KernelContainment | BystanderHealth** *(side by side, EQUAL height, EACH list scrollable)* — the jailed socket cookie next to same-host workloads still serving 200.
4. **LiveSpotlight** *(FULL WIDTH, horizontally scrollable)* — the live-attacker cookie strip: a featured **● LIVE** card (cookie, verdict, score, base × M, spark) + the rest of the armed/decoy-touched flows as compact cards, with "browse all → `/flows`".

**OFF-WALL** (left **SideNav** routed pages): **Recon** (`/recon`), **Adversary Intel** (`/intel`), **Attacker Cost** (`/cost`), **Bystanders/Precision** (`/precision`), **Credibility** (`/credibility`), **Flows** (`/flows`). LiveEscalation (the old single-flow hero) and AttackerCost are **NO LONGER on the wall**.

(The attacker-arc Journey ribbon is intentionally NOT on the one screen — the arc is legible from the cumulative-reach funnel stages in FleetSafety, the featured ● LIVE card in LiveSpotlight, and the kernel jail. The `/flow/<cookie>` drill-down still has the full per-flow journey.)

The traffic simulator keeps this **alive on its own** — benign east-west fills the
observed rail of the FleetSafety funnel; the malicious archetype fleet drives the
decoy-touched › contained › jailed tail and populates the LiveSpotlight strip; the
recon scanner populates the off-wall Recon page (left rail). No scripted puppetry;
you narrate a live system.

## Pre-flight (the one-box staging recipe)

1. **Network/IP:** `curl ifconfig.me` matches the box SG `:22` CIDR; re-authorize if drifted.
2. **Engine (`cmd/staged-range`) — observe ON, M live, fast verdicts:** runs with `-observe-cgroup` (M live; the T1 bounded scan removed the days-old-store scan bottleneck so the inline verdict returns well inside the adapter's hold), `-baseline-db`, `-contain-inline`, `-demo-escalation`, `-consume -shared-spool <spool> -sim-peers-demo`, `-dashboard-tap-addr 0.0.0.0:8088`, **plus the REQUIRED `-ground-truth-registry <file> -i-am-running-a-staged-range`** (it refuses to start without them). Confirm `/raw/state` shows `calibration.Calibrated:true`, `baseline.Live:true`, **`baseline.BucketSufficient:true` for the active time bucket** (else M=1.0 regardless of the other pills, and "the baseline sharpens the score" won't be demonstrable), and `base_m > 1` on a touched flow.
3. **Traffic sim (T2):** `deploy/m7-window/sim-setup.sh` (benign + recon `.112` + malicious `.111`, %-malicious, fail-closed `$20/day` cap, live Tier-C OFF by default). Confirm `canarysting-simdriver` is active.
4. **Simulated peers (T4):** `deploy/k3-boxes/run-sim-peers.sh` → ships crossed patterns + the `.simulated` marker to the shared spool; the engine auto-discloses "simulated" on the cross-customer panel.
5. **Tunnel:** `ssh -i ~/.ssh/canarysting-dev -L 3001:127.0.0.1:3001 ubuntu@<box>` → `localhost:3001`. Keep a warm spare SSH session.
6. **Cassette fallback present:** `/tmp/m9-demo3.cassette` on the box (the $0 deterministic spine if a live run flakes).
7. **HARD RULE (whole window):** never `terraform` in `deploy/dev-box` (it manages the live M7 host); do not rotate `/etc/canarysting/anthropic.key`.

## Run-of-show (~5 min, one screen)

| beat | on screen | say |
|---|---|---|
| **0 · Observe (0:00–0:40)** | **FleetSafety** hero: a giant **0** over the cumulative-reach funnel — a huge **observed** rail narrowing to a thin **decoy-touched › contained › jailed** tail; calibrated green pills; the **⚠ simulated** badge visible. | "This has been learning normal east-west, and the headline is a zero — nothing on this fleet was actioned by anything other than a touch on a planted decoy. **Zero false positives, by construction, not by tuning.** The wide bar is everything observed; the thin tail is the flows that actually touched a decoy and got a response. And up front: the badge says simulated — this is simdriver traffic, not a live customer fleet." |
| **1 · We see the recon (0:40–1:20)** | Click **Recon** in the left rail ("watching, not acting") → anomalous non-canary flows surfaced, none actioned. | "We *do* see scanning in the negative space and identities the baseline has never seen — we surface every one and take **no action**: none touched a decoy, so none armed a response. That gap — everything observed vs the thin slice actioned — is the zero-FP guarantee made visible." |
| **2 · The trigger is a decoy touch (1:20–2:00)** | In **FleetSafety** the **decoy-touched › contained** stages tick up; in the Row-4 **LiveSpotlight** the featured **● LIVE** card shows the live score and **base × M** (M>1, observe ON). | "The instant a flow touches a decoy it's evidence — watch the funnel's decoy-touched/contained stages move and the featured live card light up. The base-times-M means the learned baseline is live and **SHARPENS** the score — it never triggers. Response arms automatically, in the kernel, on that one socket cookie. *(Full M / baseline-novelty proof is on the Credibility page in the rail.)*" |
| **3 · THE WOW — flow-precise jail (2:00–2:55)** | **KernelContainment** (jailed cookie, scrollable) **beside BystanderHealth** (same-host workloads still serving 200, scrollable), equal height, one eye-span. | "We dropped exactly one socket in the kernel, by its cookie. Same host, real workloads — **still 200, untouched** by the response. We contain the flow, not the host, not the IP, not the service. **No non-armed flow was actioned** — and that's not a tuning number, it's the architecture." |
| **4 · Reached zero real data (2:55–3:35)** | Back on **FleetSafety**: the **jailed** stage holds; the subordinate per-event line at the bottom links to `/cost`. *(Open Attacker Cost in the rail only if a technical buyer asks for economics.)* | "It reached **zero real data** — credentials and hosts that don't exist — and it cost real time and money to get nothing. The headline stays the alarm and the precision, not the dollars; the per-event response fraction links to the full cost page. *(Economics live on the Attacker Cost page in the rail — see the appendix.)*" |
| **5 · The compounding moat (3:35–4:30)** | Click **Adversary Intel** in the left rail → the cross-customer panel: "consuming N patterns confirmed by ≥3 deployments — **⚠ simulated peer data**"; then a terminal `cat` of one crossed pattern (opaque id + 7 coarse fields). | "Every interaction becomes an anonymized fingerprint; confirmed across enough deployments it crosses the network. **Straight up — the badge says it — these peers are simulated: synthetic deployments we operate, the art of the possible, not real customers yet.** Here's the wire: seven coarse fields, no traffic, no credentials, by construction. We'd like you to be one of the first real ones." |
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
| Cross-customer panel doesn't say "simulated" | the `.simulated` marker is missing/unread — re-run `run-sim-peers.sh` (writes the marker) **and restart `staged-range`** (the marker is read at startup only, not polled), or restart it with `-sim-peers-demo`. NEVER demo the panel without the disclosure. |
| CISO presses on deployment risk | § FAIL_OPEN.md — fail-open at Tier 1, fail-closed at Tier 3, bounded inline hold; the proof is the unit tests, cited there. |

## Appendix — economic attrition (only if asked)

The Tier-2 attrition (poison_field over a tarpit) imposes real time + token cost and feeds a fabricated, internally-consistent environment. It **fully bleeds unsophisticated/automated attackers** (they don't detect it) and **delays + denies + intel's** sophisticated ones. It is a bonus, not the headline: a capable attacker detects the *provably-safe* (= provably-fake) decoys fast, so do not pitch "we bleed every attacker." Open the **Attacker Cost** page (`/cost`, left rail) — the by-mechanism cost breakdown + the engagement contest — only if a technical buyer asks for the economics.

## Teardown

`set-demo-posture.sh default` (if used) · stop the sim units · revert the dashboard drop-in/`-m7` pair (see `DASHBOARD_WIRING.md`) · `terraform -chdir=deploy/k3-boxes/terraform destroy` (k3 boxes only) · leave the M7 learning window running.
