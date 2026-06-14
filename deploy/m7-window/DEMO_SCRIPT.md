# CanarySting — CISO Demo Script (click-by-click / say-by-say)

**Posture: Option B (dual-dashboard).** Beat 0 opens on the genuinely-calibrated **M7 window**;
beats 1–6 run on the **fast demo box** where the attrition actually bleeds the attacker.
~5 minutes, 7 beats.

> This file is the **authoritative run-of-show** and SUPERSEDES the storyboard table in
> `DEMO_ARC.md` wherever they conflict. The audit (2026-06-14, GO_WITH_FIXES) found the
> old storyboard still narrates the **declined `--aggressive` / first-touch / `fake_tree`**
> posture; the live wall shows a **`-demo-escalation` 3–5/6-touch climb headlined by
> `poison_field`**. Read THIS, not the old beats.

---

## 0. The two screens (set this up before the room)

| Tab | URL (after tunnel) | Shows | Used in |
|---|---|---|---|
| **CALIBRATED** | `localhost:3002` | the **M7 window** (`m7-window`): days-calibrated, green pills, the observed-normal funnel | **Beat 0 only** |
| **BLEED** | `localhost:3001` | the **demo box** (`demo-range`): the live attacker arc, RealMeter, kernel jail | **Beats 1–6** |

**One tunnel opens both:**
```bash
ssh -i ~/.ssh/canarysting-dev -L 3001:127.0.0.1:3001 -L 3002:127.0.0.1:3002 ubuntu@<server-public-ip>
```
Open **two browser tabs** — `localhost:3002` (Beat 0) and `localhost:3001` (the rest). Pre-load both.

**The honest framing for the switch (say it once, at Beat 1):** *"I'm moving to a second, freshly
stood-up deployment so we can watch the full response play out live."* Two real deployments,
same architecture — beat 0 is the calibrated one at rest, beats 1+ are the one we attack.

---

## 1. Pre-flight checklist (run T-15 min, in order)

1. **Network/IP first.** From the demo laptop: `curl ifconfig.me`. Confirm it matches the SG `:22`
   CIDR on the server **and** the demo box. If drifted (hotel/conf WiFi, VPN), re-authorize:
   `aws ec2 authorize-security-group-ingress --region us-east-1 --group-id <SG> --protocol tcp --port 22 --cidr <ip>/32`. **Every** SSH (tunnel + attacker commands) rides this.
2. **Open the tunnel** (command above). Open both tabs. Keep a **second warm SSH session** as a spare.
3. **CALIBRATED tab (`:3002`) is genuinely green.** TopBar shows `CALIBRATED · ≥50/50` and `BASELINE LIVE`,
   and the T0 funnel is large. *(If still `WARMING UP`, the window needs more uptime — see "Beat 0 fallback".)*
4. **BLEED tab (`:3001`) renders** the demo-range arc (escalation, RealMeter $0.228, jail).
5. **Demo-box stack alive** (do NOT reboot it): on the demo box `pgrep -f staged-range && pgrep -f envoy-adapter && pgrep -f mesh-frontend` (3 PIDs). Don't run anything memory-heavy on the t4g.small.
6. **Cassette present:** on the demo box `ls -la /tmp/m9-demo3.cassette`.
7. **Beat-5 wiring (the LF2 blocker):** the demo box has `/etc/canarysting/m7.env` with
   `ENVOY_TARGET=http://127.0.0.1:8080` + `TAP_ADDR=http://127.0.0.1:8088`. Confirm a **dry beat-5**
   bleeds (not 403) before the room: `./run-attack.sh --budget 0.10 --max-turns 2` on the demo box.
8. **API key (beat 5 only):** on the demo box `sudo -u ubuntu head -c1 /etc/canarysting/anthropic.key && echo OK`.
   Cassette beats (1–4) need NO key.
9. **Tape the two spine commands to the laptop** (Beat 1 + Beat 5 + Beat 6, copy-paste exact — section 4).
10. **HARD RULE for the whole window:** never `cd`/`-chdir` into `deploy/dev-box` and never run any
    terraform there — that module manages the **live M7 server**; a single apply would destroy it and
    the shared VPC (audit REV1). Don't run `set-demo-posture.sh` / `setup-consumer.sh` on the M7 server.

---

## 2. Run-of-show

### Beat 0 — Cold open: OBSERVING, and the fear named first  · `0:00–0:40` · **tab :3002 (CALIBRATED)**
- **SCREEN:** M7 window at rest. `NO ACTIVE ESCALATION — OBSERVING`. TopBar pills green
  (`CALIBRATED`, `BASELINE LIVE`). TierLadder T0 = the large observed-normal fold count. KernelContainment idle.
- **SAY:** *"This is a real deployment that's been quietly learning normal east-west traffic for
  days. Right now it's doing nothing to anyone — that's the point. Every active-response tool
  you've been pitched scares you because it auto-blocks on a guess and takes down real traffic. We
  never guess. The only thing that can ever arm a response is a touch on a decoy no real workload
  would reach — not anomaly, not deviation, not a new identity. **Zero false positives, by
  construction, not by tuning.** Watch what one AI attacker does to that."*
- **⚠ Beat 0 fallback** (if `:3002` still says `WARMING UP`): say *"this one's still calibrating —
  and it still can't false-positive, because the trigger is a decoy touch, not the baseline.
  Calibration only sharpens the score; it never gates the alarm."* (Rule 8 — true regardless.)

### Beat 1 — The trigger is a decoy touch, never an anomaly (Rule 8)  · `0:40–1:15` · **switch to tab :3001 (BLEED)**
- **DO:** start the cassette on the demo box (section 4, command ①).
- **SCREEN:** AdversaryIntelligence recon feed lights with **`recon` / `surfaced`** probes (never
  "detected"). LiveEscalation acquires one flow by cookie hex (`0x2f1a`); canary-touch chips appear;
  suspicion sparkline climbs. TierLadder T0→T1 (Tag).
- **SAY:** *(the switch line)* *"I'm moving to a second, freshly stood-up deployment so we can watch
  the response play out live. This is a **faithful replay of a real Opus attacker run** we captured
  — same moves, same real token bill, identical every time. It's pulling on decoys we planted where
  real traffic never goes. We surface that as early warning — **'recon', not 'detected'**, because a
  probe isn't yet a verdict. It's deviating from normal and we're deliberately doing nothing. The
  instant it **touches a decoy** — now it's evidence."*

### Beat 2 — Escalation to contain: attrition begins  · `1:15–2:00` · **tab :3001**
- **SCREEN:** the flow climbs T1→T2 (**around the third touch**). AttackerCost flips into the active
  inversion view; the headline mechanism is **`poison_field`** (a fabricated, internally-consistent
  fake environment) over a tarpit hold; the per-axis bars (velocity / poison / opportunity) fill with
  the "overlapping — not a partition" caption.
- **SAY:** *"There — it crossed into containment, around the third touch. I'll be straight: that
  dwell timing is a **demo-tuned band**, not the conservative product default. Now the response arms
  automatically, **in the kernel, keyed to this one socket cookie**. It's being fed a fabricated,
  internally-consistent environment and slowed on a tarpit — one move pays into several cost axes at
  once. These bars **overlap on purpose** — they're not a pie chart."*
- **⚠** Do **not** say "crossed on the first touch" (that's the declined `--aggressive`). The
  headline is **poison_field**, not "fake_tree maze."

### Beat 3 — THE WOW: kernel-jail precision — attacker dropped, bystander alive  · `2:00–2:55` · **tab :3001 + a TERMINAL**
- **SCREEN:** flow T2→T3 (**Jail**) — eBPF kernel DROP by cookie. **SPLIT SCREEN.** Left:
  KernelContainment shows this cookie Jailed (T3), score frozen. **Right (TERMINAL, not dashboard):**
  a live curl from a legit IP on the **same host** returns **200 OK**. Then click to `/precision`:
  the "**0 legitimate flows actioned**" hero.
- **DO:** the bystander curl (section 4, command ②).
- **SAY:** *"We just dropped exactly one socket in the kernel — by its cookie. Same host, a real
  workload: **still 200, never touched.** We contain the **flow**, not the host, not the IP, not the
  service. A jailed bystander would be a critical failure for us — there are none. **Zero legitimate
  flows actioned.** That's not a number we chase; it's the architecture."*
- **⚠** The bystander survival is the **terminal curl**, not a dashboard panel.

### Beat 4 — The bleed, the asymmetry, and how it ended  · `2:55–3:45` · **tab :3001 (click AttackerCost → /cost)**
- **SCREEN:** RealMeter **$0.228** climbing in **~5s steps**, real in/out/cache token breakdown.
  Below: ATTACKER "climbing ▲" vs DEFENDER "flat · bounded". Journey latest milestone:
  **"Defender-capped — we stopped it."** AdversaryIntelligence fingerprint (ordered touches + cadence).
- **SAY:** *"Every dollar on that meter is its **own Anthropic spend**, measured from the model's
  usage — **distinct from the defender-side estimate we keep separate and never merge.** It paid real
  money to read credentials that don't exist. The meter samples every few seconds, so it climbs in
  **steps**. Their cost climbs; **ours doesn't** — every fake-resource generator is ceiling-bounded.
  And it reached **zero real data.** How did it end? **We capped it** — and about **1 in 4 gave up
  before we even reached the cap.**"*
- **⚠** `$0.228` is **real but from a replay** ("the dollars are real, the run is a recording"). Lead
  with **"we capped it"** (the dominant outcome); do **not** headline "it gave up."

### Beat 5 — Prove it's live: the on-demand ~$0.50 cap  · `3:45–4:25` · **tab :3001 + a TERMINAL**
- **DO:** the **live** capped run on the **DEMO BOX** (section 4, command ③).
- **SCREEN:** SAME dashboard. RealMeter goes "REAL TOKENS BURNING" live, $ ticking up toward ~$0.50;
  TierLadder jumps to T2 fast; the run self-terminates at the cap (~30s). Terminal shows the per-turn
  `[cost]` lines + the final ledger.
- **SAY:** *"That was a recording — deterministic, rock-solid. Don't take my word for it. Here's a
  **live one, right now**: real Claude, real tokens, hard-capped. The cap is a **per-turn pre-call
  rail** — once it's crossed, no further API call fires, so it stops within one turn of the line. We
  can run this as many times as you want. **The attacker pays every time. We don't.**"*
- **⚠ (the LF2 blocker)** This MUST run on the demo box (`ENVOY_TARGET=http://127.0.0.1:8080`), never
  the slow M7 server — or you get flat 403s and zero bleed. If it flakes (403 / cyber-safeguard
  refusal / key error): **skip it, pivot to the cassette** ("here's a deterministic recording of
  exactly that, $0.228 real Opus spend"). Never claim the cap lands exactly on $0.50.

### Beat 6 — The compounding moat: LIVE cross-customer crossing  · `4:25–5:00` · **a TERMINAL**
- **DO:** the k=3 crossing (section 4, command ④): `run-crossing.sh pull` → `k2` (rejected, 0 lines)
  → `k3` (CROSSED, 1 line) → `cat` the wire.
- **SCREEN/TERMINAL:** `pull` (3 boxes' confirmations) → `k2` → **0 cleared lines (REJECTED)** → `k3`
  → **"pattern CROSSED at k=3 distinct enrolled scopes"** → 1 line. Then `cat` a confirmation: an
  **opaque token + 7 coarse fields**, nothing else.
- **SAY:** *"Everything that attacker did also became intelligence — a coarse, anonymized behavioral
  fingerprint. Watch: two deployments confirm this pattern and the network shares **nothing** — the
  gate holds. A third confirms, and now it crosses, **exactly once.** Here's the wire: an opaque
  token and seven coarse fields — no traffic, no credentials, no environment, by construction. To be
  straight: these are **three scopes we operate, not three of your peers**, and it proves the
  **threshold is enforced** — an attacker that bled in three places gets recognized, while a single
  forged report can't poison the network. What you saw bleed, and what you saw cross, were both real.
  We'd like you as a **design partner.**"*
- **⚠** Never say "three customers independently saw this." The crossing reaches the **internal
  consume surface**, not an external feed (that's roadmap, `FeedK=5` unmet).

---

## 3. Honesty card (trust signals — say them; never say the others)

**SAY (out loud, at the relevant beat):**
- This is our **own declared-IP attacker harness** (real Opus 4.8) against a known range — not a captured wild attacker.
- The spine (beats 1–4) is a **faithful replay** of a real run: **dollars real, run recorded.** Prove it live in beat 5.
- **Zero false positives is structural, not a rate** — only a decoy touch arms a response; there's no anomaly classifier, so no FP rate to tune (Rule 8). Pin to "zero by construction; here's the code path," never a percentage.
- The escalation is a **demo-tuned dwell band** (`-demo-escalation`: tag@1 / contain@~3 / jail@~5), **not** the conservative product default.
- **Tier-2 headline = `poison_field`** over a tarpit; only **velocity (tarpit) + maze + poison** fire during the bleed — the jail-tier axes (token/exploit/op-exposure) light **only at the jail**. "Tarpit + poison during the bleed, the rest at the jail."
- A capable AI attacker **will detect a safe deception — and that's the harmlessness floor working**: EXAMPLE-namespace keys, reserved TLDs/IPs, the tarpit/429 signature are provably-fake by construction; we never ship real-looking secrets. The win is **DETECT → DELAY+DENY → INTEL**, not "we fool it forever."
- The **two cost numbers are never merged**: `real_attack_cost` (the attacker's own usage, real $) vs `tokens_burned` (a demoted defender-side estimate).
- The live `$0.50` cap is a **per-turn pre-call cap** — stops within one turn of the line, not exactly on $0.50.
- Cross-customer: **3 scopes we operate, not 3 customers**; identical pattern by construction; k≥3 = operator-vouched threshold **enforcement**, not Sybil-resistance; reaches the **internal** consume surface, not the external feed.
- The RealMeter is **live, sampled every few seconds** — it climbs in steps.
- The bystander proof is a **terminal curl returning 200**, not a dashboard panel.

**NEVER claim:**
- ❌ "it crossed on the **first touch**" / run beat 5 with `--aggressive` (that posture was declined; the wall shows a 3–5/6-touch climb).
- ❌ call the Tier-2 mechanism "**fake_tree maze**" (the headline is `poison_field`).
- ❌ the cap lands **exactly on $0.50**.
- ❌ an attacker that bled "gets recognized **everywhere**" as a live external network effect (the external feed is unmet/serves nothing).
- ❌ "**three customers** independently saw this."
- ❌ we **fool a sophisticated attacker** forever.
- ❌ show `-scripted` with a real-$ meter (`-scripted` carries no usage — a $ figure on it is fabrication).
- ❌ relabel a defender max-hold cap as the attacker "**giving up**."
- ❌ quote a **false-positive percentage** / imply there's an FP rate to tune.
- ❌ imply the **dashboard** shows a surviving bystander (it's the terminal curl).

---

## 4. The exact commands (tape these to the laptop)

> Beats 1 + 5 run **ON the demo box**; beat 6 runs from the **operator laptop**.

**① Beat 1 — cassette replay (on the demo box, $0, deterministic):**
```bash
ssh -i ~/.ssh/canarysting-dev ubuntu@<demo-box-public-ip>
cd /home/ubuntu/canarysting
deploy/m7-window/run-attack.sh --cassette /tmp/m9-demo3.cassette
# (target/tap come from the demo box's /etc/canarysting/m7.env = 127.0.0.1 — the LF2 fix)
```

**② Beat 3 — bystander curl (a legit path returns 200 while the attacker is jailed):**
```bash
# from the demo box (or any allowed host), a benign request to the front door:
curl -s -o /dev/null -w "legit request -> %{http_code}\n" http://127.0.0.1:8080/
```

**③ Beat 5 — live capped run (on the demo box; m7.env points it at loopback):**
```bash
cd /home/ubuntu/canarysting
deploy/m7-window/run-attack.sh --budget 0.50 --max-turns 5
# (target/tap come from the demo box's /etc/canarysting/m7.env = 127.0.0.1)
```

**④ Beat 6 — k=3 crossing (from the operator laptop):**
```bash
deploy/k3-boxes/run-crossing.sh pull   # pull 3 boxes' confirmations
deploy/k3-boxes/run-crossing.sh k2     # 0 cleared lines -> REJECTED at k=2
deploy/k3-boxes/run-crossing.sh k3     # "CROSSED at k=3" -> 1 line
cat /tmp/k3-inbox/cleared-out.ndjson   # the wire: opaque token + 7 coarse fields
```

---

## 5. Failure runbook (if it breaks live)

| Trigger | Do this |
|---|---|
| Beat 5 returns flat 403s / no bleed | run-attack is hitting the slow server — confirm it ran ON the demo box. If still 403: **skip beat 5, pivot to the cassette** ("$0.228 real Opus spend, deterministic recording"). |
| Live LLM hits the cyber-safeguard refusal (~turn 2) | Expected + intermittent. **Don't improvise** — fall back to the cassette and narrate it as the recording. |
| Bare `./run-attack.sh` starts a paid $5 run | The $5 hard cap blocks pre-turn; Ctrl-C, re-run the cassette command (①). |
| Wall blank / panels stale | A demo-box process died — restart only that one (re-nohup staged-range / envoy-adapter / mesh-frontend). Do **not** re-run `demo-box-setup.sh` live (it wipes warm state). If unrecoverable <2 min: narrate from the terminal ledger. |
| Tunnel drops / tab frozen | Switch to the warm-spare SSH session. If both dropped: `curl ifconfig.me`, re-authorize the `/32` on `:22`, re-open the `-L` tunnel, **reload** the tabs (a frozen tab looks live but is stale). |
| Beat 5 key permission error | `sudo -u ubuntu head -c1 /etc/canarysting/anthropic.key` pre-check; chown to ubuntu 0600. Else skip beat 5, lean on the cassette. |
| RealMeter doesn't animate | Narrate "sampled every few seconds" + read the terminal `[M9 RESULT]` ledger ($0.228) aloud. |
| `:3002` still WARMING UP at demo time | Use the Beat-0 fallback line (structural zero-FP). Don't claim "calibrated" if the pill isn't green. |
| Someone reaches for `deploy/dev-box` terraform | **STOP.** Catastrophic — would destroy the live M7 server + VPC. Never run terraform there during the window. |

---

## 6. Teardown / revert (after the demo)

1. **Dashboard #2 (M7 calibrated pair):** `sudo systemctl disable --now canarysting-dashboard-web-m7 canarysting-dashboard-backend-m7 && sudo rm /etc/systemd/system/canarysting-dashboard-{web,backend}-m7.service && sudo systemctl daemon-reload`.
2. **Dashboard #1 drop-in (points the main dashboard back at the M7 window):** `sudo rm /etc/systemd/system/canarysting-dashboard-backend.service.d/demo.conf && sudo systemctl daemon-reload && sudo systemctl restart canarysting-dashboard-backend`.
3. **Leave the M7 window running** (it's your learning window — it was down and is now re-accruing; keep it up).
4. **k3 boxes:** `terraform -chdir=deploy/k3-boxes/terraform destroy` (the 3 boxes only — **never** dev-box).
5. **SG:** revoke the `:8088` rule (`10.20.1.24/32 → demo-box SG`).
6. Do **not** rotate `/etc/canarysting/anthropic.key`; do **not** run `set-demo-posture.sh` / `setup-consumer.sh` on the M7 server.
