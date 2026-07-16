# CanarySting — Attacker Segmentation & Positioning Memo

**Status:** working draft for iteration. Once settled, this feeds the design-partner section of the investor deck (segment view, effectiveness curve, AI impact, and the ICP that follows).

**Purpose:** Decide, in writing and on the record, which attacker segments CanarySting is built to address, which it addresses incidentally, and which it deliberately does not claim to defeat. The per-segment "do or don't address" call drives the design-partner ICP, the GTM ICP, pricing, and what we do and do not build.

---

## 1. The core principle

Attrition only works when the attacker has something to lose by staying. The lever CanarySting pulls is the attacker's own sunk cost and constrained resources. That single fact determines where we win: our weapon gets sharper exactly as the attacker becomes more committed and more invested, and it loses its grip at the point where cost stops mattering to the attacker at all.

That gives us a clean way to reason about every segment: not "how dangerous is this attacker," but "how much has this attacker invested by the time they reach our canaries, and how much do they care about the cost we can impose."

---

## 2. The segments (four buckets)

We split the middle tier into two, because the behavioral fault line inside it is exactly the line that decides whether attrition works. The split does not shrink the market — it names the behavior we are built for, which (Section 5) AI is actively growing.

### Tier 1 — commodity bots
Low cost per attack, massive scale, opportunistic. Scan for known vulnerabilities and easy exfiltration. Portfolio-level logic: total return across the population only needs to beat total cost, so any single target that becomes expensive is abandoned instantly.

**Economic signature:** return X across a large population must beat cost Y. Per-target investment near zero. Optimal response to friction is to leave.

### Tier 2a — affiliate / operator end of business attackers
Ransomware affiliates and crews running semi-automated playbooks. Some commitment, but at the margin they behave like upmarket commodity attackers: if friction rises enough, they may move to an easier target. LLM-assisted but not deeply bespoke.

**Economic signature:** take Y must beat cost X, but X is modest and the playbook is reusable, so abandonment is still on the table. Attrition works, but they can sometimes leave.

### Tier 2b — bespoke-broker end of business attackers (THE BULLSEYE)
Deep reconnaissance, custom tooling, false flags, real sunk cost per target. They infiltrate, profile, plan, build, then execute via lateral movement, privilege escalation, and targeted deception. Each engagement is a committed investment they need to recoup and cannot cheaply abandon.

**Economic signature:** take Y must significantly exceed a high cost X per target. Heavy sunk cost. They cannot walk away cheaply once committed — which is exactly the condition that makes attrition maximally effective.

### Tier 3 — apex / state-funded operators
Cost is not a constraint. Money is often not the goal. Objectives are political, geopolitical, or macroeconomic. They spend whatever it takes and persist as long as needed.

**Economic signature:** cost X is effectively unbounded and largely irrelevant. The economic lever does not apply.

---

## 3. The decision: do or don't address

For each bucket: do we address it, how, and what do we claim.

### Tier 2b — ADDRESS. The bullseye. Build, sell, and price here.

Every CanarySting mechanism is maximally effective against 2b, for one reason: they have already made a heavy, target-specific investment, and their model demands the take exceed a high cost. We attack that ratio directly.

- **Velocity disruption** stretches their committed engagement, raising cost and exposure on an investment they can't abandon.
- **Information poisoning** is devastating here specifically. This attacker builds a detailed model of the environment during recon and planning. Poison that model and they build their expensive custom attack against a fiction.
- **Opportunity-cost injection and exploit-inventory burn** hit the custom tooling and bespoke exploits they invested in.
- **Lateral movement and east-west deception** is precisely this tier's behavior and exactly where our canaries live.

Against 2b we don't merely detect — we make the engagement uneconomic, the only thing that changes a committed attacker's behavior.

**Claim:** "We make targeted, bespoke intrusions uneconomic." Strong and defensible.

### Tier 2a — ADDRESS, with honest limits. Secondary, and a test bed.

Attrition works against 2a, but they retain the option to abandon when friction rises, because their per-target cost is lower and their playbook is reusable. So we impose cost effectively but can't always hold them — sometimes the win is deflection rather than uneconomic defeat, which is still a good outcome. 2a is where we learn empirically how much friction it takes to flip an attacker from "push through" to "move on."

**Claim:** "We impose real cost on operator-grade attackers and deflect many of them." We don't claim we always make them stay and bleed — that's 2b.

### Tier 1 — ADDRESS INCIDENTALLY, as hygiene. Don't build the story here (for now — see Section 5).

Commodity bots trip our canaries and detection works fine. But classic attrition is largely wasted: their optimal response to friction is to leave, so cost-imposition produces departure (containment, not differentiated attrition), and the generic behavior yields little intelligence. **False-positive discipline** matters most here, because the volume is enormous.

**Claim:** "We detect and deflect commodity attacks as table stakes." We do NOT claim our attrition story is about stopping botnets.

### Tier 3 — ADDRESS WITH DISCIPLINED HUMILITY. Don't overclaim. Capture the intelligence.

Against a cost-insensitive state actor the core attrition premise partially collapses. Overclaiming here destroys credibility with the sophisticated buyers and investors who know better. But two axes still bite: **time and stealth still matter** (surfacing them earlier or forcing a premium capability to burn on a decoy has real value even when dollar cost doesn't), and the **intelligence value of an apex encounter is our highest**, even though we'll rarely get it.

**Claim:** "We raise the cost of stealth and force exposure even against the most resourced actors, and the rare apex encounter is our highest-value intelligence." We do NOT claim "we defeat APTs."

---

## 4. The effectiveness curve (and why it's moving)

Effectiveness is governed by the attacker's sunk cost and their sensitivity to it. Across the four buckets:

- **Tier 1:** low attrition effectiveness (they leave), good detection, low intelligence yield.
- **Tier 2a:** strong effectiveness, but they retain an exit; outcomes split between uneconomic-defeat and deflection.
- **Tier 2b:** peak effectiveness on every axis — committed, cost-sensitive, behaving exactly where we operate. Highest commercial value.
- **Tier 3:** attrition effectiveness drops (cost-insensitive), but stealth-disruption and early-warning retain value, and intelligence yield is highest per encounter.

The static shape: **a 2b-centered weapon that provides 2a pressure, tier-1 hygiene, and tier-3 early-warning.**

The dynamic shape is the important part. Because AI is migrating 2b-grade behavior downward (Section 5), the attrition-effective zone is **expanding down the pyramid over time.** Attackers who were tier-1 "just leave" are becoming committed enough to be attrition-attackable. The curve isn't fixed — its effective region is growing into territory that used to be hygiene-only. That movement is the growth story.

---

## 5. How AI changes the picture (the dual-vector mechanism, and the "why now")

The segmentation is not static. AI is enlarging the exact behavior we are built to defeat, from two directions at once.

**Vector 1 — bespoke work gets cheaper.** AI drops the cost of 2b-grade work (recon, planning, custom tooling). The committed-bespoke population grows and becomes cheaper to run, while still behaving with 2b commitment. Our bullseye gets more populous.

**Vector 2 — bespoke capability moves down.** AI hands 2b-grade capability to actors who used to sit in tier 1 and 2a. Attackers who were once opportunistic now run recon, plan, and move laterally — the sunk-cost-heavy behavior attrition feasts on. Our bullseye gets fed from below.

Both vectors converge on the same outcome: **the population of attackers exhibiting 2b behavior is expanding.** And as 2b behavior migrates downward, the old "tier-1 bots just leave" assumption erodes — some tier-1-priced activity is becoming 2b-behaving and therefore attrition-attackable, which is why the effective zone of the curve is expanding down the pyramid.

**The TAM story (important framing).** Our bullseye is 2b, where effectiveness peaks. But sizing the market as "today's elite bespoke brokers" understates it and tells a small-TAM story. The real market is the **growing population of 2b-behaving attackers** — enlarged by cheaper bespoke work and by capability migrating up from below. The addressable market isn't a fixed slice of attackers; it's a slice that is actively expanding because of the precise technology shift that defines this moment. This is defensible because it is mechanistic: we can explain exactly why it grows.

**The "why now":** AI is mass-producing the attacker we are built to defeat. We are not building for the last war; we are building for the attacker population that AI is actively growing.

---

## 6. What this decides downstream

### Design-partner ICP (now)
Recruit organizations whose threat model is dominated by **2b behavior** — committed, bespoke, investment-driven attackers doing recon and lateral movement. That points to mid-market and cloud-native enterprise tech with valuable assets and real east-west traffic. NOT defense contractors or agencies whose threat model is apex-dominated; their needs pull us toward claims we shouldn't make and a roadmap that weakens the 2b story. The design-partner phase also calibrates the 2a fault line (how much friction flips push-through to move-on) and tests whether AI-driven tier-1 actors are becoming attrition-attackable.

### GTM ICP (overall)
Center of gravity is 2b, with the **growing 2b-from-below population as the TAM engine.** Price against the cost of a bespoke, committed breach — large and quantifiable. 2a is a broad secondary market where we win via cost-imposition and deflection. Tier-3 early-warning and intelligence is an upsell and a credibility signal, not the lead.

### What we do NOT build
We do not chase nation-state-grade countermeasures to win this market — a distraction that weakens the 2b story and pulls us toward indefensible claims. The effectiveness curve says our money is at 2b and the ground expanding around it.

---

## 7. Open questions to resolve with design-partner data

1. Where exactly is the 2a/2b fault line in practice — how much friction flips a 2a attacker from "push through" to "move on"?
2. How fast is Vector 2 moving — are AI-equipped tier-1 actors becoming committed enough to be attrition-attackable, and how much of tier 1 is converting?
3. Which attrition axis produces the most measurable cost against real 2b engagements? (Hypothesis: information poisoning.)
4. What is the actual intelligence yield per encounter, by bucket, and does it confirm the curve?
5. Can we instrument "time-to-disengage" by bucket as the core attrition metric, and does it show the curve expanding downward over the engagement period?
