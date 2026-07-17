# CanarySting Killer Demo Spec
### Generic mesh-enabled Kubernetes, full North-South to East-West flow

**Status:** working draft for iteration. Targets a generic mesh-enabled K8s cluster (Istio, Linkerd, or Cilium mesh). The XC/AppStack variant runs the same flow inside one F5 CE site and is noted at the end, but this spec is the clean standalone-startup version.

**What this demo has to accomplish:** make a technical buyer believe, in under ten minutes, that detection-and-alert is insufficient against a valid-credential attacker, that CanarySting acts in the moment where others only watch, and that it measures and shrinks blast radius. It must survive a sharp viewer, so it builds the hardest objection (the valid-credential attack) into the script and answers it on screen.

---

## The environment

A realistic microservices application in a mesh-enabled K8s cluster. Use something legible to a non-specialist: a payments or banking-style app with a recognizable shape.

- An ingress gateway at the perimeter (the North-South door): an Envoy-based gateway or NGINX.
- Real services east-west: frontend, orders, payments, a database, a secrets store.
- A service mesh providing identity (mTLS / SPIFFE), so every workload has a verifiable identity. This is the high-fidelity tier, chosen deliberately.
- CanarySting deployed as a per-node DaemonSet plus operator.
- Canaries seeded among the real services: a decoy credential, a decoy "admin" endpoint, a decoy secret in the secrets store, a decoy database. Placed where a recon-driven attacker would plausibly look.

Keep the topology small enough to fit on one screen as a live graph, and real enough that a CISO recognizes their own environment in it.

---

## The narrative arc

Seven scenes. The drama is the gap between "nothing looks wrong" and "we just stopped a breach no one else would have caught in time."

### Scene 0 — The calm (baseline and identity)

**On screen:** the cluster running normally. CanarySting in observe-only. The live graph builds: identities talking to services, every flow attributed to a workload identity, normal cadence learned.

**What it must prove:** we see east-west traffic the way no perimeter or endpoint tool does, attributed to identity, not just IP. This is the substrate everything else rests on.

**What must be true to show it:** the eBPF baseline is observing real flows; the socket-cookie join is attributing L7 verdicts to kernel-observed flows; identity resolves cleanly from the mesh. The observed graph renders live.

### Scene 1 — The entry (North-South, valid credentials)

**On screen:** an attacker enters through the perimeter using a stolen but valid credential, through the legitimate channel. They look exactly like a real user. A detection panel (representing the incumbent world) shows green, nothing flagged. CanarySting also does not alarm.

**What it must prove:** this is the attack that actually happens now, valid credentials through legitimate channels, and detection sees nothing. Critically, CanarySting does not false-alarm either, because nothing has touched a canary yet. We do not fire on "looks weird."

**Why this beat matters most:** it builds the blog's "82% ride valid credentials" critique directly into the demo and turns it from an objection into a setup. The viewer watches detection fail in real time, which primes them for what comes next.

**What must be true to show it:** the attacker path uses a real valid credential through the gateway; the "detection stays green" panel is honest (it genuinely would not catch this); CanarySting's silence here is real, not staged, the trigger is genuinely the canary touch, not anomaly.

### Scene 2 — Recon and lateral movement (East-West)

**On screen:** the compromised identity starts enumerating services, probing for credentials and data, moving east-west. Still looks legitimate. Still no alarm. But the live graph now highlights the compromised identity's path, attributed at every hop, even though nothing has tripped yet.

**What it must prove:** we observe and attribute lateral movement that detection tools miss, because we are watching identity-attributed east-west flow, not waiting for a signature. We see the attacker before they trip anything.

**What must be true to show it:** the lateral movement is real service-to-service traffic; the graph attributes each hop to the compromised identity in real time; the baseline does not generate a false trigger from the unusual-but-not-decoy-touching activity (proves the multiplier guardrail).

### Scene 3 — The canary touch (the trigger)

**On screen:** the attacker, exploring, hits a canary, reaches for the decoy credential, or queries the decoy secret, or connects to the decoy admin endpoint. The moment lands visibly. The suspicion score crosses the bar.

**What it must prove:** a canary touch is near-certain evidence of an intruder, because nothing legitimate has any reason to touch a decoy. This is the false-positive discipline paying off, the trigger is a deliberate touch, not a guess.

**What must be true to show it:** the canary is convincing enough that a real recon process would reach for it; the touch is detected and scored in real time; the score crossing is visible and tied to the specific flow and identity.

### Scene 4 — The sting (contain and attrit, in-kernel, no human)

**On screen:** on the confident verdict, CanarySting acts in the kernel, in the moment. Containment: the compromised flow is jailed, egress denied, it can no longer reach the real payments service, the real database, the real secrets. Attrition: the attacker is fed a poisoned, fabricated environment, their recon now returns lies. Show the timing, this happens faster than a human could read an alert, let alone respond.

**What it must prove:** we act, in-kernel, with no human in the loop, faster than the attacker retries. This is the thing no competitor does. Detection watched it happen; we stopped it.

**What must be true to show it:** kernel enforcement genuinely blocks the flow (real eBPF enforcement, not a simulated block); the containment is flow-precise (the attacker is jailed, legitimate traffic is untouched, which proves the precision claim); the attrition/poisoning is real enough to show the attacker's view degrading. Be explicit in the script about which parts are prototype-proven versus productized, do not let the demo imply more maturity than exists.

### Scene 5 — The blast-radius reveal (the payoff)

**On screen:** the graph resolves into the blast-radius picture. Show, for the compromised identity: what it actually touched (observed), what it could have reached if not contained (permitted / blast radius), the path it took toward the canary (adversarial), and what was just cut off. Put a number on it: "this identity could have reached N services and M sensitive assets, here is the blast radius we contained." Then the forward-looking half: the dark reachability, the permitted-but-unused paths this identity had, that you can safely remove.

**What it must prove:** blast radius is the metric that matters, we measured it on real behavior, we contained it live, and we can tell you how to shrink it permanently. This is the CISO's board metric and the answer to the Containment Era thesis, delivered concretely rather than as a slogan.

**What must be true to show it:** the observed and adversarial layers are real (from the demo run); the permitted/blast-radius layer requires policy ingestion (the medium case), so be honest about whether it is shown as built or as the near-term vision, the dark-reachability computation is the medium-case capability and should be labeled accordingly if it is not yet productized.

### Scene 6 — The moat (the close)

**On screen:** briefly, the encounter that just happened sharpened the intelligence, the adversarial path, the exfil ground truth, the attacker behavior, all captured, attributed, isolated to this deployment. Every encounter compounds.

**What it must prove:** this is not a one-time catch, it is a compounding data asset that makes every future detection and every blast-radius prediction sharper. The thing that makes this a company, not a feature.

**What must be true to show it:** the intelligence capture is real (the encounter data is stored and attributed, isolated per scope); the compounding claim is framed honestly as the mechanism, with the cross-deployment network as roadmap.

---

## The short "wow" cut

If you need a three-minute version (demo day, a cold first meeting), run Scenes 1, 3, 4, 5: valid-credential entry that detection misses, the canary touch, the in-kernel containment, the blast-radius reveal. Drop the baseline build (Scene 0), the lateral-movement detail (Scene 2), and the moat close (Scene 6). The four-beat cut still lands the core argument: detection fails, we catch and contain in the moment, here is the blast radius.

---

## What each scene proves, in one line

- Scene 0: we see identity-attributed east-west flow no one else sees.
- Scene 1: the real attack is valid credentials, detection is blind, and we do not false-alarm.
- Scene 2: we observe lateral movement attributed to identity before anything trips.
- Scene 3: a canary touch is near-certain evidence, the trigger is deliberate, not a guess.
- Scene 4: we act in-kernel, no human, faster than the attacker, flow-precise.
- Scene 5: blast radius is the metric, measured, contained, and shrinkable.
- Scene 6: every encounter compounds into a proprietary moat.

---

## Build and validation checklist

Group by what has to be real for the demo to be honest and to survive scrutiny. Mark each as prototype-proven, productized-this-round, or roadmap, and never let the demo imply a higher maturity than the truth.

### Identity and substrate
- Service mesh deployed and issuing verifiable workload identity (mTLS / SPIFFE). This is the high-fidelity assumption, state it openly.
- eBPF baseline observing real east-west flows at acceptable overhead.
- Socket-cookie L7-to-kernel join attributing proxy verdicts to kernel-observed flows, same-node. Confirm the kernel version supports a stable, system-global socket cookie.
- Observed graph renders live and attributes hops to identity.

### Detection honesty
- The valid-credential entry is a genuine valid credential through the real gateway, so the "detection stays green" claim is true, not staged.
- CanarySting genuinely does not trigger before the canary touch (the multiplier guardrail holds: deviation alone never fires).

### Canary and trigger
- Canaries convincing enough that a real recon process reaches for them.
- Canary touch detected and scored in real time, tied to the specific flow and identity.
- Score-crossing visible on screen.

### The sting
- Real eBPF kernel enforcement jails the flow and denies egress (not a simulated block).
- Containment is flow-precise: the attacker is jailed, legitimate traffic continues untouched. This precision is the credibility of the whole product, it must be real.
- Attrition / poisoning shows the attacker's view degrading.
- Script explicitly labels prototype-proven versus productized for each sting action.

### Blast-radius reveal
- Observed and adversarial graph layers are real from the demo run.
- Permitted / blast-radius layer (medium case) requires policy ingestion from the K8s API, NetworkPolicy, mesh authorization, RBAC. Confirm whether this is built or shown as near-term vision, and label it honestly.
- Dark-reachability computation (permitted minus observed) labeled as the medium-case capability if not yet productized.
- The blast-radius number is derived from the real graph, not invented for the slide.

### Moat
- Encounter data captured, attributed, and isolated per scope.
- Compounding framed as mechanism, cross-deployment network framed as roadmap.

---

## Demo failure modes to avoid

- **Staged-looking enforcement.** If the containment looks scripted rather than real, the whole demo dies, because the entire claim is "we actually act." The kernel block has to be genuinely live and visibly precise.
- **Overclaiming maturity.** A technical viewer will probe what is prototype versus product. Label it honestly in the script. The honesty is more persuasive than the polish.
- **Burying the valid-credential beat.** Scene 1 is the strongest part of the demo because it disarms the hardest objection. Do not rush it. Let the viewer sit with detection staying green.
- **A blast-radius reveal that is just a pretty graph.** The graph has to deliver a number and an action (here is the blast radius, here is what to cut), or it reads as visualization theater. The dark-reachability recommendation is what makes it actionable.
- **False positives in the live run.** If the baseline or scoring fires on legitimate traffic during the demo, the core "engineered out false positives" claim collapses on the spot. Rehearse the legitimate-traffic path until it is silent.

---

## XC / AppStack variant (note for later)

The same seven-scene flow runs inside a single F5 CE site on the AppStack persona (physical / managed K8s, never vK8s, which forbids the privileged eBPF, CRDs, and operator CanarySting needs). The CE is both the North-South proxy and the East-West workload host, so the entire flow runs inside one F5 site, and CanarySting inherits XC's built-in mesh identity, which makes it the highest-fidelity environment available. The one gating unknown is whether F5's managed pK8s distribution permits loading privileged eBPF programs, CRDs, and an operator on CE nodes, which only XC engineering can confirm. Spec the generic version first, validate that one question, then decide whether to stage on XC.
