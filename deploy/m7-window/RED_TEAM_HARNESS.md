# Red-Team Harness — the CTA (falsify the wedge, or pilot it)

The most credible proof of a security claim is not a vendor demo — it's the
prospect's own red team failing to break it. This is the demo's close (Beat 6) and
the design-partner on-ramp: hand them the harness and **two falsification
challenges that ARE the wedge's invariants.** If they can't break them, the claims
are theirs to verify, not ours to assert.

## The wedge invariants under test

> "A zero-false-positive-by-construction east-west tripwire you can safely
> auto-respond on — that contains the flow, not the host."

Two claims, two challenges. Either one, broken, kills the pitch — which is exactly
why letting them try is the strongest thing we can offer.

### Challenge 1 — "Arm a response without touching a decoy" (falsify Rule 8 / zero-FP)

**The claim:** only a canary touch can arm a response. No anomaly/deviation/novelty
classifier exists in the trigger path, so there is no false-positive rate to tune
or drift — it's zero *by construction*.

**The challenge:** from any identity, with any traffic — recon, scanning, weird
adjacencies, volume floods, novel identities, slow-and-low — get CanarySting to
**arm a response (tag/contain/tarpit/jail) on a flow that touched no decoy.** Watch
the ReconLive panel: it *surfaces* your most anomalous flows ("we see you") as
observe-only — **none has armed a response** (none reached Tier 1+). The only path
to a verdict is a decoy touch that crosses the threshold.

**What it proves if they fail:** the zero-FP guarantee is structural, not a knob.

### Challenge 2 — "Jail a legitimate flow / kill a bystander" (falsify flow precision)

**The claim:** containment is socket-cookie precise — we drop the attacker's flow,
not the host/IP/service; a legitimate workload on the same host keeps serving.

**The challenge:** while an attacker flow is being jailed, get a **legitimate
same-host flow actioned** — collateral-jail a neighbor, or knock a real workload
off by riding the attacker's IP/host/cgroup. Watch BystanderHealth: same-host
workloads stay green/200 throughout. A jailed bystander is, by our own standard, a
critical failure — find one.

**What it proves if they fail:** safe-to-auto-respond is real; the blast radius is
one socket, attributed by cookie.

## How to run it (scoped sandbox — their controls)

1. **Their range, their controls.** Point the harness at a range *they* designate;
   their API key, their hard `-hard-cap-usd`, their `-max-turns`. We never touch
   their production until they choose to.
2. **The harness:** `deploy/m7-window/run-attack.sh` drives a real LLM agent (or
   `--scripted`/`--cassette` for $0 deterministic runs) over a single keepalive
   socket — one escalating flow. They can also bring their own tools; the only
   thing that matters is whether the two invariants hold.
3. **The fail-open / blast-radius answer they'll ask for next:** § FAIL_OPEN.md
   (fail-open at Tier 1, fail-closed at Tier 3, bounded inline hold; proven by the
   adapter's policy + timeout tests).

## Why this is the ask, not a slide

A network-effect data moat needs real third-party deployments, and we're honest
that the cross-customer peers in the demo are simulated. The on-ramp out of that
cold start is a **design partner who pilots the wedge** — and the cleanest way to
earn that is to let their red team try to falsify it on a scoped range first. Pass
the gauntlet → pilot → become one of the first real nodes in the network.
