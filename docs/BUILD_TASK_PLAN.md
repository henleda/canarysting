# CanarySting — Build Task Plan
### Sequenced milestones for the Kubernetes-native pivot. Feed to Claude Code.

**How to use this plan.** Read the companion Architecture Spec first, it is the target state. This plan sequences the work to get there. The first milestone is reconciliation: you (Claude Code) can see the actual repo and the human and the spec author cannot, so your first job is to ground this plan in the real code before building anything. Do not start Milestone 1 until Milestone 0 is done and its gap report is reviewed.

**Standing rules for every task.**
- Surface divergence, do not silently overwrite. If the repo already does something differently than the spec, report it and propose, do not just replace.
- Honor the load-bearing decisions in the spec (per-node DaemonSet not sidecar, socket-cookie host-local, identity as spine, canary-touch-only trigger, per-scope isolation, observe-before-enforce). If a task seems to require violating one, stop and flag it.
- Two invariants are non-negotiable and must have tests: (a) baseline deviation alone never produces a Tier 1+ action, (b) no cross-scope state bleed and scope resolution fails closed.
- Mark new code and docs as prototype, productized, or roadmap. Do not imply maturity that does not exist.
- Kubernetes-only is the build target. Do not invest in generic non-K8s paths this phase, but keep the proxy contract abstract.

---

## Milestone 0 — Reconcile (do this first, build nothing yet)

Goal: produce a written gap report mapping the current repo against the Architecture Spec, so the rest of the plan is grounded in reality.

Tasks:
- Inventory the repo: top-level structure, modules/packages, build system, languages, what runs where.
- Map each spec component (canary layer, decision engine, sting layer, eBPF datapath, operator/CRDs, graph, proxy adapters, intelligence layer, scope isolation) to what exists, partially exists, or is absent in the repo.
- Identify direct conflicts: places where the repo's current design contradicts a load-bearing spec decision (for example, a sidecar deployment model, or a trigger that fires on anomaly, or shared cross-scope state).
- Identify what to keep, what to refactor, what to retire.
- Note the current deployment model and whether it already targets K8s.
- Output: a GAP_REPORT.md with the mapping, the conflicts, and a recommended reconciliation for each conflict. Stop and let the human review before proceeding.

Acceptance: GAP_REPORT.md exists, every spec component has a status, every load-bearing decision has a conflict-or-consistent verdict, and reconciliations are proposed not applied.

---

## Milestone 1 — Substrate: K8s-native datapath and identity-attributed observation

Goal: the eBPF-observed, identity-attributed flow graph running as a per-node DaemonSet on mesh-enabled K8s. This is the foundation everything else expresses.

Tasks:
- Establish (or refactor toward) the per-node DaemonSet deployment and the operator skeleton. Reconcile with whatever the repo has per Milestone 0.
- eBPF flow observation: TC hooks on pod veth for L3/L4, cgroup hooks for connection-level interception and socket-cookie acquisition. Pin and assert the minimum kernel version for a system-global socket cookie.
- Identity resolution from the mesh (mTLS/SPIFFE) as the primary path. Implement label-derived identity as an explicitly-lower-confidence fallback. Map ephemeral pod IPs to stable logical identity via label/SA set, never by IP.
- Build the OBSERVED graph: emit identity-attributed flow edges (source identity, destination service/workload, port/protocol, timestamp) into the graph store.
- Per-scope isolation from day one: scope keyed to namespace (or cluster), state isolated, scope resolution fails closed. Add the cross-scope-isolation test now, not later.

Acceptance: on a mesh-enabled test cluster, the agent observes real east-west flows, attributes them to mesh identity, renders an OBSERVED graph, and the isolation test passes (no cross-scope bleed, fail-closed resolution). Overhead measured and recorded.

---

## Milestone 2 — Canary: deception seeding and the socket-cookie join

Goal: plant decoys, detect touches, and join the L7 verdict to the kernel via socket cookie. This lights up the trigger.

Tasks:
- Operator-driven decoy seeding (DeceptionPolicy-style CRD): decoy secrets, credentials, files, endpoints, decoy services, planted via volume mount or exec into matching workloads. Reconcile with any existing canary code.
- Canary-touch detection: kprobes/LSM/tracepoints for decoy-file access, proxy-layer detection for decoy endpoints/credentials. Attribute every touch to a flow and identity.
- The socket-cookie join: node-local proxy verdict joined to node-local kernel-observed flow for the same socket. Implement and test same-host; document the host-local boundary explicitly in code.
- Score = Base x Multiplier. Base non-zero only on a canary touch. Multiplier bounded, floored at one, from the baseline. Add the false-positive-guardrail test now: baseline deviation with no canary touch must score below any action threshold.

Acceptance: a decoy touch in the test cluster produces a scored, identity-attributed event via the socket-cookie join; the guardrail test passes (no touch, no action, regardless of how anomalous the traffic looks).

---

## Milestone 3 — Sting: tiered active response, in-kernel

Goal: act on a confident verdict, contain and attrit, flow-precise, no human.

Tasks:
- Implement the four tiers: observe, tag-and-deceive, contain-and-attrit, jail/adversarial. Operator-set floor (passive/moderate/aggressive); ship the ceiling, never force a posture.
- Containment: in-kernel jail of the specific flow and egress denial, attributed via socket cookie, flow-precise (legitimate traffic on the same node untouched). This precision is the credibility of the product, test it.
- Attrition primitives: velocity disruption (latency/tarpit), information poisoning (fabricated environmental responses to the attacker), and the scaffolding for opportunity-cost, exploit-burn, operational-exposure axes. Mark which are prototype vs. roadmap.
- Observe-before-enforce enforced in code: enforcement rules cannot activate before the baseline-learning period completes.

Acceptance: in the test cluster, a confirmed hostile flow (post-canary-touch) is contained in-kernel with no human in the loop, legitimate traffic is provably unaffected, and the observe-before-enforce gate is enforced.

---

## Milestone 4 — Narrow blast radius: the observed/demonstrated graph product

Goal: ship the near-term wedge, demonstrated blast radius from data already collected, no policy ingestion.

Tasks:
- Build the graph/query/reporting layer over the OBSERVED and ADVERSARIAL edges from Milestones 1 and 2.
- Demonstrated blast radius: for a compromised identity/workload, compute the observed transitive reachable set, ranked by asset sensitivity and adversarial weighting.
- Adversarial-path overlay: show where deception fired and how attackers traversed.
- Reporting/visualization output suitable for the demo and for a design partner.

Acceptance: for a chosen workload, the product reports its demonstrated blast radius and adversarial overlay from real observed data, with a number and a ranked path list.

---

## Milestone 5 — Medium blast radius: policy ingestion, prediction, and safe policy recommendation

Goal: the medium case, predicted blast radius and behavior-derived containment policy. Gate this on mesh-grade identity.

Tasks:
- Ingest the K8s API surface: NetworkPolicy, CiliumNetworkPolicy, mesh AuthorizationPolicy/PeerAuthentication (or Linkerd equivalents), RBAC, namespaces/labels/SA mappings. Build PERMITTED edges.
- Compute dark reachability (PERMITTED minus OBSERVED).
- Predicted blast radius for not-yet-observed compromise.
- Containment policy recommendation: allow OBSERVED, deny dark reachability, emit as NetworkPolicy/CiliumNetworkPolicy. Deliver in audit/detect-only mode first, require human sign-off and a baseline-maturity gate before any enforce.

Acceptance: the product ingests cluster policy, computes dark reachability, predicts blast radius, and emits a safe policy recommendation that runs in detect-only and is reviewed before enforce. Do not auto-enforce.

---

## Milestone 6 — Intelligence and the moat

Goal: turn encounters into the compounding asset, safely isolated.

Tasks:
- Capture adversary behavior, adversarial paths, and exfil ground truth per encounter, attributed and isolated per scope.
- The intelligence loop: encounters sharpen scoring, the bait model, and adversarial weighting within a scope.
- The isolation-preserving egress: only anonymized, derived patterns may cross a scope boundary, through a single default-deny chokepoint, never raw data or baselines. Cross-deployment network is roadmap; build the isolation boundary now so it is safe later.

Acceptance: encounter intelligence is captured and isolated per scope, the within-scope loop measurably sharpens scoring, and the egress boundary is default-deny with no raw-data path out.

---

## Milestone 7 — Demo enablement

Goal: stand up the full North-South to East-West killer demo on mesh-enabled K8s (see the Demo Spec).

Tasks:
- A realistic mesh-enabled demo cluster: ingress gateway, frontend/orders/payments/db/secrets, mesh identity, CanarySting DaemonSet+operator, canaries seeded.
- Script the seven-scene flow: calm baseline, valid-credential entry that detection misses, lateral movement observed, canary touch, in-kernel sting, blast-radius reveal, moat.
- Ensure the live run is silent on legitimate traffic (no false positives during the demo) and that enforcement is genuinely live and visibly flow-precise.
- Label in the demo which capabilities are prototype, productized, roadmap (especially the medium-case permitted/dark-reachability layer).

Acceptance: the full demo runs end to end on the test cluster, the valid-credential beat shows detection blind while CanarySting stays correctly silent until the canary touch, containment is live and precise, and the blast-radius reveal produces a number and an action.

---

## Sequencing logic (why this order)

Substrate first (M1) because everything is an expression of the identity-attributed flow graph. Canary and the socket-cookie join next (M2) because they light the trigger and prove the load-bearing primitive. Sting (M3) because active response is the differentiator and depends on the join. Narrow blast radius (M4) is the shippable wedge and needs only M1-M2 data. Medium (M5) adds the heavier policy ingestion once the substrate and identity are proven. Intelligence (M6) compounds what the earlier milestones produce. Demo (M7) assembles the proven pieces into the artifact that wins design partners and funding. Milestones 1-4 plus 7 are the focused near-term slice; 5 and 6 are the build-toward.
