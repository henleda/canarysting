# CanaryPlatform Architecture

Status: architecture baseline for review. This document defines product boundaries and dependency direction. It does not rename packages, change runtime behavior, or claim that planned capabilities exist.

## Product definition

CanaryPlatform is one security operations product with three architectural systems:

- **CanaryView** is the vendor-neutral security intelligence plane. It normalizes and correlates observations from existing security and telemetry systems, explains conclusions, models reachability, and prepares evidence-backed recommendations.
- **CanarySting** is the deception, high-confidence detection, containment, and bounded-response system already implemented in this repository. Its eleven architectural rules and all safety invariants remain unchanged.
- **CanaryAttacker** is the bounded synthetic-adversary and validation harness. It produces declared intent and executed-action ground truth so CanaryView correlation can be measured rather than merely demonstrated.

The three systems are modular in code and responsibility but unified in the operator experience. Operators use one CanaryPlatform console; they should not have to reconstruct an incident by moving among vendor portals or by understanding socket cookies, BPF maps, CRDs, YAML, or raw event schemas.

`AGENTS.md` remains authoritative for coding and safety invariants. `docs/ARCHITECTURE.md` remains the detailed CanarySting subsystem specification. This document adds the broader product boundary without weakening either.

## Responsibility and boundary map

| System | Owns | Does not own |
|---|---|---|
| CanaryView | Canonical intelligence concepts; normalized observations; evidence and provenance; identity and security-trace correlation; explicit confidence and disagreement; reachability and attack-path analysis; explanations; impact assessments; recommendations; action previews; lifecycle-governed intelligence storage; telemetry-gap detection; human and agent read interfaces. | Vendor configuration, native vendor control planes, unnecessary duplication of raw telemetry, CanarySting scoring/tiering, automatic enforcement, or arbitrary mutation of source systems. |
| CanarySting | Canary generation and placement; canary-touch signals; proxy-neutral scoring; tiered verdicts; precise eBPF containment; bounded attrition; kill switch; scoped CanarySting evidence and audit. | General cross-vendor intelligence-plane availability or unapproved execution of CanaryView recommendations. |
| CanaryAttacker | Lab-scoped scenarios; bounded attacker tools; local model orchestration; declared `AttackerIntent`; recorded `AttackerAction`; cleanup; reproducible correlation ground truth. | Production telemetry truth, unrestricted shell access, unconstrained targets, or operational authority. |
| Vendor control planes | Native configuration, policy, enforcement, health, and vendor-specific source records. | Cross-stack correlation or the CanaryPlatform canonical interpretation. |

## Dependency principle

CanaryView must provide useful intelligence without CanarySting. CanarySting may consume CanaryView recommendations and publish its observations back to CanaryView. CanaryAttacker publishes ground truth to CanaryView but is never a trusted telemetry source. No circular Go package dependency should be introduced.

If implementation later needs shared contracts, place them at a neutral boundary only after the canonical-model architecture is reviewed. Do not broaden `internal/contract/` automatically: it is currently the deliberately narrow CanarySting flow/signal/verdict contract and remains authoritative for that runtime seam.

```text
  Cilium/Hubble   Envoy   Kubernetes   eBPF   NGINX/F5/OTel (later)
        \           |         |         |            /
         +----------+---------+---------+-----------+
                            |
                       observations
                            v
                     +--------------+
                     |  CanaryView  |
                     | correlate    |
                     | explain      |
                     | recommend    |
                     +------+-------+
                            |
                 preview + human approval
                            |
                 +----------+-----------+
                 v                      v
           CanarySting          vendor action adapter
          place/detect/respond     (later, controlled)
                 |
          evidence + outcome
                 +---------------------> CanaryView

  CanaryAttacker -- intent/action ground truth ------> CanaryView evaluation
```

An agent consumes the same evidence, confidence, recommendation, authorization, and action contracts as a human. It receives no hidden authority path.

## Relationship to vendor control planes

Cilium retains Cilium CLI, Hubble, and Cilium policy/configuration. BIG-IP, NGINX, and F5 Distributed Cloud retain their native control planes. Kubernetes retains its API and controllers. CanaryView sits above these systems to answer “What happened across the security stack?”

Vendor-specific identifiers and decision details remain attached as evidence. They must not leak into the canonical model as required fields. A connector may expose native deep links, but the normal incident workflow stays in CanaryPlatform and includes the supporting evidence and a concrete next step.

CanaryView may eventually delegate an approved action to a native control plane. Delegation requires explicit authorization, action provenance, a preview or simulation where practical, validation, audit, and rollback. A recommendation is never itself an action.

## Passive and active value

| Mode | Available capability |
|---|---|
| Passive CanaryView | Cross-stack security-flow visualization, distributed security tracing, topology, identity mapping, policy-decision correlation, dark-reachability analysis, blast-radius estimates, provenance, disagreement, and telemetry-gap detection. |
| CanaryView plus approved CanarySting placement | Evidence-backed canary opportunities are previewed and approved; CanarySting decides the safe materialization details and reports placement state. |
| Canary touch | CanarySting supplies high-confidence deception evidence and a verdict; CanaryView adds the event to the correlated trace and adversarial graph. |
| Approved response | CanaryPlatform presents an action plan; an authorized control plane executes it; CanaryView records result, validation, and rollback state. |

CanarySting is not a prerequisite for CanaryView adoption. Cilium/Hubble, Envoy, Kubernetes, and kernel telemetry in the DGX lab are sufficient for the first passive proof.

## Security distributed tracing

A security trace is an evidence-backed journey, not an assumption that every source emits one application trace ID. A journey may span Internet, F5 Distributed Cloud, BIG-IP, NGINX, Envoy, Kubernetes, Cilium, workload, process/socket, a canary touch, and response.

Correlation accepts partial identifiers: time, five tuple, translated tuple, workload identity, namespace, service account, pod UID, SPIFFE identity, HTTP attributes, request or proxy IDs, OpenTelemetry trace/span IDs, socket cookie, CanarySting signal/policy/canary IDs, and attacker scenario IDs. Each join records its method, evidence, confidence, conflicts, and missing expected evidence. Strong identifiers improve confidence; their absence does not erase the partial trace.

The canonical concepts and graph semantics are specified in `docs/CANARYVIEW_DATA_MODEL.md`.

## Intelligence lifecycle and storage boundary

Storage and retention are product architecture, not a database detail deferred until after the model. CanaryView follows a federated-evidence model: raw telemetry remains in the originating system or customer archive where practical, while CanaryView retains source references, integrity hashes, minimum evidence snapshots, normalized observations, correlations, relationship history, cases, actions, and authorized feature lineage.

```text
source-owned telemetry -> normalized evidence -> traces/cases -> relationship history
                                                      |              |
                                                      +-> actions    +-> graph views
                                                      +-> authorized historical features/models
```

The graph view is rebuildable and cannot become the only truth. Relationship history and evidence provenance preserve how it was derived. Operational retention permission is separate from model-use authorization. Cross-tenant learning requires explicit opt-in and additional privacy, cohort, residency, purpose, lineage, and deletion controls. Synthetic CanaryAttacker evidence is an isolated, versioned lab corpus and never silently enters production baselines or customer models.

The common lifecycle fields, recommended profiles, logical storage layers, deletion behavior, and architecture gate are defined in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`. M2A.0 reviews that architecture before M2A implements the canonical model.

## CanaryView and CanarySting feedback loop

```text
CanaryView understands environment and coverage
  -> finds high-value deception opportunity
  -> produces CanaryOpportunity and recommendation with evidence/confidence
  -> operator opens ActionPlan and approves placement
  -> CanarySting chooses and materializes a bounded harmless canary
  -> CanarySting reports placement/observation/touch/verdict/response evidence
  -> CanaryView updates trace and ADVERSARIAL graph state
  -> CanaryView recalculates impact and recommends a response
  -> operator previews and approves an authorized reversible action
```

CanaryView advises where deception has value. CanarySting owns how its deception is safely materialized. Initial placement and response are human-approved; no recommendation auto-enforces.

## Operator and agent consumers

The primary user is a traditional security or network operator using graphical controls. The unified console and interaction contracts are defined in `docs/CANARYPLATFORM_OPERATOR_EXPERIENCE.md`. Every significant finding must answer, in one workspace:

1. What happened?
2. Why does CanaryPlatform believe it?
3. What is affected or at risk?
4. What is recommended?
5. What action is available?

Machine consumers use structured equivalents of the same objects. Read operations come first (`query_graph`, `get_trace`, `get_evidence`, `explain_path`, `find_dark_reachability`, and `find_canary_opportunities`). Mutation remains behind the same approval and authorization boundaries visible to people.

## Existing implementation mapping

This mapping is descriptive and avoids duplicate abstractions:

| Existing implementation | Natural future role | Boundary note |
|---|---|---|
| `internal/engine/observebaseline` topology store | Initial OBSERVED topology source or backend candidate. | Rule 10 forbids a second observation truth; whether it is the backend or feeds a separate graph remains an open decision. |
| `internal/intelligence` scoped events, audit, profiles, L7 evidence, and network egress filter | CanarySting evidence producers and reusable provenance/audit mechanisms. | The package is not wholesale reclassified as CanaryView; much of it is touch-dependent or Sting-specific, and rule 9 remains absolute. |
| `internal/identity` | Workload identity and confidence foundation. | Syntactic identifiers must not be confused with cryptographically verified identity. |
| `internal/dashboard` and `dashboard/app` | Existing read models, flow drilldowns, topology, evidence, and console shell. | These are useful UI assets but not yet the CanaryPlatform incident/recommendation/action experience. |
| `internal/operator` | CanarySting desired-state and approved placement control plane. | It does not become the CanaryView intelligence plane. |
| `adapters/envoy` | Thin CanarySting adapter and future Envoy observation source. | Detection/decision logic stays out of the adapter. |
| `bpf/observe` | Passive kernel observation source. | `bpf/sockops` remains the CanarySting L7/kernel join; `bpf/enforce` remains Sting response. |
| `internal/llm/attacker`, `cmd/llm-attacker`, staged-range fixtures | Bounded-tool, budget, deterministic replay, and lab-ground-truth precedents. | Current code is Anthropic/demo-specific and is not the planned DGX Ollama/Qwen CanaryAttacker contract. Do not duplicate useful safety mechanisms. |
| `internal/contract` | Existing CanarySting runtime contract. | Do not stretch it into the platform model until the neutral package boundary is reviewed. |
| `internal/topology` | No current package; naming moved to `internal/identity/naming`. | Do not recreate this retired container solely for the new product name. |

## Phased implementation philosophy

1. Finish the already-sequenced DGX harness and CanarySting socket/enforcement proofs (M1B.6, M1C, M1D).
2. Review the M2A.0 storage/data-lifecycle architecture gate without selecting or implementing a production backend.
3. Review and implement the smallest CanaryView observation/evidence/provenance/confidence contracts.
4. Prove local correlation with the systems already available in the DGX lab; build the first operator trace slice at the same time.
5. Add the bounded Ollama/Qwen CanaryAttacker and compare correlation against emitted ground truth.
6. Extend the graph and evidence-backed canary-placement recommendations.
7. Complete the CanarySting Kubernetes vertical slice using CanaryView observations where appropriate.
8. Expand human and read-only agent interfaces, then vendor collectors, then controlled cross-vendor action.

Working runtime components are refactored only when a future implementation task benefits from it. Product naming alone is not justification for a source move or mass rename.

## Current alignment findings

- `docs/ARCHITECTURE.md` describes CanarySting, not the whole future platform. Scoping it as the Sting subsystem resolves the naming overlap without changing its runtime intent.
- `docs/BUILD_TASK_PLAN.md` and the Kubernetes architecture documents remain useful pivot design records, but their old milestone order is superseded for execution by `docs/DEVELOPMENT_PLAN.md`. Their Kubernetes-only “current phase” is compatible with the DGX-first roadmap; it must be revisited before M6 vendor collectors expand beyond that phase.
- `internal/identity/mesh.ParseSPIFFE` currently assigns `ConfidenceVerified` after URI parsing without carrying cryptographic peer/trust-chain proof. That is not sufficient for the CanaryView `VERIFIED` assertion or the existing mesh-first safety wording. M3.2 must separate syntactic parsing from verified identity; this bootstrap does not change runtime behavior.
- The existing dashboard has strong flow/topology/credibility/evidence building blocks, but its navigation and technical framing do not yet meet the unified Incident/Recommendation/Action contracts or interaction budgets. M2B.5 begins the incremental operator slice.
- Existing scoped intelligence types are valuable CanarySting evidence but do not represent passive cross-vendor observations, correlations, cases, recommendations, and actions. The ownership split remains an explicit M2A review decision.
- The existing Anthropic LLM attacker is bounded and useful, but it is not the Ollama/Qwen CanaryAttacker or the proposed intent/action ground-truth harness. Future work should reuse its safe fixed-target/budget/replay mechanisms without disrupting it.
- The authoritative user baseline says M1B.5 is complete, while this checkout still contains a fail-closed collection scaffold and no detailed evidence. The plan preserves the completion state and records the reconciliation gap rather than fabricating or replaying evidence.
- M1B.7 was already `DONE` in the checked-out plan, despite the prompt describing it as an expected next task. Its completion was preserved; this architecture bootstrap only evolved the environment document.
- Current persistence is a set of useful CanarySting stores rather than one CanaryView lifecycle system: bbolt event/audit state has no general retention service, topology/deviants use 30-day TTLs, L7 evidence has a nominal TTL without a production periodic caller, NDJSON spools do not rotate or acknowledge, and feature/cross-scope ledgers are in memory. These facts are mapped in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`; no production database was selected here.

## Open architecture questions

These questions are intentionally recorded rather than guessed. They do not block this architecture bootstrap.

1. Where should the canonical CanaryView model live in the Go package hierarchy?
2. How much of `internal/intelligence` belongs to CanaryView versus remaining a CanarySting evidence source?
3. Should `internal/engine/observebaseline` topology storage become the first CanaryView graph backend or feed a separate graph representation?
4. Which production storage engines should back normalized observations, relationship history, security cases, audit records, and model features?
5. What volume, latency, and cost targets apply to each data class and collector?
6. Which customer retention overrides and regulated profiles should the product support?
7. How are correlation windows selected, extended, and closed?
8. What is the calibrated identity-resolution confidence model?
9. How are NAT and proxy translations represented without losing either tuple?
10. Should OpenTelemetry trace semantics be reused directly, extended, or mapped only at ingestion?
11. What graph persistence, reconstruction, compaction, and historical-query semantics support provenance, scope isolation, expiry, and bounded queries?
12. Which APIs are shared by human and agent consumers, and where do view-specific projections begin?
13. What is the final `CanaryPlacementRecommendation`/`CanaryOpportunity` wire contract?
14. How does CanaryView deliver an approved recommendation to CanarySting without circular dependencies?
15. What is the long-term authorization model for vendor actions and delegated agents?
16. What conditions trigger a minimum-evidence snapshot before a raw vendor event expires?
17. How does deletion propagate through traces, graph edges, cases, features, recommendations, and model artifacts?
18. Which data-residency and encryption-key boundaries apply per tenant?
19. Who may create, review, release, and audit a legal hold?
20. How are operational retention permission and model-use permission represented and enforced separately?
21. How does historical evidence age or receive lower weighting in current behavior models?
22. How does CanaryView report broken raw-event references after the source system expires or deletes the underlying data?
