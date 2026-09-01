# CanaryPlatform Architecture

Status: architecture baseline for review. This document defines product boundaries and dependency direction. It does not rename packages, change runtime behavior, or claim that planned capabilities exist.

## Product definition

CanaryPlatform is one security operations product family. CanaryView leads the product and default adoption path; local capabilities are progressive and optional. Its major systems are:

- **CanaryView Core** is the central SaaS, vendor-neutral security intelligence plane. It registers connectors; ingests and normalizes evidence; resolves identity and translations; constructs security traces and the intelligence graph; exposes provenance and confidence; produces `SecurityCase`, `Explanation`, `ImpactAssessment`, `Recommendation`, and `ActionPlan`; operates the console and evidence-grounded agentic operations; and governs retention, connector health, and telemetry gaps.
- **Canary Site Gateway** is an optional single local component per approved site, cluster, cloud account, private network, or trust zone. It supplies outbound connectivity, private-source access, bounded buffering, preprocessing, policy/configuration cache, controlled action delivery, health reporting, and residency enforcement. It is not a per-workload agent.
- **CanarySting Managed Assets** are optional programmable canary assets and active-sensing capabilities. Lower-footprint honeytokens, credentials, routes, API endpoints, data objects, synthetic identities, and external decoys precede broader runtime placement.
- **CanarySting Local Response** is optional and separately authorized. It retains the implemented deception, high-confidence detection, precise containment, and bounded-response system and all eleven architectural rules.
- **CanaryAttacker** is the internal bounded synthetic-adversary and validation harness. It produces declared intent and executed-action ground truth so CanaryView correlation can be measured rather than merely demonstrated.

The systems are modular in code and responsibility but unified in the operator experience. Operators use one CanaryPlatform console; they should not have to reconstruct an incident by moving among vendor portals or by understanding socket cookies, BPF maps, CRDs, YAML, or raw event schemas.

The four progressive commercial deployment profiles are defined in `docs/CANARYPLATFORM_DEPLOYMENT_PROFILES.md`. Profile 1 requires no new customer-side CanaryPlatform data-plane software. A higher profile is chosen only when its additional value justifies its footprint and authority.

`AGENTS.md` remains authoritative for coding and safety invariants. `docs/ARCHITECTURE.md` remains the detailed CanarySting subsystem specification. This document adds the broader product boundary without weakening either.

The category contracts, collector/capability/action separation, connector operating model, and M6/M7 sequencing are defined in `docs/CANARYVIEW_CONNECTOR_ARCHITECTURE.md`.

## Responsibility and boundary map

| System | Owns | Does not own |
|---|---|---|
| CanaryView | Canonical intelligence concepts; normalized observations; evidence and provenance; identity and security-trace correlation; explicit confidence and disagreement; reachability and attack-path analysis; explanations; impact assessments; recommendations; action previews; lifecycle-governed intelligence storage; connector capability/health/coverage; telemetry-gap detection; human and agent read interfaces. | Vendor configuration, native vendor control planes, unnecessary duplication of raw telemetry, CanarySting scoring/tiering, automatic enforcement, or arbitrary mutation of source systems. |
| Canary Site Gateway | Approved private-source access; outbound secure connection; bounded local spool; preprocessing/minimization; policy/configuration cache; controlled delivery; residency and health enforcement. | Per-workload endpoint behavior, hidden data egress, detection/scoring logic, or implicit write authority. |
| CanarySting Managed Assets | Canary definitions, materialization, lifecycle, touch evidence, cleanup, and selected deployment forms. | A requirement that every asset use Kubernetes, eBPF, a proxy, or local runtime. |
| CanarySting Local Response | Proxy-neutral scoring; canary-touch signals; tiered verdicts; precise eBPF/native containment; bounded attrition; kill switch; scoped response evidence and audit. | General cross-vendor intelligence-plane availability or unapproved execution of CanaryView recommendations. |
| CanaryAttacker | Lab-scoped scenarios; bounded attacker tools; local model orchestration; declared `AttackerIntent`; recorded `AttackerAction`; cleanup; reproducible correlation ground truth. | Production telemetry truth, unrestricted shell access, unconstrained targets, or operational authority. |
| Vendor control planes | Native configuration, policy, enforcement, health, and vendor-specific source records. | Cross-stack correlation or the CanaryPlatform canonical interpretation. |

## Dependency principle

CanaryView must provide useful intelligence without CanarySting or new customer-side data-plane software. Its default collectors use vendor APIs, event streams, log pipelines, cloud-native integrations, SIEM integrations, and customer-owned telemetry stores. A Site Gateway is introduced only when direct SaaS connectivity, buffering, residency, private access, preprocessing, or controlled delivery requires it. CanarySting may consume approved CanaryView recommendations and publish its observations back to CanaryView. CanaryAttacker publishes ground truth to CanaryView but is never a trusted telemetry source. No circular Go package dependency should be introduced.

If implementation later needs shared contracts, place them at a neutral boundary only after the canonical-model architecture is reviewed. Do not broaden `internal/contract/` automatically: it is currently the deliberately narrow CanarySting flow/signal/verdict contract and remains authoritative for that runtime seam.

```text
  edge/WAAP   firewall/SASE   workload/runtime   endpoint/identity   cloud/data/SOC
       \             |                |                  |                 /
        +------------+----------------+------------------+----------------+
                                      |
                         read-only Evidence Collectors
                                      |
                                      v
                               +--------------+
                               |  CanaryView  |
                               | correlate    |
                               | explain      |
                               | recommend    |
                               +------+-------+
                                      |
                         proposed SecurityIntent + capability check
                                      |
                           vendor-native ActionPlans
                                      |
                           exact preview + human approval
                                      |
                     +----------------+----------------+
                     v                                 v
               CanarySting                    native action adapters
              place/detect/respond             (M7, separately authorized)
                     |
              evidence + outcome
                     +-------------------------------> CanaryView

  CanaryAttacker -- intent/action ground truth ------> CanaryView evaluation
```

An agent consumes the same evidence, confidence, recommendation, authorization, and action contracts as a human. It receives no hidden authority path.

## Relationship to vendor control planes

Cilium retains Cilium CLI, Hubble, and Cilium policy/configuration. Edge, firewall/SASE, endpoint/XDR, identity, cloud, data-security, SIEM/SOAR, observability, ITSM, Kubernetes, and service-networking products retain their native control planes. CanaryView sits above these systems to answer “What happened across the security stack?”

Vendor-specific identifiers and decision details remain attached as evidence. They must not leak into the canonical model as required fields. A connector may expose native deep links, but the normal incident workflow stays in CanaryPlatform and includes the supporting evidence and a concrete next step.

Collectors are read-only by default, their capability and health are product data, and passive onboarding does not request write credentials. Read and write authority remain separate. CanaryView may eventually delegate an approved action to a native control plane only through a capability-declared Action Adapter. Delegation requires exact preview, human approval, action provenance, native change identity, validation, expiration, rollback, and audit. A recommendation or `SecurityIntent` is never itself an action.

## Relationship to the SIEM

The SIEM remains the broad telemetry, alert, incident-record, hunting, compliance, and long-term search system. CanaryPlatform models and operates the cross-control workload security journey. SIEM evidence, identity events, incidents, threat intelligence, searches, and compliance records may enter CanaryView; enriched cases, traces, evidence references, impact assessments, canary touches, recommendations, approved plans, executions, and rollback results may return.

CanaryView must not collapse into a log-ingestion/rule/incident clone. Its differentiated responsibilities are explicit evidence provenance, identity and translation resolution, active ground truth, programmable canary assets, placement intelligence, the security-journey graph, precise optional response, and coordinated vendor-native plans.

## Deployment posture

The deployment profiles progress from CanaryView SaaS, to optional Site Gateway, to managed assets, to separately authorized local response. Kubernetes is the first CanarySting reference runtime and DGX laboratory, not the CanaryPlatform product boundary. The Kubernetes operator, DaemonSet, Cilium/Hubble, Envoy, eBPF, socket-cookie work, cookiespike, and enforcespike remain strategically valuable for Profiles 3 and 4.

## Passive and active value

| Mode | Available capability |
|---|---|
| Passive CanaryView | Connector-first cross-stack security-flow visualization, distributed security tracing, topology, identity mapping, policy-decision correlation, dark-reachability analysis, blast-radius estimates, provenance, disagreement, telemetry-gap detection, impact assessment, and evidence-grounded explanation/recommendation without new data-plane software. |
| CanaryView plus approved CanarySting placement | Evidence-backed canary opportunities are previewed and approved; CanarySting decides the safe materialization details and reports placement state. |
| Canary touch | CanarySting supplies high-confidence deception evidence and a verdict; CanaryView adds the event to the correlated trace and adversarial graph. |
| Approved response | CanaryPlatform presents an action plan; an authorized control plane executes it; CanaryView records result, validation, and rollback state. |

CanarySting is not a prerequisite for CanaryView adoption. Cilium/Hubble, Envoy, Kubernetes, and kernel telemetry in the DGX lab are sufficient for the first passive proof.

## Security distributed tracing

A security trace is an evidence-backed journey, not an assumption that every source emits one application trace ID. A journey may span edge/WAAP, firewall and NAT, cloud, identity, endpoint, Kubernetes/service networking, workload/process/socket, data security, a canary touch, and response across competing vendor families.

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

Agentic operations are an experience layer over the common evidence model. Initial operations explain traces/paths, summarize cases, find missing or conflicting evidence, assess impact, find dark reachability and canary opportunities, recommend a next step, generate an action preview, and explain expected impact and rollback. Each conclusion cites evidence and separates deterministic facts from model interpretation. Natural language supplements rather than replaces the visual console.

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
| M2B collector contract and DGX/local source adapters (planned) | Minimal read-only CanaryView intake seam and first correlation proof. | M6A extends and productizes this seam with capability manifests, health, certification, and onboarding; it does not create a parallel framework or replay M2B. |
| `internal/intelligence/transport` and `internal/intelligence/siem` | Existing pattern-spool and deployment-local SIEM-emitter precedents. | Neither is the general CanaryView connector SDK or canonical model; reuse lessons without inheriting source-specific semantics. |

## Phased implementation philosophy

1. Preserve completed M1C/M1D socket-cookie and precise-enforcement proofs as option-preserving technical evidence.
2. Review the M2A.0 storage/data-lifecycle architecture gate without selecting or implementing a production backend.
3. Implement the minimum CanaryView evidence model and operator contracts.
4. Establish the read-only connector framework and Wave 0 collectors for existing sources.
5. Build cross-tool correlation and the first operator-readable trace alongside backend work.
6. Add bounded CanaryAttacker ground truth and measure correlation quality.
7. Ship evidence-grounded read-only agentic insights and their visual operator workflow.
8. Extend the intelligence graph and then evidence-backed, low-footprint canary placement.
9. Add optional CanarySting deployment forms in increasing order of customer-side footprint; Kubernetes/eBPF remain reference implementations, not prerequisites.
10. Expand the operator experience, structured agent interface, category connector waves, and controlled cross-vendor actions.

Working runtime components are refactored only when a future implementation task benefits from it. Product naming alone is not justification for a source move or mass rename.

## Current alignment findings

- `docs/ARCHITECTURE.md` describes CanarySting, not the whole future platform. Scoping it as the Sting subsystem resolves the naming overlap without changing its runtime intent.
- `docs/BUILD_TASK_PLAN.md` and `docs/ARCHITECTURE_SPEC_K8S.md` remain useful historical/reference-profile records for Kubernetes local response. Their Kubernetes-only product and milestone wording is superseded by this View-first architecture and `docs/DEVELOPMENT_PLAN.md`; it is retained to explain the option-preserving design decisions rather than silently rewritten as current commercial scope.
- `internal/identity/mesh.ParseSPIFFE` currently assigns `ConfidenceVerified` after URI parsing without carrying cryptographic peer/trust-chain proof. That is not sufficient for the CanaryView `VERIFIED` assertion or the existing mesh-first safety wording. M3.2 must separate syntactic parsing from verified identity; this bootstrap does not change runtime behavior.
- The existing dashboard has strong flow/topology/credibility/evidence building blocks, but its navigation and technical framing do not yet meet the unified Incident/Recommendation/Action contracts or interaction budgets. M2B.5 begins the incremental operator slice.
- Existing scoped intelligence types are valuable CanarySting evidence but do not represent passive cross-vendor observations, correlations, cases, recommendations, and actions. The ownership split remains an explicit M2A review decision.
- The existing Anthropic LLM attacker is bounded and useful, but it is not the Ollama/Qwen CanaryAttacker or the proposed intent/action ground-truth harness. Future work should reuse its safe fixed-target/budget/replay mechanisms without disrupting it.
- M1B.5 is complete: the missing collector was recovered, negative-tested, and validated with recorded DGX evidence. The post-meeting re-baseline preserves that completion and does not replay or reinterpret it.
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

Connector SDK, execution-location, credentials, schema evolution, certification, licensing, regional deployment, telemetry coverage, and multi-adapter conflict/rollback questions are recorded without duplication in `docs/CANARYVIEW_CONNECTOR_ARCHITECTURE.md`.
