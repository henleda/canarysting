# CanaryPlatform Architecture

Status: approved architecture baseline (M2A.0.4, 2026-09-01) with the M2A.1 canonical-model boundary recorded. This document defines product boundaries and dependency direction. It does not rename packages, change runtime behavior, or claim that planned capabilities exist.

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

The graph view is rebuildable and cannot become the only truth. Immutable/versioned observations plus append-only relationship assertions, retractions, validity intervals, provenance, and lifecycle events are authoritative; graph/search/trace projections carry a high-water mark and digest and are reconstructable. Operational retention permission is separate from both per-tenant and cross-tenant model-use authorization, which default off until explicitly granted. Cross-tenant learning additionally requires de-identification, a declared cohort, residency, purpose, lineage, and deletion controls. Synthetic CanaryAttacker evidence is isolated by internal domain, residency/key/registry namespace, and evaluation path and never silently enters production baselines or customer models.

Every durable record belongs to one tenant and approved residency cell and carries a purpose-scoped logical key reference. Backups stay in the same boundary unless an explicit migration/multi-region policy is approved; restores replay the deletion ledger before service. Legal-hold roles do not grant evidence access, and Regulated hold creation/release requires separation of duties. The common lifecycle fields, accepted logical truth/rebuild and governance contracts, cost-estimation inputs/outputs, recommended profiles, deletion objectives, and remaining backend decisions are defined in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`. M2A.0 approved that architecture before M2A implements the canonical model.

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
| `internal/engine/observebaseline` topology store | Sole local source for current socket-cookie-attributed OBSERVED topology; it feeds canonical observations/relationship history through a one-way adapter. | Rule 10 forbids a second capture or attribution truth. Its bounded, expiring current-state store is not the CanaryView graph/history backend. |
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
2. Apply the approved M2A.0 storage/data-lifecycle architecture without selecting or implementing a production backend by implication.
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
- Current persistence is a set of useful CanarySting stores rather than one CanaryView lifecycle system: bbolt event/audit state has no general retention service, topology/deviants use 30-day TTLs, L7 evidence is capped and receives hourly TTL reap only when the optional SIEM drainer is enabled, NDJSON spools do not rotate or acknowledge, and feature/cross-scope ledgers are in memory. These facts are mapped in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`; no production database was selected here.

## M2A.0.4 architecture approval record

The 2026-09-01 review approved the platform, canonical-model, operator-experience, and storage/retention contracts as the architecture baseline for M2A implementation. Approval means implementations must preserve the following boundaries; it is not approval of a backend, runtime behavior, new collection, credential authority, or customer-side component.

| Review lens | Approved contract | Implementation boundary |
|---|---|---|
| Product and deployment | CanaryView remains useful in Profile 1 through connector-first, read-only evidence; Site Gateway, managed assets, and local response remain progressive and optional. | No local component or higher profile is inferred from persistence or canonical-model work. |
| Evidence and truth | Source reports remain immutable/versioned observations; append-only relationship assertions and lifecycle events are authoritative; graph, trace, search, summary, feature, and model projections remain rebuildable or explicitly invalidated. | No graph-only truth, provenance erasure, source-claim rewrite, or parallel observation path. |
| Lifecycle and governance | Data class, sensitivity, trusted retention clock, expiry state, exact lineage, tenant/scope, residency cell, purpose-key reference, hold state, and separate operational/per-tenant/cross-tenant model-use authority remain explicit. | No hold implies access or model use; no retention grant implies training; deletion cannot report success while protected copies remain unresolved. |
| Operator contract | Profile consequences are visible before approval; Standard uses the accepted concrete defaults; hold/model-use permissions are separate; lifecycle detail stays one click from a claim. | No YAML, query, CLI, prompt, hidden authority, or ambiguous expired-versus-deleted state in the core workflow. |
| Implementation restraint | The logical layers, reconstruction checks, deletion/restore objectives, synthetic isolation, and estimation contract are approved across Profiles 1–4. | Production engines, regions/DR pairs, physical tenancy, CMK products, identity-provider mappings, source manifests, and measured capacity/cost targets require later evidence and approval. |

The open questions below are therefore implementation decisions, not gaps that permit weakening the approved contracts. M2A.1 resolves the package/reuse/API boundary it names before code is introduced; later tasks resolve backend-, source-, identity-, correlation-, and authorization-specific choices at their declared gates.

## M2A.1 canonical model boundary and reuse decision

The 2026-09-01 M2A.1 review accepts `internal/canaryview/model` as the future Go source of truth for the minimum vendor-neutral CanaryView domain model. The package does not exist yet; M2A.2 creates only the approved minimum contracts. The model package will import only the Go standard library. It must not import CanarySting engine, contract, intelligence, adapter, dashboard, Kubernetes/vendor SDK, transport, or persistence packages.

`internal/contract` remains the narrow CanarySting `FlowIdentity` plus `SignalEvent` in / `Verdict` out runtime seam. It is not renamed, moved, or expanded into the platform model. Likewise, `canarysting.v1` remains the existing Sting wire contract. A future external CanaryView transport begins in a separate versioned namespace, `api/proto/canaryview/v1` with protobuf package `canaryview.v1` and generated package `api/gen/canaryview/v1`. The Go domain model is the semantic source of truth; explicit conversion code and round-trip/drift tests keep the transport contract aligned. Additive compatible fields may remain in v1. A breaking semantic or knowledge-state change requires v2 and explicit translators. Every durable record also carries its own `schema_version`; correction appends or supersedes a record rather than rewriting the original source report.

Dependency direction is one way:

```text
source/runtime packages
  (connectors, observebaseline, identity, Sting intelligence/audit)
                    |
                    v
        source-specific integration adapters
                    |
                    v
        internal/canaryview/model  (stdlib only)
                    |
                    v
      CanaryView application/query services
          |                         |
          v                         v
 human view projections      structured agent/API projections

approved CanaryOpportunity + immutable ActionPlan version
                    |
                    v
 CanaryView-to-Sting integration adapter -> existing Sting control plane
```

Neither CanarySting runtime packages nor `internal/contract` import CanaryView. Translation and approved-plan delivery live in outer integration/composition packages that may depend on both sides. CanaryView application/query services expose the same domain objects, evidence, confidence, authorization state, and audit identity to human and agent consumers. UI-shaped and transport-shaped projections begin outside `model`; they may format or omit fields for progressive disclosure but cannot create a second interpretation, evidence path, or authority path.

### Accepted and rejected reuse

| Existing area | Accepted reuse | Rejected ownership or coupling |
|---|---|---|
| `internal/engine/observebaseline` | Remains the sole local source for current, socket-cookie-attributed `OBSERVED` topology under rule 10. A one-way adapter may emit canonical observations and relationship assertions from its snapshots or future deltas without duplicating capture or attribution. | It is not the CanaryView graph/history backend: its 4,096-node/edge caps, 30-day TTL, local-rich addresses, and current-state folding cannot provide immutable provenance or append-only lifecycle history. A downstream canonical history is not a second attribution source. |
| `internal/identity` | Reuse mesh-first resolution, proof/source vocabulary, and explicitly lower-confidence fallback semantics through an adapter. | Current `WorkloadID`, naming, and `scopemap` types are not canonical cross-vendor identity/entity contracts. Syntactic SPIFFE parsing never becomes CanaryView `VERIFIED`; live trust evidence is required. Sting scope mapping does not become tenant authority. |
| `internal/intelligence` events/stores | Treat canary interaction, L7, profile, cost, reconnaissance, feed, and related outputs as Sting-owned evidence producers that can be normalized through adapters. | Do not wholesale move or relabel them as CanaryView. Touch-dependent events are not passive observations, their stores are not the canonical evidence repository, and Sting learned state remains scope-local. |
| `internal/intelligence/audit` | Reuse its hash-chain, high-water, verification, and tamper-evidence design patterns where the later platform audit implementation benefits. | Do not reuse `AuditRecord` as the canonical audit schema or its current store as lifecycle-complete platform audit storage. It carries local-rich Sting decision fields and different retention/access semantics. |
| `internal/intelligence/network` | Preserve it as the single default-deny egress chokepoint for Sting-derived cross-deployment patterns. | It is not general CanaryView connector transport and must not be bypassed by a model or adapter. |
| `internal/intelligence/transport` and `siem` | Reuse bounded-delivery and outward-projection lessons. | Neither becomes the Site Gateway spool, connector SDK, canonical API, or canonical store. |
| `internal/dashboard` and `dashboard/app` | Reuse console shell, drilldown, credibility, topology, and presentation patterns. | Existing JSON/view structs remain projections; they do not become canonical records, and the dashboard must not continue direct source-package coupling for new CanaryView workflows. |
| `api/proto/contract.proto`, `api/convert`, `api/enginegrpc` | Reuse explicit conversion and round-trip testing patterns. | Do not add CanaryView concepts to `canarysting.v1` or make transport-generated types the domain source of truth. |

The lifecycle envelope's value types belong in `internal/canaryview/model` and are composed into every durable canonical record. They express tenant/scope, class/sensitivity, retention clock and expiry, lifecycle/hold state, residency cell, purpose-key reference, lineage, model-use grants, and synthetic state. Policy evaluation, authorization, persistence, expiry work, deletion retries, projection rebuilds, and backend-specific enforcement belong to later application/repository services. A source adapter cannot claim lifecycle compliance merely because its source store has a TTL; canonical persistence is refused until the reviewed envelope is complete. This decision selects no storage engine.

`CanaryOpportunity` is the canonical domain and wire name. `CanaryPlacementRecommendation` is an operator-facing `Recommendation` projection that references one immutable, versioned `CanaryOpportunity`; it is not a second placement object. After preview and human approval, an outer CanaryView-to-Sting integration adapter delivers the immutable opportunity and approved `ActionPlan` version to the existing CanarySting control plane. CanarySting alone selects and materializes the safe asset form and reports placement/outcome evidence back through the intake adapter. This preserves one-way dependencies, separate authority, and the rule that initial placement is never automatic.

## Architecture decision and open-question ledger

This numbered ledger preserves both M2A.1 decisions and the choices still intentionally open; later work must not reopen a resolved boundary incidentally. M2A.0.2 accepted lifecycle policy. M2A.0.3 accepted the logical truth/rebuild model, tenant/residency/purpose-key and same-cell backup boundaries, hold governance, zero-tolerance default model rebuild gate, synthetic isolation, supported override categories, deletion/restore objectives, and estimation contract in `docs/CANARYVIEW_STORAGE_AND_RETENTION.md`. Unresolved entries are implementation-, source-, or product-specific choices for their declared gates.

1. **Resolved by M2A.1:** the canonical Go model will live at `internal/canaryview/model` as a standard-library-only leaf; `internal/contract` remains the narrow Sting runtime seam.
2. **Resolved by M2A.1:** `internal/intelligence` remains Sting-owned; its outputs may feed CanaryView through one-way adapters and selected integrity/delivery patterns may be reused without reusing its source-specific schemas or stores.
3. **Resolved by M2A.1:** `observebaseline` remains the sole local OBSERVED attribution source and feeds canonical relationship history through an adapter; its bounded current-state topology is not the CanaryView graph/history backend.
4. Which production storage engines should back normalized observations, relationship history, security cases, audit records, and model features?
5. What measured volume, latency, rebuild-time, and unit-cost targets apply to each data class and collector once M2B exposes the accepted counters and size distributions?
6. Which organization/regulation-specific maxima and concrete Regulated periods should be supported within the accepted override catalog?
7. How are correlation windows selected, extended, and closed?
8. What is the calibrated identity-resolution confidence model?
9. How are NAT and proxy translations represented without losing either tuple?
10. Should OpenTelemetry trace semantics be reused directly, extended, or mapped only at ingestion?
11. Which engine and physical checkpoint/compaction strategy best implements the accepted relationship-history reconstruction contract and bounded historical queries?
12. **Resolved by M2A.1:** human and agent consumers share CanaryView application/query services and canonical evidence, confidence, authorization, and audit semantics; UI and transport projections begin outside `internal/canaryview/model` and confer no extra authority.
13. **Resolved by M2A.1:** `CanaryOpportunity` is the canonical domain/wire object; `CanaryPlacementRecommendation` is a `Recommendation` projection that references it, not a second placement contract.
14. **Resolved by M2A.1:** an outer integration/composition adapter delivers an approved immutable opportunity and exact `ActionPlan` version to CanarySting; neither core package imports the other and `internal/contract` is not broadened.
15. What is the long-term authorization model for vendor actions and delegated agents?
16. Which source/category-specific field manifests implement the accepted minimum-snapshot triggers without copying excess payload?
17. Which backend mechanisms prove the accepted online deletion, backup aging, restore-ledger replay, key-destruction, and zero-tolerance default model-rebuild objectives?
18. Which physical regions, disaster-recovery pairs, single-tenancy options, rotation periods, and customer-managed-key products implement the accepted logical boundaries?
19. Which identity-provider groups and approval integrations map to the accepted lifecycle administrator, hold creator/reviewer/releaser, protected-reader, and auditor roles?
20. Which policy and registry APIs implement the accepted separate operational, per-tenant model-use, and cross-tenant model-use grants?
21. Which feature-specific windows or deterministic decay functions should be approved beyond the accepted requirement that every feature declare and test one?
22. How does each connector detect moved or integrity-mismatched source references and distinguish those states from expiry, deletion, or access denial?

Connector SDK, execution-location, credentials, schema evolution, certification, licensing, regional deployment, telemetry coverage, and multi-adapter conflict/rollback questions are recorded without duplication in `docs/CANARYVIEW_CONNECTOR_ARCHITECTURE.md`.
