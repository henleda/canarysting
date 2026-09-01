# CanaryPlatform Product Strategy

Status: post-meeting strategy baseline. This document changes product sequence and deployment posture, not current runtime behavior or the completion status of existing engineering.

## Strategic position

CanaryPlatform is a workload-security intelligence and response product family. **CanaryView leads**: the default adoption path is a read-only, connector-first CanaryView experience that produces cross-control security traces, identity and graph intelligence, impact assessments, explanations, and recommendations without requiring new customer-side data-plane software.

CanarySting remains strategic. It supplies programmable managed canary assets, high-confidence active ground truth, precise containment, and bounded response when a customer chooses those capabilities. It is not a prerequisite for CanaryView value or adoption. CanaryAttacker remains the internal bounded ground-truth laboratory, not the default customer product.

The default commercial sequence is:

1. CanaryView SaaS through existing vendor APIs, streams, log pipelines, SIEM integrations, and customer-owned telemetry stores.
2. One optional Canary Site Gateway where private access, buffering, residency, preprocessing, or controlled action delivery requires it.
3. Selected CanarySting managed canary assets where active ground truth improves the security journey.
4. Separately authorized local response or vendor-native actions where precise control justifies the additional footprint and authority.

The deployment profiles and their boundaries are defined in `docs/CANARYPLATFORM_DEPLOYMENT_PROFILES.md`.

## Product hierarchy

### CanaryView Core

The central SaaS intelligence plane owns connector registration and health, evidence ingestion and normalization, identity and translation resolution, cross-tool security traces, provenance, confidence, the intelligence graph, `SecurityCase`, `Explanation`, `ImpactAssessment`, `Recommendation`, `ActionPlan`, the operator console, evidence-grounded agentic operations, retention/governance, and telemetry-gap analysis.

CanaryView must remain useful without CanarySting. Its differentiated foundation is the common evidence model and relationship graph, not a language model by itself.

### Canary Site Gateway

The Site Gateway is an optional, single deployment unit per site, cluster, cloud account, private network, or trust zone when direct SaaS access is insufficient. It provides outbound secure connectivity, private connector access, bounded local buffering, evidence preprocessing, policy/configuration cache, controlled action delivery, health reporting, and data-residency enforcement.

It is not a per-workload agent. Every gateway proposal must explain why SaaS or an existing vendor integration is insufficient, the required privileges, deployment and upgrade owner, failure mode, removal path, support burden, and required profile.

### CanarySting Managed Assets

Managed assets are the optional active-sensing and deception layer. Lower-friction forms lead:

1. honeytokens and inert credentials;
2. decoy routes and API endpoints;
3. data-object canaries;
4. synthetic identities;
5. external decoy services;
6. Kubernetes Services and Deployments;
7. proxy- or workload-local placements where justified.

CanaryView creates evidence-backed `CanaryPlacementRecommendation`/`CanaryOpportunity` objects. An operator approves or dismisses them. CanarySting chooses the safe deployment form and returns placement, touch, lifecycle, cleanup, verdict, and outcome evidence.

Managed canary assets are never called agents.

### CanarySting Local Response

Local response is optional, separately authorized, and introduced only when the value requires it. Implementations may include proxy response, Cilium policy action, vendor-native adapters, precise eBPF flow containment, rate limiting, connection jail, or cgroup/workload containment. Read-only collector credentials and write-capable response credentials remain separate.

All existing CanarySting safety invariants remain binding: canary-touch-only punitive triggering, precise attribution, scope isolation, bounded resource use, operator-selected posture, observe-before-enforce, and verified cleanup.

### CanaryAttacker

CanaryAttacker uses the DGX Spark and bounded Ollama/Qwen tools to generate declared `AttackerIntent` and `AttackerAction` ground truth for development and evaluation. It is not production telemetry, a customer-side endpoint agent, or a general penetration-testing system.

## Evidence-grounded agentic operations

Agentic operations are a first-class CanaryView experience layer over normalized evidence, provenance, confidence, identity, traces, policy decisions, graph relationships, historical cases, and action outcomes.

Initial read-only and recommendation-oriented operations are:

- `explain_trace`
- `explain_path`
- `summarize_case`
- `identify_missing_evidence`
- `identify_conflicting_evidence`
- `assess_impact`
- `find_dark_reachability`
- `find_canary_opportunities`
- `recommend_next_step`
- `generate_action_preview`
- `explain_expected_impact`
- `explain_rollback`

Later operations may simulate an action, request approval, execute an approved action, validate it, and propose rollback. They use the same evidence and action contracts as the visual console and have no hidden authority.

Every conclusion links to evidence. Every recommendation states its reason, confidence, expected result, affected scope, executing control plane, approval requirement, validation plan, and rollback plan. Deterministic facts and model-generated interpretation stay visibly distinct. Core workflows require no prompt engineering, and read-only insight ships before write-capable action.

## SIEM relationship

CanaryPlatform complements the SIEM rather than replacing it. The SIEM remains the broad security-event, alert, incident-record, hunting, compliance, and long-term search system. CanaryPlatform models and operates the complete workload security journey: cross-control evidence correlation, active ground truth, placement intelligence, identity and translation resolution, precise local response, evidence-grounded recommendations, and coordinated vendor-native actions.

SIEM to CanaryView inputs include historical telemetry, identity events, incidents, threat intelligence, search results, and compliance records. CanaryView publishes enriched `SecurityCase`, complete traces, evidence references, `ImpactAssessment`, `CanaryTouch`, `Recommendation`, approved `ActionPlan`, `ActionExecution`, and rollback results.

If CanaryView only copies logs, normalizes fields, applies rules, and creates incidents, it becomes another SIEM. Differentiation depends on the journey model, explicit provenance, active ground truth, programmable canary assets, placement intelligence, identity/translation resolution, precise local response, and coordinated native actions.

## Kubernetes position

Kubernetes is strategic but not universal. It remains the first reference implementation, the DGX integration laboratory, an east-west workload-intelligence environment, a Cilium/Hubble/Envoy/eBPF validation environment, and one CanarySting orchestration profile.

Kubernetes is not the CanaryPlatform market boundary, a required CanaryView deployment, the sole workload estate, or the lead business outcome. M1C and M1D remain valuable option-preserving proofs of precise attribution, kernel response, and Cilium coexistence. They do not commit every customer to a DaemonSet, operator, eBPF, proxy filter, or per-workload runtime.

## Differentiation

The defensible foundation is:

- a vendor-neutral common evidence model with explicit provenance and confidence;
- a security-journey and intelligence graph spanning identities, translations, controls, and actions;
- active ground truth from programmable managed canary assets;
- evidence-backed placement intelligence;
- precise, optional local response;
- native-control-plane action coordination with preview, approval, verification, expiry, and rollback; and
- bounded attacker ground truth for measurable correlation quality.

The model experience increases usability and speed. The model alone is not the moat.

## Product risks and decision rules

- If buyers value CanaryView but reject local software, lead with Profile 1.
- If they accept one gateway but reject per-workload software, lead with Profile 2.
- If they accept credentials, routes, identities, and data canaries but reject service runtimes, prioritize low-footprint Profile 3 assets.
- If Kubernetes components receive support only in cloud-native accounts, keep Kubernetes segment-specific rather than universal.
- If agentic insight creates enthusiasm without budget, deployment approval, or workflow ownership, treat it as an experience feature rather than the business model.
- If CanaryView cannot provide standalone read-only value, do not hide the gap behind CanarySting deployment.
- If a local component lacks explicit value, ownership, privilege, failure, support, and removal justification, do not make it the default.

Product validation and evidence thresholds are defined in `docs/CANARYPLATFORM_PRODUCT_VALIDATION_PLAN.md`. Strategy changes require evidence across multiple interviews; one conversation does not rewrite the baseline.
