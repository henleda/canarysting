# CanaryPlatform Product Validation Plan

Status: parallel product-discovery track. This plan gathers evidence; it does not change runtime behavior, authorize DGX mutation, or replace the development plan.

## Objective

Test whether View-first, connector-first adoption reduces deployment friction while preserving demand for evidence-grounded intelligence, managed deception, and optional precise response. Avoid rewriting strategy after one conversation.

## Interview cohort

Run 12–15 structured interviews across:

- CISOs;
- SOC leaders;
- network security operators;
- cloud security leaders;
- platform engineering leaders;
- midmarket security leaders; and
- enterprise security architects.

Track role, organization segment, workload estate, existing control stack, buying authority, deployment authority, and stated constraints without retaining unnecessary identifying details.

## Concepts to test

Present the same four deployment profiles in consistent order:

1. CanaryView SaaS using vendor APIs and existing telemetry only.
2. CanaryView SaaS plus one Site Gateway.
3. CanaryView plus selected managed canary assets.
4. CanaryView plus a local response runtime or native action adapters.

Do not describe managed canary assets as agents. Do not lead with Kubernetes, eBPF, or a DaemonSet unless the participant's environment makes that implementation relevant.

## Structured questions

- Which deployment profile would architecture review approve?
- Which profile would security leadership reject?
- Which privileges create concern?
- Who owns deployment and upgrades?
- How long would approval take?
- Which canary forms face the least resistance?
- Would the team buy CanaryView without CanarySting?
- Which outcome receives budget?
- Would evidence-grounded recommendations change the buying decision?
- Which actions would the team approve through CanaryPlatform?
- Which actions must remain in the native vendor console?
- Which data may leave the environment, and which requires a gateway or federated reference?
- Who owns the operator workflow and acts on recommendations?

Test budget and workflow ownership for:

- cross-stack security tracing;
- east-west API intelligence;
- workload and identity mapping;
- blast-radius analysis;
- dark reachability;
- telemetry-gap analysis;
- agentic explanation;
- agentic recommendations;
- managed deception; and
- local containment.

## Evidence record

For each interview record:

- participant role and segment;
- deployment profile accepted/rejected and reason;
- privilege and approval concerns;
- deployment/upgrade owner;
- estimated approval time;
- current systems and SIEM relationship;
- top three valued outcomes;
- budget owner and stated willingness, separated from enthusiasm;
- acceptable canary forms;
- acceptable action authority;
- required native-console actions;
- quotations only when consented and de-identified;
- interviewer interpretation and confidence, visibly distinct from participant statements;
- contradictory evidence and open follow-up.

Use aggregate patterns across roles and segments. One interview is a signal, not a strategy decision.

## Decision rules

- If buyers value CanaryView and reject local components, lead with Profile 1.
- If buyers accept one Site Gateway and reject per-workload software, lead with Profile 2.
- If buyers accept credential, route, identity, and data canaries but reject service runtimes, prioritize low-footprint Profile 3 assets.
- If Kubernetes components receive support only in cloud-native accounts, treat Kubernetes as a segment-specific deployment option.
- If agentic insight receives enthusiasm without budget, deployment approval, or workflow ownership, treat it as an experience feature rather than the business model.
- If users accept recommendations but insist actions remain native, prioritize evidence, preview, and deep linkage over write adapters.
- If cross-stack tracing lacks a budget owner, test whether blast radius, telemetry gaps, managed deception, or response precision creates the funded outcome.

## Validation thresholds

After 12–15 interviews, summarize by role and segment:

- architecture-review acceptance rate by profile;
- rejection reasons and privilege thresholds;
- median/qualified approval-time estimates;
- standalone CanaryView purchase interest with named budget owner;
- canary-form acceptance ranking;
- agentic insight enthusiasm versus budget/workflow ownership;
- actions approved through CanaryPlatform versus native-only;
- Kubernetes relevance by estate;
- SIEM complement versus perceived duplication;
- evidence supporting or contradicting each strategic decision.

Do not claim product-market validation from interest alone. A strong signal combines a valued outcome, identifiable owner, deployment approval path, acceptable data/privilege boundary, and credible budget.

## Governance and next decision

The product-validation track runs alongside, not inside, engineering milestones. It may reorder unstarted work only through an explicit plan update that preserves completed evidence and records the supporting interview pattern. It must not reset M1C/M1D, weaken CanarySting invariants, bypass the M2A.0 lifecycle gate, or begin vendor connector implementation from interview interest alone.

At review, choose and record:

- lead deployment profile by target segment;
- minimum viable evidence sources;
- first funded operator outcome;
- acceptable local footprint;
- first managed asset forms;
- agentic operations that improve the primary workflow;
- actions that remain native versus candidates for controlled adapters; and
- whether direct merge/nightly learning or a fully qualified promotion path matches the product's operational risk.
