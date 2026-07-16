# CanarySting — Control-Plane Architecture Sketch
### Data plane, control plane, the SaaS boundary, storage, install, tenancy, connectivity

**Status:** working draft, companion to the Kubernetes-Native Architecture Spec. This covers the SaaS control plane and the split between what runs in the customer's cluster and what runs in the vendor cloud. The cluster-side build docs say nothing about the SaaS yet, this fills that gap.

**The one reframe that governs everything here:** we do not build a log lake. Raw telemetry is reduced in the customer's cluster, and only derived, small, valuable state crosses to the SaaS. This keeps storage cost tractable, keeps the privacy posture that makes the product sellable to security teams, and honors the existing rules (scope isolation, rule 5; anonymized-only cross-boundary, rule 9). The graph, not a log archive, is the storage centerpiece.

---

## 1. Three planes, not two

- **Data plane (in cluster).** The per-node DaemonSet agents. eBPF observation, canary seeding, sting enforcement, socket-cookie attribution. Host-local, fast, and autonomous (see section 9). This is where raw flow data exists and where it stays.
- **In-cluster control plane (in cluster).** The operator plus a per-scope aggregator running in the customer's own environment. This is where the proxy-agnostic engine runs, where the blast-radius graph is assembled locally, where the baseline lives, and where raw telemetry is reduced to derived state. Critically, this stays in the customer's cluster. It is the thing that decides what is small and safe enough to send up.
- **SaaS control plane (vendor cloud).** Multi-tenant backend. Receives derived per-tenant state only. Hosts the dashboard, the cross-customer anonymized intelligence, the image/chart distribution, tenant and license management, and the update channel.

The reason for three planes rather than two: if you collapse the in-cluster control plane into the SaaS, raw telemetry has to leave the cluster to be reduced, which breaks the privacy posture and creates the log-lake cost problem. Reducing in-cluster is what makes the SaaS cheap and safe.

---

## 2. The boundary contract: what crosses, what never does

There are two distinct upward crossings, and keeping them separate is the sophisticated part of the design. They map directly onto the two existing rules.

### Crossing A — cluster to its own tenant space in the SaaS (per-tenant, isolated)

This powers that customer's own dashboard and blast-radius product. It is tenant-isolated and never shared.

Crosses up:
- Blast-radius graph deltas: nodes and edges as stable logical identifiers (identities, workloads, services, assets), not raw IPs or payloads.
- Scored encounters: canary touches, suspicion scores, response-tier actions, attributed to logical identity.
- Blast-radius metrics over time, dark-reachability summaries, and the numbers the dashboard shows.
- Cluster/agent health and version metadata.

Governed by rule 5 (scope isolation): this is one tenant's derived state, isolated from every other tenant in the backend.

### Crossing B — tenant space to shared intelligence (anonymized, the moat)

This is the cross-customer learning that compounds. It is the only thing that is ever shared across tenants, and it is shared precisely because it has been stripped of anything tenant-identifying.

Crosses up (through the single default-deny egress filter, `internal/intelligence/network/`):
- Anonymized adversarial fingerprints and path patterns.
- Anonymized attacker-behavior signatures and the derived priors that let a brand-new deployment rank danger before it has seen its own attacker.

Governed by rule 9 (only anonymized patterns cross between deployments). Nothing tenant-identifying, no topology, no raw data.

### What never crosses, ever (stays in the cluster)

- Raw east-west flow payloads and packet data.
- The learned baseline itself (the model of normal traffic).
- Decoy contents.
- Scope state, calibration internals, feedback labels.
- Observed secrets or credentials.
- Any environment-identifying raw detail.

If a design decision seems to require any of these to leave the cluster, stop. It is almost certainly wrong.

### Crosses down (SaaS to cluster)

- Signed agent and operator images and Helm charts, from the managed registry.
- Operator-authored configuration (strictness, sting floor, scope), distributed through the SaaS but authored by the customer.
- Anonymized cross-customer intelligence priors, to bootstrap a new deployment's danger ranking.
- Updates, tenant identity, licensing.

Downward config that changes enforcement posture is validated and authorized by the in-cluster operator before it is applied. The cluster does not blindly trust the SaaS (see section 8).

---

## 3. Storage components (and why each, and why no log lake)

Five stores, none of which is a raw-telemetry warehouse:

1. **Graph store (per-tenant blast-radius graphs).** The centerpiece. A managed graph database. This is the proven path for this class of product: the point is that the product's value is a graph and the answers derived from it, not searchable logs. Per-tenant partitioned and encrypted.
2. **Event / time-series store (scored encounters and metrics).** Bounded, tiered retention. Holds the scored encounters, blast-radius-over-time, and dashboard metrics. This is small because it is derived, not raw. It is not a place to search every flow.
3. **Per-tenant state store (derived summaries, calibration snapshots, tenant config).** Relational or key-value. The per-tenant operational state the SaaS needs to run the dashboard and manage the deployment.
4. **Intelligence store (anonymized cross-customer fingerprints and priors).** A separate store, by design, carrying no tenant-identifying data. This is the moat asset and it is safe to be shared because of what crossing B strips out. Keeping it physically separate from tenant data is a defense-in-depth choice.
5. **Registry (signed images and Helm charts).** A managed container registry. Distribution plumbing, covered in section 5.

Why no log lake: raw east-west telemetry at enterprise scale is a petabyte-class, commodity, ruinously expensive storage problem, and it is exactly the cost structure that has sunk observability startups. Because the in-cluster control plane reduces before sending, the SaaS stores derived state that is orders of magnitude smaller and orders of magnitude more valuable. If a customer wants raw-flow retention for forensics, offer it as an opt-in tier that stores in the customer's own cloud account, so the cost and the data gravity stay on their side.

---

## 4. Install and registration flow

The install experience is the product's first impression, and in Kubernetes the expectation is a chart, not a docker pull.

1. **Enroll.** The operator creates a deployment in the SaaS console and receives a short-lived bootstrap enrollment token scoped to one cluster.
2. **Install.** They apply the Helm chart (and/or an OLM/OperatorHub listing) into the cluster, passing the token. This deploys the operator and the per-node DaemonSet.
3. **Pull, verified.** The operator and agents pull signed images from the managed registry and verify signatures and provenance before running. Unsigned or unverifiable images do not start.
4. **Register.** The agent opens an outbound-only mTLS channel to the SaaS, exchanges the short-lived bootstrap token for a long-lived per-cluster workload identity, and establishes the derived-state channel. This enrollment identity follows least privilege.
5. **Observe.** Observe-only begins, the baseline learns locally, and derived state (crossing A) starts flowing to the tenant space. No enforcement until the baseline matures.
6. **Appear.** The cluster shows up in the operator's dashboard.

Design notes: outbound-only, mTLS, signed images with provenance, token-based enrollment, least-privilege enrollment identity. The registration handshake and the ongoing derived-state channel are the parts that need care. The registry itself is plumbing, use a managed one (a cloud-native registry or Artifactory), never self-host a Docker-Hub-style service, and do not put Docker Hub's rate limits in a customer's install path.

---

## 5. Tenancy model

Multi-tenancy is now a first-class engineering problem, not a footnote, because the SaaS holds many customers' derived intelligence and your single strongest selling point (we keep your data isolated) becomes your single biggest liability if you get it wrong.

- **Hard isolation of tenant data.** Per-tenant encryption keys, per-tenant graph partitions or namespaces, isolation enforced at the data layer, not only the application layer.
- **The shared intelligence store is the one deliberate exception,** and it is safe by construction because crossing B strips tenant-identifying data before anything reaches it. Isolation is the default, sharing is the narrow, sanitized exception.
- **Treat tenant isolation as a correctness invariant with tests,** mirroring the in-cluster scope-isolation invariant. A cross-tenant leak in the backend is the same class of bug as a cross-scope leak in the cluster, and just as unacceptable.
- **Offer a self-hosted / BYOC control plane** for regulated or security-conscious customers who cannot send even derived data to a vendor SaaS. Some of your best ICP live here. This is a real architectural commitment, design for it early rather than retrofitting.

---

## 6. Connectivity model

- **Outbound-only from cluster to SaaS.** No inbound to the customer cluster. Security teams strongly prefer this and many require it.
- **Strict-egress support.** Customers route the outbound channel through their own egress proxy. This maps naturally onto the single-egress-point discipline the product already uses internally.
- **Separable channels.** The telemetry-up channel and the update-down channel are separable, so a customer can allow derived-state-up without allowing auto-update-down, or the reverse.
- **Air-gapped / no-callout customers.** Serve them with the self-hosted control plane, where the backend runs in their environment and cross-customer intelligence is either disabled or delivered as periodic signed bundles rather than a live feed.

---

## 7. Security of the control plane itself

You are building a control plane that can push agents into customer clusters and influence in-cluster enforcement. That makes you a high-value supply-chain target, exactly the kind of vendor a sophisticated attacker would compromise to reach many clusters at once. The bar on yourself is therefore higher than on a normal SaaS.

- **Sign everything and prove provenance.** Image signing (sigstore/cosign), SBOMs, build provenance (SLSA-style). A hardened, auditable update channel.
- **The cluster does not blindly trust the SaaS.** Any downward instruction that changes enforcement posture is authenticated, authorized, audited, and validated by the in-cluster operator before it is applied. Defense in depth across the boundary.
- **Least privilege for the enrollment and control identities,** so a compromised channel cannot do more than its narrow job.
- **Get ahead of the sales objection.** Customers will ask, correctly, why they should let your cloud influence their cluster. The answer is the autonomy principle plus the trust-but-verify boundary, have it ready.

---

## 8. The autonomy principle (fail safe if the SaaS is unreachable)

The data plane must keep protecting even when the SaaS is down or unreachable. The SaaS is for intelligence, dashboards, distribution, and cross-customer learning. It is not a runtime dependency of enforcement.

- If the SaaS is unreachable, the in-cluster system keeps observing, deceiving, and stinging with last-known-good config. It does not open up, and it does not stop enforcing.
- Derived state buffers locally and syncs when the channel returns.
- This is both a reliability property and what makes the air-gapped and strict-egress cases possible. Enforcement never depends on a callout.

---

## 9. How this maps to the existing repo and rules

- Crossing B is exactly the existing egress filter in `internal/intelligence/network/`. This doc does not introduce a new sharing path, it names the one that already exists and defines what flows through it.
- Crossing A is net-new: the per-tenant derived-state channel from the in-cluster control plane to the SaaS. It needs its own defined contract, parallel to the internal layer contract, and it should carry only logical identifiers and derived state, never raw data.
- Rule 5 (scope isolation) now has a backend counterpart: tenant isolation in the SaaS, with the same invariant status.
- Rule 9 (anonymized-only cross-boundary) governs crossing B unchanged.
- The autonomy principle reinforces the existing fail-safe posture: the data plane already fails closed on scope-resolution failure, and it must also keep running without the SaaS.

New backend concerns to add to the build plan: the SaaS control plane (tenant management, the two ingest channels, the stores), the graph store, the registration/enrollment service, the distribution registry and Helm/operator packaging, and the self-hosted/BYOC deployment mode.

---

## 10. Open questions to resolve

1. How much of the blast-radius graph does the dashboard need in the SaaS versus rendered from summaries? The full graph is sensitive topology, so decide deliberately how much per-tenant graph detail crosses in crossing A, and whether some graph queries run back down in-cluster rather than server-side.
2. What is the exact minimum derived-state schema for crossing A? The smaller and more logical-identifier-only it is, the stronger the privacy story.
3. BYOC scope: full self-hosted control plane, or a lighter on-prem collector that still talks to a vendor plane? This trades privacy against operational burden for the customer.
4. Retention and tiering for the event store, and the opt-in raw-forensics tier in the customer's own cloud.
5. Do we need the cross-customer intelligence priors on day one, or is per-tenant value enough to ship first, with the shared moat turned on later? (Likely the latter, matching the narrow-then-medium sequencing.)
