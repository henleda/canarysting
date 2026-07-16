# CanarySting — Minted Decoys and the Harvest-to-Use Join
### Working spec. Companion to the Kubernetes-Native Architecture Spec.

**Status:** working draft, to be folded into the canary layer, the blast-radius graph, the segmentation model, and the control plane. Prior art is heavy here (see section 6). Read that section before making any novelty claim.

---

## 1. The primitive

A decoy credential is minted uniquely for the flow that harvests it, and swapped into the decoy content on the way out. The credential opens nothing. If it is ever used, anywhere, the use event carries the mint, so it resolves back to the exact flow the credential was planted for.

The observed pattern that motivates this: a scanner harvests a fake `.env` from throwaway infrastructure, and hours later a different actor on a clean residential line tests the key with a different tool. To everyone else those are two unrelated events in two unrelated places. To the system that minted the key, it is one incident with both ends named.

**Why this belongs in CanarySting specifically.** We already have one join primitive, the socket cookie, which binds an L7 verdict to kernel enforcement on the same host within a flow's lifetime. Minted decoys are a second join on a different axis: they bind a harvest identity to a use identity across time, across infrastructure, and across the boundary of our own observability. Both primitives work the same way, make the adversary carry an identifier we minted. The socket cookie works inside the host. The minted decoy works out in the world, after the attacker has left.

---

## 2. What our version does that the reference implementation does not

The public pattern mints against a web visitor, so the resulting alert names an IP, an ASN, and a user agent. Network-layer attribution.

We mint against an attributed flow. At the moment of harvest we already know the workload identity (mesh/SPIFFE primary, label-derived fallback), the scope, the node, the socket cookie, and the L7 request. So the mint is bound to identity, not to an address.

The consequence: our incident does not say "a scanner at that datacenter took the key." It says "this workload identity, in this namespace, on this node, in this flow, took the key, and it was used from there, then." That is identity-layer attribution, and it is the same differentiator we claim everywhere else in the product, applied to a new signal.

This also means the join survives things that break IP-based attribution: pod churn, IP reuse, NAT, and the attacker changing infrastructure between harvest and use. The mint is stable because the identity it was bound to is stable.

---

## 3. Where it lands in the model

### Canary layer: decoys become minted, not static

Decoy content stops being a fixed artifact and becomes minted per harvesting flow. The mint happens on egress through the proxy, which is native to our proxy-attach wedge, the adapters are already in the path and already carry the flow identity.

Applies to proxied decoys: a fetched `.env`, a config or secrets endpoint, a kubeconfig served over HTTP, a decoy metadata service, a decoy internal API returning credentials.

Design notes: the mint must be cheap and must not add meaningful latency to the decoy response; the mint-to-identity binding is stored per scope; the decoy must remain convincing, a minted value has to look exactly like the real credential format.

### Blast-radius graph: this is the exfiltration ground-truth edge

We already identified exfil ground truth as the strongest contribution deception makes to blast-radius modeling, and this is the concrete mechanism for it. A minted credential that leaves and is later used proves two things nothing else proves: the exfiltration channel is genuinely open, and the path from harvest to use is real rather than theoretical.

The edge is unusual in that it has a time gap and an off-graph segment. It leaves our observability at harvest and re-enters at use. Model it as an ADVERSARIAL edge with a harvest timestamp, a use timestamp, and a confidence of certainty, because a minted credential cannot be used by accident.

### Segmentation: the harvest-to-use split is a tier classifier

The infrastructure split in the observed pattern is tradecraft. Throwaway infrastructure does the stealing, a clean line does the testing, because the clean line is the address nothing blocks. Commodity bots do not do this. Separating harvest infrastructure from test infrastructure is operational discipline, and operational discipline means sunk cost, which is the lever our whole attrition model pulls on.

So minted-decoy telemetry becomes a direct input to tier classification. Same infrastructure harvests and tests, and it looks like tier 1. Deliberate separation, clean test infrastructure, tool changes between harvest and use, and the behavior sits at 2b, our bullseye. The delay between harvest and use is itself a signal, a human or a queue sits in the loop rather than a single automated pass.

This gives the segmentation model something it currently lacks: an observable, per-encounter classifier rather than a reasoned framework.

### Intelligence moat: the best crossing-B payload we have

Harvest-to-use correlation pairs are close to the ideal anonymized adversarial fingerprint. They carry no tenant topology, no raw data, no customer-identifying detail. They describe the adversary's own infrastructure and behavior, not the customer's environment.

Pooled across deployments through the existing default-deny egress filter, that yields a dataset nobody else holds at east-west identity fidelity: which harvest infrastructure pairs with which test infrastructure, which tool sequences recur, what the typical harvest-to-use delay looks like by tier. A new deployment that has never seen its own attacker can inherit these priors on day one.

This is also the cleanest possible demonstration of the crossing-B design, because it is obvious to a security buyer that we are sharing the attacker's fingerprint, not their data.

---

## 4. Why this strengthens the credential-abuse answer

The strongest critique of a detection-triggered model is that most modern intrusions ride valid credentials through legitimate channels and never touch anything that looks like a trap.

Minted decoys attack that critique directly, because the pattern they catch is exactly the credential-abuse pattern: acquire a credential, use it later, from somewhere else, through a legitimate channel. A minted decoy credential is a credential-abuse tripwire with certainty and with both ends named.

It does not answer the critique completely, an attacker who never touches a decoy still never fires it. But it moves deception from "catches attackers who explore" toward "catches attackers who harvest credentials," which is a much larger and more current share of real intrusions.

---

## 5. Honest limits

**Static file decoys cannot be minted the same way.** A decoy file planted by volume mount and read from disk can be detected on read (LSM/eBPF), but content cannot be practically rewritten per reader at read time. So minting applies to proxied decoys, and file decoys keep the detect-on-touch model without the harvest-to-use join. Do not blur these in claims.

**Use detection requires a callback path.** When a minted credential is used against a decoy endpoint we host, we see it directly. When it is a cloud credential used against a real cloud API, detection depends on an external callback from that provider. That is a dependency on someone else's infrastructure and it needs a decision (see section 7).

**The join names an actor, not a person.** The use event names the infrastructure and tooling of whoever tested the credential. It does not attribute to a human or an organization. Be precise in the product language and never overclaim attribution.

**Minting adds a write path to the decoy response.** Anything that rewrites content in the path carries performance and correctness risk. It must not be able to affect non-decoy traffic. The blast radius of a minting bug should be exactly zero legitimate requests.

---

## 6. Prior art (read before claiming anything)

The mechanism is not ours and it is not new. Per-visitor unique honeytokens with callback alerting are the canarytokens model, publicly available and free, and the observed implementation was built on it using a cloud provider's own canary credential facility. Thinkst is already in our competitive landscape as the honeytoken player, and this narrative sharpens what they genuinely do well rather than revealing a gap.

The narrow delta that might be worth putting in front of counsel, without any expectation:

- minting bound to a kernel-attributed east-west flow identity rather than a web visitor or an IP
- the resulting harvest-to-use join integrated as an edge in a reachability and blast-radius graph
- using the harvest-to-use infrastructure split as an automated attacker-tier classifier
- anonymized cross-deployment pooling of harvest-to-use correlation pairs

Treat all four as questions for counsel, not conclusions. The base mechanism is public prior art and the burden is on the narrow delta. Add to the existing patent brief as candidate material only, flagged honestly as sitting on top of well-established prior art.

---

## 7. Open questions

1. **Do we host the callback receiver, or lean on existing canary infrastructure?** Hosting it makes the harvest-to-use join fully ours and keeps the data in our control plane. It also creates a new, externally exposed SaaS component that receives hits from attacker infrastructure, which has very different security properties from the customer-facing control plane. That surface needs its own threat model.
2. **What is the decoy credential surface?** Cloud keys, kubeconfigs, service-account tokens, database credentials, internal API keys. Each has a different use-detection path, and the in-cluster ones (a minted service-account token used against our decoy API) are the ones we can detect without any external dependency. Those may be the better starting point precisely because they need nobody else.
3. **Mint lifetime and volume.** One mint per harvesting flow could produce a large number of live mints. Decide expiry, storage, and whether mints are per flow, per identity, or per scope-plus-window.
4. **How much of this ships in the narrow case?** Minting plus in-cluster use detection needs no policy ingestion and no external callback, so it fits the narrow wedge. External cloud-credential callbacks are a later addition.

---

## 8. Edits this implies elsewhere

- **Architecture Spec, canary layer:** decoys are minted per harvesting flow at the proxy, not static. Note the file-decoy limit.
- **Architecture Spec, graph:** ADVERSARIAL edges include harvest-to-use edges with a time gap and an off-graph segment, at certainty confidence.
- **Segmentation memo:** add minted-decoy telemetry as the first observable, per-encounter tier classifier, and record the infrastructure-split reasoning.
- **Control-plane doc:** add the callback receiver as a candidate SaaS component with its own threat model, and name harvest-to-use pairs as the primary crossing-B payload.
- **Patent brief:** add the four narrow deltas in section 6 as candidate material, explicitly flagged as sitting on public prior art.
- **Competitive analysis:** sharpen the Thinkst entry. Per-token uniqueness with callback alerting is a real capability they have, not merely "honeytokens that alert."
