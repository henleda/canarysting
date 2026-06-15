# Learned Topology, Rich Deviants, and the Local-Rich Posture

Status: design (2026-06-15). Two features (F1 learned east-west topology, F2 rich
non-tripwire deviant log) and the posture that makes them legal under our own rules.
Read alongside `docs/SCOPE.md` (Rule 5), `docs/INTELLIGENCE.md` + `docs/EGRESS_FILTER_DESIGN.md`
(Rule 9), `docs/TECHNICAL_ARCHITECTURE.md` (the eBPF observe path), and the core rules
in `CLAUDE.md` (Rules 8/9). The founder has signed off on the posture in §1; the rest
is the build that follows from it.

---

## 1. The posture: LOCAL-RICH, EXPORT-COARSE, NEVER-AUTO-ACT

Lead with this, because it is the only thing that makes F1 and F2 buildable without
breaking a rule — and because we got it subtly wrong before.

Three rules govern three different things, and we previously conflated them:

- **Rule 8 governs automated RESPONSE** (tag / contain / tarpit / jail). Logging a
  flow, or drawing it on a screen, is **not** a response. Only a canary touch arms
  anything. A learned topology map, a live overlay, and a deviant log are all
  read-side views; none of them can enter the response pipeline.
- **Rule 5 governs scope isolation WITHIN a deployment** — learned state is keyed per
  scope and never aggregates across scopes (`internal/engine/persist/store.go:scopeSub`,
  the layout chokepoint at line 350).
- **Rule 9 governs only what CROSSES a deployment boundary.** Coarsening is mandatory
  at the egress boundary, and nowhere else.

The mistake we are correcting: today the engine throws away the raw address **at
capture**. `internal/engine/observebaseline/derive.go:hashAdjacency` (line 146) folds
`(srcIP, dstIP, dstPort)` into a one-way FNV-64a `uint64`, and the comment at line 137
states the intent plainly — *"Only the FNV hash is ever persisted or counted; the raw
address never is."* That is **stricter than Rule 9 requires.** Rule 9 only demands
coarsening at the egress boundary; it says nothing about what an operator may see about
their own deployment. We were applying an egress-grade control at the observation point
and paying for it with a blind dashboard.

**The correction (founder-signed):** move the coarsening from *capture* to the *egress
boundary*. Keep the raw edge **locally** — in per-scope bbolt, behind the local tap —
and let the operator see rich intelligence about their **own** deployment. The
FNV-hashed counts still feed the baseline math unchanged (they serve the scoring
masters); we *additionally* keep the un-hashed edge for the local topology and deviant
log. The single default-deny egress chokepoint at `internal/intelligence/network` stays
exactly as coarse as it is today (k>=3, hashed, default-deny — see §2a and
`internal/intelligence/network/doc.go`).

The refined on-screen wording replaces the old absolutist "zero-surveillance" banner —
which the new local-rich stores would contradict — with an honest, precise statement:

> **Local-rich, export-coarse, never-auto-act.** We keep no dossier on NORMAL traffic.
> We map your own topology and richly log ANOMALIES for your hunters. Nothing raw ever
> leaves this deployment. Observation never arms a response (Rule 8) — only a canary
> touch does.

---

## 2. Two egress paths (do not conflate them)

Adding rich local stores raises an obvious question: "if you keep raw IPs and paths,
where can they go?" There are exactly two egress paths off a deployment, and they are
not the same kind of egress.

### 2a. Cross-customer egress — `internal/intelligence/network` (the moat)

This is the boundary Rule 9 was written for: derived intelligence crossing from **one
customer to another** via the shared network. It is a single default-deny chokepoint
(`internal/intelligence/network/doc.go`: *"the SINGLE default-deny egress chokepoint"*),
and its tests already enforce the load-bearing properties — default-deny with
new-fields-drop, and a reflection guard that the `Cleared` carrier has **no exported
fields** so there is no second construction path (`network/filter_test.go`, the
"new-field-drops" and "surface reflection guard" cases). What crosses here is **coarse**:
anonymized, hashed, k>=3-aggregated patterns. This is the moat, and it must stay coarse.
**F1 and F2 never feed this path** (see §6).

### 2b. SIEM/SOAR egress — the CUSTOMER'S OWN system (local, therefore rich)

This is a different animal. Pushing a detection into the customer's own Splunk /
Sentinel / Chronicle is **not** a cross-customer crossing — it is the customer reading
their own data in their own console. So the SIEM event is the one place we *want* the
**rich** record: real identity + resolved service name + the fused L7+east-west
fingerprint + the east-west path + verdict/tier + ATT&CK technique + the
"zero-real-data-exfiltrated" proof. Anonymizing the customer's own detection before
handing it back to the customer would be absurd.

This is why the SIEM event must be built **on top of** the local-rich capture in F1/F2,
**not** on today's event. Today's egress-bound record,
`intelligence.AdversaryInteractionEvent` (`internal/intelligence/event.go:20`), is
**addressless by design**: it carries `ScopeKey`, `FlowID` (the socket cookie),
`CanaryType`, the `[0,1]` `Features` map, `Tier`/`Verdict`/`Score`, and `StingOutcome` —
and the package comment (line 17) states it *"Carries no raw"* addresses. There is **no
`L7Attributes` field** on it. A SIEM integration cannot emit a rich event from this
structure; the rich identity simply is not there.

The SIEM enrichment therefore depends on two things this doc builds: (1) the local-rich
capture below, which stops discarding the raw edge, and (2) threading the adapter's
`L7Attributes` (the Envoy adapter already stamps `contract.AttrSourceAddress`, the
well-known key at `internal/contract/contract.go:41`, plus the peer `SPIFFEID` from
mTLS, `FlowIdentity` at line 16) into the local record so the cookie-joined identity is
captured. The SIEM/SOAR egress surface itself is specified in the pilot-readiness doc;
here we only note it as the **dependency** F1/F2 unblock. It is the customer's-own,
local-rich path — never the anonymized cross-customer one.

---

## 3. F1 — Learned east-west topology

### The unlock

The raw directed `src->dst:port` tuple **is available** per flow, and we throw it away
at one line. Walking the path:

- **Kernel capture** (`bpf/observe/observe.bpf.c`): `cs_flow_stats` holds the full
  directed 4-tuple per flow — `src_ip` = the remote/initiator (the caller), `dst_ip` =
  the local/workload (the reached service), `src_port`, `dst_port`, `family` — keyed by
  socket cookie in an LRU hash.
- **Userspace mirror** (`bpf/observe/observer.go:FlowStats`, lines 45-64): copies it
  field-for-field — `SrcIP[16]`/`DstIP[16]`/`SrcPort`/`DstPort`/`Family`, plus
  `FirstSeenNs`/`LastSeenNs`, byte/pkt counters, `Closed`. `convert.go:fromRaw` copies
  the addresses straight through — **no hashing in the loader.**
- **The discard point**: `observebaseline/derive.go:hashAdjacency` (line 146) FNV-hashes
  `(srcIP, dstIP, dstPort)` to a `uint64`, called from `aggregate.go:foldFlow` (line 55)
  via `bumpCapped` into `Adjacency map[uint64]uint32` (line 25) — **pure counts; the
  addresses are gone.** That hash *already encodes the canonical directed edge key*;
  only its pre-image is dropped.

So a real learned topology is **not** blocked by one-way hashing — the edge is observed,
then discarded. We stop discarding it locally.

### Design

**(1) Edge accumulator, folded in `foldCompleted`.** `aggregator.go:foldCompleted`
(line 326) already receives the full raw `observe.FlowStats` and folds one COMPLETED
flow **exactly once** — the `a.live` + `a.folded` cookie bookkeeping (lines 252-288)
guarantees fold-once. Drop a directed-edge map upsert there, beside the existing
`bumpCapped(a.Adjacency, hashAdjacency(fs), ...)` call, fed by the **same** raw `fs`
kept **un-hashed**. It inherits fold-once for free — no new hot-path bookkeeping. Keep
the FNV counts too; the baseline math is unchanged.

- **Edge value**: `{SrcIP, DstIP, DstPort, Family, FlowCount, TotalBytes, TotalPkts,
  FirstSeenWall, LastSeenWall, open-vs-closed}`.
- **Node catalog** (a parallel map): keyed by canonical identity — the initiator
  (`SrcIP`) and each `(DstIP, DstPort)` service endpoint — value `{firstSeen, lastSeen,
  flowCount, role: initiator|service}`. Nodes are the identities; edges are the
  adjacencies.
- **Wall-clock stamping is mandatory.** Kernel `FirstSeenNs`/`LastSeenNs` are
  `bpf_ktime_get_ns` — **monotonic, not wall-clock** (see `aggregator.go:flowDurationSec`
  around line 453). Edge first/last-seen for operator display **and** for the TTL reaper
  must be stamped from the aggregator's injectable `a.clock()` at fold time, never
  derived from kernel ns.

**(2) A new per-scope `bktTopology` bbolt bucket.** Model it exactly on the existing
layout in `persist/store.go`: a new top-level bucket nesting one sub-bucket per scope
(`scope -> {edgeKey -> gob edge blob}`), added the same way `bktBaseline`/`bktMalicious`/
`bktEvents` are (lines 22-24), reusing `putNested`/`getNested`/`rangeNested` and the
`scopeSub` chokepoint (line 350) that enforces scope isolation **by layout** (Rule 5).
Edge writes **ride the existing per-tick single-fsync transaction** by extending
`BucketWrite` + `PutBucketsAndHeartbeat` (lines 157, 167) — no extra disk I/O, and off
the hot path (the fold writes after the in-memory lock is released). Bump
`persist.SchemaVersion` (line 17).

**(3) A cap + TTL reaper.** Mirror `bumpCapped`'s lowest-count eviction
(`aggregate.go:74-90`) with a per-scope cap on the order of the existing
`freqCapDefault = 4096` (`aggregate.go:16`), **plus** a wall-clock TTL so stale edges
age out over a multi-week window. Eviction is lowest-count / oldest-last-seen, so
frequent normal edges survive and rare artifacts age out; an evicted edge looked up
later correctly reads as novel. **Scan cardinality is the real risk, not normal
traffic** — a normal mesh is sparse (dozens-to-low-hundreds of identities,
hundreds-to-a-few-thousand directed edges; ~50-70 bytes/edge => low single-digit MB per
scope), but a port-sweep or source-spoof can manufacture huge edge/identity counts. The
cap + reaper is what keeps a scan from blowing up the store (the same property
`bumpCapped` gives the baseline today). The reaper runs on the existing fold tick, off
the hot path.

**(4) A node-identity resolver.** This is the one genuinely new shared component. Turn a
raw IP / IP:port / cookie->SPIFFE into a **service-name** label.

- Today `stagedlabel.Registry.Lookup` (`internal/intelligence/stagedlabel/registry.go:68`)
  returns only a `Disposition` (`DispUnknown`/`DispLegit`/`DispAttacker`, line 38) — a
  2-value demo verdict, not a name. **Generalize it to return a NAME.**
- **An operator-declared IP/CIDR/port -> name map is FIRST-CLASS config — founder
  decision.** This is the `ground-truth-registry` pattern generalized from a
  2-disposition demo table to an N-service production map, shipped as real config rather
  than deferred to SPIFFE-only.
- **Plus SPIFFE-from-mTLS**: parse `spiffe://.../sa/<service>` from the peer cert the
  adapter already surfaces on `FlowIdentity.SPIFFEID`. The two sources are complementary;
  the resolver prefers a declared name, falls back to SPIFFE, then to an IP/anonymous
  node. It **degrades gracefully — it never drops an edge for lack of a label.**
- **Demo resolver** = the ground-truth registry (external callers) + a port->service-name
  table. The demo mesh is **all loopback `127.0.0.1`** on distinct ports
  (`deploy/m7-window/server-compose.yml`: frontend 8001, api 8002, auth 8003, db 8004,
  cache 8005), so the **LISTEN port disambiguates the service, not the IP** — the
  port->name table is what labels internal nodes.
- **Fold direction (all-ends-observed artifact).** When the observer sees BOTH socket
  halves of a connection (any single-host/loopback case, and on a real mesh both the
  client host and the server host report into the same scope), the eBPF records
  `DstPort = the LOCAL socket's port`. The SERVER-ACCEPT half carries the service
  **listen** port (the correct forward edge `caller -> service:listen_port`); the
  CLIENT/INITIATOR half carries an **ephemeral** local port (a reversed edge
  `service -> caller:ephemeral`, which also explodes the store by ephemeral port). The
  topology fold therefore **skips any flow whose `DstPort >= 32768`** (`ephemeralPortFloor`,
  the Linux `ip_local_port_range` default) — a heuristic that keeps the forward fabric and
  drops the reverse half, touching ONLY the topology fold (the baseline hash is unchanged).
  **Known limitation:** a real service that LISTENS on a port `>= 32768` has its forward
  edge dropped by this heuristic and is omitted from the fabric. The clean fix is a real
  initiator flag stamped by the observer (so direction is chosen by an explicit bit, not a
  port-range heuristic) — a tracked follow-up.

**(5) Canaries render as decoy nodes in the negative space.** Canaries are their own
decoy nodes, not nodes behind a real service. `seeder.Registry.List(scope)`
(`internal/canary/seeder/registry.go:49`) yields `Placement`s with `Location`, `Type`,
and `Origin` (`PlacementOrigin`: `OriginNegativeSpace`/`OriginLateralPath`/
`OriginOperatorBroad`, `seeder/planner.go:14`). Inject each as a **decoy node positioned
off the learned service-node set** — it sits in the negative space precisely because it
has **zero learned in-edges** (the mesh never serves canary paths; `mesh/main.go`
returns a real 404 for every `canaryPrefixes` entry — line 44 — and only the Envoy
ext_proc adapter recognizes a touch). `Origin` is the decoy's placement-rationale label.
A canary **touch** (from the `boltevents` events, keyed by cookie, Tier>=1) becomes a
highlighted **source->decoy edge** — the literal "attacker reached into negative space"
visual, and the only edge that ever crosses into the ring.

**(6) A `GET /raw/topology` tap endpoint.** On `internal/dashboard/tap`, returning
`{nodes:[{id,label,kind:service|external|decoy,origin}], edges:[{src,dst,port,proto,
volume,count,firstSeen,lastSeen}]}` derived from the edge store + node resolver, with
canary placements injected as decoy nodes and the current live/deviant flows overlaid.
The live overlay is cheap: `LiveFlows` (`aggregator.go:416`) **already** calls
`reader.ReadStats` per open cookie (line 432, full raw `fs` in hand) and deliberately
omits the addresses before returning a coarse `LiveFlow` (struct at line 395) — adding
the real `SrcIP`/`DstIP`/ports is a field-addition there, not new plumbing. Local-only;
never exported.

**(7) A new React graph page.** None exists today — the frontend has recon / journey /
tier-ladder / bystander surfaces but no node/edge graph. Render the three node classes,
decoy nodes in the negative-space ring, and live/deviant edges highlighted.

**Exportable as DATA, not just a picture.** The detection-engineering persona wants the
learned graph as a **queryable adjacency graph** (JSON/Neo4j dump) to overlay on their
CMDB and ask "which services can reach the decoys" — standalone segmentation/audit value
even before any attack. The tap's `nodes[]`/`edges[]` shape is already that data; the
page is one renderer of it.

### What it takes (ordered) — effort: **large**

1. **Engine edge accumulator** — directed-edge map + node catalog in the aggregator,
   folded in `foldCompleted` beside `bumpCapped(hashAdjacency)`, fed by the same raw `fs`
   kept un-hashed; stamp first/last-seen from `a.clock()`. Keep the FNV counts.
2. **Edge store + batched write** — `bktTopology` (`scope -> edgeKey -> gob blob`) reusing
   `putNested`/`rangeNested`/`scopeSub`; extend `BucketWrite` + `PutBucketsAndHeartbeat`
   so edge writes ride the existing per-tick single fsync. Bump `SchemaVersion`.
3. **Edge reaper** — per-scope cap (mirror `freqCapDefault`) + wall-clock TTL +
   lowest-count/oldest eviction (`bumpCapped` pattern), on the fold tick, off the hot path.
4. **Node-identity resolver** — generalize `stagedlabel.Registry.Lookup` to return a
   name; demo = registry + port->name table; production = operator-declared
   IP/CIDR/port->name map (first-class config) OR SPIFFE parse; degrade to IP/anonymous.
5. **Live/deviant overlay data** — add real `SrcIP`/`DstIP`/ports to `LiveFlow` +
   `LiveFlows` (data already read at line 432); local-only.
6. **Tap endpoint** — `GET /raw/topology` emitting `nodes[]`+`edges[]` with class tags,
   canary decoy nodes (`seeder.Registry.List`), live/deviant overlay, source->decoy
   touch edges.
7. **React topology page** — brand-new graph component.
8. **Egress guard + test** — see §6.

---

## 4. F2 — Rich non-tripwire deviant log

Today the only durable per-flow record is the canary-touch event
(`boltevents`, Tier>=1, addressless). Anomalous-but-non-touching flows exist only as
**ephemeral** live surfaces (`observebaseline.LiveFlow` -> `tap.ReconLiveFlow`), never
persisted, carrying only cookie + derived novelty + coarse bytes. F2 makes the deviant
flow a **real, durable, forensic record** — because logging an anomaly locally is
neither a Rule 8 (response) nor a Rule 9 (export) act.

### The record

A **new** `intelligence.DeviantFlowRecord`, a **sibling** to `AdversaryInteractionEvent`
— **do not widen the egress-bound event**; that one stays structurally addressless so
the cross-customer path cannot regress. The new record holds:

- **Real identity**: `SrcIP`/`DstIP`/`SrcPort`/`DstPort`/`Family` (from `FlowStats`),
  `SPIFFEID` + source address (from `FlowIdentity`/`L7Attributes`, cookie-joined per
  Rule 4), and resolved `SrcLabel`/`DstLabel`/`DstService` via the F1 node resolver.
- **Fused L7+E/W fingerprint**: the L7 view the adapter saw (path/method/headers of
  interest) joined to the east-west view (dst service + port/proto).
- **The 5 novelty dims** as floats — adjacency / identity / port / volume / cadence —
  plus the peak dim and the `Score`. (The four `[0,1]` dims already surface today via
  `observebaseline` `IdentityNovelty`/`AdjacencyNovelty`/`VolumeDeviation`/
  `CadenceDeviation`.)
- **Recurrence**: `Seq`, `FirstSeen`/`LastSeen` (wall, `a.clock()`), and a `HitCount`
  for repeat offenders.
- **East-west path**: the actual pivot walked (e.g. `web-tier -> api -> db-replica`).

### Gating, dedup, storage

- **Gated to DEVIANTS, not normal traffic.** Persist a flow only when its peak novelty
  is `>=` a deviant floor — **reuse `reconLiveNoticeFloor`** (`tap.go:53`, 0.3), with
  `reconLiveSurfacedFloor` (line 56, 0.85) as the louder escalation. This is the
  load-bearing distinction: **we keep no dossier on normal flows; we richly log
  anomalies.** A normal flow is never written.
- **Deduped by canonical edge key.** Key on the same `(srcIP, dstIP, dstPort, family)`
  edge key as F1 (plus cookie). A repeat deviant from the same identity bumps
  `HitCount`/`LastSeen` instead of writing a fresh blob — so a noisy scanner does not
  flood the log (the `bumpCapped` discipline applied to the deviant store).
- **Per-scope store + reaper.** A new per-scope bbolt sub-bucket (`bktDeviant`) or
  `AppendEvent` with a distinct record tag (`store.go:243`); scope-isolated, survives
  reboot. Any per-`Submit` read **inherits `boltevents`' `recentScanCap` ceiling**
  (`store.go:RangeEventsRecent`, line 290) — the saga where an uncapped days-deep scan
  blew the adapter inline timeout and fell verdicts closed to 403 must not recur. Same
  per-scope cap + lowest-recurrence/oldest reaper as F1.
- **Capture seam** is the same `LiveFlows`/fold path that already has the raw `fs` in
  hand (`aggregator.go:432`) — we stop throwing the address away, gated to deviant flows.

### A real investigation surface (CISO-panel-required — commit to this)

A sortable table is, per the detection-engineering persona, *"worse than nothing because
it implies coverage you don't actually have."* The deviants page must be a real hunting
surface:

- **Pivot / sort / filter / group** by identity, fingerprint, recurrence, time — and
  pivot from one deviant to all flows sharing its identity or fingerprint.
- **Export** the record set: CSV / JSON / STIX, to feed a case.
- **Per-deviant ACK / SUPPRESS** so a known-good deviant stops resurfacing.
- **An events/day fidelity readout.** The deviants stream is an **anomaly feed and is
  NOT zero-FP** (unlike the canary trigger). Without a volume estimate, a tunable
  threshold, and suppression, it becomes the exact alert-fatigue swamp the whole product
  is positioned against — analysts abandon it in a week. The fidelity controls are not
  optional polish; they are what keep the hunt feed from re-creating the problem.

### Honesty (load-bearing)

The page surfaces deviants for a **HUMAN**. It **NEVER auto-acts.** Claiming the
deviants page "catches" the careful attacker automatically would re-introduce exactly
the anomaly-detection false-positive behavior Rule 8 exists to prevent. Every row carries
a loud verdict — **"NOT ACTIONED — touched no decoy (Rule 8)."** The tripwire is zero-FP
and auto-safe; the deviants list is human-hunting **with evidence**, explicitly not an
auto-trigger.

**Effort: medium** — it extends an existing store and reuses F1's raw-capture seam and
node resolver.

---

## 5. The compelling demo plan

Out of the box the M7 graph is genuinely tiny (5 loopback services + ~3 callers, ~12
edges) and reads as a lab toy; the deviants page has no data at all; and — most
important — **the current simdriver has no canary-avoiding flow.** Every `maliciousFleet`
archetype (`simdriver/main.go:407`) touches a canary immediately, so every adversary
flow arms a response. The killer CISO question — *"a skilled attacker who avoids the
canaries gets a free pass"* — has **zero on-screen answer today.** The demo plan fixes all
three.

### Expand the fabric

- **Mesh to ~14 services / 25+ edges.** Reuse `mesh/main.go` **unchanged** (it is already
  parameterized by `SVC_NAME`/`LISTEN`/`DOWNSTREAMS`); add ~8-11 service entries to
  `server-compose.yml` on `127.0.0.1:8006-8016` with realistic multi-hop downstreams
  (e.g. `api->payments->ledger`; `api->search->db-replica`; `frontend->cdn-edge->api`;
  `auth->session-store`; `reporting-worker->db-replica->cache`). `DisableKeepAlives`
  (`mesh/main.go:71`) already makes each hop a distinct completing flow the observe path
  learns — so these are **genuine** multi-hop adjacencies, not painted-on. No engine
  change, just more containers + the same binary.
- **Benign callers to ~8-10** (`.101-.110`), each with a named role and a subset of
  normal paths so per-identity learned adjacency genuinely differs — a flag/env change in
  `sim-setup.sh` + `ground-truth-registry.json`, reusing the existing
  `runBenign`/keepalive workers.

### The centerpiece: a "careful-mover" simdriver worker

A **new worker class** from a **fresh identity** (e.g. `.104` "reporting-worker") that
walks a **NOVEL east-west path of NORMAL (non-canary) application paths** against
under-trafficked services at a **slow, methodical cadence**. It scores high
**AdjacencyNovelty + CadenceDeviation** (a methodical pivot) — distinct from a scanner's
"new identity + volume" sweep — but **NEVER touches a canary.**

**Rule 8 enforcement in the harness:** `simdriver` today guarantees disjointness of
recon/benign paths from canaries via `disjoint()` (`main.go:176`) checked in `validate()`
(line 612). **Extend `validate()` to assert the careful-mover's path set is also disjoint
from `canaryPaths`** — so the deviant is structurally **unable to arm.** Model it on
`runMaliciousFlow` (`main.go:435`) but pointed at normal paths on under-trafficked
services. Add 2 noisier archetypes below it (a "new-identity burst" scoring
IdentityNovelty; a "volume-spike" batch job scoring VolumeDeviation) so the ranking
visibly does real work, with the careful-mover **#1, above the scanners.**

### The money shot

The careful-mover ranks **#1 on the deviants page** AND appears on the topology map as a
**faint anomalous east-west edge INSIDE the legit subgraph that never reaches the decoy
ring** — F1 and F2 reinforce each other (you SEE the careful pivot on the map and HUNT it
in the list, and on neither does it ever arm). Then: when the attacker (`.111`) actually
touches a canary, a single **bright source->decoy edge SNAPS** into the ring and the node
flares red — driven by a **REAL adapter-recognized touch** (`boltevents` Tier>=1, mapping
`AdversaryInteractionEvent.CanaryType -> decoy node`, identity -> source node), the only
edge that ever crosses into negative space. This makes "the canary touch is the only
trigger" a **visible, physical event** on the map.

### Three non-negotiable on-screen honesty fences

The CISO panel has already read the `DEMO_DATA_FLOOR` / simulated-peers notes and will
**actively test** "engineered demo vs production behavior." These fences are
**trust-preserving controls**, not decoration — any over-claim collapses the founder's
biggest asset (intellectual honesty about the gaps):

1. **Staged-range view.** Persistent caption: *"Staged range view — node/service names
   from the ground-truth registry; the engine's own baseline stores only hashed adjacency
   (Rule 9). In production this graph is drawn from the customer's own service registry,
   not ours."* The graph **SHAPE, edges, and volumes are real observed traffic**; only the
   human-readable **NAMES** are staging metadata. (`ground-truth-registry.json` is
   STAGING-ONLY and the production engine cannot even import the labeler — see its
   `_comment` and `stagedlabel/importguard_test.go:TestProductionEngineCannotImportLabeler`.)
2. **Simulated badge on the deviants page.** The careful-mover is `simdriver` traffic (the
   same `⚠ simulated` badge already in FleetSafety), **but its deviation score and
   fingerprint are computed by the REAL observe baseline** — the same dims that feed M.
   Say: *"This flow is our harness, but nothing about how it's scored or surfaced is
   faked."* Carry the badge onto the deviants page.
3. **Recurrence is window-observed.** *"Seen 4 times over 3 days"* must mean genuinely
   observed over the staging window (the careful-mover accruing across the ~2-day
   demo-floor window), **never a hardcoded number.** If the window is shorter, show the
   real (smaller) count.

**Never claim:** that the engine natively knows service names (it knows hashed
adjacency); that the deviant is a real external attacker (it is the harness); or that the
deviants page auto-**catches** the careful attacker (it surfaces for a human — saying
otherwise re-introduces the Rule 8 FP behavior). **Do keep saying:** the tripwire is
zero-FP by construction and auto-safe; the deviants list is human-hunting with evidence.

**Honest scale note:** the single-box loopback demo produces a small, clean graph that
**cannot** meaningfully exercise the cap/reaper or the high-cardinality scan path, and
can't show real SPIFFE labeling. Frame the demo as proof-of-concept of the *learned*
graph (validated against the known compose topology); the cap/reaper and
operator-declared/SPIFFE labeling are production-hardening the demo doesn't stress.

---

## 6. Rule compliance + the egress guard

- **Rule 5 (per-scope isolation).** Both new stores are per-scope bbolt sub-buckets under
  the `scopeSub` chokepoint (`store.go:350`) — isolation is enforced **by layout**, never
  aggregated across scopes.
- **Rule 8 (the touch is the only trigger).** F1 and F2 are entirely **read-side**. The
  topology map, the live overlay, and the deviant log cannot enter the response pipeline;
  only a canary touch arms anything. The careful-mover proves this **structurally** —
  `validate()` asserts its paths are disjoint from `canaryPaths`, so it physically cannot
  arm, and its row says so out loud.
- **Rule 9 (coarsen at the egress boundary).** The coarsening **moves** from "at capture"
  (today's hash-and-discard in `derive.go`) **to the egress boundary**
  (`internal/intelligence/network` only). Local stores keep raw IPs/SPIFFE/paths; the
  egress filter coarsens/drops them. The cross-customer path keeps emitting only the
  derived/anonymized `AdversaryInteractionEvent.Features` projection through the
  default-deny `Clear()` chokepoint — unchanged.

**MANDATORY: a guard test.** The rich stores (topology edges, deviant records, the
L7-enriched record) must be **physically unreachable** from `internal/intelligence/network`
— local-rich / export-coarse enforced **by structure, not by discipline.** Two precedents
already exist to model it on:

- `internal/intelligence/stagedlabel/importguard_test.go` does a `go list` transitive-deps
  assertion (`TestProductionEngineCannotImportLabeler`) — the same shape asserts the egress
  package cannot import the rich-store package.
- `internal/intelligence/network/filter_test.go` already has the reflection-based
  "new-field-drops" and "no exported fields on the `Cleared` carrier" guards — extend them
  to assert the egress filter cannot serialize raw IP / SPIFFE / port / path fields.

This is the load-bearing risk: persisting raw identity reverses today's structural
anonymization, and if the egress filter is ever wired to read these stores it becomes a
**critical Rule 9 bug** (leaking environment-identifying detail cross-customer). The guard
test is what makes the reversal safe.

---

## 7. Build order + effort

1. **F1 engine-side** (large): edge accumulator in `foldCompleted` -> `bktTopology` store
   on the batched write -> cap/TTL reaper -> node-identity resolver.
2. **Topology page**: `GET /raw/topology` tap endpoint -> the new React graph component.
3. **F2** (medium): reuses the F1 raw-capture seam + node resolver — the
   `DeviantFlowRecord`, the deviant floor + recurrence dedup + per-scope store/reaper, and
   the investigation surface (pivot/export/ack-suppress/fidelity readout).
4. **The careful-mover ships with F2** — it is the demo's hero row and the on-screen answer
   to the marquee objection; `validate()` extended to assert path-disjointness from
   `canaryPaths`.
5. **The egress guard test** lands with whichever of F1/F2 first introduces a rich store
   (it must never be deferred).
6. **SIEM enrichment (the L7 threading)** is the dependency that unblocks the **SIEM
   egress** (§2b) — noted here, specified in the pilot-readiness doc. It is the
   customer's-own, local-rich path, distinct from the coarse cross-customer egress.
