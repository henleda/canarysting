# CanarySting M8 — Interactive Routed Dashboard Console: Implementation Plan

**Status:** planning doc for review after a break. Self-contained. Synthesizes the backend drill-down spec, the frontend routed-console spec, and the data/UX audit into one buildable sequence.
**Repo:** `/Users/danielhenley/projects/canary-sting/canarysting-repo` · Go 1.22 · Next 14.2.35 / React 18.3.1
**Context:** dashboard-backend already serves `/api/overview`, `/api/stream`, `/healthz` from a 1h-windowed poll cache; Next.js app renders the home wall (`/`) live over SSE. This plan adds **drill-down** on top, no changes to existing behavior.

---

## 0. DECISIONS NEEDING SIGNOFF (read first)

The two source specs disagree on several points. I reconciled them in favor of the **backend spec's typed wire contract** (it is more precise and matches the existing `views.go` conventions exactly). The frontend spec's looser shapes are overridden where they collide. The items below are the live decisions — defaults are chosen so the build can proceed without blocking, but the founder should confirm.

| # | Decision | Default taken | Why it matters |
|---|----------|---------------|----------------|
| **A** | **`/api/cost` is a real backend endpoint** (backend spec) vs. frontend computing cost from `/api/flows` (frontend spec). | **Dedicated `/api/cost`** returning `CostBreakdown`. By-mechanism rollup is honest only in Go (the audit's gap #5/#6); doing it client-side guesses mechanism strings. | Adds a 4th endpoint. Frontend `/cost` page consumes it directly, no client aggregation. |
| **B** | **Four endpoints total**: `/api/flow/{cookie}`, `/api/flows`, `/api/cost`, `/api/recon` (vs. frontend spec's three). | **Four.** | Confirms scope of Phase-1 backend work. |
| **C** | **`?since=` format**: Go duration string (`"1h"`, `"30m"`) or integer seconds. | **Go duration string + int seconds**, relative. Not absolute Unix timestamps. | Simpler, matches tap's `since_sec`. Deep-linked URLs are stable enough because the frontend always re-derives `since` from the pill selection. Sign off if shareable absolute-time links are wanted. |
| **D** | **Per-request tap fetch** for drill-downs (backend spec) vs. filtering the existing 1h poll cache (frontend spec). | **Per-request `fetchEventsWindow(sinceSec)`** against the tap, with the poll cache as a fallback only. | The poll cache is fixed at 1h; filtering it silently truncates `?since=6h`. Per-request is correct and the tap read is cheap. |
| **E** | **Session-windowing for cookie reuse** (audit gap #1, HIGH). | **NOT in M8.** Ship `(cookie, since-window)` identity and cap the default + max selectable window at the cookie-reuse-safe range. The home wall and the safe windows are honest today; session-splitting is a fast-follow. | This is the single most important honesty call. See §6 gap #1. Sign off on the window cap (recommend default **1h**, max selectable **24h** with a banner). |
| **F** | **Score=0 handling.** | Emit raw `0` in JSON; **frontend renders `—`** and falls back to the tier ladder for sparklines (reusing `normalizeSpark`). Never show `0.00` as a headline score. | Honesty rule. Already how `LiveEscalation`/`normalizeSpark` behave. |
| **G** | **Per-touch vs. per-flow cost.** | Per-touch cost **is** attributable (join key is `(cookie, timestamp-ms)`); timeline rows show their own `Sting`. Zero-`Sting` T2/T3 rows render **"kernel-enforced · cost not attributed"**, not "0s held." | Audit gap #4. No store change for M8; honest labeling covers it. |
| **H** | **ReconTimeline order.** | **Oldest-first** (left=past). Differs from the live feed's newest-first. | Timeline UX. Sign off if newest-first is preferred for consistency. |
| **I** | **FlowDetail unknown cookie.** | **404** `{"error":"flow not found"}`. | Sign off if frontend prefers a 200 with `touch_count:0`. |
| **J** | **Empty mechanism in cost breakdown.** | **Omit** zero-`Sting` events from `ByMechanism` entirely (they carry no cost). | Audit gap #5. Sign off vs. bucketing them as `"none"`. |
| **K** | **Detail pages: polling, not SSE.** | **Polling** via `usePolling` (10s for `since≤5m`, 30s larger). Home wall keeps SSE. | Drill-downs inspect a historical window; live push would shift rows under the analyst. |
| **L** | **`useOverview()` on every drill-down page** (for live TopBar pills) opens one SSE per page. | **Accept** (only one drill page open at a time). Hoist into a provider later if it becomes a UX problem. | Minor; deferred. |

**Locked decisions (no signoff needed, carried from design sign-off):** dark security-ops aesthetic; canary-amber/sting-red/safe-green; Archivo + IBM Plex; all drill-down CSS reuses existing `globals.css` vars/classes; no second nav bar / modal / sidebar — breadcrumbs are a single monospace line; `body{overflow:hidden}` stays, drill pages scroll inside an `.app-console` grid; all `/api/*` proxied by `next.config.mjs` (no new proxy config).

---

## 1. Overview

Add **routed drill-down** to the existing single-page wall. The home wall (`/`) is unchanged visually but every escalation/tier/cost/recon element becomes a `<Link>`. Four new routes let a CISO inspect a flow, the flows table (tier-filtered), the attacker-cost breakdown, and the recon→escalation timeline — each scoped by a shared `?since=` time range.

**Backend:** four new read-only endpoints in the existing dashboard-backend, fed by per-request tap fetches (with poll-cache fallback), built by **pure derivation functions** in a new `views/drilldown.go` — same no-I/O/clock-injected pattern as `Derive()`. No tap changes, no engine changes, no new packages/binaries.

**Frontend:** four new app-router pages, a shared `SinceProvider` + `TimeRangeBar`, a `usePolling` hook, and five new presentational components — all reusing the locked design language.

**Data flow per request:**
```
GET /api/flow/0x3a?since=30m
  → serveFlowDetail: parseSince→1800; fetchEventsWindow(1800) [tap], fallback cachedEvents()
  → strconv.ParseUint("3a",16,64)
  → views.DeriveFlowDetail(0x3a, events, now)  [pure: filter→sort→timeline→fingerprint→Mbreakdown→spark]
  → JSON FlowDetail
```

---

## 2. Backend

All new code in package `backend` / package `views`. Handlers orchestrate **fetch → derive → encode**; all logic is in pure functions. Confirmed groundings from source:
- Go 1.22 stdlib mux supports `mux.HandleFunc("GET /api/flow/{cookie}", …)` + `r.PathValue("cookie")`.
- Event fields are `intelligence.AdversaryInteractionEvent{FlowID uint64, CanaryType, Timestamp, Features map[string]float64, Tier, Verdict, Score, Sting StingOutcome}`.
- `StingOutcome{Mechanism, TimeHeldSec, BytesServed, RequestsAbsrb int64, TokenCostProxy, DepthReached}` — **note the field is `RequestsAbsrb`, not `RequestsAbsorbed`**.
- Feature-map keys: `adjacency_novelty, identity_novelty, port_novelty, volume_deviation, cadence_deviation` (consts `featAdjacency` … in `views.go`).
- `baseline.DefaultParams()` → `Params{MMax, K, CMax: DefaultCMax=1.0}`; `baseline.MFromFeatures(Features, Params)`, `baseline.MFromD(d, Params)`, `baseline.Deviation(Features, Params)`, `baseline.Features{AdjacencyNovelty, IdentityNovelty, PortNovelty, VolumeDeviation, CadenceDeviation}`.
- Reusable same-package helpers: `groupByFlow`, `buildFlowView`, `normalizeSpark`, `computeMaxMAndPeak`, `featuresFromMap`, `clusterMembers`, `reconDescription`, `offsetLabel`, `buildReconFeed`, `DeriveFingerprint`, `cost.Rollup`.
- Existing `FlowFingerprint` JSON contract is the one in `fingerprint.go` (don't redefine).

### 2.1 Files

| File | Action |
|------|--------|
| `internal/dashboard/backend/views/drilldown.go` | CREATE — types + pure derivations |
| `internal/dashboard/backend/views/drilldown_test.go` | CREATE — table-driven derivation tests |
| `internal/dashboard/backend/backend.go` | MODIFY — `lastEvents` field, `fetchEventsWindow`, `cachedEvents`, `parseSince`, 4 handlers, route registration |
| `internal/dashboard/backend/backend_drill_test.go` | CREATE — handler tests via existing `fakeTap` |

### 2.2 Endpoints (the wire contract)

| Method+Pattern | Query params | Response type | Errors |
|---|---|---|---|
| `GET /api/flow/{cookie}` | `since` | `FlowDetail` | 400 invalid cookie; 404 not found; 503 tap-down & no cache |
| `GET /api/flows` | `tier` (−1=all), `since` | `FlowsList` | 503 only |
| `GET /api/cost` | `since` | `CostBreakdown` | 503 only |
| `GET /api/recon` | `since` | `ReconTimeline` | 503 only |

Every handler: `Content-Type: application/json`, `Cache-Control: no-store`. Error body is `{"error":"<msg>"}`. Frontend checks `res.ok` before parsing.

### 2.3 Go view structs (exact JSON tags)

These are the **new frontend contract**. Mirror 1:1 in `types.ts`.

```go
// TouchEvent is one canary touch in a flow's ordered timeline.
type TouchEvent struct {
    Timestamp   time.Time `json:"timestamp"`
    CanaryType  string    `json:"canary_type"`
    Tier        int       `json:"tier"`
    Verdict     string    `json:"verdict"`
    Score       float64   `json:"score"`          // 0 = pre-Score event; UI shows "—"
    M           float64   `json:"m"`              // MFromFeatures for THIS touch; 1.0 if none
    TimeHeldSec float64   `json:"time_held_sec"`
    BytesServed int64     `json:"bytes_served"`
    Requests    int64     `json:"requests"`       // from Sting.RequestsAbsrb
    TokenCost   float64   `json:"token_cost"`
    Mechanism   string    `json:"mechanism"`      // Sting.Mechanism; "" if none → UI: "kernel-enforced · cost not attributed"
}

type MContribution struct {
    Feature  string  `json:"feature"`   // "adjacency_novelty", ...
    RawValue float64 `json:"raw_value"`
    Capped   float64 `json:"capped"`    // min(max(raw,0), CMax)
    Label    string  `json:"label"`     // "adjacency nov." etc. (matches featureBars)
}
type MBreakdown struct {
    M             float64         `json:"m"`             // MFromFeatures over peak event
    Contributions []MContribution `json:"contributions"` // ALL 5 features (incl. port)
    GateNote      string          `json:"gate_note"`
}
type FlowDetail struct {
    FlowIDHex   string           `json:"flow_id_hex"`
    FlowID      uint64           `json:"flow_id"`
    TouchCount  int              `json:"touch_count"`
    PeakTier    int              `json:"peak_tier"`
    Verdict     string           `json:"verdict"`
    Score       float64          `json:"score"`        // latest; 0 if none
    FirstSeen   time.Time        `json:"first_seen"`
    LastSeen    time.Time        `json:"last_seen"`
    Timeline    []TouchEvent     `json:"timeline"`     // ascending timestamp
    Fingerprint *FlowFingerprint `json:"fingerprint,omitempty"`
    MBreakdown  *MBreakdown      `json:"m_breakdown,omitempty"` // nil if no features
    SparkSeries []float64        `json:"spark_series"` // normalizeSpark semantics
}
type FlowCost struct {
    TimeHeldSec float64 `json:"time_held_sec"`
    BytesServed int64   `json:"bytes_served"`
    Requests    int64   `json:"requests"`
    TokenCost   float64 `json:"token_cost"`
}
type FlowRow struct {
    FlowIDHex  string    `json:"flow_id_hex"`
    FlowID     uint64    `json:"flow_id"`
    PeakTier   int       `json:"peak_tier"`
    Verdict    string    `json:"verdict"`
    TouchCount int       `json:"touch_count"`
    Score      float64   `json:"score"`     // latest; 0 if none
    BaseM      float64   `json:"base_m"`    // max M across flow (peak M)
    TotalCost  FlowCost  `json:"total_cost"`
    FirstSeen  time.Time `json:"first_seen"`
    LastSeen   time.Time `json:"last_seen"`
}
type FlowsList struct {
    Flows      []FlowRow `json:"flows"`       // peak tier desc, then last_seen desc
    TotalCount int       `json:"total_count"` // before tier filter
    Filtered   int       `json:"filtered"`    // == len(Flows)
}
type MechanismCost struct {
    Mechanism   string  `json:"mechanism"`
    EventCount  int     `json:"event_count"`
    TimeHeldSec float64 `json:"time_held_sec"`
    BytesServed int64   `json:"bytes_served"`
    Requests    int64   `json:"requests"`
    TokenCost   float64 `json:"token_cost"`
}
type CostBucket struct {
    BucketStart time.Time `json:"bucket_start"`
    TimeHeldSec float64   `json:"time_held_sec"`
    TokenCost   float64   `json:"token_cost"`
    EventCount  int       `json:"event_count"`
}
type CostBreakdown struct {
    Total       FlowCost        `json:"total"`
    ByFlow      []FlowRow       `json:"by_flow"`      // sort by TotalCost.TimeHeldSec desc
    ByMechanism []MechanismCost `json:"by_mechanism"` // empty-mechanism events OMITTED (decision J)
    TimeSeries  []CostBucket    `json:"time_series"`  // zero-filled, bucketed
    BucketSec   int             `json:"bucket_sec"`
}
type ReconRow struct {
    FlowIDHex     string    `json:"flow_id_hex"`
    FlowID        uint64    `json:"flow_id"`
    Timestamp     time.Time `json:"timestamp"`
    OffsetLabel   string    `json:"offset_label"`   // offsetLabel(offset)
    CanaryType    string    `json:"canary_type"`
    Severity      string    `json:"severity"`       // "recon" | "surfaced"
    Description   string    `json:"description"`
    Escalated     bool      `json:"escalated"`      // flow later reached Tier>=2
    EscalatedTier int       `json:"escalated_tier"` // peak tier of this flow; 0 if not
}
type ReconTimeline struct {
    Rows       []ReconRow `json:"rows"`        // oldest first (decision H)
    TotalRecon int        `json:"total_recon"` // total T1 in window
}
```

### 2.4 Pure derivation functions (`drilldown.go`)

```go
DeriveFlowDetail(flowID uint64, events []AdversaryInteractionEvent, now time.Time) *FlowDetail
DeriveFlowsList(events []AdversaryInteractionEvent, tierFilter int) FlowsList
DeriveCostBreakdown(events []AdversaryInteractionEvent, now time.Time, bucketDur time.Duration) CostBreakdown
DeriveReconTimeline(events []AdversaryInteractionEvent, now time.Time) ReconTimeline
// private:
buildFlowRow(flowID uint64, grp []AdversaryInteractionEvent) FlowRow
mBreakdownFromEvent(e AdversaryInteractionEvent) *MBreakdown
costFromEvents(events []AdversaryInteractionEvent) FlowCost
bucketDurFor(sinceSec int) time.Duration
```

- **DeriveFlowDetail:** filter to `flowID` → nil if none. Sort ascending. Each `TouchEvent.M = MFromFeatures(featuresFromMap(e.Features), DefaultParams())`. `Score` passthrough (0 honest). `Requests` from `e.Sting.RequestsAbsrb`. `SparkSeries = normalizeSpark(rawScores, ordered)`. `Fingerprint = DeriveFingerprint(flowID, flowEvents)`. `MBreakdown = mBreakdownFromEvent(peakMEvent)` where peak event comes from `computeMaxMAndPeak` logic; nil if all `Features` nil/empty. `PeakTier`/`Verdict` via same forward pass as `buildFlowView`.
- **mBreakdownFromEvent:** `p := DefaultParams()`; per the 5 fields of `baseline.Features`, emit one `MContribution{RawValue, Capped: clamp(raw,0,p.CMax)}`. `M = MFromFeatures(f, p)`. Labels: `"adjacency nov."`, `"identity nov."`, `"port nov."`, `"volume dev."`, `"cadence dev."`. **Note:** the existing `featureBars` clamps to `[0,1]` and shows only 4 bars (omits port). `MBreakdown.Contributions` deliberately uses `CMax` (=1.0 by default, so numerically identical) and includes **all 5** features so the detail page is complete; document this divergence in a struct comment. `GateNote`: all-zero features → `"no features · M=1.0 (neutral)"`, else `"M derived from peak event · DefaultParams"`. (Gate live/calibrated state lives in the Overview's `CredibilityView`, not here.)
- **DeriveFlowsList:** `groupByFlow`; `buildFlowRow` per group; `TotalCount` = group count; filter `PeakTier==tierFilter` when `tierFilter>=0`; sort PeakTier desc then LastSeen desc; `Filtered=len(Flows)`.
- **buildFlowRow:** forward pass for PeakTier/Verdict/latest-Score/LastSeen/FirstSeen/TouchCount; `BaseM=computeMaxM(grp)`; `TotalCost=costFromEvents(grp)`.
- **DeriveCostBreakdown:** `Total=costFromEvents(all)`. `ByFlow`: `buildFlowRow` per cookie, sort by `TotalCost.TimeHeldSec` desc. `ByMechanism`: group by `e.Sting.Mechanism`, **skip `""`** (decision J), accumulate. `TimeSeries`: zero-filled buckets (algo below). `BucketSec=int(bucketDur.Seconds())`.
- **DeriveReconTimeline:** `escalationMap[flowID]=max tier` over **all** events; `t1 := events where Tier==1`; `clustered := clusterMembers(t1)`; sort `t1` ascending; each `ReconRow{Description: reconDescription(...), Severity, OffsetLabel: offsetLabel(now.Sub(ts).Seconds()*−1...), Escalated: escalationMap[id]>=2, EscalatedTier: escalationMap[id]}`. `TotalRecon=len(t1)`.

**bucketDurFor:** `d := time.Duration(sinceSec)*time.Second/24; if d<time.Minute {d=time.Minute}; if d>time.Hour {d=time.Hour}; return d.Truncate(time.Minute)`.

**TimeSeries zero-fill:** if no events → nil. `bucketStart=earliest.Truncate(bucketDur)`; `bucketEnd=now.Truncate(bucketDur)+bucketDur`; `n=int((bucketEnd-bucketStart)/bucketDur)` **capped at 1440**; alloc `n` buckets with `BucketStart` set; for each event `idx=int(e.Timestamp.Sub(bucketStart)/bucketDur)` (skip out-of-range), accumulate.

### 2.5 `backend.go` changes

1. Add `lastEvents []intelligence.AdversaryInteractionEvent` to `Backend` (after `tapOK bool`, line ~49).
2. In `poll()` success block (alongside `b.last=&ov`), under `b.mu.Lock()`: `b.lastEvents = events` (value types, shallow copy safe).
3. Refactor: rename `fetchEvents()` → `fetchEventsWindow(sinceSec int)`; add wrapper `func (b *Backend) fetchEvents() (...) { return b.fetchEventsWindow(int(b.cfg.EventsWindow.Seconds())) }`. Existing `poll()`/tests unchanged.
4. Add `cachedEvents() ([]intelligence.AdversaryInteractionEvent, bool)` — RLock, return copy + `ok=false` if `lastEvents==nil`.
5. Add package helper:
```go
func parseSince(r *http.Request, def time.Duration) int {
    v := r.URL.Query().Get("since")
    if v == "" { return max1(int(def.Seconds())) }
    if d, err := time.ParseDuration(v); err == nil && d > 0 { return max1(int(d.Seconds())) }
    if n, err := strconv.Atoi(v); err == nil && n > 0 { return n }
    return max1(int(def.Seconds()))
}
func max1(n int) int { if n < 1 { return 1 }; return n }
```
6. Four handlers, all following: `sinceSec := parseSince(r, b.cfg.EventsWindow)`; `events, err := b.fetchEventsWindow(sinceSec)`; on err `events, ok := b.cachedEvents()`; if `!ok` → 503 `{"error":"tap unreachable and no cached events"}`; else derive + encode.
   - `serveFlowDetail`: `cookie := r.PathValue("cookie")`; `id, err := strconv.ParseUint(strings.TrimPrefix(cookie,"0x"),16,64)` → 400 on err; `d := DeriveFlowDetail(id, events, time.Now())`; nil → 404.
   - `serveFlowsList`: `tier := -1`; parse `?tier=` (invalid → −1).
   - `serveCostBreakdown`: `bucketDurFor(sinceSec)`.
   - `serveReconTimeline`.
7. `Handler()` registration:
```go
mux.HandleFunc("GET /api/flow/{cookie}", b.serveFlowDetail)
mux.HandleFunc("GET /api/flows",          b.serveFlowsList)
mux.HandleFunc("GET /api/cost",           b.serveCostBreakdown)
mux.HandleFunc("GET /api/recon",          b.serveReconTimeline)
```

### 2.6 Backend tests

`drilldown_test.go` (package `views`, reuse `ev`/`evScore`, add `evSting(...)` helper):
`TestDeriveFlowDetailEmpty/Timeline/ScoreZeroGraceful/Fingerprint/MBreakdown/MBreakdownNilWhenNoFeatures`; `TestDeriveFlowsListEmpty/TierFilter/TierFilterNone/Sort`; `TestDeriveCostBreakdownTotal/ByMechanism/EmptyMechanismOmitted/TimeSeries/TimeSeriesZeroBuckets`; `TestDeriveReconTimelineEmpty/OldestFirst/Escalation/NoEscalation/Severity`.

`backend_drill_test.go` (package `backend`, reuse `fakeTap` — it already serves `/raw/events` with arbitrary events, sufficient as-is):
`TestServeFlowDetail/InvalidCookie/NotFound`; `TestServeFlowsList/TierFilter`; `TestServeCostBreakdown`; `TestServeReconTimeline`; `TestServeDrillDownFallsBackToCacheOnTapError`; `TestParseSince` (table: durations, int seconds, missing, invalid).

**Gate:** `go test ./internal/dashboard/backend/...` green; then `make check` EXIT=0.

---

## 3. Frontend

App root: `dashboard/app`. All `/api/*` auto-proxy via `next.config.mjs` rewrite (`DASHBOARD_BACKEND_URL ?? http://127.0.0.1:8089`) — **no config change**.

### 3.1 File tree

```
dashboard/app/
├── app/
│   ├── layout.tsx                  [MODIFY] wrap children in <Suspense><SinceProvider>
│   ├── page.tsx                    [MODIFY] pass link props to wall components (no visual change)
│   ├── globals.css                 [MODIFY] append drill-down CSS section (below existing marker only)
│   ├── flow/[cookie]/page.tsx      [CREATE]
│   ├── flows/page.tsx              [CREATE]
│   ├── cost/page.tsx               [CREATE]
│   └── recon/page.tsx              [CREATE]
├── components/
│   ├── SinceProvider.tsx           [CREATE] context for ?since= (read/write via URL)
│   ├── TimeRangeBar.tsx            [CREATE] 1h/6h/24h pills (7d gated — see gap #1)
│   ├── Breadcrumbs.tsx             [CREATE]
│   ├── FlowDetail.tsx              [CREATE] header + fingerprint + timeline + M breakdown + cost
│   ├── EventTimeline.tsx           [CREATE] ordered touch rows
│   ├── FlowsTable.tsx              [CREATE] tier-filterable table, cookie cells → /flow/:cookie
│   ├── CostView.tsx               [CREATE] total + by-mechanism + by-flow + time-series
│   ├── ReconTimeline.tsx           [CREATE] T1 rows + escalation badges
│   ├── TierLadder.tsx              [MODIFY] optional linkTiers prop
│   ├── LiveEscalation.tsx          [MODIFY] optional linkFlow prop
│   ├── KernelContainment.tsx       [MODIFY] optional linkFlows prop
│   ├── AttackerCost.tsx            [MODIFY] optional linkCost prop (→ /cost)
│   └── AdversaryIntelligence.tsx   [MODIFY] optional linkRecon/linkFlows props
└── lib/
    ├── types.ts                    [MODIFY] append drill-down types (mirror §2.3 exactly)
    ├── api.ts                      [MODIFY] append url builders + fetchers
    ├── usePolling.ts               [CREATE] generic polling hook
    └── fixture.ts                  [MODIFY] add FlowDetail/FlowsList/CostBreakdown/ReconTimeline fixtures
```

### 3.2 `types.ts` additions

Mirror the §2.3 structs **exactly** (snake_case, this file IS the wire contract). Reuse the existing `FlowFingerprint` interface (already present). Add: `TouchEvent`, `MContribution`, `MBreakdown`, `FlowDetail`, `FlowCost`, `FlowRow`, `FlowsList`, `MechanismCost`, `CostBucket`, `CostBreakdown`, `ReconRow`, `ReconTimeline`. Timestamps are `string` (RFC3339). Comment `score` fields: `// 0 = pre-Score event — render "—"`.

### 3.3 `api.ts` additions

```ts
export function flowDetailURL(cookie: string, since: string)  { return `/api/flow/${cookie}?since=${since}`; }
export function flowsURL(tier: number, since: string)         { return `/api/flows?since=${since}${tier>=0?`&tier=${tier}`:''}`; }
export function costURL(since: string)                        { return `/api/cost?since=${since}`; }
export function reconURL(since: string)                       { return `/api/recon?since=${since}`; }
// fetchFlowDetail/fetchFlows/fetchCost/fetchRecon — same shape as fetchOverview (cache:'no-store', check res.ok, throw on !ok)
```
`since` is the Go-duration string the pills produce (`"1h"`, `"6h"`, `"24h"`). Cookie hex strings are URL-path-safe as-is (`fmt.Sprintf("0x%x")`), no sanitization needed.

### 3.4 `usePolling.ts`

```ts
'use client';
usePolling<T>(url: string, sinceSec: number, opts?: {intervalMs?: number}): {data:T|null; loading:boolean; error:string|null}
// fetch immediately on mount; setInterval(intervalMs ?? (sinceSec<=300?10000:30000));
// cancel on unmount/url change; keep last-good data on error, set error string.
```

### 3.5 Navigation: `SinceProvider` + `TimeRange`

`since` is a **Go-duration string** in the URL (`?since=6h`) so it passes straight to the backend. `SinceProvider` (`'use client'`) reads `useSearchParams().get('since') ?? '1h'`, exposes `{ since: string, sinceSec: number, setSince(s: string) }` via context; `setSince` does `router.push(pathname + ?since=… preserving other params)`. `layout.tsx` wraps `children` in `<Suspense><SinceProvider>` (Suspense required for `useSearchParams` in Next 14). `layout.tsx` stays a Server Component; the provider is the client boundary.

`TimeRangeBar` renders pills `1h | 6h | 24h` (7d hidden unless gap #1 resolved). Active pill: `border-color: rgba(255,206,58,0.45); color: var(--canary)`. Rendered **in each drill page** (next to breadcrumbs), **not** on the home wall — the wall stays time-range-free (decision: home links carry `?since=1h` default).

### 3.6 Home wall wiring (`page.tsx` + 5 components)

Additive only — no DOM/class/animation changes. Each wall component gets an **optional** link prop (default off, so fixture/standalone use is unaffected):
- `LiveEscalation linkFlow` → wrap `flow_id_hex` in `<Link href={/flow/${flow.flow_id_hex}?since=1h}>`.
- `TierLadder linkTiers` → each rung count → `<Link href={/flows?tier=${step.tier}&since=1h}>`.
- `AttackerCost linkCost` → panel `onClick={()=>router.push('/cost?since=1h')}` + `cursor:pointer` hover ring.
- `KernelContainment linkFlows` → each cookie row → `<Link href={/flow/${f.flow_id_hex}?since=1h}>`.
- `AdversaryIntelligence linkRecon linkFlows` → recon section → `/recon?since=1h`; fingerprint/row `flow_id_hex` → `/flow/:cookie`.

`page.tsx` passes the props. Home wall remains pixel-identical to `dashboard/design/prototype.html`; only cursor/hover affordances appear.

### 3.7 Drill-down pages

All four share the shell: `<div className="app-console">` (grid `60px 1fr`, `height:100vh`) → `<TopBar snapshot status>` (from `useOverview()`, keeps pills live) → `<main className="detail-page">` (scrollable) → header row `[Breadcrumbs | TimeRangeBar]` → the view component fed by `usePolling`.

- **`/flow/[cookie]`** — `useParams<{cookie:string}>()` (Next 14: `useParams`, NOT `params` prop). `usePolling<FlowDetail>(flowDetailURL(cookie, since), sinceSec)`. Renders `<FlowDetail>`. Crumbs: OPERATIONS / FLOW / `cookie`.
- **`/flows`** — `tier = Number(useSearchParams().get('tier') ?? -1)`. `usePolling<FlowsList>(flowsURL(tier, since), sinceSec)`. `<FlowsTable>`. Crumbs: OPERATIONS / FLOWS.
- **`/cost`** — `usePolling<CostBreakdown>(costURL(since), sinceSec)`. `<CostView>`. Crumbs: OPERATIONS / ATTACKER COST. **(Uses dedicated `/api/cost`, decision A.)**
- **`/recon`** — `usePolling<ReconTimeline>(reconURL(since), sinceSec)`. `<ReconTimeline>`. Crumbs: OPERATIONS / RECON.

### 3.8 Components (props + behavior)

- **Breadcrumbs** `{crumbs:{label,href?}[]}` — monospace `/`-separated; `href` crumbs are `<Link>` (`.crumbs a`), last is `.cur`.
- **FlowDetail** `{detail:FlowDetail|null; loading; cookie}` — (1) header: `flow_id_hex` in `.ip`, verdict in `.role`, **score → `—` if 0**, `<Spark series={detail.spark_series}/>`; (2) fingerprint via existing `.fp`/`.fp-hash` classes (only if `detail.fingerprint`); (3) `<EventTimeline events={detail.timeline}/>`; (4) M breakdown via `.feats`/`.feat` bars from `detail.m_breakdown.contributions` (all 5; widths = `capped`), `gate_note` as caption; (5) cost strip from summing timeline (or reuse `.aresp`).
- **EventTimeline** `{events:TouchEvent[]}` — vertical `.timeline`/`.trow` grid: `[offset][canary chip][tier badge t1/t2/t3][score or —][mechanism or "kernel-enforced · cost not attributed"][time/tokens]`. Tier colors: `--tag`(T1)/`--contain`(T2)/`--sting`(T3). Per-touch column labeled **"M (this touch)"** to distinguish from header peak-M.
- **FlowsTable** `{data:FlowsList|null; tierFilter; loading}` — `.flows-table`: cols `cookie | tier | score | touches | last seen | time imposed | tokens`. Cookie cell `<Link href={/flow/${row.flow_id_hex}?since=…}>`. Tier-filter pill row (T0/T1/T2/T3/all) → `router.replace(?tier=N)`. T3 rows tinted sting-red, T2 contain-orange. Note if `data.flows.length > 200`.
- **CostView** `{data:CostBreakdown|null; loading}` — three panels: totals (`.aresp` hero: time/tokens/bytes/reqs from `data.total`), by-mechanism table (`data.by_mechanism`), by-flow list (`data.by_flow`, each cookie `<Link>` + per-flow `<Spark>` if available), and a simple bar/sparkline over `data.time_series` (gap-free thanks to zero-fill).
- **ReconTimeline** `{data:ReconTimeline|null; loading}` — full `.feed`/`.ev` table of **all** T1 (not capped at 10): `offset | cookie | canary_type | description | severity(recon/surfaced) | escalation`. Escalation: if `escalated`, `<Link className={esc-badge t${escalated_tier}} href={/flow/${flow_id_hex}}>T${escalated_tier}</Link>`, else `—`.

### 3.9 Live-vs-snapshot policy

- **Home `/`**: SSE (`useOverview`) — always "right now". Unchanged.
- **All four drill pages**: `usePolling` (decision K). Adaptive interval 10s (`since≤5m`) / 30s (larger). On error: keep last-good data, show a `.faint mono` error strip below breadcrumbs (same treatment as "NO ACTIVE ESCALATION"). Loading: `—` placeholder skeleton rows, never spinners.
- `TopBar` pills stay live on drill pages via `useOverview()` (one SSE per page; decision L).

### 3.10 CSS (`globals.css`)

Append a new section below the existing "Next.js reset additions" marker — **do not touch anything above it**. Classes: `.app-console` (grid `60px 1fr`, `height:100vh`), `.detail-page` (`flex:1; overflow-y:auto; padding:24px 32px; gap:28px`), `.crumbs`(+`a`,`.sep`,`.cur`), `.trange`/`.pill-btn`(+`.active`), `.timeline`/`.trow`(+`.t-offset`,`.t-type`,`.t-tier.t1/t2/t3`,`.t-score`,`.t-mech`,`.t-cost`), `.flows-table`(`th`/`td`/`tr:hover`/`td.cookie a`), `.esc-badge.t2/.t3`, `.detail-section`. All reuse existing vars (`--canary`,`--sting`,`--contain`,`--tag`,`--ink*`,`--line*`,`--panel*`,`--mono`). Verbatim block in the frontend spec is the source of truth.

---

## 4. (No frontend test framework)

`make check` covers Go only. Frontend verification is: `npm run build` (type-check + compile) and **fixture-driven visual checks** (`NEXT_PUBLIC_FIXTURE=1`) + live screenshots. Add a fixture per new view type to `lib/fixture.ts`.

---

## 5. Phased build sequence (founder's order)

Each phase ends with a hard gate. Screenshot every route at the end.

**Phase 0 — Backend endpoints + `since`**
1. `views/drilldown.go`: 12 types + 4 derivations + helpers.
2. `views/drilldown_test.go`: all cases. Gate: `go test ./internal/dashboard/backend/views/...`.
3. `backend.go`: `lastEvents`, `fetchEventsWindow`+wrapper, `cachedEvents`, `parseSince`, 4 handlers, route registration.
4. `backend_drill_test.go`. Gate: `go test ./internal/dashboard/backend/...`, then **`make check` EXIT=0**.
5. Smoke (tap or fake running): `curl localhost:8089/api/flows?since=1h`, `/api/flow/0x118?since=1h`, `/api/cost?since=1h`, `/api/recon?since=1h`.

**Phase 1 — Frontend data layer + nav infra**
6. `types.ts` (mirror §2.3), `api.ts` builders/fetchers, `usePolling.ts`, `SinceProvider.tsx`, `layout.tsx` Suspense wrap, `Breadcrumbs.tsx`, `TimeRangeBar.tsx`, `globals.css` drill section, `fixture.ts` fixtures. Gate: `npm run build` clean.

**Phase 2 — `/flow/[cookie]`**
7. `EventTimeline.tsx`, `FlowDetail.tsx`, `app/flow/[cookie]/page.tsx`. Gate: `npm run build`; screenshot `/flow/0x118?since=1h` (fixture + live) — timeline, fingerprint, M bars, cost, Score=0 shows `—`.

**Phase 3 — Flows table + tier links**
8. `FlowsTable.tsx`, `app/flows/page.tsx`; wire `TierLadder`/`LiveEscalation`/`KernelContainment` link props + `page.tsx`. Gate: `npm run build`; screenshot `/flows?tier=2&since=1h`; confirm wall tier rungs/cookies navigate.

**Phase 4 — `/cost`**
9. `CostView.tsx`, `app/cost/page.tsx`; wire `AttackerCost linkCost`. Gate: `npm run build`; screenshot `/cost?since=1h` — totals, by-mechanism, by-flow, gap-free time series.

**Phase 5 — `/recon`**
10. `ReconTimeline.tsx`, `app/recon/page.tsx`; wire `AdversaryIntelligence` link props. Gate: `npm run build`; screenshot `/recon?since=1h` — full T1 list + escalation badges link to `/flow/:cookie`.

**Phase 6 — Wire the home wall + full verification**
11. Final `page.tsx` pass enabling all link props together. Gates:
    - `make check` EXIT=0 (backend).
    - `npm run build` clean (frontend).
    - Screenshot `/` (fixture) — **pixel-identical to `dashboard/design/prototype.html`**, only hover/cursor added.
    - Screenshot each of `/flows?tier=2`, `/flow/0x118?since=1h`, `/cost?since=1h`, `/recon?since=1h` (live, backend running).
    - Verify browser back returns to `/` preserving context; `TimeRangeBar` change updates URL `?since=` and re-fetches.

---

## 6. Consolidated DATA GAPS (severity · mitigation · M9 effect)

| # | Gap | Severity | Blocks? | Mitigation in M8 | Improved by M9 LLM attacker? |
|---|-----|----------|---------|------------------|------------------------------|
| **1** | **Cookie-reuse flow identity.** Socket cookies are kernel-recycled; over a long window the same cookie maps to distinct connections. `groupByFlow` keys on cookie only. | **HIGH** | Flows table & cost fully at windows ≫1h; flow detail partially | **Ship `(cookie, since-window)` identity; default `since=1h`, cap selectable at 24h, banner on >1h: "Windows > 1h may merge reused cookies."** Within 1h reuse is negligible. **Session-windowing** (split a cookie's events when a gap > ~5–10m; pure view-layer `groupByFlowSessions`, no store change, ~1 day) is the real fix — **fast-follow, decision E.** | Indirectly. M9 produces longer, more varied sessions that make session-windowing more valuable, but does not change the kernel cookie reuse. The fix is independent of M9. |
| **2** | **Per-request time-range override** on the API. The backend used one fixed `EventsWindow`. | **HIGH** | All four drill-downs | **Resolved by this plan:** `fetchEventsWindow(sinceSec)` per request + `?since=` parsing (decision D). No longer a gap once Phase 0 lands. | N/A |
| **3** | **Score=0 on pre-Score events** → misleading headline. | **MEDIUM** | Degrades flow detail | Emit raw 0; **UI renders `—`**; `normalizeSpark` falls back to tier ladder (already implemented). Label "score unavailable — pre-calibration record" when all events score 0 (decisions F). | Yes — all M9 events carry real `Score`, so the gap shrinks to historical records only. |
| **4** | **Per-touch vs. per-flow cost / async-path attrition not captured.** `AmendOutcome` writes the real `Sting` blob keyed `(cookie, ts-ms)` only for inline T2/T3; kernel-async enforcement may never write it → zero `Sting` rows. | **MEDIUM** | Degrades flow-detail cost column | Per-touch cost **is** attributable for inline events (timeline rows carry their own `Sting`). Zero-`Sting` rows render **"kernel-enforced · cost not attributed"**, never "0s held" (decision G). No store change for M8. | Yes (partially) — M9 drives more inline T2/T3 interactions (more amended outcomes), so more rows have real cost. The async-path capture (kernel callback) remains separate future instrumentation. |
| **5** | **No per-mechanism cost rollup** in `cost.Summary`. | **LOW** | Degrades cost breakdown | New `DeriveCostBreakdown` does a grouped pass by `Sting.Mechanism` in the view layer (decision A). `cost.Rollup` stays the totals building block. Empty-mechanism events omitted (decision J). | Neutral — same code path; M9 just populates more mechanisms. |
| **6** | **Mechanism string values not canonicalized** (`Mech*` consts live in `internal/sting/attrition`, not surfaced). | **LOW** | Degrades cost breakdown if a new mechanism appears | Backend emits whatever string the event carries; frontend renders the string verbatim (no hard-coded mechanism set), so unknown values display correctly rather than vanishing. Optional follow-up: export `Mech*` consts. | Neutral. |
| **7** | **Unconditional "▲ escalating"** label (pre-existing in `LiveEscalation`). | **LOW** | No | Out of scope for M8 drill-down; `FlowDetail` can compute the real score delta (▲/▬/▼) as a secondary task. | Yes — richer M9 trajectories make trend direction meaningful. |
| **8** | **Source identity empty** (`source_label` blank; cookie-only identity per CLAUDE.md rule 4/9). | **LOW** | No | UI labels identity as cookie hex only; never "attacker IP." | **This is the M9/registry feature** — the planned registry join attaches L7 identity, which is exactly what fills `source_label`. |

**M9 summary:** the LLM attacker most improves gaps **#3 (real scores everywhere), #4 (more inline cost-attributed rows), #7 (meaningful trends), and #8 (identity via the M9 registry join)**. It does **not** fix **#1 (cookie reuse)** — that is an independent view-layer change — and is **neutral** to #2/#5/#6.

---

## 7. Reconciliation notes (where the specs disagreed)

For the reviewer — the spec conflicts I resolved and why:
- **Wire contract shape:** chose the backend spec's flat typed structs (`FlowRow`, `FlowDetail`, `TouchEvent`) over the frontend spec's nested `FlowDetailView{ Flow FlowView; Events []EventRow }`. The flat forms match `views.go` conventions and avoid double-nesting `FlowView` inside the detail. `types.ts` mirrors §2.3.
- **`/api/cost`:** kept it as a dedicated endpoint (decision A) — the frontend spec's "reuse `/api/flows` and aggregate client-side" can't honestly do by-mechanism (gaps #5/#6).
- **Fetch model:** per-request tap fetch (backend spec, decision D), not cache-filtering (frontend spec) — the cache is fixed at 1h.
- **Field name:** `Sting.RequestsAbsrb` (verified in source), surfaced as json `requests` / `requests_absorbed`.
- **Routing:** Go 1.22 method+pattern mux + `PathValue` (backend spec) over the frontend spec's `/api/flow/` prefix-match handler — cleaner and version-supported.
- **M breakdown:** included all 5 features capped at `CMax` (=1.0), noting the existing `featureBars` shows only 4 clamped to [0,1]; the detail page is intentionally more complete.

**Relevant files:** `/Users/danielhenley/projects/canary-sting/canarysting-repo/internal/dashboard/backend/backend.go`, `…/views/views.go`, `…/views/fingerprint.go`, `…/internal/intelligence/event.go`, `…/internal/intelligence/cost/cost.go`, `…/internal/engine/baseline/baseline.go`, `…/dashboard/app/lib/types.ts`, `…/dashboard/app/lib/api.ts`, `…/dashboard/app/app/page.tsx`, `…/dashboard/app/next.config.mjs`, `…/dashboard/design/prototype.html`.
