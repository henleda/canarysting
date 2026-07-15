# Storefront SPA Design — service C replacement

Design for replacing the minimal service-C storefront (`cmd/service-c/main.go`) with a
believable e-commerce SPA whose shopping actions drive real east-west traffic through the
existing 6-service mock mesh. Read-only research; every claim about existing code carries a
file:line citation. Authored 2026-07-15 by fable-storefront.

---

## 0. Ground truth (what exists today)

**service-c** (`cmd/service-c/main.go`):
- Routes: `/healthz` (main.go:162), `GET /` server-rendered HTML page (main.go:164-165,
  177-207), `POST /api/transaction` (main.go:166-167), everything else 404 (main.go:168-169).
- Standard persona drives `standardPaths = ["/", "/api/status"]` (main.go:124) against the
  gateway via the `gatewayCaller` seam (main.go:37-39, 215-226).
- Redteam persona launches the in-process cassette-replay attacker via `redteamLauncher`
  / `cassetteLauncher` (main.go:62-118); single-slot, rejoins an active run, returns `run_id`
  (main.go:89-118, 227-238). The attacker makes its own gateway calls over its own HTTPTool —
  service C makes zero `gw.Fetch` calls on that path (main.go:58-61).
- Env config: `GATEWAY_URL` (default `http://gateway.canarysting.svc.cluster.local:8080`),
  `LISTEN` (`:8000`), `DASHBOARD_URL`, `CASSETTE_PATH` (main.go:132-135).
- Deployed from the `canarysting/core` image (deploy/kina/90-servicec.yaml:33), ClusterIP
  :8000 (90-servicec.yaml:80) plus NodePort 30302 (90-servicec.yaml:90-102).

**Mesh** (`deploy/m7-window/mesh/main.go` + `deploy/kina/60-mesh.yaml`):
- One binary is every service; `SVC_NAME`/`LISTEN`/`DOWNSTREAMS` shape the role (main.go:1-6,
  75-83). Deployed graph: `frontend → api → {auth, db, cache, payments}`
  (60-mesh.yaml:37-38, 97-98); auth/db/cache/payments have no downstreams
  (60-mesh.yaml:152-156 and siblings). Envoy gateway routes to `frontend`; frontend is the
  only externally reachable mesh service (60-mesh.yaml:4-6).
- Served surface: `/` and `/index.html` (fanout + landing page, main.go:148-152),
  `/robots.txt` (main.go:153-155), `/favicon.ico` (main.go:156-157), `/api/*` (fanout, then
  `serveAPI`, main.go:158-162), everything else a real 404 (main.go:163-164). `serveAPI`
  currently answers only `/api/health` and `/api/status`; other `/api/*` → 404
  (main.go:184-195).
- **Fanout semantics (load-bearing for this design):** `fanout` always calls each downstream
  at `/` regardless of the inbound path (main.go:106-117, specifically `d+"/"` at
  main.go:108), and fanout fires for ANY `/api/*` path BEFORE `serveAPI` decides 200 vs 404
  (main.go:158-162). Two consequences:
  1. A request to an unknown path like `/api/cart` on frontend already produces the FULL
     east-west chain today (frontend→api→auth+db+cache+payments) with zero mesh changes —
     only frontend's response to the gateway is a 404 (cosmetic).
  2. The mesh cannot today differentiate flows per action (login lighting up only auth):
     every `/` or `/api/*` request triggers the identical full fan-out.
- Canary prefixes are 404'd defensively and never served (main.go:57-73, 139-145).

**Canary-free constraint** (`cmd/envoy-adapter/main.go:243-249`): the decoy paths are
`/.aws/credentials`, `/secrets/`, `/.env`, `/config/`, `/backup/db.sql`, `/backup/`,
`/internal/buckets`, `/internal/`, `/admin/metrics`, `/admin/`. The comment at
envoy-adapter/main.go:240-242 already designates `/shop,/search,/products,/account,/cart,
/checkout,/orders` as legit-generator paths disjoint from the negative space. The existing
scope-guard test `TestStandardPathsAreCanaryFree` (cmd/service-c/main_test.go:85-96) asserts
disjointness against a hand-mirrored prefix list (main_test.go:79-81) AND that every standard
path is `/` or `/api/*` (main_test.go:92-93).

**Dashboard build path (reuse candidate):** Next.js 14.2 standalone app in `dashboard/app/`,
built by `deploy/kina/Dockerfile.dashboard-web` (node:20-alpine two-stage, standalone output,
port 3001), loaded via `load-images.nu` `load-dashboard-web` with `--no-cache` + k8s.io
bridge (load-images.nu:74-80), exposed on NodePort 30301
(deploy/kina/81-dashboard-nodeport.yaml:15-22). `Dockerfile.core` COPYs the whole repo
because of `go:embed` bpf .o files (per the comment at Dockerfile.dashboard-web:2-5) — i.e.
go:embed asset embedding is already the established pattern in the core image.

---

## 1. What it looks like — a believable storefront

A single-page store for a fictional outdoor-gear brand (working name: **"Meridian Supply
Co."** — fictional, no real-org branding). Client-side hash routing, one HTML shell. Views:

- **Header (persistent):** logo, category nav (Camping, Climbing, Apparel, Electronics),
  search box, cart icon with item-count badge, account/login link, and the **persona
  switcher** — a labeled pill toggle `Standard | Redteam` on the far right. Standard is the
  default. Flipping to Redteam paints a persistent red banner across the top:
  *"Red-team test mode — launches a simulated attacker against this environment"* with a
  **Run security test** button and (when `DASHBOARD_URL` is set, main.go:128-134) a
  *"Watch on operator dashboard"* link. Shopping UI stays usable in either mode; the banner
  makes the mode unmistakable to a demo audience.
- **Home / catalog:** hero strip, category tiles, product grid (~12 products, 4 categories)
  with inline-SVG product art (no external image hosts — self-contained page), price,
  "Add to cart" per card.
- **Category / search results:** same grid filtered client-side; the search box drives a
  search action (traffic-generating, see §3) plus client-side filtering for instant UX.
- **Product detail:** larger art, description, price, quantity picker, Add to cart, "related
  items" row.
- **Cart drawer/page:** line items, quantity +/-, remove, subtotal, "Proceed to checkout."
- **Login/account:** email + password form prefilled with demo credentials
  (`demo@example.com`); on "sign in" shows a signed-in state in the header. Purely
  presentational auth — the point is the auth-service traffic, not a session system.
- **Checkout:** shipping summary + order summary prefilled with obviously-demo data and a
  "Place order" button. No realistic card-entry fields — a "Demo payment on file" line
  instead (keeps the page believable without building a fake payment form).
- **Order confirmation + order history:** confirmation with a generated order number;
  "Your orders" list accumulated client-side for the session.

Product data is a static embedded `catalog.json` shipped with the SPA. The mesh services
return simple JSON stubs (mesh main.go:184-195) — the SPA drives them for the traffic
pattern, never for product data.

## 2. Tech decision — static SPA served by the Go service-c binary (option b)

**Recommendation: a hand-authored static SPA (vanilla ES-module JS + CSS, no build step),
embedded into the existing service-c binary with `go:embed`, served at `/`.** Not a second
Next.js app.

Restraint-ladder walk:
- Rung 2 (already in codebase): service-c already serves the storefront HTML from the same
  binary (main.go:177-207) and already owns the API seams the SPA needs (main.go:160-171).
  Extending it is the incumbent pattern.
- Rung 3 (stdlib): `go:embed` + `http.FileServer` cover static serving; the core image
  already COPYs the whole repo precisely to support go:embed assets
  (Dockerfile.dashboard-web:2-5 comment).
- A second Next.js app (option a) buys the dashboard's proven build path
  (load-images.nu:74-80) but costs: a second npm dependency tree, a second image + manifest +
  NodePort, and a CORS/proxy hop between the SPA origin and service-c's `/api/*` (the
  dashboard is an operator tool; the storefront is the *demo subject* — they don't need to
  share a stack). The SPA's behavior is a catalog grid + fetch calls; it does not need React
  server components, SSR, or a routing framework.
- A Vite/React SPA (option b-heavy) adds a node build stage to `Dockerfile.core` (or a
  pre-build committed dist) for what is ~4 views of DOM. Not justified at this scope; if the
  UI later grows real complexity, the dashboard's Next path is the documented upgrade route.

What this preserves (hard requirements from the current design):
- The `gatewayCaller` seam and canary-free Standard path (main.go:34-39, 120-124) — all new
  action endpoints drive the gateway through the same interface, unit-testable with the
  existing `recordingFake` pattern (main_test.go:61-72, 128-135).
- The `redteamLauncher`/`cassetteLauncher` mechanism unchanged (main.go:62-118).
- The `POST /api/transaction` contract (main.go:215-242) — kept as-is for the redteam launch
  and for backward compatibility with existing tests and any demo scripting.
- 12-factor env config: `GATEWAY_URL`/`LISTEN`/`DASHBOARD_URL`/`CASSETTE_PATH`
  (main.go:132-135). No new env vars are required; `DASHBOARD_URL` gets injected into the SPA
  shell the same way it is today (main.go:179-182) or via a tiny `GET /api/store/config`.

Layout: `cmd/service-c/static/` (index.html, app.js, styles.css, catalog.json, svg art),
embedded with `//go:embed static` and served by the router's default case instead of 404
(replacing main.go:168-169 for GET; unknown `/api/*` still 404).

## 3. Action → mesh-traffic map (the point of the exercise)

All shopping actions flow **SPA → service-c action endpoint → gateway (`GATEWAY_URL`,
Envoy :8080, deploy/kina/40-gateway.yaml:128-141) → frontend → api → {auth,db,cache,
payments}** (60-mesh.yaml:37-38, 97-98). The browser never talks to the gateway directly
(it can't — gateway is ClusterIP-only); service-c proxies via `gw.Fetch`, exactly the
`standardPaths` mechanism today (main.go:217-226), generalized to a per-action path table:

```go
// actionPaths: ordered gateway paths each storefront action drives.
// Every path is mesh-served ("/" or "/api/*", mesh main.go:147-165) and
// disjoint from the canary negative space (envoy-adapter main.go:243-249).
var actionPaths = map[string][]string{
    "browse":   {"/", "/api/products"},
    "search":   {"/api/search"},
    "product":  {"/api/products"},          // detail view re-fetches the catalog stub
    "login":    {"/api/login", "/api/session"},
    "cart":     {"/api/cart"},              // add/view/update all drive the same path
    "checkout": {"/api/checkout", "/api/orders"},
    "orders":   {"/api/orders"},
}
```

Path names deliberately reuse the legit-generator set already documented as disjoint from
the canaries (envoy-adapter main.go:240-242: `/search,/products,/account,/cart,/checkout,
/orders`), lifted under `/api/` to satisfy the served-surface rule (mesh main.go:158;
scope-guard main_test.go:92-93). None of the canary prefixes (`/.aws/credentials`,
`/secrets/`, `/.env`, `/config/`, `/backup/`, `/internal/`, `/admin/`) begins with `/api`,
so disjointness holds by construction — and the extended scope-guard test asserts it
(see §5).

**East-west flows, staged honestly:**

- **Stage 1 (zero mesh changes):** every action above already produces the full genuine
  chain `gateway→frontend→api→auth+db+cache+payments`, because mesh fanout fires on any
  `/api/*` path before the 200/404 decision (mesh main.go:158-162) and each internal hop is
  a distinct keep-alive-free flow (mesh main.go:85-105). Hubble sees real multi-service
  east-west traffic per click. Limitation: frontend answers 404 for the new paths
  (serveAPI knows only health/status, mesh main.go:184-195), and every action's flow
  signature is identical (fanout is unconditional and path-blind, mesh main.go:106-117).
- **Stage 2 (small mesh stub extension):** add the storefront paths to `serveAPI` with
  plausible JSON stubs (`/api/products` → `{"service":"db","items":N}` style), so frontend
  returns 200s and the L7 view reads clean.
- **Stage 3 (optional, the differentiated-flow upgrade):** make fanout path-aware so the
  flows match the action semantics the demo narrates:

  | Action | Intended flow |
  |---|---|
  | Browse / product detail | frontend → api → db |
  | Search | frontend → api → db + cache |
  | Login / session | frontend → api → auth (+ cache for session) |
  | Cart | frontend → api → cache |
  | Checkout | frontend → api → payments + db |
  | Order history | frontend → api → db |

  Minimal mechanism: (1) `fanout` forwards the inbound path to downstreams instead of
  hardcoded `/` (change at mesh main.go:108), so internal hops carry meaningful L7 paths in
  Hubble; (2) a new optional env `ROUTE_MAP` (e.g.
  `"/api/login=auth;/api/cart=cache;/api/checkout=payments,db;/api/products=db;/api/search=db,cache;/api/orders=db;/api/session=auth,cache"`)
  consulted only by services that set it (only `api` in 60-mesh.yaml needs it); a path with
  no mapping fans out to all downstreams — current behavior preserved, backward compatible,
  `/` unchanged. This is an extension of the existing SVC_NAME/DOWNSTREAMS env-shaping
  pattern (mesh main.go:75-83), not a rebuild.

**Standard persona = a real shopping session.** The Standard persona is no longer a single
"Buy" POST; it is the shopper actually using the store — each click drives its action's
path list. The legacy `standardPaths` drive (main.go:124, 217-226) stays intact behind
`POST /api/transaction persona=standard` for compatibility.

**Scope guard extension:** `TestStandardPathsAreCanaryFree` (main_test.go:85-96) generalizes
to iterate `standardPaths` **plus every list in `actionPaths`**, asserting (a) no
path equals or falls under a mirrored canary prefix and (b) every path is `/` or `/api/*`.
Same hand-mirror discipline documented at main_test.go:74-78. If Stage 3 lands, a sibling
test in the mesh package asserts every `ROUTE_MAP` key is likewise canary-free.

## 4. Redteam persona in the SPA

Pure reuse of the P2 mechanism — no re-invention:

- The header toggle flips the app into Redteam mode: red banner, **Run security test**
  button, mode persisted in `localStorage` so a reload keeps it.
- The button POSTs the existing `POST /api/transaction` with `persona=redteam`
  (main.go:227-238) and renders the returned `run_id` in the banner ("Attack run
  `redteam-…` in progress — watch the operator dashboard"), linking to `DASHBOARD_URL` when
  set. The single-slot rejoin behavior (main.go:88-93) means repeated clicks show the same
  run — surface that in the UI copy ("a run is already active").
- The two personas read as the two archetypes: Standard = a genuine shopper generating
  benign east-west traffic through the mesh; Redteam = a probing test client whose attacker
  (its own HTTPTool, never through `gw` — main.go:58-61) walks into the decoy paths and gets
  deterred/contained. Shopping in Standard mode while a Redteam run is active is a
  compelling side-by-side for the dashboard.

## 5. Backend wiring (what changes in service-c Go)

Client-side (SPA owns): routing, search filtering, persona mode UI. No client-side cart/order
persistence as of P2 (superseding the original plan below) — catalog, cart, and order history
now live server-side, session-scoped via an `sid` cookie (§8 item 3 records the decision).

Client-side (as originally planned, P1): routing, catalog data, cart state (localStorage),
search filtering, order history for the session, persona mode UI. No server state —
service-c stays stateless (12-factor process, no session store needed for a demo).

Server-side (service-c changes):
1. **Serve the embedded SPA.** `//go:embed static`; `serve` (main.go:160-171) routes
   GET non-`/api` paths to the embedded FS (index.html fallback for hash/deep links),
   replacing `serveIndex` (main.go:177-207). `/healthz` unchanged (main.go:162-163).
2. **Action endpoints.** One handler, table-driven: `POST /api/store/action/{name}` (or
   `?action=` param) looks up `actionPaths[name]`, drives each path via `gw.Fetch` in order
   (the main.go:217-220 loop generalized), returns
   `{"action":name,"ok":true,"paths":[...]}` — the same receipt shape as today
   (main.go:221-226). Unknown action → 400, mirroring the persona 400 (main.go:239-241).
   Testable with the existing `recordingFake` (main_test.go:128-135) — assert exact path
   sequence per action.
3. **Keep `POST /api/transaction`** exactly as-is (main.go:215-242): redteam launch path,
   plus standard for compatibility.
4. **Config exposure.** Inject `DASHBOARD_URL` into the shell as today (main.go:179-182) or
   via `GET /api/store/config` returning `{"dashboard_url":...}` — pick whichever keeps the
   embedded index.html static (the config endpoint keeps the FS byte-identical; slight
   preference).
5. **Env unchanged:** `GATEWAY_URL`, `LISTEN`, `DASHBOARD_URL`, `CASSETTE_PATH`
   (main.go:132-135). No new env vars.
6. **Tests:** extend the scope guard (§3); per-action path-sequence tests; keep
   `TestRedteamMakesNoGatewayCalls` (referenced at main.go:61) green — the SPA adds no
   gateway calls on the redteam path; keep `TestShipsNoSecrets` (referenced at
   main.go:174-176) and extend it over the embedded static FS (no keys/PEMs/routable hosts
   in shipped assets).
7. **P2 — server-side shop-to-order store (`cmd/service-c/store.go`).** Supersedes the "no
   server state" line above for this one seam only; every other server-side item (1-6) is
   unchanged. `newStore(products []Product)` holds the catalog plus per-session carts and
   order history, guarded by a single mutex. Session identity is an `sid` cookie
   (crypto/rand hex, HttpOnly, SameSite=Lax) minted on the first `/api/store/*` request
   lacking one — no real auth, no shared/global cart (rule 5-style isolation, scoped to the
   demo, not the platform's actual scope-isolation machinery). Endpoints, all under
   `/api/store/`: `GET products` (the catalog, now served from the store instead of the
   static `catalog.json` fetch); `GET cart` / `POST cart` (`product_id` + `delta` form
   fields, floored at zero, unknown product → 400); `POST checkout` (confirms the cart as an
   `Order`, 400 on an empty cart, clears the cart); `GET orders` (session's orders,
   most-recent-first). Zero `gw.Fetch` calls from any store endpoint — the store is
   data-plane only and stays outside the canary-free mesh seam (`TestStoreEndpointsMakeNoGatewayCalls`
   mirrors `TestRedteamMakesNoGatewayCalls`). Capped at `maxSessions` in-memory sessions
   (oldest evicted first) — see the `restraint:` marker in store.go and §8 item 3.

## 6. Build & deploy

- **No new image, no new manifest.** SPA assets live in `cmd/service-c/static/` and ride the
  existing `canarysting/core` image — `Dockerfile.core` already COPYs the full repo for
  go:embed (Dockerfile.dashboard-web:2-5 comment), so embedding Just Works. Rebuild/reload
  via the existing `load-images.nu` core entry with `--no-cache` and the k8s.io bridge
  (load-images.nu:24-28, 63).
- **Reach:** the existing `service-c-nodeport` NodePort 30302 (90-servicec.yaml:83-102) is
  the operator URL; unchanged.
- **Mesh stages 2/3** rebuild the mesh image via the existing load-images.nu mesh entry
  (load-images.nu:86); Stage 3 additionally adds the `ROUTE_MAP` env to the `api` Deployment
  in 60-mesh.yaml (only manifest diff in the whole design).
- If the Next.js route were chosen instead (not recommended), the mirror path is
  Dockerfile.dashboard-web + load-dashboard-web (load-images.nu:74-80) + the NodePort
  pattern of 81-dashboard-nodeport.yaml — documented here so the fallback is cheap.

## 7. Build phases (independently demoable)

- **P1 — SPA shell + catalog + Standard actions + persona control.** Embedded vanilla SPA
  (header, catalog grid, product detail, cart UI client-side), action-endpoint table in
  service-c, persona toggle + redteam button wired to the existing `/api/transaction`
  (nothing regresses vs today's page). Zero mesh changes — every click already generates the
  full east-west chain (§3 Stage 1). Extend scope-guard + action tests.
  *Demo: click around the store, watch Hubble light up per click; run a redteam test.*
- **P2 — Clean 200s + full shopping loop.** Mesh `serveAPI` storefront stubs
  (mesh main.go:184-195 extension); login, checkout, order-confirmation, order-history
  views complete. Shipped as: real server-side cart/checkout/orders
  (`cmd/service-c/store.go`, §5 item 7) rather than the client-only-state plan originally
  scoped here — the SPA now reads the catalog and renders cart/order views from
  `/api/store/*` instead of localStorage, for demo realism (§8 item 3 records the
  supersession). *Demo: full shop-to-order journey with clean L7 status codes, cart and
  order history that actually live on the server.*
- **P3 — Differentiated flows.** Path-forwarding fanout + `ROUTE_MAP` on the `api` service
  (§3 Stage 3) + the mesh-side canary-free test. *Demo: login lights up auth, checkout
  lights up payments+db — the Hubble graph matches the narration.*
- **P4 — Polish.** Visual pass (SVG art, transitions, cart badge), redteam banner copy,
  dashboard cross-links, README/demo-script update.

P1 and P2 ship value alone; P3 is where the "action maps to specific services" story
becomes literally true rather than narrated; P4 is cosmetic.

## 8. Restraint & risks

**Reused, not rebuilt:** the mesh binary + graph (60-mesh.yaml), the gateway (40-gateway.yaml),
the `gatewayCaller`/`redteamLauncher` seams and cassette attacker (main.go:34-118), the
scope-guard test pattern (main_test.go:74-96), the core-image go:embed build
(Dockerfile.core), load-images.nu, NodePort 30302, all env config. **Genuinely new:** the
SPA UI (static assets), the `actionPaths` table + one table-driven handler, mesh serveAPI
stubs (P2), and the optional `ROUTE_MAP` fanout selection (P3). The monitoring stack,
adapter, engine, and canary machinery are untouched.

Top risks / open questions:

1. **Flow-differentiation expectation vs mesh reality.** Until P3, every action's east-west
   signature is identical (path-blind full fanout, mesh main.go:106-117). If the demo script
   narrates "login → auth", P3 is functionally required, and it is the largest mesh change
   in the design. Mitigation: P3 is small and backward compatible (unmapped paths keep
   full fanout, `/` unchanged), but it needs review against the baseline learner — the
   learned east-west adjacencies stay the same node-pairs, only per-request fan-out width
   and internal L7 paths change. Requires validation by whoever owns the M7 baseline
   (rule 8 context, mesh main.go:1-17).
2. **Legacy-page supersession while another agent debugs it.** The task notes a separate
   agent is diagnosing live errors on the current storefront. This design deletes
   `serveIndex` (main.go:177-207) and repurposes `GET /`; coordinate merge order so the
   diagnosis isn't invalidated mid-flight and any real bug it finds (e.g. in the launcher or
   gateway path) is fixed before or with P1, not silently papered over by the rewrite.
3. **Scope-balloon watchlist (updated P2).** In-memory, server-side cart/order state is now
   IN SCOPE as of P2 (`cmd/service-c/store.go`, §5 item 7) — added deliberately for demo
   realism (a cart/checkout/order-history flow with state that survives a page reload and is
   isolated per browser session), not scope creep. The rest of the original watchlist stands
   and should still be rejected if it creeps in: real sessions/auth (the `sid` cookie is
   session identity only, not authentication), a real product database (the catalog is still
   the embedded `catalog.json`, just served through the store instead of fetched directly),
   real payment fields, a second web framework, mesh services returning actual product data,
   and canary-adjacent "admin" store pages (an `/admin` store UI would collide with the
   canary prefix — envoy-adapter main.go:248). If the operator later wants richer UI than
   vanilla JS comfortably carries, the upgrade path is the dashboard's Next.js pattern (§6),
   as a deliberate decision — not a drift.
   **12-factor / eviction caveat:** the store is in-process memory, not a backing service (12F
   factor IV/VI) — it does not survive a pod restart, does not scale past one replica
   (90-servicec.yaml is already single-replica), and is capped at `maxSessions` concurrent
   carts with oldest-first eviction (the `restraint:` marker in store.go). Acceptable for a
   single-replica demo; a durable cart would need a real backing store (Redis/Postgres) if
   this ever needs to survive a restart or run at more than one replica.
4. **(Minor) `TestShipsNoSecrets` coverage.** The no-secrets/no-routable-hosts assertion
   (main.go:174-176) currently reads the rendered page; it must be extended over the whole
   embedded static tree or the invariant silently narrows as content moves out of Go
   string literals.
