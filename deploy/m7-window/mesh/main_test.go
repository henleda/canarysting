package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// noFanout is a no-op downstream caller for the router tests. Signature matches
// serve's fanout param: func(context.Context, string) — the request path is now
// threaded through so fanout can forward it (d+path, not a hardcoded d+"/").
func noFanout(context.Context, string) {}

func get(t *testing.T, path string) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	serve(rr, req, "frontend", noFanout)
	return rr.Code, rr.Body.String()
}

// Rule 8: the frontend must NEVER serve a canary path — they stay negative space so a
// touch is recognized only by the adapter. Every canary prefix (and a path under it)
// must 404, not 200.
func TestFrontendNeverServesCanaryPaths(t *testing.T) {
	for _, p := range []string{
		"/.env", "/.env.bak", "/.aws/credentials", "/secrets/", "/secrets/db.json",
		"/config/", "/config/app.yml", "/backup/", "/backup/db.sql",
		"/internal/", "/internal/admin/credentials", "/admin/", "/admin/metrics",
	} {
		code, body := get(t, p)
		if code != 404 {
			t.Errorf("canary path %q returned %d, want 404 (must stay negative space)", p, code)
		}
		if strings.Contains(body, "ok") {
			t.Errorf("canary path %q body %q must not be an ok stub", p, body)
		}
	}
}

// An enumerating attacker must NOT see a uniform "ok" stub for every path: unknown
// paths 404 (including a random nonexistent one), known app paths serve real content.
func TestFrontendRouting(t *testing.T) {
	if code, body := get(t, "/"); code != 200 || !strings.Contains(body, "<html") {
		t.Errorf("/ = %d %q, want 200 HTML", code, body)
	}
	if code, _ := get(t, "/robots.txt"); code != 200 {
		t.Errorf("/robots.txt = %d, want 200", code)
	}
	if code, body := get(t, "/api/health"); code != 200 || !strings.Contains(body, "status") {
		t.Errorf("/api/health = %d %q, want 200 JSON", code, body)
	}
	for _, p := range []string{"/totally-random-nonexistent-12345", "/index.php", "/wp-login.php", "/api/unknown"} {
		if code, _ := get(t, p); code != 404 {
			t.Errorf("unknown path %q = %d, want 404 (not a uniform ok stub)", p, code)
		}
	}
}

// listenHost parses the bind host out of LISTEN so a service dials its downstreams
// from its OWN distinct loopback identity (the named east-west fabric). A bare port
// or a wildcard host must yield "" so we bind no LocalAddr (graceful fallback).
func TestListenHostParsesBindAddress(t *testing.T) {
	for _, tc := range []struct {
		listen string
		want   string
	}{
		{"127.0.1.2:8002", "127.0.1.2"},
		{"127.0.1.1:8001", "127.0.1.1"},
		{"127.0.1.16:8016", "127.0.1.16"},
		{":8000", ""},        // bare port -> no bind
		{"0.0.0.0:8080", ""}, // wildcard v4 -> no bind
		{"[::]:8080", ""},    // wildcard v6 -> no bind
		{"not-a-listen", ""}, // unparseable -> no bind
		{"", ""},             // empty -> no bind
	} {
		if got := listenHost(tc.listen); got != tc.want {
			t.Errorf("listenHost(%q) = %q, want %q", tc.listen, got, tc.want)
		}
	}
}

// The frontend is NOT covered by harmless.CrossScan — assert by hand it ships no
// real-looking secrets or routable hosts across all served paths, including the
// storefront stub endpoints.
func TestFrontendShipsNoSecrets(t *testing.T) {
	akia := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	pem := regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	for _, p := range []string{
		"/", "/index.html", "/robots.txt", "/api/health", "/api/status",
		"/api/products", "/api/search", "/api/login", "/api/session",
		"/api/cart", "/api/checkout", "/api/orders",
	} {
		_, body := get(t, p)
		if akia.MatchString(body) {
			t.Errorf("path %q body contains an AWS key id", p)
		}
		if pem.MatchString(body) {
			t.Errorf("path %q body contains a PEM private key", p)
		}
	}
}

// parseRouteMap parses the ROUTE_MAP env grammar: ';'-separated "path=svc[,svc]"
// entries. Malformed entries (no '=') are skipped; an empty string yields an empty
// map.
func TestParseRouteMap(t *testing.T) {
	got := parseRouteMap("/api/cart=cache;/api/checkout=payments,db")
	want := map[string][]string{
		"/api/cart":     {"cache"},
		"/api/checkout": {"payments", "db"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseRouteMap(...) = %#v, want %#v", got, want)
	}

	if got := parseRouteMap(""); len(got) != 0 {
		t.Errorf(`parseRouteMap("") = %#v, want empty map`, got)
	}

	got = parseRouteMap("/api/cart=cache;malformed;/api/checkout=payments")
	want = map[string][]string{
		"/api/cart":     {"cache"},
		"/api/checkout": {"payments"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseRouteMap with malformed entry = %#v, want %#v (malformed entry skipped)", got, want)
	}
}

// matchesService anchors on "//<name>." so a downstream URL is matched only by its
// own service name, not a prefix of another (payment must not match payments).
func TestMatchesService(t *testing.T) {
	for _, tc := range []struct {
		url, name string
		want      bool
	}{
		{"http://auth.canarysting.svc.cluster.local:8000", "auth", true},
		{"http://cache.canarysting.svc.cluster.local:8000", "db", false},
		{"http://db.canarysting.svc.cluster.local:8000", "db", true},
		{"http://payments.canarysting.svc.cluster.local:8000", "payment", false}, // anchor edge
	} {
		if got := matchesService(tc.url, tc.name); got != tc.want {
			t.Errorf("matchesService(%q, %q) = %v, want %v", tc.url, tc.name, got, tc.want)
		}
	}
}

// demoRouteMap mirrors the ROUTE_MAP the deploy manifest sets for the differentiated
// storefront mesh (kept in sync by hand, like the existing canary-prefix mirror).
const demoRouteMap = "/api/cart=cache;/api/checkout=payments,db"

// selectDownstreams: an unmapped path preserves full fanout (every downstream);
// a mapped path narrows to the resolved subset (order preserved); a mapped path
// whose names ALL fail to resolve against downstreams falls back to full fanout
// (typo safety — a bad ROUTE_MAP degrades to "fanout everything", never "nothing").
func TestSelectDownstreams(t *testing.T) {
	auth := "http://auth.canarysting.svc.cluster.local:8000"
	db := "http://db.canarysting.svc.cluster.local:8000"
	cache := "http://cache.canarysting.svc.cluster.local:8000"
	payments := "http://payments.canarysting.svc.cluster.local:8000"
	downstreams := []string{auth, db, cache, payments}
	rm := parseRouteMap(demoRouteMap)

	if got := selectDownstreams("/api/cart", downstreams, rm); !reflect.DeepEqual(got, []string{cache}) {
		t.Errorf("selectDownstreams(/api/cart, ...) = %v, want [%s]", got, cache)
	}
	if got := selectDownstreams("/api/checkout", downstreams, rm); !reflect.DeepEqual(got, []string{payments, db}) {
		t.Errorf("selectDownstreams(/api/checkout, ...) = %v, want [%s %s]", got, payments, db)
	}
	for _, p := range []string{"/api/foo", "/"} {
		if got := selectDownstreams(p, downstreams, rm); !reflect.DeepEqual(got, downstreams) {
			t.Errorf("selectDownstreams(%q, ...) = %v, want all downstreams %v (unmapped -> full fanout)", p, got, downstreams)
		}
	}

	typoRM := parseRouteMap("/api/x=typo")
	if got := selectDownstreams("/api/x", downstreams, typoRM); !reflect.DeepEqual(got, downstreams) {
		t.Errorf("selectDownstreams(/api/x, ...) with unresolvable mapped name = %v, want all downstreams %v (fallback)", got, downstreams)
	}
}

// TestFanoutSelectsAndForwardsPath proves selection + path-forwarding together: the
// package-level fanout dials d+path (not a hardcoded d+"/"), and only the downstreams
// selectDownstreams resolves for the given path get hit. Downstream URLs use fake
// ".test" hostnames so matchesService's "//<name>." anchor matches real service
// names, with a custom Transport.DialContext redirecting those fake hosts to the
// real httptest listener addresses.
func TestFanoutSelectsAndForwardsPath(t *testing.T) {
	var mu sync.Mutex
	hits := map[string][]string{}
	record := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits[name] = append(hits[name], r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}
	}

	authSrv := httptest.NewServer(record("auth"))
	dbSrv := httptest.NewServer(record("db"))
	cacheSrv := httptest.NewServer(record("cache"))
	paymentsSrv := httptest.NewServer(record("payments"))
	defer authSrv.Close()
	defer dbSrv.Close()
	defer cacheSrv.Close()
	defer paymentsSrv.Close()

	addrFor := map[string]string{
		"auth.test":     strings.TrimPrefix(authSrv.URL, "http://"),
		"db.test":       strings.TrimPrefix(dbSrv.URL, "http://"),
		"cache.test":    strings.TrimPrefix(cacheSrv.URL, "http://"),
		"payments.test": strings.TrimPrefix(paymentsSrv.URL, "http://"),
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err == nil {
					if real, ok := addrFor[host]; ok {
						addr = real
					}
				}
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}

	downstreams := []string{"http://auth.test", "http://db.test", "http://cache.test", "http://payments.test"}
	rm := parseRouteMap("/api/cart=cache;/api/checkout=payments,db")

	reset := func() {
		mu.Lock()
		hits = map[string][]string{}
		mu.Unlock()
	}

	fanout(context.Background(), "/api/cart", downstreams, client, rm)
	mu.Lock()
	if len(hits) != 1 || !reflect.DeepEqual(hits["cache"], []string{"/api/cart"}) {
		t.Errorf("/api/cart fanout hits = %v, want only cache hit at /api/cart", hits)
	}
	mu.Unlock()
	reset()

	fanout(context.Background(), "/api/checkout", downstreams, client, rm)
	mu.Lock()
	if len(hits) != 2 || !reflect.DeepEqual(hits["payments"], []string{"/api/checkout"}) || !reflect.DeepEqual(hits["db"], []string{"/api/checkout"}) {
		t.Errorf("/api/checkout fanout hits = %v, want payments+db hit at /api/checkout", hits)
	}
	mu.Unlock()
	reset()

	fanout(context.Background(), "/", downstreams, client, rm)
	mu.Lock()
	if len(hits) != 4 {
		t.Errorf("/ fanout hits = %v, want all 4 services hit (unmapped -> full fanout)", hits)
	}
	for name, paths := range hits {
		if !reflect.DeepEqual(paths, []string{"/"}) {
			t.Errorf("service %q hit at %v, want a single hit at /", name, paths)
		}
	}
	mu.Unlock()
}

// TestServeAPIStorefrontStubs: the 7 store paths return plausible JSON stubs naming
// the resource (last path segment); /api/unknown still 404s; /api/health and
// /api/status are unchanged.
func TestServeAPIStorefrontStubs(t *testing.T) {
	stubs := map[string]string{
		"/api/products": "products",
		"/api/search":   "search",
		"/api/login":    "login",
		"/api/session":  "session",
		"/api/cart":     "cart",
		"/api/checkout": "checkout",
		"/api/orders":   "orders",
	}
	for path, resource := range stubs {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		serve(rr, req, "frontend", noFanout)

		if rr.Code != 200 {
			t.Errorf("%s = %d, want 200", path, rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("%s Content-Type = %q, want to contain application/json", path, ct)
		}
		body := rr.Body.String()
		if !strings.Contains(body, `"resource":"`+resource+`"`) {
			t.Errorf("%s body %q, want to contain resource %q", path, body, resource)
		}
		if !strings.Contains(body, `"status":"ok"`) {
			t.Errorf("%s body %q, want status ok", path, body)
		}
	}

	if code, _ := get(t, "/api/unknown"); code != 404 {
		t.Errorf("/api/unknown = %d, want 404", code)
	}
	for _, p := range []string{"/api/health", "/api/status"} {
		if code, body := get(t, p); code != 200 || !strings.Contains(body, "status") {
			t.Errorf("%s = %d %q, want 200 with status field (unchanged)", p, code, body)
		}
	}
}

// TestRouteMapCanaryFree hand-mirrors the canary-prefix discipline: every ROUTE_MAP
// key must be a normal application path (/ or /api/*) and never a canary path — a
// routing typo must not accidentally point traffic AT a negative-space path.
func TestRouteMapCanaryFree(t *testing.T) {
	rm := parseRouteMap(demoRouteMap)
	if len(rm) == 0 {
		t.Fatal("demoRouteMap parsed to an empty map")
	}
	for key := range rm {
		if key != "/" && !strings.HasPrefix(key, "/api/") {
			t.Errorf("route map key %q is neither / nor /api/*", key)
		}
		if isCanaryPath(key) {
			t.Errorf("route map key %q is a canary path (must stay negative space)", key)
		}
	}
}
