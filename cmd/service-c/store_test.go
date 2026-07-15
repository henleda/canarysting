package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fixtureProducts is the small product set store tests (and the serve()
// helpers in main_test.go, after the signature change below) construct a
// store from — deliberately NOT the embedded catalog.json, so unit tests
// don't depend on the embedded FS. newStore's real caller (main) loads the
// full catalog.
var fixtureProducts = []Product{
	{ID: "widget-a", Category: "gear", Name: "Widget A", Price: 10.00, Art: "🔧", Blurb: "The first widget."},
	{ID: "widget-b", Category: "gear", Name: "Widget B", Price: 25.50, Art: "⚙️", Blurb: "The second widget."},
	{ID: "widget-c", Category: "gear", Name: "Widget C", Price: 5.25, Art: "🔩", Blurb: "The third widget."},
}

// storeSession threads the sid cookie returned by one request into the next,
// simulating a single browser session across the calls that make up a test.
type storeSession struct {
	t      *testing.T
	st     *store
	gw     gatewayCaller
	rt     redteamLauncher
	cookie *http.Cookie
}

func newStoreSession(t *testing.T, st *store) *storeSession {
	t.Helper()
	return &storeSession{t: t, st: st, gw: &recordingFake{}, rt: &recordingLauncher{}}
}

func (s *storeSession) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	s.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if s.cookie != nil {
		req.AddCookie(s.cookie)
	}
	rr := httptest.NewRecorder()
	serve(rr, req, s.gw, s.rt, s.st)
	for _, c := range rr.Result().Cookies() {
		if c.Name == "sid" {
			s.cookie = c
		}
	}
	return rr
}

func decodeCartSnapshot(t *testing.T, rr *httptest.ResponseRecorder) CartSnapshot {
	t.Helper()
	var snap CartSnapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("cart snapshot not JSON: %v (%q)", err, rr.Body.String())
	}
	return snap
}

// 1. GET /api/store/products lists the full catalog the store was built from.
func TestStoreProductsListsCatalog(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)

	rr := sess.do(http.MethodGet, "/api/store/products", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/store/products = %d, want 200", rr.Code)
	}
	var products []Product
	if err := json.Unmarshal(rr.Body.Bytes(), &products); err != nil {
		t.Fatalf("response not a JSON array: %v (%q)", err, rr.Body.String())
	}
	if len(products) != len(fixtureProducts) {
		t.Fatalf("got %d products, want %d", len(products), len(fixtureProducts))
	}
	if products[0] != fixtureProducts[0] {
		t.Errorf("first product = %+v, want %+v", products[0], fixtureProducts[0])
	}
}

// 2. Session identity: an sid cookie is set on the first /api/store/*
// request lacking one, and a second request WITH that cookie reuses the same
// cart — state persists per sid.
func TestStoreSessionCookiePersists(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)
	p := fixtureProducts[0]

	sess.do(http.MethodGet, "/api/store/cart", nil)
	if sess.cookie == nil || sess.cookie.Value == "" {
		t.Fatalf("no non-empty sid cookie set on first /api/store/cart request")
	}

	sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {p.ID}, "delta": {"1"}})

	rr := sess.do(http.MethodGet, "/api/store/cart", nil)
	snap := decodeCartSnapshot(t, rr)
	if snap.Count != 1 {
		t.Errorf("cart count = %d, want 1 (session persisted via cookie)", snap.Count)
	}
}

// 3. GET /api/store/cart for a brand-new session is empty.
func TestStoreCartEmptyForNewSession(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)

	rr := sess.do(http.MethodGet, "/api/store/cart", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/store/cart = %d, want 200", rr.Code)
	}
	snap := decodeCartSnapshot(t, rr)
	if len(snap.Items) != 0 {
		t.Errorf("new session cart items = %v, want empty", snap.Items)
	}
	if snap.Subtotal != 0 {
		t.Errorf("new session cart subtotal = %v, want 0", snap.Subtotal)
	}
	if snap.Count != 0 {
		t.Errorf("new session cart count = %v, want 0", snap.Count)
	}
}

// 4. POST /api/store/cart with a positive delta adds a line with correct
// line_total/subtotal/count.
func TestStoreCartAddItem(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)
	p := fixtureProducts[0]

	rr := sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {p.ID}, "delta": {"1"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/store/cart = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	snap := decodeCartSnapshot(t, rr)
	if len(snap.Items) != 1 {
		t.Fatalf("cart items = %v, want exactly 1 line", snap.Items)
	}
	item := snap.Items[0]
	if item.ProductID != p.ID || item.Qty != 1 {
		t.Errorf("cart item = %+v, want product_id=%q qty=1", item, p.ID)
	}
	if item.LineTotal != p.Price {
		t.Errorf("line_total = %v, want %v", item.LineTotal, p.Price)
	}
	if snap.Subtotal != p.Price {
		t.Errorf("subtotal = %v, want %v", snap.Subtotal, p.Price)
	}
	if snap.Count != 1 {
		t.Errorf("count = %d, want 1", snap.Count)
	}
}

// 5. Adding the same product again accumulates qty rather than adding a
// second line.
func TestStoreCartAccumulatesQty(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)
	p := fixtureProducts[0]
	form := url.Values{"product_id": {p.ID}, "delta": {"1"}}

	sess.do(http.MethodPost, "/api/store/cart", form)
	rr := sess.do(http.MethodPost, "/api/store/cart", form)

	snap := decodeCartSnapshot(t, rr)
	if len(snap.Items) != 1 {
		t.Fatalf("cart items = %v, want exactly 1 line (same product)", snap.Items)
	}
	if snap.Items[0].Qty != 2 {
		t.Errorf("qty = %d, want 2 (accumulated)", snap.Items[0].Qty)
	}
	if snap.Count != 2 {
		t.Errorf("count = %d, want 2", snap.Count)
	}
}

// 6. A negative delta floors qty at zero and removes the line; count and
// subtotal update accordingly.
func TestStoreCartNegativeDeltaFloorsAtZeroAndRemovesLine(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)
	p := fixtureProducts[0]

	sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {p.ID}, "delta": {"1"}})
	rr := sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {p.ID}, "delta": {"-5"}})

	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/store/cart (negative delta) = %d, want 200", rr.Code)
	}
	snap := decodeCartSnapshot(t, rr)
	if len(snap.Items) != 0 {
		t.Errorf("cart items = %v, want line removed after floor-at-zero", snap.Items)
	}
	if snap.Count != 0 {
		t.Errorf("count = %d, want 0", snap.Count)
	}
	if snap.Subtotal != 0 {
		t.Errorf("subtotal = %v, want 0", snap.Subtotal)
	}
}

// 7. An unknown product_id is rejected with 400 and leaves the cart
// unchanged. (F3a)
func TestStoreCartUnknownProductRejected(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)

	rr := sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {"does-not-exist"}, "delta": {"1"}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unknown product_id = %d, want 400", rr.Code)
	}

	after := sess.do(http.MethodGet, "/api/store/cart", nil)
	snap := decodeCartSnapshot(t, after)
	if len(snap.Items) != 0 {
		t.Errorf("cart items = %v, want unchanged (empty) after rejected add", snap.Items)
	}
}

// 8. A missing or non-numeric delta is rejected with 400 and leaves the cart
// unchanged. (F3b)
func TestStoreCartMissingOrNonNumericDeltaRejected(t *testing.T) {
	p := fixtureProducts[0]
	cases := []struct {
		name string
		form url.Values
	}{
		{"missing delta", url.Values{"product_id": {p.ID}}},
		{"non-numeric delta", url.Values{"product_id": {p.ID}, "delta": {"banana"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := newStore(fixtureProducts)
			sess := newStoreSession(t, st)

			rr := sess.do(http.MethodPost, "/api/store/cart", c.form)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("%s = %d, want 400", c.name, rr.Code)
			}

			after := sess.do(http.MethodGet, "/api/store/cart", nil)
			snap := decodeCartSnapshot(t, after)
			if len(snap.Items) != 0 {
				t.Errorf("cart items = %v, want unchanged (empty) after rejected add (%s)", snap.Items, c.name)
			}
		})
	}
}

// 9. Checking out a non-empty cart returns a confirmed order matching the
// cart at checkout time, and clears the cart.
func TestStoreCheckoutConfirmsOrderAndClearsCart(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)
	p := fixtureProducts[0]

	addRR := sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {p.ID}, "delta": {"2"}})
	beforeSnap := decodeCartSnapshot(t, addRR)

	rr := sess.do(http.MethodPost, "/api/store/checkout", url.Values{})
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/store/checkout = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Order Order `json:"order"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("checkout response not JSON: %v (%q)", err, rr.Body.String())
	}
	if resp.Order.Number == "" {
		t.Errorf("order.number is empty, want non-empty")
	}
	if resp.Order.Status != "confirmed" {
		t.Errorf("order.status = %q, want \"confirmed\"", resp.Order.Status)
	}
	if resp.Order.Total != beforeSnap.Subtotal {
		t.Errorf("order.total = %v, want %v (cart subtotal at checkout)", resp.Order.Total, beforeSnap.Subtotal)
	}
	if len(resp.Order.Items) != len(beforeSnap.Items) {
		t.Fatalf("order.items = %v, want %v", resp.Order.Items, beforeSnap.Items)
	}
	for i, item := range beforeSnap.Items {
		if resp.Order.Items[i] != item {
			t.Errorf("order.items[%d] = %+v, want %+v", i, resp.Order.Items[i], item)
		}
	}

	after := sess.do(http.MethodGet, "/api/store/cart", nil)
	afterSnap := decodeCartSnapshot(t, after)
	if len(afterSnap.Items) != 0 {
		t.Errorf("cart after checkout = %v, want cleared (empty)", afterSnap.Items)
	}
}

// 10. Checking out an empty cart is rejected with 400 and creates no order.
func TestStoreCheckoutEmptyCartRejected(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)

	rr := sess.do(http.MethodPost, "/api/store/checkout", url.Values{})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("checkout empty cart = %d, want 400", rr.Code)
	}
	var errResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("error response not JSON: %v (%q)", err, rr.Body.String())
	}
	if _, ok := errResp["error"]; !ok {
		t.Errorf("error response missing \"error\" key: %v", errResp)
	}

	ordersRR := sess.do(http.MethodGet, "/api/store/orders", nil)
	var orders []Order
	if err := json.Unmarshal(ordersRR.Body.Bytes(), &orders); err != nil {
		t.Fatalf("orders response not JSON: %v (%q)", err, ordersRR.Body.String())
	}
	if len(orders) != 0 {
		t.Errorf("orders = %v, want none created from rejected checkout", orders)
	}
}

// 11. Two successive checkouts get distinct order numbers.
func TestStoreCheckoutOrderNumbersAreDistinct(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)
	p := fixtureProducts[0]

	sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {p.ID}, "delta": {"1"}})
	rr1 := sess.do(http.MethodPost, "/api/store/checkout", url.Values{})
	var resp1 struct {
		Order Order `json:"order"`
	}
	if err := json.Unmarshal(rr1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("first checkout response not JSON: %v (%q)", err, rr1.Body.String())
	}

	sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {p.ID}, "delta": {"1"}})
	rr2 := sess.do(http.MethodPost, "/api/store/checkout", url.Values{})
	var resp2 struct {
		Order Order `json:"order"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("second checkout response not JSON: %v (%q)", err, rr2.Body.String())
	}

	if resp1.Order.Number == resp2.Order.Number {
		t.Errorf("both checkouts got order.number %q, want distinct", resp1.Order.Number)
	}
}

// 12. GET /api/store/orders returns the session's orders most-recent-first;
// a different session sees none of them (isolation).
func TestStoreOrdersMostRecentFirstAndIsolatedBySession(t *testing.T) {
	st := newStore(fixtureProducts)
	sess := newStoreSession(t, st)
	p := fixtureProducts[0]

	sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {p.ID}, "delta": {"1"}})
	rr1 := sess.do(http.MethodPost, "/api/store/checkout", url.Values{})
	var resp1 struct {
		Order Order `json:"order"`
	}
	if err := json.Unmarshal(rr1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("first checkout response not JSON: %v (%q)", err, rr1.Body.String())
	}

	sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {p.ID}, "delta": {"1"}})
	rr2 := sess.do(http.MethodPost, "/api/store/checkout", url.Values{})
	var resp2 struct {
		Order Order `json:"order"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("second checkout response not JSON: %v (%q)", err, rr2.Body.String())
	}

	ordersRR := sess.do(http.MethodGet, "/api/store/orders", nil)
	var orders []Order
	if err := json.Unmarshal(ordersRR.Body.Bytes(), &orders); err != nil {
		t.Fatalf("orders response not JSON: %v (%q)", err, ordersRR.Body.String())
	}
	if len(orders) != 2 {
		t.Fatalf("orders = %v, want exactly 2", orders)
	}
	if orders[0].Number != resp2.Order.Number || orders[1].Number != resp1.Order.Number {
		t.Errorf("orders = [%q, %q], want most-recent-first [%q, %q]",
			orders[0].Number, orders[1].Number, resp2.Order.Number, resp1.Order.Number)
	}

	otherSess := newStoreSession(t, st)
	otherRR := otherSess.do(http.MethodGet, "/api/store/orders", nil)
	var otherOrders []Order
	if err := json.Unmarshal(otherRR.Body.Bytes(), &otherOrders); err != nil {
		t.Fatalf("other-session orders response not JSON: %v (%q)", err, otherRR.Body.String())
	}
	if len(otherOrders) != 0 {
		t.Errorf("different sid sees %v, want [] (isolation)", otherOrders)
	}
}

// 13. Seam guard: driving every /api/store/* endpoint records zero gw.Fetch
// calls — the store is data-plane only and never touches the gateway,
// preserving the canary-free seam (mirrors TestRedteamMakesNoGatewayCalls).
func TestStoreEndpointsMakeNoGatewayCalls(t *testing.T) {
	st := newStore(fixtureProducts)
	p := fixtureProducts[0]
	fake := &recordingFake{}
	sess := &storeSession{t: t, st: st, gw: fake, rt: &recordingLauncher{}}

	sess.do(http.MethodGet, "/api/store/products", nil)
	sess.do(http.MethodGet, "/api/store/cart", nil)
	sess.do(http.MethodPost, "/api/store/cart", url.Values{"product_id": {p.ID}, "delta": {"1"}})
	sess.do(http.MethodPost, "/api/store/checkout", url.Values{})
	sess.do(http.MethodGet, "/api/store/orders", nil)

	if len(fake.paths) != 0 {
		t.Errorf("gw.Fetch called %v across /api/store/* endpoints, want zero (canary-free seam)", fake.paths)
	}
}
