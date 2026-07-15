package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Product is one catalog item — the same shape as the embedded catalog.json
// (design doc §0), now served from the store instead of the static file
// directly.
type Product struct {
	ID       string  `json:"id"`
	Category string  `json:"category"`
	Name     string  `json:"name"`
	Price    float64 `json:"price"`
	Art      string  `json:"art"`
	Blurb    string  `json:"blurb"`
}

// CartItem is one line in a cart snapshot or a placed order.
type CartItem struct {
	ProductID string  `json:"product_id"`
	Name      string  `json:"name"`
	Price     float64 `json:"price"`
	Qty       int     `json:"qty"`
	LineTotal float64 `json:"line_total"`
}

// CartSnapshot is the GET /api/store/cart response shape: items sorted by
// product_id ascending, plus the derived subtotal and total item count.
type CartSnapshot struct {
	Items    []CartItem `json:"items"`
	Subtotal float64    `json:"subtotal"`
	Count    int        `json:"count"`
}

// Order is a placed, confirmed order — returned by POST /api/store/checkout
// and listed by GET /api/store/orders.
type Order struct {
	Number   string     `json:"number"`
	Status   string     `json:"status"`
	Items    []CartItem `json:"items"`
	Total    float64    `json:"total"`
	PlacedAt time.Time  `json:"placed_at"`
}

var (
	errUnknownProduct = errors.New("unknown product_id")
	errEmptyCart      = errors.New("cart is empty")
)

// maxSessions bounds how many concurrent sid carts the in-memory store
// retains.
// restraint: in-memory demo store, single replica (90-servicec.yaml), lost on
// restart; capped at N sessions, no persistence — a backing service is the
// upgrade path if this outlives the demo.
const maxSessions = 500

// maxOrdersPerSession caps retained order history per sid (A1): the most-recent
// N orders are kept, older dropped. In-memory demo store — bounds unbounded growth.
const maxOrdersPerSession = 20

// store is the server-side shop-to-order state: catalog plus per-session
// carts and order history. All map access is mutex-guarded — store is shared
// across every request goroutine.
type store struct {
	mu       sync.Mutex
	products []Product
	byID     map[string]Product
	carts    map[string]map[string]int // sid -> product_id -> qty
	orders   map[string][]Order        // sid -> orders, oldest first
	seq      int64

	sidOrder []string // cart-creation order, for maxSessions eviction
}

// newStore builds a store over the given catalog. The real caller (main)
// loads the full embedded catalog.json; tests build a small fixture.
func newStore(products []Product) *store {
	byID := make(map[string]Product, len(products))
	for _, p := range products {
		byID[p.ID] = p
	}
	return &store{
		products: products,
		byID:     byID,
		carts:    make(map[string]map[string]int),
		orders:   make(map[string][]Order),
	}
}

// touchSession ensures a cart map exists for sid, evicting the oldest
// session once the cap is exceeded. Caller holds s.mu.
func (s *store) touchSession(sid string) {
	if _, ok := s.carts[sid]; ok {
		return
	}
	s.carts[sid] = make(map[string]int)
	s.sidOrder = append(s.sidOrder, sid)
	if len(s.sidOrder) > maxSessions {
		oldest := s.sidOrder[0]
		s.sidOrder = s.sidOrder[1:]
		delete(s.carts, oldest)
		delete(s.orders, oldest)
	}
}

// snapshot builds sid's CartSnapshot: items sorted by product_id ascending,
// count is the sum of qty. Caller holds s.mu.
func (s *store) snapshot(sid string) CartSnapshot {
	cart := s.carts[sid]
	ids := make([]string, 0, len(cart))
	for id := range cart {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	items := make([]CartItem, 0, len(ids))
	var subtotal float64
	var count int
	for _, id := range ids {
		qty := cart[id]
		p := s.byID[id]
		lineTotal := p.Price * float64(qty)
		items = append(items, CartItem{ProductID: id, Name: p.Name, Price: p.Price, Qty: qty, LineTotal: lineTotal})
		subtotal += lineTotal
		count += qty
	}
	return CartSnapshot{Items: items, Subtotal: subtotal, Count: count}
}

// cartSnapshot returns sid's current cart snapshot.
func (s *store) cartSnapshot(sid string) CartSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touchSession(sid)
	return s.snapshot(sid)
}

// updateCart applies delta to product_id's qty in sid's cart, flooring at
// zero (which removes the line). Returns errUnknownProduct if product_id
// isn't in the catalog.
func (s *store) updateCart(sid, productID string, delta int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[productID]; !ok {
		return errUnknownProduct
	}
	s.touchSession(sid)
	qty := s.carts[sid][productID] + delta
	if qty <= 0 {
		delete(s.carts[sid], productID)
	} else {
		s.carts[sid][productID] = qty
	}
	return nil
}

// checkout confirms sid's current cart as an order and clears the cart.
// Returns errEmptyCart if the cart has no lines.
func (s *store) checkout(sid string) (Order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touchSession(sid)
	snap := s.snapshot(sid)
	if len(snap.Items) == 0 {
		return Order{}, errEmptyCart
	}
	s.seq++
	order := Order{
		Number:   "MSC-" + strconv.FormatInt(s.seq, 10),
		Status:   "confirmed",
		Items:    snap.Items,
		Total:    snap.Subtotal,
		PlacedAt: time.Now(),
	}
	s.orders[sid] = append(s.orders[sid], order)
	if n := len(s.orders[sid]); n > maxOrdersPerSession {
		// copy (not reslice) so dropped orders are released, not pinned by the backing array
		s.orders[sid] = append([]Order(nil), s.orders[sid][n-maxOrdersPerSession:]...)
	}
	s.carts[sid] = make(map[string]int)
	return order, nil
}

// listOrders returns sid's orders, most-recent-first.
func (s *store) listOrders(sid string) []Order {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.orders[sid]
	out := make([]Order, len(src))
	for i, o := range src {
		out[len(src)-1-i] = o
	}
	return out
}

// sidCookieName is the session cookie set on the first /api/store/* request
// lacking one.
const sidCookieName = "sid"

// sessionID returns r's sid cookie value, or mints and sets a new one on w
// if r has none — crypto/rand hex, HttpOnly, SameSite=Lax.
func sessionID(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(sidCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	sid := hex.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     sidCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return sid
}

// writeStoreError writes a JSON {"error": msg} body with the given status —
// the shared error shape for every /api/store/* endpoint.
func writeStoreError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// serveStoreProducts lists the full catalog the store was built from.
func serveStoreProducts(w http.ResponseWriter, r *http.Request, st *store) {
	_ = sessionID(w, r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st.products)
}

// serveStoreCartGet returns the caller's current cart snapshot.
func serveStoreCartGet(w http.ResponseWriter, r *http.Request, st *store) {
	sid := sessionID(w, r)
	snap := st.cartSnapshot(sid)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

// serveStoreCartPost applies a product_id + delta change to the caller's
// cart and returns the resulting snapshot.
func serveStoreCartPost(w http.ResponseWriter, r *http.Request, st *store) {
	sid := sessionID(w, r)
	productID := r.FormValue("product_id")
	delta, err := strconv.Atoi(r.FormValue("delta"))
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, "delta must be an integer")
		return
	}
	if err := st.updateCart(sid, productID, delta); err != nil {
		writeStoreError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap := st.cartSnapshot(sid)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

// serveStoreCheckout confirms the caller's cart as an order and returns it.
func serveStoreCheckout(w http.ResponseWriter, r *http.Request, st *store) {
	sid := sessionID(w, r)
	order, err := st.checkout(sid)
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"order": order})
}

// serveStoreOrders lists the caller's orders, most-recent-first.
func serveStoreOrders(w http.ResponseWriter, r *http.Request, st *store) {
	sid := sessionID(w, r)
	orders := st.listOrders(sid)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(orders)
}
