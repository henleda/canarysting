// Command dashboard-backend is the read-only M8 CISO-dashboard backend. It polls
// the engine's data tap (cmd/staged-range -dashboard-tap-addr / internal/dashboard/tap)
// over HTTP, derives the Overview view tree, and serves it to the Next.js
// frontend as JSON (GET /api/overview) and SSE (GET /api/stream). It is a
// SEPARATE process from the engine because the engine holds the bbolt write
// lock; this binary never writes anything and reaches the engine only via HTTP.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/canarysting/canarysting/internal/dashboard/backend"
)

func main() {
	var (
		tapAddr      = flag.String("tap-addr", "http://127.0.0.1:8088", "dashboard tap base URL (engine process)")
		listenAddr   = flag.String("listen-addr", "127.0.0.1:8089", "address to serve the dashboard API on (defaults to loopback; the API exposes attacker intelligence and has no auth, and the Next.js proxy reaches it same-box)")
		pollInterval = flag.Duration("poll-interval", 5*time.Second, "tap poll cadence")
		eventsWindow = flag.Duration("events-window", time.Hour, "events window requested from the tap (since_sec)")
		env          = flag.String("env", "", "free-form environment label surfaced in the dashboard topbar")
	)
	flag.Parse()

	b := backend.New(backend.Config{
		TapBaseURL:   *tapAddr,
		PollInterval: *pollInterval,
		EventsWindow: *eventsWindow,
		Env:          *env,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go b.Run(ctx)

	srv := &http.Server{Addr: *listenAddr, Handler: b.Handler()}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Printf("dashboard-backend: graceful shutdown error: %v", err)
		}
	}()

	log.Printf("dashboard-backend: listening on %s, polling tap %s every %s (events window %s)",
		*listenAddr, *tapAddr, *pollInterval, *eventsWindow)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("dashboard-backend: serve: %v", err)
	}
	log.Printf("dashboard-backend: stopped")
}
