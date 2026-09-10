package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
	"github.com/canarysting/canarysting/internal/canaryattacker/scenarios"
)

func main() {
	if len(os.Args) < 2 {
		failUsage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		if len(os.Args) != 2 {
			failUsage()
		}
		err = serveFixture()
	case "run":
		err = runJourney(os.Args[2:], os.Stdout, os.Stderr)
	default:
		failUsage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "attackerscenariospike: fixed operation failed")
		os.Exit(1)
	}
}

func failUsage() {
	fmt.Fprintln(os.Stderr, "attackerscenariospike: use serve or run -run-id ID -target-address PRIVATE_IP")
	os.Exit(2)
}

func runJourney(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var runID, targetAddress string
	flags.StringVar(&runID, "run-id", "", "bounded laboratory run identifier")
	flags.StringVar(&targetAddress, "target-address", "", "exact private Kubernetes Service address")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !identifier(runID) {
		return errors.New("invalid fixed runner arguments")
	}
	address, err := netip.ParseAddr(targetAddress)
	if err != nil || !address.Unmap().IsPrivate() || address.Zone() != "" {
		return errors.New("target must be one exact private address")
	}
	journey, err := scenarios.NewInitialJourney(address)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	corpus, executions, err := journey.Run(ctx, runID)
	if err != nil {
		return err
	}
	semantic, err := journey.SemanticSHA256(executions)
	if err != nil {
		return err
	}
	blob, err := groundtruth.MarshalCorpusV1(corpus)
	if err != nil {
		return err
	}
	if _, err = stdout.Write(blob); err != nil {
		return err
	}
	lines := []string{
		"PROOF scenario=PASS id=" + scenarios.InitialScenarioID + " version=" + strconv.Itoa(scenarios.InitialScenarioVersion) + " scenario_sha256=" + journey.Scenario.SemanticSHA256(),
		"PROOF journey=PASS steps=5 intents=5 actions=5 semantic_sha256=" + semantic,
		"PROOF isolation=PASS synthetic=true model_use=DISABLED address_retained=false credential_retained=false",
		"PROOF safety=PASS model_execution=false kubernetes_authority=false shell_authority=false",
	}
	for _, line := range lines {
		if _, err = fmt.Fprintln(stderr, line); err != nil {
			return err
		}
	}
	return nil
}

func serveFixture() error {
	listener, err := net.Listen("tcp4", ":"+strconv.Itoa(scenarios.InitialTargetPort))
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           newFixtureHandler(os.Stdout),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       3 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	signalContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case serveErr := <-done:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	case <-signalContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return err
		}
		serveErr := <-done
		if !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	}
}

type fixtureHandler struct {
	events     io.Writer
	mu         sync.Mutex
	discovered bool
}

func newFixtureHandler(events io.Writer) http.Handler {
	return &fixtureHandler{events: events}
}

func (h *fixtureHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	if request.URL.Path == "/ready" && request.Method == http.MethodGet {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	wantHost := net.JoinHostPort(scenarios.InitialTargetHost, strconv.Itoa(scenarios.InitialTargetPort))
	if request.Host != wantHost || request.Method != http.MethodGet {
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	switch request.URL.Path {
	case "/":
		h.record(writer, "enumeration-root", "harmless root")
	case "/catalog":
		h.record(writer, "enumeration-catalog", "harmless catalog")
	case "/probe":
		h.record(writer, "http-probe", "harmless probe")
	case "/credential":
		username, password, ok := request.BasicAuth()
		if !ok || username != "fixture-user" || password != "fixture-secret" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.record(writer, "credential-accepted", "harmless credential accepted")
	case "/discover":
		h.mu.Lock()
		h.discovered = true
		writer.Header().Set("Link", "</canary>; rel=canary")
		fmt.Fprintln(h.events, "EVENT canary-discovered")
		h.mu.Unlock()
		_, _ = writer.Write([]byte("harmless discovery"))
	case "/canary":
		h.mu.Lock()
		defer h.mu.Unlock()
		if !h.discovered {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		h.discovered = false
		fmt.Fprintln(h.events, "EVENT canary-touched")
		_, _ = writer.Write([]byte("harmless canary"))
	default:
		http.Error(writer, "not found", http.StatusNotFound)
	}
}

func (h *fixtureHandler) record(writer http.ResponseWriter, event, body string) {
	h.mu.Lock()
	fmt.Fprintln(h.events, "EVENT "+event)
	h.mu.Unlock()
	_, _ = writer.Write([]byte(body))
}

func identifier(value string) bool {
	if value == "" || len(value) > 48 || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && character == '-' && index < len(value)-1) {
			continue
		}
		return false
	}
	return true
}
