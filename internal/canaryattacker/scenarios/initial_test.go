package scenarios

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

func TestInitialJourneyExecutesReviewedFiveStepSequence(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	discovered := false
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != net.JoinHostPort(InitialTargetHost, strconv.Itoa(int(port))) || request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		switch request.URL.Path {
		case "/", "/catalog", "/probe":
			_, _ = writer.Write([]byte("harmless fixture"))
		case "/credential":
			username, password, ok := request.BasicAuth()
			if !ok || username != fixtureUsername || password != fixtureSecret {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = writer.Write([]byte("harmless credential"))
		case "/discover":
			discovered = true
			writer.Header().Set("Link", "</canary>; rel=canary")
			_, _ = writer.Write([]byte("harmless discovery"))
		case "/canary":
			if !discovered {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			discovered = false
			_, _ = writer.Write([]byte("harmless canary"))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-done
	}()

	journey, err := newInitialJourney(netip.MustParseAddr("127.0.0.1"), port)
	if err != nil {
		t.Fatal(err)
	}
	first, firstExecutions, err := journey.Run(context.Background(), "m2c5-unit-first")
	if err != nil {
		t.Fatal(err)
	}
	second, secondExecutions, err := journey.Run(context.Background(), "m2c5-unit-second")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Intents()) != 5 || len(first.Actions()) != 5 || len(second.Intents()) != 5 || len(second.Actions()) != 5 {
		t.Fatal("repeated journey did not emit exactly five intents and actions")
	}
	for _, action := range append(first.Actions(), second.Actions()...) {
		if action.Status() != groundtruth.ActionSucceeded || !action.Attempted() {
			t.Fatal("journey action was not a successful attempt")
		}
	}
	firstSemantic, err := journey.SemanticSHA256(firstExecutions)
	if err != nil {
		t.Fatal(err)
	}
	secondSemantic, err := journey.SemanticSHA256(secondExecutions)
	if err != nil {
		t.Fatal(err)
	}
	if firstSemantic != secondSemantic {
		t.Fatal("repeated runs changed reviewed intent/action semantics")
	}
	for _, corpus := range []groundtruth.Corpus{first, second} {
		blob, marshalErr := groundtruth.MarshalCorpusV1(corpus)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		for _, forbidden := range []string{"fixture-secret", "127.0.0.1", "Authorization"} {
			if strings.Contains(string(blob), forbidden) {
				t.Fatalf("corpus retained forbidden value %q", forbidden)
			}
		}
	}
}
