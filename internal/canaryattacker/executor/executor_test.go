package executor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

func TestClosedCatalogExecutesOnlyReviewedOperations(t *testing.T) {
	var credentialSeen atomic.Bool
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/first":
			writer.Header().Set("Link", "</next>; rel=next")
			_, _ = writer.Write([]byte("first response"))
		case "/next":
			_, _ = writer.Write([]byte("followed response"))
		case "/credential":
			username, password, ok := request.BasicAuth()
			credentialSeen.Store(ok && username == "fixture-user" && password == "fixture-secret")
			_, _ = writer.Write([]byte("credential checked"))
		default:
			_, _ = writer.Write([]byte("enumerated"))
		}
	})

	fixture := newFixture(t, fixtureURL, defaultLimits(), nil, httpFixtureDialer(handler))
	run := fixture.newRun(t, &MemoryLedger{})
	defer run.Close()
	for index, action := range fixture.actions {
		execution, err := run.Execute(context.Background(), fixture.invocation(index, action))
		if err != nil {
			t.Fatalf("execute action %d (%s): %v", index+1, action.Tool(), err)
		}
		if execution.Result.Status != groundtruth.ActionSucceeded {
			t.Fatalf("action %s status = %s (%s)", action.Tool(), execution.Result.Status, execution.Result.ErrorCode)
		}
		if action.Tool() == groundtruth.ToolInspectResponse && string(execution.Result.Content) != "first response" {
			t.Fatalf("inspect content = %q", execution.Result.Content)
		}
	}
	if !credentialSeen.Load() {
		t.Fatal("fixture credential was not resolved for the exact reviewed credential action")
	}
}

func TestIntentIsCommittedBeforeNetworkAndDenialsNeverDial(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("ok"))
	})
	ledger := &orderingLedger{}
	baseDialer := httpFixtureDialer(handler)
	var dialCount atomic.Uint32
	dialer := dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if ledger.intentCount() == 0 {
			return nil, errors.New("dial happened before intent commit")
		}
		dialCount.Add(1)
		return baseDialer.DialContext(ctx, network, address)
	})
	fixture := newFixture(t, fixtureURL, defaultLimits(), nil, dialer)
	run := fixture.newRun(t, ledger)
	defer run.Close()
	first, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
	if err != nil || first.Result.Status != groundtruth.ActionSucceeded {
		t.Fatalf("approved execution = %+v, %v", first.Result, err)
	}

	denied, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: "shell", TargetAlias: fixture.actions[0].TargetAlias(), TargetRef: fixture.actions[0].TargetRef(), Operation: "run-command",
	})
	if err != nil {
		t.Fatal(err)
	}
	dialsBefore := dialCount.Load()
	execution, err := run.Execute(context.Background(), fixture.invocation(0, denied))
	if err != nil {
		t.Fatal(err)
	}
	if execution.Result.Status != groundtruth.ActionDenied || execution.Action.Attempted() || execution.Intent.Policy().ReasonCode() != "outside_reviewed_policy" {
		t.Fatalf("unexpected denial: %+v", execution.Result)
	}
	if ledger.intentCount() != 2 {
		t.Fatal("policy denial was not audited")
	}
	if dialCount.Load() != dialsBefore {
		t.Fatal("policy denial reached the dialer")
	}
}

func TestIntentLedgerFailurePreventsNetworkAndClosesRun(t *testing.T) {
	var dialed atomic.Bool
	ledger := &failingLedger{failIntent: true}
	fixture := newFixture(t, fixtureURL, defaultLimits(), nil, dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("unexpected dial")
	}))
	run := fixture.newRun(t, ledger)
	defer run.Close()
	if _, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0])); err == nil {
		t.Fatal("expected intent-ledger failure")
	}
	if dialed.Load() {
		t.Fatal("network was reached after intent-ledger failure")
	}
	if _, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0])); !errors.Is(err, ErrRunTerminal) {
		t.Fatalf("subsequent error = %v, want ErrRunTerminal", err)
	}
}

func TestCallerCancellationIsAuditedWithoutNetwork(t *testing.T) {
	var dialed atomic.Bool
	ledger := &contextAwareLedger{}
	fixture := newFixture(t, fixtureURL, defaultLimits(), nil, dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("unexpected dial")
	}))
	run := fixture.newRun(t, ledger)
	defer run.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	execution, err := run.Execute(ctx, fixture.invocation(0, fixture.actions[0]))
	if err != nil || execution.Result.Status != groundtruth.ActionCancelled || execution.Result.ErrorCode != "caller_cancelled" {
		t.Fatalf("cancelled execution = %+v, %v", execution.Result, err)
	}
	if dialed.Load() {
		t.Fatal("caller-cancelled execution reached the network")
	}
	if len(ledger.Intents()) != 1 || len(ledger.Actions()) != 1 {
		t.Fatal("caller cancellation did not preserve complete intent/action ground truth")
	}
}

func TestLedgerFailureCancelsConcurrentNetworkWork(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	dialer := dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	})
	ledger := &failOnceActionLedger{}
	fixture := newFixture(t, fixtureURL, defaultLimits(), nil, dialer)
	run := fixture.newRun(t, ledger)
	defer run.Close()
	type outcome struct {
		execution Execution
		err       error
	}
	active := make(chan outcome, 1)
	go func() {
		execution, err := run.Execute(context.Background(), fixture.invocation(2, fixture.actions[2]))
		active <- outcome{execution: execution, err: err}
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("concurrent network action did not start")
	}
	ledger.failNext.Store(true)
	denied, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: "shell", TargetAlias: fixture.actions[0].TargetAlias(), TargetRef: fixture.actions[0].TargetRef(), Operation: "run-command",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Execute(context.Background(), fixture.invocation(0, denied)); err == nil {
		t.Fatal("expected terminal action-ledger failure")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("terminal ledger failure did not cancel active network work")
	}
	select {
	case result := <-active:
		if result.err != nil || result.execution.Result.Status != groundtruth.ActionCancelled || result.execution.Result.ErrorCode != "run_cancelled" {
			t.Fatalf("active execution after ledger failure = %+v, %v", result.execution.Result, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled network action did not finish")
	}
}

func TestRedirectAndDNSRebindingFailClosed(t *testing.T) {
	var redirect atomic.Bool
	redirect.Store(true)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/first" && redirect.Load() {
			http.Redirect(writer, request, "/next", http.StatusFound)
			return
		}
		_, _ = writer.Write([]byte("ok"))
	})
	dialer := httpFixtureDialer(handler)
	fixture := newFixture(t, fixtureURL, defaultLimits(), nil, dialer)
	run := fixture.newRun(t, &MemoryLedger{})
	execution, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
	run.Close()
	if err != nil || execution.Result.ErrorCode != "redirect_denied" || execution.Result.Status != groundtruth.ActionFailed {
		t.Fatalf("redirect result = %+v, %v", execution.Result, err)
	}

	redirect.Store(false)
	sequence := &sequenceResolver{answers: [][]netip.Addr{{netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("127.0.0.2")}}}
	fixture = newFixture(t, fixtureURL, defaultLimits(), sequence, dialer)
	run = fixture.newRun(t, &MemoryLedger{})
	execution, err = run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
	run.Close()
	if err != nil || execution.Result.ErrorCode != "dns_rebinding_denied" {
		t.Fatalf("rebinding result = %+v, %v", execution.Result, err)
	}
}

func TestResponseAndActionLimitsAndCancellationAreAudited(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/first" {
			_, _ = writer.Write([]byte(strings.Repeat("x", 129)))
			return
		}
		_, _ = writer.Write([]byte("ok"))
	})
	dialer := httpFixtureDialer(handler)
	limits := defaultLimits()
	limits.MaxResponseBytes = 128
	limits.MaxStoredResponseBytes = 128
	fixture := newFixture(t, fixtureURL, limits, nil, dialer)
	ledger := &MemoryLedger{}
	run := fixture.newRun(t, ledger)
	execution, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
	if err != nil || execution.Result.ErrorCode != "response_limit_exceeded" {
		t.Fatalf("response limit result = %+v, %v", execution.Result, err)
	}
	for len(ledger.Intents()) < int(fixture.scenario.Budgets().MaxActions()) {
		_, _ = run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
	}
	if _, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0])); !errors.Is(err, ErrActionBudget) {
		t.Fatalf("action ceiling error = %v", err)
	}
	run.Close()

	limits = defaultLimits()
	limits.MaxActionDuration = 20 * time.Millisecond
	fixture = newFixture(t, fixtureURL, limits, nil, dialer)
	run = fixture.newRun(t, &MemoryLedger{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	execution, err = run.Execute(ctx, fixture.invocation(0, fixture.actions[0]))
	run.Close()
	if err != nil || execution.Result.Status != groundtruth.ActionCancelled || execution.Result.ErrorCode != "caller_cancelled" {
		t.Fatalf("cancel result = %+v, %v", execution.Result, err)
	}
}

func TestSecretsAndLocatorsDoNotEnterGroundTruth(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("ok"))
	})
	fixture := newFixture(t, fixtureURL, defaultLimits(), nil, httpFixtureDialer(handler))
	run := fixture.newRun(t, &MemoryLedger{})
	defer run.Close()
	execution, err := run.Execute(context.Background(), fixture.invocation(5, fixture.actions[5]))
	if err != nil {
		t.Fatal(err)
	}
	intentJSON, err := groundtruth.MarshalAttackerIntentV1(fixture.scenario, execution.Intent)
	if err != nil {
		t.Fatal(err)
	}
	actionJSON, err := groundtruth.MarshalAttackerActionV1(execution.Intent, execution.Action)
	if err != nil {
		t.Fatal(err)
	}
	combined := string(intentJSON) + string(actionJSON) + execution.Result.ErrorCode + string(execution.Result.Content)
	for _, forbidden := range []string{"fixture-secret", "fixture-user", "fixture.local", "127.0.0.1", fixtureURL} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("ground truth or result exposed forbidden value %q", forbidden)
		}
	}
}

func TestPolicyRejectsPublicAndLinkLocalTargetsAndUnregisteredOperations(t *testing.T) {
	for _, test := range []struct {
		name    string
		host    string
		address string
	}{
		{name: "public", host: "public.example", address: "8.8.8.8"},
		{name: "ipv4-link-local", host: "metadata.internal", address: "169.254.169.254"},
		{name: "ipv6-link-local", host: "host-local.internal", address: "fe80::1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, err := NewTargetBinding(TargetBindingInput{
				Alias: "lab", Reference: opaque("labtarget:sha256:", test.name), FixtureRef: opaque("fixture:sha256:", test.name),
				Scheme: "http", Host: test.host, Port: 80, AllowedAddresses: []netip.Addr{netip.MustParseAddr(test.address)},
			})
			if err == nil || target.reference != "" {
				t.Fatalf("%s target was accepted", test.name)
			}
		})
	}
	limits := defaultLimits()
	if _, err := NewPolicy(PolicyConfig{Limits: limits}); err == nil {
		t.Fatal("empty policy was accepted")
	}
	for _, path := range []string{"/../escape", "/%2e%2e/escape", "/%252e%252e/escape", "/safe%2fescape"} {
		if err := validatePath(path); err == nil {
			t.Fatalf("ambiguous or traversing path %q was accepted", path)
		}
	}
}

func TestEnumerationUsesRemainingAggregateResponseBudget(t *testing.T) {
	var requests atomic.Uint32
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = writer.Write([]byte(strings.Repeat("e", 100)))
	})
	limits := defaultLimits()
	limits.MaxResponseBytes = 128
	fixture := newFixture(t, fixtureURL, limits, nil, httpFixtureDialer(handler))
	run := fixture.newRun(t, &MemoryLedger{})
	defer run.Close()
	execution, err := run.Execute(context.Background(), fixture.invocation(3, fixture.actions[3]))
	if err != nil || execution.Result.ErrorCode != "response_limit_exceeded" || requests.Load() != 2 {
		t.Fatalf("bounded enumeration = %+v, err=%v, requests=%d", execution.Result, err, requests.Load())
	}
	operation := fixture.policy.operations[actionKey(fixture.actions[3])]
	target := fixture.policy.targets[fixture.actions[3].TargetRef()]
	part := run.httpRequestWithResponseLimit(context.Background(), operation, target, http.MethodGet, "/enum/a", PayloadFixture{}, CredentialFixture{}, nil, 28)
	if part.errorCode != "response_limit_exceeded" {
		t.Fatalf("remaining response cap result = %+v", part)
	}
}

func TestOrderedScenarioRejectsStepRegressionBeforeNetwork(t *testing.T) {
	var dials atomic.Uint32
	dialer := httpFixtureDialer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("ok"))
	}))
	fixture := newFixture(t, fixtureURL, defaultLimits(), nil, dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return dialer.DialContext(ctx, network, address)
	}))
	fixture.scenario = scenarioWithExecutionMode(t, fixture.scenario, groundtruth.ExecutionOrdered)
	run := fixture.newRun(t, &MemoryLedger{})
	defer run.Close()
	first, err := run.Execute(context.Background(), fixture.invocation(1, fixture.actions[1]))
	if err != nil || first.Result.Status != groundtruth.ActionSucceeded {
		t.Fatalf("ordered step 2 execution = %+v, %v", first.Result, err)
	}
	if _, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0])); !errors.Is(err, ErrStepSequence) {
		t.Fatalf("ordered step regression error = %v, want ErrStepSequence", err)
	}
	if dials.Load() != 0 {
		t.Fatal("ordered step regression reached the network")
	}
}

func TestPerToolConcurrencyAndRateLimitsAreExternalToCaller(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-release
		_, _ = writer.Write([]byte("ok"))
	})
	limits := defaultLimits()
	limits.MaxConcurrency = 1
	fixture := newFixture(t, fixtureURL, limits, nil, httpFixtureDialer(handler))
	run := fixture.newRun(t, &MemoryLedger{})
	defer run.Close()
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func() {
			execution, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
			if err == nil && execution.Result.Status != groundtruth.ActionSucceeded {
				err = errors.New("HTTP action did not succeed")
			}
			results <- err
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first bounded action did not start")
	}
	select {
	case <-started:
		t.Fatal("second network action bypassed the concurrency ceiling")
	case <-time.After(40 * time.Millisecond):
	}
	close(release)
	for index := 0; index < 2; index++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}

	rateHandler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte("ok")) })
	limits = defaultLimits()
	limits.MaxRequestsPerSecond = 2
	limits.MaxActionDuration = 2 * time.Second
	limits.MaxRunDuration = 4 * time.Second
	fixture = newFixture(t, fixtureURL, limits, nil, httpFixtureDialer(rateHandler))
	run = fixture.newRun(t, &MemoryLedger{})
	startedAt := time.Now()
	execution, err := run.Execute(context.Background(), fixture.invocation(3, fixture.actions[3]))
	run.Close()
	if err != nil || execution.Result.Status != groundtruth.ActionSucceeded {
		t.Fatalf("rate-limited enumeration = %+v, %v", execution.Result, err)
	}
	if elapsed := time.Since(startedAt); elapsed < 450*time.Millisecond {
		t.Fatalf("two requests completed in %s and bypassed the 2 request/second ceiling", elapsed)
	}
}

func TestTimeoutRequestMemoryAndPerToolCeilingsAreAudited(t *testing.T) {
	timeoutHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
		_, _ = writer.Write([]byte("late"))
	})
	limits := defaultLimits()
	limits.MaxActionDuration = 20 * time.Millisecond
	fixture := newFixture(t, fixtureURL, limits, nil, httpFixtureDialer(timeoutHandler))
	run := fixture.newRun(t, &MemoryLedger{})
	execution, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
	run.Close()
	if err != nil || execution.Result.Status != groundtruth.ActionCancelled || execution.Result.ErrorCode != "action_timeout" {
		t.Fatalf("timeout result = %+v, %v", execution.Result, err)
	}

	var requestDials atomic.Uint32
	limits = defaultLimits()
	limits.MaxRequestBytes = 40
	fixture = newFixture(t, fixtureURL, limits, nil, dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		requestDials.Add(1)
		return nil, errors.New("unexpected dial")
	}))
	run = fixture.newRun(t, &MemoryLedger{})
	execution, err = run.Execute(context.Background(), fixture.invocation(5, fixture.actions[5]))
	run.Close()
	if err != nil || execution.Result.ErrorCode != "request_limit_exceeded" || requestDials.Load() != 0 {
		t.Fatalf("request bound result = %+v, err=%v, dials=%d", execution.Result, err, requestDials.Load())
	}

	memoryHandler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("m", 100)))
	})
	limits = defaultLimits()
	limits.MaxResponseBytes = 128
	limits.MaxStoredResponseBytes = 128
	fixture = newFixture(t, fixtureURL, limits, nil, httpFixtureDialer(memoryHandler))
	run = fixture.newRun(t, &MemoryLedger{})
	first, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
	if err != nil || first.Result.Status != groundtruth.ActionSucceeded {
		t.Fatalf("first stored response = %+v, %v", first.Result, err)
	}
	second, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
	if err != nil || second.Result.ErrorCode != "stored_response_limit" {
		t.Fatalf("stored response ceiling = %+v, %v", second.Result, err)
	}
	third, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
	run.Close()
	if err != nil || third.Result.Status != groundtruth.ActionDenied || third.Intent.Policy().ReasonCode() != "tool_budget_exhausted" {
		t.Fatalf("per-tool ceiling = %+v, %v", third.Result, err)
	}

	limits = defaultLimits()
	limits.MaxRunDuration = 15 * time.Millisecond
	limits.MaxActionDuration = 5 * time.Millisecond
	limits.CompletionReserve = time.Millisecond
	fixture = newFixture(t, fixtureURL, limits, nil, httpFixtureDialer(memoryHandler))
	run = fixture.newRun(t, &MemoryLedger{})
	time.Sleep(20 * time.Millisecond)
	if _, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0])); !errors.Is(err, ErrRunDuration) {
		t.Fatalf("run duration error = %v, want ErrRunDuration", err)
	}
	run.Close()
}

func TestFollowLinkCannotPivotTargetsAndActionLedgerFailureClosesRun(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/first" {
			writer.Header().Set("Link", "<http://other.local:18080/not-allowed>; rel=next")
		}
		_, _ = writer.Write([]byte("ok"))
	})
	base := httpFixtureDialer(handler)
	var dials atomic.Uint32
	dialer := dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return base.DialContext(ctx, network, address)
	})
	fixture := newFixture(t, fixtureURL, defaultLimits(), nil, dialer)
	run := fixture.newRun(t, &MemoryLedger{})
	first, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0]))
	if err != nil || first.Result.Status != groundtruth.ActionSucceeded {
		t.Fatal("source response did not succeed")
	}
	before := dials.Load()
	follow, err := run.Execute(context.Background(), fixture.invocation(4, fixture.actions[4]))
	run.Close()
	if err != nil || follow.Result.ErrorCode != "link_target_denied" || dials.Load() != before {
		t.Fatalf("off-target link result = %+v, err=%v, dials=%d/%d", follow.Result, err, dials.Load(), before)
	}

	fixture = newFixture(t, fixtureURL, defaultLimits(), nil, httpFixtureDialer(handler))
	run = fixture.newRun(t, &failingLedger{failAction: true})
	if _, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0])); err == nil {
		t.Fatal("expected action-ledger failure")
	}
	if _, err := run.Execute(context.Background(), fixture.invocation(0, fixture.actions[0])); !errors.Is(err, ErrRunTerminal) {
		t.Fatalf("subsequent error = %v, want ErrRunTerminal", err)
	}
	run.Close()
}

type fixtureValues struct {
	scenario groundtruth.Scenario
	actions  []groundtruth.ActionSpec
	model    groundtruth.ModelIdentity
	policy   *Policy
	executor *Executor
}

const fixtureURL = "http://fixture.local:18080"

func newFixture(t *testing.T, serverURL string, limits Limits, resolver Resolver, dialer Dialer) fixtureValues {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	portValue, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	targetRef := opaque("labtarget:sha256:", "target")
	targetFixtureRef := opaque("fixture:sha256:", "target")
	payloadRef := opaque("fixture:sha256:", "payload")
	credentialRef := opaque("fixture:sha256:", "credential")
	target, err := NewTargetBinding(TargetBindingInput{
		Alias: "lab-target", Reference: targetRef, FixtureRef: targetFixtureRef,
		Scheme: parsed.Scheme, Host: "fixture.local", Port: uint16(portValue),
		AllowedAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := NewPayloadFixture(PayloadFixtureInput{
		Reference: payloadRef, TargetFixtureRef: targetFixtureRef, ContentType: "text/plain", Body: []byte("harmless fixture payload"),
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewCredentialFixture(CredentialFixtureInput{
		Reference: credentialRef, TargetFixtureRef: targetFixtureRef, Kind: CredentialBasic,
		Username: "fixture-user", Secret: []byte("fixture-secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	actions := []groundtruth.ActionSpec{
		mustActionSpec(t, groundtruth.ToolHTTPRequest, targetRef, "fetch-root", "", ""),
		mustActionSpec(t, groundtruth.ToolDNSLookup, targetRef, "resolve-a", "", ""),
		mustActionSpec(t, groundtruth.ToolTCPConnect, targetRef, "connect", "", ""),
		mustActionSpec(t, groundtruth.ToolEnumerateEndpoint, targetRef, "enumerate", "", ""),
		mustActionSpec(t, groundtruth.ToolFollowLink, targetRef, "follow-reviewed-link", "", ""),
		mustActionSpec(t, groundtruth.ToolTryCredential, targetRef, "try-fixture-credential", payloadRef, credentialRef),
		mustActionSpec(t, groundtruth.ToolInspectResponse, targetRef, "inspect-prior-response", "", ""),
	}
	operations := []OperationInput{
		{Action: actions[0], HTTPMethod: http.MethodGet, Path: "/first"},
		{Action: actions[1], DNSQueryType: "A"},
		{Action: actions[2], TCPPort: uint16(portValue)},
		{Action: actions[3], EnumerationPaths: []string{"/enum/a", "/enum/b"}},
		{Action: actions[4], SourceOrdinal: 1, LinkIndex: 0},
		{Action: actions[5], HTTPMethod: http.MethodPost, Path: "/credential"},
		{Action: actions[6], SourceOrdinal: 1},
	}
	policy, err := NewPolicy(PolicyConfig{
		Limits: limits, Targets: []TargetBinding{target}, PayloadFixtures: []PayloadFixture{payload},
		CredentialFixtures: []CredentialFixture{credential}, Operations: operations,
	})
	if err != nil {
		t.Fatal(err)
	}
	groundTarget, err := groundtruth.NewTarget(groundtruth.TargetInput{Alias: "lab-target", Reference: targetRef, FixtureRef: targetFixtureRef})
	if err != nil {
		t.Fatal(err)
	}
	constraints := make([]groundtruth.ToolConstraint, 0, len(actions))
	steps := make([]groundtruth.Step, 0, len(actions))
	for index, action := range actions {
		constraint, constraintErr := groundtruth.NewToolConstraint(groundtruth.ToolConstraintInput{
			Tool: action.Tool(), AllowedOperations: []string{action.Operation()}, MaxActions: 2,
			MaxRequestBytes: limits.MaxRequestBytes, MaxResponseBytes: limits.MaxResponseBytes,
		})
		if constraintErr != nil {
			t.Fatal(constraintErr)
		}
		constraints = append(constraints, constraint)
		step, stepErr := groundtruth.NewStep(groundtruth.StepInput{
			ID: "step-" + strconv.Itoa(index+1), Sequence: uint32(index + 1),
			Objective: "Exercise one reviewed harmless laboratory operation.", AllowedActions: []groundtruth.ActionSpec{action},
		})
		if stepErr != nil {
			t.Fatal(stepErr)
		}
		steps = append(steps, step)
	}
	budgets, err := groundtruth.NewBudgets(groundtruth.BudgetsInput{
		MaxActions: 10, MaxDuration: limits.MaxRunDuration, MaxConcurrency: limits.MaxConcurrency,
		MaxRequestBytes: limits.MaxRequestBytes, MaxResponseBytes: limits.MaxResponseBytes, MaxModelTokens: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := groundtruth.NewScope(groundtruth.ScopeInput{
		TenantID: "synthetic-lab", ScopeID: "executor-fixture", DeploymentBoundary: "loopback-process",
		ResidencyCellID: "dgx-local", KeyNamespace: "synthetic-keyspace", RegistryNamespace: "executor-fixtures",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scenario, err := groundtruth.NewScenario(groundtruth.ScenarioInput{
		Scope: scope, ID: "m2c3-bounded-executor", Version: 1, Name: "Bounded executor fixture",
		Objective: "Prove the closed tool catalog against harmless process fixtures.",
		Safety:    groundtruth.SafetyHarmlessLab, ExecutionMode: groundtruth.ExecutionBoundedAdaptive,
		RequiredFixtures: []string{targetFixtureRef, payloadRef, credentialRef}, Targets: []groundtruth.Target{groundTarget},
		ToolConstraints: constraints, Steps: steps, Budgets: budgets, ExpectedTelemetry: []string{"executor-audit"},
		RecordedAt: now.Add(-time.Hour), CorpusReviewDue: now.AddDate(1, 0, 0),
		LifecyclePolicyVersion: "synthetic-ground-truth-v1", ResidencyPolicyRef: "residency-dgx-local-v1",
		EncryptionKeyRef: opaque("keyref:sha256:", "executor-key"), EstimatedStorageBytes: 8192,
		EstimateBasis: groundtruth.EstimateAssumed,
	})
	if err != nil {
		t.Fatal(err)
	}
	model, err := groundtruth.NewModelIdentity(groundtruth.ModelIdentityInput{
		AttackerID: "bounded-test-planner", Provider: "deterministic-fixture", Model: "static-plan-v1",
		ModelVersion: "fixture-v1", PlannerVersion: "planner-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolver == nil {
		resolver = staticResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	}
	executor, err := New(policy, resolver, dialer)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureValues{scenario: scenario, actions: actions, model: model, policy: policy, executor: executor}
}

func (f fixtureValues) newRun(t *testing.T, ledger Ledger) *Run {
	t.Helper()
	run, err := f.executor.NewRun(RunConfig{
		Scenario: f.scenario, RunID: "m2c3-fixture-run", Ledger: ledger,
		ClockSource: "monotonic-system-clock", ClockUncertaintyMillis: 1,
		IntentStorageBytes: 2048, ActionStorageBytes: 2048, EstimateBasis: groundtruth.EstimateAssumed,
	})
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func (f fixtureValues) invocation(index int, action groundtruth.ActionSpec) Invocation {
	return Invocation{
		StepID: "step-" + strconv.Itoa(index+1), Objective: "Exercise one reviewed harmless laboratory operation.",
		Model: f.model, ProposedAction: action, EmittedAt: time.Now().UTC(),
		PlannerOutputRef: opaque("planner:sha256:", "output-"+strconv.Itoa(index+1)),
	}
}

func scenarioWithExecutionMode(t *testing.T, scenario groundtruth.Scenario, mode groundtruth.ExecutionMode) groundtruth.Scenario {
	t.Helper()
	envelope := scenario.Envelope()
	rebuilt, err := groundtruth.NewScenario(groundtruth.ScenarioInput{
		Scope: envelope.Scope(), ID: envelope.ScenarioID(), Version: envelope.ScenarioVersion(),
		Name: scenario.Name(), Objective: scenario.Objective(), Safety: scenario.Safety(), ExecutionMode: mode,
		RequiredFixtures: scenario.RequiredFixtures(), Targets: scenario.Targets(), ToolConstraints: scenario.ToolConstraints(),
		Steps: scenario.Steps(), Budgets: scenario.Budgets(), ExpectedTelemetry: scenario.ExpectedTelemetry(),
		RecordedAt: envelope.RecordedAt(), CorpusReviewDue: envelope.CorpusReviewDue(),
		LifecyclePolicyVersion: envelope.LifecyclePolicyVersion(), ResidencyPolicyRef: envelope.ResidencyPolicyRef(),
		EncryptionKeyRef: envelope.EncryptionKeyRef(), EstimatedStorageBytes: envelope.EstimatedStorageBytes(),
		EstimateBasis: envelope.EstimateBasis(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return rebuilt
}

func defaultLimits() Limits {
	return Limits{
		MaxActions: 10, MaxRunDuration: 3 * time.Second, MaxActionDuration: time.Second,
		CompletionReserve: 50 * time.Millisecond, MaxConcurrency: 2, MaxRequestsPerSecond: 20,
		MaxRequestBytes: 2048, MaxResponseBytes: 2048, MaxStoredResponseBytes: 8192,
		MaxResponseHeaderBytes: 4096, MaxEnumerationPaths: 4,
	}
}

func mustActionSpec(t *testing.T, tool groundtruth.ToolName, targetRef, operation, payload, credential string) groundtruth.ActionSpec {
	t.Helper()
	action, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: tool, TargetAlias: "lab-target", TargetRef: targetRef, Operation: operation,
		InputFixture: payload, CredentialRef: credential,
	})
	if err != nil {
		t.Fatal(err)
	}
	return action
}

type staticResolver struct{ addresses []netip.Addr }

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.addresses...), nil
}

type sequenceResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	index   int
}

func (r *sequenceResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := r.index
	if index >= len(r.answers) {
		index = len(r.answers) - 1
	}
	r.index++
	return append([]netip.Addr(nil), r.answers[index]...), nil
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (function dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return function(ctx, network, address)
}

func httpFixtureDialer(handler http.Handler) Dialer {
	return dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			request, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				return
			}
			defer request.Body.Close()
			request = request.WithContext(ctx)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			_ = response.Write(server)
		}()
		return client, nil
	})
}

type orderingLedger struct {
	MemoryLedger
}

func (l *orderingLedger) intentCount() int { return len(l.Intents()) }

type failingLedger struct {
	failIntent bool
	failAction bool
}

type contextAwareLedger struct{ MemoryLedger }

func (l *contextAwareLedger) AppendIntent(ctx context.Context, intent groundtruth.AttackerIntent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return l.MemoryLedger.AppendIntent(ctx, intent)
}

func (l *contextAwareLedger) AppendAction(ctx context.Context, action groundtruth.AttackerAction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return l.MemoryLedger.AppendAction(ctx, action)
}

type failOnceActionLedger struct {
	MemoryLedger
	failNext atomic.Bool
}

func (l *failOnceActionLedger) AppendAction(ctx context.Context, action groundtruth.AttackerAction) error {
	if l.failNext.CompareAndSwap(true, false) {
		return errors.New("fixed action ledger failure")
	}
	return l.MemoryLedger.AppendAction(ctx, action)
}

func (l *failingLedger) AppendIntent(context.Context, groundtruth.AttackerIntent) error {
	if l.failIntent {
		return errors.New("intent failure")
	}
	return nil
}

func (l *failingLedger) AppendAction(context.Context, groundtruth.AttackerAction) error {
	if l.failAction {
		return errors.New("action failure")
	}
	return nil
}

func opaque(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + hex.EncodeToString(digest[:])
}
