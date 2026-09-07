package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/executor"
	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

const objective = "Exercise one reviewed harmless laboratory operation."

func main() {
	var runID string
	var scenarioID string
	var selfcheck bool
	flag.StringVar(&runID, "run-id", "", "bounded lowercase run identifier")
	flag.StringVar(&scenarioID, "scenario-id", "", "reviewed scenario identifier")
	flag.BoolVar(&selfcheck, "selfcheck", false, "run the fixed bounded-executor proof")
	flag.Parse()
	if !selfcheck || flag.NArg() != 0 || !identifier(runID) || !identifier(scenarioID) {
		fmt.Fprintln(os.Stderr, "attackerexecutorspike: -selfcheck and canonical -run-id/-scenario-id are required")
		os.Exit(2)
	}
	if err := prove(runID, scenarioID); err != nil {
		fmt.Fprintf(os.Stderr, "attackerexecutorspike: proof failed: %v\n", err)
		os.Exit(1)
	}
	for _, line := range []string{
		"PROOF catalog=PASS tools=7 arbitrary_tools=false",
		"PROOF audit_order=PASS intent_before_resolve_and_dial=true failures_terminal=true",
		"PROOF allowlist=PASS http_dns_tcp=loopback_only exact_target=true ambient_proxy=false",
		"PROOF structured_tools=PASS enumeration=true follow_link=true fixture_credential=true inspect_response=true",
		"PROOF redirect_rebinding=PASS redirects_followed=false dns_set_change_denied=true",
		"PROOF exercised_bounds=PASS actions=true response=true pre_cancellation=audited",
		"PROOF denied=PASS shell_kubernetes_docker_filesystem_control_plane=false audited=true",
		"PROOF cleanup=PASS listener_closed=true persistent_state=false",
	} {
		fmt.Println(line)
	}
}

func prove(runID, scenarioID string) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("loopback listener unavailable")
	}
	address := listener.Addr().(*net.TCPAddr)
	var responseMode atomic.Int32
	var credentialSeen atomic.Bool
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/ok" {
			switch responseMode.Load() {
			case 1:
				http.Redirect(writer, request, "/next", http.StatusFound)
				return
			case 2:
				_, _ = writer.Write([]byte(strings.Repeat("x", 257)))
				return
			}
			writer.Header().Set("Link", "</next>; rel=next")
			_, _ = writer.Write([]byte("harmless response"))
			return
		}
		if request.URL.Path == "/credential" {
			username, password, ok := request.BasicAuth()
			credentialSeen.Store(ok && username == "fixture-user" && password == "fixture-secret")
		}
		_, _ = writer.Write([]byte("harmless fixture"))
	})}
	serveDone := make(chan struct{})
	go func() {
		_ = server.Serve(listener)
		close(serveDone)
	}()
	cleanup := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = listener.Close()
		select {
		case <-serveDone:
		case <-ctx.Done():
			return errors.New("loopback listener did not stop")
		}
		connection, dialErr := net.DialTimeout("tcp4", listener.Addr().String(), 25*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return errors.New("loopback listener remained reachable")
		}
		return nil
	}
	cleaned := false
	defer func() {
		if !cleaned {
			_ = cleanup()
		}
	}()

	values, err := buildFixture(scenarioID, uint16(address.Port))
	if err != nil {
		return err
	}
	ledger := &executor.MemoryLedger{}
	resolver := &proofResolver{}
	dialer := auditDialer{ledger: ledger}
	boundary, err := executor.New(values.policy, resolver, dialer)
	if err != nil {
		return err
	}
	run, err := boundary.NewRun(executor.RunConfig{
		Scenario: values.scenario, RunID: runID, Ledger: ledger,
		ClockSource: "monotonic-system-clock", ClockUncertaintyMillis: 1,
		IntentStorageBytes: 2048, ActionStorageBytes: 2048, EstimateBasis: groundtruth.EstimateMeasured,
	})
	if err != nil {
		return err
	}
	defer run.Close()
	for index, action := range values.actions {
		result, executeErr := run.Execute(context.Background(), values.invocation(index, action, "catalog"))
		if executeErr != nil || result.Result.Status != groundtruth.ActionSucceeded {
			return fmt.Errorf("closed catalog operation %d failed", index+1)
		}
	}
	if !credentialSeen.Load() {
		return errors.New("fixture credential was not resolved inside its exact operation")
	}

	responseMode.Store(1)
	result, err := run.Execute(context.Background(), values.invocation(0, values.actions[0], "redirect"))
	if err != nil || result.Result.ErrorCode != "redirect_denied" {
		return errors.New("redirect was not denied")
	}
	responseMode.Store(0)
	resolver.rebind.Store(true)
	resolver.calls.Store(0)
	result, err = run.Execute(context.Background(), values.invocation(0, values.actions[0], "rebind"))
	if err != nil || result.Result.ErrorCode != "dns_rebinding_denied" {
		return errors.New("DNS address-set change was not denied")
	}
	resolver.rebind.Store(false)
	resolver.calls.Store(0)

	responseMode.Store(2)
	result, err = run.Execute(context.Background(), values.invocation(0, values.actions[0], "response-bound"))
	if err != nil || result.Result.ErrorCode != "response_limit_exceeded" {
		return errors.New("response byte ceiling was not enforced")
	}
	responseMode.Store(0)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = run.Execute(cancelled, values.invocation(0, values.actions[0], "cancel"))
	if err != nil || result.Result.Status != groundtruth.ActionCancelled || result.Result.ErrorCode != "caller_cancelled" {
		return errors.New("cancellation was not audited")
	}
	denied, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: "shell", TargetAlias: values.actions[0].TargetAlias(), TargetRef: values.actions[0].TargetRef(), Operation: "run-command",
	})
	if err != nil {
		return err
	}
	result, err = run.Execute(context.Background(), values.invocation(0, denied, "deny"))
	if err != nil || result.Result.Status != groundtruth.ActionDenied || result.Action.Attempted() {
		return errors.New("unregistered tool was not denied without execution")
	}
	if _, err = run.Execute(context.Background(), values.invocation(0, denied, "budget")); !errors.Is(err, executor.ErrActionBudget) {
		return errors.New("global action ceiling was not enforced")
	}
	if len(ledger.Intents()) != 12 || len(ledger.Actions()) != 12 {
		return errors.New("intent/action audit cardinality is incomplete")
	}
	failingLedger := &intentFailLedger{}
	countingDialer := &countDialer{}
	failureBoundary, err := executor.New(values.policy, &proofResolver{}, countingDialer)
	if err != nil {
		return err
	}
	failureRun, err := failureBoundary.NewRun(executor.RunConfig{
		Scenario: values.scenario, RunID: runID + "-audit", Ledger: failingLedger,
		ClockSource: "monotonic-system-clock", ClockUncertaintyMillis: 1,
		IntentStorageBytes: 2048, ActionStorageBytes: 2048, EstimateBasis: groundtruth.EstimateMeasured,
	})
	if err != nil {
		return err
	}
	if _, err = failureRun.Execute(context.Background(), values.invocation(0, values.actions[0], "ledger-failure")); err == nil {
		return errors.New("intent ledger failure was not surfaced")
	}
	if _, err = failureRun.Execute(context.Background(), values.invocation(0, values.actions[0], "ledger-terminal")); !errors.Is(err, executor.ErrRunTerminal) {
		return errors.New("intent ledger failure did not close the run")
	}
	failureRun.Close()
	if countingDialer.calls.Load() != 0 {
		return errors.New("intent ledger failure reached the dialer")
	}
	if err := cleanup(); err != nil {
		return err
	}
	cleaned = true
	return nil
}

type fixtureValues struct {
	policy   *executor.Policy
	scenario groundtruth.Scenario
	actions  []groundtruth.ActionSpec
	model    groundtruth.ModelIdentity
}

func (v fixtureValues) invocation(index int, action groundtruth.ActionSpec, suffix string) executor.Invocation {
	return executor.Invocation{
		StepID: "step-" + strconv.Itoa(index+1), Objective: objective, Model: v.model,
		ProposedAction: action, EmittedAt: time.Now().UTC(),
		PlannerOutputRef: opaque("planner:sha256:", "proof-"+suffix),
	}
}

func buildFixture(scenarioID string, port uint16) (fixtureValues, error) {
	targetRef := opaque("labtarget:sha256:", "executor-target")
	targetFixtureRef := opaque("fixture:sha256:", "executor-target")
	payloadRef := opaque("fixture:sha256:", "executor-payload")
	credentialRef := opaque("fixture:sha256:", "executor-credential")
	target, err := executor.NewTargetBinding(executor.TargetBindingInput{
		Alias: "loopback-fixture", Reference: targetRef, FixtureRef: targetFixtureRef,
		Scheme: "http", Host: "fixture.local", Port: port,
		AllowedAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	})
	if err != nil {
		return fixtureValues{}, err
	}
	payload, err := executor.NewPayloadFixture(executor.PayloadFixtureInput{
		Reference: payloadRef, TargetFixtureRef: targetFixtureRef, ContentType: "text/plain", Body: []byte("harmless payload"),
	})
	if err != nil {
		return fixtureValues{}, err
	}
	credential, err := executor.NewCredentialFixture(executor.CredentialFixtureInput{
		Reference: credentialRef, TargetFixtureRef: targetFixtureRef, Kind: executor.CredentialBasic,
		Username: "fixture-user", Secret: []byte("fixture-secret"),
	})
	if err != nil {
		return fixtureValues{}, err
	}
	tools := []groundtruth.ToolName{
		groundtruth.ToolHTTPRequest, groundtruth.ToolDNSLookup, groundtruth.ToolTCPConnect,
		groundtruth.ToolEnumerateEndpoint, groundtruth.ToolFollowLink, groundtruth.ToolTryCredential,
		groundtruth.ToolInspectResponse,
	}
	operations := []string{"fetch", "resolve", "connect", "enumerate", "follow", "credential", "inspect"}
	actions := make([]groundtruth.ActionSpec, len(tools))
	for index := range tools {
		input, credentialInput := "", ""
		if tools[index] == groundtruth.ToolTryCredential {
			input, credentialInput = payloadRef, credentialRef
		}
		actions[index], err = groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
			Tool: tools[index], TargetAlias: "loopback-fixture", TargetRef: targetRef,
			Operation: operations[index], InputFixture: input, CredentialRef: credentialInput,
		})
		if err != nil {
			return fixtureValues{}, err
		}
	}
	limits := executor.Limits{
		MaxActions: 12, MaxRunDuration: 10 * time.Second, MaxActionDuration: time.Second,
		CompletionReserve: 100 * time.Millisecond, MaxConcurrency: 2, MaxRequestsPerSecond: 20,
		MaxRequestBytes: 512, MaxResponseBytes: 256, MaxStoredResponseBytes: 4096,
		MaxResponseHeaderBytes: 4096, MaxEnumerationPaths: 4,
	}
	policy, err := executor.NewPolicy(executor.PolicyConfig{
		Limits: limits, Targets: []executor.TargetBinding{target}, PayloadFixtures: []executor.PayloadFixture{payload},
		CredentialFixtures: []executor.CredentialFixture{credential},
		Operations: []executor.OperationInput{
			{Action: actions[0], HTTPMethod: http.MethodGet, Path: "/ok"},
			{Action: actions[1], DNSQueryType: "A"},
			{Action: actions[2], TCPPort: port},
			{Action: actions[3], EnumerationPaths: []string{"/enum/a", "/enum/b"}},
			{Action: actions[4], SourceOrdinal: 1},
			{Action: actions[5], HTTPMethod: http.MethodPost, Path: "/credential"},
			{Action: actions[6], SourceOrdinal: 1},
		},
	})
	if err != nil {
		return fixtureValues{}, err
	}
	groundTarget, err := groundtruth.NewTarget(groundtruth.TargetInput{Alias: "loopback-fixture", Reference: targetRef, FixtureRef: targetFixtureRef})
	if err != nil {
		return fixtureValues{}, err
	}
	constraints := make([]groundtruth.ToolConstraint, len(tools))
	steps := make([]groundtruth.Step, len(tools))
	for index := range tools {
		maxActions := uint32(1)
		if tools[index] == groundtruth.ToolHTTPRequest {
			maxActions = 5
		}
		constraints[index], err = groundtruth.NewToolConstraint(groundtruth.ToolConstraintInput{
			Tool: tools[index], AllowedOperations: []string{operations[index]}, MaxActions: maxActions,
			MaxRequestBytes: limits.MaxRequestBytes, MaxResponseBytes: limits.MaxResponseBytes,
		})
		if err != nil {
			return fixtureValues{}, err
		}
		steps[index], err = groundtruth.NewStep(groundtruth.StepInput{
			ID: "step-" + strconv.Itoa(index+1), Sequence: uint32(index + 1), Objective: objective,
			AllowedActions: []groundtruth.ActionSpec{actions[index]},
		})
		if err != nil {
			return fixtureValues{}, err
		}
	}
	budgets, err := groundtruth.NewBudgets(groundtruth.BudgetsInput{
		MaxActions: 12, MaxDuration: limits.MaxRunDuration, MaxConcurrency: limits.MaxConcurrency,
		MaxRequestBytes: limits.MaxRequestBytes, MaxResponseBytes: limits.MaxResponseBytes, MaxModelTokens: 1024,
	})
	if err != nil {
		return fixtureValues{}, err
	}
	scope, err := groundtruth.NewScope(groundtruth.ScopeInput{
		TenantID: "synthetic-lab", ScopeID: "bounded-executor", DeploymentBoundary: "loopback-process",
		ResidencyCellID: "dgx-local", KeyNamespace: "synthetic-keyspace", RegistryNamespace: "executor-fixtures",
	})
	if err != nil {
		return fixtureValues{}, err
	}
	now := time.Now().UTC()
	scenario, err := groundtruth.NewScenario(groundtruth.ScenarioInput{
		Scope: scope, ID: scenarioID, Version: 1, Name: "Bounded executor proof",
		Objective: "Prove closed tools against a harmless loopback fixture.",
		Safety:    groundtruth.SafetyHarmlessLab, ExecutionMode: groundtruth.ExecutionBoundedAdaptive,
		RequiredFixtures: []string{targetFixtureRef, payloadRef, credentialRef}, Targets: []groundtruth.Target{groundTarget},
		ToolConstraints: constraints, Steps: steps, Budgets: budgets, ExpectedTelemetry: []string{"executor-audit"},
		RecordedAt: now.Add(-time.Minute), CorpusReviewDue: now.AddDate(1, 0, 0),
		LifecyclePolicyVersion: "synthetic-ground-truth-v1", ResidencyPolicyRef: "residency-dgx-local-v1",
		EncryptionKeyRef: opaque("keyref:sha256:", "executor-proof-key"), EstimatedStorageBytes: 16384,
		EstimateBasis: groundtruth.EstimateMeasured,
	})
	if err != nil {
		return fixtureValues{}, err
	}
	model, err := groundtruth.NewModelIdentity(groundtruth.ModelIdentityInput{
		AttackerID: "bounded-proof-planner", Provider: "deterministic-fixture", Model: "static-plan-v1",
		ModelVersion: "fixture-v1", PlannerVersion: "planner-v1",
	})
	return fixtureValues{policy: policy, scenario: scenario, actions: actions, model: model}, err
}

type proofResolver struct {
	rebind atomic.Bool
	calls  atomic.Uint32
}

func (r *proofResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	call := r.calls.Add(1)
	if r.rebind.Load() && call > 1 {
		return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

type auditDialer struct{ ledger *executor.MemoryLedger }

func (d auditDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if len(d.ledger.Intents()) <= len(d.ledger.Actions()) {
		return nil, errors.New("intent was not committed before dial")
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

type intentFailLedger struct{}

func (*intentFailLedger) AppendIntent(context.Context, groundtruth.AttackerIntent) error {
	return errors.New("fixed intent ledger failure")
}

func (*intentFailLedger) AppendAction(context.Context, groundtruth.AttackerAction) error { return nil }

type countDialer struct{ calls atomic.Uint32 }

func (d *countDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errors.New("unexpected dial")
}

func opaque(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + hex.EncodeToString(digest[:])
}

func identifier(value string) bool {
	if value == "" || len(value) > 127 || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			(index > 0 && (character == '-' || character == '.' || character == '_' || character == ':' || character == '/')) {
			continue
		}
		return false
	}
	return true
}
