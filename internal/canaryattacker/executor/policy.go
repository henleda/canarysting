package executor

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

type PolicyConfig struct {
	Limits             Limits
	Targets            []TargetBinding
	PayloadFixtures    []PayloadFixture
	CredentialFixtures []CredentialFixture
	Operations         []OperationInput
}

type Policy struct {
	limits      Limits
	targets     map[string]TargetBinding
	payloads    map[string]PayloadFixture
	credentials map[string]CredentialFixture
	operations  map[string]Operation
}

func NewPolicy(config PolicyConfig) (*Policy, error) {
	if err := config.Limits.validate(); err != nil {
		return nil, fmt.Errorf("limits: %w", err)
	}
	if len(config.Targets) == 0 || len(config.Targets) > maximumTargets {
		return nil, fmt.Errorf("policy must define between 1 and %d targets", maximumTargets)
	}
	if len(config.Operations) == 0 || len(config.Operations) > maximumOperations {
		return nil, fmt.Errorf("policy must define between 1 and %d operations", maximumOperations)
	}
	if len(config.PayloadFixtures)+len(config.CredentialFixtures) > maximumFixtures {
		return nil, fmt.Errorf("policy fixture count exceeds %d", maximumFixtures)
	}
	policy := &Policy{
		limits: config.Limits, targets: make(map[string]TargetBinding, len(config.Targets)),
		payloads:    make(map[string]PayloadFixture, len(config.PayloadFixtures)),
		credentials: make(map[string]CredentialFixture, len(config.CredentialFixtures)),
		operations:  make(map[string]Operation, len(config.Operations)),
	}
	targetAliases := make(map[string]struct{}, len(config.Targets))
	targetFixtures := make(map[string]struct{}, len(config.Targets))
	for _, target := range config.Targets {
		canonical, err := NewTargetBinding(TargetBindingInput{
			Alias: target.alias, Reference: target.reference, FixtureRef: target.fixtureRef,
			Scheme: target.scheme, Host: target.host, Port: target.port,
			AllowedAddresses: target.allowedAddresses,
		})
		if err != nil {
			return nil, fmt.Errorf("target: %w", err)
		}
		if _, exists := policy.targets[canonical.reference]; exists {
			return nil, fmt.Errorf("duplicate target reference")
		}
		if _, exists := targetAliases[canonical.alias]; exists {
			return nil, fmt.Errorf("duplicate target alias")
		}
		if _, exists := targetFixtures[canonical.fixtureRef]; exists {
			return nil, fmt.Errorf("target fixture is bound to more than one executable target")
		}
		policy.targets[canonical.reference] = canonical
		targetAliases[canonical.alias] = struct{}{}
		targetFixtures[canonical.fixtureRef] = struct{}{}
	}
	for _, fixture := range config.PayloadFixtures {
		canonical, err := NewPayloadFixture(PayloadFixtureInput{
			Reference: fixture.reference, TargetFixtureRef: fixture.targetFixtureRef,
			ContentType: fixture.contentType, Body: fixture.body,
		})
		if err != nil {
			return nil, fmt.Errorf("payload fixture: %w", err)
		}
		if uint64(len(canonical.body)) > policy.limits.MaxRequestBytes {
			return nil, fmt.Errorf("payload fixture exceeds the policy request-byte ceiling")
		}
		if _, registered := targetFixtures[canonical.targetFixtureRef]; !registered {
			return nil, fmt.Errorf("payload fixture target is not registered")
		}
		if _, duplicate := policy.payloads[canonical.reference]; duplicate {
			return nil, fmt.Errorf("duplicate payload fixture reference")
		}
		policy.payloads[canonical.reference] = canonical
	}
	for _, fixture := range config.CredentialFixtures {
		canonical, err := NewCredentialFixture(CredentialFixtureInput{
			Reference: fixture.reference, TargetFixtureRef: fixture.targetFixtureRef,
			Kind: fixture.kind, Username: fixture.username, Secret: fixture.secret,
		})
		if err != nil {
			return nil, fmt.Errorf("credential fixture: %w", err)
		}
		if uint64(len(canonical.secret)+len(canonical.username)) > policy.limits.MaxRequestBytes {
			return nil, fmt.Errorf("credential fixture exceeds the policy request-byte ceiling")
		}
		if _, registered := targetFixtures[canonical.targetFixtureRef]; !registered {
			return nil, fmt.Errorf("credential fixture target is not registered")
		}
		if _, duplicate := policy.credentials[canonical.reference]; duplicate {
			return nil, fmt.Errorf("duplicate credential fixture reference")
		}
		if _, collision := policy.payloads[canonical.reference]; collision {
			return nil, fmt.Errorf("fixture reference is reused across fixture kinds")
		}
		policy.credentials[canonical.reference] = canonical
	}
	for _, input := range config.Operations {
		operation, err := policy.newOperation(input)
		if err != nil {
			return nil, fmt.Errorf("operation: %w", err)
		}
		key := actionKey(operation.action)
		if _, duplicate := policy.operations[key]; duplicate {
			return nil, fmt.Errorf("duplicate operation binding")
		}
		policy.operations[key] = operation
	}
	return policy, nil
}

func (p *Policy) newOperation(in OperationInput) (Operation, error) {
	if _, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: in.Action.Tool(), TargetAlias: in.Action.TargetAlias(), TargetRef: in.Action.TargetRef(),
		Operation: in.Action.Operation(), InputFixture: in.Action.InputFixture(),
		CredentialRef: in.Action.CredentialRef(),
	}); err != nil {
		return Operation{}, fmt.Errorf("ground-truth action: %w", err)
	}
	target, ok := p.targets[in.Action.TargetRef()]
	if !ok || target.alias != in.Action.TargetAlias() {
		return Operation{}, fmt.Errorf("operation target is not exactly registered")
	}
	operation := Operation{
		action: in.Action, httpMethod: strings.ToUpper(in.HTTPMethod), path: in.Path,
		enumerationPaths: append([]string(nil), in.EnumerationPaths...), dnsQueryType: in.DNSQueryType,
		tcpPort: in.TCPPort, sourceOrdinal: in.SourceOrdinal, linkIndex: in.LinkIndex,
	}
	switch in.Action.Tool() {
	case groundtruth.ToolHTTPRequest:
		if operation.httpMethod != http.MethodGet && operation.httpMethod != http.MethodHead {
			return Operation{}, fmt.Errorf("http_request permits only GET or HEAD")
		}
		if err := validatePath(operation.path); err != nil {
			return Operation{}, err
		}
		if err := requireZeroAlternateFields(operation, "http"); err != nil {
			return Operation{}, err
		}
	case groundtruth.ToolDNSLookup:
		if operation.dnsQueryType != "A" && operation.dnsQueryType != "AAAA" {
			return Operation{}, fmt.Errorf("dns_lookup query type must be A or AAAA")
		}
		if err := requireZeroAlternateFields(operation, "dns"); err != nil {
			return Operation{}, err
		}
	case groundtruth.ToolTCPConnect:
		if operation.tcpPort == 0 || operation.tcpPort != target.port {
			return Operation{}, fmt.Errorf("tcp_connect port must exactly equal the registered target port")
		}
		if err := requireZeroAlternateFields(operation, "tcp"); err != nil {
			return Operation{}, err
		}
	case groundtruth.ToolEnumerateEndpoint:
		if len(operation.enumerationPaths) == 0 || len(operation.enumerationPaths) > int(p.limits.MaxEnumerationPaths) {
			return Operation{}, fmt.Errorf("enumerate_endpoint path count is outside the policy ceiling")
		}
		for _, path := range operation.enumerationPaths {
			if err := validatePath(path); err != nil {
				return Operation{}, err
			}
		}
		if !sort.StringsAreSorted(operation.enumerationPaths) {
			return Operation{}, fmt.Errorf("enumeration paths must be in canonical sorted order")
		}
		for index := 1; index < len(operation.enumerationPaths); index++ {
			if operation.enumerationPaths[index] == operation.enumerationPaths[index-1] {
				return Operation{}, fmt.Errorf("enumeration paths must be unique")
			}
		}
		if err := requireZeroAlternateFields(operation, "enumeration"); err != nil {
			return Operation{}, err
		}
	case groundtruth.ToolFollowLink:
		if operation.sourceOrdinal == 0 || operation.linkIndex >= maximumCapturedLinks {
			return Operation{}, fmt.Errorf("follow_link requires a bounded prior response and link index")
		}
		if err := requireZeroAlternateFields(operation, "source"); err != nil {
			return Operation{}, err
		}
	case groundtruth.ToolTryCredential:
		if operation.httpMethod != http.MethodGet && operation.httpMethod != http.MethodPost {
			return Operation{}, fmt.Errorf("try_credential permits only GET or POST")
		}
		if err := validatePath(operation.path); err != nil {
			return Operation{}, err
		}
		credential, ok := p.credentials[in.Action.CredentialRef()]
		if !ok || credential.targetFixtureRef != target.fixtureRef {
			return Operation{}, fmt.Errorf("credential is not registered for the exact target fixture")
		}
		if err := requireZeroAlternateFields(operation, "http"); err != nil {
			return Operation{}, err
		}
	case groundtruth.ToolInspectResponse:
		if operation.sourceOrdinal == 0 {
			return Operation{}, fmt.Errorf("inspect_response requires a prior response ordinal")
		}
		if err := requireZeroAlternateFields(operation, "source"); err != nil {
			return Operation{}, err
		}
	default:
		return Operation{}, fmt.Errorf("tool %q is not in the closed executable catalog", in.Action.Tool())
	}
	if fixtureRef := in.Action.InputFixture(); fixtureRef != "" {
		fixture, ok := p.payloads[fixtureRef]
		if !ok || fixture.targetFixtureRef != target.fixtureRef {
			return Operation{}, fmt.Errorf("payload is not registered for the exact target fixture")
		}
		if in.Action.Tool() != groundtruth.ToolHTTPRequest && in.Action.Tool() != groundtruth.ToolTryCredential {
			return Operation{}, fmt.Errorf("only reviewed HTTP operations may carry a payload fixture")
		}
	}
	if in.Action.Tool() != groundtruth.ToolTryCredential && in.Action.CredentialRef() != "" {
		return Operation{}, fmt.Errorf("only try_credential may carry a credential fixture")
	}
	return operation, nil
}

func requireZeroAlternateFields(operation Operation, keep string) error {
	if keep != "http" && (operation.httpMethod != "" || operation.path != "") {
		return fmt.Errorf("operation carries fields for a different tool")
	}
	if keep != "enumeration" && len(operation.enumerationPaths) != 0 {
		return fmt.Errorf("operation carries fields for a different tool")
	}
	if keep != "dns" && operation.dnsQueryType != "" {
		return fmt.Errorf("operation carries fields for a different tool")
	}
	if keep != "tcp" && operation.tcpPort != 0 {
		return fmt.Errorf("operation carries fields for a different tool")
	}
	if keep != "source" && (operation.sourceOrdinal != 0 || operation.linkIndex != 0) {
		return fmt.Errorf("operation carries fields for a different tool")
	}
	return nil
}

func validatePath(path string) error {
	if path == "" || len(path) > 4096 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "\\") {
		return fmt.Errorf("HTTP path must be a bounded origin-form path")
	}
	parsed, err := url.ParseRequestURI(path)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("HTTP path must be a bounded origin-form path")
	}
	for _, segment := range strings.Split(parsed.EscapedPath(), "/") {
		decoded := segment
		for pass := 0; pass < 3; pass++ {
			next, err := url.PathUnescape(decoded)
			if err != nil {
				return fmt.Errorf("HTTP path contains an invalid escape")
			}
			decoded = next
			if decoded == "." || decoded == ".." || strings.ContainsAny(decoded, "/\\") {
				return fmt.Errorf("HTTP path cannot contain traversal or encoded separators")
			}
			if next == segment && pass == 0 {
				break
			}
		}
	}
	return nil
}

func actionKey(action groundtruth.ActionSpec) string {
	return strings.Join([]string{
		string(action.Tool()), action.TargetAlias(), action.TargetRef(), action.Operation(),
		action.InputFixture(), action.CredentialRef(),
	}, "\x00")
}

func scenarioPermits(scenario groundtruth.Scenario, stepID string, action groundtruth.ActionSpec) bool {
	wanted := actionKey(action)
	for _, step := range scenario.Steps() {
		if step.ID() != stepID {
			continue
		}
		for _, allowed := range step.AllowedActions() {
			if actionKey(allowed) == wanted {
				return true
			}
		}
	}
	return false
}

func (p *Policy) validateScenario(scenario groundtruth.Scenario) error {
	if _, err := groundtruth.MarshalScenarioV1(scenario); err != nil {
		return fmt.Errorf("scenario: %w", err)
	}
	budgets := scenario.Budgets()
	if budgets.MaxActions() > p.limits.MaxActions || budgets.MaxDuration() > p.limits.MaxRunDuration ||
		budgets.MaxConcurrency() > p.limits.MaxConcurrency || budgets.MaxRequestBytes() > p.limits.MaxRequestBytes ||
		budgets.MaxResponseBytes() > p.limits.MaxResponseBytes {
		return fmt.Errorf("scenario exceeds the executor hard limits")
	}
	for _, target := range scenario.Targets() {
		binding, ok := p.targets[target.Reference()]
		if !ok || binding.alias != target.Alias() || binding.fixtureRef != target.FixtureRef() {
			return fmt.Errorf("scenario target does not exactly match the executable target registry")
		}
	}
	knownFixtures := make(map[string]struct{})
	for _, target := range p.targets {
		knownFixtures[target.fixtureRef] = struct{}{}
	}
	for reference := range p.payloads {
		knownFixtures[reference] = struct{}{}
	}
	for reference := range p.credentials {
		knownFixtures[reference] = struct{}{}
	}
	for _, reference := range scenario.RequiredFixtures() {
		if _, ok := knownFixtures[reference]; !ok {
			return fmt.Errorf("scenario requires a fixture outside the executable registry")
		}
	}
	for _, step := range scenario.Steps() {
		for _, action := range step.AllowedActions() {
			if _, ok := p.operations[actionKey(action)]; !ok {
				return fmt.Errorf("scenario permits an action without an exact executable operation binding")
			}
		}
	}
	return nil
}
