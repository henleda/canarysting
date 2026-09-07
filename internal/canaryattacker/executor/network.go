package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

type systemResolver struct{}

func (systemResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

type systemDialer struct{ net.Dialer }

type execResult struct {
	status         groundtruth.ActionStatus
	errorCode      string
	httpStatus     uint16
	requestBytes   uint64
	responseBytes  uint64
	responseSHA256 string
	networkRefs    []string
	content        []byte
	stored         *storedResponse
}

func (r *Run) executeOperation(ctx context.Context, operation Operation) execResult {
	target := r.executor.policy.targets[operation.action.TargetRef()]
	var result execResult
	switch operation.action.Tool() {
	case groundtruth.ToolHTTPRequest:
		result = r.performHTTP(ctx, operation, target, operation.httpMethod, operation.path, nil)
	case groundtruth.ToolDNSLookup:
		result = r.performDNS(ctx, operation, target)
	case groundtruth.ToolTCPConnect:
		result = r.performTCP(ctx, operation, target)
	case groundtruth.ToolEnumerateEndpoint:
		result = r.performEnumeration(ctx, operation, target)
	case groundtruth.ToolFollowLink:
		result = r.performFollow(ctx, operation, target)
	case groundtruth.ToolTryCredential:
		result = r.performCredential(ctx, operation, target)
	case groundtruth.ToolInspectResponse:
		result = r.performInspect(operation)
	default:
		return execResult{status: groundtruth.ActionFailed, errorCode: "closed_catalog_violation"}
	}
	return result
}

func (r *Run) performHTTP(ctx context.Context, operation Operation, target TargetBinding, method, path string, headers http.Header) execResult {
	payload := r.executor.policy.payloads[operation.action.InputFixture()]
	return r.httpRequest(ctx, operation, target, method, path, payload, CredentialFixture{}, headers)
}

func (r *Run) performCredential(ctx context.Context, operation Operation, target TargetBinding) execResult {
	payload := r.executor.policy.payloads[operation.action.InputFixture()]
	credential := r.executor.policy.credentials[operation.action.CredentialRef()]
	return r.httpRequest(ctx, operation, target, operation.httpMethod, operation.path, payload, credential, nil)
}

func (r *Run) performEnumeration(ctx context.Context, operation Operation, target TargetBinding) execResult {
	var body []byte
	var links []string
	var refs []string
	var requestBytes uint64
	var responseBytes uint64
	var lastStatus uint16
	requestLimit, responseLimit := r.actionByteLimits(operation.action.Tool())
	for _, path := range operation.enumerationPaths {
		remainingRequestBytes := requestLimit - requestBytes
		remainingResponseBytes := responseLimit - responseBytes
		part := r.httpRequestWithLimits(ctx, operation, target, http.MethodGet, path, PayloadFixture{}, CredentialFixture{}, nil, remainingRequestBytes, remainingResponseBytes)
		refs = append(refs, part.networkRefs...)
		if part.status != groundtruth.ActionSucceeded {
			part.networkRefs = refs
			return part
		}
		requestBytes += part.requestBytes
		responseBytes += part.responseBytes
		if responseBytes > responseLimit {
			return execResult{status: groundtruth.ActionFailed, errorCode: "response_limit_exceeded", networkRefs: refs}
		}
		lastStatus = part.httpStatus
		if part.stored != nil {
			body = append(body, part.stored.body...)
			links = append(links, part.stored.links...)
		}
	}
	return successfulHTTP(lastStatus, body, links, refs)
}

func (r *Run) performFollow(ctx context.Context, operation Operation, target TargetBinding) execResult {
	source, ok := r.loadResponse(operation.sourceOrdinal)
	if !ok || source.targetRef != operation.action.TargetRef() || int(operation.linkIndex) >= len(source.links) {
		return execResult{status: groundtruth.ActionFailed, errorCode: "source_link_missing"}
	}
	base := &url.URL{Scheme: target.scheme, Host: targetAuthority(target), Path: "/"}
	reference, err := url.Parse(source.links[operation.linkIndex])
	if err != nil {
		return execResult{status: groundtruth.ActionFailed, errorCode: "link_invalid"}
	}
	resolved := base.ResolveReference(reference)
	if resolved.User != nil || resolved.Fragment != "" || resolved.Scheme != target.scheme || resolved.Hostname() != target.host || resolved.Port() != strconv.Itoa(int(target.port)) {
		return execResult{status: groundtruth.ActionFailed, errorCode: "link_target_denied"}
	}
	path := resolved.EscapedPath()
	if path == "" {
		path = "/"
	}
	if resolved.RawQuery != "" {
		path += "?" + resolved.RawQuery
	}
	if validatePath(path) != nil {
		return execResult{status: groundtruth.ActionFailed, errorCode: "link_invalid"}
	}
	return r.httpRequest(ctx, operation, target, http.MethodGet, path, PayloadFixture{}, CredentialFixture{}, nil)
}

func (r *Run) performInspect(operation Operation) execResult {
	source, ok := r.loadResponse(operation.sourceOrdinal)
	if !ok || source.targetRef != operation.action.TargetRef() {
		return execResult{status: groundtruth.ActionFailed, errorCode: "source_response_missing"}
	}
	_, responseLimit := r.actionByteLimits(operation.action.Tool())
	if uint64(len(source.body)) > responseLimit {
		return execResult{status: groundtruth.ActionFailed, errorCode: "response_limit_exceeded"}
	}
	digest := sha256.Sum256(source.body)
	result := execResult{
		status: groundtruth.ActionSucceeded, httpStatus: source.status,
		responseBytes: uint64(len(source.body)), content: append([]byte(nil), source.body...),
	}
	if len(source.body) > 0 {
		result.responseSHA256 = hex.EncodeToString(digest[:])
	}
	return result
}

func (r *Run) performDNS(ctx context.Context, operation Operation, target TargetBinding) execResult {
	network := "ip4"
	if operation.dnsQueryType == "AAAA" {
		network = "ip6"
	}
	if err := r.waitRate(ctx); err != nil {
		return failedForContext(ctx, "rate_wait_failed")
	}
	if _, err := r.resolveExact(ctx, target, network); err != nil {
		return failedForContext(ctx, "dns_boundary_denied")
	}
	return execResult{
		status:      groundtruth.ActionSucceeded,
		networkRefs: []string{digestReference("network:sha256:", operation.action.TargetRef(), operation.action.Operation(), operation.dnsQueryType)},
	}
}

func (r *Run) performTCP(ctx context.Context, operation Operation, target TargetBinding) execResult {
	addresses, err := r.resolveExact(ctx, target, "ip")
	if err != nil {
		return failedForContext(ctx, "address_boundary_denied")
	}
	if err := r.waitRate(ctx); err != nil {
		return failedForContext(ctx, "rate_wait_failed")
	}
	connection, err := r.executor.dialer.DialContext(ctx, "tcp", net.JoinHostPort(addresses[0].String(), strconv.Itoa(int(target.port))))
	if err != nil {
		return failedForContext(ctx, "connect_failed")
	}
	_ = connection.Close()
	return execResult{
		status:      groundtruth.ActionSucceeded,
		networkRefs: []string{digestReference("network:sha256:", operation.action.TargetRef(), operation.action.Operation(), "tcp")},
	}
}

func (r *Run) httpRequest(ctx context.Context, operation Operation, target TargetBinding, method, path string, payload PayloadFixture, credential CredentialFixture, headers http.Header) execResult {
	_, responseLimit := r.actionByteLimits(operation.action.Tool())
	return r.httpRequestWithResponseLimit(ctx, operation, target, method, path, payload, credential, headers, responseLimit)
}

func (r *Run) httpRequestWithResponseLimit(ctx context.Context, operation Operation, target TargetBinding, method, path string, payload PayloadFixture, credential CredentialFixture, headers http.Header, responseLimit uint64) execResult {
	requestLimit, _ := r.actionByteLimits(operation.action.Tool())
	return r.httpRequestWithLimits(ctx, operation, target, method, path, payload, credential, headers, requestLimit, responseLimit)
}

func (r *Run) httpRequestWithLimits(ctx context.Context, operation Operation, target TargetBinding, method, path string, payload PayloadFixture, credential CredentialFixture, headers http.Header, requestLimit, responseLimit uint64) execResult {
	networkRefs := requestNetworkReference(operation, method, path)
	configuredRequestLimit, configuredResponseLimit := r.actionByteLimits(operation.action.Tool())
	requestLimit = min64(requestLimit, configuredRequestLimit)
	responseLimit = min64(responseLimit, configuredResponseLimit)
	requestURL := (&url.URL{Scheme: target.scheme, Host: targetAuthority(target), Path: "/"}).ResolveReference(&url.URL{Path: path}).String()
	if parsed, parseErr := url.ParseRequestURI(path); parseErr == nil {
		requestURL = (&url.URL{Scheme: target.scheme, Host: targetAuthority(target), Path: parsed.Path, RawPath: parsed.RawPath, RawQuery: parsed.RawQuery}).String()
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(payload.body))
	if err != nil {
		return execResult{status: groundtruth.ActionFailed, errorCode: "request_invalid"}
	}
	if payload.contentType != "" {
		request.Header.Set("Content-Type", payload.contentType)
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	if credential.kind == CredentialBasic {
		value := base64.StdEncoding.EncodeToString(append(append([]byte(credential.username), ':'), credential.secret...))
		request.Header.Set("Authorization", "Basic "+value)
	} else if credential.kind == CredentialBearer {
		request.Header.Set("Authorization", "Bearer "+string(credential.secret))
	}
	request.Header.Set("User-Agent", "canarysting-attacker-executor/"+ExecutorVersion)
	request.Close = true
	requestBytes, err := serializedRequestBytes(request, requestLimit)
	if err != nil {
		if !errors.Is(err, errRequestWireLimit) {
			return execResult{status: groundtruth.ActionFailed, errorCode: "request_invalid"}
		}
		return execResult{status: groundtruth.ActionFailed, errorCode: "request_limit_exceeded"}
	}
	before, err := r.resolveExact(ctx, target, "ip")
	if err != nil {
		return failedForContext(ctx, "address_boundary_denied")
	}
	if err := r.waitRate(ctx); err != nil {
		return failedForContext(ctx, "rate_wait_failed")
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: int64(r.executor.policy.limits.MaxResponseHeaderBytes),
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.host},
		TLSNextProto:           make(map[string]func(string, *tls.Conn) http.RoundTripper),
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, errors.New("network denied")
			}
			return r.executor.dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(before[0].String(), strconv.Itoa(int(target.port))))
		},
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		transport.CloseIdleConnections()
		return failedForContext(ctx, "request_failed")
	}
	defer response.Body.Close()
	defer transport.CloseIdleConnections()
	if response.StatusCode >= 300 && response.StatusCode <= 399 && response.Header.Get("Location") != "" {
		return execResult{status: groundtruth.ActionFailed, errorCode: "redirect_denied", networkRefs: networkRefs}
	}
	if headerBytes(response.Header) > r.executor.policy.limits.MaxResponseHeaderBytes {
		return execResult{status: groundtruth.ActionFailed, errorCode: "response_header_limit", networkRefs: networkRefs}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(responseLimit)+1))
	if err != nil {
		return failedForContextWithRefs(ctx, "response_read_failed", networkRefs)
	}
	if uint64(len(body)) > responseLimit {
		return execResult{status: groundtruth.ActionFailed, errorCode: "response_limit_exceeded", networkRefs: networkRefs}
	}
	after, err := r.resolveExact(ctx, target, "ip")
	if err != nil {
		return failedForContextWithRefs(ctx, "dns_rebinding_denied", networkRefs)
	}
	if !sameAddresses(before, after) {
		return execResult{status: groundtruth.ActionFailed, errorCode: "dns_rebinding_denied", networkRefs: networkRefs}
	}
	links := captureLinks(response.Header.Values("Link"))
	result := successfulHTTP(uint16(response.StatusCode), body, links, networkRefs)
	result.requestBytes = requestBytes
	return result
}

var errRequestWireLimit = errors.New("serialized request exceeds byte limit")

type requestByteCounter struct {
	limit   uint64
	written uint64
}

func (w *requestByteCounter) Write(value []byte) (int, error) {
	if w.written > w.limit || uint64(len(value)) > w.limit-w.written {
		return 0, errRequestWireLimit
	}
	w.written += uint64(len(value))
	return len(value), nil
}

func serializedRequestBytes(request *http.Request, limit uint64) (uint64, error) {
	clone := request.Clone(request.Context())
	if request.GetBody != nil {
		body, err := request.GetBody()
		if err != nil {
			return 0, err
		}
		clone.Body = body
		defer body.Close()
	}
	counter := &requestByteCounter{limit: limit}
	if err := clone.Write(counter); err != nil {
		return 0, err
	}
	return counter.written, nil
}

func successfulHTTP(status uint16, body []byte, links, refs []string) execResult {
	digest := sha256.Sum256(body)
	result := execResult{
		status: groundtruth.ActionSucceeded, httpStatus: status, responseBytes: uint64(len(body)),
		networkRefs: refs,
		stored:      &storedResponse{status: status, links: append([]string(nil), links...), body: append([]byte(nil), body...)},
	}
	if len(body) > 0 {
		result.responseSHA256 = hex.EncodeToString(digest[:])
	}
	return result
}

func (r *Run) actionByteLimits(tool groundtruth.ToolName) (uint64, uint64) {
	requestLimit := r.executor.policy.limits.MaxRequestBytes
	responseLimit := r.executor.policy.limits.MaxResponseBytes
	budgets := r.config.Scenario.Budgets()
	requestLimit = min64(requestLimit, budgets.MaxRequestBytes())
	responseLimit = min64(responseLimit, budgets.MaxResponseBytes())
	if constraint, ok := toolConstraint(r.config.Scenario, tool); ok {
		requestLimit = min64(requestLimit, constraint.MaxRequestBytes())
		responseLimit = min64(responseLimit, constraint.MaxResponseBytes())
	}
	return requestLimit, responseLimit
}

func (r *Run) resolveExact(ctx context.Context, target TargetBinding, network string) ([]netip.Addr, error) {
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(target.host); err == nil {
		addresses = []netip.Addr{literal.Unmap()}
	} else {
		resolved, err := r.executor.resolver.LookupNetIP(ctx, network, target.host)
		if err != nil {
			return nil, errors.New("resolution failed")
		}
		addresses = resolved
	}
	canonical := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() ||
			(!address.IsPrivate() && !address.IsLoopback()) {
			return nil, errors.New("address outside laboratory boundary")
		}
		canonical = append(canonical, address)
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Less(canonical[j]) })
	canonical = compactAddresses(canonical)
	expected := target.allowedAddresses
	if network == "ip4" || network == "ip6" {
		expected = expected[:0:0]
		for _, address := range target.allowedAddresses {
			if (network == "ip4" && address.Is4()) || (network == "ip6" && address.Is6()) {
				expected = append(expected, address)
			}
		}
	}
	if len(canonical) == 0 || len(canonical) > maximumResolvedAddresses || !sameAddresses(canonical, expected) {
		return nil, errors.New("resolved address set differs from exact policy binding")
	}
	return canonical, nil
}

func (r *Run) waitRate(ctx context.Context) error {
	interval := time.Second / time.Duration(r.executor.policy.limits.MaxRequestsPerSecond)
	r.mu.Lock()
	now := time.Now()
	when := now
	if r.nextRequestAt.After(now) {
		when = r.nextRequestAt
	}
	r.nextRequestAt = when.Add(interval)
	r.mu.Unlock()
	if delay := time.Until(when); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func (r *Run) storeResponse(ordinal uint32, response storedResponse) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	bytes := uint64(len(response.body))
	for _, link := range response.links {
		bytes += uint64(len(link))
	}
	if r.storedBytes+bytes > r.executor.policy.limits.MaxStoredResponseBytes {
		return false
	}
	r.stored[ordinal] = storedResponse{
		targetRef: response.targetRef, status: response.status,
		links: append([]string(nil), response.links...), body: append([]byte(nil), response.body...),
	}
	r.storedBytes += bytes
	return true
}

func (r *Run) loadResponse(ordinal uint32) (storedResponse, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	response, ok := r.stored[ordinal]
	response.links = append([]string(nil), response.links...)
	response.body = append([]byte(nil), response.body...)
	return response, ok
}

func targetAuthority(target TargetBinding) string {
	return net.JoinHostPort(target.host, strconv.Itoa(int(target.port)))
}

func requestNetworkReference(operation Operation, method, path string) []string {
	return []string{digestReference("network:sha256:", operation.action.TargetRef(), operation.action.Operation(), method, path)}
}

func headerBytes(header http.Header) uint64 {
	var total uint64
	for name, values := range header {
		total += uint64(len(name))
		for _, value := range values {
			total += uint64(len(value))
		}
	}
	return total
}

func captureLinks(values []string) []string {
	links := make([]string, 0, len(values))
	for _, value := range values {
		for _, entry := range strings.Split(value, ",") {
			entry = strings.TrimSpace(entry)
			if !strings.HasPrefix(entry, "<") {
				continue
			}
			end := strings.IndexByte(entry, '>')
			if end <= 1 {
				continue
			}
			links = append(links, entry[1:end])
			if len(links) == maximumCapturedLinks {
				return links
			}
		}
	}
	return links
}

func compactAddresses(addresses []netip.Addr) []netip.Addr {
	if len(addresses) < 2 {
		return addresses
	}
	result := addresses[:1]
	for _, address := range addresses[1:] {
		if address != result[len(result)-1] {
			result = append(result, address)
		}
	}
	return result
}

func sameAddresses(left, right []netip.Addr) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func failedForContext(ctx context.Context, code string) execResult {
	return failedForContextWithRefs(ctx, code, nil)
}

func failedForContextWithRefs(ctx context.Context, code string, refs []string) execResult {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		code = "deadline_exceeded"
	} else if errors.Is(ctx.Err(), context.Canceled) {
		code = "caller_cancelled"
	}
	return execResult{status: groundtruth.ActionFailed, errorCode: code, networkRefs: refs}
}

func min64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}
