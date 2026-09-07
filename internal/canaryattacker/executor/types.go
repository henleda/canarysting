package executor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

const (
	PolicyVersion   = "bounded-tool-policy-v1"
	ExecutorVersion = "bounded-tool-executor-v1"

	AbsoluteMaxActions             = 256
	AbsoluteMaxConcurrency         = 8
	AbsoluteMaxRequestsPerSecond   = 20
	AbsoluteMaxRequestBytes        = 1 << 20
	AbsoluteMaxResponseBytes       = 1 << 20
	AbsoluteMaxStoredResponseBytes = 8 << 20
	AbsoluteMaxResponseHeaderBytes = 64 << 10
	AbsoluteMaxEnumerationPaths    = 16
	AbsoluteMaxRunDuration         = 15 * time.Minute
	AbsoluteMaxActionDuration      = 30 * time.Second
	AbsoluteMaxCompletionReserve   = time.Second
	maximumTargets                 = 32
	maximumOperations              = 256
	maximumFixtures                = 256
	maximumResolvedAddresses       = 16
	maximumCapturedLinks           = 32
)

type Limits struct {
	MaxActions             uint32
	MaxRunDuration         time.Duration
	MaxActionDuration      time.Duration
	CompletionReserve      time.Duration
	MaxConcurrency         uint32
	MaxRequestsPerSecond   uint32
	MaxRequestBytes        uint64
	MaxResponseBytes       uint64
	MaxStoredResponseBytes uint64
	MaxResponseHeaderBytes uint64
	MaxEnumerationPaths    uint32
}

func (l Limits) validate() error {
	checks := []struct {
		name  string
		value uint64
		limit uint64
	}{
		{"max actions", uint64(l.MaxActions), AbsoluteMaxActions},
		{"max concurrency", uint64(l.MaxConcurrency), AbsoluteMaxConcurrency},
		{"max requests per second", uint64(l.MaxRequestsPerSecond), AbsoluteMaxRequestsPerSecond},
		{"max request bytes", l.MaxRequestBytes, AbsoluteMaxRequestBytes},
		{"max response bytes", l.MaxResponseBytes, AbsoluteMaxResponseBytes},
		{"max stored response bytes", l.MaxStoredResponseBytes, AbsoluteMaxStoredResponseBytes},
		{"max response header bytes", l.MaxResponseHeaderBytes, AbsoluteMaxResponseHeaderBytes},
		{"max enumeration paths", uint64(l.MaxEnumerationPaths), AbsoluteMaxEnumerationPaths},
	}
	for _, check := range checks {
		if check.value == 0 || check.value > check.limit {
			return fmt.Errorf("%s must be between 1 and %d", check.name, check.limit)
		}
	}
	if l.MaxRunDuration <= 0 || l.MaxRunDuration > AbsoluteMaxRunDuration {
		return fmt.Errorf("max run duration must be between 1ns and %s", AbsoluteMaxRunDuration)
	}
	if l.MaxActionDuration <= 0 || l.MaxActionDuration > AbsoluteMaxActionDuration || l.MaxActionDuration > l.MaxRunDuration {
		return fmt.Errorf("max action duration must be positive and no greater than %s or the run duration", AbsoluteMaxActionDuration)
	}
	if l.CompletionReserve < time.Millisecond || l.CompletionReserve > AbsoluteMaxCompletionReserve || l.CompletionReserve >= l.MaxRunDuration {
		return fmt.Errorf("completion reserve must be between 1ms and %s and less than the run duration", AbsoluteMaxCompletionReserve)
	}
	if l.MaxConcurrency > l.MaxActions {
		return fmt.Errorf("max concurrency cannot exceed max actions")
	}
	if l.MaxResponseBytes > l.MaxStoredResponseBytes {
		return fmt.Errorf("stored-response ceiling must hold at least one maximum response")
	}
	return nil
}

type TargetBinding struct {
	alias            string
	reference        string
	fixtureRef       string
	scheme           string
	host             string
	port             uint16
	allowedAddresses []netip.Addr
}

type TargetBindingInput struct {
	Alias            string
	Reference        string
	FixtureRef       string
	Scheme           string
	Host             string
	Port             uint16
	AllowedAddresses []netip.Addr
}

func NewTargetBinding(in TargetBindingInput) (TargetBinding, error) {
	if _, err := groundtruth.NewTarget(groundtruth.TargetInput{
		Alias: in.Alias, Reference: in.Reference, FixtureRef: in.FixtureRef,
	}); err != nil {
		return TargetBinding{}, fmt.Errorf("ground-truth target: %w", err)
	}
	if in.Scheme != "http" && in.Scheme != "https" {
		return TargetBinding{}, fmt.Errorf("target scheme must be http or https")
	}
	if err := validateHost(in.Host); err != nil {
		return TargetBinding{}, err
	}
	if in.Port == 0 {
		return TargetBinding{}, fmt.Errorf("target port is required")
	}
	if len(in.AllowedAddresses) == 0 || len(in.AllowedAddresses) > maximumResolvedAddresses {
		return TargetBinding{}, fmt.Errorf("target must bind between 1 and %d addresses", maximumResolvedAddresses)
	}
	addresses := make([]netip.Addr, 0, len(in.AllowedAddresses))
	for _, address := range in.AllowedAddresses {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() ||
			(!address.IsPrivate() && !address.IsLoopback()) {
			return TargetBinding{}, fmt.Errorf("target address must be an exact private or loopback laboratory address")
		}
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	for index := 1; index < len(addresses); index++ {
		if addresses[index] == addresses[index-1] {
			return TargetBinding{}, fmt.Errorf("target contains duplicate allowed address")
		}
	}
	if literal, err := netip.ParseAddr(in.Host); err == nil {
		literal = literal.Unmap()
		if len(addresses) != 1 || addresses[0] != literal {
			return TargetBinding{}, fmt.Errorf("literal target host must exactly equal its sole allowed address")
		}
	}
	return TargetBinding{
		alias: in.Alias, reference: in.Reference, fixtureRef: in.FixtureRef,
		scheme: in.Scheme, host: in.Host, port: in.Port, allowedAddresses: addresses,
	}, nil
}

func validateHost(host string) error {
	if host == "" || len(host) > 253 || strings.TrimSpace(host) != host || strings.HasSuffix(host, ".") {
		return fmt.Errorf("target host must be a non-empty canonical hostname or address")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("target host must use canonical lower-case DNS labels")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return fmt.Errorf("target host must use canonical lower-case DNS labels")
			}
		}
	}
	return nil
}

type PayloadFixture struct {
	reference        string
	targetFixtureRef string
	contentType      string
	body             []byte
}

type PayloadFixtureInput struct {
	Reference        string
	TargetFixtureRef string
	ContentType      string
	Body             []byte
}

func NewPayloadFixture(in PayloadFixtureInput) (PayloadFixture, error) {
	if !validOpaqueReference(in.Reference, "fixture:sha256:") || !validOpaqueReference(in.TargetFixtureRef, "fixture:sha256:") {
		return PayloadFixture{}, fmt.Errorf("payload and target fixture references must be canonical opaque fixture references")
	}
	switch in.ContentType {
	case "application/json", "application/x-www-form-urlencoded", "text/plain":
	default:
		return PayloadFixture{}, fmt.Errorf("payload content type is not in the closed catalog")
	}
	if len(in.Body) == 0 || len(in.Body) > AbsoluteMaxRequestBytes {
		return PayloadFixture{}, fmt.Errorf("payload body must be between 1 and %d bytes", AbsoluteMaxRequestBytes)
	}
	return PayloadFixture{
		reference: in.Reference, targetFixtureRef: in.TargetFixtureRef,
		contentType: in.ContentType, body: append([]byte(nil), in.Body...),
	}, nil
}

type CredentialKind string

const (
	CredentialBasic  CredentialKind = "BASIC"
	CredentialBearer CredentialKind = "BEARER"
)

type CredentialFixture struct {
	reference        string
	targetFixtureRef string
	kind             CredentialKind
	username         string
	secret           []byte
}

type CredentialFixtureInput struct {
	Reference        string
	TargetFixtureRef string
	Kind             CredentialKind
	Username         string
	Secret           []byte
}

func NewCredentialFixture(in CredentialFixtureInput) (CredentialFixture, error) {
	if !validOpaqueReference(in.Reference, "fixture:sha256:") || !validOpaqueReference(in.TargetFixtureRef, "fixture:sha256:") {
		return CredentialFixture{}, fmt.Errorf("credential and target fixture references must be canonical opaque fixture references")
	}
	if len(in.Secret) == 0 || len(in.Secret) > AbsoluteMaxRequestBytes {
		return CredentialFixture{}, fmt.Errorf("credential secret must be present and bounded")
	}
	switch in.Kind {
	case CredentialBasic:
		if in.Username == "" || len(in.Username) > 256 || strings.ContainsAny(in.Username, ":\r\n") {
			return CredentialFixture{}, fmt.Errorf("basic credential username is invalid")
		}
	case CredentialBearer:
		if in.Username != "" {
			return CredentialFixture{}, fmt.Errorf("bearer credential cannot carry a username")
		}
	default:
		return CredentialFixture{}, fmt.Errorf("credential kind is not in the closed catalog")
	}
	return CredentialFixture{
		reference: in.Reference, targetFixtureRef: in.TargetFixtureRef, kind: in.Kind,
		username: in.Username, secret: append([]byte(nil), in.Secret...),
	}, nil
}

type Operation struct {
	action           groundtruth.ActionSpec
	httpMethod       string
	path             string
	enumerationPaths []string
	dnsQueryType     string
	tcpPort          uint16
	sourceOrdinal    uint32
	linkIndex        uint32
}

type OperationInput struct {
	Action           groundtruth.ActionSpec
	HTTPMethod       string
	Path             string
	EnumerationPaths []string
	DNSQueryType     string
	TCPPort          uint16
	SourceOrdinal    uint32
	LinkIndex        uint32
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Result struct {
	Status        groundtruth.ActionStatus
	ErrorCode     string
	HTTPStatus    uint16
	ResponseBytes uint64
	ResponseRef   string
	Content       []byte
}

func validOpaqueReference(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
