package correlation

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/model"
)

const (
	maximumTextBytes   = 256
	maximumKeysPerKind = 16
)

// Strength deliberately separates deterministic identifier equality from
// strong contextual evidence and weak time-window evidence. It is not a
// probability and must not be treated as one.
type Strength string

const (
	StrengthExact  Strength = "EXACT"
	StrengthStrong Strength = "STRONG"
	StrengthWeak   Strength = "WEAK"
)

func strengthRank(value Strength) int {
	switch value {
	case StrengthExact:
		return 3
	case StrengthStrong:
		return 2
	case StrengthWeak:
		return 1
	default:
		return 0
	}
}

// JoinMethod names the evidence that linked two records. Multiple independent
// methods may support one candidate and are all retained.
type JoinMethod string

const (
	JoinSocketCookie     JoinMethod = "SOCKET_COOKIE"
	JoinRequestID        JoinMethod = "REQUEST_ID"
	JoinVendorID         JoinMethod = "VENDOR_ID"
	JoinOTelSpanID       JoinMethod = "OTEL_SPAN_ID"
	JoinOTelTraceID      JoinMethod = "OTEL_TRACE_ID"
	JoinVerifiedIdentity JoinMethod = "VERIFIED_IDENTITY"
	JoinDeclaredIdentity JoinMethod = "DECLARED_IDENTITY"
	JoinTupleTime        JoinMethod = "TUPLE_TIME_WINDOW"
	JoinTranslatedTuple  JoinMethod = "TRANSLATED_TUPLE_TIME_WINDOW"
)

// MissingKey names an absent optional correlation input. Absence is useful
// evidence and never causes the record itself to be rejected.
type MissingKey string

const (
	MissingTime         MissingKey = "TIME"
	MissingTuple        MissingKey = "TUPLE"
	MissingIdentity     MissingKey = "IDENTITY"
	MissingRequestID    MissingKey = "REQUEST_ID"
	MissingVendorID     MissingKey = "VENDOR_ID"
	MissingSocketCookie MissingKey = "SOCKET_COOKIE"
	MissingOTelTraceID  MissingKey = "OTEL_TRACE_ID"
	MissingOTelSpanID   MissingKey = "OTEL_SPAN_ID"
)

// RejectionReason explains why a considered record was not a candidate.
type RejectionReason string

const (
	RejectedNoSharedKey          RejectionReason = "NO_SHARED_KEY"
	RejectedMissingTime          RejectionReason = "MISSING_TIME_FOR_CONTEXTUAL_KEY"
	RejectedOutsideWindow        RejectionReason = "OUTSIDE_CORRELATION_WINDOW"
	RejectedNoTranslation        RejectionReason = "NO_TRANSLATION_PATH"
	RejectedSocketCookieRequired RejectionReason = "CANARYSTING_SOCKET_COOKIE_REQUIRED"
)

// Protocol is the transport component of a minimized five-tuple.
type Protocol string

const (
	ProtocolTCP Protocol = "TCP"
	ProtocolUDP Protocol = "UDP"
)

// NetworkTuple retains tuple direction and ports, but only opaque address
// digests. Constructors reject raw addresses so correlation results cannot
// accidentally become a new raw-network-data carrier.
type NetworkTuple struct {
	protocol            Protocol
	sourceAddressDigest string
	sourcePort          uint16
	destAddressDigest   string
	destPort            uint16
}

func NewNetworkTuple(protocol Protocol, sourceAddressDigest string, sourcePort uint16, destAddressDigest string, destPort uint16) (NetworkTuple, error) {
	if protocol != ProtocolTCP && protocol != ProtocolUDP {
		return NetworkTuple{}, fmt.Errorf("unsupported network protocol %q", protocol)
	}
	if err := validateDigest("source address", sourceAddressDigest); err != nil {
		return NetworkTuple{}, err
	}
	if err := validateDigest("destination address", destAddressDigest); err != nil {
		return NetworkTuple{}, err
	}
	if sourcePort == 0 || destPort == 0 {
		return NetworkTuple{}, fmt.Errorf("network tuple ports must be nonzero")
	}
	return NetworkTuple{
		protocol: protocol, sourceAddressDigest: sourceAddressDigest,
		sourcePort: sourcePort, destAddressDigest: destAddressDigest, destPort: destPort,
	}, nil
}

func (t NetworkTuple) Protocol() Protocol               { return t.protocol }
func (t NetworkTuple) SourceAddressDigest() string      { return t.sourceAddressDigest }
func (t NetworkTuple) SourcePort() uint16               { return t.sourcePort }
func (t NetworkTuple) DestinationAddressDigest() string { return t.destAddressDigest }
func (t NetworkTuple) DestinationPort() uint16          { return t.destPort }

func (t NetworkTuple) validate() error {
	_, err := NewNetworkTuple(t.protocol, t.sourceAddressDigest, t.sourcePort, t.destAddressDigest, t.destPort)
	return err
}

// OpaqueID is a source-namespace-bound digest of a request or vendor ID. The
// namespace prevents identical source-native values from colliding across
// unrelated ID domains.
type OpaqueID struct {
	namespace string
	digest    string
}

func NewOpaqueID(namespace, digest string) (OpaqueID, error) {
	if err := boundedRequired("opaque ID namespace", namespace); err != nil {
		return OpaqueID{}, err
	}
	if err := validateDigest("opaque ID", digest); err != nil {
		return OpaqueID{}, err
	}
	return OpaqueID{namespace: namespace, digest: digest}, nil
}

func (id OpaqueID) Namespace() string { return id.namespace }
func (id OpaqueID) Digest() string    { return id.digest }

func (id OpaqueID) validate() error {
	_, err := NewOpaqueID(id.namespace, id.digest)
	return err
}

// SocketVantage prevents a general vendor identifier from masquerading as the
// CanarySting socket-cookie join.
type SocketVantage string

const (
	SocketVantageL7     SocketVantage = "CANARYSTING_L7"
	SocketVantageKernel SocketVantage = "CANARYSTING_KERNEL"
	SocketVantageEngine SocketVantage = "CANARYSTING_ENGINE"
)

type SocketCookieKey struct {
	digest  string
	vantage SocketVantage
}

func NewSocketCookieKey(digest string, vantage SocketVantage) (SocketCookieKey, error) {
	if err := validateDigest("socket cookie", digest); err != nil {
		return SocketCookieKey{}, err
	}
	switch vantage {
	case SocketVantageL7, SocketVantageKernel, SocketVantageEngine:
	default:
		return SocketCookieKey{}, fmt.Errorf("unsupported socket-cookie vantage %q", vantage)
	}
	return SocketCookieKey{digest: digest, vantage: vantage}, nil
}

func (k SocketCookieKey) Digest() string         { return k.digest }
func (k SocketCookieKey) Vantage() SocketVantage { return k.vantage }
func (k SocketCookieKey) validate() error {
	_, err := NewSocketCookieKey(k.digest, k.vantage)
	return err
}

// SourceVantage is mandatory so a CanarySting kernel record cannot silently
// masquerade as a general source and fall back to a tuple or request-ID join.
type SourceVantage string

const (
	SourceVantageGeneral     SourceVantage = "GENERAL_SOURCE"
	SourceVantageStingL7     SourceVantage = "CANARYSTING_L7"
	SourceVantageStingKernel SourceVantage = "CANARYSTING_KERNEL"
	SourceVantageStingEngine SourceVantage = "CANARYSTING_ENGINE"
)

func (v SourceVantage) valid() bool {
	switch v {
	case SourceVantageGeneral, SourceVantageStingL7, SourceVantageStingKernel, SourceVantageStingEngine:
		return true
	default:
		return false
	}
}

// OTelKey keeps OpenTelemetry IDs structurally typed. Trace-only evidence is
// allowed; a span ID cannot exist without its trace ID.
type OTelKey struct {
	traceID string
	spanID  string
}

func NewOTelKey(traceID, spanID string) (OTelKey, error) {
	if err := validateHexLength("OpenTelemetry trace ID", traceID, 16); err != nil {
		return OTelKey{}, err
	}
	if spanID != "" {
		if err := validateHexLength("OpenTelemetry span ID", spanID, 8); err != nil {
			return OTelKey{}, err
		}
	}
	return OTelKey{traceID: traceID, spanID: spanID}, nil
}

func (k OTelKey) TraceID() string { return k.traceID }
func (k OTelKey) SpanID() string  { return k.spanID }

func (k OTelKey) validate() error {
	_, err := NewOTelKey(k.traceID, k.spanID)
	return err
}

// EventTime is an immutable event-time estimate. Uncertainty expands the
// interval around At and is used explicitly by the configured window policy.
type EventTime struct {
	at          time.Time
	uncertainty time.Duration
}

func NewEventTime(at time.Time, uncertainty time.Duration) (EventTime, error) {
	if at.IsZero() {
		return EventTime{}, fmt.Errorf("event time is required")
	}
	if uncertainty < 0 {
		return EventTime{}, fmt.Errorf("event-time uncertainty cannot be negative")
	}
	return EventTime{at: at.UTC(), uncertainty: uncertainty}, nil
}

func (t EventTime) At() time.Time              { return t.at }
func (t EventTime) Uncertainty() time.Duration { return t.uncertainty }

func (t EventTime) validate() error {
	_, err := NewEventTime(t.at, t.uncertainty)
	return err
}

type RecordInput struct {
	Reference    model.RecordReference
	Scope        model.Scope
	Vantage      SourceVantage
	Time         *EventTime
	Tuple        *NetworkTuple
	Identities   []model.EntityReference
	RequestIDs   []OpaqueID
	VendorIDs    []OpaqueID
	SocketCookie *SocketCookieKey
	OTel         *OTelKey
}

// Record is an immutable candidate input assembled by source-specific code.
// It is not a durable canonical record and carries no payload or raw address.
type Record struct {
	reference    model.RecordReference
	scope        model.Scope
	vantage      SourceVantage
	eventTime    *EventTime
	tuple        *NetworkTuple
	identities   []model.EntityReference
	requestIDs   []OpaqueID
	vendorIDs    []OpaqueID
	socketCookie *SocketCookieKey
	otel         *OTelKey
}

func NewRecord(in RecordInput) (Record, error) {
	if err := validateRecordReference(in.Reference); err != nil {
		return Record{}, fmt.Errorf("record reference: %w", err)
	}
	if err := validateScope(in.Scope); err != nil {
		return Record{}, fmt.Errorf("record scope: %w", err)
	}
	if !in.Vantage.valid() {
		return Record{}, fmt.Errorf("unsupported source vantage %q", in.Vantage)
	}
	eventTime, err := copyOptional(in.Time, func(value EventTime) error { return value.validate() })
	if err != nil {
		return Record{}, err
	}
	tuple, err := copyOptional(in.Tuple, func(value NetworkTuple) error { return value.validate() })
	if err != nil {
		return Record{}, err
	}
	identities, err := sortedIdentities(in.Identities)
	if err != nil {
		return Record{}, err
	}
	requestIDs, err := sortedOpaqueIDs("request IDs", in.RequestIDs)
	if err != nil {
		return Record{}, err
	}
	vendorIDs, err := sortedOpaqueIDs("vendor IDs", in.VendorIDs)
	if err != nil {
		return Record{}, err
	}
	socketCookie, err := copyOptional(in.SocketCookie, func(value SocketCookieKey) error { return value.validate() })
	if err != nil {
		return Record{}, err
	}
	if socketCookie != nil {
		want := socketVantageForSource(in.Vantage)
		if want == "" {
			return Record{}, fmt.Errorf("general source cannot carry a CanarySting socket-cookie key")
		}
		if socketCookie.vantage != want {
			return Record{}, fmt.Errorf("socket-cookie vantage %q does not match source vantage %q", socketCookie.vantage, in.Vantage)
		}
	}
	otel, err := copyOptional(in.OTel, func(value OTelKey) error { return value.validate() })
	if err != nil {
		return Record{}, err
	}
	return Record{
		reference: in.Reference, scope: in.Scope, vantage: in.Vantage, eventTime: eventTime, tuple: tuple,
		identities: identities, requestIDs: requestIDs, vendorIDs: vendorIDs,
		socketCookie: socketCookie, otel: otel,
	}, nil
}

func (r Record) Reference() model.RecordReference { return r.reference }
func (r Record) Scope() model.Scope               { return r.scope }
func (r Record) Vantage() SourceVantage           { return r.vantage }
func (r Record) Time() (EventTime, bool)          { return valueOptional(r.eventTime) }
func (r Record) Tuple() (NetworkTuple, bool)      { return valueOptional(r.tuple) }
func (r Record) Identities() []model.EntityReference {
	return append([]model.EntityReference(nil), r.identities...)
}
func (r Record) RequestIDs() []OpaqueID                { return append([]OpaqueID(nil), r.requestIDs...) }
func (r Record) VendorIDs() []OpaqueID                 { return append([]OpaqueID(nil), r.vendorIDs...) }
func (r Record) SocketCookie() (SocketCookieKey, bool) { return valueOptional(r.socketCookie) }
func (r Record) OTel() (OTelKey, bool)                 { return valueOptional(r.otel) }

func (r Record) validate() error {
	_, err := NewRecord(RecordInput{
		Reference: r.reference, Scope: r.scope, Vantage: r.vantage, Time: r.eventTime, Tuple: r.tuple,
		Identities: r.identities, RequestIDs: r.requestIDs, VendorIDs: r.vendorIDs,
		SocketCookie: r.socketCookie, OTel: r.otel,
	})
	return err
}

func socketVantageForSource(vantage SourceVantage) SocketVantage {
	switch vantage {
	case SourceVantageStingL7:
		return SocketVantageL7
	case SourceVantageStingKernel:
		return SocketVantageKernel
	case SourceVantageStingEngine:
		return SocketVantageEngine
	default:
		return ""
	}
}

type TranslationInput struct {
	Reference  model.RecordReference
	Scope      model.Scope
	Before     NetworkTuple
	After      NetworkTuple
	Control    model.ControlIdentity
	ObservedAt EventTime
}

// Translation is an immutable, directed assertion by one translating control.
// Both original tuples are retained; traversal may later use either direction
// without asserting that the tuples are identical.
type Translation struct {
	reference  model.RecordReference
	scope      model.Scope
	before     NetworkTuple
	after      NetworkTuple
	control    model.ControlIdentity
	observedAt EventTime
}

func NewTranslation(in TranslationInput) (Translation, error) {
	if err := validateRecordReference(in.Reference); err != nil {
		return Translation{}, fmt.Errorf("translation reference: %w", err)
	}
	if err := validateScope(in.Scope); err != nil {
		return Translation{}, fmt.Errorf("translation scope: %w", err)
	}
	if err := in.Before.validate(); err != nil {
		return Translation{}, fmt.Errorf("translation before tuple: %w", err)
	}
	if err := in.After.validate(); err != nil {
		return Translation{}, fmt.Errorf("translation after tuple: %w", err)
	}
	if in.Before == in.After {
		return Translation{}, fmt.Errorf("translation before and after tuples must differ")
	}
	if err := validateControl(in.Control); err != nil {
		return Translation{}, fmt.Errorf("translation control: %w", err)
	}
	if err := in.ObservedAt.validate(); err != nil {
		return Translation{}, fmt.Errorf("translation observed time: %w", err)
	}
	return Translation{
		reference: in.Reference, scope: in.Scope, before: in.Before,
		after: in.After, control: in.Control, observedAt: in.ObservedAt,
	}, nil
}

func (t Translation) Reference() model.RecordReference { return t.reference }
func (t Translation) Scope() model.Scope               { return t.scope }
func (t Translation) Before() NetworkTuple             { return t.before }
func (t Translation) After() NetworkTuple              { return t.after }
func (t Translation) Control() model.ControlIdentity   { return t.control }
func (t Translation) ObservedAt() EventTime            { return t.observedAt }

func (t Translation) validate() error {
	_, err := NewTranslation(TranslationInput{
		Reference: t.reference, Scope: t.scope, Before: t.before, After: t.after,
		Control: t.control, ObservedAt: t.observedAt,
	})
	return err
}

// TraversalDirection says whether a path used the control's declared mapping
// or traversed it in reverse. The retained before/after tuples never change.
type TraversalDirection string

const (
	TraversalForward TraversalDirection = "FORWARD"
	TraversalReverse TraversalDirection = "REVERSE"
)

type TranslationHop struct {
	translation Translation
	direction   TraversalDirection
}

func (h TranslationHop) Translation() Translation      { return h.translation }
func (h TranslationHop) Direction() TraversalDirection { return h.direction }

type Match struct {
	method         JoinMethod
	strength       Strength
	keyFingerprint string
	timeGap        time.Duration
	window         time.Duration
	translation    []TranslationHop
}

func (m Match) Method() JoinMethod     { return m.method }
func (m Match) Strength() Strength     { return m.strength }
func (m Match) KeyFingerprint() string { return m.keyFingerprint }
func (m Match) TimeGap() time.Duration { return m.timeGap }
func (m Match) Window() time.Duration  { return m.window }
func (m Match) TranslationPath() []TranslationHop {
	return append([]TranslationHop(nil), m.translation...)
}

type Candidate struct {
	reference     model.RecordReference
	strength      Strength
	matches       []Match
	missing       []MissingKey
	confidence    model.Confidence
	pathAmbiguous bool
}

func (c Candidate) Reference() model.RecordReference { return c.reference }
func (c Candidate) Strength() Strength               { return c.strength }
func (c Candidate) Matches() []Match                 { return append([]Match(nil), c.matches...) }
func (c Candidate) MissingKeys() []MissingKey        { return append([]MissingKey(nil), c.missing...) }
func (c Candidate) Confidence() model.Confidence     { return c.confidence }
func (c Candidate) TranslationPathAmbiguous() bool   { return c.pathAmbiguous }

type Rejection struct {
	reference model.RecordReference
	reasons   []RejectionReason
	missing   []MissingKey
}

func (r Rejection) Reference() model.RecordReference { return r.reference }
func (r Rejection) Reasons() []RejectionReason       { return append([]RejectionReason(nil), r.reasons...) }
func (r Rejection) MissingKeys() []MissingKey        { return append([]MissingKey(nil), r.missing...) }

type Result struct {
	anchor           model.RecordReference
	algorithmID      string
	algorithmVersion string
	anchorMissing    []MissingKey
	candidates       []Candidate
	rejected         []Rejection
	chosen           *Candidate
	ambiguous        bool
}

func (r Result) Anchor() model.RecordReference { return r.anchor }
func (r Result) AlgorithmID() string           { return r.algorithmID }
func (r Result) AlgorithmVersion() string      { return r.algorithmVersion }
func (r Result) AnchorMissingKeys() []MissingKey {
	return append([]MissingKey(nil), r.anchorMissing...)
}
func (r Result) Candidates() []Candidate   { return append([]Candidate(nil), r.candidates...) }
func (r Result) Rejected() []Rejection     { return append([]Rejection(nil), r.rejected...) }
func (r Result) Ambiguous() bool           { return r.ambiguous }
func (r Result) Chosen() (Candidate, bool) { return valueOptional(r.chosen) }

func missingKeys(record Record) []MissingKey {
	missing := make([]MissingKey, 0, 8)
	if record.eventTime == nil {
		missing = append(missing, MissingTime)
	}
	if record.tuple == nil {
		missing = append(missing, MissingTuple)
	}
	if len(record.identities) == 0 {
		missing = append(missing, MissingIdentity)
	}
	if len(record.requestIDs) == 0 {
		missing = append(missing, MissingRequestID)
	}
	if len(record.vendorIDs) == 0 {
		missing = append(missing, MissingVendorID)
	}
	if record.socketCookie == nil {
		missing = append(missing, MissingSocketCookie)
	}
	if record.otel == nil {
		missing = append(missing, MissingOTelTraceID, MissingOTelSpanID)
	} else if record.otel.spanID == "" {
		missing = append(missing, MissingOTelSpanID)
	}
	return missing
}

func validateRecordReference(ref model.RecordReference) error {
	_, err := model.NewRecordReference(ref.ID(), ref.SchemaVersion())
	return err
}

func validateScope(scope model.Scope) error {
	_, err := model.NewScope(scope.TenantID(), scope.ScopeID(), scope.DeploymentBoundary(), scope.ResidencyCellID())
	return err
}

func sameScope(left, right model.Scope) bool {
	return left.TenantID() == right.TenantID() &&
		left.ScopeID() == right.ScopeID() &&
		left.DeploymentBoundary() == right.DeploymentBoundary() &&
		left.ResidencyCellID() == right.ResidencyCellID()
}

func validateControl(control model.ControlIdentity) error {
	_, err := model.NewControlIdentity(control.ID(), control.Kind())
	return err
}

func sortedIdentities(values []model.EntityReference) ([]model.EntityReference, error) {
	if len(values) > maximumKeysPerKind {
		return nil, fmt.Errorf("identities exceed hard limit %d", maximumKeysPerKind)
	}
	result := append([]model.EntityReference(nil), values...)
	for _, value := range result {
		if err := boundedRequired("identity ID", value.ID()); err != nil {
			return nil, err
		}
		if err := boundedRequired("identity kind", value.Kind()); err != nil {
			return nil, err
		}
		switch value.AssertionMode() {
		case model.AssertionObserved, model.AssertionDeclared, model.AssertionVerified:
		default:
			return nil, fmt.Errorf("identity %q has unsupported assertion mode %q", value.ID(), value.AssertionMode())
		}
		if value.AssertionMode() == model.AssertionVerified {
			if _, ok := value.Verification(); !ok {
				return nil, fmt.Errorf("verified identity %q lacks verification evidence", value.ID())
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return identityKey(result[i]) < identityKey(result[j]) })
	for index := 1; index < len(result); index++ {
		if identityKey(result[index-1]) == identityKey(result[index]) {
			return nil, fmt.Errorf("duplicate identity %q", result[index].ID())
		}
	}
	return result, nil
}

func identityKey(value model.EntityReference) string {
	return value.Kind() + "\x00" + value.ID()
}

func sortedOpaqueIDs(label string, values []OpaqueID) ([]OpaqueID, error) {
	if len(values) > maximumKeysPerKind {
		return nil, fmt.Errorf("%s exceed hard limit %d", label, maximumKeysPerKind)
	}
	result := append([]OpaqueID(nil), values...)
	for _, value := range result {
		if err := value.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].namespace+"\x00"+result[i].digest < result[j].namespace+"\x00"+result[j].digest
	})
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, fmt.Errorf("duplicate %s entry in namespace %q", label, result[index].namespace)
		}
	}
	return result, nil
}

func validateDigest(label, value string) error {
	return validateHexLength(label+" digest", value, 32)
}

func validateHexLength(label, value string, byteLength int) error {
	if value != strings.ToLower(value) {
		return fmt.Errorf("%s must use lowercase hexadecimal", label)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != byteLength {
		return fmt.Errorf("%s must be %d lowercase hexadecimal characters", label, byteLength*2)
	}
	allZero := true
	for _, value := range decoded {
		if value != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("%s cannot be all zero", label)
	}
	return nil
}

func boundedRequired(label, value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is required and must not have surrounding whitespace", label)
	}
	if len(value) > maximumTextBytes {
		return fmt.Errorf("%s exceeds %d bytes", label, maximumTextBytes)
	}
	return nil
}

func copyOptional[T any](value *T, validate func(T) error) (*T, error) {
	if value == nil {
		return nil, nil
	}
	copyValue := *value
	if err := validate(copyValue); err != nil {
		return nil, err
	}
	return &copyValue, nil
}

func valueOptional[T any](value *T) (T, bool) {
	if value == nil {
		var zero T
		return zero, false
	}
	return *value, true
}
