package trace

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/model"
)

var (
	ErrNotFound             = errors.New("trace not found")
	ErrDuplicate            = errors.New("trace already exists")
	ErrCapacity             = errors.New("scope trace capacity reached")
	ErrBound                = errors.New("requested operation exceeds configured bound")
	ErrLifecycleUnavailable = errors.New("trace is unavailable to ordinary queries")
	ErrSynthetic            = errors.New("synthetic trace rejected from production store")
	ErrProduction           = errors.New("production trace rejected from synthetic store")
	ErrInvalidationReason   = errors.New("unsupported trace invalidation reason")
)

// StoreLimits are hard resource bounds for the in-memory proof seam.
// InvalidationResults covers a complete per-scope collection so propagation is
// all-or-nothing and never silently truncated.
type StoreLimits struct {
	TracesPerScope      int
	QueryResults        int
	InvalidationResults int
}

func (l StoreLimits) validate() error {
	for label, value := range map[string]int{
		"traces per scope":     l.TracesPerScope,
		"query results":        l.QueryResults,
		"invalidation results": l.InvalidationResults,
	} {
		if value <= 0 || value > maximumConfiguredBound {
			return fmt.Errorf("%s must be between 1 and %d", label, maximumConfiguredBound)
		}
	}
	if l.QueryResults > l.TracesPerScope {
		return fmt.Errorf("query results cannot exceed traces per scope")
	}
	if l.InvalidationResults < l.TracesPerScope {
		return fmt.Errorf("invalidation results must cover the bounded per-scope collection")
	}
	return nil
}

// LifecycleDisposition is the ordinary-query interpretation of immutable
// lifecycle metadata at a trusted time. Physical deletion is deliberately
// outside this proof seam.
type LifecycleDisposition struct {
	Queryable            bool
	RequiresInvalidation bool
	EffectiveState       model.LifecycleState
}

func EvaluateLifecycle(value Trace, now time.Time) (LifecycleDisposition, error) {
	if now.IsZero() {
		return LifecycleDisposition{}, fmt.Errorf("lifecycle evaluation time is required")
	}
	lifecycle := value.envelope.Lifecycle()
	switch lifecycle.State() {
	case model.LifecycleActive:
		if !now.UTC().Before(lifecycle.ExpiresAt()) {
			return LifecycleDisposition{RequiresInvalidation: true, EffectiveState: model.LifecycleExpiryDue}, nil
		}
		return LifecycleDisposition{Queryable: true, EffectiveState: model.LifecycleActive}, nil
	case model.LifecycleHeld:
		return LifecycleDisposition{Queryable: true, EffectiveState: model.LifecycleHeld}, nil
	case model.LifecycleExpiryDue, model.LifecycleDeletionPending, model.LifecycleDeletionFailed:
		return LifecycleDisposition{RequiresInvalidation: true, EffectiveState: lifecycle.State()}, nil
	case model.LifecycleDeleted, model.LifecycleInvalidated:
		return LifecycleDisposition{EffectiveState: lifecycle.State()}, nil
	default:
		return LifecycleDisposition{}, fmt.Errorf("unsupported lifecycle state %q", lifecycle.State())
	}
}

type InvalidationReason string

const (
	InvalidationParentExpired     InvalidationReason = "PARENT_EXPIRED"
	InvalidationParentDeleted     InvalidationReason = "PARENT_DELETED"
	InvalidationParentInvalidated InvalidationReason = "PARENT_INVALIDATED"
)

func (r InvalidationReason) valid() bool {
	return r == InvalidationParentExpired || r == InvalidationParentDeleted || r == InvalidationParentInvalidated
}

// Invalidation is an immutable audit result. The source record and the trace
// remain distinct; this marks only the derived projection unavailable.
type Invalidation struct {
	trace       model.RecordReference
	parent      model.RecordReference
	reason      InvalidationReason
	invalidated time.Time
}

func (i Invalidation) Trace() model.RecordReference  { return i.trace }
func (i Invalidation) Parent() model.RecordReference { return i.parent }
func (i Invalidation) Reason() InvalidationReason    { return i.reason }
func (i Invalidation) InvalidatedAt() time.Time      { return i.invalidated }

type scopeKey struct {
	tenantID           string
	scopeID            string
	deploymentBoundary string
	residencyCellID    string
}

func keyFor(scope model.Scope) (scopeKey, error) {
	canonical, err := model.NewScope(scope.TenantID(), scope.ScopeID(), scope.DeploymentBoundary(), scope.ResidencyCellID())
	if err != nil {
		return scopeKey{}, fmt.Errorf("scope: %w", err)
	}
	return scopeKey{
		tenantID: canonical.TenantID(), scopeID: canonical.ScopeID(),
		deploymentBoundary: canonical.DeploymentBoundary(), residencyCellID: canonical.ResidencyCellID(),
	}, nil
}

// ProductionStore is a bounded, concurrency-safe projection proof seam. It is
// not a selected durable backend or a physical lifecycle service.
type ProductionStore struct {
	mu          sync.RWMutex
	limits      StoreLimits
	now         func() time.Time
	byScope     map[scopeKey]map[string]Trace
	invalidated map[scopeKey]map[string]Invalidation
}

func NewProductionStore(limits StoreLimits, now func() time.Time) (*ProductionStore, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if now == nil {
		return nil, fmt.Errorf("trusted clock is required")
	}
	return &ProductionStore{
		limits: limits, now: now, byScope: make(map[scopeKey]map[string]Trace),
		invalidated: make(map[scopeKey]map[string]Invalidation),
	}, nil
}

func (s *ProductionStore) Put(value Trace) error {
	if err := value.validate(); err != nil {
		return fmt.Errorf("validate trace: %w", err)
	}
	if value.envelope.Synthetic().Synthetic() {
		return ErrSynthetic
	}
	return s.putValidated(value)
}

// SyntheticStore is a separate in-memory laboratory namespace. It accepts
// exactly one scenario and cannot be substituted for the production store.
type SyntheticStore struct {
	*ProductionStore
	scenarioID string
}

func NewSyntheticStore(limits StoreLimits, scenarioID string, now func() time.Time) (*SyntheticStore, error) {
	synthetic, err := model.NewSyntheticContext(scenarioID)
	if err != nil {
		return nil, err
	}
	store, err := NewProductionStore(limits, now)
	if err != nil {
		return nil, err
	}
	return &SyntheticStore{ProductionStore: store, scenarioID: synthetic.ScenarioID()}, nil
}

func (s *SyntheticStore) Put(value Trace) error {
	if s == nil || s.ProductionStore == nil {
		return fmt.Errorf("synthetic trace store is required")
	}
	if err := value.validate(); err != nil {
		return fmt.Errorf("validate trace: %w", err)
	}
	context := value.envelope.Synthetic()
	if !context.Synthetic() || context.ScenarioID() != s.scenarioID {
		return ErrProduction
	}
	return s.putValidated(value)
}

func (s *ProductionStore) putValidated(value Trace) error {
	disposition, err := EvaluateLifecycle(value, s.now())
	if err != nil {
		return err
	}
	if !disposition.Queryable {
		return fmt.Errorf("%w: %s", ErrLifecycleUnavailable, disposition.EffectiveState)
	}
	key, err := keyFor(value.envelope.Scope())
	if err != nil {
		return err
	}
	id := value.envelope.RecordID()

	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.byScope[key]
	if records == nil {
		records = make(map[string]Trace)
		s.byScope[key] = records
	}
	if _, exists := records[id]; exists {
		return ErrDuplicate
	}
	if len(records) >= s.limits.TracesPerScope {
		return ErrCapacity
	}
	records[id] = value
	return nil
}

func (s *ProductionStore) Get(scope model.Scope, recordID string) (Trace, error) {
	key, err := keyFor(scope)
	if err != nil {
		return Trace{}, err
	}
	if recordID == "" || strings.TrimSpace(recordID) != recordID {
		return Trace{}, fmt.Errorf("record id is required and must not have surrounding whitespace")
	}
	s.mu.RLock()
	value, ok := s.byScope[key][recordID]
	_, invalidated := s.invalidated[key][recordID]
	s.mu.RUnlock()
	if !ok || invalidated || !queryable(value, s.now()) {
		return Trace{}, ErrNotFound
	}
	return value, nil
}

// Query inspects exactly one complete scope and orders results by trace close
// time and record ID. Expired and invalidated projections are not visible.
func (s *ProductionStore) Query(scope model.Scope, limit int) ([]Trace, error) {
	if limit <= 0 || limit > s.limits.QueryResults {
		return nil, ErrBound
	}
	key, err := keyFor(scope)
	if err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.RLock()
	result := make([]Trace, 0, len(s.byScope[key]))
	for id, value := range s.byScope[key] {
		if _, invalidated := s.invalidated[key][id]; !invalidated && queryable(value, now) {
			result = append(result, value)
		}
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].closedAt.Equal(result[j].closedAt) {
			return result[i].envelope.RecordID() < result[j].envelope.RecordID()
		}
		return result[i].closedAt.Before(result[j].closedAt)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// AffectedBy returns the complete, bounded set of currently queryable traces
// that directly cite parent. It never scans or reveals another scope.
func (s *ProductionStore) AffectedBy(scope model.Scope, parent model.RecordReference) ([]Trace, error) {
	if err := validateReference(parent); err != nil {
		return nil, fmt.Errorf("parent: %w", err)
	}
	key, err := keyFor(scope)
	if err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.RLock()
	result := make([]Trace, 0)
	for id, value := range s.byScope[key] {
		if _, invalidated := s.invalidated[key][id]; invalidated || !queryable(value, now) {
			continue
		}
		if containsReference(value.envelope.DerivationLineage(), parent) {
			result = append(result, value)
		}
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].envelope.RecordID() < result[j].envelope.RecordID() })
	return result, nil
}

// InvalidateBy marks every exact-scope projection that directly cites parent.
// It includes expired and held projections because provenance invalidation is
// independent of ordinary-query visibility and retention hold status.
func (s *ProductionStore) InvalidateBy(scope model.Scope, parent model.RecordReference, reason InvalidationReason, at time.Time) ([]Invalidation, error) {
	if err := validateReference(parent); err != nil {
		return nil, fmt.Errorf("parent: %w", err)
	}
	if !reason.valid() {
		return nil, ErrInvalidationReason
	}
	if at.IsZero() {
		return nil, fmt.Errorf("invalidation time is required")
	}
	key, err := keyFor(scope)
	if err != nil {
		return nil, err
	}
	at = at.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	matching := make([]Trace, 0)
	for id, value := range s.byScope[key] {
		if _, done := s.invalidated[key][id]; done {
			continue
		}
		if containsReference(value.envelope.DerivationLineage(), parent) {
			matching = append(matching, value)
		}
	}
	if len(matching) > s.limits.InvalidationResults {
		return nil, ErrBound
	}
	if s.invalidated[key] == nil {
		s.invalidated[key] = make(map[string]Invalidation)
	}
	result := make([]Invalidation, 0, len(matching))
	for _, value := range matching {
		traceRef, refErr := model.NewRecordReference(value.envelope.RecordID(), value.envelope.SchemaVersion())
		if refErr != nil {
			return nil, refErr
		}
		invalidation := Invalidation{trace: traceRef, parent: parent, reason: reason, invalidated: at}
		s.invalidated[key][value.envelope.RecordID()] = invalidation
		result = append(result, invalidation)
	}
	sort.Slice(result, func(i, j int) bool { return referenceKey(result[i].trace) < referenceKey(result[j].trace) })
	return result, nil
}

func queryable(value Trace, now time.Time) bool {
	disposition, err := EvaluateLifecycle(value, now)
	return err == nil && disposition.Queryable
}
