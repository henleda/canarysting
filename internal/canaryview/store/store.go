package store

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
	ErrNotFound             = errors.New("observation not found")
	ErrDuplicate            = errors.New("observation already exists")
	ErrCapacity             = errors.New("scope observation capacity reached")
	ErrBound                = errors.New("requested operation exceeds configured bound")
	ErrLifecycleUnavailable = errors.New("observation is unavailable to ordinary queries")
	ErrSynthetic            = errors.New("synthetic observation rejected from production store")
	ErrModelUseDenied       = errors.New("observation is not authorized for per-tenant model use")
)

const maximumConfiguredBound = 1 << 20

// Limits are hard resource bounds for one store instance. QueryResults must be
// at least ObservationsPerScope so lifecycle propagation can return a complete,
// bounded affected set instead of silently truncating it.
type Limits struct {
	ObservationsPerScope int
	QueryResults         int
	JoinRecords          int
}

func (l Limits) validate() error {
	for name, value := range map[string]int{
		"observations per scope": l.ObservationsPerScope,
		"query results":          l.QueryResults,
		"join records":           l.JoinRecords,
	} {
		if value <= 0 || value > maximumConfiguredBound {
			return fmt.Errorf("%s must be between 1 and %d", name, maximumConfiguredBound)
		}
	}
	if l.QueryResults < l.ObservationsPerScope {
		return fmt.Errorf("query results must cover the bounded per-scope collection")
	}
	if l.JoinRecords > l.QueryResults {
		return fmt.Errorf("join records cannot exceed query results")
	}
	return nil
}

// LifecycleDisposition is the ordinary-query result of the immutable
// lifecycle metadata at a given trusted time. RequiresInvalidation means a
// later lifecycle service must delete/invalidate protected copies and derived
// projections; this in-memory seam does not claim that work completed.
type LifecycleDisposition struct {
	Queryable            bool
	RequiresInvalidation bool
	EffectiveState       model.LifecycleState
}

// EvaluateLifecycle keeps expiry, hold, deletion, and invalidation distinct.
func EvaluateLifecycle(observation model.Observation, now time.Time) (LifecycleDisposition, error) {
	if now.IsZero() {
		return LifecycleDisposition{}, fmt.Errorf("lifecycle evaluation time is required")
	}
	lifecycle := observation.Envelope().Lifecycle()
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

type scopeKey struct {
	tenantID           string
	scopeID            string
	deploymentBoundary string
	residencyCellID    string
}

func keyFor(scope model.Scope) (scopeKey, error) {
	validated, err := model.NewScope(scope.TenantID(), scope.ScopeID(), scope.DeploymentBoundary(), scope.ResidencyCellID())
	if err != nil {
		return scopeKey{}, fmt.Errorf("scope: %w", err)
	}
	return scopeKey{
		tenantID: validated.TenantID(), scopeID: validated.ScopeID(),
		deploymentBoundary: validated.DeploymentBoundary(), residencyCellID: validated.ResidencyCellID(),
	}, nil
}

// ProductionObservationStore is a concurrency-safe proof seam. Synthetic and
// non-queryable records fail before they can consume production capacity.
type ProductionObservationStore struct {
	mu      sync.RWMutex
	limits  Limits
	now     func() time.Time
	byScope map[scopeKey]map[string]model.Observation
}

func NewProductionObservationStore(limits Limits, now func() time.Time) (*ProductionObservationStore, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if now == nil {
		return nil, fmt.Errorf("trusted clock is required")
	}
	return &ProductionObservationStore{
		limits: limits, now: now, byScope: make(map[scopeKey]map[string]model.Observation),
	}, nil
}

// Put validates and canonicalizes an immutable production observation before
// adding it. The same record ID may exist in different scopes; no global index
// is consulted by reads or joins.
func (s *ProductionObservationStore) Put(observation model.Observation) error {
	blob, err := model.MarshalObservationV3(observation)
	if err != nil {
		return fmt.Errorf("validate observation: %w", err)
	}
	canonical, err := model.UnmarshalObservationV3(blob)
	if err != nil {
		return fmt.Errorf("canonicalize observation: %w", err)
	}
	if canonical.Envelope().Synthetic().Synthetic() {
		return ErrSynthetic
	}
	disposition, err := EvaluateLifecycle(canonical, s.now())
	if err != nil {
		return err
	}
	if !disposition.Queryable {
		return fmt.Errorf("%w: %s", ErrLifecycleUnavailable, disposition.EffectiveState)
	}
	key, err := keyFor(canonical.Envelope().Scope())
	if err != nil {
		return err
	}
	id := canonical.Envelope().RecordID()

	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.byScope[key]
	if records == nil {
		records = make(map[string]model.Observation)
		s.byScope[key] = records
	}
	if _, exists := records[id]; exists {
		return ErrDuplicate
	}
	if len(records) >= s.limits.ObservationsPerScope {
		return ErrCapacity
	}
	records[id] = canonical
	return nil
}

func (s *ProductionObservationStore) Get(scope model.Scope, recordID string) (model.Observation, error) {
	key, err := keyFor(scope)
	if err != nil {
		return model.Observation{}, err
	}
	if recordID == "" || strings.TrimSpace(recordID) != recordID {
		return model.Observation{}, fmt.Errorf("record id is required and must not have surrounding whitespace")
	}

	s.mu.RLock()
	observation, ok := s.byScope[key][recordID]
	s.mu.RUnlock()
	if !ok {
		return model.Observation{}, ErrNotFound
	}
	disposition, err := EvaluateLifecycle(observation, s.now())
	if err != nil || !disposition.Queryable {
		return model.Observation{}, ErrNotFound
	}
	return observation, nil
}

// Query returns at most limit records in deterministic observed-time/ID order.
// It can inspect exactly one complete scope and never falls back to a global
// scope. Expired records disappear from ordinary reads even before a later
// backend performs physical deletion.
func (s *ProductionObservationStore) Query(scope model.Scope, limit int) ([]model.Observation, error) {
	if limit <= 0 || limit > s.limits.QueryResults {
		return nil, ErrBound
	}
	key, err := keyFor(scope)
	if err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.RLock()
	result := make([]model.Observation, 0, len(s.byScope[key]))
	for _, observation := range s.byScope[key] {
		disposition, dispositionErr := EvaluateLifecycle(observation, now)
		if dispositionErr == nil && disposition.Queryable {
			result = append(result, observation)
		}
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i].ObservedTimestamp(), result[j].ObservedTimestamp()
		if left.Equal(right) {
			return result[i].Envelope().RecordID() < result[j].Envelope().RecordID()
		}
		return left.Before(right)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// Join is all-or-nothing. A missing record—including one that exists in a
// different scope—returns ErrNotFound with no partial result.
func (s *ProductionObservationStore) Join(scope model.Scope, recordIDs []string) ([]model.Observation, error) {
	if len(recordIDs) == 0 || len(recordIDs) > s.limits.JoinRecords {
		return nil, ErrBound
	}
	key, err := keyFor(scope)
	if err != nil {
		return nil, err
	}
	now := s.now()
	seen := make(map[string]struct{}, len(recordIDs))
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.Observation, 0, len(recordIDs))
	for _, id := range recordIDs {
		if id == "" || strings.TrimSpace(id) != id {
			return nil, ErrNotFound
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("duplicate join record id %q", id)
		}
		seen[id] = struct{}{}
		observation, ok := s.byScope[key][id]
		if !ok {
			return nil, ErrNotFound
		}
		disposition, dispositionErr := EvaluateLifecycle(observation, now)
		if dispositionErr != nil || !disposition.Queryable {
			return nil, ErrNotFound
		}
		result = append(result, observation)
	}
	return result, nil
}

// AffectedBy returns the complete bounded set of ordinary-query observations
// whose envelope directly names parent. A lifecycle service can use this set
// to schedule derived invalidation without scanning another tenant or scope.
func (s *ProductionObservationStore) AffectedBy(scope model.Scope, parent model.RecordReference) ([]model.Observation, error) {
	if parent.ID() == "" || parent.SchemaVersion() == 0 {
		return nil, fmt.Errorf("valid parent reference is required")
	}
	key, err := keyFor(scope)
	if err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.RLock()
	result := make([]model.Observation, 0)
	for _, observation := range s.byScope[key] {
		disposition, dispositionErr := EvaluateLifecycle(observation, now)
		if dispositionErr != nil || !disposition.Queryable {
			continue
		}
		for _, reference := range observation.Envelope().DerivationLineage() {
			if reference.ID() == parent.ID() && reference.SchemaVersion() == parent.SchemaVersion() {
				result = append(result, observation)
				break
			}
		}
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		return result[i].Envelope().RecordID() < result[j].Envelope().RecordID()
	})
	return result, nil
}

// PerTenantBaselineInputs is an explicit model-use gate. Operationally retained
// records do not become baseline inputs unless every record carries the exact
// allowed per-tenant policy. Cross-tenant authority cannot substitute for it.
func (s *ProductionObservationStore) PerTenantBaselineInputs(scope model.Scope, recordIDs []string, policyRef string) ([]model.Observation, error) {
	if policyRef == "" || strings.TrimSpace(policyRef) != policyRef {
		return nil, fmt.Errorf("per-tenant model-use policy reference is required")
	}
	observations, err := s.Join(scope, recordIDs)
	if err != nil {
		return nil, err
	}
	for _, observation := range observations {
		grant := observation.Envelope().Lifecycle().PerTenantModelUse()
		if !grant.Allowed() || grant.PolicyRef() != policyRef || observation.Envelope().Synthetic().Synthetic() {
			return nil, ErrModelUseDenied
		}
	}
	return observations, nil
}
