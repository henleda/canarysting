package model

import (
	"fmt"
	"sort"
	"time"
)

// ModelUseGrant is independent of operational retention. Its zero value is an
// explicit default-off grant.
type ModelUseGrant struct {
	allowed   bool
	policyRef string
}

func NewModelUseGrant(allowed bool, policyRef string) (ModelUseGrant, error) {
	if policyRef != "" {
		if err := required("model-use policy reference", policyRef); err != nil {
			return ModelUseGrant{}, err
		}
	}
	if allowed && policyRef == "" {
		return ModelUseGrant{}, fmt.Errorf("authorized model use requires a policy reference")
	}
	return ModelUseGrant{allowed: allowed, policyRef: policyRef}, nil
}

func (g ModelUseGrant) Allowed() bool     { return g.allowed }
func (g ModelUseGrant) PolicyRef() string { return g.policyRef }

func (g ModelUseGrant) validate() error {
	_, err := NewModelUseGrant(g.allowed, g.policyRef)
	return err
}

// StorageEstimate makes each durable record's estimated storage impact
// explicit without pretending that an assumption is measured capacity.
type StorageEstimate struct {
	bytes uint64
	basis EstimateBasis
}

func NewStorageEstimate(bytes uint64, basis EstimateBasis) (StorageEstimate, error) {
	if bytes == 0 {
		return StorageEstimate{}, fmt.Errorf("storage estimate bytes must be greater than zero")
	}
	if !basis.valid() {
		return StorageEstimate{}, fmt.Errorf("unsupported storage estimate basis %q", basis)
	}
	return StorageEstimate{bytes: bytes, basis: basis}, nil
}

func (e StorageEstimate) Bytes() uint64        { return e.bytes }
func (e StorageEstimate) Basis() EstimateBasis { return e.basis }

func (e StorageEstimate) validate() error {
	_, err := NewStorageEstimate(e.bytes, e.basis)
	return err
}

// LifecycleInput is copied into an immutable Lifecycle value.
type LifecycleInput struct {
	DataClass              DataClass
	Sensitivity            Sensitivity
	RetentionProfile       RetentionProfile
	PolicyVersion          string
	RetentionDecisionRef   string
	OverrideVersion        string
	RetentionClock         RetentionClock
	RetentionStart         time.Time
	ExpiresAt              time.Time
	State                  LifecycleState
	LegalHoldIDs           []string
	ResidencyPolicyRef     string
	EncryptionKeyRef       string
	OperationalPolicyRef   string
	PerTenantModelUse      ModelUseGrant
	CrossTenantModelUse    ModelUseGrant
	EstimatedStorageImpact StorageEstimate
}

// Lifecycle is the immutable policy decision carried by a durable record.
type Lifecycle struct {
	dataClass              DataClass
	sensitivity            Sensitivity
	retentionProfile       RetentionProfile
	policyVersion          string
	retentionDecisionRef   string
	overrideVersion        string
	retentionClock         RetentionClock
	retentionStart         time.Time
	expiresAt              time.Time
	state                  LifecycleState
	legalHoldIDs           []string
	residencyPolicyRef     string
	encryptionKeyRef       string
	operationalPolicyRef   string
	perTenantModelUse      ModelUseGrant
	crossTenantModelUse    ModelUseGrant
	estimatedStorageImpact StorageEstimate
}

func NewLifecycle(in LifecycleInput) (Lifecycle, error) {
	if !in.DataClass.valid() {
		return Lifecycle{}, fmt.Errorf("unsupported data class %q", in.DataClass)
	}
	if !in.Sensitivity.valid() {
		return Lifecycle{}, fmt.Errorf("unsupported sensitivity %q", in.Sensitivity)
	}
	if !in.RetentionProfile.valid() {
		return Lifecycle{}, fmt.Errorf("unsupported retention profile %q", in.RetentionProfile)
	}
	if err := required("lifecycle policy version", in.PolicyVersion); err != nil {
		return Lifecycle{}, err
	}
	if err := required("retention decision reference", in.RetentionDecisionRef); err != nil {
		return Lifecycle{}, err
	}
	if in.RetentionProfile == RetentionOverride && in.OverrideVersion == "" {
		return Lifecycle{}, fmt.Errorf("approved override retention requires an override version")
	}
	if in.RetentionProfile != RetentionOverride && in.OverrideVersion != "" {
		return Lifecycle{}, fmt.Errorf("override version requires approved override retention")
	}
	if in.OverrideVersion != "" {
		if err := required("override version", in.OverrideVersion); err != nil {
			return Lifecycle{}, err
		}
	}
	if !in.RetentionClock.valid() {
		return Lifecycle{}, fmt.Errorf("unsupported retention clock %q", in.RetentionClock)
	}
	if in.RetentionStart.IsZero() || in.ExpiresAt.IsZero() {
		return Lifecycle{}, fmt.Errorf("retention start and expiry are required")
	}
	if !in.ExpiresAt.After(in.RetentionStart) {
		return Lifecycle{}, fmt.Errorf("expiry must be after retention start")
	}
	if in.DataClass == DataClassNormalizedObservation {
		var expected time.Time
		switch in.RetentionProfile {
		case RetentionLean:
			expected = in.RetentionStart.AddDate(0, 6, 0)
		case RetentionStandard:
			expected = in.RetentionStart.AddDate(0, 13, 0)
		}
		if !expected.IsZero() && !in.ExpiresAt.Equal(expected) {
			return Lifecycle{}, fmt.Errorf("%s normalized-observation expiry must be %s", in.RetentionProfile, expected.UTC().Format(time.RFC3339Nano))
		}
	}
	if !in.State.valid() {
		return Lifecycle{}, fmt.Errorf("unsupported lifecycle state %q", in.State)
	}
	if err := required("residency policy reference", in.ResidencyPolicyRef); err != nil {
		return Lifecycle{}, err
	}
	if err := required("encryption key reference", in.EncryptionKeyRef); err != nil {
		return Lifecycle{}, err
	}
	if err := required("operational policy reference", in.OperationalPolicyRef); err != nil {
		return Lifecycle{}, err
	}
	if err := in.PerTenantModelUse.validate(); err != nil {
		return Lifecycle{}, fmt.Errorf("per-tenant model use: %w", err)
	}
	if err := in.CrossTenantModelUse.validate(); err != nil {
		return Lifecycle{}, fmt.Errorf("cross-tenant model use: %w", err)
	}
	if err := in.EstimatedStorageImpact.validate(); err != nil {
		return Lifecycle{}, err
	}
	holds := append([]string(nil), in.LegalHoldIDs...)
	sort.Strings(holds)
	for i, hold := range holds {
		if err := required("legal hold id", hold); err != nil {
			return Lifecycle{}, err
		}
		if i > 0 && holds[i-1] == hold {
			return Lifecycle{}, fmt.Errorf("duplicate legal hold id %q", hold)
		}
	}
	if in.State == LifecycleHeld && len(holds) == 0 {
		return Lifecycle{}, fmt.Errorf("held lifecycle requires at least one legal hold reference")
	}
	if in.State != LifecycleHeld && len(holds) != 0 {
		return Lifecycle{}, fmt.Errorf("legal hold references require HELD lifecycle state")
	}
	return Lifecycle{
		dataClass: in.DataClass, sensitivity: in.Sensitivity,
		retentionProfile: in.RetentionProfile, policyVersion: in.PolicyVersion,
		retentionDecisionRef: in.RetentionDecisionRef, overrideVersion: in.OverrideVersion,
		retentionClock: in.RetentionClock, retentionStart: in.RetentionStart.UTC(),
		expiresAt: in.ExpiresAt.UTC(), state: in.State, legalHoldIDs: holds,
		residencyPolicyRef: in.ResidencyPolicyRef, encryptionKeyRef: in.EncryptionKeyRef,
		operationalPolicyRef: in.OperationalPolicyRef,
		perTenantModelUse:    in.PerTenantModelUse, crossTenantModelUse: in.CrossTenantModelUse,
		estimatedStorageImpact: in.EstimatedStorageImpact,
	}, nil
}

func (l Lifecycle) DataClass() DataClass                    { return l.dataClass }
func (l Lifecycle) Sensitivity() Sensitivity                { return l.sensitivity }
func (l Lifecycle) RetentionProfile() RetentionProfile      { return l.retentionProfile }
func (l Lifecycle) PolicyVersion() string                   { return l.policyVersion }
func (l Lifecycle) RetentionDecisionRef() string            { return l.retentionDecisionRef }
func (l Lifecycle) OverrideVersion() string                 { return l.overrideVersion }
func (l Lifecycle) RetentionClock() RetentionClock          { return l.retentionClock }
func (l Lifecycle) RetentionStart() time.Time               { return l.retentionStart }
func (l Lifecycle) ExpiresAt() time.Time                    { return l.expiresAt }
func (l Lifecycle) State() LifecycleState                   { return l.state }
func (l Lifecycle) ResidencyPolicyRef() string              { return l.residencyPolicyRef }
func (l Lifecycle) EncryptionKeyRef() string                { return l.encryptionKeyRef }
func (l Lifecycle) OperationalPolicyRef() string            { return l.operationalPolicyRef }
func (l Lifecycle) PerTenantModelUse() ModelUseGrant        { return l.perTenantModelUse }
func (l Lifecycle) CrossTenantModelUse() ModelUseGrant      { return l.crossTenantModelUse }
func (l Lifecycle) EstimatedStorageImpact() StorageEstimate { return l.estimatedStorageImpact }

func (l Lifecycle) LegalHoldIDs() []string {
	return append([]string(nil), l.legalHoldIDs...)
}

func (l Lifecycle) validate() error {
	_, err := NewLifecycle(LifecycleInput{
		DataClass: l.dataClass, Sensitivity: l.sensitivity,
		RetentionProfile: l.retentionProfile, PolicyVersion: l.policyVersion,
		RetentionDecisionRef: l.retentionDecisionRef, OverrideVersion: l.overrideVersion,
		RetentionClock: l.retentionClock, RetentionStart: l.retentionStart,
		ExpiresAt: l.expiresAt, State: l.state, LegalHoldIDs: l.legalHoldIDs,
		ResidencyPolicyRef: l.residencyPolicyRef, EncryptionKeyRef: l.encryptionKeyRef,
		OperationalPolicyRef: l.operationalPolicyRef,
		PerTenantModelUse:    l.perTenantModelUse, CrossTenantModelUse: l.crossTenantModelUse,
		EstimatedStorageImpact: l.estimatedStorageImpact,
	})
	return err
}
