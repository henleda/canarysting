package model

import "fmt"

// Scope is the mandatory tenant and isolation boundary for a canonical record.
// Residency is part of the scope so a record cannot lose it during projection.
type Scope struct {
	tenantID           string
	scopeID            string
	deploymentBoundary string
	residencyCellID    string
}

// NewScope constructs a complete fail-closed scope.
func NewScope(tenantID, scopeID, deploymentBoundary, residencyCellID string) (Scope, error) {
	if err := required("tenant id", tenantID); err != nil {
		return Scope{}, err
	}
	if err := required("scope id", scopeID); err != nil {
		return Scope{}, err
	}
	if err := required("deployment boundary", deploymentBoundary); err != nil {
		return Scope{}, err
	}
	if err := required("residency cell id", residencyCellID); err != nil {
		return Scope{}, err
	}
	return Scope{tenantID: tenantID, scopeID: scopeID, deploymentBoundary: deploymentBoundary, residencyCellID: residencyCellID}, nil
}

func (s Scope) TenantID() string           { return s.tenantID }
func (s Scope) ScopeID() string            { return s.scopeID }
func (s Scope) DeploymentBoundary() string { return s.deploymentBoundary }
func (s Scope) ResidencyCellID() string    { return s.residencyCellID }

func (s Scope) validate() error {
	_, err := NewScope(s.tenantID, s.scopeID, s.deploymentBoundary, s.residencyCellID)
	return err
}

// SourceIdentity names the system and optional instance that made a report.
type SourceIdentity struct {
	system   string
	instance string
}

func NewSourceIdentity(system, instance string) (SourceIdentity, error) {
	if err := required("source system", system); err != nil {
		return SourceIdentity{}, err
	}
	if instance != "" {
		if err := required("source instance", instance); err != nil {
			return SourceIdentity{}, err
		}
	}
	return SourceIdentity{system: system, instance: instance}, nil
}

func (s SourceIdentity) System() string   { return s.system }
func (s SourceIdentity) Instance() string { return s.instance }

func (s SourceIdentity) validate() error {
	_, err := NewSourceIdentity(s.system, s.instance)
	return err
}

// CollectorIdentity identifies the read-only producer and its exact version.
type CollectorIdentity struct {
	id      string
	version string
}

func NewCollectorIdentity(id, version string) (CollectorIdentity, error) {
	if err := required("collector id", id); err != nil {
		return CollectorIdentity{}, err
	}
	if err := required("collector version", version); err != nil {
		return CollectorIdentity{}, err
	}
	return CollectorIdentity{id: id, version: version}, nil
}

func (c CollectorIdentity) ID() string      { return c.id }
func (c CollectorIdentity) Version() string { return c.version }

func (c CollectorIdentity) validate() error {
	_, err := NewCollectorIdentity(c.id, c.version)
	return err
}

// ControlIdentity identifies a source-native security control without making
// that control's schema canonical.
type ControlIdentity struct {
	id   string
	kind string
}

func NewControlIdentity(id, kind string) (ControlIdentity, error) {
	if err := required("control id", id); err != nil {
		return ControlIdentity{}, err
	}
	if err := required("control kind", kind); err != nil {
		return ControlIdentity{}, err
	}
	return ControlIdentity{id: id, kind: kind}, nil
}

func (c ControlIdentity) ID() string   { return c.id }
func (c ControlIdentity) Kind() string { return c.kind }

func (c ControlIdentity) validate() error {
	_, err := NewControlIdentity(c.id, c.kind)
	return err
}

// EntityReference is a partial canonical subject/object reference with an
// explicit assertion mode. The convenience constructor represents only a
// syntactically accepted, declared identifier; it can never claim verification.
type EntityReference struct {
	id            string
	kind          string
	assertionMode AssertionMode
	verification  *Verification
}

func NewEntityReference(id, kind string) (EntityReference, error) {
	return NewEntityReferenceWithAssertion(id, kind, AssertionDeclared, nil)
}

func NewEntityReferenceWithAssertion(id, kind string, mode AssertionMode, verification *Verification) (EntityReference, error) {
	if err := required("entity id", id); err != nil {
		return EntityReference{}, err
	}
	if err := required("entity kind", kind); err != nil {
		return EntityReference{}, err
	}
	if !mode.valid() {
		return EntityReference{}, fmt.Errorf("unsupported entity assertion mode %q", mode)
	}
	proof, err := copyOptional(verification, func(value Verification) error { return value.validate() })
	if err != nil {
		return EntityReference{}, fmt.Errorf("entity verification: %w", err)
	}
	if mode == AssertionVerified && proof == nil {
		return EntityReference{}, fmt.Errorf("VERIFIED entity reference requires verification evidence")
	}
	if mode != AssertionVerified && proof != nil {
		return EntityReference{}, fmt.Errorf("entity verification evidence requires VERIFIED assertion mode")
	}
	return EntityReference{id: id, kind: kind, assertionMode: mode, verification: proof}, nil
}

func (e EntityReference) ID() string                   { return e.id }
func (e EntityReference) Kind() string                 { return e.kind }
func (e EntityReference) AssertionMode() AssertionMode { return e.assertionMode }
func (e EntityReference) Verification() (Verification, bool) {
	return valueOptional(e.verification)
}

func (e EntityReference) validate() error {
	_, err := NewEntityReferenceWithAssertion(e.id, e.kind, e.assertionMode, e.verification)
	return err
}
