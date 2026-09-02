package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/model"
)

const (
	maximumBatchSize = 10_000
	checkpointPrefix = "checkpoint:sha256:"
)

var (
	ErrBound                = errors.New("collector bound exceeded")
	ErrScopeMismatch        = errors.New("collector scope mismatch")
	ErrSourceMismatch       = errors.New("collector source mismatch")
	ErrCollectorMismatch    = errors.New("collector identity mismatch")
	ErrCheckpointExpired    = errors.New("collector checkpoint expired")
	ErrReplayLoss           = errors.New("collector replay data loss")
	ErrConflictingDuplicate = errors.New("collector duplicate record conflict")
	ErrCheckpointConflict   = errors.New("collector checkpoint conflict")
	ErrCheckpointStore      = errors.New("collector checkpoint repository error")
	ErrSourceRead           = errors.New("collector source read error")
	ErrSinkDelivery         = errors.New("collector observation delivery error")
)

// AcquisitionMode states how a read-only collector receives source reports.
type AcquisitionMode string

const (
	ModeStream   AcquisitionMode = "STREAM"
	ModePoll     AcquisitionMode = "POLL"
	ModeWebhook  AcquisitionMode = "WEBHOOK"
	ModeFile     AcquisitionMode = "FILE"
	ModeBackfill AcquisitionMode = "BACKFILL"
)

func (m AcquisitionMode) valid() bool {
	switch m {
	case ModeStream, ModePoll, ModeWebhook, ModeFile, ModeBackfill:
		return true
	default:
		return false
	}
}

// DescriptorInput is copied into an immutable Descriptor. No credential,
// vendor mutation, or action capability can be represented here.
type DescriptorInput struct {
	Source       model.SourceIdentity
	Collector    model.CollectorIdentity
	Modes        []AcquisitionMode
	MaxBatchSize int
}

// Descriptor is the complete capability exposed by a read-only Source.
type Descriptor struct {
	source       model.SourceIdentity
	collector    model.CollectorIdentity
	modes        []AcquisitionMode
	maxBatchSize int
}

func NewDescriptor(in DescriptorInput) (Descriptor, error) {
	if _, err := model.NewSourceIdentity(in.Source.System(), in.Source.Instance()); err != nil {
		return Descriptor{}, fmt.Errorf("source: %w", err)
	}
	if _, err := model.NewCollectorIdentity(in.Collector.ID(), in.Collector.Version()); err != nil {
		return Descriptor{}, fmt.Errorf("collector: %w", err)
	}
	if in.MaxBatchSize <= 0 || in.MaxBatchSize > maximumBatchSize {
		return Descriptor{}, fmt.Errorf("%w: max batch size must be between 1 and %d", ErrBound, maximumBatchSize)
	}
	if len(in.Modes) == 0 || len(in.Modes) > 5 {
		return Descriptor{}, fmt.Errorf("collector requires between one and five acquisition modes")
	}
	modes := append([]AcquisitionMode(nil), in.Modes...)
	seen := make(map[AcquisitionMode]struct{}, len(modes))
	for _, mode := range modes {
		if !mode.valid() {
			return Descriptor{}, fmt.Errorf("unsupported acquisition mode %q", mode)
		}
		if _, duplicate := seen[mode]; duplicate {
			return Descriptor{}, fmt.Errorf("duplicate acquisition mode %q", mode)
		}
		seen[mode] = struct{}{}
	}
	return Descriptor{source: in.Source, collector: in.Collector, modes: modes, maxBatchSize: in.MaxBatchSize}, nil
}

func (d Descriptor) Source() model.SourceIdentity       { return d.source }
func (d Descriptor) Collector() model.CollectorIdentity { return d.collector }
func (d Descriptor) Modes() []AcquisitionMode           { return append([]AcquisitionMode(nil), d.modes...) }
func (d Descriptor) MaxBatchSize() int                  { return d.maxBatchSize }

func (d Descriptor) validate() error {
	_, err := NewDescriptor(DescriptorInput{Source: d.source, Collector: d.collector, Modes: d.modes, MaxBatchSize: d.maxBatchSize})
	return err
}

// CheckpointInput is copied into an immutable, scope- and producer-bound
// checkpoint. Reference is a platform-generated digest, never a raw cursor.
// A concrete source may resolve that reference to encrypted local cursor state.
type CheckpointInput struct {
	Reference       string
	Scope           model.Scope
	Source          model.SourceIdentity
	Collector       model.CollectorIdentity
	CreatedAt       time.Time
	ObservedThrough time.Time
	ExpiresAt       time.Time
}

type Checkpoint struct {
	reference       string
	scope           model.Scope
	source          model.SourceIdentity
	collector       model.CollectorIdentity
	createdAt       time.Time
	observedThrough time.Time
	expiresAt       time.Time
}

func NewCheckpoint(in CheckpointInput) (Checkpoint, error) {
	if err := validateDigestReference("checkpoint", in.Reference, checkpointPrefix); err != nil {
		return Checkpoint{}, err
	}
	if err := validateScope(in.Scope); err != nil {
		return Checkpoint{}, err
	}
	if _, err := model.NewSourceIdentity(in.Source.System(), in.Source.Instance()); err != nil {
		return Checkpoint{}, fmt.Errorf("source: %w", err)
	}
	if _, err := model.NewCollectorIdentity(in.Collector.ID(), in.Collector.Version()); err != nil {
		return Checkpoint{}, fmt.Errorf("collector: %w", err)
	}
	if in.CreatedAt.IsZero() || in.ObservedThrough.IsZero() || in.ExpiresAt.IsZero() {
		return Checkpoint{}, fmt.Errorf("checkpoint timestamps are required")
	}
	createdAt := in.CreatedAt.UTC()
	observedThrough := in.ObservedThrough.UTC()
	expiresAt := in.ExpiresAt.UTC()
	if !expiresAt.After(createdAt) {
		return Checkpoint{}, fmt.Errorf("checkpoint expiry must follow creation")
	}
	return Checkpoint{
		reference: in.Reference, scope: in.Scope, source: in.Source, collector: in.Collector,
		createdAt: createdAt, observedThrough: observedThrough, expiresAt: expiresAt,
	}, nil
}

func (c Checkpoint) Reference() string                  { return c.reference }
func (c Checkpoint) Scope() model.Scope                 { return c.scope }
func (c Checkpoint) Source() model.SourceIdentity       { return c.source }
func (c Checkpoint) Collector() model.CollectorIdentity { return c.collector }
func (c Checkpoint) CreatedAt() time.Time               { return c.createdAt }
func (c Checkpoint) ObservedThrough() time.Time         { return c.observedThrough }
func (c Checkpoint) ExpiresAt() time.Time               { return c.expiresAt }

func (c Checkpoint) validate() error {
	_, err := NewCheckpoint(CheckpointInput{
		Reference: c.reference, Scope: c.scope, Source: c.source, Collector: c.collector,
		CreatedAt: c.createdAt, ObservedThrough: c.observedThrough, ExpiresAt: c.expiresAt,
	})
	return err
}

func (c Checkpoint) expired(now time.Time) bool { return !now.UTC().Before(c.expiresAt) }

func validateDigestReference(label, reference, prefix string) error {
	if !strings.HasPrefix(reference, prefix) {
		return fmt.Errorf("%s reference must be a platform-generated %s digest id", label, prefix)
	}
	digestText := strings.TrimPrefix(reference, prefix)
	if digestText != strings.ToLower(digestText) {
		return fmt.Errorf("%s reference digest must use lowercase hexadecimal", label)
	}
	digest, err := hex.DecodeString(digestText)
	if err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("%s reference digest must be 64 hexadecimal characters", label)
	}
	return nil
}

// ReplayState distinguishes ordinary forward reads from replay and explicit
// continuity failures. A loss or expiry can never masquerade as an empty read.
type ReplayState string

const (
	ReplayLive     ReplayState = "LIVE"
	ReplayReplayed ReplayState = "REPLAYED"
	ReplayExpired  ReplayState = "EXPIRED"
	ReplayLost     ReplayState = "LOSS"
)

// ReplayReason is a closed, non-secret classification suitable for logs and
// health records. Source error text and cursor material must not be stored here.
type ReplayReason string

const (
	ReplayReasonNone                   ReplayReason = ""
	ReplayReasonCheckpointUnknown      ReplayReason = "CHECKPOINT_UNKNOWN"
	ReplayReasonSourceRetentionExpired ReplayReason = "SOURCE_RETENTION_EXPIRED"
	ReplayReasonSourceGap              ReplayReason = "SOURCE_GAP"
	ReplayReasonSourceReset            ReplayReason = "SOURCE_RESET"
)

func (r ReplayReason) valid() bool {
	switch r {
	case ReplayReasonCheckpointUnknown, ReplayReasonSourceRetentionExpired,
		ReplayReasonSourceGap, ReplayReasonSourceReset:
		return true
	default:
		return false
	}
}

type ReplayDisposition struct {
	state             ReplayState
	reason            ReplayReason
	unavailableBefore *time.Time
}

func NewReplayDisposition(state ReplayState, reason ReplayReason, unavailableBefore *time.Time) (ReplayDisposition, error) {
	switch state {
	case ReplayLive, ReplayReplayed:
		if reason != ReplayReasonNone || unavailableBefore != nil {
			return ReplayDisposition{}, fmt.Errorf("successful replay state cannot carry a loss reason or boundary")
		}
	case ReplayExpired, ReplayLost:
		if !reason.valid() {
			return ReplayDisposition{}, fmt.Errorf("replay expiry or loss requires a supported reason code")
		}
		if unavailableBefore == nil || unavailableBefore.IsZero() {
			return ReplayDisposition{}, fmt.Errorf("replay expiry or loss requires an unavailable-before boundary")
		}
	default:
		return ReplayDisposition{}, fmt.Errorf("unsupported replay state %q", state)
	}
	var boundary *time.Time
	if unavailableBefore != nil {
		value := unavailableBefore.UTC()
		boundary = &value
	}
	return ReplayDisposition{state: state, reason: reason, unavailableBefore: boundary}, nil
}

func (r ReplayDisposition) State() ReplayState   { return r.state }
func (r ReplayDisposition) Reason() ReplayReason { return r.reason }
func (r ReplayDisposition) UnavailableBefore() (time.Time, bool) {
	if r.unavailableBefore == nil {
		return time.Time{}, false
	}
	return *r.unavailableBefore, true
}

func (r ReplayDisposition) validate() error {
	_, err := NewReplayDisposition(r.state, r.reason, r.unavailableBefore)
	return err
}

type ReadRequest struct {
	scope      model.Scope
	checkpoint *Checkpoint
	limit      int
}

func newReadRequest(scope model.Scope, checkpoint *Checkpoint, limit int) (ReadRequest, error) {
	if err := validateScope(scope); err != nil {
		return ReadRequest{}, err
	}
	if limit <= 0 || limit > maximumBatchSize {
		return ReadRequest{}, fmt.Errorf("%w: read limit must be between 1 and %d", ErrBound, maximumBatchSize)
	}
	var copied *Checkpoint
	if checkpoint != nil {
		value := *checkpoint
		copied = &value
	}
	return ReadRequest{scope: scope, checkpoint: copied, limit: limit}, nil
}

func (r ReadRequest) Scope() model.Scope { return r.scope }
func (r ReadRequest) Limit() int         { return r.limit }
func (r ReadRequest) Checkpoint() (Checkpoint, bool) {
	if r.checkpoint == nil {
		return Checkpoint{}, false
	}
	return *r.checkpoint, true
}

type ReadResultInput struct {
	Observations   []model.Observation
	NextCheckpoint *Checkpoint
	Replay         ReplayDisposition
	MoreAvailable  bool
}

type ReadResult struct {
	observations   []model.Observation
	nextCheckpoint *Checkpoint
	replay         ReplayDisposition
	moreAvailable  bool
}

func NewReadResult(in ReadResultInput) (ReadResult, error) {
	if err := in.Replay.validate(); err != nil {
		return ReadResult{}, err
	}
	if len(in.Observations) > maximumBatchSize {
		return ReadResult{}, fmt.Errorf("%w: source batch has %d observations", ErrBound, len(in.Observations))
	}
	loss := in.Replay.state == ReplayExpired || in.Replay.state == ReplayLost
	if loss && (len(in.Observations) != 0 || in.NextCheckpoint != nil || in.MoreAvailable) {
		return ReadResult{}, fmt.Errorf("replay expiry or loss cannot carry observations, a checkpoint, or a continuation")
	}
	if !loss && in.NextCheckpoint == nil {
		return ReadResult{}, fmt.Errorf("successful read requires a next checkpoint")
	}
	var checkpoint *Checkpoint
	if in.NextCheckpoint != nil {
		if err := in.NextCheckpoint.validate(); err != nil {
			return ReadResult{}, fmt.Errorf("next checkpoint: %w", err)
		}
		value := *in.NextCheckpoint
		checkpoint = &value
	}
	return ReadResult{
		observations: append([]model.Observation(nil), in.Observations...), nextCheckpoint: checkpoint,
		replay: in.Replay, moreAvailable: in.MoreAvailable,
	}, nil
}

func (r ReadResult) Observations() []model.Observation {
	return append([]model.Observation(nil), r.observations...)
}
func (r ReadResult) Replay() ReplayDisposition { return r.replay }
func (r ReadResult) MoreAvailable() bool       { return r.moreAvailable }
func (r ReadResult) NextCheckpoint() (Checkpoint, bool) {
	if r.nextCheckpoint == nil {
		return Checkpoint{}, false
	}
	return *r.nextCheckpoint, true
}

// Source is intentionally incapable of representing a vendor write. Action
// adapters and write-capable credentials belong to a later, separate contract.
type Source interface {
	Descriptor() Descriptor
	Read(context.Context, ReadRequest) (ReadResult, error)
}

// CheckpointKey is the exact isolation boundary for local delivery progress.
type CheckpointKey struct {
	Scope     model.Scope
	Source    model.SourceIdentity
	Collector model.CollectorIdentity
}

// CheckpointRepository persists CanaryView-owned delivery progress. Commit is
// compare-and-swap: expected is nil for the first checkpoint.
type CheckpointRepository interface {
	Load(context.Context, CheckpointKey) (Checkpoint, bool, error)
	Commit(context.Context, CheckpointKey, *Checkpoint, Checkpoint) error
}

type DeliveryDisposition string

const (
	DeliveryStored    DeliveryDisposition = "STORED"
	DeliveryDuplicate DeliveryDisposition = "DUPLICATE"
)

// ObservationSink owns normalized CanaryView intake. Duplicate means the
// immutable record already exists with identical canonical content.
type ObservationSink interface {
	Put(context.Context, model.Observation) (DeliveryDisposition, error)
}

func validateScope(scope model.Scope) error {
	_, err := model.NewScope(scope.TenantID(), scope.ScopeID(), scope.DeploymentBoundary(), scope.ResidencyCellID())
	if err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	return nil
}

func sameScope(left, right model.Scope) bool {
	return left.TenantID() == right.TenantID() &&
		left.ScopeID() == right.ScopeID() &&
		left.DeploymentBoundary() == right.DeploymentBoundary() &&
		left.ResidencyCellID() == right.ResidencyCellID()
}

func sameSource(left, right model.SourceIdentity) bool {
	return left.System() == right.System() && left.Instance() == right.Instance()
}

func sameCollector(left, right model.CollectorIdentity) bool {
	return left.ID() == right.ID() && left.Version() == right.Version()
}
