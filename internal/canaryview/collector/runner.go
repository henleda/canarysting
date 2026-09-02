package collector

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/model"
)

type HealthState string

const (
	HealthHealthy  HealthState = "HEALTHY"
	HealthDegraded HealthState = "DEGRADED"
	HealthDataLoss HealthState = "DATA_LOSS"
)

type FailureClass string

const (
	FailureNone              FailureClass = "NONE"
	FailureSource            FailureClass = "SOURCE_ERROR"
	FailureContract          FailureClass = "CONTRACT_ERROR"
	FailureSink              FailureClass = "SINK_ERROR"
	FailureCheckpoint        FailureClass = "CHECKPOINT_ERROR"
	FailureCheckpointExpired FailureClass = "CHECKPOINT_EXPIRED"
	FailureReplayLoss        FailureClass = "REPLAY_LOSS"
)

// RunReport is safe connector-health input. It contains bounded counters and
// typed state, never credentials, raw cursor values, payloads, or source errors.
// A later repository may persist it under the CONNECTOR_HEALTH lifecycle class.
type RunReport struct {
	State              HealthState
	Failure            FailureClass
	Replay             ReplayState
	StartedAt          time.Time
	FinishedAt         time.Time
	Accepted           int
	Duplicates         int
	Rejected           int
	CheckpointAdvanced bool
	MoreAvailable      bool
	LastSourceTime     *time.Time
	LastObservedTime   *time.Time
}

type Runner struct {
	checkpoints CheckpointRepository
	sink        ObservationSink
	now         func() time.Time
	maxBatch    int
}

func NewRunner(checkpoints CheckpointRepository, sink ObservationSink, now func() time.Time, maxBatch int) (*Runner, error) {
	if checkpoints == nil {
		return nil, fmt.Errorf("checkpoint repository is required")
	}
	if sink == nil {
		return nil, fmt.Errorf("observation sink is required")
	}
	if now == nil {
		return nil, fmt.Errorf("trusted clock is required")
	}
	if maxBatch <= 0 || maxBatch > maximumBatchSize {
		return nil, fmt.Errorf("%w: runner batch size must be between 1 and %d", ErrBound, maximumBatchSize)
	}
	return &Runner{checkpoints: checkpoints, sink: sink, now: now, maxBatch: maxBatch}, nil
}

// Run performs exactly one bounded source read. It has no automatic retry:
// callers may invoke Run again, at which point the unchanged checkpoint and an
// idempotent sink make partial delivery deterministic.
func (r *Runner) Run(ctx context.Context, source Source, scope model.Scope) (RunReport, error) {
	startedAt := r.now().UTC()
	report := RunReport{State: HealthDegraded, Failure: FailureContract, Replay: ReplayLive, StartedAt: startedAt}
	finish := func() RunReport {
		report.FinishedAt = r.now().UTC()
		return report
	}
	if startedAt.IsZero() {
		return finish(), fmt.Errorf("trusted clock returned zero time")
	}
	if source == nil {
		return finish(), fmt.Errorf("source is required")
	}
	if err := validateScope(scope); err != nil {
		return finish(), err
	}
	descriptor := source.Descriptor()
	if err := descriptor.validate(); err != nil {
		return finish(), fmt.Errorf("source descriptor: %w", err)
	}
	key := CheckpointKey{Scope: scope, Source: descriptor.source, Collector: descriptor.collector}
	checkpoint, found, err := r.checkpoints.Load(ctx, key)
	if err != nil {
		report.Failure = FailureCheckpoint
		return finish(), ErrCheckpointStore
	}
	var prior *Checkpoint
	if found {
		if err := validateCheckpointBinding(checkpoint, key); err != nil {
			report.Failure = FailureCheckpoint
			return finish(), err
		}
		if checkpoint.expired(startedAt) {
			report.Failure = FailureCheckpointExpired
			report.Replay = ReplayExpired
			return finish(), ErrCheckpointExpired
		}
		value := checkpoint
		prior = &value
	}
	limit := r.maxBatch
	if descriptor.maxBatchSize < limit {
		limit = descriptor.maxBatchSize
	}
	request, err := newReadRequest(scope, prior, limit)
	if err != nil {
		return finish(), err
	}
	result, err := source.Read(ctx, request)
	if err != nil {
		report.Failure = FailureSource
		return finish(), ErrSourceRead
	}
	if err := validateReadResult(result, descriptor, scope, limit); err != nil {
		report.Failure = FailureContract
		report.Rejected = len(result.observations)
		return finish(), err
	}
	report.Replay = result.replay.state
	report.MoreAvailable = result.moreAvailable
	if result.replay.state == ReplayExpired {
		report.Failure = FailureCheckpointExpired
		return finish(), fmt.Errorf("%w: %s", ErrCheckpointExpired, result.replay.reason)
	}
	if result.replay.state == ReplayLost {
		report.State = HealthDataLoss
		report.Failure = FailureReplayLoss
		return finish(), fmt.Errorf("%w: %s", ErrReplayLoss, result.replay.reason)
	}

	seen := make(map[string][sha256.Size]byte, len(result.observations))
	for _, observation := range result.observations {
		blob, marshalErr := model.MarshalObservationV3(observation)
		if marshalErr != nil {
			report.Failure = FailureContract
			report.Rejected++
			return finish(), fmt.Errorf("validate observation: %w", marshalErr)
		}
		id := observation.Envelope().RecordID()
		digest := sha256.Sum256(blob)
		if previous, duplicate := seen[id]; duplicate {
			if previous != digest {
				report.Failure = FailureContract
				report.Rejected++
				return finish(), fmt.Errorf("%w: record %q", ErrConflictingDuplicate, id)
			}
			report.Duplicates++
			continue
		}
		seen[id] = digest
		disposition, putErr := r.sink.Put(ctx, observation)
		if putErr != nil {
			report.Failure = FailureSink
			report.Rejected++
			if errors.Is(putErr, ErrConflictingDuplicate) {
				return finish(), fmt.Errorf("%w: record %q", ErrConflictingDuplicate, id)
			}
			return finish(), ErrSinkDelivery
		}
		switch disposition {
		case DeliveryStored:
			report.Accepted++
		case DeliveryDuplicate:
			report.Duplicates++
		default:
			report.Failure = FailureSink
			report.Rejected++
			return finish(), fmt.Errorf("store observation %q returned unsupported disposition %q", id, disposition)
		}
		updateLatestTimes(&report, observation)
	}
	next := *result.nextCheckpoint
	if next.expired(startedAt) {
		report.Failure = FailureCheckpointExpired
		return finish(), fmt.Errorf("next checkpoint: %w", ErrCheckpointExpired)
	}
	if prior != nil && (next.createdAt.Before(prior.createdAt) || next.observedThrough.Before(prior.observedThrough)) {
		report.Failure = FailureCheckpoint
		return finish(), fmt.Errorf("next checkpoint regresses committed progress")
	}
	if err := r.checkpoints.Commit(ctx, key, prior, next); err != nil {
		report.Failure = FailureCheckpoint
		if errors.Is(err, ErrCheckpointConflict) {
			return finish(), ErrCheckpointConflict
		}
		return finish(), ErrCheckpointStore
	}
	report.State = HealthHealthy
	report.Failure = FailureNone
	report.CheckpointAdvanced = true
	return finish(), nil
}

func validateReadResult(result ReadResult, descriptor Descriptor, scope model.Scope, limit int) error {
	if err := result.replay.validate(); err != nil {
		return fmt.Errorf("replay disposition: %w", err)
	}
	if len(result.observations) > limit {
		return fmt.Errorf("%w: source returned %d observations for limit %d", ErrBound, len(result.observations), limit)
	}
	loss := result.replay.state == ReplayExpired || result.replay.state == ReplayLost
	if loss {
		if len(result.observations) != 0 || result.nextCheckpoint != nil || result.moreAvailable {
			return fmt.Errorf("replay expiry or loss cannot carry data")
		}
		return nil
	}
	if result.nextCheckpoint == nil {
		return fmt.Errorf("successful read requires a next checkpoint")
	}
	key := CheckpointKey{Scope: scope, Source: descriptor.source, Collector: descriptor.collector}
	if err := validateCheckpointBinding(*result.nextCheckpoint, key); err != nil {
		return fmt.Errorf("next checkpoint: %w", err)
	}
	for _, observation := range result.observations {
		if !sameScope(observation.Envelope().Scope(), scope) {
			return fmt.Errorf("%w: observation %q", ErrScopeMismatch, observation.Envelope().RecordID())
		}
		if !sameSource(observation.Source(), descriptor.source) {
			return fmt.Errorf("%w: observation %q", ErrSourceMismatch, observation.Envelope().RecordID())
		}
		if !sameCollector(observation.Collector(), descriptor.collector) {
			return fmt.Errorf("%w: observation %q", ErrCollectorMismatch, observation.Envelope().RecordID())
		}
		if observation.Envelope().Synthetic().Synthetic() {
			return fmt.Errorf("production collector cannot emit synthetic observation %q", observation.Envelope().RecordID())
		}
	}
	return nil
}

func validateCheckpointBinding(checkpoint Checkpoint, key CheckpointKey) error {
	if err := checkpoint.validate(); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	if !sameScope(checkpoint.scope, key.Scope) {
		return ErrScopeMismatch
	}
	if !sameSource(checkpoint.source, key.Source) {
		return ErrSourceMismatch
	}
	if !sameCollector(checkpoint.collector, key.Collector) {
		return ErrCollectorMismatch
	}
	return nil
}

func updateLatestTimes(report *RunReport, observation model.Observation) {
	observed := observation.ObservedTimestamp()
	if report.LastObservedTime == nil || observed.After(*report.LastObservedTime) {
		value := observed
		report.LastObservedTime = &value
	}
	if sourceTime, ok := observation.SourceTimestamp(); ok && (report.LastSourceTime == nil || sourceTime.After(*report.LastSourceTime)) {
		value := sourceTime
		report.LastSourceTime = &value
	}
}
