package collector

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/model"
)

var (
	testNow      = time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	testObserved = testNow.Add(-time.Minute)
)

func TestRunnerPreservesPartialObservationAndAdvancesCheckpoint(t *testing.T) {
	scope, sourceID, collectorID := identities(t, "scope-a")
	descriptor := descriptorFixture(t, sourceID, collectorID, 8)
	raw, err := model.NewRawEventReference("rawref:sha256:"+strings.Repeat("b", 64), model.RawAvailable, "sha256", strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	sourceTime := testObserved.Add(-3 * time.Second)
	observation := observationFixture(t, observationInput{
		id: "partial-1", scope: scope, source: sourceID, collector: collectorID,
		sourceTime: &sourceTime, observedAt: testObserved, raw: &raw,
	})
	next := checkpointFixture(t, "1", scope, sourceID, collectorID, testNow)
	result := readResultFixture(t, []model.Observation{observation}, next, ReplayLive, false)
	source := &fakeSource{descriptor: descriptor, results: []sourceResponse{{result: result}}}
	repository := newFakeCheckpointRepository()
	sink := newFakeSink()
	runner := runnerFixture(t, repository, sink, 4)

	report, err := runner.Run(context.Background(), source, scope)
	if err != nil {
		t.Fatal(err)
	}
	if report.State != HealthHealthy || report.Failure != FailureNone || !report.CheckpointAdvanced {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Accepted != 1 || report.Duplicates != 0 || source.lastRequest.Limit() != 4 {
		t.Fatalf("unexpected delivery counts/request: report=%+v limit=%d", report, source.lastRequest.Limit())
	}
	stored := sink.observation("partial-1")
	gotSourceTime, ok := stored.SourceTimestamp()
	if !ok || !gotSourceTime.Equal(sourceTime) || !stored.ObservedTimestamp().Equal(testObserved) {
		t.Fatalf("source/observed timestamps changed: source=%v ok=%v observed=%v", gotSourceTime, ok, stored.ObservedTimestamp())
	}
	gotRaw, ok := stored.RawEvent()
	if !ok || gotRaw.Reference() != raw.Reference() || gotRaw.HashValue() != raw.HashValue() {
		t.Fatalf("raw reference/checksum changed: %+v ok=%v", gotRaw, ok)
	}
	if _, hasSubject := stored.Subject(); hasSubject {
		t.Fatal("partial observation invented a subject")
	}
	committed, ok := repository.value(checkpointKey(scope, sourceID, collectorID))
	if !ok || committed.Reference() != next.Reference() {
		t.Fatalf("checkpoint was not committed: %+v ok=%v", committed, ok)
	}
}

func TestRunnerSourceErrorLeavesCheckpointAndRetryDeterministic(t *testing.T) {
	scope, sourceID, collectorID := identities(t, "scope-retry")
	descriptor := descriptorFixture(t, sourceID, collectorID, 3)
	prior := checkpointFixture(t, "1", scope, sourceID, collectorID, testNow.Add(-time.Minute))
	next := checkpointFixture(t, "2", scope, sourceID, collectorID, testNow)
	observation := observationFixture(t, observationInput{id: "retry-1", scope: scope, source: sourceID, collector: collectorID})
	source := &fakeSource{descriptor: descriptor, results: []sourceResponse{
		{err: errors.New("Bearer source-secret-must-not-escape")},
		{result: readResultFixture(t, []model.Observation{observation}, next, ReplayReplayed, false)},
	}}
	repository := newFakeCheckpointRepository()
	repository.seed(checkpointKey(scope, sourceID, collectorID), prior)
	runner := runnerFixture(t, repository, newFakeSink(), 3)

	first, err := runner.Run(context.Background(), source, scope)
	if !errors.Is(err, ErrSourceRead) || strings.Contains(err.Error(), "source-secret") || first.Failure != FailureSource || first.CheckpointAdvanced {
		t.Fatalf("source error was hidden: report=%+v err=%v", first, err)
	}
	unchanged, _ := repository.value(checkpointKey(scope, sourceID, collectorID))
	if unchanged.Reference() != prior.Reference() {
		t.Fatal("source error advanced checkpoint")
	}
	second, err := runner.Run(context.Background(), source, scope)
	if err != nil || second.Replay != ReplayReplayed || !second.CheckpointAdvanced {
		t.Fatalf("retry did not replay deterministically: report=%+v err=%v", second, err)
	}
	for index, request := range source.requests {
		checkpoint, ok := request.Checkpoint()
		if !ok || checkpoint.Reference() != prior.Reference() {
			t.Fatalf("request %d did not reuse prior checkpoint", index)
		}
	}
}

func TestRunnerPartialSinkFailureReplaysAsDuplicate(t *testing.T) {
	scope, sourceID, collectorID := identities(t, "scope-sink")
	descriptor := descriptorFixture(t, sourceID, collectorID, 4)
	next := checkpointFixture(t, "3", scope, sourceID, collectorID, testNow)
	observations := []model.Observation{
		observationFixture(t, observationInput{id: "record-a", scope: scope, source: sourceID, collector: collectorID}),
		observationFixture(t, observationInput{id: "record-b", scope: scope, source: sourceID, collector: collectorID, observedAt: testObserved.Add(time.Second)}),
	}
	result := readResultFixture(t, observations, next, ReplayLive, false)
	source := &fakeSource{descriptor: descriptor, results: []sourceResponse{{result: result}, {result: result}}}
	repository := newFakeCheckpointRepository()
	sink := newFakeSink()
	sink.failRecordOnce = "record-b"
	runner := runnerFixture(t, repository, sink, 4)

	first, err := runner.Run(context.Background(), source, scope)
	if err == nil || first.Accepted != 1 || first.Rejected != 1 || first.CheckpointAdvanced {
		t.Fatalf("partial failure report=%+v err=%v", first, err)
	}
	second, err := runnerFixture(t, repository, sink, 4).Run(context.Background(), source, scope)
	if err != nil || second.Accepted != 1 || second.Duplicates != 1 || !second.CheckpointAdvanced {
		t.Fatalf("replay report=%+v err=%v", second, err)
	}
	if sink.count() != 2 {
		t.Fatalf("sink has %d unique records, want 2", sink.count())
	}
}

func TestRunnerHandlesIdenticalAndConflictingBatchDuplicates(t *testing.T) {
	scope, sourceID, collectorID := identities(t, "scope-duplicates")
	descriptor := descriptorFixture(t, sourceID, collectorID, 4)
	next := checkpointFixture(t, "4", scope, sourceID, collectorID, testNow)
	first := observationFixture(t, observationInput{id: "same", scope: scope, source: sourceID, collector: collectorID})
	identicalResult := readResultFixture(t, []model.Observation{first, first}, next, ReplayLive, false)
	repository := newFakeCheckpointRepository()
	report, err := runnerFixture(t, repository, newFakeSink(), 4).Run(context.Background(), &fakeSource{
		descriptor: descriptor, results: []sourceResponse{{result: identicalResult}},
	}, scope)
	if err != nil || report.Accepted != 1 || report.Duplicates != 1 {
		t.Fatalf("identical duplicate was not idempotent: report=%+v err=%v", report, err)
	}

	conflicting := observationFixture(t, observationInput{
		id: "same", scope: scope, source: sourceID, collector: collectorID, observedAt: testObserved.Add(time.Second),
	})
	conflictNext := checkpointFixture(t, "5", scope, sourceID, collectorID, testNow.Add(time.Second))
	conflictResult := readResultFixture(t, []model.Observation{first, conflicting}, conflictNext, ReplayReplayed, false)
	newRepository := newFakeCheckpointRepository()
	report, err = runnerFixture(t, newRepository, newFakeSink(), 4).Run(context.Background(), &fakeSource{
		descriptor: descriptor, results: []sourceResponse{{result: conflictResult}},
	}, scope)
	if !errors.Is(err, ErrConflictingDuplicate) || report.CheckpointAdvanced {
		t.Fatalf("conflicting duplicate was accepted: report=%+v err=%v", report, err)
	}
}

func TestRunnerMakesCheckpointExpiryAndReplayLossVisible(t *testing.T) {
	scope, sourceID, collectorID := identities(t, "scope-loss")
	descriptor := descriptorFixture(t, sourceID, collectorID, 2)
	repository := newFakeCheckpointRepository()
	expired := checkpointFixture(t, "6", scope, sourceID, collectorID, testNow.Add(-2*time.Hour))
	repository.seed(checkpointKey(scope, sourceID, collectorID), expired)
	source := &fakeSource{descriptor: descriptor}
	report, err := runnerFixture(t, repository, newFakeSink(), 2).Run(context.Background(), source, scope)
	if !errors.Is(err, ErrCheckpointExpired) || report.Failure != FailureCheckpointExpired || source.callCount() != 0 {
		t.Fatalf("expired checkpoint was not stopped before source read: report=%+v calls=%d err=%v", report, source.callCount(), err)
	}

	boundary := testNow.Add(-24 * time.Hour)
	loss, err := NewReplayDisposition(ReplayLost, ReplayReasonSourceRetentionExpired, &boundary)
	if err != nil {
		t.Fatal(err)
	}
	lossResult, err := NewReadResult(ReadResultInput{Replay: loss})
	if err != nil {
		t.Fatal(err)
	}
	emptyRepository := newFakeCheckpointRepository()
	report, err = runnerFixture(t, emptyRepository, newFakeSink(), 2).Run(context.Background(), &fakeSource{
		descriptor: descriptor, results: []sourceResponse{{result: lossResult}},
	}, scope)
	if !errors.Is(err, ErrReplayLoss) || report.State != HealthDataLoss || report.Failure != FailureReplayLoss {
		t.Fatalf("replay loss was hidden: report=%+v err=%v", report, err)
	}
	if _, committed := emptyRepository.value(checkpointKey(scope, sourceID, collectorID)); committed {
		t.Fatal("replay loss advanced checkpoint")
	}
}

func TestRunnerRejectsSyntheticOutputAndRegressingCheckpoint(t *testing.T) {
	scope, sourceID, collectorID := identities(t, "scope-integrity")
	descriptor := descriptorFixture(t, sourceID, collectorID, 2)
	next := checkpointFixture(t, "synthetic", scope, sourceID, collectorID, testNow)
	synthetic := observationFixture(t, observationInput{
		id: "synthetic", scope: scope, source: sourceID, collector: collectorID, synthetic: true,
	})
	result := readResultFixture(t, []model.Observation{synthetic}, next, ReplayLive, false)
	report, err := runnerFixture(t, newFakeCheckpointRepository(), newFakeSink(), 2).Run(context.Background(), &fakeSource{
		descriptor: descriptor, results: []sourceResponse{{result: result}},
	}, scope)
	if err == nil || report.Failure != FailureContract || report.CheckpointAdvanced {
		t.Fatalf("synthetic production output accepted: report=%+v err=%v", report, err)
	}

	prior := checkpointFixture(t, "prior", scope, sourceID, collectorID, testNow.Add(-time.Minute))
	regressing := checkpointFixture(t, "regressing", scope, sourceID, collectorID, testNow.Add(-2*time.Minute))
	production := observationFixture(t, observationInput{id: "production", scope: scope, source: sourceID, collector: collectorID})
	regressingResult := readResultFixture(t, []model.Observation{production}, regressing, ReplayReplayed, false)
	repository := newFakeCheckpointRepository()
	repository.seed(checkpointKey(scope, sourceID, collectorID), prior)
	report, err = runnerFixture(t, repository, newFakeSink(), 2).Run(context.Background(), &fakeSource{
		descriptor: descriptor, results: []sourceResponse{{result: regressingResult}},
	}, scope)
	if err == nil || report.Failure != FailureCheckpoint || report.CheckpointAdvanced {
		t.Fatalf("regressing checkpoint accepted: report=%+v err=%v", report, err)
	}
	unchanged, _ := repository.value(checkpointKey(scope, sourceID, collectorID))
	if unchanged.Reference() != prior.Reference() {
		t.Fatal("regressing checkpoint replaced committed progress")
	}
}

func TestRunnerFailsClosedOnScopeSourceCollectorAndBounds(t *testing.T) {
	scope, sourceID, collectorID := identities(t, "scope-expected")
	descriptor := descriptorFixture(t, sourceID, collectorID, 1)
	otherScope, otherSource, _ := identities(t, "scope-other")
	otherCollector, err := model.NewCollectorIdentity("other-collector", "v2")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		observation model.Observation
		want        error
	}{
		{"scope", observationFixture(t, observationInput{id: "scope", scope: otherScope, source: sourceID, collector: collectorID}), ErrScopeMismatch},
		{"source", observationFixture(t, observationInput{id: "source", scope: scope, source: otherSource, collector: collectorID}), ErrSourceMismatch},
		{"collector", observationFixture(t, observationInput{id: "collector", scope: scope, source: sourceID, collector: otherCollector}), ErrCollectorMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			next := checkpointFixture(t, test.name, scope, sourceID, collectorID, testNow)
			result := readResultFixture(t, []model.Observation{test.observation}, next, ReplayLive, false)
			report, err := runnerFixture(t, newFakeCheckpointRepository(), newFakeSink(), 1).Run(context.Background(), &fakeSource{
				descriptor: descriptor, results: []sourceResponse{{result: result}},
			}, scope)
			if !errors.Is(err, test.want) || report.CheckpointAdvanced {
				t.Fatalf("boundary accepted: report=%+v err=%v", report, err)
			}
		})
	}

	tooMany := []model.Observation{
		observationFixture(t, observationInput{id: "a", scope: scope, source: sourceID, collector: collectorID}),
		observationFixture(t, observationInput{id: "b", scope: scope, source: sourceID, collector: collectorID}),
	}
	next := checkpointFixture(t, "bound", scope, sourceID, collectorID, testNow)
	result := readResultFixture(t, tooMany, next, ReplayLive, true)
	_, err = runnerFixture(t, newFakeCheckpointRepository(), newFakeSink(), 1).Run(context.Background(), &fakeSource{
		descriptor: descriptor, results: []sourceResponse{{result: result}},
	}, scope)
	if !errors.Is(err, ErrBound) {
		t.Fatalf("source exceeded requested bound: %v", err)
	}
}

func TestConcurrentRunsUseCheckpointCompareAndSwap(t *testing.T) {
	scope, sourceID, collectorID := identities(t, "scope-concurrent")
	descriptor := descriptorFixture(t, sourceID, collectorID, 1)
	next := checkpointFixture(t, "concurrent", scope, sourceID, collectorID, testNow)
	observation := observationFixture(t, observationInput{id: "concurrent", scope: scope, source: sourceID, collector: collectorID})
	result := readResultFixture(t, []model.Observation{observation}, next, ReplayLive, false)
	barrier := make(chan struct{})
	ready := make(chan struct{}, 2)
	source := &fakeSource{descriptor: descriptor, read: func(_ context.Context, _ ReadRequest) (ReadResult, error) {
		ready <- struct{}{}
		<-barrier
		return result, nil
	}}
	repository := newFakeCheckpointRepository()
	runner := runnerFixture(t, repository, newFakeSink(), 1)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := runner.Run(context.Background(), source, scope)
			results <- err
		}()
	}
	<-ready
	<-ready
	close(barrier)
	var succeeded, conflicted int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrCheckpointConflict):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("CAS results succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}

type sourceResponse struct {
	result ReadResult
	err    error
}

type fakeSource struct {
	mu          sync.Mutex
	descriptor  Descriptor
	results     []sourceResponse
	read        func(context.Context, ReadRequest) (ReadResult, error)
	requests    []ReadRequest
	lastRequest ReadRequest
}

func (s *fakeSource) Descriptor() Descriptor { return s.descriptor }
func (s *fakeSource) Read(ctx context.Context, request ReadRequest) (ReadResult, error) {
	s.mu.Lock()
	s.requests = append(s.requests, request)
	s.lastRequest = request
	read := s.read
	if read == nil {
		if len(s.results) == 0 {
			s.mu.Unlock()
			return ReadResult{}, errors.New("unexpected read")
		}
		response := s.results[0]
		s.results = s.results[1:]
		s.mu.Unlock()
		return response.result, response.err
	}
	s.mu.Unlock()
	return read(ctx, request)
}
func (s *fakeSource) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

type fakeCheckpointRepository struct {
	mu     sync.Mutex
	values map[CheckpointKey]Checkpoint
}

func newFakeCheckpointRepository() *fakeCheckpointRepository {
	return &fakeCheckpointRepository{values: make(map[CheckpointKey]Checkpoint)}
}
func (r *fakeCheckpointRepository) Load(_ context.Context, key CheckpointKey) (Checkpoint, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.values[key]
	return value, ok, nil
}
func (r *fakeCheckpointRepository) Commit(_ context.Context, key CheckpointKey, expected *Checkpoint, next Checkpoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, found := r.values[key]
	if expected == nil {
		if found {
			return ErrCheckpointConflict
		}
	} else if !found || !sameCheckpoint(current, *expected) {
		return ErrCheckpointConflict
	}
	r.values[key] = next
	return nil
}
func (r *fakeCheckpointRepository) seed(key CheckpointKey, value Checkpoint) {
	r.mu.Lock()
	r.values[key] = value
	r.mu.Unlock()
}
func (r *fakeCheckpointRepository) value(key CheckpointKey) (Checkpoint, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.values[key]
	return value, ok
}

type fakeSink struct {
	mu             sync.Mutex
	values         map[string]model.Observation
	digests        map[string][sha256.Size]byte
	failRecordOnce string
}

func newFakeSink() *fakeSink {
	return &fakeSink{values: make(map[string]model.Observation), digests: make(map[string][sha256.Size]byte)}
}
func (s *fakeSink) Put(_ context.Context, observation model.Observation) (DeliveryDisposition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := observation.Envelope().RecordID()
	if s.failRecordOnce == id {
		s.failRecordOnce = ""
		return "", errors.New("one-time sink failure")
	}
	blob, err := model.MarshalObservationV3(observation)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(blob)
	if previous, ok := s.digests[id]; ok {
		if previous != digest {
			return "", ErrConflictingDuplicate
		}
		return DeliveryDuplicate, nil
	}
	s.digests[id] = digest
	s.values[id] = observation
	return DeliveryStored, nil
}
func (s *fakeSink) observation(id string) model.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.values[id]
}
func (s *fakeSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.values)
}

type observationInput struct {
	id         string
	scope      model.Scope
	source     model.SourceIdentity
	collector  model.CollectorIdentity
	sourceTime *time.Time
	observedAt time.Time
	raw        *model.RawEventReference
	synthetic  bool
}

func observationFixture(t *testing.T, in observationInput) model.Observation {
	t.Helper()
	if in.observedAt.IsZero() {
		in.observedAt = testObserved
	}
	estimate, err := model.NewStorageEstimate(2048, model.EstimateAssumed)
	if err != nil {
		t.Fatal(err)
	}
	modelUse, err := model.NewModelUseGrant(false, "")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := model.NewLifecycle(model.LifecycleInput{
		DataClass: model.DataClassNormalizedObservation, Sensitivity: model.SensitivityConfidential,
		RetentionProfile: model.RetentionOverride, PolicyVersion: "collector-test-v1",
		RetentionDecisionRef: "retention/" + in.id, OverrideVersion: "collector-test-v1",
		RetentionClock: model.RetentionFromObserved, RetentionStart: in.observedAt,
		ExpiresAt: in.observedAt.Add(24 * time.Hour), State: model.LifecycleActive,
		ResidencyPolicyRef: "residency/test-v1", EncryptionKeyRef: "key://test/collector",
		OperationalPolicyRef: "operational/test-v1", PerTenantModelUse: modelUse,
		CrossTenantModelUse: modelUse, EstimatedStorageImpact: estimate,
	})
	if err != nil {
		t.Fatal(err)
	}
	synthetic := model.ProductionContext()
	if in.synthetic {
		synthetic, err = model.NewSyntheticContext("collector-test-scenario")
		if err != nil {
			t.Fatal(err)
		}
	}
	envelope, err := model.NewEnvelope(model.EnvelopeInput{
		RecordID: in.id, SchemaVersion: model.CurrentSchemaVersion, Scope: in.scope,
		Lifecycle: lifecycle, Synthetic: synthetic,
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := model.NewRecordReference(in.id, model.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := model.NewProvenance(root, "normalize.collector-test", "v1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	confidence, err := model.NewConfidence(model.ConfidenceInput{
		Level: model.ConfidenceHigh, Method: model.ConfidenceDirectSource,
		SourceQuality: model.AssuranceDeclared, IdentityAssurance: model.AssuranceUnverified,
		Completeness: model.EvidencePartial, CandidateCount: 1, TimeUncertainty: model.TimeExact,
		AlgorithmID: "normalize.collector-test", AlgorithmVersion: "v1",
		Calibration: model.CalibrationNotApplicable, HumanReview: model.HumanUnreviewed,
	})
	if err != nil {
		t.Fatal(err)
	}
	knowledge, err := model.NewKnowledge(model.KnowledgeInput{
		State: model.KnowledgeSourceObservation, AssertionMode: model.AssertionObserved,
		Producer: model.ProducerDeterministic, Confidence: confidence, Provenance: provenance,
	})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := model.NewObservation(model.ObservationInput{
		Envelope: envelope, Basis: model.ObservationSourceReport, Knowledge: knowledge,
		ObservationType: "test.network.flow", Source: in.source, Collector: in.collector,
		SourceTimestamp: in.sourceTime, ObservedTimestamp: in.observedAt,
		IngestedAt: in.observedAt.Add(time.Second), RawEvent: in.raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func identities(t *testing.T, scopeID string) (model.Scope, model.SourceIdentity, model.CollectorIdentity) {
	t.Helper()
	scope, err := model.NewScope("tenant-test", scopeID, "saas-test", "us-test-1")
	if err != nil {
		t.Fatal(err)
	}
	source, err := model.NewSourceIdentity("test-source", scopeID)
	if err != nil {
		t.Fatal(err)
	}
	collectorID, err := model.NewCollectorIdentity("test-collector", "v1")
	if err != nil {
		t.Fatal(err)
	}
	return scope, source, collectorID
}

func descriptorFixture(t *testing.T, source model.SourceIdentity, collectorID model.CollectorIdentity, maxBatch int) Descriptor {
	t.Helper()
	descriptor, err := NewDescriptor(DescriptorInput{Source: source, Collector: collectorID, Modes: []AcquisitionMode{ModePoll}, MaxBatchSize: maxBatch})
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func checkpointFixture(t *testing.T, suffix string, scope model.Scope, source model.SourceIdentity, collectorID model.CollectorIdentity, createdAt time.Time) Checkpoint {
	t.Helper()
	digest := fmt.Sprintf("%064x", sha256.Sum256([]byte("checkpoint-"+suffix)))
	checkpoint, err := NewCheckpoint(CheckpointInput{
		Reference: checkpointPrefix + digest, Scope: scope, Source: source, Collector: collectorID,
		CreatedAt: createdAt, ObservedThrough: createdAt.Add(-time.Second), ExpiresAt: createdAt.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return checkpoint
}

func readResultFixture(t *testing.T, observations []model.Observation, next Checkpoint, state ReplayState, more bool) ReadResult {
	t.Helper()
	replay, err := NewReplayDisposition(state, ReplayReasonNone, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewReadResult(ReadResultInput{Observations: observations, NextCheckpoint: &next, Replay: replay, MoreAvailable: more})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func runnerFixture(t *testing.T, repository CheckpointRepository, sink ObservationSink, maxBatch int) *Runner {
	t.Helper()
	runner, err := NewRunner(repository, sink, func() time.Time { return testNow }, maxBatch)
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func checkpointKey(scope model.Scope, source model.SourceIdentity, collectorID model.CollectorIdentity) CheckpointKey {
	return CheckpointKey{Scope: scope, Source: source, Collector: collectorID}
}

func sameCheckpoint(left, right Checkpoint) bool {
	return left.reference == right.reference && sameScope(left.scope, right.scope) &&
		sameSource(left.source, right.source) && sameCollector(left.collector, right.collector) &&
		left.createdAt.Equal(right.createdAt) && left.observedThrough.Equal(right.observedThrough) && left.expiresAt.Equal(right.expiresAt)
}
