package trace

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/correlation"
	"github.com/canarysting/canarysting/internal/canaryview/model"
)

const (
	DefaultAlgorithmID      = "canaryview.trace.builder"
	DefaultAlgorithmVersion = "1"
	maximumConfiguredBound  = 1 << 16
)

// BuilderConfig makes every collection bound explicit. Input over a bound is
// rejected as a whole; trace construction never silently truncates evidence.
type BuilderConfig struct {
	AlgorithmID                 string
	AlgorithmVersion            string
	MaxHops                     int
	MaxCorrelations             int
	MaxCandidatesPerCorrelation int
	MaxMatchesPerCandidate      int
	MaxTranslationHopsPerMatch  int
	MaxCorrelationWork          int
	MaxConflicts                int
	MaxEvidencePerConflict      int
	MaxExpectations             int
	MaxEvidencePerHop           int
	MaxLineage                  int
}

func DefaultBuilderConfig() BuilderConfig {
	return BuilderConfig{
		AlgorithmID: DefaultAlgorithmID, AlgorithmVersion: DefaultAlgorithmVersion,
		MaxHops: 256, MaxCorrelations: 256, MaxCandidatesPerCorrelation: 256,
		MaxMatchesPerCandidate: 32, MaxTranslationHopsPerMatch: 8,
		MaxCorrelationWork: 65536, MaxConflicts: 128, MaxEvidencePerConflict: 32,
		MaxExpectations: 256, MaxEvidencePerHop: 32,
		MaxLineage: 4096,
	}
}

type Builder struct {
	config BuilderConfig
}

func NewBuilder(config BuilderConfig) (*Builder, error) {
	if err := validateBuilderConfig(config); err != nil {
		return nil, err
	}
	return &Builder{config: config}, nil
}

func (b *Builder) Config() BuilderConfig {
	if b == nil {
		return BuilderConfig{}
	}
	return b.config
}

// Build creates one closed immutable trace projection. Open-trace mutation is
// intentionally absent; a later observation produces a new immutable trace.
func (b *Builder) Build(in BuildInput) (Trace, error) {
	if b == nil {
		return Trace{}, fmt.Errorf("trace builder is required")
	}
	if err := validateScope(in.Scope); err != nil {
		return Trace{}, fmt.Errorf("scope: %w", err)
	}
	if err := in.Synthetic.Validate(); err != nil {
		return Trace{}, fmt.Errorf("trace synthetic context: %w", err)
	}
	if len(in.Hops) == 0 || len(in.Hops) > b.config.MaxHops {
		return Trace{}, fmt.Errorf("trace hops must be between 1 and %d", b.config.MaxHops)
	}
	if len(in.Correlations) > b.config.MaxCorrelations {
		return Trace{}, fmt.Errorf("trace correlations exceed configured limit %d", b.config.MaxCorrelations)
	}
	if len(in.Expectations) == 0 || len(in.Expectations) > b.config.MaxExpectations {
		return Trace{}, fmt.Errorf("declared coverage expectations must be between 1 and %d", b.config.MaxExpectations)
	}
	if len(in.Conflicts) > b.config.MaxConflicts {
		return Trace{}, fmt.Errorf("trace conflicts exceed configured limit %d", b.config.MaxConflicts)
	}
	if err := b.validateCorrelationWork(in.Correlations); err != nil {
		return Trace{}, err
	}
	if in.ClosedAt.IsZero() || in.BuiltAt.IsZero() {
		return Trace{}, fmt.Errorf("trace close and build times are required")
	}
	closedAt, builtAt := in.ClosedAt.UTC(), in.BuiltAt.UTC()
	if builtAt.Before(closedAt) {
		return Trace{}, fmt.Errorf("trace build time cannot precede close time")
	}
	if err := validateReference(in.HighWaterMark); err != nil {
		return Trace{}, fmt.Errorf("input high-water mark: %w", err)
	}

	hops, records, validFrom, validTo, err := b.normalizeHops(in.Scope, in.Synthetic, in.Hops)
	if err != nil {
		return Trace{}, err
	}
	if closedAt.Before(validTo) {
		return Trace{}, fmt.Errorf("trace close time cannot precede its validity window")
	}
	lifecycle, err := canonicalTraceLifecycle(in.Lifecycle, closedAt)
	if err != nil {
		return Trace{}, err
	}
	correlations, err := b.normalizeCorrelations(in.Correlations, records)
	if err != nil {
		return Trace{}, err
	}
	expectations, err := b.normalizeExpectations(in.Expectations, records)
	if err != nil {
		return Trace{}, err
	}
	conflicts, err := b.normalizeConflicts(in.Conflicts, correlations, records)
	if err != nil {
		return Trace{}, err
	}
	expectations, missing, err := b.evaluateCoverage(expectations, hops, correlations)
	if err != nil {
		return Trace{}, err
	}

	status := StatusComplete
	if len(missing) > 0 {
		status = StatusPartial
	}
	if len(conflicts) > 0 {
		status = StatusConflicted
	}

	lineage, err := b.lineage(in.HighWaterMark, hops, correlations, conflicts)
	if err != nil {
		return Trace{}, err
	}
	semantic := semanticParts(in.Scope, in.Synthetic, status, validFrom, validTo, closedAt, in.HighWaterMark, hops, correlations, expectations, missing, conflicts)
	traceID := "trace:sha256:" + digest(append([]string{b.config.AlgorithmID, b.config.AlgorithmVersion}, semantic...)...)
	root, err := model.NewRecordReference(traceID, model.CurrentSchemaVersion)
	if err != nil {
		return Trace{}, err
	}
	for _, parent := range lineage {
		if parent == root {
			return Trace{}, fmt.Errorf("trace cannot cite itself as lineage")
		}
	}
	envelope, err := model.NewEnvelope(model.EnvelopeInput{
		RecordID: traceID, SchemaVersion: model.CurrentSchemaVersion, Scope: in.Scope,
		Lifecycle: lifecycle, DerivationLineage: lineage, Synthetic: in.Synthetic,
	})
	if err != nil {
		return Trace{}, fmt.Errorf("trace envelope: %w", err)
	}
	knowledge, err := b.knowledge(root, lineage, status, validFrom, validTo, correlations, missing, conflicts)
	if err != nil {
		return Trace{}, err
	}
	integrityParts := append([]string{traceID, builtAt.Format(time.RFC3339Nano)}, semantic...)
	integrityParts = append(integrityParts, lifecycleParts(lifecycle)...)
	return Trace{
		envelope: envelope, knowledge: knowledge, status: status,
		validFrom: validFrom, validTo: validTo, closedAt: closedAt, builtAt: builtAt,
		highWaterMark: in.HighWaterMark, hops: hops, correlations: correlations,
		expectations: expectations, missingTelemetry: missing, conflicts: conflicts,
		integrityDigest: "trace-integrity:sha256:" + digest(integrityParts...),
	}, nil
}

func (b *Builder) normalizeHops(scope model.Scope, synthetic model.SyntheticContext, inputs []HopInput) ([]Hop, map[string]correlation.Record, time.Time, time.Time, error) {
	hops := make([]Hop, 0, len(inputs))
	records := make(map[string]correlation.Record, len(inputs))
	var validFrom, validTo time.Time
	for index, input := range inputs {
		if !input.Kind.valid() {
			return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("hop %d has unsupported kind %q", index, input.Kind)
		}
		if !sameScope(scope, input.Record.Scope()) {
			return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("hop %q is outside trace scope", input.Record.Reference().ID())
		}
		if !sameSyntheticContext(synthetic, input.Record.Synthetic()) {
			return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("hop %q synthetic context differs from trace", input.Record.Reference().ID())
		}
		if err := validateReference(input.Record.Reference()); err != nil {
			return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("hop %d reference: %w", index, err)
		}
		key := referenceKey(input.Record.Reference())
		if _, duplicate := records[key]; duplicate {
			return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("duplicate trace hop %q", input.Record.Reference().ID())
		}
		if len(input.Evidence) > b.config.MaxEvidencePerHop {
			return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("hop %q evidence exceeds configured limit %d", input.Record.Reference().ID(), b.config.MaxEvidencePerHop)
		}
		evidence, err := canonicalEvidence(input.Evidence)
		if err != nil {
			return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("hop %q evidence: %w", input.Record.Reference().ID(), err)
		}
		var raw *model.RawEventReference
		if input.RawEvent != nil {
			canonical, rawErr := model.NewRawEventReference(input.RawEvent.Reference(), input.RawEvent.Availability(), input.RawEvent.HashAlgorithm(), input.RawEvent.HashValue())
			if rawErr != nil {
				return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("hop %q raw reference: %w", input.Record.Reference().ID(), rawErr)
			}
			raw = &canonical
		}
		var eventTime *correlation.EventTime
		if value, ok := input.Record.Time(); ok {
			canonical, timeErr := correlation.NewEventTime(value.At(), value.Uncertainty())
			if timeErr != nil {
				return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("hop %q time: %w", input.Record.Reference().ID(), timeErr)
			}
			eventTime = &canonical
			start, end := canonical.At().Add(-canonical.Uncertainty()), canonical.At().Add(canonical.Uncertainty())
			if validFrom.IsZero() || start.Before(validFrom) {
				validFrom = start
			}
			if validTo.IsZero() || end.After(validTo) {
				validTo = end
			}
		}
		hop := Hop{
			reference: input.Record.Reference(), kind: input.Kind, eventTime: eventTime,
			identities: input.Record.Identities(), rawEvent: raw, evidence: evidence,
		}
		hops = append(hops, hop)
		records[key] = input.Record
	}
	if validFrom.IsZero() {
		return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("at least one trace hop requires event time")
	}
	sort.Slice(hops, func(i, j int) bool {
		left, leftOK := hops[i].Time()
		right, rightOK := hops[j].Time()
		if leftOK != rightOK {
			return leftOK
		}
		if leftOK {
			leftStart, rightStart := left.At().Add(-left.Uncertainty()), right.At().Add(-right.Uncertainty())
			if !leftStart.Equal(rightStart) {
				return leftStart.Before(rightStart)
			}
		}
		return referenceKey(hops[i].reference) < referenceKey(hops[j].reference)
	})
	return hops, records, validFrom.UTC(), validTo.UTC(), nil
}

func (b *Builder) normalizeCorrelations(results []correlation.Result, records map[string]correlation.Record) ([]CorrelationSet, error) {
	sets := make([]CorrelationSet, 0, len(results))
	seen := make(map[string]bool, len(results))
	for index, result := range results {
		if err := boundedRequired("correlation algorithm id", result.AlgorithmID()); err != nil {
			return nil, fmt.Errorf("correlation %d: %w", index, err)
		}
		if err := boundedRequired("correlation algorithm version", result.AlgorithmVersion()); err != nil {
			return nil, fmt.Errorf("correlation %d: %w", index, err)
		}
		anchorKey := referenceKey(result.Anchor())
		anchorRecord, exists := records[anchorKey]
		if !exists {
			return nil, fmt.Errorf("correlation anchor %q is not a trace hop", result.Anchor().ID())
		}
		if !result.MatchesAnchor(anchorRecord) {
			return nil, fmt.Errorf("correlation anchor %q does not match the exact trace-hop input", result.Anchor().ID())
		}
		if seen[anchorKey] {
			return nil, fmt.Errorf("duplicate correlation anchor %q", result.Anchor().ID())
		}
		seen[anchorKey] = true
		if len(result.Candidates()) > b.config.MaxCandidatesPerCorrelation || len(result.Rejected()) > b.config.MaxCandidatesPerCorrelation {
			return nil, fmt.Errorf("correlation %q exceeds candidate/rejection limit %d", result.Anchor().ID(), b.config.MaxCandidatesPerCorrelation)
		}
		set := CorrelationSet{
			anchor: result.Anchor(), algorithmID: result.AlgorithmID(), algorithmVersion: result.AlgorithmVersion(),
			anchorMissing: append([]correlation.MissingKey(nil), result.AnchorMissingKeys()...), ambiguous: result.Ambiguous(),
		}
		for _, sourceCandidate := range result.Candidates() {
			candidateRecord, exists := records[referenceKey(sourceCandidate.Reference())]
			if !exists {
				return nil, fmt.Errorf("correlation candidate %q is not a trace hop", sourceCandidate.Reference().ID())
			}
			if !sourceCandidate.MatchesRecord(candidateRecord) {
				return nil, fmt.Errorf("correlation candidate %q does not match the exact trace-hop input", sourceCandidate.Reference().ID())
			}
			matches := sourceCandidate.Matches()
			if len(matches) == 0 || len(matches) > b.config.MaxMatchesPerCandidate {
				return nil, fmt.Errorf("candidate %q matches must be between 1 and %d", sourceCandidate.Reference().ID(), b.config.MaxMatchesPerCandidate)
			}
			candidate := Candidate{
				reference: sourceCandidate.Reference(), strength: sourceCandidate.Strength(), confidence: sourceCandidate.Confidence(),
				missing: append([]correlation.MissingKey(nil), sourceCandidate.MissingKeys()...), pathAmbiguous: sourceCandidate.TranslationPathAmbiguous(),
			}
			for _, match := range matches {
				path := match.TranslationPath()
				if len(path) > b.config.MaxTranslationHopsPerMatch {
					return nil, fmt.Errorf("candidate %q translation path exceeds limit %d", sourceCandidate.Reference().ID(), b.config.MaxTranslationHopsPerMatch)
				}
				citations := []model.RecordReference{result.Anchor(), sourceCandidate.Reference()}
				explanation := JoinExplanation{
					method: match.Method(), strength: match.Strength(), keyFingerprint: match.KeyFingerprint(),
					timeGap: match.TimeGap(), window: match.Window(),
				}
				if err := boundedRequired("join key fingerprint", explanation.keyFingerprint); err != nil {
					return nil, fmt.Errorf("candidate %q: %w", sourceCandidate.Reference().ID(), err)
				}
				for _, hop := range path {
					translation := hop.Translation()
					if !sameScope(translation.Scope(), anchorRecord.Scope()) {
						return nil, fmt.Errorf("candidate %q translation %q is outside trace scope", sourceCandidate.Reference().ID(), translation.Reference().ID())
					}
					if !sameSyntheticContext(translation.Synthetic(), anchorRecord.Synthetic()) {
						return nil, fmt.Errorf("candidate %q translation %q synthetic context differs from trace", sourceCandidate.Reference().ID(), translation.Reference().ID())
					}
					citations = append(citations, translation.Reference())
					explanation.translations = append(explanation.translations, TranslationStep{
						reference: translation.Reference(), before: translation.Before(), after: translation.After(),
						control: translation.Control(), observedAt: translation.ObservedAt(), direction: hop.Direction(),
					})
				}
				var citationErr error
				explanation.citations, citationErr = sortedReferences(citations)
				if citationErr != nil {
					return nil, fmt.Errorf("candidate %q citations: %w", sourceCandidate.Reference().ID(), citationErr)
				}
				candidate.explanations = append(candidate.explanations, explanation)
			}
			set.candidates = append(set.candidates, candidate)
		}
		for _, sourceRejection := range result.Rejected() {
			rejectionRecord, exists := records[referenceKey(sourceRejection.Reference())]
			if !exists {
				return nil, fmt.Errorf("correlation rejection %q is not a trace hop", sourceRejection.Reference().ID())
			}
			if !sourceRejection.MatchesRecord(rejectionRecord) {
				return nil, fmt.Errorf("correlation rejection %q does not match the exact trace-hop input", sourceRejection.Reference().ID())
			}
			set.rejections = append(set.rejections, Rejection{
				reference: sourceRejection.Reference(), reasons: append([]correlation.RejectionReason(nil), sourceRejection.Reasons()...),
				missing: append([]correlation.MissingKey(nil), sourceRejection.MissingKeys()...),
			})
		}
		if chosen, ok := result.Chosen(); ok {
			ref := chosen.Reference()
			set.chosen = &ref
		}
		sets = append(sets, set)
	}
	sort.Slice(sets, func(i, j int) bool { return referenceKey(sets[i].anchor) < referenceKey(sets[j].anchor) })
	return sets, nil
}

func (b *Builder) validateCorrelationWork(results []correlation.Result) error {
	work := 0
	consume := func(amount int) error {
		if amount < 0 || amount > b.config.MaxCorrelationWork-work {
			return fmt.Errorf("aggregate correlation work exceeds configured limit %d", b.config.MaxCorrelationWork)
		}
		work += amount
		return nil
	}
	for _, result := range results {
		candidates := result.Candidates()
		rejections := result.Rejected()
		if err := consume(1 + len(candidates) + len(rejections)); err != nil {
			return err
		}
		for _, candidate := range candidates {
			matches := candidate.Matches()
			if err := consume(len(matches)); err != nil {
				return err
			}
			for _, match := range matches {
				if err := consume(len(match.TranslationPath())); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (b *Builder) normalizeExpectations(inputs []ExpectationInput, records map[string]correlation.Record) ([]Expectation, error) {
	result := make([]Expectation, 0, len(inputs))
	seen := make(map[string]bool, len(inputs))
	for index, input := range inputs {
		if !input.Kind.valid() {
			return nil, fmt.Errorf("expectation %d has unsupported kind %q", index, input.Kind)
		}
		requiresRecord := input.Kind == ExpectSourceTime || input.Kind == ExpectRawEvidence
		forbidsRecord := input.Kind == ExpectObservation || input.Kind == ExpectPolicyDecision
		if requiresRecord && input.Record == nil {
			return nil, fmt.Errorf("expectation %s requires a record", input.Kind)
		}
		if forbidsRecord && input.Record != nil {
			return nil, fmt.Errorf("expectation %s applies to the whole trace", input.Kind)
		}
		var ref *model.RecordReference
		key := string(input.Kind)
		if input.Record != nil {
			if err := validateReference(*input.Record); err != nil {
				return nil, fmt.Errorf("expectation %d record: %w", index, err)
			}
			if _, exists := records[referenceKey(*input.Record)]; !exists {
				return nil, fmt.Errorf("expectation record %q is not a trace hop", input.Record.ID())
			}
			copyRef := *input.Record
			ref = &copyRef
			key += "\x00" + referenceKey(copyRef)
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate declared-coverage expectation %q", key)
		}
		seen[key] = true
		result = append(result, Expectation{kind: input.Kind, reference: ref})
	}
	sort.Slice(result, func(i, j int) bool { return expectationKey(result[i]) < expectationKey(result[j]) })
	return result, nil
}

func (b *Builder) normalizeConflicts(inputs []ConflictInput, correlations []CorrelationSet, records map[string]correlation.Record) ([]Conflict, error) {
	result := make([]Conflict, 0, len(inputs)+len(correlations))
	for index, input := range inputs {
		if !input.Kind.valid() {
			return nil, fmt.Errorf("conflict %d has unsupported kind %q", index, input.Kind)
		}
		references, err := sortedReferences(input.Records)
		if err != nil || len(references) < 2 {
			return nil, fmt.Errorf("conflict %d requires at least two distinct valid record references", index)
		}
		for _, ref := range references {
			if _, exists := records[referenceKey(ref)]; !exists {
				return nil, fmt.Errorf("conflict record %q is not a trace hop", ref.ID())
			}
		}
		if len(input.Evidence) > b.config.MaxEvidencePerConflict {
			return nil, fmt.Errorf("conflict %d evidence exceeds configured limit %d", index, b.config.MaxEvidencePerConflict)
		}
		evidence, err := canonicalEvidence(input.Evidence)
		if err != nil {
			return nil, fmt.Errorf("conflict %d evidence: %w", index, err)
		}
		if input.Kind == ConflictContradictoryEvidence && len(evidence) == 0 {
			return nil, fmt.Errorf("contradictory-evidence conflict requires evidence")
		}
		for _, ref := range evidence {
			if ref.Role() != model.EvidenceContradicting {
				return nil, fmt.Errorf("conflict evidence %q must have CONTRADICTING role", ref.ID())
			}
		}
		result = append(result, Conflict{kind: input.Kind, records: references, evidence: evidence})
	}
	for _, set := range correlations {
		if !set.ambiguous {
			continue
		}
		if len(result) >= b.config.MaxConflicts {
			return nil, fmt.Errorf("combined explicit and correlation conflicts exceed configured limit %d", b.config.MaxConflicts)
		}
		references := []model.RecordReference{set.anchor}
		for _, candidate := range set.candidates {
			references = append(references, candidate.reference)
		}
		references, err := sortedReferences(references)
		if err != nil {
			return nil, err
		}
		result = append(result, Conflict{kind: ConflictAmbiguousCorrelation, records: references})
	}
	if len(result) > b.config.MaxConflicts {
		return nil, fmt.Errorf("derived trace conflicts exceed configured limit %d", b.config.MaxConflicts)
	}
	sort.Slice(result, func(i, j int) bool { return conflictKey(result[i]) < conflictKey(result[j]) })
	for index := 1; index < len(result); index++ {
		if conflictKey(result[index-1]) == conflictKey(result[index]) {
			return nil, fmt.Errorf("duplicate trace conflict")
		}
	}
	return result, nil
}

func (b *Builder) evaluateCoverage(expectations []Expectation, hops []Hop, correlations []CorrelationSet) ([]Expectation, []MissingTelemetry, error) {
	all := append([]Expectation(nil), expectations...)
	seen := make(map[string]bool, len(all))
	for _, expectation := range all {
		seen[expectationKey(expectation)] = true
	}
	for _, hop := range hops {
		if hop.rawEvent == nil || hop.rawEvent.Availability() == model.RawAvailable {
			continue
		}
		ref := hop.reference
		expectation := Expectation{kind: ExpectRawEvidence, reference: &ref}
		if !seen[expectationKey(expectation)] {
			seen[expectationKey(expectation)] = true
			all = append(all, expectation)
		}
	}
	if len(all) > b.config.MaxExpectations {
		return nil, nil, fmt.Errorf("declared and broken-reference expectations exceed configured limit %d", b.config.MaxExpectations)
	}
	sort.Slice(all, func(i, j int) bool { return expectationKey(all[i]) < expectationKey(all[j]) })
	missing := make([]MissingTelemetry, 0)
	for _, expectation := range all {
		present := false
		var availability *model.RawAvailability
		switch expectation.kind {
		case ExpectObservation, ExpectPolicyDecision:
			wanted := HopObservation
			if expectation.kind == ExpectPolicyDecision {
				wanted = HopPolicyDecision
			}
			for _, hop := range hops {
				if hop.kind == wanted {
					present = true
					break
				}
			}
		case ExpectSourceTime:
			hop := findHop(hops, *expectation.reference)
			_, present = hop.Time()
		case ExpectRawEvidence:
			hop := findHop(hops, *expectation.reference)
			if raw, ok := hop.RawEvent(); ok {
				value := raw.Availability()
				availability = &value
				present = value == model.RawAvailable
			}
		case ExpectCorrelation:
			for _, set := range correlations {
				if expectation.reference != nil && set.anchor != *expectation.reference {
					continue
				}
				if set.chosen != nil {
					present = true
					break
				}
			}
		}
		if !present {
			missing = append(missing, MissingTelemetry{expectation: expectation, availability: availability})
		}
	}
	return all, missing, nil
}

func (b *Builder) lineage(highWater model.RecordReference, hops []Hop, correlations []CorrelationSet, conflicts []Conflict) ([]model.RecordReference, error) {
	refs, err := traceLineage(highWater, hops, correlations, conflicts)
	if err != nil {
		return nil, err
	}
	if len(refs) > b.config.MaxLineage {
		return nil, fmt.Errorf("trace lineage exceeds configured limit %d", b.config.MaxLineage)
	}
	return refs, nil
}

func (b *Builder) knowledge(root model.RecordReference, lineage []model.RecordReference, status Status, validFrom, validTo time.Time, correlations []CorrelationSet, missing []MissingTelemetry, conflicts []Conflict) (model.Knowledge, error) {
	links := make([]model.LineageLink, 0, len(lineage))
	for _, parent := range lineage {
		link, err := model.NewLineageLink(root, parent)
		if err != nil {
			return model.Knowledge{}, err
		}
		links = append(links, link)
	}
	provenance, err := model.NewProvenance(root, b.config.AlgorithmID, b.config.AlgorithmVersion, lineage, links)
	if err != nil {
		return model.Knowledge{}, fmt.Errorf("trace provenance: %w", err)
	}
	candidateCount := uint32(0)
	allHigh := len(correlations) > 0
	for _, set := range correlations {
		candidateCount += uint32(len(set.candidates))
		if set.chosen == nil {
			allHigh = false
			continue
		}
		for _, candidate := range set.candidates {
			if candidate.reference == *set.chosen && candidate.confidence.Level() != model.ConfidenceHigh {
				allHigh = false
			}
		}
	}
	if candidateCount == 0 {
		candidateCount = 1
	}
	level := model.ConfidenceLow
	if status == StatusComplete {
		level = model.ConfidenceMedium
		if allHigh {
			level = model.ConfidenceHigh
		}
	}
	timeUncertainty, window := model.TimeExact, time.Duration(0)
	if validTo.After(validFrom) {
		timeUncertainty, window = model.TimeBounded, validTo.Sub(validFrom)
	}
	confidence, err := model.NewConfidence(model.ConfidenceInput{
		Level: level, Method: model.ConfidenceCompositeCorrelation,
		SourceQuality: model.AssuranceDeclared, IdentityAssurance: model.AssuranceUnverified,
		Completeness:   map[bool]model.EvidenceCompleteness{true: model.EvidenceComplete, false: model.EvidencePartial}[len(missing) == 0],
		CandidateCount: candidateCount, TimeUncertainty: timeUncertainty, TimeWindow: window,
		AlgorithmID: b.config.AlgorithmID, AlgorithmVersion: b.config.AlgorithmVersion,
		Calibration: model.CalibrationNotApplicable, HumanReview: model.HumanUnreviewed,
	})
	if err != nil {
		return model.Knowledge{}, err
	}
	missingKinds := make([]model.MissingEvidenceKind, 0, len(missing))
	missingSet := make(map[model.MissingEvidenceKind]bool)
	for _, gap := range missing {
		kind := model.MissingSupportingEvidence
		switch gap.expectation.kind {
		case ExpectSourceTime:
			kind = model.MissingSourceTimestamp
		case ExpectRawEvidence:
			kind = model.MissingRawEvent
		}
		if !missingSet[kind] {
			missingSet[kind] = true
			missingKinds = append(missingKinds, kind)
		}
	}
	conflicting := make([]model.EvidenceReference, 0)
	for _, conflict := range conflicts {
		conflicting = append(conflicting, conflict.evidence...)
	}
	conflicting, err = uniqueEvidence(conflicting)
	if err != nil {
		return model.Knowledge{}, err
	}
	return model.NewKnowledge(model.KnowledgeInput{
		State: model.KnowledgeCorrelation, AssertionMode: model.AssertionInferred, Producer: model.ProducerCorrelation,
		Confidence: confidence, Provenance: provenance, MissingEvidence: missingKinds, ConflictingEvidence: conflicting,
	})
}

func canonicalTraceLifecycle(value model.Lifecycle, closedAt time.Time) (model.Lifecycle, error) {
	canonical, err := model.NewLifecycle(model.LifecycleInput{
		DataClass: value.DataClass(), Sensitivity: value.Sensitivity(), RetentionProfile: value.RetentionProfile(),
		PolicyVersion: value.PolicyVersion(), RetentionDecisionRef: value.RetentionDecisionRef(), OverrideVersion: value.OverrideVersion(),
		RetentionClock: value.RetentionClock(), RetentionStart: value.RetentionStart(), ExpiresAt: value.ExpiresAt(),
		State: value.State(), LegalHoldIDs: value.LegalHoldIDs(), ResidencyPolicyRef: value.ResidencyPolicyRef(),
		EncryptionKeyRef: value.EncryptionKeyRef(), OperationalPolicyRef: value.OperationalPolicyRef(),
		PerTenantModelUse: value.PerTenantModelUse(), CrossTenantModelUse: value.CrossTenantModelUse(),
		EstimatedStorageImpact: value.EstimatedStorageImpact(),
	})
	if err != nil {
		return model.Lifecycle{}, fmt.Errorf("trace lifecycle: %w", err)
	}
	if canonical.DataClass() != model.DataClassCorrelatedTrace {
		return model.Lifecycle{}, fmt.Errorf("trace lifecycle requires data class %s", model.DataClassCorrelatedTrace)
	}
	if canonical.Sensitivity() != model.SensitivityConfidential {
		return model.Lifecycle{}, fmt.Errorf("correlated traces require %s sensitivity", model.SensitivityConfidential)
	}
	if canonical.RetentionClock() != model.RetentionFromTraceClose || !canonical.RetentionStart().Equal(closedAt) {
		return model.Lifecycle{}, fmt.Errorf("trace retention must start at the exact trace close time")
	}
	return canonical, nil
}

func canonicalEvidence(values []model.EvidenceReference) ([]model.EvidenceReference, error) {
	result := make([]model.EvidenceReference, 0, len(values))
	for _, value := range values {
		canonical, err := model.NewEvidenceReference(value.ID(), value.SchemaVersion(), value.Role(), value.ExtensionNamespace(), value.ExtensionVersion())
		if err != nil {
			return nil, err
		}
		result = append(result, canonical)
	}
	sort.Slice(result, func(i, j int) bool {
		return referenceKey(evidenceReference(result[i])) < referenceKey(evidenceReference(result[j]))
	})
	for index := 1; index < len(result); index++ {
		if evidenceReference(result[index-1]) == evidenceReference(result[index]) {
			return nil, fmt.Errorf("duplicate evidence reference %q", result[index].ID())
		}
	}
	return result, nil
}

func uniqueEvidence(values []model.EvidenceReference) ([]model.EvidenceReference, error) {
	byReference := make(map[string]model.EvidenceReference, len(values))
	for _, value := range values {
		canonical, err := model.NewEvidenceReference(value.ID(), value.SchemaVersion(), value.Role(), value.ExtensionNamespace(), value.ExtensionVersion())
		if err != nil {
			return nil, err
		}
		key := referenceKey(evidenceReference(canonical))
		if existing, ok := byReference[key]; ok && (existing.Role() != canonical.Role() || existing.ExtensionNamespace() != canonical.ExtensionNamespace() || existing.ExtensionVersion() != canonical.ExtensionVersion()) {
			return nil, fmt.Errorf("evidence reference %q has inconsistent metadata", canonical.ID())
		}
		byReference[key] = canonical
	}
	result := make([]model.EvidenceReference, 0, len(byReference))
	for _, value := range byReference {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		return referenceKey(evidenceReference(result[i])) < referenceKey(evidenceReference(result[j]))
	})
	return result, nil
}

func evidenceReference(value model.EvidenceReference) model.RecordReference {
	ref, _ := model.NewRecordReference(value.ID(), value.SchemaVersion())
	return ref
}

func semanticParts(scope model.Scope, synthetic model.SyntheticContext, status Status, validFrom, validTo, closedAt time.Time, highWater model.RecordReference, hops []Hop, correlations []CorrelationSet, expectations []Expectation, missing []MissingTelemetry, conflicts []Conflict) []string {
	parts := []string{
		scope.TenantID(), scope.ScopeID(), scope.DeploymentBoundary(), scope.ResidencyCellID(), string(status),
		fmt.Sprint(synthetic.Synthetic()), synthetic.ScenarioID(),
		validFrom.Format(time.RFC3339Nano), validTo.Format(time.RFC3339Nano), closedAt.Format(time.RFC3339Nano), referenceKey(highWater),
	}
	for _, hop := range hops {
		parts = append(parts, "hop", referenceKey(hop.reference), string(hop.kind))
		if eventTime, ok := hop.Time(); ok {
			parts = append(parts, eventTime.At().Format(time.RFC3339Nano), eventTime.Uncertainty().String())
		} else {
			parts = append(parts, "missing-time")
		}
		if raw, ok := hop.RawEvent(); ok {
			parts = append(parts, raw.Reference(), string(raw.Availability()), raw.HashAlgorithm(), raw.HashValue())
		} else {
			parts = append(parts, "missing-raw")
		}
		for _, identity := range hop.identities {
			parts = append(parts, identityParts(identity)...)
		}
		for _, evidence := range hop.evidence {
			parts = append(parts, evidenceParts(evidence)...)
		}
	}
	for _, set := range correlations {
		parts = append(parts, "correlation", referenceKey(set.anchor), set.algorithmID, set.algorithmVersion, fmt.Sprint(set.ambiguous))
		for _, missingKey := range set.anchorMissing {
			parts = append(parts, "anchor-missing", string(missingKey))
		}
		if set.chosen != nil {
			parts = append(parts, "chosen", referenceKey(*set.chosen))
		}
		for _, candidate := range set.candidates {
			parts = append(parts, "candidate", referenceKey(candidate.reference), string(candidate.strength), fmt.Sprint(candidate.pathAmbiguous))
			parts = append(parts, confidenceParts(candidate.confidence)...)
			for _, missingKey := range candidate.missing {
				parts = append(parts, "candidate-missing", string(missingKey))
			}
			for _, explanation := range candidate.explanations {
				parts = append(parts, string(explanation.method), string(explanation.strength), explanation.keyFingerprint, explanation.timeGap.String(), explanation.window.String())
				for _, citation := range explanation.citations {
					parts = append(parts, referenceKey(citation))
				}
				for _, step := range explanation.translations {
					parts = append(parts, referenceKey(step.reference), string(step.direction), step.control.Kind(), step.control.ID(), tuplePart(step.before), tuplePart(step.after), step.observedAt.At().Format(time.RFC3339Nano), step.observedAt.Uncertainty().String())
				}
			}
		}
		for _, rejection := range set.rejections {
			parts = append(parts, "rejected", referenceKey(rejection.reference))
			for _, reason := range rejection.reasons {
				parts = append(parts, string(reason))
			}
			for _, missingKey := range rejection.missing {
				parts = append(parts, "rejection-missing", string(missingKey))
			}
		}
	}
	for _, expectation := range expectations {
		parts = append(parts, "expectation", expectationKey(expectation))
	}
	for _, gap := range missing {
		parts = append(parts, "missing", expectationKey(gap.expectation))
		if gap.availability != nil {
			parts = append(parts, string(*gap.availability))
		}
	}
	for _, conflict := range conflicts {
		parts = append(parts, "conflict", conflictKey(conflict))
	}
	return parts
}

func identityParts(value model.EntityReference) []string {
	parts := []string{"identity", value.Kind(), value.ID(), string(value.AssertionMode())}
	verification, ok := value.Verification()
	if !ok {
		return append(parts, "unverified")
	}
	parts = append(parts, "verification", verification.ProcedureID(), verification.ProcedureVersion(), string(verification.Producer()))
	for _, evidence := range verification.Evidence() {
		parts = append(parts, evidenceParts(evidence)...)
	}
	return parts
}

func evidenceParts(value model.EvidenceReference) []string {
	return []string{
		"evidence", referenceKey(evidenceReference(value)), string(value.Role()),
		value.ExtensionNamespace(), value.ExtensionVersion(),
	}
}

func confidenceParts(value model.Confidence) []string {
	return []string{
		"confidence", string(value.Level()), string(value.Method()), string(value.SourceQuality()),
		string(value.IdentityAssurance()), string(value.Completeness()), fmt.Sprint(value.CandidateCount()),
		string(value.TimeUncertainty()), value.TimeWindow().String(), value.AlgorithmID(), value.AlgorithmVersion(),
		string(value.Calibration()), string(value.HumanReview()),
	}
}

func uniqueReferences(values []model.RecordReference) ([]model.RecordReference, error) {
	byReference := make(map[string]model.RecordReference, len(values))
	for _, value := range values {
		if err := validateReference(value); err != nil {
			return nil, err
		}
		byReference[referenceKey(value)] = value
	}
	result := make([]model.RecordReference, 0, len(byReference))
	for _, value := range byReference {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return referenceKey(result[i]) < referenceKey(result[j]) })
	return result, nil
}

func lifecycleParts(value model.Lifecycle) []string {
	parts := []string{
		string(value.DataClass()), string(value.Sensitivity()), string(value.RetentionProfile()), value.PolicyVersion(), value.RetentionDecisionRef(), value.OverrideVersion(),
		string(value.RetentionClock()), value.RetentionStart().Format(time.RFC3339Nano), value.ExpiresAt().Format(time.RFC3339Nano), string(value.State()),
		value.ResidencyPolicyRef(), value.EncryptionKeyRef(), value.OperationalPolicyRef(),
		fmt.Sprint(value.PerTenantModelUse().Allowed()), value.PerTenantModelUse().PolicyRef(),
		fmt.Sprint(value.CrossTenantModelUse().Allowed()), value.CrossTenantModelUse().PolicyRef(),
		fmt.Sprint(value.EstimatedStorageImpact().Bytes()), string(value.EstimatedStorageImpact().Basis()),
	}
	return append(parts, value.LegalHoldIDs()...)
}

func tuplePart(value correlation.NetworkTuple) string {
	return fmt.Sprintf("%s/%s/%d/%s/%d", value.Protocol(), value.SourceAddressDigest(), value.SourcePort(), value.DestinationAddressDigest(), value.DestinationPort())
}

func expectationKey(value Expectation) string {
	key := string(value.kind)
	if value.reference != nil {
		key += "\x00" + referenceKey(*value.reference)
	}
	return key
}

func conflictKey(value Conflict) string {
	key := string(value.kind)
	for _, ref := range value.records {
		key += "\x00" + referenceKey(ref)
	}
	for _, evidence := range value.evidence {
		key += "\x00" + referenceKey(evidenceReference(evidence))
	}
	return key
}

func findHop(hops []Hop, reference model.RecordReference) Hop {
	for _, hop := range hops {
		if hop.reference == reference {
			return hop
		}
	}
	return Hop{}
}

func digest(parts ...string) string {
	hash := sha256.New()
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validateBuilderConfig(config BuilderConfig) error {
	if err := boundedRequired("trace algorithm id", config.AlgorithmID); err != nil {
		return err
	}
	if err := boundedRequired("trace algorithm version", config.AlgorithmVersion); err != nil {
		return err
	}
	values := map[string]int{
		"hop limit": config.MaxHops, "correlation limit": config.MaxCorrelations,
		"candidate limit": config.MaxCandidatesPerCorrelation, "match limit": config.MaxMatchesPerCandidate,
		"translation-hop limit": config.MaxTranslationHopsPerMatch, "aggregate correlation-work limit": config.MaxCorrelationWork,
		"conflict limit": config.MaxConflicts, "evidence-per-conflict limit": config.MaxEvidencePerConflict,
		"expectation limit": config.MaxExpectations, "evidence-per-hop limit": config.MaxEvidencePerHop,
		"lineage limit": config.MaxLineage,
	}
	for label, value := range values {
		if value <= 0 || value > maximumConfiguredBound {
			return fmt.Errorf("%s must be between 1 and %d", label, maximumConfiguredBound)
		}
	}
	return nil
}
