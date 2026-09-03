package correlation

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/model"
)

const (
	DefaultAlgorithmID      = "canaryview.correlation.candidates"
	DefaultAlgorithmVersion = "1"

	maximumWindow           = 24 * time.Hour
	maximumCandidateLimit   = 4096
	maximumTranslationLimit = 4096
	maximumHopLimit         = 8
	maximumPathLimit        = 64
)

var ErrTranslationPathLimit = errors.New("correlation translation path limit exceeded")

// Config is versioned because a window change can change candidate membership.
// The v1 defaults are fixed, uncalibrated operational semantics: two minutes
// for record context, five minutes for translation assertions, and ten minutes
// as the largest accepted source-clock uncertainty. They are not learned
// parameters and make no probabilistic confidence claim.
type Config struct {
	AlgorithmID         string
	AlgorithmVersion    string
	ContextWindow       time.Duration
	TranslationWindow   time.Duration
	MaxTimeUncertainty  time.Duration
	MaxCandidates       int
	MaxTranslations     int
	MaxTranslationHops  int
	MaxTranslationPaths int
}

func DefaultConfig() Config {
	return Config{
		AlgorithmID: DefaultAlgorithmID, AlgorithmVersion: DefaultAlgorithmVersion,
		ContextWindow: 2 * time.Minute, TranslationWindow: 5 * time.Minute,
		MaxTimeUncertainty: 10 * time.Minute, MaxCandidates: 256,
		MaxTranslations: 256, MaxTranslationHops: 4, MaxTranslationPaths: 16,
	}
}

type Engine struct {
	config Config
}

func NewEngine(config Config) (*Engine, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	return &Engine{config: config}, nil
}

func (e *Engine) Config() Config {
	if e == nil {
		return Config{}
	}
	return e.config
}

// Correlate evaluates every supplied record against anchor. Input over a hard
// bound or from another scope fails closed; no candidate set is silently
// truncated. The result retains every qualifying and rejected record and picks
// a candidate only when the strongest relationship is unique and its
// translation path is unambiguous.
func (e *Engine) Correlate(anchor Record, records []Record, translations []Translation) (Result, error) {
	if e == nil {
		return Result{}, fmt.Errorf("correlation engine is required")
	}
	if err := anchor.validate(); err != nil {
		return Result{}, fmt.Errorf("anchor: %w", err)
	}
	if len(records) > e.config.MaxCandidates {
		return Result{}, fmt.Errorf("candidate records %d exceed configured limit %d", len(records), e.config.MaxCandidates)
	}
	if len(translations) > e.config.MaxTranslations {
		return Result{}, fmt.Errorf("translations %d exceed configured limit %d", len(translations), e.config.MaxTranslations)
	}
	if err := e.validateTime(anchor.eventTime, "anchor"); err != nil {
		return Result{}, err
	}

	recordIDs := map[string]bool{referenceKey(anchor.reference): true}
	for index := range records {
		if err := records[index].validate(); err != nil {
			return Result{}, fmt.Errorf("candidate %d: %w", index, err)
		}
		if !sameScope(anchor.scope, records[index].scope) {
			return Result{}, fmt.Errorf("candidate %q is outside anchor scope", records[index].reference.ID())
		}
		if !sameSyntheticContext(anchor.synthetic, records[index].synthetic) {
			return Result{}, fmt.Errorf("candidate %q synthetic context differs from anchor", records[index].reference.ID())
		}
		if err := e.validateTime(records[index].eventTime, "candidate "+records[index].reference.ID()); err != nil {
			return Result{}, err
		}
		key := referenceKey(records[index].reference)
		if recordIDs[key] {
			return Result{}, fmt.Errorf("duplicate candidate or anchor reference %q", records[index].reference.ID())
		}
		recordIDs[key] = true
	}

	translationIDs := make(map[string]bool, len(translations))
	for index := range translations {
		if err := translations[index].validate(); err != nil {
			return Result{}, fmt.Errorf("translation %d: %w", index, err)
		}
		if !sameScope(anchor.scope, translations[index].scope) {
			return Result{}, fmt.Errorf("translation %q is outside anchor scope", translations[index].reference.ID())
		}
		if !sameSyntheticContext(anchor.synthetic, translations[index].synthetic) {
			return Result{}, fmt.Errorf("translation %q synthetic context differs from anchor", translations[index].reference.ID())
		}
		if err := e.validateTime(&translations[index].observedAt, "translation "+translations[index].reference.ID()); err != nil {
			return Result{}, err
		}
		key := referenceKey(translations[index].reference)
		if translationIDs[key] {
			return Result{}, fmt.Errorf("duplicate translation reference %q", translations[index].reference.ID())
		}
		translationIDs[key] = true
	}

	result := Result{
		anchorRecord: anchor, anchor: anchor.reference, algorithmID: e.config.AlgorithmID,
		algorithmVersion: e.config.AlgorithmVersion, anchorMissing: missingKeys(anchor),
	}
	for _, record := range records {
		evaluation, err := e.evaluate(anchor, record, translations)
		if err != nil {
			return Result{}, err
		}
		if len(evaluation.matches) == 0 {
			result.rejected = append(result.rejected, Rejection{
				record: record, reference: record.reference, reasons: evaluation.reasons, missing: missingKeys(record),
			})
			continue
		}
		sortMatches(evaluation.matches)
		translatedPaths := 0
		for _, match := range evaluation.matches {
			if match.method == JoinTranslatedTuple {
				translatedPaths++
			}
		}
		result.candidates = append(result.candidates, Candidate{
			record: record, reference: record.reference, strength: evaluation.matches[0].strength,
			matches: evaluation.matches, missing: missingKeys(record),
			pathAmbiguous: evaluation.matches[0].method == JoinTranslatedTuple && translatedPaths > 1,
		})
	}

	sort.Slice(result.candidates, func(i, j int) bool {
		left, right := result.candidates[i], result.candidates[j]
		if strengthRank(left.strength) != strengthRank(right.strength) {
			return strengthRank(left.strength) > strengthRank(right.strength)
		}
		return referenceKey(left.reference) < referenceKey(right.reference)
	})
	sort.Slice(result.rejected, func(i, j int) bool {
		return referenceKey(result.rejected[i].reference) < referenceKey(result.rejected[j].reference)
	})

	for index := range result.candidates {
		confidence, err := e.confidence(
			result.candidates[index], result.anchorMissing,
			uint32(len(result.candidates)),
		)
		if err != nil {
			return Result{}, fmt.Errorf("candidate confidence: %w", err)
		}
		result.candidates[index].confidence = confidence
	}
	if len(result.candidates) > 0 {
		topStrength := result.candidates[0].strength
		topCount := 0
		for _, candidate := range result.candidates {
			if candidate.strength == topStrength {
				topCount++
			}
		}
		result.ambiguous = topCount != 1 || result.candidates[0].pathAmbiguous
		if !result.ambiguous {
			chosen := result.candidates[0]
			result.chosen = &chosen
		}
	}
	return result, nil
}

type evaluation struct {
	matches []Match
	reasons []RejectionReason
}

func (e *Engine) evaluate(anchor, candidate Record, translations []Translation) (evaluation, error) {
	var result evaluation

	if distinctCanaryStingVantages(anchor.vantage, candidate.vantage) {
		if anchor.socketCookie != nil && candidate.socketCookie != nil &&
			anchor.socketCookie.digest == candidate.socketCookie.digest {
			result.matches = append(result.matches, exactMatch(JoinSocketCookie, anchor.socketCookie.digest))
		} else {
			result.reasons = append(result.reasons, RejectedSocketCookieRequired)
		}
		return result, nil
	}

	if anchor.socketCookie != nil && candidate.socketCookie != nil &&
		anchor.socketCookie.digest == candidate.socketCookie.digest {
		result.matches = append(result.matches, exactMatch(JoinSocketCookie, anchor.socketCookie.digest))
	}
	for _, shared := range sharedOpaqueIDs(anchor.requestIDs, candidate.requestIDs) {
		result.matches = append(result.matches, exactMatch(JoinRequestID, shared.namespace, shared.digest))
	}
	for _, shared := range sharedOpaqueIDs(anchor.vendorIDs, candidate.vendorIDs) {
		result.matches = append(result.matches, exactMatch(JoinVendorID, shared.namespace, shared.digest))
	}
	if anchor.otel != nil && candidate.otel != nil && anchor.otel.traceID == candidate.otel.traceID {
		if anchor.otel.spanID != "" && anchor.otel.spanID == candidate.otel.spanID {
			result.matches = append(result.matches, exactMatch(JoinOTelSpanID, anchor.otel.traceID, anchor.otel.spanID))
		}
		result.matches = append(result.matches, Match{
			method: JoinOTelTraceID, strength: StrengthStrong,
			keyFingerprint: fingerprint("otel-trace", anchor.otel.traceID),
		})
	}

	gap, timeOK, timeMissing := timeWithin(anchor.eventTime, candidate.eventTime, e.config.ContextWindow)
	sharedContext := false
	for _, pair := range sharedIdentities(anchor.identities, candidate.identities) {
		sharedContext = true
		if !timeOK {
			continue
		}
		method, strength := JoinDeclaredIdentity, StrengthWeak
		if pair.left.AssertionMode() == model.AssertionVerified && pair.right.AssertionMode() == model.AssertionVerified {
			method, strength = JoinVerifiedIdentity, StrengthStrong
		}
		result.matches = append(result.matches, Match{
			method: method, strength: strength,
			keyFingerprint: fingerprint("identity", pair.left.Kind(), pair.left.ID()),
			timeGap:        gap, window: e.config.ContextWindow,
		})
	}

	translationAttempted := false
	if anchor.tuple != nil && candidate.tuple != nil {
		sharedContext = true
		if timeOK {
			if *anchor.tuple == *candidate.tuple {
				result.matches = append(result.matches, Match{
					method: JoinTupleTime, strength: StrengthWeak,
					keyFingerprint: tupleFingerprint(*anchor.tuple),
					timeGap:        gap, window: e.config.ContextWindow,
				})
			} else {
				translationAttempted = true
				paths, err := e.translationPaths(*anchor.tuple, *candidate.tuple, anchor.eventTime, candidate.eventTime, translations)
				if err != nil {
					return evaluation{}, err
				}
				for _, path := range paths {
					result.matches = append(result.matches, Match{
						method: JoinTranslatedTuple, strength: StrengthStrong,
						keyFingerprint: pathFingerprint(path), timeGap: gap,
						window: e.config.ContextWindow, translation: path,
					})
				}
			}
		}
	}

	if len(result.matches) == 0 {
		switch {
		case sharedContext && timeMissing:
			result.reasons = append(result.reasons, RejectedMissingTime)
		case sharedContext && !timeOK:
			result.reasons = append(result.reasons, RejectedOutsideWindow)
		case translationAttempted:
			result.reasons = append(result.reasons, RejectedNoTranslation)
		default:
			result.reasons = append(result.reasons, RejectedNoSharedKey)
		}
	}
	return result, nil
}

func distinctCanaryStingVantages(left, right SourceVantage) bool {
	return left != SourceVantageGeneral && right != SourceVantageGeneral && left != right
}

func (e *Engine) confidence(candidate Candidate, anchorMissing []MissingKey, candidateCount uint32) (model.Confidence, error) {
	primary := candidate.matches[0]
	level := model.ConfidenceLow
	method := model.ConfidenceTupleTimeWindow
	identityAssurance := model.AssuranceUnverified
	switch primary.strength {
	case StrengthExact:
		level, method = model.ConfidenceHigh, model.ConfidenceExactIdentifier
	case StrengthStrong:
		level = model.ConfidenceMedium
		switch primary.method {
		case JoinVerifiedIdentity:
			method, identityAssurance = model.ConfidenceVerifiedIdentity, model.AssuranceVerified
		case JoinTranslatedTuple:
			method = model.ConfidenceDeclaredMapping
		default:
			method = model.ConfidenceExactIdentifier
		}
	case StrengthWeak:
		if primary.method == JoinDeclaredIdentity {
			method, identityAssurance = model.ConfidenceDeclaredMapping, model.AssuranceDeclared
		}
	}
	completeness := model.EvidencePartial
	if len(anchorMissing) == 0 && len(candidate.missing) == 0 {
		completeness = model.EvidenceComplete
	}
	timeUncertainty := model.TimeUnknown
	window := time.Duration(0)
	if primary.window > 0 {
		timeUncertainty, window = model.TimeBounded, primary.window
	}
	return model.NewConfidence(model.ConfidenceInput{
		Level: level, Method: method, SourceQuality: model.AssuranceDeclared,
		IdentityAssurance: identityAssurance, Completeness: completeness,
		CandidateCount: candidateCount, TimeUncertainty: timeUncertainty,
		TimeWindow: window, AlgorithmID: e.config.AlgorithmID,
		AlgorithmVersion: e.config.AlgorithmVersion,
		Calibration:      model.CalibrationNotApplicable, HumanReview: model.HumanUnreviewed,
	})
}

func validateConfig(config Config) error {
	if err := boundedRequired("correlation algorithm ID", config.AlgorithmID); err != nil {
		return err
	}
	if err := boundedRequired("correlation algorithm version", config.AlgorithmVersion); err != nil {
		return err
	}
	if config.ContextWindow <= 0 || config.ContextWindow > maximumWindow {
		return fmt.Errorf("context window must be greater than zero and at most %s", maximumWindow)
	}
	if config.TranslationWindow <= 0 || config.TranslationWindow > maximumWindow {
		return fmt.Errorf("translation window must be greater than zero and at most %s", maximumWindow)
	}
	if config.MaxTimeUncertainty < 0 || config.MaxTimeUncertainty > maximumWindow {
		return fmt.Errorf("maximum time uncertainty must be between zero and %s", maximumWindow)
	}
	if config.MaxCandidates <= 0 || config.MaxCandidates > maximumCandidateLimit {
		return fmt.Errorf("candidate limit must be between 1 and %d", maximumCandidateLimit)
	}
	if config.MaxTranslations <= 0 || config.MaxTranslations > maximumTranslationLimit {
		return fmt.Errorf("translation limit must be between 1 and %d", maximumTranslationLimit)
	}
	if config.MaxTranslationHops <= 0 || config.MaxTranslationHops > maximumHopLimit {
		return fmt.Errorf("translation hop limit must be between 1 and %d", maximumHopLimit)
	}
	if config.MaxTranslationPaths <= 0 || config.MaxTranslationPaths > maximumPathLimit {
		return fmt.Errorf("translation path limit must be between 1 and %d", maximumPathLimit)
	}
	return nil
}

func (e *Engine) validateTime(value *EventTime, label string) error {
	if value != nil && value.uncertainty > e.config.MaxTimeUncertainty {
		return fmt.Errorf("%s time uncertainty %s exceeds configured limit %s", label, value.uncertainty, e.config.MaxTimeUncertainty)
	}
	return nil
}

func exactMatch(method JoinMethod, parts ...string) Match {
	values := append([]string{string(method)}, parts...)
	return Match{method: method, strength: StrengthExact, keyFingerprint: fingerprint(values...)}
}

func sharedOpaqueIDs(left, right []OpaqueID) []OpaqueID {
	var result []OpaqueID
	leftIndex, rightIndex := 0, 0
	for leftIndex < len(left) && rightIndex < len(right) {
		leftKey := left[leftIndex].namespace + "\x00" + left[leftIndex].digest
		rightKey := right[rightIndex].namespace + "\x00" + right[rightIndex].digest
		switch {
		case leftKey < rightKey:
			leftIndex++
		case leftKey > rightKey:
			rightIndex++
		default:
			result = append(result, left[leftIndex])
			leftIndex++
			rightIndex++
		}
	}
	return result
}

type identityPair struct {
	left  model.EntityReference
	right model.EntityReference
}

func sharedIdentities(left, right []model.EntityReference) []identityPair {
	var result []identityPair
	leftIndex, rightIndex := 0, 0
	for leftIndex < len(left) && rightIndex < len(right) {
		leftKey, rightKey := identityKey(left[leftIndex]), identityKey(right[rightIndex])
		switch {
		case leftKey < rightKey:
			leftIndex++
		case leftKey > rightKey:
			rightIndex++
		default:
			result = append(result, identityPair{left: left[leftIndex], right: right[rightIndex]})
			leftIndex++
			rightIndex++
		}
	}
	return result
}

// timeWithin compares uncertainty intervals rather than pretending source
// timestamps are exact. gap is zero when the intervals overlap.
func timeWithin(left, right *EventTime, window time.Duration) (gap time.Duration, ok, missing bool) {
	if left == nil || right == nil {
		return 0, false, true
	}
	delta := left.at.Sub(right.at)
	if delta < 0 {
		delta = -delta
	}
	uncertainty := left.uncertainty + right.uncertainty
	if delta > uncertainty {
		gap = delta - uncertainty
	}
	return gap, gap <= window, false
}

type translationEdge struct {
	to  NetworkTuple
	hop TranslationHop
}

func (e *Engine) translationPaths(from, to NetworkTuple, anchorTime, candidateTime *EventTime, translations []Translation) ([][]TranslationHop, error) {
	adjacency := make(map[NetworkTuple][]translationEdge)
	for _, translation := range translations {
		if !translationTimeUsable(anchorTime, candidateTime, translation.observedAt, e.config.TranslationWindow) {
			continue
		}
		adjacency[translation.before] = append(adjacency[translation.before], translationEdge{
			to: translation.after, hop: TranslationHop{translation: translation, direction: TraversalForward},
		})
		adjacency[translation.after] = append(adjacency[translation.after], translationEdge{
			to: translation.before, hop: TranslationHop{translation: translation, direction: TraversalReverse},
		})
	}
	for tuple := range adjacency {
		sort.Slice(adjacency[tuple], func(i, j int) bool {
			left, right := adjacency[tuple][i], adjacency[tuple][j]
			leftKey := referenceKey(left.hop.translation.reference) + "\x00" + string(left.hop.direction) + "\x00" + tupleKey(left.to)
			rightKey := referenceKey(right.hop.translation.reference) + "\x00" + string(right.hop.direction) + "\x00" + tupleKey(right.to)
			return leftKey < rightKey
		})
	}

	visited := map[NetworkTuple]bool{from: true}
	var paths [][]TranslationHop
	var walk func(NetworkTuple, []TranslationHop) error
	walk = func(current NetworkTuple, path []TranslationHop) error {
		if len(path) >= e.config.MaxTranslationHops {
			return nil
		}
		for _, edge := range adjacency[current] {
			if visited[edge.to] {
				continue
			}
			nextPath := append(append([]TranslationHop(nil), path...), edge.hop)
			if edge.to == to {
				paths = append(paths, nextPath)
				if len(paths) > e.config.MaxTranslationPaths {
					return fmt.Errorf("%w: configured maximum is %d", ErrTranslationPathLimit, e.config.MaxTranslationPaths)
				}
				continue
			}
			visited[edge.to] = true
			if err := walk(edge.to, nextPath); err != nil {
				return err
			}
			delete(visited, edge.to)
		}
		return nil
	}
	if err := walk(from, nil); err != nil {
		return nil, err
	}
	sort.Slice(paths, func(i, j int) bool { return pathKey(paths[i]) < pathKey(paths[j]) })
	return paths, nil
}

func translationTimeUsable(anchor, candidate *EventTime, translation EventTime, window time.Duration) bool {
	_, anchorOK, _ := timeWithin(anchor, &translation, window)
	_, candidateOK, _ := timeWithin(candidate, &translation, window)
	return anchorOK && candidateOK
}

func sortMatches(matches []Match) {
	sort.Slice(matches, func(i, j int) bool {
		left, right := matches[i], matches[j]
		if strengthRank(left.strength) != strengthRank(right.strength) {
			return strengthRank(left.strength) > strengthRank(right.strength)
		}
		if left.method != right.method {
			return left.method < right.method
		}
		if left.keyFingerprint != right.keyFingerprint {
			return left.keyFingerprint < right.keyFingerprint
		}
		return pathKey(left.translation) < pathKey(right.translation)
	})
}

func referenceKey(ref model.RecordReference) string {
	return fmt.Sprintf("%s\x00%010d", ref.ID(), ref.SchemaVersion())
}

func tupleKey(tuple NetworkTuple) string {
	return fmt.Sprintf("%s\x00%s\x00%05d\x00%s\x00%05d", tuple.protocol, tuple.sourceAddressDigest, tuple.sourcePort, tuple.destAddressDigest, tuple.destPort)
}

func tupleFingerprint(tuple NetworkTuple) string {
	return fingerprint("tuple", tupleKey(tuple))
}

func pathFingerprint(path []TranslationHop) string {
	parts := []string{"translation-path"}
	for _, hop := range path {
		parts = append(parts, referenceKey(hop.translation.reference), string(hop.direction))
	}
	return fingerprint(parts...)
}

func pathKey(path []TranslationHop) string {
	key := ""
	for _, hop := range path {
		key += referenceKey(hop.translation.reference) + "\x00" + string(hop.direction) + "\x00"
	}
	return key
}

func fingerprint(parts ...string) string {
	hash := sha256.New()
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	return "correlation-key:sha256:" + hex.EncodeToString(hash.Sum(nil))
}
