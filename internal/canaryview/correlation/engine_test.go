package correlation_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/correlation"
	"github.com/canarysting/canarysting/internal/canaryview/model"
)

func TestExactStrongAndWeakJoinClassesRemainDistinct(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	scope := testScope(t, "scope-a")
	tuple := testTuple(t, "client-a", 40100, "service-a", 8443)
	verified := verifiedIdentity(t, "spiffe://example.test/workload")
	declared := declaredIdentity(t, "service-account-a")
	requestID := opaqueID(t, "envoy.request", "request-a")
	vendorID := opaqueID(t, "firewall.session", "session-a")
	cookie := socketKey(t, "cookie-a", correlation.SocketVantageL7)
	otel := otelKey(t, "trace-a", "span-a")
	anchor := testRecord(t, "anchor", scope, recordOptions{
		vantage: correlation.SourceVantageStingL7,
		time:    eventTime(t, now, 0), tuple: &tuple, identities: []model.EntityReference{verified, declared},
		requestIDs: []correlation.OpaqueID{requestID}, vendorIDs: []correlation.OpaqueID{vendorID},
		socketCookie: &cookie, otel: &otel,
	})

	requestExact := testRecord(t, "a-request-exact", scope, recordOptions{requestIDs: []correlation.OpaqueID{requestID}})
	vendorExact := testRecord(t, "b-vendor-exact", scope, recordOptions{vendorIDs: []correlation.OpaqueID{vendorID}})
	kernelCookie := socketKey(t, "cookie-a", correlation.SocketVantageKernel)
	cookieExact := testRecord(t, "c-cookie-exact", scope, recordOptions{
		vantage: correlation.SourceVantageStingKernel, socketCookie: &kernelCookie,
	})
	otelExact := testRecord(t, "d-otel-span-exact", scope, recordOptions{otel: &otel})
	otelTrace := otelKey(t, "trace-a", "span-b")
	otelStrong := testRecord(t, "e-otel-trace-strong", scope, recordOptions{otel: &otelTrace})
	verifiedStrong := testRecord(t, "f-verified-strong", scope, recordOptions{
		time: eventTime(t, now.Add(time.Minute), 0), identities: []model.EntityReference{verified},
	})
	tupleWeak := testRecord(t, "g-tuple-weak", scope, recordOptions{
		time: eventTime(t, now.Add(30*time.Second), 0), tuple: &tuple,
	})
	declaredWeak := testRecord(t, "h-declared-weak", scope, recordOptions{
		time: eventTime(t, now.Add(45*time.Second), 0), identities: []model.EntityReference{declared},
	})
	rejected := testRecord(t, "z-rejected", scope, recordOptions{})

	engine := testEngine(t, correlation.DefaultConfig())
	result, err := engine.Correlate(anchor, []correlation.Record{
		rejected, tupleWeak, requestExact, verifiedStrong, otelStrong,
		vendorExact, declaredWeak, cookieExact, otelExact,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wants := map[string]correlation.Strength{
		"a-request-exact":     correlation.StrengthExact,
		"b-vendor-exact":      correlation.StrengthExact,
		"c-cookie-exact":      correlation.StrengthExact,
		"d-otel-span-exact":   correlation.StrengthExact,
		"e-otel-trace-strong": correlation.StrengthStrong,
		"f-verified-strong":   correlation.StrengthStrong,
		"g-tuple-weak":        correlation.StrengthWeak,
		"h-declared-weak":     correlation.StrengthWeak,
	}
	if len(result.Candidates()) != len(wants) {
		t.Fatalf("got %d candidates, want %d", len(result.Candidates()), len(wants))
	}
	for _, candidate := range result.Candidates() {
		want, ok := wants[candidate.Reference().ID()]
		if !ok {
			t.Fatalf("unexpected candidate %q", candidate.Reference().ID())
		}
		if candidate.Strength() != want {
			t.Errorf("candidate %q strength = %s, want %s", candidate.Reference().ID(), candidate.Strength(), want)
		}
		if candidate.Confidence().CandidateCount() != uint32(len(wants)) {
			t.Errorf("candidate %q did not preserve candidate count", candidate.Reference().ID())
		}
		if candidate.Confidence().Calibration() != model.CalibrationNotApplicable {
			t.Errorf("candidate %q claimed calibration", candidate.Reference().ID())
		}
	}
	if !result.Ambiguous() {
		t.Fatal("four equally exact candidates were not marked ambiguous")
	}
	if _, ok := result.Chosen(); ok {
		t.Fatal("ambiguous result selected a candidate")
	}
	if len(result.Rejected()) != 1 || result.Rejected()[0].Reference().ID() != "z-rejected" {
		t.Fatalf("rejected set not preserved: %#v", rejectionIDs(result.Rejected()))
	}
	if result.Rejected()[0].Reasons()[0] != correlation.RejectedNoSharedKey {
		t.Fatalf("unexpected rejection reason: %v", result.Rejected()[0].Reasons())
	}
}

func TestPartialRecordsPreserveMissingKeysAndCanStillJoinExactly(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "scope-a")
	requestID := opaqueID(t, "edge.request", "request-1")
	anchor := testRecord(t, "anchor", scope, recordOptions{requestIDs: []correlation.OpaqueID{requestID}})
	candidate := testRecord(t, "candidate", scope, recordOptions{requestIDs: []correlation.OpaqueID{requestID}})

	result, err := testEngine(t, correlation.DefaultConfig()).Correlate(anchor, []correlation.Record{candidate}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !containsMissing(result.AnchorMissingKeys(), correlation.MissingTime) ||
		!containsMissing(result.AnchorMissingKeys(), correlation.MissingTuple) {
		t.Fatalf("anchor missing keys were not explicit: %v", result.AnchorMissingKeys())
	}
	candidates := result.Candidates()
	if len(candidates) != 1 || candidates[0].Strength() != correlation.StrengthExact {
		t.Fatalf("partial exact candidate was lost: %#v", candidates)
	}
	if !containsMissing(candidates[0].MissingKeys(), correlation.MissingTime) {
		t.Fatalf("candidate missing time was not retained: %v", candidates[0].MissingKeys())
	}
	if candidates[0].Confidence().Completeness() != model.EvidencePartial ||
		candidates[0].Confidence().TimeUncertainty() != model.TimeUnknown {
		t.Fatal("partial exact join overstated completeness or timestamp knowledge")
	}
	chosen, ok := result.Chosen()
	if !ok || chosen.Reference().ID() != "candidate" || result.Ambiguous() {
		t.Fatal("unique exact partial candidate was not selected")
	}
}

func TestTranslationRetainsBothTuplesControlAndDirection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 13, 0, 0, 0, time.UTC)
	scope := testScope(t, "scope-a")
	before := testTuple(t, "external-client", 44321, "edge-address", 443)
	after := testTuple(t, "gateway-address", 53001, "service-address", 8443)
	control := testControl(t, "nat-gateway-a", "NAT_GATEWAY")
	translation := testTranslation(t, "translation-a", scope, before, after, control, now)
	anchor := testRecord(t, "anchor", scope, recordOptions{time: eventTime(t, now, 0), tuple: &before})
	candidate := testRecord(t, "candidate", scope, recordOptions{time: eventTime(t, now.Add(time.Second), 0), tuple: &after})
	engine := testEngine(t, correlation.DefaultConfig())

	result, err := engine.Correlate(anchor, []correlation.Record{candidate}, []correlation.Translation{translation})
	if err != nil {
		t.Fatal(err)
	}
	assertTranslationCandidate(t, result, before, after, control, correlation.TraversalForward)

	reverse, err := engine.Correlate(candidate, []correlation.Record{anchor}, []correlation.Translation{translation})
	if err != nil {
		t.Fatal(err)
	}
	assertTranslationCandidate(t, reverse, before, after, control, correlation.TraversalReverse)
}

func TestMultipleTranslationPathsRemainAmbiguous(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 14, 0, 0, 0, time.UTC)
	scope := testScope(t, "scope-a")
	start := testTuple(t, "a", 1001, "b", 2001)
	middleOne := testTuple(t, "c", 1002, "d", 2002)
	middleTwo := testTuple(t, "e", 1003, "f", 2003)
	end := testTuple(t, "g", 1004, "h", 2004)
	control := testControl(t, "proxy", "PROXY")
	translations := []correlation.Translation{
		testTranslation(t, "path-1a", scope, start, middleOne, control, now),
		testTranslation(t, "path-1b", scope, middleOne, end, control, now),
		testTranslation(t, "path-2a", scope, start, middleTwo, control, now),
		testTranslation(t, "path-2b", scope, middleTwo, end, control, now),
	}
	anchor := testRecord(t, "anchor", scope, recordOptions{time: eventTime(t, now, 0), tuple: &start})
	candidate := testRecord(t, "candidate", scope, recordOptions{time: eventTime(t, now, 0), tuple: &end})

	result, err := testEngine(t, correlation.DefaultConfig()).Correlate(anchor, []correlation.Record{candidate}, translations)
	if err != nil {
		t.Fatal(err)
	}
	candidates := result.Candidates()
	if len(candidates) != 1 || !candidates[0].TranslationPathAmbiguous() {
		t.Fatal("multiple explicit translation paths were not preserved as ambiguity")
	}
	translatedMatches := 0
	for _, match := range candidates[0].Matches() {
		if match.Method() == correlation.JoinTranslatedTuple {
			translatedMatches++
			if len(match.TranslationPath()) != 2 {
				t.Fatalf("translation path has %d hops, want 2", len(match.TranslationPath()))
			}
		}
	}
	if translatedMatches != 2 || !result.Ambiguous() {
		t.Fatalf("got %d translation paths and ambiguous=%v", translatedMatches, result.Ambiguous())
	}
	if _, ok := result.Chosen(); ok {
		t.Fatal("ambiguous translation path selected a relationship")
	}
}

func TestExactEvidenceOutranksTranslationPathAmbiguity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 14, 30, 0, 0, time.UTC)
	scope := testScope(t, "scope-a")
	start := testTuple(t, "a", 1001, "b", 2001)
	middleOne := testTuple(t, "c", 1002, "d", 2002)
	middleTwo := testTuple(t, "e", 1003, "f", 2003)
	end := testTuple(t, "g", 1004, "h", 2004)
	control := testControl(t, "proxy", "PROXY")
	requestID := opaqueID(t, "edge.request", "exact")
	translations := []correlation.Translation{
		testTranslation(t, "path-1a", scope, start, middleOne, control, now),
		testTranslation(t, "path-1b", scope, middleOne, end, control, now),
		testTranslation(t, "path-2a", scope, start, middleTwo, control, now),
		testTranslation(t, "path-2b", scope, middleTwo, end, control, now),
	}
	anchor := testRecord(t, "anchor", scope, recordOptions{
		time: eventTime(t, now, 0), tuple: &start, requestIDs: []correlation.OpaqueID{requestID},
	})
	candidate := testRecord(t, "candidate", scope, recordOptions{
		time: eventTime(t, now, 0), tuple: &end, requestIDs: []correlation.OpaqueID{requestID},
	})

	result, err := testEngine(t, correlation.DefaultConfig()).Correlate(anchor, []correlation.Record{candidate}, translations)
	if err != nil {
		t.Fatal(err)
	}
	chosen, ok := result.Chosen()
	if !ok || chosen.Strength() != correlation.StrengthExact || result.Ambiguous() {
		t.Fatal("independent exact evidence did not resolve weaker translation-path ambiguity")
	}
}

func TestClockUncertaintyChangesWindowMembershipWithoutRewritingTime(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	scope := testScope(t, "scope-a")
	tuple := testTuple(t, "a", 1001, "b", 2001)
	anchorTime := eventTime(t, now, 30*time.Second)
	anchor := testRecord(t, "anchor", scope, recordOptions{time: anchorTime, tuple: &tuple})
	inside := testRecord(t, "inside", scope, recordOptions{
		time: eventTime(t, now.Add(2*time.Minute+30*time.Second), 30*time.Second), tuple: &tuple,
	})
	outside := testRecord(t, "outside", scope, recordOptions{
		time: eventTime(t, now.Add(3*time.Minute+31*time.Second), 30*time.Second), tuple: &tuple,
	})
	missing := testRecord(t, "missing", scope, recordOptions{tuple: &tuple})

	result, err := testEngine(t, correlation.DefaultConfig()).Correlate(anchor, []correlation.Record{outside, missing, inside}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates()) != 1 || result.Candidates()[0].Reference().ID() != "inside" {
		t.Fatalf("uncertainty interval membership was wrong: %v", candidateIDs(result.Candidates()))
	}
	match := result.Candidates()[0].Matches()[0]
	if match.TimeGap() != 90*time.Second || match.Window() != 2*time.Minute {
		t.Fatalf("gap/window = %s/%s, want 90s/2m", match.TimeGap(), match.Window())
	}
	reasons := rejectionReasons(result.Rejected())
	if reasons["outside"] != correlation.RejectedOutsideWindow || reasons["missing"] != correlation.RejectedMissingTime {
		t.Fatalf("clock-skew rejections were not explicit: %v", reasons)
	}
	if got := anchorTime.At(); !got.Equal(now) {
		t.Fatalf("source time was rewritten: %s", got)
	}
}

func TestCandidateAndTranslationOrderDoNotChangeResult(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 16, 0, 0, 0, time.UTC)
	scope := testScope(t, "scope-a")
	start := testTuple(t, "a", 1001, "b", 2001)
	middle := testTuple(t, "c", 1002, "d", 2002)
	end := testTuple(t, "e", 1003, "f", 2003)
	control := testControl(t, "proxy", "PROXY")
	requestID := opaqueID(t, "edge.request", "request")
	anchor := testRecord(t, "anchor", scope, recordOptions{
		time: eventTime(t, now, 0), tuple: &start, requestIDs: []correlation.OpaqueID{requestID},
	})
	records := []correlation.Record{
		testRecord(t, "exact", scope, recordOptions{requestIDs: []correlation.OpaqueID{requestID}}),
		testRecord(t, "translated", scope, recordOptions{time: eventTime(t, now, 0), tuple: &end}),
		testRecord(t, "rejected", scope, recordOptions{}),
	}
	translations := []correlation.Translation{
		testTranslation(t, "one", scope, start, middle, control, now),
		testTranslation(t, "two", scope, middle, end, control, now),
	}
	engine := testEngine(t, correlation.DefaultConfig())
	baseline, err := engine.Correlate(anchor, records, translations)
	if err != nil {
		t.Fatal(err)
	}
	want := summarize(baseline)
	random := rand.New(rand.NewSource(42))
	for iteration := 0; iteration < 100; iteration++ {
		recordCopy := append([]correlation.Record(nil), records...)
		translationCopy := append([]correlation.Translation(nil), translations...)
		random.Shuffle(len(recordCopy), func(i, j int) { recordCopy[i], recordCopy[j] = recordCopy[j], recordCopy[i] })
		random.Shuffle(len(translationCopy), func(i, j int) { translationCopy[i], translationCopy[j] = translationCopy[j], translationCopy[i] })
		got, correlateErr := engine.Correlate(anchor, recordCopy, translationCopy)
		if correlateErr != nil {
			t.Fatal(correlateErr)
		}
		if summary := summarize(got); summary != want {
			t.Fatalf("iteration %d was non-deterministic\n got: %s\nwant: %s", iteration, summary, want)
		}
	}
}

func TestNamespacesAndTranslationTimePreventFalseJoins(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "scope-a")
	now := time.Date(2026, 9, 2, 16, 30, 0, 0, time.UTC)
	sharedDigest := digest("same-native-value")
	leftID, err := correlation.NewOpaqueID("vendor-a.session", sharedDigest)
	if err != nil {
		t.Fatal(err)
	}
	rightID, err := correlation.NewOpaqueID("vendor-b.session", sharedDigest)
	if err != nil {
		t.Fatal(err)
	}
	anchor := testRecord(t, "anchor-id", scope, recordOptions{vendorIDs: []correlation.OpaqueID{leftID}})
	candidate := testRecord(t, "candidate-id", scope, recordOptions{vendorIDs: []correlation.OpaqueID{rightID}})
	result, err := testEngine(t, correlation.DefaultConfig()).Correlate(anchor, []correlation.Record{candidate}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates()) != 0 || result.Rejected()[0].Reasons()[0] != correlation.RejectedNoSharedKey {
		t.Fatal("equal native ID digest crossed namespace boundaries")
	}

	before := testTuple(t, "a", 1001, "b", 2001)
	after := testTuple(t, "c", 1002, "d", 2002)
	timedAnchor := testRecord(t, "anchor-tuple", scope, recordOptions{time: eventTime(t, now, 0), tuple: &before})
	timedCandidate := testRecord(t, "candidate-tuple", scope, recordOptions{time: eventTime(t, now, 0), tuple: &after})
	stale := testTranslation(t, "stale", scope, before, after, testControl(t, "proxy", "PROXY"), now.Add(-6*time.Minute))
	result, err = testEngine(t, correlation.DefaultConfig()).Correlate(timedAnchor, []correlation.Record{timedCandidate}, []correlation.Translation{stale})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates()) != 0 || result.Rejected()[0].Reasons()[0] != correlation.RejectedNoTranslation {
		t.Fatal("stale translation assertion joined current tuples")
	}
}

func TestScopeAndBoundsFailClosed(t *testing.T) {
	t.Parallel()
	scopeA := testScope(t, "scope-a")
	scopeB := testScope(t, "scope-b")
	requestID := opaqueID(t, "edge.request", "request")
	anchor := testRecord(t, "anchor", scopeA, recordOptions{requestIDs: []correlation.OpaqueID{requestID}})
	crossScope := testRecord(t, "cross", scopeB, recordOptions{requestIDs: []correlation.OpaqueID{requestID}})
	engine := testEngine(t, correlation.DefaultConfig())
	if _, err := engine.Correlate(anchor, []correlation.Record{crossScope}, nil); err == nil || !strings.Contains(err.Error(), "outside anchor scope") {
		t.Fatalf("cross-scope candidate did not fail closed: %v", err)
	}

	config := correlation.DefaultConfig()
	config.MaxCandidates = 1
	bounded := testEngine(t, config)
	one := testRecord(t, "one", scopeA, recordOptions{})
	two := testRecord(t, "two", scopeA, recordOptions{})
	if _, err := bounded.Correlate(anchor, []correlation.Record{one, two}, nil); err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("over-bound candidates did not fail closed: %v", err)
	}
}

func TestDistinctCanaryStingLayersCannotFallBackToAnotherKey(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "scope-a")
	requestID := opaqueID(t, "envoy.request", "same-request")
	anchor := testRecord(t, "l7", scope, recordOptions{
		vantage: correlation.SourceVantageStingL7, requestIDs: []correlation.OpaqueID{requestID},
	})
	kernel := testRecord(t, "kernel", scope, recordOptions{
		vantage: correlation.SourceVantageStingKernel, requestIDs: []correlation.OpaqueID{requestID},
	})
	result, err := testEngine(t, correlation.DefaultConfig()).Correlate(anchor, []correlation.Record{kernel}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates()) != 0 || len(result.Rejected()) != 1 ||
		result.Rejected()[0].Reasons()[0] != correlation.RejectedSocketCookieRequired {
		t.Fatalf("cross-layer fallback was accepted: candidates=%v rejected=%v", candidateIDs(result.Candidates()), rejectionReasons(result.Rejected()))
	}
}

func TestTranslationPathLimitFailsRatherThanTruncates(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 17, 0, 0, 0, time.UTC)
	scope := testScope(t, "scope-a")
	start := testTuple(t, "a", 1001, "b", 2001)
	middleOne := testTuple(t, "c", 1002, "d", 2002)
	middleTwo := testTuple(t, "e", 1003, "f", 2003)
	end := testTuple(t, "g", 1004, "h", 2004)
	control := testControl(t, "proxy", "PROXY")
	translations := []correlation.Translation{
		testTranslation(t, "path-1a", scope, start, middleOne, control, now),
		testTranslation(t, "path-1b", scope, middleOne, end, control, now),
		testTranslation(t, "path-2a", scope, start, middleTwo, control, now),
		testTranslation(t, "path-2b", scope, middleTwo, end, control, now),
	}
	anchor := testRecord(t, "anchor", scope, recordOptions{time: eventTime(t, now, 0), tuple: &start})
	candidate := testRecord(t, "candidate", scope, recordOptions{time: eventTime(t, now, 0), tuple: &end})
	config := correlation.DefaultConfig()
	config.MaxTranslationPaths = 1
	_, err := testEngine(t, config).Correlate(anchor, []correlation.Record{candidate}, translations)
	if !errors.Is(err, correlation.ErrTranslationPathLimit) {
		t.Fatalf("translation path overflow was truncated or misclassified: %v", err)
	}
}

func TestMinimizedInputConstructorsRejectRawOrMalformedKeys(t *testing.T) {
	t.Parallel()
	if _, err := correlation.NewNetworkTuple(correlation.ProtocolTCP, "10.0.0.1", 1234, digest("destination"), 443); err == nil {
		t.Fatal("raw source address was accepted")
	}
	if _, err := correlation.NewOpaqueID("request", "raw-request-id"); err == nil {
		t.Fatal("raw request ID was accepted")
	}
	if _, err := correlation.NewSocketCookieKey(strings.Repeat("0", 64), correlation.SocketVantageL7); err == nil {
		t.Fatal("all-zero socket-cookie digest was accepted")
	}
	if _, err := correlation.NewOTelKey(strings.Repeat("A", 32), strings.Repeat("b", 16)); err == nil {
		t.Fatal("uppercase OpenTelemetry ID was accepted")
	}
	if _, err := correlation.NewOTelKey(strings.Repeat("a", 32), strings.Repeat("b", 15)); err == nil {
		t.Fatal("malformed OpenTelemetry span ID was accepted")
	}
	scope := testScope(t, "scope-a")
	reference, err := model.NewRecordReference("record", model.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := correlation.NewRecord(correlation.RecordInput{Reference: reference, Scope: scope}); err == nil {
		t.Fatal("record without an explicit source vantage was accepted")
	}
	l7Cookie := socketKey(t, "cookie", correlation.SocketVantageL7)
	if _, err := correlation.NewRecord(correlation.RecordInput{
		Reference: reference, Scope: scope, Vantage: correlation.SourceVantageGeneral, SocketCookie: &l7Cookie,
	}); err == nil {
		t.Fatal("general source carrying a CanarySting socket cookie was accepted")
	}
	if _, err := correlation.NewRecord(correlation.RecordInput{
		Reference: reference, Scope: scope, Vantage: correlation.SourceVantageStingKernel, SocketCookie: &l7Cookie,
	}); err == nil {
		t.Fatal("record/socket-cookie vantage mismatch was accepted")
	}
}

func TestEngineIsSafeForConcurrentReadOnlyUse(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "scope-a")
	requestID := opaqueID(t, "edge.request", "request")
	anchor := testRecord(t, "anchor", scope, recordOptions{requestIDs: []correlation.OpaqueID{requestID}})
	candidate := testRecord(t, "candidate", scope, recordOptions{requestIDs: []correlation.OpaqueID{requestID}})
	engine := testEngine(t, correlation.DefaultConfig())

	var wait sync.WaitGroup
	errorsFound := make(chan error, 64)
	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := engine.Correlate(anchor, []correlation.Record{candidate}, nil)
			if err != nil {
				errorsFound <- err
				return
			}
			if chosen, ok := result.Chosen(); !ok || chosen.Reference().ID() != "candidate" {
				errorsFound <- fmt.Errorf("unique candidate was not selected")
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}

func TestPublicInputsHaveNoPayloadCarrier(t *testing.T) {
	t.Parallel()
	for _, value := range []any{
		correlation.RecordInput{}, correlation.TranslationInput{}, correlation.NetworkTuple{},
		correlation.OpaqueID{}, correlation.SocketCookieKey{}, correlation.OTelKey{},
	} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			name := strings.ToLower(typeOf.Field(index).Name)
			for _, forbidden := range []string{"payload", "body", "header", "token", "credential", "rawaddress"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s unexpectedly carries %s", typeOf, typeOf.Field(index).Name)
				}
			}
		}
	}
}

func TestConfigIsVersionedAndBounded(t *testing.T) {
	t.Parallel()
	config := correlation.DefaultConfig()
	if config.AlgorithmID == "" || config.AlgorithmVersion == "" || config.ContextWindow <= 0 {
		t.Fatal("default correlation semantics are not explicitly versioned")
	}
	invalid := []func(*correlation.Config){
		func(value *correlation.Config) { value.AlgorithmVersion = "" },
		func(value *correlation.Config) { value.ContextWindow = 0 },
		func(value *correlation.Config) { value.TranslationWindow = 25 * time.Hour },
		func(value *correlation.Config) { value.MaxCandidates = 0 },
		func(value *correlation.Config) { value.MaxTranslations = 5000 },
		func(value *correlation.Config) { value.MaxTranslationHops = 9 },
		func(value *correlation.Config) { value.MaxTranslationPaths = 65 },
	}
	for index, mutate := range invalid {
		candidate := config
		mutate(&candidate)
		if _, err := correlation.NewEngine(candidate); err == nil {
			t.Errorf("invalid config %d was accepted", index)
		}
	}
}

func assertTranslationCandidate(t *testing.T, result correlation.Result, before, after correlation.NetworkTuple, control model.ControlIdentity, direction correlation.TraversalDirection) {
	t.Helper()
	candidates := result.Candidates()
	if len(candidates) != 1 || candidates[0].Strength() != correlation.StrengthStrong {
		t.Fatalf("translation candidate = %#v", candidates)
	}
	matches := candidates[0].Matches()
	if len(matches) != 1 || matches[0].Method() != correlation.JoinTranslatedTuple {
		t.Fatalf("translation match = %#v", matches)
	}
	path := matches[0].TranslationPath()
	if len(path) != 1 || path[0].Direction() != direction {
		t.Fatalf("translation path = %#v", path)
	}
	translation := path[0].Translation()
	if translation.Before() != before || translation.After() != after {
		t.Fatal("translation rewrote its before/after tuple")
	}
	if translation.Control().ID() != control.ID() || translation.Control().Kind() != control.Kind() {
		t.Fatal("translation lost its control identity")
	}
	if result.Ambiguous() {
		t.Fatal("one translation path was marked ambiguous")
	}
}

type recordOptions struct {
	vantage      correlation.SourceVantage
	time         *correlation.EventTime
	tuple        *correlation.NetworkTuple
	identities   []model.EntityReference
	requestIDs   []correlation.OpaqueID
	vendorIDs    []correlation.OpaqueID
	socketCookie *correlation.SocketCookieKey
	otel         *correlation.OTelKey
}

func testRecord(t *testing.T, id string, scope model.Scope, options recordOptions) correlation.Record {
	t.Helper()
	reference, err := model.NewRecordReference(id, model.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	vantage := options.vantage
	if vantage == "" {
		vantage = correlation.SourceVantageGeneral
	}
	record, err := correlation.NewRecord(correlation.RecordInput{
		Reference: reference, Scope: scope, Vantage: vantage, Time: options.time, Tuple: options.tuple,
		Identities: options.identities, RequestIDs: options.requestIDs, VendorIDs: options.vendorIDs,
		SocketCookie: options.socketCookie, OTel: options.otel,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func testTranslation(t *testing.T, id string, scope model.Scope, before, after correlation.NetworkTuple, control model.ControlIdentity, observedAt time.Time) correlation.Translation {
	t.Helper()
	reference, err := model.NewRecordReference(id, model.CurrentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	translation, err := correlation.NewTranslation(correlation.TranslationInput{
		Reference: reference, Scope: scope, Before: before, After: after,
		Control: control, ObservedAt: *eventTime(t, observedAt, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return translation
}

func testTuple(t *testing.T, source string, sourcePort uint16, destination string, destinationPort uint16) correlation.NetworkTuple {
	t.Helper()
	tuple, err := correlation.NewNetworkTuple(correlation.ProtocolTCP, digest(source), sourcePort, digest(destination), destinationPort)
	if err != nil {
		t.Fatal(err)
	}
	return tuple
}

func opaqueID(t *testing.T, namespace, value string) correlation.OpaqueID {
	t.Helper()
	id, err := correlation.NewOpaqueID(namespace, digest(value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func socketKey(t *testing.T, value string, vantage correlation.SocketVantage) correlation.SocketCookieKey {
	t.Helper()
	key, err := correlation.NewSocketCookieKey(digest(value), vantage)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func otelKey(t *testing.T, trace, span string) correlation.OTelKey {
	t.Helper()
	traceDigest := sha256.Sum256([]byte(trace))
	spanDigest := sha256.Sum256([]byte(span))
	key, err := correlation.NewOTelKey(hex.EncodeToString(traceDigest[:16]), hex.EncodeToString(spanDigest[:8]))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func eventTime(t *testing.T, at time.Time, uncertainty time.Duration) *correlation.EventTime {
	t.Helper()
	value, err := correlation.NewEventTime(at, uncertainty)
	if err != nil {
		t.Fatal(err)
	}
	return &value
}

func testScope(t *testing.T, scopeID string) model.Scope {
	t.Helper()
	scope, err := model.NewScope("tenant-a", scopeID, "deployment-a", "residency-a")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func declaredIdentity(t *testing.T, value string) model.EntityReference {
	t.Helper()
	identity, err := model.NewEntityReference("identity:sha256:"+digest(value), "WORKLOAD")
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func verifiedIdentity(t *testing.T, value string) model.EntityReference {
	t.Helper()
	evidence, err := model.NewEvidenceReference("evidence:sha256:"+digest("evidence-"+value), model.CurrentSchemaVersion, model.EvidenceSupporting, "", "")
	if err != nil {
		t.Fatal(err)
	}
	verification, err := model.NewVerification("spiffe.svid.verify", "1", model.ProducerDeterministic, []model.EvidenceReference{evidence})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := model.NewEntityReferenceWithAssertion(
		"identity:sha256:"+digest(value), "WORKLOAD", model.AssertionVerified, &verification,
	)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testControl(t *testing.T, id, kind string) model.ControlIdentity {
	t.Helper()
	control, err := model.NewControlIdentity("control:sha256:"+digest(id), kind)
	if err != nil {
		t.Fatal(err)
	}
	return control
}

func testEngine(t *testing.T, config correlation.Config) *correlation.Engine {
	t.Helper()
	engine, err := correlation.NewEngine(config)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func containsMissing(values []correlation.MissingKey, want correlation.MissingKey) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func candidateIDs(values []correlation.Candidate) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Reference().ID())
	}
	return result
}

func rejectionIDs(values []correlation.Rejection) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Reference().ID())
	}
	return result
}

func rejectionReasons(values []correlation.Rejection) map[string]correlation.RejectionReason {
	result := make(map[string]correlation.RejectionReason, len(values))
	for _, value := range values {
		result[value.Reference().ID()] = value.Reasons()[0]
	}
	return result
}

func summarize(result correlation.Result) string {
	parts := []string{
		result.AlgorithmID(), result.AlgorithmVersion(), fmt.Sprint(result.Ambiguous()),
		strings.Join(missingStrings(result.AnchorMissingKeys()), ","),
	}
	for _, candidate := range result.Candidates() {
		matchParts := make([]string, 0, len(candidate.Matches()))
		for _, match := range candidate.Matches() {
			pathParts := make([]string, 0, len(match.TranslationPath()))
			for _, hop := range match.TranslationPath() {
				pathParts = append(pathParts, hop.Translation().Reference().ID()+":"+string(hop.Direction()))
			}
			matchParts = append(matchParts, fmt.Sprintf("%s:%s:%s:%s", match.Method(), match.Strength(), match.KeyFingerprint(), strings.Join(pathParts, ">")))
		}
		parts = append(parts, fmt.Sprintf("C:%s:%s:%s", candidate.Reference().ID(), candidate.Strength(), strings.Join(matchParts, ",")))
	}
	for _, rejected := range result.Rejected() {
		reasonParts := make([]string, 0, len(rejected.Reasons()))
		for _, reason := range rejected.Reasons() {
			reasonParts = append(reasonParts, string(reason))
		}
		parts = append(parts, fmt.Sprintf("R:%s:%s", rejected.Reference().ID(), strings.Join(reasonParts, ",")))
	}
	return strings.Join(parts, "|")
}

func missingStrings(values []correlation.MissingKey) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, string(value))
	}
	sort.Strings(result)
	return result
}
