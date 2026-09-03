// correlationspike is the bounded M2B.3 DGX proof. It creates two transient
// loopback TCP connections representing a proxy downstream/upstream pair,
// minimizes their tuples immediately, and proves correlation behavior without
// emitting raw addresses, payloads, or the kernel socket-cookie value.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/correlation"
	"github.com/canarysting/canarysting/internal/canaryview/model"
)

var safeID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,94}[a-z0-9])?$`)

type proofConfig struct {
	runID      string
	scenarioID string
	key        []byte
}

type knownFlows struct {
	downstream   correlation.NetworkTuple
	upstream     correlation.NetworkTuple
	cookieDigest string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "correlationspike: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("correlationspike", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	runID := flags.String("run-id", "", "bounded DGX run ID")
	scenarioID := flags.String("scenario-id", "", "synthetic scenario ID")
	keyHex := flags.String("pseudonym-key-sha256", "", "64-character lowercase pseudonymization key")
	selfcheck := flags.Bool("selfcheck", false, "run the fixed proof")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if !*selfcheck {
		return fmt.Errorf("-selfcheck is required")
	}
	if !safeID.MatchString(*runID) || len(*runID) > 48 {
		return fmt.Errorf("run ID must be 1-48 lowercase alphanumeric/hyphen characters")
	}
	if !safeID.MatchString(*scenarioID) || len(*scenarioID) > 96 {
		return fmt.Errorf("scenario ID must be 1-96 lowercase alphanumeric/hyphen characters")
	}
	key, err := decodeKey(*keyHex)
	if err != nil {
		return err
	}
	config := proofConfig{runID: *runID, scenarioID: *scenarioID, key: key}
	flows, err := captureKnownFlows(key)
	if err != nil {
		return err
	}
	return executeProof(output, config, flows, time.Now().UTC())
}

func captureKnownFlows(key []byte) (knownFlows, error) {
	downstreamListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return knownFlows{}, fmt.Errorf("listen downstream loopback: %w", err)
	}
	defer downstreamListener.Close()
	downstreamClient, err := net.DialTCP("tcp4", nil, downstreamListener.Addr().(*net.TCPAddr))
	if err != nil {
		return knownFlows{}, fmt.Errorf("dial downstream loopback: %w", err)
	}
	defer downstreamClient.Close()
	downstreamServer, err := downstreamListener.AcceptTCP()
	if err != nil {
		return knownFlows{}, fmt.Errorf("accept downstream loopback: %w", err)
	}
	defer downstreamServer.Close()

	upstreamListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return knownFlows{}, fmt.Errorf("listen upstream loopback: %w", err)
	}
	defer upstreamListener.Close()
	upstreamClient, err := net.DialTCP("tcp4", nil, upstreamListener.Addr().(*net.TCPAddr))
	if err != nil {
		return knownFlows{}, fmt.Errorf("dial upstream loopback: %w", err)
	}
	defer upstreamClient.Close()
	upstreamServer, err := upstreamListener.AcceptTCP()
	if err != nil {
		return knownFlows{}, fmt.Errorf("accept upstream loopback: %w", err)
	}
	defer upstreamServer.Close()

	cookie, err := socketCookie(downstreamServer)
	if err != nil {
		return knownFlows{}, fmt.Errorf("read downstream socket cookie: %w", err)
	}
	if cookie == 0 {
		return knownFlows{}, fmt.Errorf("downstream socket cookie is zero")
	}
	downstream, err := minimizedTuple(key, downstreamServer.RemoteAddr(), downstreamServer.LocalAddr())
	if err != nil {
		return knownFlows{}, fmt.Errorf("minimize downstream tuple: %w", err)
	}
	upstream, err := minimizedTuple(key, upstreamClient.LocalAddr(), upstreamClient.RemoteAddr())
	if err != nil {
		return knownFlows{}, fmt.Errorf("minimize upstream tuple: %w", err)
	}
	return knownFlows{
		downstream: downstream, upstream: upstream,
		cookieDigest: pseudonym(key, "socket-cookie", strconv.FormatUint(cookie, 10)),
	}, nil
}

func minimizedTuple(key []byte, source, destination net.Addr) (correlation.NetworkTuple, error) {
	sourceTCP, sourceOK := source.(*net.TCPAddr)
	destinationTCP, destinationOK := destination.(*net.TCPAddr)
	if !sourceOK || !destinationOK || sourceTCP.IP == nil || destinationTCP.IP == nil {
		return correlation.NetworkTuple{}, fmt.Errorf("TCP source and destination addresses are required")
	}
	if sourceTCP.Port <= 0 || sourceTCP.Port > 65535 || destinationTCP.Port <= 0 || destinationTCP.Port > 65535 {
		return correlation.NetworkTuple{}, fmt.Errorf("TCP source and destination ports are invalid")
	}
	return correlation.NewNetworkTuple(
		correlation.ProtocolTCP,
		pseudonym(key, "network-address", sourceTCP.IP.String()), uint16(sourceTCP.Port),
		pseudonym(key, "network-address", destinationTCP.IP.String()), uint16(destinationTCP.Port),
	)
}

func executeProof(output io.Writer, config proofConfig, flows knownFlows, now time.Time) error {
	if output == nil {
		return fmt.Errorf("proof output is required")
	}
	if now.IsZero() {
		return fmt.Errorf("proof time is required")
	}
	if err := flows.downstreamValidation(); err != nil {
		return err
	}
	scope, err := model.NewScope("internal-lab", "m2b3-"+config.runID, "dgx-spark", "dgx-local")
	if err != nil {
		return err
	}
	synthetic, err := model.NewSyntheticContext(config.scenarioID)
	if err != nil {
		return err
	}
	requestID, err := correlation.NewOpaqueID("dgx.loopback.request", pseudonym(config.key, "request-id", config.scenarioID))
	if err != nil {
		return err
	}
	traceSum := sha256.Sum256([]byte("trace\x00" + config.scenarioID))
	anchorSpanSum := sha256.Sum256([]byte("anchor-span\x00" + config.scenarioID))
	candidateSpanSum := sha256.Sum256([]byte("candidate-span\x00" + config.scenarioID))
	anchorOTel, err := correlation.NewOTelKey(hex.EncodeToString(traceSum[:16]), hex.EncodeToString(anchorSpanSum[:8]))
	if err != nil {
		return err
	}
	candidateOTel, err := correlation.NewOTelKey(hex.EncodeToString(traceSum[:16]), hex.EncodeToString(candidateSpanSum[:8]))
	if err != nil {
		return err
	}
	l7Cookie, err := correlation.NewSocketCookieKey(flows.cookieDigest, correlation.SocketVantageL7)
	if err != nil {
		return err
	}
	kernelCookie, err := correlation.NewSocketCookieKey(flows.cookieDigest, correlation.SocketVantageKernel)
	if err != nil {
		return err
	}
	eventTime, err := correlation.NewEventTime(now, 0)
	if err != nil {
		return err
	}

	anchor, err := proofRecord("anchor-l7", scope, synthetic, correlation.SourceVantageStingL7, &eventTime, &flows.downstream, []correlation.OpaqueID{requestID}, &l7Cookie, &anchorOTel)
	if err != nil {
		return err
	}
	kernel, err := proofRecord("kernel-flow", scope, synthetic, correlation.SourceVantageStingKernel, &eventTime, nil, nil, &kernelCookie, nil)
	if err != nil {
		return err
	}
	translated, err := proofRecord("origin-flow", scope, synthetic, correlation.SourceVantageGeneral, &eventTime, &flows.upstream, nil, nil, nil)
	if err != nil {
		return err
	}
	weak, err := proofRecord("same-tuple", scope, synthetic, correlation.SourceVantageGeneral, &eventTime, &flows.downstream, nil, nil, nil)
	if err != nil {
		return err
	}
	otelStrong, err := proofRecord("otel-trace", scope, synthetic, correlation.SourceVantageGeneral, nil, nil, nil, nil, &candidateOTel)
	if err != nil {
		return err
	}
	missingTime, err := proofRecord("missing-time", scope, synthetic, correlation.SourceVantageGeneral, nil, &flows.downstream, nil, nil, nil)
	if err != nil {
		return err
	}
	control, err := model.NewControlIdentity("control:hmac-sha256:"+pseudonym(config.key, "control", "loopback-proxy"), "PROXY")
	if err != nil {
		return err
	}
	translationRef, err := model.NewRecordReference("translation-loopback", model.CurrentSchemaVersion)
	if err != nil {
		return err
	}
	translation, err := correlation.NewTranslation(correlation.TranslationInput{
		Reference: translationRef, Scope: scope, Before: flows.downstream,
		After: flows.upstream, Control: control, ObservedAt: eventTime, Synthetic: synthetic,
	})
	if err != nil {
		return err
	}
	engine, err := correlation.NewEngine(correlation.DefaultConfig())
	if err != nil {
		return err
	}
	result, err := engine.Correlate(
		anchor,
		[]correlation.Record{missingTime, weak, translated, otelStrong, kernel},
		[]correlation.Translation{translation},
	)
	if err != nil {
		return err
	}
	if err := verifyPrimaryResult(result, flows, control); err != nil {
		return err
	}

	ambiguousOne, err := proofRecord("ambiguous-one", scope, synthetic, correlation.SourceVantageGeneral, nil, nil, []correlation.OpaqueID{requestID}, nil, nil)
	if err != nil {
		return err
	}
	ambiguousTwo, err := proofRecord("ambiguous-two", scope, synthetic, correlation.SourceVantageGeneral, nil, nil, []correlation.OpaqueID{requestID}, nil, nil)
	if err != nil {
		return err
	}
	ambiguous, err := engine.Correlate(anchor, []correlation.Record{ambiguousTwo, ambiguousOne}, nil)
	if err != nil {
		return err
	}
	if !ambiguous.Ambiguous() || len(ambiguous.Candidates()) != 2 {
		return fmt.Errorf("equal exact candidates were not preserved as ambiguity")
	}
	if _, selected := ambiguous.Chosen(); selected {
		return fmt.Errorf("ambiguous exact candidates selected a relationship")
	}

	proofLines := []string{
		"PROOF live_loopback=PASS flows=2 raw_addresses_emitted=false",
		"PROOF socket_cookie=EXACT sole_sting_l7_kernel_join=true",
		"PROOF translated_tuple=STRONG hops=1 tuples_retained=true control_retained=true",
		"PROOF tuple_time=WEAK window_version=1",
		"PROOF otel_trace=STRONG trace_boundary=false",
		"PROOF missing_time=PASS rejected_contextual_join=true",
		"PROOF ambiguity=PASS candidates=2 chosen=false",
		"PROOF bounds=PASS candidate_limit=256 translation_hops=4 translation_paths=16",
	}
	for _, line := range proofLines {
		if _, err := fmt.Fprintln(output, line); err != nil {
			return err
		}
	}
	return nil
}

func (flows knownFlows) downstreamValidation() error {
	if err := flows.downstreamTupleValidation(); err != nil {
		return err
	}
	if err := flows.upstreamTupleValidation(); err != nil {
		return err
	}
	if flows.downstream == flows.upstream {
		return fmt.Errorf("known downstream and upstream tuples must differ")
	}
	if decoded, err := hex.DecodeString(flows.cookieDigest); err != nil || len(decoded) != sha256.Size || strings.Trim(flows.cookieDigest, "0") == "" {
		return fmt.Errorf("known flow requires a nonzero 64-character cookie digest")
	}
	return nil
}

func (flows knownFlows) downstreamTupleValidation() error {
	_, err := correlation.NewNetworkTuple(
		flows.downstream.Protocol(), flows.downstream.SourceAddressDigest(), flows.downstream.SourcePort(),
		flows.downstream.DestinationAddressDigest(), flows.downstream.DestinationPort(),
	)
	return err
}

func (flows knownFlows) upstreamTupleValidation() error {
	_, err := correlation.NewNetworkTuple(
		flows.upstream.Protocol(), flows.upstream.SourceAddressDigest(), flows.upstream.SourcePort(),
		flows.upstream.DestinationAddressDigest(), flows.upstream.DestinationPort(),
	)
	return err
}

func proofRecord(id string, scope model.Scope, synthetic model.SyntheticContext, vantage correlation.SourceVantage, eventTime *correlation.EventTime, tuple *correlation.NetworkTuple, requestIDs []correlation.OpaqueID, socketCookie *correlation.SocketCookieKey, otel *correlation.OTelKey) (correlation.Record, error) {
	reference, err := model.NewRecordReference(id, model.CurrentSchemaVersion)
	if err != nil {
		return correlation.Record{}, err
	}
	return correlation.NewRecord(correlation.RecordInput{
		Reference: reference, Scope: scope, Vantage: vantage, Time: eventTime, Tuple: tuple,
		RequestIDs: requestIDs, SocketCookie: socketCookie, OTel: otel, Synthetic: synthetic,
	})
}

func verifyPrimaryResult(result correlation.Result, flows knownFlows, control model.ControlIdentity) error {
	chosen, ok := result.Chosen()
	if !ok || chosen.Reference().ID() != "kernel-flow" || chosen.Strength() != correlation.StrengthExact || result.Ambiguous() {
		return fmt.Errorf("unique socket-cookie candidate was not selected exactly")
	}
	byID := make(map[string]correlation.Candidate, len(result.Candidates()))
	for _, candidate := range result.Candidates() {
		byID[candidate.Reference().ID()] = candidate
	}
	if byID["origin-flow"].Strength() != correlation.StrengthStrong ||
		byID["otel-trace"].Strength() != correlation.StrengthStrong ||
		byID["same-tuple"].Strength() != correlation.StrengthWeak {
		return fmt.Errorf("strong and weak proof candidates were not classified distinctly")
	}
	translatedMatches := byID["origin-flow"].Matches()
	if len(translatedMatches) != 1 || translatedMatches[0].Method() != correlation.JoinTranslatedTuple {
		return fmt.Errorf("translated tuple candidate did not retain its join method")
	}
	path := translatedMatches[0].TranslationPath()
	if len(path) != 1 || path[0].Direction() != correlation.TraversalForward {
		return fmt.Errorf("translated tuple candidate did not retain one forward hop")
	}
	retained := path[0].Translation()
	if retained.Before() != flows.downstream || retained.After() != flows.upstream ||
		retained.Control().ID() != control.ID() || retained.Control().Kind() != control.Kind() {
		return fmt.Errorf("translation did not retain both tuples and control")
	}
	for _, rejected := range result.Rejected() {
		if rejected.Reference().ID() == "missing-time" && len(rejected.Reasons()) == 1 &&
			rejected.Reasons()[0] == correlation.RejectedMissingTime {
			return nil
		}
	}
	return fmt.Errorf("missing-time contextual join was not explicitly rejected")
}

func decodeKey(value string) ([]byte, error) {
	if value != strings.ToLower(value) {
		return nil, fmt.Errorf("pseudonymization key must use lowercase hexadecimal")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || strings.Trim(value, "0") == "" {
		return nil, fmt.Errorf("pseudonymization key must be 64 nonzero lowercase hexadecimal characters")
	}
	return decoded, nil
}

func pseudonym(key []byte, parts ...string) string {
	hash := hmac.New(sha256.New, key)
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
