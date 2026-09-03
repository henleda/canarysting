// Command dgxstackspike validates the M2B.2 reference-stack normalization path
// against a digest-only capture manifest. It is a bounded development proof,
// not a production collector or supported connector.
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/canarysting/canarysting/internal/canaryview/collector/dgxstack"
	"github.com/canarysting/canarysting/internal/canaryview/model"
)

const (
	maximumManifestBytes = 64 << 10
	manifestColumns      = 8
)

var runIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)

type captureRow struct {
	kind            dgxstack.SourceKind
	instance        string
	eventKey        string
	sourceTimestamp time.Time
	observedAt      time.Time
	ingestedAt      time.Time
	rawReference    string
	contentHash     string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "dgxstackspike: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("dgxstackspike", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var manifestPath, runID, scenarioID, keyHex string
	flags.StringVar(&manifestPath, "capture-manifest", "", "digest-only capture manifest")
	flags.StringVar(&runID, "run-id", "", "bounded proof run ID")
	flags.StringVar(&scenarioID, "scenario-id", "", "synthetic scenario ID")
	flags.StringVar(&keyHex, "pseudonym-key-sha256", "", "32-byte proof pseudonym key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("positional arguments are not accepted")
	}
	if manifestPath == "" {
		return fmt.Errorf("-capture-manifest is required")
	}
	if !runIDPattern.MatchString(runID) {
		return fmt.Errorf("run ID must be 1-48 lowercase alphanumeric/hyphen characters")
	}
	if scenarioID == "" || len(scenarioID) > 128 || strings.TrimSpace(scenarioID) != scenarioID {
		return fmt.Errorf("scenario ID is required and bounded to 128 bytes")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 || keyHex != strings.ToLower(keyHex) {
		return fmt.Errorf("pseudonym key must be exactly 64 lowercase hexadecimal characters")
	}
	rows, err := readCaptureManifest(manifestPath)
	if err != nil {
		return err
	}
	scope, err := model.NewScope("internal-development-lab", "dgx-proof-"+runID, "dgx-spark", "dgx-local")
	if err != nil {
		return err
	}
	normalizer, err := dgxstack.NewNormalizer(dgxstack.Policy{
		Scope: scope, RetentionProfile: model.RetentionOverride, RetentionDuration: 24 * time.Hour,
		PolicyVersion: "dgx-validation-v1", RetentionDecisionRef: "m2b2-dgx-validation-24h",
		OverrideVersion: "m2b2-dgx-validation-24h-v1", ResidencyPolicyRef: "dgx-local-only",
		EncryptionKeyRef: "operator-managed-dgx-filesystem", OperationalPolicyRef: "m2b2-read-only-proof",
		EstimatedBytes: 4096, EstimatedBytesBasis: model.EstimateAssumed, PseudonymizationKey: key,
	})
	if err != nil {
		return err
	}
	synthetic, err := model.NewSyntheticContext(scenarioID)
	if err != nil {
		return err
	}

	observations := make([]model.Observation, 0, len(rows))
	writer := bufio.NewWriter(stdout)
	for _, row := range rows {
		observation, normalizeErr := normalizer.NormalizeInventory(dgxstack.Context{
			SourceInstance: row.instance, EventKey: row.eventKey,
			ObservedAt: row.observedAt, IngestedAt: row.ingestedAt, Synthetic: synthetic,
			Raw: dgxstack.RawEvidence{
				ReferenceSHA256: row.rawReference, ContentSHA256: row.contentHash,
				Availability: model.RawDeleted,
			},
		}, row.kind, row.sourceTimestamp)
		if normalizeErr != nil {
			return fmt.Errorf("normalize %s: %w", row.kind, normalizeErr)
		}
		blob, marshalErr := model.MarshalObservationV3(observation)
		if marshalErr != nil {
			return fmt.Errorf("serialize %s: %w", row.kind, marshalErr)
		}
		if uint64(len(blob)) > observation.Envelope().Lifecycle().EstimatedStorageImpact().Bytes() {
			return fmt.Errorf("normalized %s record exceeds its explicit storage estimate", row.kind)
		}
		if _, writeErr := writer.Write(append(blob, '\n')); writeErr != nil {
			return fmt.Errorf("write normalized observation: %w", writeErr)
		}
		observations = append(observations, observation)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush normalized observations: %w", err)
	}
	summary, err := dgxstack.Measure(observations)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "PROOF sources=%d records=%d total_bytes=%d min_bytes=%d max_bytes=%d synthetic=true raw_payload_retained=false\n",
		len(rows), summary.Records, summary.TotalBytes, summary.MinBytes, summary.MaxBytes)
	return nil
}

func readCaptureManifest(path string) ([]captureRow, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat capture manifest: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumManifestBytes {
		return nil, fmt.Errorf("capture manifest must be a non-empty regular file no larger than %d bytes", maximumManifestBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open capture manifest: %w", err)
	}
	defer file.Close()
	limited := io.LimitReader(file, maximumManifestBytes+1)
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), maximumManifestBytes+1)
	const header = "kind\tinstance\tevent_key\tsource_timestamp\tobserved_at\tingested_at\traw_reference_sha256\tcontent_sha256"
	if !scanner.Scan() || scanner.Text() != header {
		return nil, fmt.Errorf("capture manifest header is invalid")
	}
	rows := make([]captureRow, 0, len(dgxstack.SourceKinds()))
	seen := make(map[dgxstack.SourceKind]bool)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != manifestColumns {
			return nil, fmt.Errorf("capture manifest row must contain exactly %d fields", manifestColumns)
		}
		for _, field := range fields {
			if field == "" || len(field) > 512 || strings.TrimSpace(field) != field {
				return nil, fmt.Errorf("capture manifest fields must be non-empty, trimmed, and at most 512 bytes")
			}
		}
		kind := dgxstack.SourceKind(fields[0])
		if seen[kind] {
			return nil, fmt.Errorf("duplicate source kind %q", kind)
		}
		seen[kind] = true
		sourceTimestamp, err := time.Parse(time.RFC3339Nano, fields[3])
		if err != nil {
			return nil, fmt.Errorf("source %s timestamp is invalid", kind)
		}
		observedAt, err := time.Parse(time.RFC3339Nano, fields[4])
		if err != nil {
			return nil, fmt.Errorf("source %s observed time is invalid", kind)
		}
		ingestedAt, err := time.Parse(time.RFC3339Nano, fields[5])
		if err != nil {
			return nil, fmt.Errorf("source %s ingest time is invalid", kind)
		}
		rows = append(rows, captureRow{
			kind: kind, instance: fields[1], eventKey: fields[2], sourceTimestamp: sourceTimestamp.UTC(),
			observedAt: observedAt.UTC(), ingestedAt: ingestedAt.UTC(),
			rawReference: fields[6], contentHash: fields[7],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read capture manifest: %w", err)
	}
	want := dgxstack.SourceKinds()
	if len(rows) != len(want) {
		return nil, fmt.Errorf("capture manifest must contain exactly %d source rows", len(want))
	}
	order := make(map[dgxstack.SourceKind]int, len(want))
	for index, kind := range want {
		order[kind] = index
		if !seen[kind] {
			return nil, fmt.Errorf("capture manifest is missing source kind %q", kind)
		}
	}
	for kind := range seen {
		if _, ok := order[kind]; !ok {
			return nil, fmt.Errorf("capture manifest contains unsupported source kind %q", kind)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return order[rows[i].kind] < order[rows[j].kind] })
	return rows, nil
}
