package siem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/l7events"
)

func sampleRecord() l7events.EnrichedTouchRecord {
	return l7events.EnrichedTouchRecord{
		EventID:              "m7-window:abc123",
		Scope:                "m7-window",
		SocketCookie:         42,
		CanaryType:           string(catalog.TypeFakeBucket),
		Tier:                 int(contract.TierContain),
		Verdict:              "contain",
		Score:                2.5,
		Calibrated:           true,
		Mode:                 int(contract.ModeInline),
		SourceAddress:        "10.0.0.9:51514",
		Method:               "GET",
		Path:                 "/secret-bucket/?list-type=2",
		SPIFFEID:             "spiffe://mesh/ns/app/sa/worker",
		Features:             map[string]float64{"novelty": 0.8},
		BytesRealDataCrossed: 0,
		FirstSeen:            time.Unix(1700000000, 0).UTC(),
		LastSeen:             time.Unix(1700000010, 0).UTC(),
		HitCount:             3,
	}
}

func TestFromRecordJSON_StableFields(t *testing.T) {
	ev := FromRecord(sampleRecord())
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := map[string]any{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Stable field NAMES a SOC parser binds to (the contract). Assert presence + value.
	want := map[string]any{
		"schema_version":          float64(SchemaVersion),
		"event_id":                "m7-window:abc123",
		"event_type":              EventTypeCanaryTouch, // contain tier -> canary-touch
		"scope":                   "m7-window",
		"src":                     "10.0.0.9:51514",
		"actor_spiffe_id":         "spiffe://mesh/ns/app/sa/worker",
		"http_method":             "GET",
		"http_path":               "/secret-bucket/?list-type=2",
		"socket_cookie":           float64(42),
		"canary_type":             string(catalog.TypeFakeBucket),
		"tier":                    float64(int(contract.TierContain)),
		"verdict":                 "contain",
		"action":                  "contain",
		"score":                   2.5,
		"calibrated":              true,
		"bytes_real_data_crossed": float64(0),
		"hit_count":               float64(3),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("json field %q = %v (%T), want %v (%T)", k, got[k], got[k], v, v)
		}
	}
	// att_ck is present for a mapped type (fake_bucket -> T1530,T1619).
	techs, ok := got["att_ck"].([]any)
	if !ok || len(techs) == 0 || techs[0] != "T1530" {
		t.Errorf("att_ck = %v, want [T1530 ...]", got["att_ck"])
	}
	// novelty fingerprint present.
	if nf, ok := got["novelty_fingerprint"].(map[string]any); !ok || nf["novelty"] != 0.8 {
		t.Errorf("novelty_fingerprint = %v, want {novelty:0.8}", got["novelty_fingerprint"])
	}
	// bytes_real_data_crossed must NOT be omitted (the 0 is load-bearing).
	if !strings.Contains(string(b), `"bytes_real_data_crossed":0`) {
		t.Errorf("bytes_real_data_crossed:0 missing from JSON (the structural zero must be explicit): %s", b)
	}
}

func TestFromRecord_JailDerivesKernelJailEventType(t *testing.T) {
	r := sampleRecord()
	r.Tier = int(contract.TierJail)
	r.Verdict = "jail"
	ev := FromRecord(r)
	if ev.EventType != EventTypeKernelJail {
		t.Fatalf("jail tier event_type = %q, want %q", ev.EventType, EventTypeKernelJail)
	}
}

func TestFromRecord_OmitsNotFakedFields(t *testing.T) {
	// A bare record (no L7 context, no features, unmapped type) must OMIT the
	// not-captured fields, never fake them.
	r := l7events.EnrichedTouchRecord{
		EventID:    "s:1",
		Scope:      "s",
		Tier:       int(contract.TierTag),
		Verdict:    "tag",
		CanaryType: "", // unmapped/empty
	}
	ev := FromRecord(r)
	b, _ := json.Marshal(ev)
	s := string(b)
	for _, omitted := range []string{"src", "actor_spiffe_id", "http_method", "http_path", "att_ck", "novelty_fingerprint"} {
		if strings.Contains(s, `"`+omitted+`"`) {
			t.Errorf("field %q should be omitted for a bare record, got: %s", omitted, s)
		}
	}
	if ev.AttackTechniques != nil {
		t.Errorf("unmapped canary type must yield nil techniques (omit, never guess), got %v", ev.AttackTechniques)
	}
}

func TestFormatCEF_StableHeaderAndExtension(t *testing.T) {
	line := FormatCEF(FromRecord(sampleRecord()))
	if !strings.HasPrefix(line, "CEF:0|CanarySting|CanarySting|1.0|fake_bucket|canary-touch|7|") {
		t.Fatalf("CEF header unexpected: %q", line)
	}
	// Spot-check stable extension keys.
	for _, kv := range []string{
		"externalId=m7-window:abc123",
		"cs1Label=scope", "cs1=m7-window",
		"src=10.0.0.9:51514",
		"suser=spiffe://mesh/ns/app/sa/worker",
		"requestMethod=GET",
		"cs3Label=canary_type", "cs3=fake_bucket",
		"cs4=T1530,T1619",
		"cs5=contain",
		"cn1=2.5",
		"cn2=0",
	} {
		if !strings.Contains(line, kv) {
			t.Errorf("CEF line missing %q\n  line: %s", kv, line)
		}
	}
	// The path's '=' must be CEF-escaped in the extension value.
	if !strings.Contains(line, `request=/secret-bucket/?list-type\=2`) {
		t.Errorf("CEF path value not escaped: %s", line)
	}
}

func TestFormatCEF_JailSeverity10(t *testing.T) {
	r := sampleRecord()
	r.Tier = int(contract.TierJail)
	r.Verdict = "jail"
	line := FormatCEF(FromRecord(r))
	if !strings.Contains(line, "|kernel-jail|10|") {
		t.Fatalf("jail CEF should be name kernel-jail severity 10: %s", line)
	}
}
