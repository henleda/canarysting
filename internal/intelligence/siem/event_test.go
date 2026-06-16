package siem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/canarysting/canarysting/internal/canary/catalog"
	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/intelligence/audit"
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

// TestFromHighWaterMark_AddOnlyAnchor: the audit-anchor projector sets only the v2
// audit_* fields + the reused SchemaVersion/Scope/Timestamp, leaves all touch-specific
// fields zero (so omitempty drops them — no touch PII on an anchor), and mints a
// deterministic-but-distinguishable EventID per (scope, latestSeq).
func TestFromHighWaterMark_AddOnlyAnchor(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	hwm := audit.HighWaterMark{
		Scope:     "m7-window",
		Head:      []byte{0xde, 0xad, 0xbe, 0xef},
		Count:     7,
		LatestSeq: 7,
		Algo:      audit.AlgoHMACSHA256,
		Keyed:     true,
		Timestamp: ts,
	}
	ev := FromHighWaterMark(hwm)

	if ev.EventType != EventTypeAuditAnchor {
		t.Fatalf("event_type = %q, want %q", ev.EventType, EventTypeAuditAnchor)
	}
	if ev.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %d, want %d", ev.SchemaVersion, SchemaVersion)
	}
	if ev.Scope != "m7-window" || !ev.Timestamp.Equal(ts) {
		t.Fatalf("scope/timestamp not reused: scope=%q ts=%v", ev.Scope, ev.Timestamp)
	}
	wantID := "audit-anchor|m7-window|7"
	if ev.EventID != wantID {
		t.Fatalf("event_id = %q, want %q (deterministic per scope+seq)", ev.EventID, wantID)
	}

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	// The five v2 audit_* fields are present with the right values.
	for _, kv := range []string{
		`"audit_head_hash":"deadbeef"`,
		`"audit_record_count":7`,
		`"audit_latest_seq":7`,
		`"audit_algo":"hmac-sha256"`,
		`"audit_keyed":true`,
	} {
		if !strings.Contains(s, kv) {
			t.Errorf("anchor JSON missing %q: %s", kv, s)
		}
	}
	// No touch PII leaks onto an anchor: the omitempty touch fields are DROPPED entirely
	// (no src/path/SPIFFE/att_ck/novelty), and the non-omitempty v1 fields that remain on
	// the wire (the ADD-ONLY contract forbids changing their tags) carry only zero/empty
	// values — there is no identity or request content on an anchor.
	for _, dropped := range []string{"src", "actor_spiffe_id", "http_method", "http_path", "att_ck", "novelty_fingerprint"} {
		if strings.Contains(s, `"`+dropped+`"`) {
			t.Errorf("anchor must DROP omitempty touch field %q: %s", dropped, s)
		}
	}
	// The present-but-zero v1 fields must be exactly their zero values on an anchor (no
	// PII): empty canary_type/verdict/action, zero cookie/tier/score/hit_count.
	if ev.CanaryType != "" || ev.Verdict != "" || ev.Action != "" {
		t.Errorf("anchor leaked a non-empty touch label: canary_type=%q verdict=%q action=%q", ev.CanaryType, ev.Verdict, ev.Action)
	}
	if ev.SocketCookie != 0 || ev.Tier != 0 || ev.Score != 0 || ev.HitCount != 0 {
		t.Errorf("anchor leaked a non-zero touch number: cookie=%d tier=%d score=%v hit=%d", ev.SocketCookie, ev.Tier, ev.Score, ev.HitCount)
	}
	// Distinguishability: successive anchors for the same scope at a higher seq are
	// distinct events (so the SOC does not dedup two different high-water-marks into one).
	hwm.LatestSeq = 8
	if FromHighWaterMark(hwm).EventID == wantID {
		t.Fatal("anchor EventID did not advance with LatestSeq — successive anchors would dedup")
	}
}

// TestFromRecord_AddOnlyAnchorFieldsAbsentOnTouch: a v1-style canary-touch event must
// be byte-identical to before EXCEPT schema_version=2 — the new audit_* fields are
// omitempty and absent, and the existing event_type is unaffected.
func TestFromRecord_AddOnlyAnchorFieldsAbsentOnTouch(t *testing.T) {
	ev := FromRecord(sampleRecord())
	if ev.EventType != EventTypeCanaryTouch {
		t.Fatalf("existing event_type changed: %q", ev.EventType)
	}
	b, _ := json.Marshal(ev)
	s := string(b)
	for _, omitted := range []string{"audit_head_hash", "audit_record_count", "audit_latest_seq", "audit_algo", "audit_keyed"} {
		if strings.Contains(s, `"`+omitted+`"`) {
			t.Errorf("touch event must NOT carry anchor field %q (add-only, omitempty): %s", omitted, s)
		}
	}
	if !strings.Contains(s, `"schema_version":2`) {
		t.Errorf("schema_version not bumped to 2: %s", s)
	}
}

// TestFormatCEF_AnchorRendersAuditFields: the CEF view renders the anchor's five
// audit_* fields under its own add-only extension keys (a missed add() would silently
// drop them in CEF even though JSON carries them).
func TestFormatCEF_AnchorRendersAuditFields(t *testing.T) {
	hwm := audit.HighWaterMark{Scope: "s", Head: []byte{0x01, 0x02}, Count: 4, LatestSeq: 4, Algo: audit.AlgoSHA256, Keyed: false, Timestamp: time.Unix(1700000000, 0)}
	line := FormatCEF(FromHighWaterMark(hwm))
	if !strings.Contains(line, "|audit-anchor|") {
		t.Fatalf("CEF name header is not audit-anchor: %s", line)
	}
	for _, kv := range []string{
		"cs6Label=audit_head_hash", "cs6=0102",
		"cs7Label=audit_algo", "cs7=sha256",
		"cn3Label=audit_record_count", "cn3=4",
		"cn4Label=audit_latest_seq", "cn4=4",
		"cs8Label=audit_keyed", "cs8=false",
	} {
		if !strings.Contains(line, kv) {
			t.Errorf("anchor CEF line missing %q\n  line: %s", kv, line)
		}
	}
	// A touch event must NOT carry the anchor extension keys (gated on event_type).
	touch := FormatCEF(FromRecord(sampleRecord()))
	for _, k := range []string{"cs6Label=audit_head_hash", "cn3Label=audit_record_count"} {
		if strings.Contains(touch, k) {
			t.Errorf("touch CEF must not carry anchor key %q: %s", k, touch)
		}
	}
}
