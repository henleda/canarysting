package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// SharedPattern is the INBOUND mirror of the egress ExportForm — the validated shape a
// deployment reconstructs from a received Cleared.Marshal() payload. It is deliberately
// NOT a *Cleared: Cleared has unexported fields and no inbound constructor (the
// single-chokepoint invariant), so reconstructing one would be a second construction
// path. Keeping the inbound type separate + narrower means the receive path can never
// masquerade as an egress path. The two ends distrust each other (EGRESS §1.3), so
// ParseSharedPattern re-validates every field on ingest, fail-closed.
type SharedPattern struct {
	ReachedContain  bool
	EngagedVelocity bool
	EngagedPoison   bool
	HeldBand        int
	DisengagedEarly bool
	PoisonClass     string
	CadenceBand     int
}

// sharedBoolFields / sharedIntFields / sharedStringField enumerate the EXACT key set a
// valid wire payload carries (mirrors ExportForm). A received payload missing OR
// exceeding these is rejected — so an accepted SharedPattern always carries a real
// CadenceBand (no silent zero-as-unknown that would feed the match a coincidence).
var (
	sharedBoolFields  = []string{"ReachedContain", "EngagedVelocity", "EngagedPoison", "DisengagedEarly"}
	sharedIntFields   = []string{"HeldBand", "CadenceBand"}
	sharedStringField = "PoisonClass"
)

// ParseSharedPattern validates ONE received Cleared.Marshal() payload into a
// SharedPattern — the inbound mirror of Clear, fail-closed (the two ends distrust each
// other). It rejects unknown OR missing keys, a non-bool bool, a non-integer or
// out-of-band (0..3) int, a PoisonClass outside the closed enum, or any non-scalar. A
// malformed/partial/oversized payload therefore never reaches the consumer.
func ParseSharedPattern(b []byte) (SharedPattern, error) {
	// Strict, distrustful decode (the two ends distrust each other): a token stream so a
	// DUPLICATE key is rejected (a plain map decode silently last-wins, masking an 8-token
	// payload as 7 unique keys), and trailing data / a non-object is rejected.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // exact integer range-checks; no float coercion surprise
	tok, err := dec.Token()
	if err != nil {
		return SharedPattern{}, fmt.Errorf("shared: decode: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return SharedPattern{}, fmt.Errorf("shared: payload is not a JSON object")
	}
	raw := map[string]any{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return SharedPattern{}, fmt.Errorf("shared: decode key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return SharedPattern{}, fmt.Errorf("shared: non-string object key")
		}
		if _, dup := raw[key]; dup {
			return SharedPattern{}, fmt.Errorf("shared: duplicate key %q", key)
		}
		var val any
		if err := dec.Decode(&val); err != nil {
			return SharedPattern{}, fmt.Errorf("shared: decode value for %q: %w", key, err)
		}
		raw[key] = val
	}
	if _, err := dec.Token(); err != nil { // consume the closing '}'
		return SharedPattern{}, fmt.Errorf("shared: decode close: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF { // nothing may follow the object
		return SharedPattern{}, fmt.Errorf("shared: trailing data after the pattern object")
	}

	want := len(sharedBoolFields) + len(sharedIntFields) + 1
	if len(raw) != want {
		return SharedPattern{}, fmt.Errorf("shared: payload has %d fields, want exactly %d (the coarse export shape)", len(raw), want)
	}

	getBool := func(k string) (bool, error) {
		v, ok := raw[k]
		if !ok {
			return false, fmt.Errorf("shared: missing field %q", k)
		}
		b, ok := v.(bool)
		if !ok {
			return false, fmt.Errorf("shared: field %q is not a bool", k)
		}
		return b, nil
	}
	getBand := func(k string) (int, error) {
		v, ok := raw[k]
		if !ok {
			return 0, fmt.Errorf("shared: missing field %q", k)
		}
		num, ok := v.(json.Number)
		if !ok {
			return 0, fmt.Errorf("shared: field %q is not a number", k)
		}
		i, err := num.Int64()
		if err != nil {
			return 0, fmt.Errorf("shared: field %q is not an integer: %w", k, err)
		}
		if i < 0 || i > 3 {
			return 0, fmt.Errorf("shared: field %q=%d is outside band 0..3", k, i)
		}
		return int(i), nil
	}

	var sp SharedPattern
	if sp.ReachedContain, err = getBool("ReachedContain"); err != nil {
		return SharedPattern{}, err
	}
	if sp.EngagedVelocity, err = getBool("EngagedVelocity"); err != nil {
		return SharedPattern{}, err
	}
	if sp.EngagedPoison, err = getBool("EngagedPoison"); err != nil {
		return SharedPattern{}, err
	}
	if sp.DisengagedEarly, err = getBool("DisengagedEarly"); err != nil {
		return SharedPattern{}, err
	}
	if sp.HeldBand, err = getBand("HeldBand"); err != nil {
		return SharedPattern{}, err
	}
	if sp.CadenceBand, err = getBand("CadenceBand"); err != nil {
		return SharedPattern{}, err
	}
	pcv, ok := raw[sharedStringField]
	if !ok {
		return SharedPattern{}, fmt.Errorf("shared: missing field %q", sharedStringField)
	}
	pc, ok := pcv.(string)
	if !ok {
		return SharedPattern{}, fmt.Errorf("shared: field %q is not a string", sharedStringField)
	}
	if !enumValues["poisonclass"][pc] {
		return SharedPattern{}, fmt.Errorf("shared: field %q value %q is not in the closed enum", sharedStringField, pc)
	}
	sp.PoisonClass = pc
	return sp, nil
}
