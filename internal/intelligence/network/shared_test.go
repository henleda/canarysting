package network

import "testing"

const validShared = `{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":false,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1}`

func TestParseSharedPatternValid(t *testing.T) {
	sp, err := ParseSharedPattern([]byte(validShared))
	if err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
	if !sp.ReachedContain || !sp.EngagedVelocity || sp.EngagedPoison || sp.HeldBand != 2 || !sp.DisengagedEarly || sp.PoisonClass != "topology" || sp.CadenceBand != 1 {
		t.Fatalf("parsed fields wrong: %+v", sp)
	}
}

func TestParseSharedPatternRejects(t *testing.T) {
	cases := map[string]string{
		"missing field (6 keys)":  `{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":false,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology"}`,
		"extra/unknown key (8)":   `{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":false,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1,"Extra":1}`,
		"renamed key (still 7)":   `{"Reached":true,"EngagedVelocity":true,"EngagedPoison":false,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1}`,
		"HeldBand out of band":    `{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":false,"HeldBand":5,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1}`,
		"CadenceBand negative":    `{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":false,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":-1}`,
		"HeldBand a float":        `{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":false,"HeldBand":2.5,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1}`,
		"PoisonClass not in enum": `{"ReachedContain":true,"EngagedVelocity":true,"EngagedPoison":false,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"evil","CadenceBand":1}`,
		"bool field is a number":  `{"ReachedContain":1,"EngagedVelocity":true,"EngagedPoison":false,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1}`,
		"trailing data":           validShared + `{"x":1}`,
		"not an object":           `[1,2,3]`,
		// 8 key-tokens, 7 unique (ReachedContain twice) — a plain map decode would
		// last-wins-mask this as 7 keys; the strict token parse rejects the duplicate.
		"duplicate key": `{"ReachedContain":true,"ReachedContain":false,"EngagedVelocity":true,"EngagedPoison":false,"HeldBand":2,"DisengagedEarly":true,"PoisonClass":"topology","CadenceBand":1}`,
	}
	for name, payload := range cases {
		if _, err := ParseSharedPattern([]byte(payload)); err == nil {
			t.Errorf("%s: expected rejection, got nil error", name)
		}
	}
}

// The inbound parser is the mirror of Clear: a pattern that ClearWithLedger produced and
// Marshaled must parse back cleanly (the two ends agree on the shape).
func TestParseSharedPatternRoundTripsAClearedCarrier(t *testing.T) {
	l, _ := NewLedger()
	export, _ := ReferenceCandidate().EgressFields()
	for _, s := range []string{"a", "b", "c"} {
		l.RecordForm(s, export)
	}
	c, err := ClearWithLedger(cand{export: export, ctx: ContributionContext{Contribute: true}}, ClearContext{Ledger: l})
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSharedPattern(b); err != nil {
		t.Fatalf("a real cleared carrier must parse back as a SharedPattern: %v", err)
	}
}
