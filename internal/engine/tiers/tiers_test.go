package tiers

import (
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
)

func TestDecide_EscalatesWithScoreUnderDefaultConfig(t *testing.T) {
	d := StaticDecider{}
	cfg := DefaultConfig()
	// Default thresholds: T1=1.30, T2=3.00, T3=5.10 (see tiers.go).
	cases := []struct {
		score float64
		want  contract.Tier
	}{
		{0.0, contract.TierObserve},
		{1.0, contract.TierObserve}, // one touch: observe, no action
		{1.30, contract.TierTag},
		{2.0, contract.TierTag},
		{3.0, contract.TierContain},
		{5.0, contract.TierContain},
		{5.10, contract.TierJail},
		{9.0, contract.TierJail},
	}
	for _, c := range cases {
		got, _, err := d.Decide("s", c.score, cfg)
		if err != nil {
			t.Fatalf("score %.2f: %v", c.score, err)
		}
		if got != c.want {
			t.Errorf("score %.2f: got tier %d, want %d", c.score, got, c.want)
		}
	}
}

func TestDecide_AsyncOnlyForLowTiers(t *testing.T) {
	d := StaticDecider{}
	cfg := DefaultConfig()
	for _, score := range []float64{0.0, 1.30} { // observe, tag
		_, mode, _ := d.Decide("s", score, cfg)
		if mode != contract.ModeAsync {
			t.Errorf("score %.2f: tiers 0-1 must be async, got mode %d", score, mode)
		}
	}
}

func TestDecide_HonorsOperatorModeForActionTiers(t *testing.T) {
	d := StaticDecider{}
	cfg := DefaultConfig()
	cfg.Mode[contract.TierContain] = contract.ModeInline
	_, mode, err := d.Decide("s", 3.0, cfg) // contain
	if err != nil {
		t.Fatal(err)
	}
	if mode != contract.ModeInline {
		t.Errorf("operator inline choice for Tier 2 not honored: got %d", mode)
	}
}

func TestDecide_ThresholdsForcedMonotonic(t *testing.T) {
	// A misordered config (Tier 2 permissive, Tier 1 strict) must not make a
	// higher tier easier to enter than a lower one.
	d := StaticDecider{}
	cfg := DefaultConfig()
	cfg.ConfidenceRequired[contract.TierTag] = 1.00     // strict T1
	cfg.ConfidenceRequired[contract.TierContain] = 0.01 // permissive T2
	// Even so, entering Contain must require a score >= the Tag threshold.
	tagThresh := threshold(contract.TierTag, cfg) // 1 + 1*1 = 2.0
	got, _, _ := d.Decide("s", tagThresh, cfg)
	if got > contract.TierContain {
		t.Fatalf("monotonicity broken: score %.2f reached tier %d", tagThresh, got)
	}
}

func TestConfigValidate_Rejects(t *testing.T) {
	tests := map[string]func(Config) Config{
		"confidence out of range": func(c Config) Config {
			c.ConfidenceRequired[contract.TierTag] = 1.5
			return c
		},
		"confidence on non-thresholded tier": func(c Config) Config {
			c.ConfidenceRequired[contract.TierObserve] = 0.5
			return c
		},
		"mode on async-only tier": func(c Config) Config {
			c.Mode[contract.TierTag] = contract.ModeInline
			return c
		},
		"tier 1 fail-closed": func(c Config) Config {
			c.FailClosed[contract.TierTag] = true
			return c
		},
		"tier 3 fail-open": func(c Config) Config {
			c.FailClosed[contract.TierJail] = false
			return c
		},
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			if err := mut(DefaultConfig()).Validate(); err == nil {
				t.Errorf("expected Validate to reject %q", name)
			}
		})
	}
}

func TestConfigValidate_DefaultIsValid(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default config must validate: %v", err)
	}
}

func TestOnEngineUnavailable_FailOpenT1_FailClosedT3(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.OnEngineUnavailable(contract.TierTag) {
		t.Error("Tier 1 must fail-open (allow) on engine outage")
	}
	if cfg.OnEngineUnavailable(contract.TierJail) {
		t.Error("Tier 3 must fail-closed (deny) on engine outage")
	}
	if !cfg.OnEngineUnavailable(contract.TierObserve) {
		t.Error("Tier 0 carries no inline enforcement; must allow")
	}
}
