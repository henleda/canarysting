package kernel

import (
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		release  string
		maj, min int
		wantErr  bool
	}{
		{"6.8.0-45-generic", 6, 8, false},
		{"5.10.0", 5, 10, false},
		{"5.15.0-1051-aws", 5, 15, false},
		{"5.10", 5, 10, false},
		{"4.19.0-21-amd64", 4, 19, false},
		{"6", 6, 0, false},
		{"  5.10.0  ", 5, 10, false}, // surrounding whitespace tolerated
		{"", 0, 0, true},
		{"not-a-version", 0, 0, true},
		{"garbage", 0, 0, true},
	}
	for _, c := range cases {
		maj, min, err := parseVersion(c.release)
		if (err != nil) != c.wantErr {
			t.Errorf("parseVersion(%q) err=%v, wantErr=%v", c.release, err, c.wantErr)
			continue
		}
		if err == nil && (maj != c.maj || min != c.min) {
			t.Errorf("parseVersion(%q) = %d.%d, want %d.%d", c.release, maj, min, c.maj, c.min)
		}
	}
}

func TestCheckReleaseAcceptsAtOrAboveMinimum(t *testing.T) {
	for _, r := range []string{"5.10.0", "5.10", "5.15.0-generic", "6.8.0-45-generic", "5.11", "7.0.0"} {
		if err := checkRelease(r); err != nil {
			t.Errorf("checkRelease(%q) = %v, want nil (meets %d.%d)", r, err, MinMajor, MinMinor)
		}
	}
}

func TestCheckReleaseRejectsBelowMinimum(t *testing.T) {
	for _, r := range []string{"5.9.0", "5.4.0-generic", "4.19.0", "3.10.0-1160.el7"} {
		err := checkRelease(r)
		if err == nil {
			t.Errorf("checkRelease(%q) = nil, want below-minimum error", r)
			continue
		}
		if !strings.Contains(err.Error(), "below the minimum") {
			t.Errorf("checkRelease(%q) error = %q, want a 'below the minimum' message", r, err)
		}
	}
}

func TestCheckReleaseRejectsUnparseable(t *testing.T) {
	for _, r := range []string{"", "garbage", "not-a-version"} {
		if err := checkRelease(r); err == nil {
			t.Errorf("checkRelease(%q) = nil, want parse error", r)
		}
	}
}
