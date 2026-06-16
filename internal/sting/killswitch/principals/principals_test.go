package principals

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sha256hex is the helper an operator runs out of band to compute the digest of a
// raw token before placing it in the principals file (the tests mirror it so a
// presented raw token resolves to its principal).
func sha256hex(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// A well-formed two-principal file loads, and each raw token resolves to the
// VERIFIED name + role via the same hash-then-map-get the admin uses.
func TestLoadPrincipalsRoundTrip(t *testing.T) {
	aliceTok := "alice-raw-bearer-token-ABC123"
	botTok := "ir-bot-raw-bearer-token-XYZ789"
	doc := `{
	  "principals": [
	    { "name": "alice",  "token_sha256": "` + sha256hex(aliceTok) + `", "role": "operator" },
	    { "name": "ir-bot", "token_sha256": "` + sha256hex(botTok) + `", "role": "viewer" }
	  ]
	}`
	set, err := LoadPrincipals(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("LoadPrincipals: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}

	p, ok := set.Lookup(sha256hex(aliceTok))
	if !ok || p.Name != "alice" || p.Role != RoleOperator {
		t.Fatalf("alice lookup = %+v ok=%v, want {alice operator}", p, ok)
	}
	p, ok = set.Lookup(sha256hex(botTok))
	if !ok || p.Name != "ir-bot" || p.Role != RoleViewer {
		t.Fatalf("ir-bot lookup = %+v ok=%v, want {ir-bot viewer}", p, ok)
	}

	// An unknown token digest does NOT resolve (the admin maps this to 401).
	if _, ok := set.Lookup(sha256hex("some-token-not-in-the-file")); ok {
		t.Fatal("unknown token must NOT resolve")
	}
}

// LoadPrincipalsFile reads + validates from a path (the boot path).
func TestLoadPrincipalsFile(t *testing.T) {
	doc := `{"principals":[{"name":"a","token_sha256":"` + sha256hex("t") + `","role":"operator"}]}`
	p := filepath.Join(t.TempDir(), "killswitch-principals.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := LoadPrincipalsFile(p)
	if err != nil {
		t.Fatalf("LoadPrincipalsFile: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("Len = %d, want 1", set.Len())
	}
	if _, err := LoadPrincipalsFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("a missing file must error (fail-closed)")
	}
}

// Every malformed shape is REFUSED loudly (fail-closed). Table-driven so each
// validation rule has a named case.
func TestLoadPrincipalsLoudFailures(t *testing.T) {
	good := sha256hex("tok")
	other := sha256hex("tok2")
	cases := []struct {
		name string
		doc  string
		want string // substring expected in the error
	}{
		{
			name: "empty list refused (fail-closed, not 'no one authorized')",
			doc:  `{"principals":[]}`,
			want: "EMPTY",
		},
		{
			name: "missing principals key => empty => refused",
			doc:  `{}`,
			want: "EMPTY",
		},
		{
			name: "empty name",
			doc:  `{"principals":[{"name":"  ","token_sha256":"` + good + `","role":"operator"}]}`,
			want: "empty name",
		},
		{
			name: "duplicate name",
			doc:  `{"principals":[{"name":"a","token_sha256":"` + good + `","role":"operator"},{"name":"a","token_sha256":"` + other + `","role":"viewer"}]}`,
			want: "duplicate name",
		},
		{
			name: "token not 64 hex (too short)",
			doc:  `{"principals":[{"name":"a","token_sha256":"abc","role":"operator"}]}`,
			want: "64 lowercase hex",
		},
		{
			name: "token uppercase hex rejected (must be lowercase canonical)",
			doc:  `{"principals":[{"name":"a","token_sha256":"` + strings.ToUpper(good) + `","role":"operator"}]}`,
			want: "64 lowercase hex",
		},
		{
			name: "token non-hex chars",
			doc:  `{"principals":[{"name":"a","token_sha256":"zzzz5678901234567890123456789012345678901234567890123456789012zz","role":"operator"}]}`,
			want: "64 lowercase hex",
		},
		{
			name: "duplicate token_sha256 (same raw token issued twice)",
			doc:  `{"principals":[{"name":"a","token_sha256":"` + good + `","role":"operator"},{"name":"b","token_sha256":"` + good + `","role":"viewer"}]}`,
			want: "duplicate token_sha256",
		},
		{
			name: "unknown role",
			doc:  `{"principals":[{"name":"a","token_sha256":"` + good + `","role":"admin"}]}`,
			want: "unknown role",
		},
		{
			name: "empty role",
			doc:  `{"principals":[{"name":"a","token_sha256":"` + good + `","role":""}]}`,
			want: "unknown role",
		},
		{
			name: "malformed json",
			doc:  `{"principals":[`,
			want: "parse principals file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadPrincipals(strings.NewReader(tc.doc))
			if err == nil {
				t.Fatalf("expected load to fail (%s), got nil error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
