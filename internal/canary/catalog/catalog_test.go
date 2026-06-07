package catalog

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"go/parser"
	"go/token"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/harmless"
)

func fixedCatalog(t *testing.T, seed int64) *Catalog {
	t.Helper()
	c, err := New(Config{Rand: mrand.New(mrand.NewSource(seed)), HarmlessSamples: 16})
	if err != nil {
		t.Fatalf("catalog construction failed: %v", err)
	}
	return c
}

func TestDefaultCatalogConstructsHarmlessly(t *testing.T) {
	c := Default() // panics if any shipped generator is not harmless
	if got := len(c.Types()); got != 5 {
		t.Fatalf("expected 5 canary types, got %d", got)
	}
}

func TestEveryGeneratorIsProvablyHarmless(t *testing.T) {
	c := fixedCatalog(t, 1)
	for _, typ := range c.Types() {
		for i := 0; i < 300; i++ {
			inst, err := c.Generate(typ) // Generate runs IsHarmless as a fail-closed gate
			if err != nil {
				t.Fatalf("%s sample %d not harmless: %v", typ, i, err)
			}
			if !carriesCanaryMarker(inst.Payload) {
				t.Fatalf("%s sample %d missing canary marker", typ, i)
			}
		}
	}
}

func TestSecretPredicateRejectsRealKey(t *testing.T) {
	// A genuine RSA key, PEM-armored, MUST fail isInertPrivateKey (it parses).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	realPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	if harmless.IsInertPrivateKey(realPEM) {
		t.Fatal("a real RSA key passed harmless.IsInertPrivateKey — the predicate has no teeth")
	}
	// And it must be rejected if smuggled into a fake_secret instance.
	bad := Instance{Type: TypeFakeSecret, Payload: append(realPEM, []byte("\n# "+canaryMarker+"X\n")...)}
	c := fixedCatalog(t, 2)
	if err := c.IsHarmless(bad); err == nil {
		t.Fatal("a real key smuggled into a decoy was accepted")
	}
}

func TestSecretPredicateRejectsEncryptedAndOpenSSHKeys(t *testing.T) {
	// The pure predicate teeth (encrypted/OpenSSH/inert) live in internal/harmless;
	// here we prove the catalog's IsHarmless gate rejects such keys smuggled into a
	// decoy instance — the catalog-integration half of the guarantee.
	c := fixedCatalog(t, 5)
	encrypted := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjBABg" +
		"kqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI\n-----END ENCRYPTED PRIVATE KEY-----\n# " + canaryMarker + "X\n")
	if err := c.IsHarmless(Instance{Type: TypeFakeSecret, Payload: encrypted}); err == nil {
		t.Fatal("an encrypted (real) key smuggled into a decoy was accepted")
	}
	openssh := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n# " + canaryMarker + "X\n")
	if err := c.IsHarmless(Instance{Type: TypeFakeSecret, Payload: openssh}); err == nil {
		t.Fatal("an OpenSSH-format key smuggled into a decoy was accepted")
	}
}

func TestCrossScanIsUniversalBackstop(t *testing.T) {
	c := fixedCatalog(t, 5)
	// fake_secret whose OWN predicate passes (inert PEM + marker) but which smuggles
	// a live AKIA / routable host. The per-type predicate does not host-scan, so
	// only the universal crossScan can catch these — isolating it as the backstop.
	inertPEM := "-----BEGIN RSA PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAA\n-----END RSA PRIVATE KEY-----\n"
	mk := "# " + canaryMarker + "X\n"
	cases := map[string]string{
		"live-aws-key":  inertPEM + mk + "extra = AKIA1234567890ABCDEF\n",
		"routable-host": inertPEM + mk + "# beacon https://attacker.evil.com/track\n",
	}
	for name, payload := range cases {
		inst := Instance{Type: TypeFakeSecret, Payload: []byte(payload)}
		if err := fakeSecretHarmless(inst); err != nil {
			t.Fatalf("%s: per-type predicate should pass (to isolate crossScan), but failed: %v", name, err)
		}
		if err := c.IsHarmless(inst); err == nil {
			t.Fatalf("%s: crossScan failed to reject a smuggled live secret/host", name)
		}
	}
}

func TestFakeSecretJWTForkIsDeterministicAndHarmless(t *testing.T) {
	// Find a seed that takes the JWT fork (the other tests' seed 99 hits PEM), so
	// both branches' determinism + harmlessness are pinned.
	var jwtSeed int64 = -1
	for s := int64(0); s < 64; s++ {
		c := fixedCatalog(t, s)
		inst, _ := c.Generate(TypeFakeSecret)
		if strings.Contains(string(inst.Payload), "vault token (decoy)") {
			jwtSeed = s
			break
		}
	}
	if jwtSeed < 0 {
		t.Skip("no JWT-fork seed found in range")
	}
	a, _ := fixedCatalog(t, jwtSeed).Generate(TypeFakeSecret)
	b, _ := fixedCatalog(t, jwtSeed).Generate(TypeFakeSecret)
	if string(a.Payload) != string(b.Payload) {
		t.Fatal("JWT fork is not deterministic for a fixed seed")
	}
	if !harmless.IsUnsignedJWT(jwtRe.FindString(string(a.Payload))) {
		t.Fatal("JWT-fork instance does not carry an unsigned JWT")
	}
}

func TestGenerateIsConcurrencySafe(t *testing.T) {
	// The seeder calls Generate from many goroutines; the shared RNG must be
	// safe. This test fails under -race if the entropy source is not guarded.
	c := fixedCatalog(t, 11)
	types := c.Types()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := c.Generate(types[i%len(types)]); err != nil {
				t.Errorf("concurrent Generate failed: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestCatalogNewProvesHarmlessAtConstruction(t *testing.T) {
	// An entry whose generator emits a real key but whose Harmless lies (nil)
	// must still be caught by the construction-time cross-scan.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	realPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	bad := Entry{
		Type:     contract.CanaryType("evil"),
		Harmless: func(Instance) error { return nil }, // lies
		Generate: func() (Instance, error) {
			return Instance{Type: "evil", Payload: append(realPEM, []byte("# "+canaryMarker+"X")...)}, nil
		},
	}
	if _, err := build([]Entry{bad}, 8); err == nil {
		t.Fatal("construction registered an entry that emits a real key")
	}
}

func TestGenerateIsFailClosed(t *testing.T) {
	// Register with 0 construction samples, then prove Generate's runtime gate
	// catches a non-harmless payload.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	realPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	bad := Entry{
		Type:     contract.CanaryType("evil"),
		Harmless: func(Instance) error { return nil },
		Generate: func() (Instance, error) {
			return Instance{Type: "evil", Payload: append(realPEM, []byte("# "+canaryMarker+"X")...)}, nil
		},
	}
	c, err := build([]Entry{bad}, 0)
	if err != nil {
		t.Fatalf("build with 0 samples should skip construction check: %v", err)
	}
	if _, err := c.Generate("evil"); err == nil {
		t.Fatal("Generate emitted a non-harmless instance (gate is not fail-closed)")
	}
}

func TestGeneratorsAreReproducible(t *testing.T) {
	a := fixedCatalog(t, 99)
	b := fixedCatalog(t, 99)
	for _, typ := range a.Types() {
		ia, _ := a.Generate(typ)
		ib, _ := b.Generate(typ)
		if string(ia.Payload) != string(ib.Payload) {
			t.Fatalf("%s: same seed produced different output (not pure/deterministic)", typ)
		}
	}
}

func TestSeedWeightOrdering(t *testing.T) {
	c := fixedCatalog(t, 3)
	w := c.SeedWeights()
	order := []contract.CanaryType{TypePlantedCredential, TypeFakeSecret, TypeDecoyFile, TypeFakeBucket, TypeFakeEndpoint}
	for i := 0; i+1 < len(order); i++ {
		if !(w[order[i]] >= w[order[i+1]]) {
			t.Fatalf("seed weights not ordered by intent strength: %s(%.2f) < %s(%.2f)", order[i], w[order[i]], order[i+1], w[order[i+1]])
		}
	}
	if !(w[TypePlantedCredential] > w[TypeFakeEndpoint]) {
		t.Fatal("planted_credential must outrank fake_endpoint")
	}
	for typ, v := range w { // stay inside calibration's [0.1, 2.0] clamp
		if v < 0.1 || v > 2.0 {
			t.Fatalf("%s seed weight %.2f outside [0.1, 2.0]", typ, v)
		}
	}
}

func TestNoChainedCredential(t *testing.T) {
	// Independence (ARCH §11): a decoy must carry exactly its OWN single marker —
	// no second marker token that could act as a pointer to unlock another canary —
	// and must not embed any other sampled instance's full marker.
	c := fixedCatalog(t, 7)
	type sample struct {
		typ     contract.CanaryType
		marker  string
		payload string
	}
	var samples []sample
	for _, typ := range c.Types() {
		for i := 0; i < 30; i++ {
			inst, _ := c.Generate(typ)
			p := string(inst.Payload)
			if n := strings.Count(p, canaryMarker); n != 1 {
				t.Fatalf("%s payload carries %d markers, want exactly 1 (a second marker is an unlock pointer)", typ, n)
			}
			idx := strings.Index(p, canaryMarker)
			samples = append(samples, sample{typ, p[idx : idx+len(canaryMarker)+12], p})
		}
	}
	for _, a := range samples {
		for _, b := range samples {
			if a.marker != b.marker && strings.Contains(a.payload, b.marker) {
				t.Fatalf("%s payload references another canary's marker (%s) — chained-credential edge", a.typ, b.marker)
			}
		}
	}
}

func TestCanaryDoesNotImportEngine(t *testing.T) {
	// Production (non-test) code in internal/canary must not import internal/engine
	// — so the seed ordering can never leak where the engine reads live weight, and
	// the canary layer carries no decision dependency. Parsed via go/parser (import
	// specs only) so comments/strings cannot cause false positives or negatives.
	if bad := importsMatching(t, "../", "canarysting/internal/engine"); len(bad) > 0 {
		t.Errorf("the canary layer must not import the engine; offenders: %v", bad)
	}
}

// importsMatching returns "file: importpath" for every production (non-test) .go
// file under root whose import paths contain substr.
func importsMatching(t *testing.T, root, substr string) []string {
	t.Helper()
	var bad []string
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, substr) {
				bad = append(bad, path+": "+imp.Path.Value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return bad
}
