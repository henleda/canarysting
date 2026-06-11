package decoy

import (
	"go/parser"
	gotoken "go/token" // aliased: this package defines a token() builder
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/canarysting/canarysting/internal/harmless"
)

// TestImportsStdlibOnly guards decoy's load-bearing import constraint. decoy sits
// INSIDE attrition's allowed import set {contract, harmless, stdlib}, but the
// attrition import-graph test is NON-transitive (it parses only attrition's own
// dir), so a future decoy.go importing a forbidden package (intelligence / engine /
// canary / adapters) would make attrition transitively violate its constraint with
// no attrition-side test failing. Guard it at the source: production decoy code may
// import only stdlib (optionally internal/contract).
func TestImportsStdlibOnly(t *testing.T) {
	fset := gotoken.NewFileSet()
	var bad []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.Contains(p, "canarysting/internal/") && p != "github.com/canarysting/canarysting/internal/contract" {
				bad = append(bad, path+": "+p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Errorf("decoy production code must import only stdlib (optionally internal/contract); found forbidden imports: %v", bad)
	}
}

// TestBuildersHarmlessByConstruction proves every decoy builder emits bodies that
// pass harmless.CrossScan for a wide range of seeds — no live AWS key, no
// parseable/encrypted private key, no routable host can be smuggled out, by
// construction. Mirrors the canary catalog's construction-time self-test.
func TestBuildersHarmlessByConstruction(t *testing.T) {
	for seed := uint64(0); seed < 4096; seed++ {
		body := strings.Join([]string{
			"AWS_ACCESS_KEY_ID=" + ExampleAWSKeyID(seed),
			"AWS_SECRET_ACCESS_KEY=" + ExampleAWSSecret(mix(seed, 1)),
			"DATABASE_URL=postgres://svc:decoy@" + ReservedHost(seed) + ":5432/payments",
		}, "\n") + "\n"
		if err := harmless.CrossScan([]byte(body)); err != nil {
			t.Fatalf("seed %d: decoy body not provably harmless: %v\nbody:\n%s", seed, err, body)
		}
	}
}

// TestKeyIDInExampleNamespace pins the AWS EXAMPLE-namespace shape the harmless
// validator keys on (AKIA…EXAMPLE), so a builder change that broke the namespace
// would fail loudly rather than silently mint a real-looking key.
func TestKeyIDInExampleNamespace(t *testing.T) {
	for seed := uint64(0); seed < 256; seed++ {
		id := ExampleAWSKeyID(seed)
		if !strings.HasPrefix(id, "AKIA") || !strings.HasSuffix(id, "EXAMPLE") || len(id) != 20 {
			t.Fatalf("seed %d: key id %q not in the AKIA…EXAMPLE (20-char) namespace", seed, id)
		}
		if !strings.HasSuffix(ExampleAWSSecret(seed), "EXAMPLEKEY") {
			t.Fatalf("seed %d: secret not in the EXAMPLE namespace", seed)
		}
	}
}

// TestDeterministic confirms builders are pure functions of the seed (same seed →
// same bytes; different seed → different bytes), the property attrition relies on
// to make a re-fetch idempotent per flow.
func TestDeterministic(t *testing.T) {
	if ExampleAWSKeyID(42) != ExampleAWSKeyID(42) || ReservedHost(7) != ReservedHost(7) {
		t.Fatal("builders are not deterministic for a fixed seed")
	}
	if ExampleAWSKeyID(1) == ExampleAWSKeyID(2) {
		t.Fatal("distinct seeds produced identical key ids")
	}
}
