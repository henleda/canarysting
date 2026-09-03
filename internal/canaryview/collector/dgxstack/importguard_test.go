package dgxstack_test

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestReferenceNormalizersCannotReachDecisionOrActionPackages(t *testing.T) {
	for _, file := range []string{"adapters.go", "normalize.go"} {
		tree, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range tree.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"/internal/engine/scoring", "/internal/engine/tiers",
				"/internal/canary/signal", "/internal/sting/", "/bpf/enforce", "/bpf/sockops",
			} {
				if strings.Contains(path, forbidden) {
					t.Fatalf("%s imports forbidden decision/action package %s", file, path)
				}
			}
		}
	}
}
