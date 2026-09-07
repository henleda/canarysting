package planner

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlannerImportBoundary(t *testing.T) {
	allowed := map[string]bool{
		"github.com/canarysting/canarysting/internal/canaryattacker/executor":    true,
		"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if strings.Contains(path, "/internal/") && !allowed[path] {
				t.Fatalf("forbidden internal import %q", path)
			}
		}
	}
}
