package model_test

import (
	"os/exec"
	"strings"
	"testing"
)

const modulePath = "github.com/canarysting/canarysting"

func TestModelHasOnlyStandardLibraryDependencies(t *testing.T) {
	pkg := modulePath + "/internal/canaryview/model"
	out, err := exec.Command("go", "list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}{{end}}`, pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list model dependencies: %v\n%s", err, out)
	}
	nonStandard := strings.Fields(string(out))
	if len(nonStandard) != 1 || nonStandard[0] != pkg {
		t.Fatalf("model must be a standard-library-only leaf; non-standard dependencies: %v", nonStandard)
	}
}

func TestCanaryStingRuntimeDoesNotDependOnCanaryView(t *testing.T) {
	packages := []string{
		modulePath + "/internal/contract",
		modulePath + "/internal/engine/...",
		modulePath + "/internal/intelligence/...",
		modulePath + "/internal/sting/...",
		modulePath + "/adapters/...",
	}
	out, err := exec.Command("go", append([]string{"list", "-deps"}, packages...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("go list CanarySting runtime dependencies: %v\n%s", err, out)
	}
	for _, dependency := range strings.Fields(string(out)) {
		if dependency == modulePath+"/internal/canaryview/model" || strings.HasPrefix(dependency, modulePath+"/internal/canaryview/model/") {
			t.Fatalf("CanarySting runtime depends on CanaryView model through %s", dependency)
		}
	}
}
