package evaluation_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestEvaluationIsAnOuterLaboratoryBoundary(t *testing.T) {
	t.Parallel()
	const module = "github.com/canarysting/canarysting"
	const pkg = module + "/internal/canaryattacker/evaluation"
	allowed := map[string]bool{
		pkg: true,
		module + "/internal/canaryattacker/groundtruth": true,
		module + "/internal/canaryview/model":           true,
		module + "/internal/canaryview/correlation":     true,
		module + "/internal/canaryview/trace":           true,
	}
	out, err := exec.Command("go", "list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}{{end}}`, pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list evaluation dependencies: %v\n%s", err, out)
	}
	for _, dependency := range strings.Fields(string(out)) {
		if !allowed[dependency] {
			t.Fatalf("evaluation package has unexpected non-standard dependency %q", dependency)
		}
	}
}
