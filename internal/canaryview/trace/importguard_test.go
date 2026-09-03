package trace_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestTraceDependsOnlyOnCorrelationModelAndStandardLibrary(t *testing.T) {
	t.Parallel()
	const module = "github.com/canarysting/canarysting"
	pkg := module + "/internal/canaryview/trace"
	allowed := map[string]bool{
		pkg:                                   true,
		module + "/internal/canaryview/model": true,
		module + "/internal/canaryview/correlation": true,
	}
	out, err := exec.Command("go", "list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}{{end}}`, pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list trace dependencies: %v\n%s", err, out)
	}
	for _, dependency := range strings.Fields(string(out)) {
		if !allowed[dependency] {
			t.Fatalf("trace package has unexpected non-standard dependency %q", dependency)
		}
	}
}
