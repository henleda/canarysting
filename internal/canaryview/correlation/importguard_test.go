package correlation_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestCorrelationDependsOnlyOnModelAndStandardLibrary(t *testing.T) {
	t.Parallel()
	const module = "github.com/canarysting/canarysting"
	pkg := module + "/internal/canaryview/correlation"
	modelPackage := module + "/internal/canaryview/model"
	out, err := exec.Command("go", "list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}{{end}}`, pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list correlation dependencies: %v\n%s", err, out)
	}
	for _, dependency := range strings.Fields(string(out)) {
		if dependency != pkg && dependency != modelPackage {
			t.Fatalf("correlation package has unexpected non-standard dependency %q", dependency)
		}
	}
}
