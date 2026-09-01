package model_test

import (
	"bufio"
	"bytes"
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
	format := `{{.ImportPath}}{{"\t"}}{{join .Deps " "}}`
	command := exec.Command("go", "list", "-f", format, "./...")
	command.Dir = "../../.."
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list CanarySting runtime dependencies: %v\n%s", err, out)
	}
	modelPackage := modulePath + "/internal/canaryview/model"
	prohibitedRoots := []string{
		modulePath + "/internal/contract",
		modulePath + "/internal/engine",
		modulePath + "/internal/canary",
		modulePath + "/internal/sting",
		modulePath + "/internal/intelligence",
		modulePath + "/internal/identity",
		modulePath + "/internal/operator",
		modulePath + "/adapters",
		modulePath + "/bpf",
		modulePath + "/api/convert",
		modulePath + "/api/enginegrpc",
	}
	checked := 0
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		pkg, dependencies, ok := strings.Cut(scanner.Text(), "\t")
		if !ok {
			t.Fatalf("unexpected go list output %q", scanner.Text())
		}
		if !hasPackageRoot(pkg, prohibitedRoots) {
			continue
		}
		checked++
		for _, dependency := range strings.Fields(dependencies) {
			if dependency == modelPackage || strings.HasPrefix(dependency, modelPackage+"/") {
				t.Fatalf("CanarySting package %s depends on CanaryView model through %s", pkg, dependency)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("CanarySting runtime guard did not inspect any packages")
	}
}

func hasPackageRoot(pkg string, roots []string) bool {
	for _, root := range roots {
		if pkg == root || strings.HasPrefix(pkg, root+"/") {
			return true
		}
	}
	return false
}
