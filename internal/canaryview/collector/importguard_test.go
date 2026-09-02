package collector_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"strings"
	"testing"
)

const collectorModulePath = "github.com/canarysting/canarysting"

func TestCollectorDependsOnlyOnCanonicalModelAndStandardLibrary(t *testing.T) {
	pkg := collectorModulePath + "/internal/canaryview/collector"
	out, err := exec.Command("go", "list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}{{end}}`, pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list collector dependencies: %v\n%s", err, out)
	}
	nonStandard := strings.Fields(string(out))
	want := map[string]bool{
		collectorModulePath + "/internal/canaryview/model": true,
		pkg: true,
	}
	if len(nonStandard) != len(want) {
		t.Fatalf("collector has unexpected non-standard dependencies: %v", nonStandard)
	}
	for _, dependency := range nonStandard {
		if !want[dependency] {
			t.Fatalf("collector has unexpected dependency %s", dependency)
		}
	}
}

func TestSourceInterfaceExposesOnlyReadCapability(t *testing.T) {
	files := token.NewFileSet()
	tree, err := parser.ParseFile(files, "contract.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, declaration := range tree.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "Source" {
				continue
			}
			found = true
			interfaceType, ok := typeSpec.Type.(*ast.InterfaceType)
			if !ok {
				t.Fatal("Source is not an interface")
			}
			got := make(map[string]bool)
			for _, method := range interfaceType.Methods.List {
				for _, name := range method.Names {
					got[name.Name] = true
				}
			}
			if len(got) != 2 || !got["Descriptor"] || !got["Read"] {
				t.Fatalf("Source interface must expose only Descriptor and Read, got %v", got)
			}
		}
	}
	if !found {
		t.Fatal("Source interface not found")
	}
}
