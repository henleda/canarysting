package groundtruth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/canarysting/canarysting"

func TestGroundTruthContractHasOnlyStandardLibraryDependencies(t *testing.T) {
	imports := repositoryImports(t)
	pkg := modulePath + "/internal/canaryattacker/groundtruth"
	for _, dependency := range imports[pkg] {
		first := strings.Split(dependency, "/")[0]
		if strings.Contains(first, ".") {
			t.Fatalf("ground-truth contract has non-standard dependency %s", dependency)
		}
	}
}

func TestDecisionAndEnforcementRuntimeDoNotDependOnGroundTruth(t *testing.T) {
	imports := repositoryImports(t)
	groundTruthPackage := modulePath + "/internal/canaryattacker/groundtruth"
	prohibitedRoots := []string{
		modulePath + "/internal/contract", modulePath + "/internal/engine",
		modulePath + "/internal/canary", modulePath + "/internal/sting",
		modulePath + "/internal/intelligence", modulePath + "/internal/canaryview",
		modulePath + "/adapters", modulePath + "/bpf",
	}
	checked := 0
	for pkg := range imports {
		if !hasPackageRoot(pkg, prohibitedRoots) {
			continue
		}
		checked++
		if dependencyPath(imports, pkg, groundTruthPackage, map[string]bool{}) {
			t.Fatalf("decision/enforcement package %s depends on synthetic ground truth", pkg)
		}
	}
	if checked == 0 {
		t.Fatal("runtime import guard did not inspect any packages")
	}
}

func repositoryImports(t *testing.T) map[string][]string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string][]string)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relativeDirectory, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		pkg := modulePath
		if relativeDirectory != "." {
			pkg += "/" + filepath.ToSlash(relativeDirectory)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		if _, exists := result[pkg]; !exists {
			result[pkg] = nil
		}
		for _, declaration := range parsed.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.IMPORT {
				continue
			}
			for _, spec := range general.Specs {
				importSpec := spec.(*ast.ImportSpec)
				dependency, err := strconv.Unquote(importSpec.Path.Value)
				if err != nil {
					return err
				}
				result[pkg] = append(result[pkg], dependency)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func dependencyPath(graph map[string][]string, current, target string, visiting map[string]bool) bool {
	if visiting[current] {
		return false
	}
	visiting[current] = true
	defer delete(visiting, current)
	for _, dependency := range graph[current] {
		if dependency == target || (strings.HasPrefix(dependency, modulePath+"/") && dependencyPath(graph, dependency, target, visiting)) {
			return true
		}
	}
	return false
}

func hasPackageRoot(pkg string, roots []string) bool {
	for _, root := range roots {
		if pkg == root || strings.HasPrefix(pkg, root+"/") {
			return true
		}
	}
	return false
}
