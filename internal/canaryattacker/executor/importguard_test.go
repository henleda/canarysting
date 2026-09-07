package executor_test

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

func TestExecutorCannotAcquireShellFilesystemOrControlPlaneAuthority(t *testing.T) {
	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"os", "os/exec", "syscall", "path/filepath",
		"k8s.io/", "github.com/docker/", "github.com/moby/",
	}
	const modulePrefix = "github.com/canarysting/canarysting/"
	const groundTruthPackage = modulePrefix + "internal/canaryattacker/groundtruth"
	files := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files++
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, declaration := range parsed.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.IMPORT {
				continue
			}
			for _, specification := range general.Specs {
				dependency, err := strconv.Unquote(specification.(*ast.ImportSpec).Path.Value)
				if err != nil {
					return err
				}
				if strings.HasPrefix(dependency, modulePrefix) && dependency != groundTruthPackage {
					t.Errorf("production executor file %s imports non-contract repository package %s", filepath.Base(path), dependency)
				}
				for _, denied := range forbidden {
					if dependency == denied || strings.HasPrefix(dependency, denied) {
						t.Errorf("production executor file %s imports forbidden authority %s", filepath.Base(path), dependency)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("executor import guard did not inspect production files")
	}
}
