package testgate

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type goPackage struct {
	ImportPath string   `json:"ImportPath"`
	Dir        string   `json:"Dir"`
	Standard   bool     `json:"Standard"`
	Deps       []string `json:"Deps"`
}

// RunNonScenarioGo runs every repository Go test except the exact tests owned
// by the versioned adversarial manifest. Those tests run once through scenario
// nodes so their seed, ground truth, parser, cleanup, and replay evidence remain
// authoritative instead of being duplicated by a broad package command.
func RunNonScenarioGo(race bool, scenarios ScenarioManifest) error {
	names := make(map[string]bool)
	for _, scenario := range scenarios.Scenarios {
		for _, name := range scenario.RequiredTestPasses {
			names[name] = true
		}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	quoted := make([]string, 0, len(ordered))
	for _, name := range ordered {
		quoted = append(quoted, regexp.QuoteMeta(name))
	}
	args := []string{"test"}
	if race {
		args = append(args, "-race")
	} else {
		args = append(args, "-count=1")
	}
	if len(quoted) > 0 {
		args = append(args, "-skip", "^("+strings.Join(quoted, "|")+")$")
	}
	packages := []string{"./..."}
	if !race {
		listed, err := exec.Command("go", "list", "./...").Output()
		if err != nil {
			return fmt.Errorf("discover ordinary Go packages: %w", err)
		}
		packages = packages[:0]
		for _, pkg := range strings.Fields(string(listed)) {
			if strings.Contains(pkg, "/test/integration") || strings.Contains(pkg, "/tests/integration") {
				continue
			}
			packages = append(packages, pkg)
		}
		if len(packages) == 0 {
			return fmt.Errorf("ordinary Go package discovery returned no packages")
		}
	}
	args = append(args, packages...)
	command := exec.Command("go", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("Go non-scenario suite: %w", err)
	}
	return nil
}

// RunAffectedGo runs the smallest conservative package set for the current
// merge-base diff. Uncertain module/package impact expands to ./....
func RunAffectedGo(mode string, files []string) error {
	packages, err := affectedGoPackages(files)
	if err != nil {
		fmt.Printf("affected Go selection expanded to ./...: %v\n", err)
		packages = []string{"./..."}
	}
	if len(packages) == 0 {
		fmt.Println("PASS: no Go package is affected")
		return nil
	}
	args := []string{"test"}
	switch mode {
	case "build":
		args = append(args, "-run", "^$")
	case "test":
		args = append(args, "-count=1")
	case "race":
		args = append(args, "-race", "-count=1")
	case "integration":
		filtered := packages[:0]
		for _, pkg := range packages {
			if pkg == "./test/integration" || strings.HasPrefix(pkg, "./test/integration/") ||
				pkg == "./tests/integration" || strings.HasPrefix(pkg, "./tests/integration/") {
				filtered = append(filtered, pkg)
			}
		}
		packages = filtered
		if len(packages) == 0 {
			fmt.Println("PASS: no local integration package is affected")
			return nil
		}
		args = append(args, "-count=1")
	default:
		return fmt.Errorf("unknown affected Go mode %q", mode)
	}
	args = append(args, packages...)
	fmt.Printf("affected Go %s packages: %s\n", mode, strings.Join(packages, ","))
	command := exec.Command("go", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("go %s affected packages: %w", mode, err)
	}
	return nil
}

func affectedGoPackages(files []string) ([]string, error) {
	root, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	module, err := modulePath("go.mod")
	if err != nil {
		return nil, err
	}
	targets := make(map[string]bool)
	goChanged := false
	for _, file := range files {
		if file == "go.mod" || file == "go.sum" {
			return []string{"./..."}, nil
		}
		if !strings.HasSuffix(file, ".go") {
			continue
		}
		goChanged = true
		dir := filepath.ToSlash(filepath.Dir(file))
		if dir == "." {
			targets[module] = true
		} else {
			targets[module+"/"+strings.TrimPrefix(dir, "./")] = true
		}
	}
	if !goChanged {
		return nil, nil
	}
	command := exec.Command("go", "list", "-deps", "-test", "-json", "./...")
	output, err := command.Output()
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	selected := make(map[string]bool)
	for {
		var pkg goPackage
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if pkg.Standard || pkg.Dir == "" || !strings.HasPrefix(pkg.ImportPath, module) || strings.Contains(pkg.ImportPath, " [") || strings.HasSuffix(pkg.ImportPath, ".test") {
			continue
		}
		impacted := targets[pkg.ImportPath]
		if !impacted {
			for _, dep := range pkg.Deps {
				if targets[dep] {
					impacted = true
					break
				}
			}
		}
		if !impacted {
			continue
		}
		relative, err := filepath.Rel(root, pkg.Dir)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("affected package %s is outside repository", pkg.ImportPath)
		}
		pattern := "./" + filepath.ToSlash(relative)
		if pattern == "./." {
			pattern = "."
		}
		selected[pattern] = true
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("changed Go package was not discoverable")
	}
	packages := make([]string, 0, len(selected))
	for pkg := range selected {
		packages = append(packages, pkg)
	}
	sort.Strings(packages)
	return packages, nil
}

func modulePath(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("go.mod has no module directive")
}
