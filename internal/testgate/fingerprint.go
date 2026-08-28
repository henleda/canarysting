package testgate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

func BuildFingerprint(manifestDigest string) (Fingerprint, error) {
	revision, err := outputOf("git", "rev-parse", "HEAD")
	if err != nil {
		return Fingerprint{}, fmt.Errorf("source revision: %w", err)
	}
	status, err := outputOf("git", "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return Fingerprint{}, fmt.Errorf("working tree status: %w", err)
	}
	diff, err := outputOf("git", "diff", "--binary", "HEAD", "--", ".", ":(exclude).test-artifacts")
	if err != nil {
		return Fingerprint{}, fmt.Errorf("working tree diff: %w", err)
	}
	changed := changedFiles(status)
	working := sha256.New()
	working.Write([]byte(status + "\x00" + diff))
	for _, path := range changed {
		info, statErr := os.Stat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return Fingerprint{}, fmt.Errorf("fingerprint %s: %w", path, readErr)
		}
		working.Write([]byte("\x00" + path + "\x00"))
		working.Write(data)
	}
	workingHash := working.Sum(nil)
	versions := make([]string, 0, 5)
	for _, command := range [][]string{{"go", "version"}, {"node", "--version"}, {"npm", "--version"}, {"clang", "--version"}} {
		value, versionErr := outputOf(command[0], command[1:]...)
		if versionErr != nil {
			value = "unavailable"
		}
		versions = append(versions, command[0]+"="+strings.Split(value, "\n")[0])
	}
	toolHash := sha256.Sum256([]byte(strings.Join(versions, "\n")))
	environment := runtime.GOOS + "/" + runtime.GOARCH
	envHash := sha256.Sum256([]byte(environment))
	return Fingerprint{
		SourceRevision: strings.TrimSpace(revision), WorkingTree: hex.EncodeToString(workingHash),
		Toolchain: hex.EncodeToString(toolHash[:]), Manifest: manifestDigest,
		Environment: hex.EncodeToString(envHash[:]), ChangedFiles: changed,
	}, nil
}

func outputOf(name string, args ...string) (string, error) {
	data, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(data)))
	}
	return string(data), nil
}

func changedFiles(status string) []string {
	var files []string
	for _, line := range strings.Split(status, "\n") {
		if len(line) < 4 {
			continue
		}
		path := strings.TrimSpace(line[3:])
		if arrow := strings.LastIndex(path, " -> "); arrow >= 0 {
			path = path[arrow+4:]
		}
		if strings.HasPrefix(path, ".test-artifacts/") || strings.HasPrefix(path, "dashboard/app/.next/") {
			continue
		}
		files = append(files, path)
	}
	sort.Strings(files)
	return files
}

func CompatibleForReplay(old, current Fingerprint) (string, bool) {
	if old.SourceRevision != current.SourceRevision || old.Toolchain != current.Toolchain || old.Manifest != current.Manifest || old.Environment != current.Environment {
		return "incompatible revision, toolchain, manifest, or environment; run make check-fast or make check-merge-local", false
	}
	if old.WorkingTree != current.WorkingTree {
		return "working tree changed; replay expanded with conservatively affected checks", true
	}
	return "exact fingerprint match", true
}
