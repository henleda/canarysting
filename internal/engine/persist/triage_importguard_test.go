package persist_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// RULE 8 / DISPLAY-ONLY FENCE (load-bearing): the deviant ACK/SUPPRESS triage
// overlay (persist.PutDeviantTriage / DeleteDeviantTriage / RangeDeviantTriage /
// GetDeviantTriage / DeviantTriageRecord, bucket "deviant_triage") is read/written
// ONLY on the DISPLAY/control side (the dashboard tap + backend view, and the
// token-gated admin endpoint). It must NEVER be in the dependency closure of the
// VERDICT path. The danger is concrete: the overlay keys on the SAME identity-shape
// as scoring.BenignExcluder and observebaseline.MaliciousSet — if it were ever wired
// as a BenignExcluder, a suppressed attacker would score 0 and a canary touch would
// not arm; if merged into MaliciousSet it would poison the baseline. So the four
// arming-path packages must not so much as NAME the overlay accessor.
//
// Because the overlay accessor METHODS live on persist.Store (which the verdict path
// legitimately imports for the baseline/event stores), a package-import graph cannot
// distinguish them. This guard is therefore a SOURCE fence: the non-test .go source
// of the verdict-path packages must not reference any overlay symbol. A behavioral
// companion (boot.TestSuppressedDeviantStillArms) proves the runtime invariant; this
// guard catches a regression at the SOURCE before it can compile.
func TestVerdictPathDoesNotReferenceTriageOverlay(t *testing.T) {
	root := repoRoot(t)
	// The verdict/scoring/baseline/exclusion closure (CLAUDE.md rule 8): engine,
	// scoring, baseline, observebaseline. None may name the overlay accessor.
	verdictPkgs := []string{
		filepath.Join(root, "internal", "engine"),
		filepath.Join(root, "internal", "engine", "scoring"),
		filepath.Join(root, "internal", "engine", "baseline"),
		filepath.Join(root, "internal", "engine", "observebaseline"),
	}
	// The overlay accessor symbols (the only handles to read/write the overlay).
	forbidden := []string{
		"PutDeviantTriage",
		"DeleteDeviantTriage",
		"RangeDeviantTriage",
		"GetDeviantTriage",
		"DeviantTriageRecord",
		"DecodeDeviantTriage",
		"deviant_triage",
		"bktDeviantTriage",
	}
	for _, dir := range verdictPkgs {
		for _, src := range goSources(t, dir, false /* exclude _test.go */) {
			data, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read %s: %v", src, err)
			}
			body := string(data)
			for _, sym := range forbidden {
				if strings.Contains(body, sym) {
					t.Fatalf("verdict-path source %s references overlay symbol %q — the deviant triage overlay must stay DISPLAY-ONLY (Rule 8). A suppressed mover that touches a canary must STILL arm; the overlay must never be reachable from scoring/baseline/the benign-exclusion set/the engine Submit path.", src, sym)
				}
			}
		}
	}

	// Sanity (non-vacuous): the DISPLAY side (the tap) legitimately DOES reference the
	// overlay accessor, so the symbol names above are real and this guard is meaningful.
	tapDir := filepath.Join(root, "internal", "dashboard", "tap")
	sawOnDisplaySide := false
	for _, src := range goSources(t, tapDir, false) {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		if strings.Contains(string(data), "RangeDeviantTriage") {
			sawOnDisplaySide = true
			break
		}
	}
	if !sawOnDisplaySide {
		t.Fatal("sanity: the dashboard tap does not reference RangeDeviantTriage — the overlay symbol names may be wrong, making this guard vacuous")
	}
}

// repoRoot returns the module root (where go.mod lives) via `go env GOMOD`'s dir.
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		t.Fatal("no go.mod found (not in a module)")
	}
	return filepath.Dir(gomod)
}

// goSources lists the .go files directly in dir. When includeTests is false, _test.go
// files are excluded (we fence the SHIPPING source, not test fixtures).
func goSources(t *testing.T, dir string, includeTests bool) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if !includeTests && strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}
