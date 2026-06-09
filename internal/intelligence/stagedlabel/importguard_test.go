package stagedlabel_test

import (
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/engine/calibration"
	"github.com/canarysting/canarysting/internal/engine/feedback"
	"github.com/canarysting/canarysting/internal/intelligence/stagedlabel"
)

const stagedlabelPkg = "github.com/canarysting/canarysting/internal/intelligence/stagedlabel"

// PRODUCTION SAFETY (gate 3): the production engine binary's transitive
// dependency closure must NOT reach the staged labeler, so a production build
// cannot construct one. The staging binary, by contrast, must reach it.
func TestProductionEngineCannotImportLabeler(t *testing.T) {
	deps := goListDeps(t, "github.com/canarysting/canarysting/cmd/engine")
	if deps[stagedlabelPkg] {
		t.Fatalf("cmd/engine transitively imports %s — a production build must not be able to construct the staged labeler", stagedlabelPkg)
	}

	// Sanity: the staging binary DOES reach it (otherwise the guard is vacuous).
	stagedDeps := goListDeps(t, "github.com/canarysting/canarysting/cmd/staged-range")
	if !stagedDeps[stagedlabelPkg] {
		t.Fatalf("cmd/staged-range does not import %s — the staged labeler is unreachable", stagedlabelPkg)
	}
}

func goListDeps(t *testing.T, pkg string) map[string]bool {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	set := map[string]bool{}
	for _, p := range strings.Fields(string(out)) {
		set[p] = true
	}
	return set
}

// D4 end-to-end: a stream of REAL canary-touch verdicts from the declared
// attacker, labeled by ground truth, drives the scope across the calibration
// evidence floor through the SAME feedback seam an analyst uses — so the M7
// window legitimately reaches calibrated mode with no human and no fabrication.
func TestLabelerReachesCalibrated(t *testing.T) {
	const scope = contract.ScopeKey("scopeA")
	calib := calibration.New(calibration.Config{})
	intake := feedback.NewIntake(calib)

	reg := stagedlabel.NewRegistry()
	reg.Declare(scope, netip.MustParseAddr("10.0.1.99"), stagedlabel.DispAttacker)
	l := stagedlabel.NewLabeler(reg, intake, true)

	if calib.State(scope).Calibrated {
		t.Fatal("precondition: scope should start uncalibrated")
	}
	for i := 0; i < calibration.DefaultEvidenceFloor; i++ {
		ev := contract.SignalEvent{
			Flow:  contract.FlowIdentity{SocketCookie: uint64(i + 1), L7Attributes: map[string]string{contract.AttrSourceAddress: "10.0.1.99"}},
			Scope: scope, Canary: "aws.key",
		}
		l.OnVerdict(ev, contract.Verdict{Scope: scope, Tier: contract.TierContain})
	}
	if !calib.State(scope).Calibrated {
		t.Fatalf("scope not calibrated after %d real ground-truth labels", calibration.DefaultEvidenceFloor)
	}
}
