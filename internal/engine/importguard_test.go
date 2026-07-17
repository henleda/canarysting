package engine_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestEngineIsProxyAgnostic is the executable form of CLAUDE.md rules 1 & 2: the
// engine is proxy-agnostic. Its TRANSITIVE dependency closure (engine + every
// subpackage) must never reach a proxy adapter (adapters/*) or a proxy SDK
// (envoyproxy/go-control-plane). The engine talks only to internal/contract; adding
// a proxy must mean writing one adapter, with zero engine changes.
//
// This is the symmetric twin of adapters/envoy/guard_test.go's
// TestAdapterImportsAreThin — that one fences the adapter from the engine; this one
// fences the engine from any adapter/proxy SDK, so the seam is guarded from BOTH
// sides and a regression on either is caught.
//
// `go list -deps` returns the full transitive closure for the current platform, so a
// leak through ANY seam package is caught, not just a direct import (which a
// parser-only check would miss).
//
// NOTE: github.com/cilium/ebpf is deliberately NOT forbidden. The engine's own
// observe-only baseline (internal/engine/observebaseline -> bpf/observe) legitimately
// uses it; that is a kernel library, not a proxy SDK, and it carries no proxy
// coupling. The forbidden set is exactly "proxy adapters" and "proxy SDKs".
func TestEngineIsProxyAgnostic(t *testing.T) {
	forbidden := []string{
		"github.com/canarysting/canarysting/adapters", // no proxy adapter, ever
		"github.com/envoyproxy/go-control-plane",      // no Envoy proxy SDK
	}
	out, err := exec.Command("go", "list", "-deps",
		"github.com/canarysting/canarysting/internal/engine/...").Output()
	if err != nil {
		t.Fatalf("go list -deps failed: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, f := range forbidden {
			if strings.Contains(dep, f) {
				t.Errorf("engine transitively imports forbidden proxy package %q (rules 1 & 2: the engine is proxy-agnostic)", dep)
			}
		}
	}
}
