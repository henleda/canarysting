// Command cnp-actuate is a LIVE-VERIFY harness for the CiliumNetworkPolicy
// containment actuator. It constructs a real contract.Verdict and the REAL
// cilium.Enforcer over a REAL client-go dynamic client, then calls Apply or
// Release — so running it exercises the actual actuator code path against a live
// cluster (the same path the adapter's OnVerdict->enforcer seam drives).
//
// It is a NORMAL main (no build tags): client-go's dynamic client and kubeconfig
// loader are pure Go, so this cross-compiles to the DGX (linux/arm64).
//
// Example (reproduce the proven drop of cli(10.0.0.235) -> srv(app=srv) in default):
//
//	cnp-actuate -kubeconfig /etc/rancher/k3s/k3s.yaml \
//	  -source-cidr 10.0.0.235 -target-ns default -target-labels app=srv \
//	  -scope m7-window -action apply
//
// then release it:
//
//	cnp-actuate -kubeconfig /etc/rancher/k3s/k3s.yaml \
//	  -source-cidr 10.0.0.235 -target-ns default -target-labels app=srv \
//	  -scope m7-window -action release
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/k8s/cnp"
	"github.com/canarysting/canarysting/internal/sting/containment"
	cilium "github.com/canarysting/canarysting/internal/sting/containment/cilium"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("cnp-actuate: %v", err)
	}
}

func run() error {
	var (
		kubeconfig   = flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "path to kubeconfig (default $KUBECONFIG)")
		sourceCIDR   = flag.String("source-cidr", "", "attributed source IP (e.g. 10.0.0.235; an optional /mask is stripped)")
		targetNS     = flag.String("target-ns", "", "namespace of the decoy (target) workload")
		targetLabels = flag.String("target-labels", "", "target endpointSelector labels as k=v,k=v (e.g. app=srv)")
		scope        = flag.String("scope", "", "CanarySting scope key stamped on the CNP")
		action       = flag.String("action", "apply", "apply | release")
	)
	flag.Parse()

	if *kubeconfig == "" {
		return fmt.Errorf("-kubeconfig is required (or set $KUBECONFIG)")
	}
	if *sourceCIDR == "" {
		return fmt.Errorf("-source-cidr is required")
	}
	if *targetNS == "" {
		return fmt.Errorf("-target-ns is required")
	}
	tl, err := parseLabels(*targetLabels)
	if err != nil {
		return err
	}
	if len(tl) == 0 {
		return fmt.Errorf("-target-labels must set at least one k=v (a CNP must not select every pod)")
	}
	ip, err := hostIP(*sourceCIDR)
	if err != nil {
		return err
	}

	// Build the REAL dynamic client from the kubeconfig.
	restCfg, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		return fmt.Errorf("load kubeconfig %q: %w", *kubeconfig, err)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("build dynamic client: %w", err)
	}

	// Construct the REAL enforcer over the REAL writer.
	enf, err := cilium.New(cilium.Config{
		Writer:          cnp.NewDynamicWriter(dyn),
		Scope:           contract.ScopeKey(*scope),
		TargetNamespace: *targetNS,
		TargetLabels:    tl,
	})
	if err != nil {
		return fmt.Errorf("build enforcer: %w", err)
	}

	// A real attributed verdict: async, Tier 3 (jail), with the source IP stamped on
	// the flow the way an adapter stamps it (AttrSourceAddress) and a non-zero socket
	// cookie (the attribution key — a synthetic deterministic value here, since there
	// is no kernel in the loop for this harness).
	v := contract.Verdict{
		Flow: contract.FlowIdentity{
			SocketCookie: syntheticCookie(ip),
			L7Attributes: map[string]string{contract.AttrSourceAddress: ip},
		},
		Scope: contract.ScopeKey(*scope),
		Tier:  contract.TierJail,
		Mode:  contract.ModeAsync,
	}

	// The deterministic name the enforcer will address (for the human summary).
	params := cnp.Params{
		Scope:           *scope,
		SourceIP:        ip,
		TargetNamespace: *targetNS,
		TargetLabels:    tl,
	}
	name := cnp.Name(params)

	switch *action {
	case "apply":
		// Show the exact object the enforcer renders (same params, same code path).
		obj, rerr := cnp.Render(cnp.Params{
			Scope: *scope, SourceIP: ip, TargetNamespace: *targetNS, TargetLabels: tl,
			SocketCookie: v.Flow.SocketCookie, Tier: fmt.Sprintf("%d", int(v.Tier)),
			Confidence: "source-ip", Reason: containment.Jail.String(),
		})
		if rerr != nil {
			return fmt.Errorf("render for display: %w", rerr)
		}
		fmt.Printf("APPLY: enforcer.Apply writing CiliumNetworkPolicy %s/%s (source %s/32 -> target %s)\n",
			*targetNS, name, ip, labelString(tl))
		printJSON(obj)
		if err := enf.Apply(v, containment.Jail); err != nil {
			return err
		}
		fmt.Printf("OK: applied %s/%s at %s\n", *targetNS, name, time.Now().Format(time.RFC3339))
		fmt.Printf("verify: kubectl -n %s get ciliumnetworkpolicy %s -o yaml\n", *targetNS, name)
	case "release":
		fmt.Printf("RELEASE: enforcer.Release deleting CiliumNetworkPolicy %s/%s\n", *targetNS, name)
		if err := enf.Release(v); err != nil {
			return err
		}
		fmt.Printf("OK: released %s/%s at %s (NotFound is treated as success)\n", *targetNS, name, time.Now().Format(time.RFC3339))
	default:
		return fmt.Errorf("-action must be apply or release, got %q", *action)
	}
	return nil
}

// parseLabels parses "k=v,k=v" into a label map. An empty string yields an empty map.
func parseLabels(s string) (map[string]string, error) {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, val, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		val = strings.TrimSpace(val)
		if !ok || k == "" {
			return nil, fmt.Errorf("bad label %q: want k=v", pair)
		}
		out[k] = val
	}
	return out, nil
}

// hostIP extracts a bare IP from a value that may carry a /mask (e.g. 10.0.0.235/32).
func hostIP(s string) (string, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("source %q is not a valid IP", s)
	}
	return ip.String(), nil
}

// syntheticCookie derives a non-zero, deterministic socket cookie from the source IP
// so a harness apply/release pair stamp the same attribution value. Real deployments
// get the cookie from the kernel sockops join (rule 4); the harness has no kernel.
func syntheticCookie(ip string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(ip))
	c := h.Sum64()
	if c == 0 {
		c = 1
	}
	return c
}

func labelString(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func printJSON(obj interface{}) {
	b, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		fmt.Printf("(unprintable object: %v)\n", err)
		return
	}
	fmt.Println(string(b))
}
