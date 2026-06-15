package identity

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

// Config is the OPERATOR-DECLARED node-identity map — a first-class config
// (founder decision), the production source of node names and what the demo
// populates. It is loaded from JSON (stdlib only — no YAML dependency, mirroring
// internal/intelligence/stagedlabel's LoadRegistryFile pattern).
//
// Each Entry names a node by an address selector — an exact ip, a CIDR, and/or a
// port — and declares its kind. The selectors compose into the resolver's
// precedence (exact (ip,port) > exact ip > CIDR > port-only); see Resolver.Resolve.
type Config struct {
	Entries []Entry `json:"entries"`
}

// Entry is one operator-declared identity. At least one selector (CIDR, IP, or
// Port) must be present, and Name and Kind are required. The selector combinations
// the resolver honors:
//
//   - ip + port  -> exact (ip,port) endpoint (highest precedence)
//   - ip         -> exact host (any port)
//   - cidr       -> a named range
//   - port       -> a named service by listen/destination port (the all-loopback
//     demo mesh, where the PORT — not the IP — is the discriminator)
//
// ip and cidr are mutually exclusive on one entry. Kind is "service", "caller", or
// "external" (the operator-declarable kinds — "external" names a declared off-mesh
// entry point such as the ingress gateway); "decoy"/"unknown" are resolver-derived
// classes, not operator inputs.
type Entry struct {
	CIDR string `json:"cidr,omitempty"`
	IP   string `json:"ip,omitempty"`
	Port uint16 `json:"port,omitempty"`
	Name string `json:"name"`
	Kind string `json:"kind"`

	// parsed/derived at load time (unexported; never serialized).
	addr    netip.Addr
	prefix  netip.Prefix
	hasPort bool
	kind    NodeKind
}

// LoadConfig parses a JSON operator-identity map. Every selector must parse and
// every entry must be well-formed, or it errors loudly — an operator map with a
// typo'd CIDR/IP must not silently mis-name (or worse, silently drop) a node.
func LoadConfig(r io.Reader) (*Config, error) {
	var cfg Config
	if err := json.NewDecoder(r).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("identity: parse config: %w", err)
	}
	for i := range cfg.Entries {
		if err := cfg.Entries[i].normalize(i); err != nil {
			return nil, err
		}
	}
	return &cfg, nil
}

// LoadConfigFile loads an operator-identity map from a JSON file path.
func LoadConfigFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("identity: open config %q: %w", path, err)
	}
	defer f.Close()
	return LoadConfig(f)
}

// normalize validates one entry and fills its parsed/derived fields. idx is the
// entry's position, for legible error messages.
func (e *Entry) normalize(idx int) error {
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("identity: entry %d: empty name", idx)
	}

	switch e.Kind {
	case "service":
		e.kind = KindService
	case "caller":
		e.kind = KindCaller
	case "external":
		// "external" names a declared off-mesh entry point — e.g. the ingress
		// gateway (Envoy), which originates traffic into the mesh from its own
		// loopback identity. It is operator-declarable (unlike "decoy"/"unknown",
		// which are resolver-derived classes) so the ingress hop can be NAMED and
		// placed as an entry point in the topology view instead of degrading to an
		// anonymous IP node.
		e.kind = KindExternal
	case "":
		return fmt.Errorf("identity: entry %d (%q): missing kind (want \"service\", \"caller\", or \"external\")", idx, e.Name)
	default:
		return fmt.Errorf("identity: entry %d (%q): unknown kind %q (want \"service\", \"caller\", or \"external\")", idx, e.Name, e.Kind)
	}

	if e.IP != "" && e.CIDR != "" {
		return fmt.Errorf("identity: entry %d (%q): ip and cidr are mutually exclusive", idx, e.Name)
	}

	if e.IP != "" {
		addr, err := netip.ParseAddr(e.IP)
		if err != nil {
			return fmt.Errorf("identity: entry %d (%q): bad ip %q: %w", idx, e.Name, e.IP, err)
		}
		e.addr = addr.Unmap()
	}
	if e.CIDR != "" {
		pfx, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			return fmt.Errorf("identity: entry %d (%q): bad cidr %q: %w", idx, e.Name, e.CIDR, err)
		}
		e.prefix = pfx.Masked()
	}
	e.hasPort = e.Port != 0

	if !e.addr.IsValid() && !e.prefix.IsValid() && !e.hasPort {
		return fmt.Errorf("identity: entry %d (%q): no selector — need at least one of ip, cidr, or port", idx, e.Name)
	}
	return nil
}
