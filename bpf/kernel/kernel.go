// Package kernel asserts that the running Linux kernel provides the socket-cookie
// guarantees CanarySting's datapath depends on.
//
// The socket cookie (bpf_get_socket_cookie) is the SOLE join key between the L7 proxy
// verdict and in-kernel enforcement (CLAUDE.md rule 4), and containment precision —
// never jail a bystander, a critical failure — rests on that cookie being system-global
// and NEVER reused for the life of the host (docs/IDENTITY.md). That guarantee holds
// only on a recent-enough kernel, so we PIN a minimum and ASSERT it at datapath startup
// rather than assuming it. The floor matches the one already named in
// docs/TECHNICAL_ARCHITECTURE.md §12.4.
//
// The version policy here is pure and unit-tested on every platform (checkRelease); the
// Linux-only uname read that feeds it lives in AssertSocketCookie (kernel_linux.go).
package kernel

import (
	"fmt"
	"strconv"
	"strings"
)

// MinMajor and MinMinor are the minimum kernel version (major.minor) that provides a
// system-global, never-reused socket cookie. See docs/TECHNICAL_ARCHITECTURE.md §12.4
// (the pinned floor) and docs/IDENTITY.md (why never-reuse is load-bearing). Bump only
// deliberately, alongside the doc.
const (
	MinMajor = 5
	MinMinor = 10
)

// parseVersion extracts the leading major.minor from a `uname -r` release string such
// as "6.8.0-45-generic", "5.15.0-1051-aws", or a bare "5.10". The distro suffix after
// the first '-' and any patch/extra components are ignored. It errors if it cannot read
// an integer major (and, when a minor component is present, an integer minor).
func parseVersion(release string) (major, minor int, err error) {
	core := strings.TrimSpace(release)
	if core == "" {
		return 0, 0, fmt.Errorf("kernel: empty release string")
	}
	if i := strings.IndexByte(core, '-'); i >= 0 {
		core = core[:i] // drop the distro suffix ("-45-generic", "-1051-aws", ...)
	}
	parts := strings.Split(core, ".")
	if major, err = strconv.Atoi(parts[0]); err != nil {
		return 0, 0, fmt.Errorf("kernel: cannot parse major version from %q: %w", release, err)
	}
	if len(parts) > 1 {
		if minor, err = strconv.Atoi(parts[1]); err != nil {
			return 0, 0, fmt.Errorf("kernel: cannot parse minor version from %q: %w", release, err)
		}
	}
	return major, minor, nil
}

// atLeastMinimum reports whether major.minor >= MinMajor.MinMinor.
func atLeastMinimum(major, minor int) bool {
	if major != MinMajor {
		return major > MinMajor
	}
	return minor >= MinMinor
}

// checkRelease parses a `uname -r` release string and returns a descriptive error if
// the kernel is older than the pinned minimum. It is pure (no OS calls) so the policy
// is unit-tested on every platform; the actual uname read is the caller's job
// (AssertSocketCookie, Linux-only).
func checkRelease(release string) error {
	major, minor, err := parseVersion(release)
	if err != nil {
		return err
	}
	if !atLeastMinimum(major, minor) {
		return fmt.Errorf("kernel: running %d.%d is below the minimum %d.%d required for a system-global, "+
			"never-reused socket cookie (the L7<->kernel join key — CLAUDE.md rule 4, docs/IDENTITY.md); "+
			"refusing to start the datapath to avoid misattributed enforcement", major, minor, MinMajor, MinMinor)
	}
	return nil
}
