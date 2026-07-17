//go:build linux

package kernel

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// AssertSocketCookie reads the running kernel version via uname(2) and returns an error
// if it is older than the pinned minimum that guarantees a system-global, never-reused
// socket cookie. Call it at datapath startup, BEFORE loading or attaching any eBPF
// program, so a too-old kernel fails LOUD instead of silently risking a misattributed
// jail (CLAUDE.md rule 4; docs/IDENTITY.md).
func AssertSocketCookie() error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return fmt.Errorf("kernel: uname: %w", err)
	}
	return checkRelease(unix.ByteSliceToString(uts.Release[:]))
}
