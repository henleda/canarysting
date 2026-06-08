//go:build !linux

package loader

import "errors"

// errNotLinux reports that kernel enforcement is unavailable off Linux. It fails
// LOUD (never a silent no-op enforce) so a misconfigured deployment is obvious.
var errNotLinux = errors.New("loader: kernel enforcement requires Linux; run on the box")

// NoopLoader satisfies Loader on non-Linux hosts so the tree builds on macOS. Every
// method errors rather than pretending to enforce.
type NoopLoader struct{}

var _ Loader = (*NoopLoader)(nil)

func (NoopLoader) Load() error                                  { return errNotLinux }
func (NoopLoader) Program(uint64, uint32, uint64, uint64) error { return errNotLinux }
func (NoopLoader) Release(uint64) error                         { return errNotLinux }
func (NoopLoader) Counters(uint64) (Counters, bool)             { return Counters{}, false }
func (NoopLoader) Close() error                                 { return nil }
