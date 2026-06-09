//go:build !linux

package observe

// PlatformObserver returns the observer for this platform. Off Linux there is no
// kernel observation, so it is the NoopObserver (the engine runs touch-only).
func PlatformObserver() Observer { return NoopObserver{} }
