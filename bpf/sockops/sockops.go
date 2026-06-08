// Package sockops loads the socket-cookie bridge (the sockops eBPF program in
// sockops.bpf.c) and resolves a connection 4-tuple to its kernel socket cookie —
// the L7<->kernel join the Envoy adapter needs but ext_proc cannot surface
// (docs/IDENTITY.md, ROADMAP §7). The kernel-touching MapResolver is in
// resolver_linux.go (build-tag linux); the bpf2go-generated bindings below build
// on any little-endian host so the rest of the tree compiles on macOS too.
//
// Regenerate the bindings (requires clang + a generated vmlinux.h in this dir):
//
//	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/sockops/vmlinux.h
//	go generate ./bpf/sockops/
//
// vmlinux.h is kernel-specific and gitignored; the generated *_bpfel.go and .o
// are committed so `go build` works without clang (and CI's Go gate stays green).
package sockops

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type flow_key -type flow_val -cflags "-O2 -g -Wall -Wno-unused-function" sockops sockops.bpf.c
