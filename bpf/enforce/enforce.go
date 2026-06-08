// Package enforce loads the kernel containment programs (enforce.bpf.c) and holds
// the verdict map keyed by socket cookie. The KernelLoader (resolver_linux.go,
// build-tag linux) implements bpf/loader.Loader by loading + attaching the
// cgroup_skb/egress and cgroup/sock_release programs and programming per-cookie
// verdicts. The bpf2go-generated bindings below build on any little-endian host so
// the rest of the tree compiles on macOS.
//
// Regenerate (requires clang + a generated vmlinux.h in this dir):
//
//	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/enforce/vmlinux.h
//	go generate ./bpf/enforce/
//
// vmlinux.h is gitignored; the generated *_bpfel.go and .o are committed so
// `go build` needs no clang.
package enforce

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type verdict_val -cflags "-O2 -g -Wall -Wno-unused-function" enforce enforce.bpf.c
