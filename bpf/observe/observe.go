package observe

// bpf2go generation for the OBSERVE-ONLY baseline programs. The generated
// observe_bpfel.go (observeObjects/Programs/Maps + the observeCsFlowStats struct)
// and observe_bpfel.o build on any little-endian host, so the rest of the tree
// compiles on macOS with no clang; the kernel-backed KernelObserver in
// loader_linux.go uses them.
//
// Regenerate (requires clang + a generated vmlinux.h in this dir, Linux only):
//
//	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/observe/vmlinux.h
//	go generate ./bpf/observe/
//
// vmlinux.h is gitignored; the generated *_bpfel.go and .o are committed.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type cs_flow_stats -cflags "-O2 -g -Wall -Wno-unused-function" observe observe.bpf.c
