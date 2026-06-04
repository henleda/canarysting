// enforce.bpf.c — minimal eBPF enforcement (TC/cgroup hooks).
//
// This is the ONLY C in the codebase. Keep it minimal: only what must run in
// kernel. Userspace logic lives in Go (bpf/loader, internal/sting). The map is
// keyed by socket cookie — the L7<->kernel join key. See docs/IDENTITY.md.
//
// Actions (must match internal/sting/containment.Action and loader):
//   0 = rate-limit, 1 = hard-deny, 2 = jail
//
// TODO: implement the cgroup/TC hook that looks up the socket cookie in the
// verdict map and applies the programmed action. Bound everything; never block
// a flow with no entry.

// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
//
// struct { ... } verdict_map SEC(".maps"); // key: __u64 socket_cookie -> __u32 action
//
// SEC("cgroup/skb") int enforce_egress(struct __sk_buff *skb) { /* TODO */ return 1; }
//
// char _license[] SEC("license") = "GPL";
