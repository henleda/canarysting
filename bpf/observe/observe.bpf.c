//go:build ignore

// observe.bpf.c — the OBSERVE-ONLY baseline path (M7, docs/BASELINE_MULTIPLIER.md).
//
// It accrues per-flow byte/packet/timing statistics for the M7 learning window,
// keyed by the SAME socket cookie the M4 sockops bridge and the M5 enforce map
// use (rule 4 — one cookie, no second join). It is STRUCTURALLY incapable of
// enforcing:
//   - every program returns 1 (PASS) on every path; there is no `return 0`.
//   - userspace has no write path to this map (the Observer interface exposes no
//     Update/Delete/Program), so the baseline is observation, and observation
//     cannot act.
// It is a SEPARATE object/map/loader/cgroup-link from bpf/enforce — observation
// and enforcement never share state (CLAUDE.md rule 4, docs/BASELINE_MULTIPLIER §10).
//
// Three programs share ONE map:
//   observe_ingress (cgroup_skb/ingress): per-packet, account toward the workload.
//   observe_egress  (cgroup_skb/egress):  per-packet, account from the workload.
//   observe_release (cgroup/sock_release): MARK the cookie's entry closed on
//     close (not delete), so a flow that opens and closes between two userspace
//     poll ticks is still present (closed) for the aggregator to fold exactly
//     once; the LRU evicts it afterward.
//
// flow_stats is mirrored field-for-field by the bpf2go-generated observeCsFlowStats
// (layout_test pins it) and converted to bpf/observe.FlowStats by the loader.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual BSD/GPL"; // bpf_get_socket_cookie is GPL-only

#define AF_INET  2
#define AF_INET6 10

// flow_stats: cumulative per-cookie statistics. Counters first (so the kernel's
// __sync_fetch_and_add lands at a stable offset), then the timestamps, then the
// captured 4-tuple. Total 88 bytes. SrcIP/SrcPort = the REMOTE peer (the caller /
// initiator); DstIP/DstPort = the LOCAL end (the reached workload). The exact
// src-vs-dst orientation on an accepted server socket is kernel-dependent and is
// VERIFIED by the loader_linux_test oracle (tuple == getpeername/getsockname).
struct cs_flow_stats {
	__u64 ingress_packets;
	__u64 ingress_bytes;
	__u64 egress_packets;
	__u64 egress_bytes;
	__u64 first_seen_ns;
	__u64 last_seen_ns;
	__u16 family;
	__u16 src_port; // remote/initiator port (host order)
	__u16 dst_port; // local/service port (host order)
	__u16 closed;   // 0 = open; 1 = flow ended (set by sock_release) — the fold-once signal
	__u8  src_ip[16]; // remote/initiator address (the caller's identity)
	__u8  dst_ip[16]; // local/service address (the reached workload)
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64); // socket cookie — THE join key
	__type(value, struct cs_flow_stats);
} observe_stats SEC(".maps");

// capture_tuple fills st's 4-tuple from the packet's socket. Read sk fields by
// value (sk is skb->sk, a bpf_sock, not the ctx, so this is allowed). The address
// __u32 octets are network byte order; copied into the byte array they land in IP
// order, matching Go's netip.As4()/As16(). dst_port is __be16 (network order) ->
// bpf_ntohs; src_port is already host order.
static __always_inline void capture_tuple(struct bpf_sock *sk, struct cs_flow_stats *st)
{
	st->family   = sk->family;
	st->src_port = bpf_ntohs(sk->dst_port);  // REMOTE peer port
	st->dst_port = (__u16)sk->src_port;       // LOCAL (workload) port
	__u32 *sip = (__u32 *)st->src_ip;         // REMOTE peer address
	__u32 *dip = (__u32 *)st->dst_ip;         // LOCAL address
	if (sk->family == AF_INET) {
		sip[0] = sk->dst_ip4;
		dip[0] = sk->src_ip4;
	} else {
		sip[0] = sk->dst_ip6[0];
		sip[1] = sk->dst_ip6[1];
		sip[2] = sk->dst_ip6[2];
		sip[3] = sk->dst_ip6[3];
		dip[0] = sk->src_ip6[0];
		dip[1] = sk->src_ip6[1];
		dip[2] = sk->src_ip6[2];
		dip[3] = sk->src_ip6[3];
	}
}

// account folds one packet into the per-cookie stats. ALWAYS returns 1 (PASS):
// observation never drops.
static __always_inline int account(struct __sk_buff *skb, int ingress)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	if (cookie == 0)
		return 1; // unattributable -> count nothing, but always PASS

	__u64 len = skb->len;
	__u64 now = bpf_ktime_get_ns();

	struct cs_flow_stats *st = bpf_map_lookup_elem(&observe_stats, &cookie);
	if (st) {
		if (ingress) {
			__sync_fetch_and_add(&st->ingress_packets, 1);
			__sync_fetch_and_add(&st->ingress_bytes, len);
		} else {
			__sync_fetch_and_add(&st->egress_packets, 1);
			__sync_fetch_and_add(&st->egress_bytes, len);
		}
		st->last_seen_ns = now;
		return 1;
	}

	// First packet for this cookie: capture the 4-tuple and seed the counters.
	struct bpf_sock *sk = skb->sk;
	if (!sk)
		return 1; // no socket context yet (early/non-socket packet) -> PASS, capture later

	// Only SEED a new entry for an ESTABLISHED flow. This is the fold-on-completion
	// contract's other half: once sock_release deletes a closed flow's entry, the
	// late FIN/ACK/RST packets of the teardown (state != ESTABLISHED) must NOT
	// re-create it, or the cookie would never disappear from the map and the
	// aggregator would never fold the flow. Existing entries are still updated
	// above regardless of state (the if(st) branch); this gate only governs
	// CREATION.
	if (sk->state != BPF_TCP_ESTABLISHED)
		return 1;

	struct cs_flow_stats init = {};
	init.first_seen_ns = now;
	init.last_seen_ns  = now;
	if (ingress) {
		init.ingress_packets = 1;
		init.ingress_bytes   = len;
	} else {
		init.egress_packets = 1;
		init.egress_bytes   = len;
	}
	capture_tuple(sk, &init);
	bpf_map_update_elem(&observe_stats, &cookie, &init, BPF_ANY);
	return 1;
}

SEC("cgroup_skb/ingress")
int observe_ingress(struct __sk_buff *skb)
{
	return account(skb, 1);
}

SEC("cgroup_skb/egress")
int observe_egress(struct __sk_buff *skb)
{
	return account(skb, 0);
}

SEC("cgroup/sock_release")
int observe_release(struct bpf_sock *sk)
{
	// MARK the flow closed instead of deleting it. The entry persists (the LRU
	// evicts it once the userspace aggregator has folded it), so a flow that opens
	// and closes BETWEEN two userspace poll ticks is still present (closed) on the
	// next tick and gets folded exactly once — fold-on-completion no longer misses
	// short flows. (Deleting on close, as the enforce path does, would make a
	// sub-tick flow vanish before the poller ever saw it.)
	__u64 cookie = bpf_get_socket_cookie(sk);
	if (cookie == 0)
		return 1;
	struct cs_flow_stats *st = bpf_map_lookup_elem(&observe_stats, &cookie);
	if (st) {
		st->closed = 1;
		st->last_seen_ns = bpf_ktime_get_ns();
	}
	return 1;
}
