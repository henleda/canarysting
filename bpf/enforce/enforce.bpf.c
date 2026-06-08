//go:build ignore

// enforce.bpf.c — kernel containment (M5, docs/STING.md, docs/IDENTITY.md).
//
// Two programs sharing ONE map keyed by the socket cookie — the SAME cookie the
// M4 sockops bridge resolves and that rides contract.Verdict.Flow.SocketCookie.
// The userspace loader programs a verdict for an attributed flow; the kernel
// enforces it on that flow's egress and cleans up when the socket closes.
//
//   enforce_egress (cgroup_skb/egress): per-packet, look up the socket cookie;
//     hard-deny/jail -> DROP; rate-limit -> token-bucket throttle; otherwise PASS.
//     FAIL-OPEN by construction: cookie 0 -> PASS, map-miss -> PASS. Only an
//     explicitly-programmed cookie is ever affected — a bystander is never touched.
//   enforce_release (cgroup/sock_release): delete the cookie's entry on socket
//     close, so a stale jail can never outlive its socket (strict, map-owned-here
//     lifecycle; no reliance on cookie-reuse semantics).
//
// This map/program pair is DISTINCT from the M4 sockops observation path (separate
// object, map, loader, link) — docs keep observation and enforcement separate.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual BSD/GPL"; // bpf_get_socket_cookie is GPL-only

// Action codes — match internal/sting/containment.Action and the loader.
#define ACTION_RATE_LIMIT 0
#define ACTION_HARD_DENY  1
#define ACTION_JAIL       2

// verdict_val mirrors the bpf2go-generated Go struct (a layout test pins it). The
// loader writes {action, rate, burst}; the kernel writes the counters and the
// token-bucket state (tokens, last_ns).
struct verdict_val {
	__u32 action;
	__u32 _pad;
	__u64 dropped_pkts;
	__u64 dropped_bytes;
	__u64 tokens;  // rate-limit: available tokens (bytes)
	__u64 last_ns; // rate-limit: last refill time
	__u64 rate;    // rate-limit: refill rate (bytes/sec); 0 disables (PASS)
	__u64 burst;   // rate-limit: bucket size (max tokens, bytes)
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64); // socket cookie — THE join key
	__type(value, struct verdict_val);
} verdict_map SEC(".maps");

SEC("cgroup_skb/egress")
int enforce_egress(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	if (cookie == 0)
		return 1; // unattributable -> NEVER drop (fail-open per-packet)
	struct verdict_val *v = bpf_map_lookup_elem(&verdict_map, &cookie);
	if (!v)
		return 1; // no programmed verdict -> PASS (mandated per-packet fail-open)

	if (v->action == ACTION_HARD_DENY || v->action == ACTION_JAIL) {
		__sync_fetch_and_add(&v->dropped_pkts, 1);
		__sync_fetch_and_add(&v->dropped_bytes, skb->len);
		return 0; // DROP — the jail
	}

	if (v->action == ACTION_RATE_LIMIT && v->rate > 0) {
		__u64 now = bpf_ktime_get_ns();
		if (v->last_ns == 0) {
			v->tokens = v->burst; // first packet: full bucket
		} else if (now > v->last_ns) {
			// refill = elapsed_ms * rate / 1000 (bytes). ms-scaling avoids u64
			// overflow on long idle gaps; tokens are capped at burst.
			__u64 refill = ((now - v->last_ns) / 1000000ULL) * v->rate / 1000ULL;
			__u64 t = v->tokens + refill;
			v->tokens = t > v->burst ? v->burst : t;
		}
		v->last_ns = now;
		__u64 cost = skb->len;
		if (v->tokens >= cost) {
			v->tokens -= cost;
			return 1; // within rate -> PASS
		}
		__sync_fetch_and_add(&v->dropped_pkts, 1);
		__sync_fetch_and_add(&v->dropped_bytes, skb->len);
		return 0; // over rate -> DROP (throttle; TCP backs off)
	}

	return 1; // rate-limit disabled / unknown action -> PASS
}

SEC("cgroup/sock_release")
int enforce_release(struct bpf_sock *sk)
{
	__u64 cookie = bpf_get_socket_cookie(sk);
	if (cookie != 0)
		bpf_map_delete_elem(&verdict_map, &cookie); // delete-on-close (strict lifecycle)
	return 1;
}
