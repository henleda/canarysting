//go:build ignore

// sockops.bpf.c — the socket-cookie bridge (M4, docs/IDENTITY.md, ROADMAP §7).
//
// Envoy never surfaces SO_COOKIE to an ext_proc filter, so this sockops program
// captures the kernel socket cookie for each ACCEPTED downstream connection and
// stores it in a map keyed by the connection 4-tuple. The userspace adapter
// rebuilds the identical key from the ext_proc source/destination attributes and
// looks the cookie up (bpf/sockops resolver). A MISS => the flow is
// unattributable => the adapter never enforces. There is NO second join mechanism.
//
// We capture on PASSIVE_ESTABLISHED — the server-accept socket, the exact one M5
// will enforce against (NOT the active client side, which has a different cookie)
// — and DELETE on TCP_CLOSE, because a missed delete plus ephemeral-port reuse
// could resurrect a stale cookie and misattribute a verdict (the failure
// IDENTITY.md/CLAUDE.md forbid). The map is LRU_HASH (belt) on top of
// delete-on-close (suspenders).
//
// The flow_key / flow_val layouts are mirrored field-for-field by Go's
// identity.FourTuple / identity.Resolution; bpf2go emits the type-safe Go structs
// and a layout test asserts they match, so C and Go can never drift.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define AF_INET6 10

// flow_key mirrors identity.FourTuple. Src = the REMOTE end (the attacker;
// ext_proc source.*), Dst = the LOCAL end (Envoy; ext_proc destination.*). Ports
// are host byte order; IPv4 occupies the first 4 bytes of the 16-byte fields.
struct flow_key {
	__u16 family;
	__u16 src_port;
	__u16 dst_port;
	__u16 _pad;
	__u8  src_ip[16];
	__u8  dst_ip[16];
};

// flow_val mirrors identity.Resolution.
struct flow_val {
	__u64 cookie;
	__u64 cgroup_id;
	__u32 pid;
	__u32 generation;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} flow_cookies SEC(".maps");

// gen_seq is the monotonic generation source: a single-entry array map holding a
// host-global counter bumped on every PASSIVE_ESTABLISHED capture. It makes the
// flow_val.generation a REAL staleness ordinal (was a hardcoded 1) so userspace can
// detect that an entry it resolved was replaced by a newer connection on the SAME
// 4-tuple — the missed-TCP_CLOSE + reused-ephemeral-port case that would otherwise
// misattribute a verdict to a bystander (docs/IDENTITY.md, CLAUDE.md rule 4). A
// fresh capture always has a strictly higher generation than any stale entry, so a
// re-resolve that returns a higher generation than the one the caller is about to
// enforce on is proof the entry churned and the cookie may no longer be that flow's.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} gen_seq SEC(".maps");

// next_generation returns a strictly-increasing, host-global generation. The
// read-modify-write is not atomic across CPUs, so two concurrent accepts can
// briefly collide on a value; that only ever weakens the guard toward a MISS (a
// refuse-to-enforce), never toward jailing a bystander, so the cheap non-atomic
// path is acceptable here (a 0 is never returned — first capture is generation 1).
static __always_inline __u32 next_generation(void)
{
	__u32 zero = 0;
	__u64 *seq = bpf_map_lookup_elem(&gen_seq, &zero);
	if (!seq)
		return 1;
	__u64 g = *seq + 1;
	*seq = g;
	// Fold to 32 bits; generation is an ordinal, not an index. 0 means "unset",
	// so skip it on the (astronomically distant) wrap.
	__u32 g32 = (__u32)g;
	return g32 == 0 ? 1 : g32;
}

// build_key fills the host-canonical key from the sock_ops context.
// local_port is HOST byte order; remote_port is NETWORK byte order; the ip4/ip6
// fields are NETWORK byte order (their in-memory bytes are the address octets,
// which is exactly what Go's netip.As4()/As16() produce — so a raw copy matches).
static __always_inline void build_key(struct bpf_sock_ops *skops, struct flow_key *k)
{
	__builtin_memset(k, 0, sizeof(*k));
	k->family   = skops->family;
	// remote_port is a __u32 carrying the port in network byte order in the HIGH
	// 16 bits ((__u16)remote_port is 0), so a full-word bpf_ntohl yields the
	// host-order port in the low 16 bits. local_port is already host order.
	k->src_port = bpf_ntohl(skops->remote_port);
	k->dst_port = (__u16)skops->local_port;
	// Read the ctx ip fields by VALUE (taking &skops->field and dereferencing it
	// is a "modified ctx ptr" the verifier rejects). The __u32 values are network
	// byte order; written into the byte array their octets land in IP order, which
	// matches Go's netip.As4()/As16().
	__u32 *sip = (__u32 *)k->src_ip;
	__u32 *dip = (__u32 *)k->dst_ip;
	if (skops->family == AF_INET) {
		sip[0] = skops->remote_ip4;
		dip[0] = skops->local_ip4;
	} else {
		sip[0] = skops->remote_ip6[0];
		sip[1] = skops->remote_ip6[1];
		sip[2] = skops->remote_ip6[2];
		sip[3] = skops->remote_ip6[3];
		dip[0] = skops->local_ip6[0];
		dip[1] = skops->local_ip6[1];
		dip[2] = skops->local_ip6[2];
		dip[3] = skops->local_ip6[3];
	}
}

SEC("sockops")
int canary_sockops(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
		struct flow_key k;
		build_key(skops, &k);
		struct flow_val v = {};
		v.cookie     = bpf_get_socket_cookie(skops);
		v.generation = next_generation(); // real monotonic ordinal (was a stub 1)
		// cgroup_id / pid are informational (the cookie is the join key); they are
		// often not meaningful in the accept softirq context, so leave them 0.
		bpf_map_update_elem(&flow_cookies, &k, &v, BPF_ANY);
		// Subscribe to state-change callbacks so we can delete on close.
		bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
		break;
	}
	case BPF_SOCK_OPS_STATE_CB:
		// args[1] is the new TCP state. Delete on close so a reused ephemeral port
		// can never resurrect a stale cookie.
		if (skops->args[1] == BPF_TCP_CLOSE) {
			struct flow_key k;
			build_key(skops, &k);
			bpf_map_delete_elem(&flow_cookies, &k);
		}
		break;
	}
	return 1;
}
