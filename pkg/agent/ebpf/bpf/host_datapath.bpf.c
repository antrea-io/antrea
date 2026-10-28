//go:build ignore

// Cross-Node Pod TCP/UDP forwarding for noEncap and hybrid modes. Gateway ingress sends local Pod
// traffic to peer Nodes; transport ingress sends remote Pod traffic to OVS through the gateway.
// Handle both directions to avoid exposing only half a connection to host conntrack. Kernel routes
// remain installed for packets returned with TC_ACT_OK, including ICMP, unresolved neighbors and errors.
// Regenerate the embedded programs with make bpf-objects.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

// Constants
#define AF_INET  2  // IPv4 address family.
#define AF_INET6 10 // IPv6 address family.

#define IP_TTL_OFF         (ETH_HLEN + 8)  // IPv4 TTL offset from the Ethernet header start.
#define IP_CHECK_OFF       (ETH_HLEN + 10) // IPv4 checksum offset from the Ethernet header start.
#define IPV6_HOP_LIMIT_OFF (ETH_HLEN + 7)  // IPv6 Hop Limit offset from the Ethernet header start.

// stats indices shared with the Go loader.
#define STAT_FWD         0 // Redirect requested toward a peer Node.
#define STAT_FWD_MISS    1 // Outbound lookup or packet rewrite failed.
#define STAT_RETURN      2 // Redirect requested toward OVS through antrea-gw0.
#define STAT_RETURN_MISS 3 // Inbound lookup or packet rewrite failed.
#define STAT_PASS        4 // Packet is outside the acceleration scope.
#define STAT_TTL_EXPIRED 5 // TTL/Hop Limit exhausted, or IPv4 TTL/checksum update failed.
#define STAT_TOO_BIG     6 // Packet needs MTU handling by the host stack.

// Kernel helper IDs, declared locally to avoid a libbpf dependency.
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

static long (*bpf_skb_store_bytes)(struct __sk_buff *skb,
                                   __u32 offset,
                                   const void *from,
                                   __u32 len,
                                   __u64 flags) = (void *)9;

static long (*bpf_l3_csum_replace)(struct __sk_buff *skb,
                                   __u32 offset,
                                   __u64 from,
                                   __u64 to,
                                   __u64 size) = (void *)10;

static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;

static long (*bpf_fib_lookup)(void *ctx,
                              struct bpf_fib_lookup *params,
                              int plen,
                              __u32 flags) = (void *)69;

// Map descriptors in .hostdp_maps are consumed by hack/gen-bpf-objects and the Go loader.
// Keep this layout synchronized with the generator; the custom format does not require BTF.
struct hostdp_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

// LPM keys contain a prefix length followed by network-order address bytes.
struct pod_route_key {
	__u32 prefixlen;
	__u8 addr[4];
};

// Remote Pod CIDR -> peer Node transport address, mirroring kernel routes.
__attribute__((section(".hostdp_maps"), used))
struct hostdp_map_def pod_routes = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct pod_route_key),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.map_flags = BPF_F_NO_PREALLOC,
};

// Address fields use network byte order; other fields use host byte order.
struct hostdp_ipconfig4 {
	__u32 prefixlen;
	__u32 local_pod_net;
	__u32 gateway_ip;
};

struct hostdp_ipconfig6 {
	__u32 prefixlen;
	__u32 local_pod_net[4];
	__u32 gateway_ip[4];
};

struct hostdp_config {
	__u32 transport_mtu;
	__u32 gateway_mtu;
	__u32 gateway_ifindex;
	__u32 forwarding_enabled;
	struct hostdp_ipconfig4 ipv4;
	struct hostdp_ipconfig6 ipv6;
};

// Node configuration, refreshed when interfaces change.
__attribute__((section(".hostdp_maps"), used))
struct hostdp_map_def node_config = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct hostdp_config),
	.max_entries = 1,
	.map_flags = 0,
};

__attribute__((section(".hostdp_maps"), used))
struct hostdp_map_def stats = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 7,
	.map_flags = 0,
};

// IPv6 routes use 128-bit address keys.
struct pod_route_key6 {
	__u32 prefixlen;
	__u8 addr[16];
};

__attribute__((section(".hostdp_maps"), used))
struct hostdp_map_def pod_routes6 = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct pod_route_key6),
	.value_size = sizeof(struct in6_addr),
	.max_entries = 1024,
	.map_flags = BPF_F_NO_PREALLOC,
};

// All helpers must be inlined: the loader does not relocate BPF-to-BPF calls.
__attribute__((always_inline))
static inline struct hostdp_config *load_config(void) {
	__u32 key = 0;
	return bpf_map_lookup_elem(&node_config, &key);
}

__attribute__((always_inline))
static inline void increment_stat(__u32 slot) {
	__u64 *v = bpf_map_lookup_elem(&stats, &slot);
	if (v == 0) {
		return;
	}

	// The shared counter can be updated by programs running on different CPUs.
	__sync_fetch_and_add(v, 1);
}

// Accept TCP/UDP with a fixed IPv4 header; leave other protocols and IP options to the stack.
__attribute__((always_inline))
static inline int parse_ipv4(struct __sk_buff *skb, struct iphdr **ip_out) {
	// Direct access covers only the linear headers; GRO payload may be non-linear.
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return -1;
	}
	if (eth->h_proto != __builtin_bswap16(ETH_P_IP)) {
		return -1;
	}

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return -1;
	}
	if (ip->ihl != 5) {
		return -1;
	}
	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
		return -1;
	}

	*ip_out = ip;
	return 0;
}

// Exclude the gateway to keep Node-originated traffic with the stack in both directions.
__attribute__((always_inline))
static inline int is_local_pod_ip(__u32 addr) {
	struct hostdp_config *config = load_config();
	if (config == 0) {
		return 0;
	}

	__u32 prefix = config->ipv4.prefixlen;
	if (prefix == 0 || prefix > 32) {
		return 0;
	}

	if (addr == config->ipv4.gateway_ip) {
		return 0;
	}

	// Match raw network-order addresses without converting them to host byte order.
	__u32 mask = __builtin_bswap32(~(((__u32)1 << (32 - prefix)) - 1));

	return (addr & mask) == (config->ipv4.local_pod_net & mask);
}

// Look up the longest remote Pod CIDR prefix covering this address.
__attribute__((always_inline))
static inline __u32 next_hop_of(__u32 addr) {
	struct pod_route_key key = {.prefixlen = 32};
	__builtin_memcpy(key.addr, &addr, 4);

	__u32 *nh = bpf_map_lookup_elem(&pod_routes, &key);
	if (nh == 0) {
		return 0;
	}

	return *nh;
}

// Match remote Pod CIDRs that use the accelerated direct-routing path.
__attribute__((always_inline))
static inline int is_remote_pod_ip(__u32 addr) {
	struct pod_route_key key = {.prefixlen = 32};
	__builtin_memcpy(key.addr, &addr, sizeof(key.addr));

	return bpf_map_lookup_elem(&pod_routes, &key) != 0;
}

// Leave expired TTLs to the stack for ICMP Time Exceeded generation.
__attribute__((always_inline))
static inline int dec_ttl(struct __sk_buff *skb, struct iphdr *ip) {
	__u8 ttl = ip->ttl;
	if (ttl <= 1) {
		return -1;
	}

	__u8 new_ttl = ttl - 1;

	// TTL shares a 16-bit checksum word with protocol, which remains unchanged.
	__u16 old_word = ((__u16)ttl << 8) | ip->protocol;
	__u16 new_word = ((__u16)new_ttl << 8) | ip->protocol;

	if (bpf_skb_store_bytes(skb, IP_TTL_OFF, &new_ttl, 1, 0) < 0) {
		return -1;
	}

	if (bpf_l3_csum_replace(skb,
	                        IP_CHECK_OFF,
	                        __builtin_bswap16(old_word),
	                        __builtin_bswap16(new_word),
	                        2) < 0) {
		return -1;
	}

	return 0;
}

// pod_routes selects the peer; the direct FIB lookup resolves its output interface and MAC.
// An unresolved neighbor falls back to the stack. Managed neighbors let the kernel revalidate cached
// MACs even when redirected traffic bypasses normal neighbor output.
__attribute__((always_inline))
static inline int redirect_via(struct __sk_buff *skb,
                               struct iphdr *ip,
                               __u32 next_hop,
                               __u32 ingress_mtu,
                               __u32 egress_mtu,
                               __u32 miss_stat) {
	// Neighbor reconciliation keeps the kernel's next-hop MACs fresh. Stay on the host stack until it succeeds.
	struct hostdp_config *config = load_config();
	if (config == 0 || config->forwarding_enabled != 1) {
		return TC_ACT_OK;
	}

	struct bpf_fib_lookup fib = {0};
	fib.family = AF_INET;
	fib.ipv4_dst = next_hop;
	fib.ifindex = skb->ifindex;

	// The helper accepts GRO/GSO aggregates but rejects oversized non-GSO packets.
	int fib_ret = bpf_fib_lookup(skb, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);
	switch (fib_ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		break;
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:
		increment_stat(STAT_TOO_BIG);
		return TC_ACT_OK;
	default:
		increment_stat(miss_stat);
		return TC_ACT_OK;
	}

	// Smaller egress MTUs may not fit the original GRO segments. Leave those skbs to the stack.
	if (egress_mtu != 0 &&
        skb->len - ETH_HLEN > egress_mtu &&
	    (ingress_mtu == 0 || ingress_mtu > egress_mtu)) {
		increment_stat(STAT_TOO_BIG);
		return TC_ACT_OK;
	}

	if (dec_ttl(skb, ip) < 0) {
		increment_stat(STAT_TTL_EXPIRED);
		return TC_ACT_OK;
	}

	if (bpf_skb_store_bytes(skb, 0, fib.dmac, 6, 0) < 0 ||
	    bpf_skb_store_bytes(skb, 6, fib.smac, 6, 0) < 0) {
		increment_stat(miss_stat);
		return TC_ACT_OK;
	}

	return bpf_redirect(fib.ifindex, 0);
}

// Gateway ingress: forward local Pod traffic to a peer Node.
__attribute__((always_inline))
static inline int forward_ipv4(struct __sk_buff *skb, struct iphdr *ip) {
	struct hostdp_config *config = load_config();
	if (config == 0) {
		increment_stat(STAT_PASS);
		return TC_ACT_OK;
	}

	if (!is_local_pod_ip(ip->saddr)) {
		increment_stat(STAT_PASS);
		return TC_ACT_OK;
	}

	__u32 next_hop = next_hop_of(ip->daddr);
	if (next_hop == 0) {
		increment_stat(STAT_PASS);
		return TC_ACT_OK;
	}

	int ret = redirect_via(skb,
	                       ip,
	                       next_hop,
	                       config->gateway_mtu,
	                       config->transport_mtu,
	                       STAT_FWD_MISS);
	if (ret != TC_ACT_OK) {
		increment_stat(STAT_FWD);
	}

	return ret;
}

// Transport ingress: deliver remote Pod traffic through the gateway to OVS.
__attribute__((always_inline))
static inline int return_ipv4(struct __sk_buff *skb, struct iphdr *ip) {
	struct hostdp_config *config = load_config();
	if (config == 0) {
		increment_stat(STAT_PASS);
		return TC_ACT_OK;
	}

	// Match the forward path scope so host conntrack sees neither direction of accelerated flows.
	if (!is_local_pod_ip(ip->daddr) || !is_remote_pod_ip(ip->saddr)) {
		increment_stat(STAT_PASS);
		return TC_ACT_OK;
	}

	int ret = redirect_via(skb,
	                       ip,
	                       ip->daddr,
	                       config->transport_mtu,
	                       config->gateway_mtu,
	                       STAT_RETURN_MISS);
	if (ret != TC_ACT_OK) {
		increment_stat(STAT_RETURN);
	}

	return ret;
}

// Accept TCP/UDP without extension headers. ICMPv6, fragments and jumbograms stay with the stack.
__attribute__((always_inline))
static inline int parse_ipv6(struct __sk_buff *skb, struct ipv6hdr **ip_out) {
	// Direct access covers only the linear headers; GRO payload may be non-linear.
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end || eth->h_proto != __builtin_bswap16(ETH_P_IPV6)) {
		return -1;
	}

	struct ipv6hdr *ip = (void *)(eth + 1);

	// Zero payload length also covers BIG TCP aggregates using a Jumbo Payload option.
	if ((void *)(ip + 1) > data_end || ip->version != 6 || ip->payload_len == 0) {
		return -1;
	}
	if (ip->nexthdr != IPPROTO_TCP && ip->nexthdr != IPPROTO_UDP) {
		return -1;
	}

	*ip_out = ip;
	return 0;
}

// Match the local Pod CIDR, excluding the gateway as in the IPv4 path.
__attribute__((always_inline))
static inline int is_local_pod_ipv6(const struct in6_addr *addr) {
	struct hostdp_config *config = load_config();
	if (config == 0 || config->ipv6.prefixlen == 0 || config->ipv6.prefixlen > 128) {
		return 0;
	}

	if (addr->s6_addr32[0] == config->ipv6.gateway_ip[0] &&
	    addr->s6_addr32[1] == config->ipv6.gateway_ip[1] &&
	    addr->s6_addr32[2] == config->ipv6.gateway_ip[2] &&
	    addr->s6_addr32[3] == config->ipv6.gateway_ip[3]) {
		return 0;
	}

	// Unroll for kernels without bounded-loop support.
#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (config->ipv6.prefixlen <= i * 32) {
			break;
		}

		__u32 bits = config->ipv6.prefixlen - i * 32;

		// Avoid a shift by 32 and match partial words in network byte order.
		__u32 mask;
		if (bits >= 32) {
			mask = (__u32)0xffffffff;
		} else {
			mask = __builtin_bswap32((__u32)0xffffffff << (32 - bits));
		}
		if ((addr->s6_addr32[i] & mask) != (config->ipv6.local_pod_net[i] & mask)) {
			return 0;
		}
	}

	return 1;
}

// Look up the longest remote Pod CIDR prefix covering this IPv6 address.
__attribute__((always_inline))
static inline struct in6_addr *next_hop6_of(const struct in6_addr *addr) {
	struct pod_route_key6 key = {.prefixlen = 128};
	__builtin_memcpy(key.addr, addr, sizeof(key.addr));

	return bpf_map_lookup_elem(&pod_routes6, &key);
}

// Match remote IPv6 Pod CIDRs that use the accelerated direct-routing path.
__attribute__((always_inline))
static inline int is_remote_pod_ipv6(const struct in6_addr *addr) {
	struct pod_route_key6 key = {.prefixlen = 128};
	__builtin_memcpy(key.addr, addr, sizeof(key.addr));

	return bpf_map_lookup_elem(&pod_routes6, &key) != 0;
}

// IPv6 counterpart of redirect_via; Hop Limit changes require no header checksum update.
__attribute__((always_inline))
static inline int redirect_via6(struct __sk_buff *skb,
                                struct ipv6hdr *ip,
                                const struct in6_addr *next_hop,
                                __u32 ingress_mtu,
                                __u32 egress_mtu,
                                __u32 miss_stat) {
	struct hostdp_config *config = load_config();
	if (config == 0 || config->forwarding_enabled != 1) {
		return TC_ACT_OK;
	}

	struct bpf_fib_lookup fib = {0};
	fib.family = AF_INET6;
	fib.ifindex = skb->ifindex;
	__builtin_memcpy(fib.ipv6_dst, next_hop, sizeof(fib.ipv6_dst));
	__builtin_memcpy(fib.ipv6_src, &ip->saddr, sizeof(fib.ipv6_src));

	// The helper accepts GRO/GSO aggregates but rejects oversized non-GSO packets.
	int fib_ret = bpf_fib_lookup(skb, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);
	switch (fib_ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		break;
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:
		increment_stat(STAT_TOO_BIG);
		return TC_ACT_OK;
	default:
		increment_stat(miss_stat);
		return TC_ACT_OK;
	}

	// Smaller egress MTUs may not fit the original GRO segments. Leave those skbs to the stack.
	if (egress_mtu != 0 &&
        skb->len - ETH_HLEN > egress_mtu &&
	    (ingress_mtu == 0 || ingress_mtu > egress_mtu)) {
		increment_stat(STAT_TOO_BIG);
		return TC_ACT_OK;
	}

	if (ip->hop_limit <= 1) {
		increment_stat(STAT_TTL_EXPIRED);
		return TC_ACT_OK;
	}

	// Packet stores can invalidate direct packet pointers; do not dereference ip after this point.
	__u8 hop_limit = ip->hop_limit - 1;

	if (bpf_skb_store_bytes(skb, IPV6_HOP_LIMIT_OFF, &hop_limit, 1, 0) < 0 ||
	    bpf_skb_store_bytes(skb, 0, fib.dmac, 6, 0) < 0 ||
	    bpf_skb_store_bytes(skb, 6, fib.smac, 6, 0) < 0) {
		increment_stat(miss_stat);
		return TC_ACT_OK;
	}

	return bpf_redirect(fib.ifindex, 0);
}

// Gateway ingress: forward local Pod traffic to a peer Node.
__attribute__((always_inline))
static inline int forward_ipv6(struct __sk_buff *skb, struct ipv6hdr *ip) {
	struct hostdp_config *config = load_config();
	if (config == 0) {
		increment_stat(STAT_PASS);
		return TC_ACT_OK;
	}

	if (!is_local_pod_ipv6(&ip->saddr)) {
		increment_stat(STAT_PASS);
		return TC_ACT_OK;
	}

	struct in6_addr *next_hop = next_hop6_of(&ip->daddr);
	if (next_hop == 0) {
		increment_stat(STAT_PASS);
		return TC_ACT_OK;
	}

	int ret = redirect_via6(skb,
	                        ip,
	                        next_hop,
	                        config->gateway_mtu,
	                        config->transport_mtu,
	                        STAT_FWD_MISS);
	if (ret != TC_ACT_OK) {
		increment_stat(STAT_FWD);
	}

	return ret;
}

// Transport ingress: deliver remote Pod traffic through the gateway to OVS.
__attribute__((always_inline))
static inline int return_ipv6(struct __sk_buff *skb, struct ipv6hdr *ip) {
	struct hostdp_config *config = load_config();
	if (config == 0) {
		increment_stat(STAT_PASS);
		return TC_ACT_OK;
	}

	// Match the forward path scope so host conntrack sees neither direction of accelerated flows.
	if (!is_local_pod_ipv6(&ip->daddr) || !is_remote_pod_ipv6(&ip->saddr)) {
		increment_stat(STAT_PASS);
		return TC_ACT_OK;
	}

	int ret = redirect_via6(skb,
	                        ip,
	                        &ip->daddr,
	                        config->transport_mtu,
	                        config->gateway_mtu,
	                        STAT_RETURN_MISS);
	if (ret != TC_ACT_OK) {
		increment_stat(STAT_RETURN);
	}

	return ret;
}

// TC entry points retained in the ELF object for the Go loader.
__attribute__((section("tc"), used))
int hostdp_fwd(struct __sk_buff *skb) {
	struct iphdr *ip4;
	if (parse_ipv4(skb, &ip4) == 0) {
		return forward_ipv4(skb, ip4);
	}

	struct ipv6hdr *ip6;
	if (parse_ipv6(skb, &ip6) == 0) {
		return forward_ipv6(skb, ip6);
	}

	increment_stat(STAT_PASS);
	return TC_ACT_OK;
}

__attribute__((section("tc"), used))
int hostdp_return(struct __sk_buff *skb) {
	struct iphdr *ip4;
	if (parse_ipv4(skb, &ip4) == 0) {
		return return_ipv4(skb, ip4);
	}

	struct ipv6hdr *ip6;
	if (parse_ipv6(skb, &ip6) == 0) {
		return return_ipv6(skb, ip6);
	}

	increment_stat(STAT_PASS);
	return TC_ACT_OK;
}

// Required by the GPL-only bpf_fib_lookup helper.
__attribute__((section("license"), used))
char LICENSE[] = "GPL";
