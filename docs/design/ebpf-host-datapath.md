# eBPF Host Network Datapath

The `EBPFHostDataPath` feature gate enables cross-Node Pod TCP/UDP forwarding with eBPF.
It is Alpha and disabled by default. It supports IPv4, IPv6 and dual-stack Nodes in
noEncap and hybrid modes. Only traffic that uses direct routing to the peer Node is
accelerated; tunneled traffic keeps its existing path.

## Packet path

Normally, OVS sends a remote Pod packet through `antrea-gw0`, then the host network
stack routes it to the peer Node. The eBPF programs redirect it between interfaces,
skipping host IP forwarding and netfilter:

```text
Outbound: Pod -> OVS -> antrea-gw0 ingress -> hostdp_fwd -> transport interface -> peer Node
Inbound:  peer Node -> transport ingress -> hostdp_return -> antrea-gw0 -> OVS -> Pod
```

Both directions are handled to avoid having only one direction of a connection pass
through host conntrack. OVS still handles Pod networking, Service translation and
Antrea NetworkPolicy. This feature adds no NAT or connection tracking in eBPF.

The Node route controller copies remote Pod CIDRs and peer Node IPs into the
`pod_routes` and `pod_routes6` BPF maps. For each matching packet, the program:

1. Finds the peer Node IP in the route map, or selects the local Pod IP for inbound traffic.
2. Calls `bpf_fib_lookup` to get the output interface and MAC addresses from the kernel's
   routing and neighbor tables.
3. Decrements IPv4 TTL or IPv6 Hop Limit, updates the IPv4 header checksum, rewrites the
   Ethernet addresses and redirects the packet.

Pod addresses are identified by Pod CIDRs. The local gateway IP is excluded so that
Node-originated traffic keeps using the host stack. Loading fails if the Node's own
transport IP falls inside its local Pod CIDR.

## Kernel fallback

Antrea continues to install the normal kernel routes. A program returns `TC_ACT_OK`
to let the host stack handle traffic it cannot accelerate, including:

- ICMP, ICMPv6, SCTP and other protocols outside TCP/UDP.
- IPv4 options, IPv6 extension headers, IPv6 fragments and IPv6 jumbograms.
- Missing route-map entries or unresolved neighbors.
- Expired TTL or Hop Limit, and packets that need kernel MTU handling.

GRO aggregates can be redirected while preserving their segmentation metadata.
Ordinary oversized packets fall back to the stack. Aggregates also fall back when
the outgoing MTU is smaller than the incoming MTU, or the incoming MTU is unknown.

Failure to load the programs is logged; the Agent continues using the host stack.
Accelerated packets bypass host netfilter rules and conntrack. Administrators who
use host `FORWARD` rules to restrict Pod traffic must account for this behavior.

## Neighbor refresh

A successful `bpf_fib_lookup` can return a cached MAC even when the neighbor is
`STALE`. Redirecting traffic does not trigger normal kernel neighbor probing, so
lookup failures alone cannot keep MAC addresses fresh.

The Agent registers peer Node IPs on the transport interface and local Pod IPs on
`antrea-gw0` with `NTF_EXT_MANAGED` and `NTF_EXT_LEARNED`. The kernel then resolves
and refreshes these entries using ARP for IPv4 and NDP for IPv6. Existing
`PERMANENT` and `NOARP` entries are left unchanged.

Redirects start disabled. The first successful neighbor reconciliation enables them;
a later reconciliation error pauses them until reconciliation succeeds again.
Node route changes trigger reconciliation. A 30-second check also discovers local
Pod addresses from the interface store and repairs registrations. The kernel runs
the probes; the Agent does not send ARP or NDP probes itself.

A runtime check verifies managed-neighbor support for each enabled address family
before attaching the programs. This requires Linux 5.16 or a kernel with the feature
backported. If the check fails, traffic stays on the host stack.

## Build and loading

```text
host_datapath.bpf.c -> clang -> host_datapath.o -> hack/gen-bpf-objects -> objects_linux.go
                                                             |
                                                    Agent creates maps,
                                                    loads programs and
                                                    attaches TC hooks
```

Run `make bpf-objects` after changing the C source. The generated Go file contains
program instructions, map definitions and map references. Normal Agent builds need
neither clang nor an eBPF library. All C helper functions are inlined; the generator
rejects objects containing separate BPF functions.

The loader tries BPF link attachment first and falls back to a clsact TC filter.
BPF links detach when their descriptors close. TC filters can survive an Agent crash;
the Agent removes its old filters on startup and removes its attachments on shutdown.
The 30-second check repairs missing interfaces or filters and updates interface MTUs.

## Counters and limits

`antrea_agent_ebpf_host_datapath_packets_total` exports seven results: `forwarded`,
`returned`, `forward_miss`, `return_miss`, `passed`, `ttl_expired` and `too_big`.
A redirect counter records an attempted redirect, not confirmed delivery. A miss
counter does not identify the exact lookup failure or prove neighbor health.

Each route map holds up to 1024 CIDR entries. IPv4 and IPv6 use separate maps;
both families share one Node configuration structure and one set of counters. Route keys store IP bytes in
network order for longest-prefix matching.

Remaining limitations:

- Interface and MTU changes may take up to the next periodic check to be reflected.
  A BPF-link interface recreated with the same index between checks may be missed.
- Local Pod addresses absent from the interface store are registered by a later check.
- Neighbor flag ownership is tracked only in memory. An Agent crash can leave managed
  registrations behind; cleanup of orphaned registrations across restarts is not implemented.
- Neighbor recovery time depends on kernel settings and peer reachability.
- Verifier errors report instruction indices without mapping them back to C source lines.
