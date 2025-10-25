# Host Network Traffic Acceleration

## Table of Contents

<!-- toc -->
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Implementation](#implementation)
  - [Table](#table)
  - [Peer Pod CIDR Set](#peer-pod-cidr-set)
  - [Flowtable](#flowtable)
  - [Forwarding Chain](#forwarding-chain)
- [Benchmark](#benchmark)
<!-- /toc -->

## Overview

Antrea introduces nftables flowtable to accelerate traffic that is forwarded through the Node's host network when the
traffic mode is noEncap or hybrid. By offloading eligible connections into the nftables flowtable at the ingress hook,
packets can be fast-tracked through the Node's host networking stack. Once offloaded, theses packets bypass most kernel
networking processing, reducing overhead and significantly improving forwarding performance.

## Prerequisites

- Antrea v2.5.0 or later
- Linux kernel 3.13 or later
- Kernel modules (should be built-in or loadable):
  - `nf_tables`, nftables core module
  - `nf_flow_table`, generic flow table infrastructure
  - `nft_flow_offload`, flowtable offload support for nftables
  - `nf_flow_table_inet`, flowtable support for IPv4 and IPv6
  - `nf_flow_table_ipv4`, flowtable implementation for IPv4 (required only before Linux kernel 5.17)
  - `nf_flow_table_ipv6`, flowtable implementation for IPv6 (required only before Linux kernel 5.17)

To enable traffic acceleration, the antrea-agent config option `hostNetworkAcceleration.enable` must be set to `true`.

```yaml
    hostNetworkAcceleration:
      # Enable to accelerate Pod-to-Pod traffic in the Node's host network using nftables flowtable when traffic mode is
      # noEncap or hybrid.
      enable: true
```

## Implementation

### Table

Antrea introduces dedicated nftables tables named `antrea` for both IPv4 and IPv6:

```text
table ip antrea {
    comment "Rules for Antrea"
}

table ip6 antrea {
    comment "Rules for Antrea"
}
```

These tables contain flowtables, sets, and chains used for acceleration logic.

### Peer Pod CIDR Set

Each nftables table maintains a set named `peer-pod-cidr` containing Pod CIDRs of remote Nodes.

IPv4 example:

```text
table ip antrea {
    set peer-pod-cidr {
        type ipv4_addr
        flags interval
        comment "Set for storing IPv4 peer Pods CIDRs"
        elements = { 10.244.0.0/24, 10.244.1.0/24 }
    }
}
```

IPv6 example:

```text
table ip6 antrea {
    set peer-pod-cidr {
        type ipv6_addr
        flags interval
        comment "Set for storing IPv6 peer Pods CIDRs"
        elements = { fd00:10:244::/64, fd00:10:244:1::/64 }
    }
}
```

### Flowtable

The flowtable named `fastpath` is bound to both the Antrea gateway interface (`antrea-gw0`) and the Node’s transport
interface (e.g., `eth0`). This configuration allows packets forwarded between these interfaces to be accelerated.

```text
table ip antrea {
    flowtable fastpath {
        hook ingress priority filter
        devices = { antrea-gw0, eth0 }
    }
}
```

### Forwarding Chain

The chain named `forward` holds the rules to match the connections which are eligible for flowtable acceleration.
Currently, only inter-Node Pod-to-Pod traffic of noEncap or hybrid mode is supported.

```text
table ip antrea {
    chain forward {
        comment "Forward chain for storing rules"
        type filter hook forward priority filter; policy accept;

        iif "antrea-gw0" ip saddr 10.244.2.0/24 oif "eth0" ip daddr @peer-pod-cidr \
            flow add @fastpath counter packets 0 bytes 0 \
            comment "Accelerate IPv4 connections: local Pod CIDR to remote Pod CIDRs"

        iif "eth0" ip saddr @peer-pod-cidr oif "antrea-gw0" ip daddr 10.244.2.0/24 \
            flow add @fastpath counter packets 0 bytes 0 \
            comment "Accelerate IPv4 connections: remote Pod CIDRs to local Pod CIDR"
    }
}
```

In the future, Antrea will support more traffic types:

- External-to-Service traffic: accelerate external client traffic destined for a Service before it enters the Antrea
  OVS pipeline in encap, noEncap, and hybrid modes.
- Pod-to-external traffic: accelerate Pod egress traffic after it leaves the Antrea OVS pipeline in encap, noEncap, and
  hybrid modes.

## Benchmark

Netperf tests were conducted to compare performance across three configurations: encap (no acceleration), noEncap (no
acceleration), and noEncap (with acceleration). The test environment is:

- AWS c5.4 xlarge VM
- Kind cluster with 3 Nodes
- Antrea v2.5.0

|                              | TCP_STREAM          | TCP_RR               | TCP_CRR            |
|------------------------------|---------------------|----------------------|--------------------|
| encap                        | 5540.38             | 24566.09             | 6740.29            |
| noEncap without acceleration | 6086.53  **(+10%)** | 21880.85  **(-11%)** | 6685.29  **(-1%)** |
| noEncap with acceleration    | 7733.76  **(+40%)** | 25763.51   **(+5%)** | 7289.91  **(+8%)** |
