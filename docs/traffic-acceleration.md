# Traffic Acceleration with NFTables Flowtable

## Table of Contents

<!-- toc -->
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Implementation](#implementation)
  - [Peer Pod CIDR Sets](#peer-pod-cidr-sets)
  - [Flowtable](#flowtable)
  - [Forwarding Chain](#forwarding-chain)
- [Benchmark](#benchmark)
<!-- /toc -->

## Overview

Antrea introduces nftables flowtable to accelerate traffic that is forwarded through Node host networking when the
traffic mode is noEncap or hybrid. By offloading eligible connections into the nftables flowtable at the ingress hook,
packets can be fast-tracked in the datapath. Once offloaded, they bypass most of the Linux host networking stack,
reducing overhead and significantly improving forwarding performance.

## Prerequisites

- Antrea v2.5.0 or greater
- Linux Kernel 3.13 or greater

To enable traffic acceleration, the antrea-agent option `hostNetworkAcceleration.enable` must be set to `true`.

```yaml
    hostNetworkAcceleration:
      # Enable to accelerate traffic on Node host networking when traffic mode is noEncap or hybrid. Currently only
      # Pod-to-Pod traffic is supported. External-to-Service and Pod-to-external traffic will be supported in the future.
      enable: true
```

## Implementation

A new nftables table named `antrea` is introduced. The table consists of three main components:

### Peer Pod CIDR Sets

- `antrea-peer-pod-cidr-ip`: stores IPv4 peer Pod CIDRs.
- `antrea-peer-pod-cidr-ip6` stores IPv6 peer Pod CIDRs.

```text
    set antrea-peer-pod-cidr-ip {
        type ipv4_addr
        flags interval
        comment "Antrea: IPv4 peer Pods CIDRs"
        elements = { 10.244.0.0/24, 10.244.1.0/24 }
    }

    set antrea-peer-pod-cidr-ip6 {
        type ipv6_addr
        flags interval
        comment "Antrea: IPv6 peer Pods CIDRs"
        elements = { fd00:10:244::/64,
                     fd00:10:244:1::/64 }
    }
```

### Flowtable

The flowtable `antrea-flowtable` is bound to both the Antrea gateway interface (`antrea-gw0`) and the Node’s transport
interface (e.g. `eth0`). This configuration enables acceleration of traffic forwarded through the interfaces. Additional
interfaces may be supported in the future to accelerate other traffic types such as NodePort.

```text
    flowtable antrea-flowtable {
        hook ingress priority filter
        devices = { antrea-gw0, eth0 }
    }
```

### Forwarding Chain

The chain `antrea-forward` stores the rules to match the connections which are eligible for flowtable acceleration.
Currently, only Pod-to-Pod traffic in noEncap or hybrid is supported.

```text
    chain antrea-forward {
        comment "Antrea: forward chain"
        type filter hook forward priority filter; policy accept;

        iif "antrea-gw0" ip saddr 10.244.2.0/24 oif "eth0" ip daddr @antrea-peer-pod-cidr-ip \
            flow add @antrea-flowtable counter packets 10 bytes 520 \
            comment "Accelerate IPv4 traffic from local Pod CIDR to remote Pod CIDRs"

        iif "eth0" ip saddr @antrea-peer-pod-cidr-ip oif "antrea-gw0" ip daddr 10.244.2.0/24 \
            flow add @antrea-flowtable counter packets 0 bytes 0 \
            comment "Accelerate IPv4 traffic from remote Pod CIDRs to local Pod CIDR"

        iif "antrea-gw0" ip6 saddr fd00:10:244:2::/64 oif "eth0" ip6 daddr @antrea-peer-pod-cidr-ip6 \
            flow add @antrea-flowtable counter packets 0 bytes 0 \
            comment "Accelerate IPv6 traffic from local Pod CIDR to remote Pod CIDRs"

        iif "eth0" ip6 saddr @antrea-peer-pod-cidr-ip6 oif "antrea-gw0" ip6 daddr fd00:10:244:2::/64 \
            flow add @antrea-flowtable counter packets 0 bytes 0 \
            comment "Accelerate IPv6 traffic from remote Pod CIDRs to local Pod CIDR"
    }
}

```

In the future, Antrea will support more traffic types:

- External-to-Service traffic: accelerate external client traffic destined for a Service before it enters the Antrea
  OVS pipeline on Node host networking, in encap, noEncap, or hybrid modes.
- Pod-to-external traffic: accelerate Pod egress traffic after it leaves the Antrea OVS pipeline on Node host networking,
  in encap, noEncap, or hybrid modes.

## Benchmark

The following results are the netperf results of encap, noEncap without acceleration, noEncap with acceleration:

Test environment:

- AWS c5.4xlarge VM
- Kind cluster with 3 Nodes
- Antrea 2.5.0

|                              | TCP_STREAM           | TCP_RR               | TCP_CRR             |
|------------------------------|----------------------|----------------------|---------------------|
| encap                        | 5540.38              | 24566.09             | 6740.29             |
| noEncap without acceleration | 6086.53  **(+10%)**  | 21880.85  **(-11%)** | 6685.29  **(-1%)**  |
| noEncap with acceleration    | 7733.76   **(+40%)** | 25763.51   **(+5%)** | 7289.91   **(+8%)** |
