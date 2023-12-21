# Multicast User Guide

Antrea supports multicast traffic in the following scenarios:

1. Pod to Pod - a Pod that has joined a multicast group will receive the
   multicast traffic to that group from the Pod senders.
2. Pod to External - external hosts can receive the multicast traffic sent
   from Pods, when the Node network supports multicast forwarding / routing to
   the external hosts.
3. External to Pod - Pods can receive the multicast traffic from external
   hosts.

## Table of Contents

<!-- toc -->
- [Prerequisites](#prerequisites)
- [Multicast NetworkPolicy](#multicast-networkpolicy)
- [Debugging and collecting multicast statistics](#debugging-and-collecting-multicast-statistics)
  - [Pod multicast group information](#pod-multicast-group-information)
  - [Inbound and outbound multicast traffic statistics](#inbound-and-outbound-multicast-traffic-statistics)
  - [Multicast NetworkPolicy statistics](#multicast-networkpolicy-statistics)
- [Use case example](#use-case-example)
- [Limitations](#limitations)
  - [Encap mode](#encap-mode)
  - [Maximum number of receiver groups on one Node](#maximum-number-of-receiver-groups-on-one-node)
  - [Traffic in local network control block](#traffic-in-local-network-control-block)
  - [Linux kernel](#linux-kernel)
  - [Antrea FlexibleIPAM](#antrea-flexibleipam)
<!-- /toc -->

## Prerequisites

Multicast support was introduced in Antrea v1.5.0 as an alpha feature, and was
graduated to beta in v1.12.0.

* Prior to v1.12.0, a feature gate, `Multicast` must be enabled in the
  `antrea-controller` and `antrea-agent` configuration to use the feature.
* Starting from v1.12.0, the feature gate is enabled by default, you need to set
  the `multicast.enable` flag to true in the `antrea-agent` configuration to use
  the feature.

There are three other configuration options -`multicastInterfaces`,
`igmpQueryVersions`, and `igmpQueryInterval` for `antrea-agent`.

```yaml
  antrea-agent.conf: |
    multicast:
      enable: true
      # The names of the interfaces on Nodes that are used to forward multicast traffic.
      # Defaults to transport interface if not set.
      multicastInterfaces: 
      # The versions of IGMP queries antrea-agent sends to Pods.
      # Valid versions are 1, 2 and 3.
      igmpQueryVersions:
      - 1
      - 2
      - 3
      # The interval at which the antrea-agent sends IGMP queries to Pods.
      # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
      igmpQueryInterval: "125s"
```

## Multicast NetworkPolicy

Antrea NetworkPolicy and Antrea ClusterNetworkPolicy are supported for the
following types of multicast traffic:

1. IGMP egress rules: applied to IGMP membership report and IGMP leave group
   messages.
2. IGMP ingress rules: applied to IGMP query, which includes IGMPv1, IGMPv2, and
   IGMPv3.
3. Multicast egress rules: applied to non-IGMP multicast traffic from the
   selected Pods to other Pods or external hosts.

Note, multicast ingress rules are not supported at the moment.

Examples: You can refer to the [ACNP for IGMP traffic](antrea-network-policy.md#acnp-for-igmp-traffic)
and [ACNP for multicast egress traffic](antrea-network-policy.md#acnp-for-multicast-egress-traffic)
examples in the Antrea NetworkPolicy document.

## Debugging and collecting multicast statistics

Antrea provides tooling to check multicast group information and multicast
traffic statistics.

### Pod multicast group information

The `kubectl get multicastgroups` command prints multicast groups joined by Pods
in the cluster. Example output of the command:

```bash
$ kubectl get multicastgroups
GROUP       PODS
225.1.2.3   default/mcjoin, namespace/pod
224.5.6.4   default/mcjoin
```

### Inbound and outbound multicast traffic statistics

`antctl` supports printing multicast traffic statistics of Pods. Please refer to
the corresponding [antctl user guide section](antctl.md#multicast-commands).

### Multicast NetworkPolicy statistics

The [Antrea NetworkPolicyStats feature](feature-gates.md#networkpolicystats)
also supports multicast NetworkPolices.

## Use case example

This section will take multicast video streaming as an example to demonstrate
how multicast works with Antrea. In this example,
[VLC](https://www.videolan.org/vlc/) multimedia tools are used to generate and
consume multicast video streams.

To start a video streaming server, we start a VLC Pod to stream a sample video
to the multicast IP address `239.255.12.42` with TTL 6.

```bash
kubectl run -i --tty --image=quay.io/galexrt/vlc:latest vlc-sender -- --intf ncurses --vout dummy --aout dummy 'https://upload.wikimedia.org/wikipedia/commons/transcoded/2/26/Bees_on_flowers.webm/Bees_on_flowers.webm.120p.vp9.webm' --sout udp:239.255.12.42 --ttl 6 --repeat
```

You can verify multicast traffic is sent out from this Pod by running
`antctl get podmulticaststats` in the `antrea-agent` Pod on the local Node,
which indicates the VLC Pod is sending out multicast video streams.

You can also check the multicast routes on the Node by running command
`ip mroute`, which should print the following route for forwarding the multicast
traffic from the Antrea gateway interface to the transport interface.

```bash
$ ip mroute
(<POD IP>, 239.255.12.42)     Iif: antrea-gw0 Oifs: <TRANSPORT INTERFACES> State: resolved
```

We also create a VLC Pod to be the receiver with the following command:

```bash
kubectl run -i --tty --image=quay.io/galexrt/vlc:latest vlc-receiver -- --intf ncurses --vout dummy --aout dummy udp://@239.255.12.42 --repeat
```

It's expected to see inbound multicast traffic to this Pod by running
`antctl get podmulticaststats` in the local `antrea-agent` Pod,
which indicates the VLC Pod is receiving the video stream.

Also, the `kubectl get multicastgroups` command will show that `vlc-receiver`
has joined multicast group `239.255.12.42`.

## Limitations

This feature is currently supported only for IPv4 Linux clusters. Support for
Windows and IPv6 will be added in the future.

### Encap mode

The configuration option `multicastInterfaces` is not supported with encap mode.
Multicast packets in encap mode are SNATed and forwarded to the transport
interface only.

### Maximum number of receiver groups on one Node

A Linux host limits the maximum number of multicast groups it can subscribe to;
the default number is 20. The limit can be changed by setting [/proc/sys/net/ipv4/igmp_max_memberships](https://sysctl-explorer.net/net/ipv4/igmp_max_memberships/).
Users are responsible for changing the limit if Pods on the Node are expected to
join more than 20 groups.

### Traffic in local network control block

Multicast IPs in [Local Network Control Block](https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml#multicast-addresses-1) (224.0.0.0/24)
can only work in encap mode. Multicast traffic destined for those addresses
is not expected to be forwarded, therefore, no multicast route will be
configured for them. External hosts are not supposed to send and receive traffic
with those addresses either.

### Linux kernel

If the following situations apply to your Nodes, you may observe multicast
traffic is not routed correctly:

1. Node kernel version under 5.4
2. Node network doesn't support IGMP snooping

### Antrea FlexibleIPAM

The configuration option `multicastInterfaces` is not supported with
[Antrea FlexibleIPAM](antrea-ipam.md#antrea-flexible-ipam). When Antrea
FlexibleIPAM is enabled, multicast packets are forwarded to the uplink interface
only.
