# BGPPolicy

## Table of Contents

<!-- toc -->
- [What is BGPPolicy?](#what-is-bgppolicy)
- [Prerequisites](#prerequisites)
- [The BGPPolicy resource](#the-bgppolicy-resource)
  - [NodeSelector](#nodeselector)
  - [LocalASN](#localasn)
  - [ListenPort](#listenport)
  - [Confederation](#confederation)
  - [Advertisements](#advertisements)
  - [BGPPeers](#bgppeers)
- [BGP router ID](#bgp-router-id)
- [BGP Authentication](#bgp-authentication)
- [Example Usage](#example-usage)
  - [Combined Advertisements of Service, Pod, and Egress IPs](#combined-advertisements-of-service-pod-and-egress-ips)
  - [Advertise Egress IPs to external BGP peers with more than one hop](#advertise-egress-ips-to-external-bgp-peers-with-more-than-one-hop)
  - [Advertise Pod IPs through BGP Confederation](#advertise-pod-ips-through-bgp-confederation)
  - [Enable BFD for fast failover](#enable-bfd-for-fast-failover)
- [Using antctl](#using-antctl)
- [BFD conformance notes](#bfd-conformance-notes)
- [Limitations](#limitations)
<!-- /toc -->

## What is BGPPolicy?

`BGPPolicy` is a custom resource that allows users to run a BGP process on selected Kubernetes Nodes and advertise
Service IPs, Pod IPs, and Egress IPs to remote BGP peers, facilitating the integration of Kubernetes workloads with an
external BGP-enabled network.

## Prerequisites

BGPPolicy was introduced in Antrea v2.1 as an alpha feature. A feature gate, `BGPPolicy`, must be enabled on antrea-agent
in the `antrea-config` ConfigMap for the feature to work, like the following:

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      BGPPolicy: true
```

## The BGPPolicy resource

A BGPPolicy in Kubernetes is a Custom Resource Definition (CRD) object.

The following manifest creates a BGPPolicy object. It will start a BGP process with ASN `64512`, listening on port `179`,
on Nodes labeled with `bgp=enabled`. The process will advertise LoadBalancerIPs and ExternalIPs to a BGP peer at IP
address `192.168.77.200`, which has ASN `65001` and listens on port `179`:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: BGPPolicy
metadata:
  name: example-bgp-policy
spec:
  nodeSelector:
    matchLabels:
      bgp: enabled
  localASN: 64512
  listenPort: 179
  advertisements:
    service:
      ipTypes: [LoadBalancerIP, ExternalIP]
  bgpPeers:
    - address: 192.168.77.200
      asn: 65001
      port: 179
```

### NodeSelector

The `nodeSelector` field selects which Kubernetes Nodes the BGPPolicy applies to based on the Node labels. The field is
mandatory.

**Note**: If multiple BGPPolicy objects select the same Node, the one with the earliest creation time will be chosen
as the effective BGPPolicy.

### LocalASN

The `localASN` field defines the Autonomous System Number (ASN) that the local BGP process uses. This field is mandatory
and accepts values in the range of `1-65535`.

Private ASNs, which are within the ranges 64512-65534 (16-bit), should be strictly limited to private networks or
environments that do not peer with public ASNs. If public network connectivity is required, coordinate with your upstream
provider to avoid issues caused by private ASN usage.

### ListenPort

The `listenPort` field specifies the port on which the BGP process listens. The default value is 179. The valid port
range is `1-65535`.

### Confederation

The `confederation` field specifies that the BGP process operates within a confederation.

- `identifier`: Specifies the ASN of the confederation, serving as its identifier.
- `memberASNs`: Specifies the ASNs of other members that are part of the confederation.

See example [Advertise Pod IPs through BGP Confederation](#advertise-pod-ips-through-bgp-confederation).

### Advertisements

The `advertisements` field configures which IPs are advertised to BGP peers.

- `pod`: Specifies how to advertise Pod IPs. The Node IPAM Pod CIDRs will be advertised by setting `pod:{}`. Note that
  IPs allocated by Antrea Flexible IPAM are not yet supported.
- `egress`: Specifies how to advertise Egress IPs. All Egress IPs will be advertised by setting `egress:{}`. A Node will
  only advertise Egress IPs which are local (i.e., assigned to the Node).
- `service`: Specifies how to advertise Service IPs. The `ipTypes` field lists the types of Service IPs to be advertised,
  which can include `ClusterIP`, `ExternalIP`, and `LoadBalancerIP`.
  - All Nodes can advertise all ClusterIPs, respecting `internalTrafficPolicy`. If `internalTrafficPolicy` is set to
    `Local`, a Node will only advertise ClusterIPs with at least one local Endpoint.
  - All Nodes can advertise all ExternalIPs and LoadBalancerIPs, respecting `externalTrafficPolicy`. If
    `externalTrafficPolicy` is set to `Local`, a Node will only advertise IPs with at least one local Endpoint.

### BGPPeers

The `bgpPeers` field lists the BGP peers to which the advertisements are sent.

- `address`: The IP address of the BGP peer.
- `asn`: The Autonomous System Number of the BGP peer.
- `port`: The port number on which the BGP peer listens. The default value is 179.
- `multihopTTL`: The Time To Live (TTL) value used in BGP packets sent to the BGP peer, with a range of 1 to 255.
  The default value is 1.
- `gracefulRestartTimeSeconds`: Specifies how long the BGP peer waits for the BGP session to re-establish after a
  restart before deleting stale routes, with a range of 1 to 3600 seconds. The default value is 120 seconds.
- `bfd`: Configures Bidirectional Forwarding Detection (RFC 5880) towards the BGP peer, for failure detection much
  faster than the BGP hold timer can provide. BFD runs only when `bfd.enabled` is `true`. When the BFD session
  transitions from up to down, the BGP session is reset immediately, without waiting for the BGP hold timer to expire.
  If the BFD session never comes up (e.g., the peer does not support or enable BFD), the BGP session is not affected.
  BFD is only supported for directly connected peers (`multihopTTL` of 1). BFD control packets are exchanged on UDP
  port 3784, using a source port in the range 49152-65535, and are sent with an IP TTL of 255 as
  [RFC 5881](https://datatracker.ietf.org/doc/html/rfc5881#section-5) requires. This traffic must be allowed by the host
  firewall in both directions: antrea-agent does not install rules for it, just as it does not for the BGP port itself.
  Because the packets have to arrive with a TTL of 255, they cannot cross a router, which is a second reason BFD is
  limited to directly connected peers.
  - `enabled`: Whether BFD runs towards the peer. This field is required, so that BFD can be turned off by setting it
    to `false` while the other fields keep their values.
  - `minReceiveIntervalMilliseconds`: The minimum interval at which the Node is capable of receiving BFD control
    packets, in milliseconds. The peer adjusts its transmission rate to be no faster than this value. The range is 10
    to 60000 and the default value is 300.
  - `minTransmitIntervalMilliseconds`: The interval at which the Node transmits BFD control packets, in milliseconds.
    This interval is used as configured: it is not adjusted to the minimum receive interval advertised by the peer, so
    it should not be set faster than the peer is willing to receive. The range is 10 to 60000 and the default value is
    300.
  - `detectionMultiplier`: The number of consecutive BFD control packets that must be missed before the session is
    declared down. The range is 1 to 255 and the default value is 3.

  See example [Enable BFD for fast failover](#enable-bfd-for-fast-failover), and
  [BFD conformance notes](#bfd-conformance-notes) for the ways the implementation departs from RFC 5880.

## BGP router ID

The BGP router identifier (ID) is a 4-byte field that is usually represented as an IPv4 address. Antrea uses the following
steps to choose the BGP router ID:

1. If the `node.antrea.io/bgp-router-id` annotation is present on the Node and its value is a valid IPv4 address string,
   we will use the provided value.
2. Otherwise, for an IPv4-only or dual-stack Kubernetes cluster, the Node's IPv4 address (assigned to the transport
   interface) is used.
3. Otherwise, for IPv6-only clusters, a 32-bit integer will be generated by hashing the Node's name, then converted to the
   string representation of an IPv4 address.

After this selection process, the `node.antrea.io/bgp-router-id` annotation is added or updated as necessary to reflect
the selected BGP router ID.

The router ID is generated once and will not be updated if the Node configuration changes (e.g., if the Node's IPv4 address is updated).

## BGP Authentication

BGP authentication ensures that BGP sessions are established and maintained only with legitimate peers. Users can provide
authentication passwords for different BGP peering sessions by storing them in a Kubernetes Secret. The Secret must
be defined in the same Namespace as Antrea (`kube-system` by default) and must be named `antrea-bgp-passwords`.

By default, this Secret is not created, and BGP authentication is considered unconfigured for all BGP peers. If the
Secret is created like in the following example, each entry should have a key that is the concatenated string of the BGP
peer IP address and ASN (e.g., `192.168.77.100-65000`, `2001:db8::1-65000`), with the value being the password for that
BGP peer. If a given BGP peer does not have a corresponding key in the Secret data, then authentication is considered
disabled for that peer.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: antrea-bgp-passwords
  namespace: kube-system
stringData:
  192.168.77.100-65000: "password"
  2001:db8::1-65000: "password"
type: Opaque
```

## Example Usage

### Combined Advertisements of Service, Pod, and Egress IPs

In this example, we will advertise Service IPs of types LoadBalancerIP and ExternalIPs, along with Pod CIDRs and Egress
IPs from the selected Nodes to multiple remote BGP peers.

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: BGPPolicy
metadata:
  name: advertise-all-ips
spec:
  nodeSelector:
    matchLabels:
      bgp: enabled
  localASN: 64512
  listenPort: 179
  advertisements:
    service:
      ipTypes: [LoadBalancerIP, ExternalIP]
    pod: {}
    egress: {}
  bgpPeers:
    - address: 192.168.77.200
      asn: 65001
      port: 179
    - address: 192.168.77.201
      asn: 65001
      port: 179
```

### Advertise Egress IPs to external BGP peers with more than one hop

In this example, we configure the BGPPolicy to advertise Egress IPs from selected Nodes to a remote BGP peer located
multiple hops away from the cluster. It's crucial to set the `multihopTTL` to a value equal to or greater than the
number of hops, allowing BGP packets to traverse multiple hops to reach the peer.

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: BGPPolicy
metadata:
  name: advertise-all-egress-ips
spec:
  nodeSelector:
    matchLabels:
      bgp: enabled
  localASN: 64512
  listenPort: 179
  advertisements:
    egress: {}
  bgpPeers:
    - address: 192.168.78.201
      asn: 65001
      port: 179
      multihopTTL: 2
```

### Advertise Pod IPs through BGP Confederation

In this example, we configure a BGPPolicy to advertise Pod IPs from selected Nodes to remote BGP peers. The BGP process
operates within a confederation identified by ASN `65000`, which includes another member with ASN `64513`. When
communicating with the peer at IP address `192.168.77.200`, which is outside the confederation, the ASN `65000` is used
as the identifier, to represent the confederation. Conversely, when communicating with the peer at IP address
`192.168.77.103`, which is within the confederation, the private ASN `64512` is used. This configuration ensures that the
BGP process correctly identifies and communicates with peers both inside and outside the confederation.

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: BGPPolicy
metadata:
  name: example-bgp-policy-with-confederation
spec:
  nodeSelector:
    matchLabels:
      bgp: enabled
  localASN: 64512
  listenPort: 179
  confederation:
    identifier: 65000
    memberASNs:
      - 64513
  advertisements:
    pod: {}
  bgpPeers:
    - address: 192.168.77.200
      asn: 65001
      port: 179
    - address: 192.168.77.103
      asn: 64513
      port: 179
```

### Enable BFD for fast failover

In this example, BFD is enabled towards the BGP peer. With the default parameters (a 300 millisecond interval in each
direction and a detection multiplier of 3), a connectivity failure to the peer is detected in less than a second, and
the BGP session is reset immediately, so that the peer stops forwarding traffic through this Node without waiting for
the BGP hold timer (90 seconds by default) to expire. The hold timer still acts as a backstop, e.g. if BFD is not
running. Setting only `enabled: true` is enough to run BFD with the default parameters; the interval and multiplier
values below are shown for illustration. Setting `enabled: false` stops BFD towards the peer while leaving the other
values in place for the next time it is turned on.

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: BGPPolicy
metadata:
  name: example-bgp-policy-with-bfd
spec:
  nodeSelector:
    matchLabels:
      bgp: enabled
  localASN: 64512
  advertisements:
    service:
      ipTypes: [LoadBalancerIP]
  bgpPeers:
    - address: 192.168.77.200
      asn: 65001
      bfd:
        enabled: true
        minReceiveIntervalMilliseconds: 300
        minTransmitIntervalMilliseconds: 300
        detectionMultiplier: 3
```

The state of the BFD sessions can be checked with `antctl get bgppeers`.

Checking it is worth doing after enabling BFD, because a blocked UDP 3784 fails quietly. The BFD session simply never
leaves `Down`, the BGP session is unaffected, and failure detection falls back to the BGP hold timer: nothing breaks,
and the only symptom is that failover is not fast. A `Down` BFD state on an `Established` peer is the signal to check
the host firewall.

## Using antctl

Please refer to the corresponding [antctl page](antctl.md#bgp-commands).

## BFD conformance notes

BFD is implemented by the embedded gobgp library rather than by Antrea, and as of gobgp v4.9.0 it departs from
[RFC 5880](https://datatracker.ietf.org/doc/html/rfc5880) in the three ways listed below. All three affect only the
control packets a Node sends. How quickly a Node detects a failed peer is unaffected: the detection time is derived
from the timers the peer advertises, as
[Section 6.8.4](https://datatracker.ietf.org/doc/html/rfc5880#section-6.8.4) requires.

- **The transmit interval is not negotiated.**
  [Section 6.8.3](https://datatracker.ietf.org/doc/html/rfc5880#section-6.8.3) requires a system to slow its
  transmissions to the minimum receive interval advertised by the peer. That field is read off the wire and then
  ignored, so a Node keeps transmitting at `minTransmitIntervalMilliseconds` even when the peer asks for a slower rate.
  Set `minTransmitIntervalMilliseconds` to a rate the peer is configured to accept: a peer that polices BFD control
  packets may drop the excess and take the session down.
- **Transmissions are not jittered.**
  [Section 6.8.7](https://datatracker.ietf.org/doc/html/rfc5880#section-6.8.7) requires up to 25% jitter so that
  sessions do not synchronise with one another. Every BFD session on a Node therefore transmits in lockstep, which
  concentrates the packets of a Node with many BFD-enabled peers into bursts.
- **The transmit rate is not reduced while the session is down.**
  [Section 6.8.3](https://datatracker.ietf.org/doc/html/rfc5880#section-6.8.3) requires a system to back off to no
  faster than one packet per second while the session is not up. Enabling BFD towards a peer that never answers, for
  example one that does not have BFD configured, therefore produces a steady stream of unanswered packets rather than
  a slow probe. The BGP session itself is unaffected.

A further consideration is not a conformance question but is worth weighing before choosing aggressive timers: this BFD
runs in the antrea-agent process, not in the kernel or in hardware. If the agent is starved of CPU for longer than the
peer's detection time, the peer declares the session down and the BGP session is reset, withdrawing the Node's routes.
The default timers give a budget of roughly 900 milliseconds. Do not set a CPU limit on the antrea-agent container when
BFD is enabled, and prefer more conservative timers, for example 500 milliseconds with a detection multiplier of 4,
until you have flap data for your cluster.

## Limitations

- The routes received from remote BGP peers will not be installed. Therefore, you must ensure that the path from Nodes
  to the remote BGP network is properly configured and routable. This involves configuring your network infrastructure
  to handle the routing of traffic between your Kubernetes cluster and the remote BGP network.
- Only Linux Nodes are supported. The feature has not been validated on Windows Nodes, though theoretically it can work
  with Windows Nodes.
- Advanced BGP features such as BGP communities, route filtering, route reflection, confederations, and other BGP policy
  mechanisms defined in BGP RFCs are not supported.
- BFD is only supported for directly connected BGP peers (`multihopTTL` of 1).
- The BFD implementation departs from RFC 5880 in the transmit path. See
  [BFD conformance notes](#bfd-conformance-notes).
