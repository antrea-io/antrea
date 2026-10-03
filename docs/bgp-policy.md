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
  - [Tune the BGP timers for faster failure detection](#tune-the-bgp-timers-for-faster-failure-detection)
  - [Leaving room for jitter](#leaving-room-for-jitter)
- [Using antctl](#using-antctl)
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
- `gracefulRestartEnabled`: Whether to advertise the BGP graceful restart capability to the BGP peer. The default value
  is `true`. When it is set to `false`, the capability is not advertised and `gracefulRestartTimeSeconds` has no effect.
- `gracefulRestartTimeSeconds`: Specifies how long the BGP peer waits for the BGP session to re-establish after a
  restart before deleting stale routes, with a range of 1 to 3600 seconds. The default value is 120 seconds.

The following fields configure the BGP timers of the session with the peer.

- `holdTimeSeconds`: The hold time proposed to the BGP peer when the session is established, i.e. how long the peer
  should wait without receiving a KEEPALIVE or an UPDATE message from the Node before tearing the session down. The
  effective hold time is the smaller of the two values proposed by the two BGP speakers. The range is 3 to 65535
  seconds. The default value is 90 seconds.
- `keepaliveIntervalSeconds`: The interval at which KEEPALIVE messages are sent to the BGP peer. The range is 1 to
  65534 seconds. It must be less than `holdTimeSeconds`, otherwise the peer's hold timer can never be refreshed in
  time; a BGPPolicy that breaks this rule is rejected. Because `holdTimeSeconds` defaults to 90 seconds, setting only
  `keepaliveIntervalSeconds` to 90 or more is rejected as well.

  This is the one timer with no default value. When it is left unset, the BGP process derives the interval from one
  third of `holdTimeSeconds`, so lowering only the hold time speeds up the KEEPALIVEs to match. A fixed default would
  also be rejected by the rule above as soon as `holdTimeSeconds` was lowered below it.

  The hold time is negotiated but the keepalive interval is not. Each speaker proposes a hold time in its OPEN message
  and the smaller of the two takes effect ([RFC 4271 section 4.2](https://www.rfc-editor.org/rfc/rfc4271.html#section-4.2)).
  The BGP process then recomputes the keepalive interval as one third of the negotiated hold time for the speaker that
  proposed the larger value, [discarding `keepaliveIntervalSeconds` even when it is
  set](https://github.com/osrg/gobgp/blob/v4.8.0/pkg/server/fsm.go#L690-L694). A peer proposing a smaller hold time
  than this Node therefore also decides this Node's keepalive interval.
- `connectRetrySeconds`: How long to wait before retrying to connect to the BGP peer after a failed connection attempt.
  The range is 2 to 65535 seconds. The default value is 120 seconds.
- `idleHoldTimeAfterResetSeconds`: How long the session stays in the Idle state before a new connection to the BGP peer
  is attempted, after the antrea-agent itself resets the session. It does not apply to a session lost because the hold
  timer expired or because the peer closed it, and the antrea-agent currently never resets a session on its own. The
  range is 1 to 3600 seconds. The default value is 30 seconds.

[RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-10) suggests a keepalive interval of one third of the
hold time. That ratio is not enforced, because a thinner one still gives a working session; it only leaves less room
for a burst of lost messages. See
[Leaving room for jitter](#leaving-room-for-jitter) for how to choose the two values together.

**Note**: `holdTimeSeconds` and `keepaliveIntervalSeconds` are fixed when the session is established, so changing
either of them on an existing peer makes the antrea-agent tear the session down and re-establish it, which briefly
interrupts the advertisements to that peer. `gracefulRestartEnabled` and `gracefulRestartTimeSeconds` are advertised in
the same OPEN message, so changing them re-establishes the session as well. `connectRetrySeconds` applies only while
the session is down, so it never interrupts an established one, and `idleHoldTimeAfterResetSeconds` is only read when a
reset happens, so it does not interrupt one either.

See example [Tune the BGP timers for faster failure detection](#tune-the-bgp-timers-for-faster-failure-detection).

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

### Tune the BGP timers for faster failure detection

The following BGPPolicy detects the loss of a peer after 10 seconds instead of the default 90, by sending a KEEPALIVE
message every 3 seconds, and retries a failed connection every 5 seconds:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: BGPPolicy
metadata:
  name: example-bgp-policy-timers
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
      holdTimeSeconds: 10
      keepaliveIntervalSeconds: 3
      connectRetrySeconds: 5
```

Make sure the peer is configured to propose a compatible hold time: the effective hold time is the smaller of the two
proposed values, so a peer proposing 90 seconds does not shorten its own detection time just because this Node proposes
10.

### Leaving room for jitter

The peer resets its hold timer every time it receives a KEEPALIVE or an UPDATE, so what decides whether a session
survives is not the interval on its own, but the largest gap between two messages the peer actually receives. With a
keepalive interval of 3 seconds:

| KEEPALIVEs lost in a row | Gap | Hold time 9 | Hold time 10 |
| --- | --- | --- | --- |
| 0 | 3s | 6s to spare | 7s to spare |
| 1 | 6s | 3s to spare | 4s to spare |
| 2 | 9s | exactly the deadline | 1s to spare |

The BGP process sends KEEPALIVE messages on a fixed interval, with no jitter and no margin, and it expires the hold
timer at exactly the negotiated value. So a hold time of 9 with an interval of 3 — the ratio RFC 4271 suggests — makes
the loss of two consecutive KEEPALIVEs a race: the third is sent 9 seconds after the last one the peer received and
arrives one network delay later, while the peer's hold timer fires at 9 seconds exactly. Scheduling delays and network
latency only ever make a message later, never earlier, so the race is biased towards the session being torn down. A
hold time of 10 turns it into a full second of margin, for one extra second of detection time. That is why the example
above uses 10 and 3 rather than 9 and 3.

This is not a quirk of small numbers: the default 90 and 30 has exactly the same geometry, and two consecutive missed
KEEPALIVEs land on the deadline there too. What changes with aggressive timers is the absolute margin. At 90 and 30 a
session survives unless 60 consecutive seconds of KEEPALIVEs are lost, whereas at 9 and 3 six seconds are enough, which
a short CPU starvation of the antrea-agent or a brief reconvergence can produce. Short timers are exactly where jitter
matters, so prefer a hold time slightly above three times the keepalive interval rather than exactly at it. A hold time
of four times the interval, for example 12 and 3, survives a burst of three lost messages.

Antrea only rejects a keepalive interval greater than or equal to the hold time, because such a session can never stay
up. Everything above is guidance rather than a constraint, so a thinner ratio is accepted if your network calls for it.

## Using antctl

Please refer to the corresponding [antctl page](antctl.md#bgp-commands).

## Limitations

- The routes received from remote BGP peers will not be installed. Therefore, you must ensure that the path from Nodes
  to the remote BGP network is properly configured and routable. This involves configuring your network infrastructure
  to handle the routing of traffic between your Kubernetes cluster and the remote BGP network.
- Only Linux Nodes are supported. The feature has not been validated on Windows Nodes, though theoretically it can work
  with Windows Nodes.
- Advanced BGP features such as BGP communities, route filtering, route reflection, confederations, and other BGP policy
  mechanisms defined in BGP RFCs are not supported.
