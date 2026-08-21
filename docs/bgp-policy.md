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
    - [MED](#med)
  - [BGPPeers](#bgppeers)
- [BGP router ID](#bgp-router-id)
- [BGP Authentication](#bgp-authentication)
- [Example Usage](#example-usage)
  - [Combined Advertisements of Service, Pod, and Egress IPs](#combined-advertisements-of-service-pod-and-egress-ips)
  - [Advertise Egress IPs to external BGP peers with more than one hop](#advertise-egress-ips-to-external-bgp-peers-with-more-than-one-hop)
  - [Advertise Pod IPs through BGP Confederation](#advertise-pod-ips-through-bgp-confederation)
  - [Multi-Node ingress for an ExternalIPPool with MED](#multi-node-ingress-for-an-externalippool-with-med)
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
  - The `med` field configures the MULTI_EXIT_DISC attribute attached to the advertised Service IP routes. See
    [MED](#med).

#### MED

The `advertisements.service.med` field attaches a MULTI_EXIT_DISC (MED) attribute to the advertised Service IP routes.
MED is the BGP attribute a BGP speaker uses to tell its peers which of several paths to the same destination it would
prefer them to use: **the lower the MED, the more preferred the path**. When the field is unset, no MED attribute is
attached, which is the behavior of Antrea versions without MED support.

| Field                  | Default | Description                                                                                                                                   |
|------------------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `mode`                 | `None`  | `None`, `Static` or `NodePriority`. See below.                                                                                                |
| `baseValue`            | `100`   | The MED of the most preferred path, in the range [0, 4294967295]. A value of `0` disables the attribute.                                       |
| `step`                 | `100`   | The MED increment applied per Node rank in the `NodePriority` mode.                                                                            |
| `maxAdvertisingNodes`  | `0`     | How many Nodes of an ExternalIPPool advertise each of its IPs in the `NodePriority` mode. `0` means all of them.                               |
| `allowServiceOverride` | `true`  | Whether the `service.antrea.io/bgp-med` and `service.antrea.io/bgp-med-mode` Service annotations are honored.                                  |

The three modes are:

- `None`: no MED attribute is attached. This is the default.
- `Static`: every Node attaches `baseValue` to every advertised Service IP route. This is useful to make the routes
  advertised by Antrea uniformly more or less preferred than the routes for the same destinations advertised by another
  BGP speaker.
- `NodePriority`: **multi-Node ingress**. Every Node of an ExternalIPPool advertises each LoadBalancer IP allocated from
  that pool, with a distinct MED per Node: `baseValue + rank * step`, where `rank` is the position of the Node in the
  same consistent hash ring which the `ServiceExternalIP` feature uses to elect the owner of the IP. The owner therefore
  advertises the most preferred path, and the other Nodes advertise backup paths.

The `NodePriority` mode gives two properties which a single-Node advertisement cannot:

- **Ingress traffic is spread across Nodes.** Different IPs of the same ExternalIPPool hash to different Nodes, so each
  Node is the most preferred path for a different subset of the pool.
- **Failover does not wait for a re-advertisement.** The BGP peers already hold the backup paths in their RIB, so when
  the owner of an IP withdraws its path (because the Node went down, or because the IP was reassigned), the peers switch
  to the next path immediately, instead of waiting for the new owner to advertise it.

Notes and constraints for the `NodePriority` mode:

- It only ranks the LoadBalancer IPs of the Services which carry the `service.antrea.io/external-ip-pool` annotation,
  which requires the `ServiceExternalIP` feature gate. The Service IPs which do not come from an ExternalIPPool cannot
  be ranked and are advertised with `baseValue`, exactly as in the `Static` mode.
- A Node which is not a member of the ExternalIPPool (i.e. does not match its `nodeSelector`), or which is ranked beyond
  `maxAdvertisingNodes`, does not advertise the IP at all.
- With `externalTrafficPolicy: Local`, the Nodes without a local Endpoint are excluded from the ranking, exactly as they
  are excluded from the election of the owner of the IP, and they do not advertise the IP.
- Because the Nodes which do not own an IP also advertise it, they must be able to serve its traffic. With
  `externalTrafficPolicy: Cluster` they always can, but a Node without a local Endpoint SNATs the traffic, so the
  backend Pods see the Node IP instead of the client IP. To preserve the client IP, enable the `LoadBalancerModeDSR`
  feature gate and set the `service.antrea.io/load-balancer-mode: dsr` annotation on the Service (or set
  `antreaProxy.defaultLoadBalancerMode: DSR` in the agent configuration). antrea-agent logs a warning when the
  `NodePriority` mode is used for a Service which uses neither DSR nor `externalTrafficPolicy: Local`.
- The ranking is derived from each Agent's own view of the memberlist cluster. While that view is converging, e.g. right
  after a Node fails, two Nodes may briefly advertise the same MED for one IP. This resolves on its own, and the peers
  simply ECMP or tie-break between the two paths in the meantime.
- Every Node of the ExternalIPPool contributes one path per IP to the BGP peers. On a pool with many Nodes, set
  `maxAdvertisingNodes` to bound the number of paths the peers have to hold (two or three backups are enough for
  failover), which also bounds the work each Agent does to rank the Nodes.

A Service can override the BGPPolicy configuration with two annotations, unless `allowServiceOverride` is set to
`false`:

- `service.antrea.io/bgp-med`: overrides `baseValue` for this Service, in the range [0, 4294967295]. In the
  `NodePriority` mode this shifts the whole ladder, which is how one Service is made more preferred than another over
  the same set of Nodes.
- `service.antrea.io/bgp-med-mode`: overrides `mode` for this Service, i.e. opts a single Service in or out of the MED
  behavior.

The annotations are only honored once `advertisements.service.med` is set in the BGPPolicy: MED stays opt-in at the
cluster level, so annotating a Service in a cluster whose BGPPolicy does not mention MED changes nothing. An invalid
annotation value is logged and ignored, leaving the BGPPolicy configuration in effect.

### BGPPeers

The `bgpPeers` field lists the BGP peers to which the advertisements are sent.

- `address`: The IP address of the BGP peer.
- `asn`: The Autonomous System Number of the BGP peer.
- `port`: The port number on which the BGP peer listens. The default value is 179.
- `multihopTTL`: The Time To Live (TTL) value used in BGP packets sent to the BGP peer, with a range of 1 to 255.
  The default value is 1.
- `gracefulRestartTimeSeconds`: Specifies how long the BGP peer waits for the BGP session to re-establish after a
  restart before deleting stale routes, with a range of 1 to 3600 seconds. The default value is 120 seconds.

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

### Multi-Node ingress for an ExternalIPPool with MED

This example spreads the ingress traffic for a pool of LoadBalancer IPs across every worker Node, while keeping a
deterministic, immediately failover-able primary Node per IP.

First, define the pool of external IPs and the Nodes that can serve them:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ExternalIPPool
metadata:
  name: service-external-ip-pool
spec:
  ipRanges:
    - start: 10.10.0.2
      end: 10.10.0.20
  nodeSelector:
    matchLabels:
      network-role: ingress
```

Then advertise the pool IPs from every Node of the pool, with one MED per Node:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: BGPPolicy
metadata:
  name: multi-node-ingress
spec:
  nodeSelector:
    matchLabels:
      network-role: ingress
  localASN: 64512
  advertisements:
    service:
      ipTypes:
        - LoadBalancerIP
      med:
        mode: NodePriority
        baseValue: 100
        step: 100
        # Hold at most 3 paths per IP in the upstream routers.
        maxAdvertisingNodes: 3
  bgpPeers:
    - address: 192.168.77.200
      asn: 65001
```

Finally, request an IP from the pool for a Service, and use DSR so that the Nodes which do not host a backend Pod still
preserve the client IP:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: web
  annotations:
    service.antrea.io/external-ip-pool: service-external-ip-pool
    service.antrea.io/load-balancer-mode: dsr
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 8080
```

With three Nodes in the pool, each of them advertises the IP, and `antctl get bgproutes` reports the MED that the local
Node uses. On the Node which owns the IP:

```bash
$ antctl get bgproutes
ROUTE          TYPE                   MED  K8S-OBJ-REF
10.10.0.2/32   ServiceLoadBalancerIP  100  default/web
```

On the two other Nodes, the same route is advertised with `200` and `300` respectively, so the upstream router forwards
the traffic to the owner and falls back to the other two, in order, if it goes away. A second Service allocated
`10.10.0.3` from the same pool most likely hashes to a different Node, which is what spreads the ingress load.

To make one Service more preferred as a whole, e.g. to pin it to a specific set of Nodes ahead of the others, set its
base value explicitly:

```yaml
metadata:
  annotations:
    service.antrea.io/external-ip-pool: service-external-ip-pool
    service.antrea.io/bgp-med: "50"
```

## Using antctl

Please refer to the corresponding [antctl page](antctl.md#bgp-commands).

## Limitations

- The routes received from remote BGP peers will not be installed. Therefore, you must ensure that the path from Nodes
  to the remote BGP network is properly configured and routable. This involves configuring your network infrastructure
  to handle the routing of traffic between your Kubernetes cluster and the remote BGP network.
- Only Linux Nodes are supported. The feature has not been validated on Windows Nodes, though theoretically it can work
  with Windows Nodes.
- Advanced BGP features such as BGP communities, route filtering, route reflection, and other BGP policy mechanisms
  defined in BGP RFCs are not supported. The only path attribute that can be configured is MULTI_EXIT_DISC, and only
  for Service IP advertisements: Pod CIDR and Egress IP routes are always advertised without a MED attribute.
