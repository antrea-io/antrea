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
- [Draining Nodes for maintenance](#draining-nodes-for-maintenance)
- [Example Usage](#example-usage)
  - [Combined Advertisements of Service, Pod, and Egress IPs](#combined-advertisements-of-service-pod-and-egress-ips)
  - [Advertise Egress IPs to external BGP peers with more than one hop](#advertise-egress-ips-to-external-bgp-peers-with-more-than-one-hop)
  - [Advertise Pod IPs through BGP Confederation](#advertise-pod-ips-through-bgp-confederation)
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

## Draining Nodes for maintenance

`kubectl drain` cordons a Node and then evicts its Pods, and throughout that time the Node keeps advertising its Service
IPs to BGP peers, so traffic keeps arriving while the Pods are being torn down. A graceful drain needs the opposite
order: withdraw the Service routes first, then evict, so traffic has already moved elsewhere by the time the Pods stop
serving it.

The optional `spec.drainOnTaints` field on a BGPPolicy gets that order without changing how you drain a Node. It makes
the antrea-agent treat an untolerated Node taint as a signal to withdraw the Node's Service advertisements, while
keeping its BGP sessions established. The following BGPPolicy advertises ClusterIP, ExternalIP, and LoadBalancerIP
Service IPs on Nodes labeled `bgp=enabled`, and tolerates the control-plane taint so that a control-plane Node which
also speaks BGP does not drain on that taint alone:

```yaml
apiVersion: crd.antrea.io/v1alpha1
kind: BGPPolicy
metadata:
  name: advertise-service-ips-with-drain-on-taints
spec:
  nodeSelector:
    matchLabels:
      bgp: enabled
  localASN: 64512
  listenPort: 179
  advertisements:
    service:
      ipTypes: [ClusterIP, ExternalIP, LoadBalancerIP]
  bgpPeers:
    - address: 192.168.77.200
      asn: 65001
      port: 179
  drainOnTaints:
    enabled: true
    tolerations:
      - key: node-role.kubernetes.io/control-plane
        operator: Exists
```

`drainOnTaints` has the following semantics:

- It is off by default. A BGPPolicy without `drainOnTaints` behaves exactly as before, so upgrading Antrea does not
  change anything.
- A Node is draining when it carries a `NoSchedule` or `NoExecute` taint that the BGPPolicy does not tolerate.
  `PreferNoSchedule` taints are ignored.
- Cordoning a Node drains it out of the box. The node lifecycle controller adds the
  `node.kubernetes.io/unschedulable:NoSchedule` taint to every cordoned Node, and that taint alone is enough to
  trigger draining, whether or not a drain follows the cordon.
- `tolerations` uses the same matching rules as Pod tolerations. Tolerate a taint that is permanent on some Nodes,
  such as `node-role.kubernetes.io/control-plane`, or a site-specific taint unrelated to maintenance, and the Node
  keeps advertising through it.
- A draining Node withdraws its Service advertisements only: ClusterIP, ExternalIP, and LoadBalancerIP routes. Pod
  CIDR routes and Egress IP routes are not withdrawn. Other Nodes that still have endpoints for the Service keep
  advertising it, so the fabric converges onto them.
- BGP sessions stay up while a Node drains. Draining changes only the advertised route set. Uncordoning restores the
  advertisements with no session teardown, no re-establishment, and no interaction with graceful restart.
- `enabled` is required inside `drainOnTaints`, so `drainOnTaints: {}` is rejected. Setting `enabled: false` with a
  `tolerations` list is accepted and does nothing, so the feature can be turned off without deleting the list.

With `drainOnTaints` configured, the recommended sequence for maintenance is:

```bash
# 1. Cordon the Node. It withdraws its Service routes but keeps serving existing connections.
kubectl cordon <node>

# 2. Wait for the fabric to converge: one antrea-agent sync plus BGP propagation, typically seconds.
sleep 5

# 3. Evict the Pods. Traffic has already moved to other Nodes.
kubectl drain <node> --ignore-daemonsets

# 4. Perform the maintenance.

# 5. Bring the Node back into service.
kubectl uncordon <node>
```

A bare `kubectl cordon`, with no `kubectl drain` following it, also withdraws the Node's Service routes while its
Pods keep serving traffic locally. This is intended: the cordon taint is what `drainOnTaints` watches for, and the
Node's Pods have not been asked to stop, only new ones have been asked not to schedule there.

Without `drainOnTaints`, an operator can move traffic away before a drain by hand with a label: set a label on the
Node that the BGPPolicy's `nodeSelector` excludes, then cordon and drain. That moves traffic away before eviction
too, but at a higher cost. When a Node stops matching a BGPPolicy, the antrea-agent stops the BGP server on that Node entirely,
tearing down every BGP session on cordon and re-establishing all of them on uncordon, a flap every peer sees.
`drainOnTaints` avoids that: the BGP sessions never go down, only the advertised routes change.

If control-plane Nodes are also BGP speakers, tolerate `node-role.kubernetes.io/control-plane` in `drainOnTaints`.
Many clusters keep that taint on control-plane Nodes permanently, so without the toleration those Nodes would
withdraw their Service routes at all times, not only during maintenance.

Each transition is logged by the antrea-agent, naming the BGPPolicy and, when draining starts, the taint that
caused it. The current state is also visible as a `draining` field in the output of `antctl get bgppolicy -o json`
and `-o yaml`.

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
