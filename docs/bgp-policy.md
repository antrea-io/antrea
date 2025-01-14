# BGPPolicy

## Table of Contents

<!-- toc -->
- [What is BGPPolicy?](#what-is-bgppolicy)
- [Prerequisites](#prerequisites)
- [The BGPPolicy resource](#the-bgppolicy-resource)
  - [NodeSelector](#nodeselector)
  - [LocalASN](#localasn)
  - [ListenPort](#listenport)
  - [Advertisements](#advertisements)
  - [BGPPeers](#bgppeers)
- [BGP router ID](#bgp-router-id)
- [BGP Authentication](#bgp-authentication)
- [Example Usage](#example-usage)
  - [Combined Advertisements of Service, Pod, and Egress IPs](#combined-advertisements-of-service-pod-and-egress-ips)
  - [Advertise Egress IPs to external BGP peers with more than one hop](#advertise-egress-ips-to-external-bgp-peers-with-more-than-one-hop)
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
