# Egress

## Table of Contents

<!-- toc -->
- [What is Egress?](#what-is-egress)
- [Prerequisites](#prerequisites)
- [The Egress resource](#the-egress-resource)
  - [AppliedTo](#appliedto)
  - [EgressIP](#egressip)
  - [ExternalIPPool](#externalippool)
  - [Bandwidth](#bandwidth)
- [The ExternalIPPool resource](#the-externalippool-resource)
  - [IPRanges](#ipranges)
  - [SubnetInfo](#subnetinfo)
  - [NodeSelector](#nodeselector)
- [Usage examples](#usage-examples)
  - [Configuring High-Availability Egress](#configuring-high-availability-egress)
  - [Configuring static Egress](#configuring-static-egress)
- [Configuration options](#configuration-options)
- [Egress on Cloud](#egress-on-cloud)
  - [AWS](#aws)
- [Limitations](#limitations)
<!-- /toc -->

## What is Egress?

`Egress` is a CRD API that manages external access from the Pods in a cluster.
It supports specifying which egress (SNAT) IP the traffic from the selected Pods
to the external network should use. When a selected Pod accesses the external
network, the egress traffic will be tunneled to the Node that hosts the egress
IP if it's different from the Node that the Pod runs on and will be SNATed to
the egress IP when leaving that Node.

You may be interested in using this capability if any of the following apply:

- A consistent IP address is desired when specific Pods connect to services
  outside of the cluster, for source tracing in audit logs, or for filtering
  by source IP in external firewall, etc.

- You want to force outgoing external connections to leave the cluster via
  certain Nodes, for security controls, or due to network topology restrictions.

This guide demonstrates how to configure `Egress` to achieve the above result.

## Prerequisites

Egress was introduced in v1.0 as an alpha feature, and was graduated to beta in
v1.6, at which time it was enabled by default. Prior to v1.6, a feature gate,
`Egress` must be enabled on the antrea-controller and antrea-agent in the
`antrea-config` ConfigMap like the following options for the feature to work:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      Egress: true
  antrea-controller.conf: |
    featureGates:
      Egress: true
```

## The Egress resource

A typical Egress resource example:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: Egress
metadata:
  name: egress-prod-web
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        env: prod
    podSelector:
      matchLabels:
        role: web
  egressIP: 10.10.0.8 # can be populated by Antrea after assigning an IP from the pool below
  externalIPPool: prod-external-ip-pool
status:
  egressNode: node01
```

### AppliedTo

The `appliedTo` field specifies the grouping criteria of Pods to which the
Egress applies to. Pods can be selected cluster-wide using `podSelector`. If set
with a `namespaceSelector`, all Pods from Namespaces selected by the
`namespaceSelector` will be selected. Specific Pods from specific Namespaces can
be selected by providing both a `podSelector` and a `namespaceSelector`. Empty
`appliedTo` selects nothing. The field is mandatory.

### EgressIP

The `egressIP` field specifies the egress (SNAT) IP the traffic from the
selected Pods to the external network should use. **The IP must be reachable
from all Nodes.** The IP can be specified when creating the Egress. Starting
with Antrea v1.2, it can be allocated from an `ExternalIPPool` automatically.

- If `egressIP` is not specified, `externalIPPool` must be specified. An IP will
  be allocated from the pool by the antrea-controller. The IP will be assigned
  to a Node selected by the `nodeSelector` of the `externalIPPool` automatically.
- If both `egressIP` and `externalIPPool` are specified, the IP must be in the
  range of the pool. Similarly, the IP will be assigned to a Node selected by
  the `externalIPPool` automatically.
- If only `egressIP` is specified, Antrea will not manage the assignment of the
  IP and it must be assigned to an arbitrary interface of one Node manually.

**Starting with Antrea v1.2, high availability is provided automatically when
the `egressIP` is allocated from an `externalIPPool`**, i.e. when the
`externalIPPool` is specified. If the Node hosting the `egressIP` fails, another
Node will be elected (from among the remaining Nodes selected by the
`nodeSelector` of the `externalIPPool`) as the new egress Node of this Egress.
It will take over the IP and send layer 2 advertisement (for example, Gratuitous
ARP for IPv4) to notify the other hosts and routers on the network that the MAC
address associated with the IP has changed.

**Note**: If more than one Egress applies to a Pod and they specify different
`egressIP`, the effective egress IP will be selected randomly.

### ExternalIPPool

The `externalIPPool` field specifies the name of the `ExternalIPPool` that the
`egressIP` should be allocated from. It also determines which Nodes the IP can
be assigned to. It can be empty, which means users should assign the `egressIP`
to one Node manually.

### Bandwidth

The `bandwidth` field enables traffic shaping for an Egress, by limiting the
bandwidth for all egress traffic belonging to this Egress. `rate` specifies
the maximum transmission rate. `burst` specifies the maximum burst size when
traffic exceeds the rate. The user-provided values for `rate` and `burst` must
follow the Kubernetes [Quantity](https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/) format,
e.g. 300k, 100M, 2G. All backend workloads selected by a rate-limited Egress share the
same bandwidth while sending egress traffic via this Egress. If these limits are exceeded,
the traffic will be dropped.

**Note**: Traffic shaping is currently in alpha version. To use this feature, users should
enable the `EgressTrafficShaping` feature gate. Each Egress IP can be applied one bandwidth only.
If multiple Egresses use the same IP but configure different bandwidths, the effective
bandwidth will be selected randomly from the set of configured bandwidths. The effective use of the `bandwidth`
function requires the OVS datapath to support meters.

An Egress with traffic shaping example:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: Egress
metadata:
  name: egress-prod-web
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        env: prod
    podSelector:
      matchLabels:
        role: web
  egressIP: 10.10.0.8
  bandwidth:
    rate: 800M
    burst: 2G
status:
  egressNode: node01
```

## The ExternalIPPool resource

ExternalIPPool defines one or multiple IP ranges that can be used in the
external network. The IPs in the pool can be allocated to the Egress resources
as the Egress IPs. A typical ExternalIPPool resource example:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ExternalIPPool
metadata:
  name: prod-external-ip-pool
spec:
  ipRanges:
  - start: 10.10.0.2
    end: 10.10.0.10
  - cidr: 10.10.1.0/28
  nodeSelector:
    matchLabels:
      network-role: egress-gateway
```

### IPRanges

The `ipRanges` field contains a list of IP ranges representing the available IPs
of this IP pool. Each IP range may consist of a `cidr` or a pair of `start` and
`end` IPs (which are themselves included in the range).

### SubnetInfo

By default, it's assumed that the IPs allocated from an ExternalIPPool are in
the same subnet as the Node IPs. Starting with Antrea v1.15, IPs can be
allocated from a subnet different from the Node IPs.

The optional `subnetInfo` field contains the subnet attributes of the IPs in
this pool. When using a different subnet:

* `gateway` and `prefixLength` must be set. Antrea will route Egress traffic to
the specified gateway when the destination is not in the same subnet of the
Egress IP, otherwise route it to the destination directly.

* Optionally, you can specify `vlan` if the underlying network is expecting it.
Once set, Antrea will tag Egress traffic leaving the Egress Node with the
specified VLAN ID. Correspondingly, it's expected that reply traffic towards
these Egress IPs is also tagged with the specified VLAN ID when arriving at the
Egress Node.

An example of ExternalIPPool using a non-default subnet is as below:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ExternalIPPool
metadata:
  name: prod-external-ip-pool
spec:
  ipRanges:
  - start: 10.10.0.2
    end: 10.10.0.10
  subnetInfo:
    gateway: 10.10.0.1
    prefixLength: 24
    vlan: 10
  nodeSelector:
    matchLabels:
      network-role: egress-gateway
```

**Note**: Specifying different subnets is currently in alpha version. To use
this feature, users should enable the `EgressSeparateSubnet` feature gate.
Currently, the maximum number of different subnets that can be supported in a
cluster is 20, which should be sufficient for most cases. If you need to have
more subnets, please raise an issue with your use case, and we will consider
revising the limit based on that.

### NodeSelector

The `nodeSelector` field specifies which Nodes the IPs in this pool can be
assigned to. It's useful when you want to limit egress traffic to certain Nodes.
The semantics of the selector is the same as those used elsewhere in Kubernetes,
i.e. both `matchLabels` and `matchExpressions` are supported. It can be empty,
which means all Nodes can be selected.

## Usage examples

### Configuring High-Availability Egress

In this example, we will make web apps in different namespaces use different
egress IPs to access the external network.

First, create an `ExternalIPPool` with a list of external routable IPs on the
network.

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ExternalIPPool
metadata:
  name: external-ip-pool
spec:
  ipRanges:
  - start: 10.10.0.11  # 10.10.0.11-10.10.0.20 can be used as Egress IPs
    end: 10.10.0.20
  nodeSelector: {}     # All Nodes can be Egress Nodes
```

Then create two `Egress` resources, each of which applies to web apps in one
Namespace.

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: Egress
metadata:
  name: egress-prod-web
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: prod
    podSelector:
      matchLabels:
        app: web
  externalIPPool: external-ip-pool
---
apiVersion: crd.antrea.io/v1beta1
kind: Egress
metadata:
  name: egress-staging-web
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: staging
    podSelector:
      matchLabels:
        app: web
  externalIPPool: external-ip-pool
```

List the `Egress` resource with kubectl. The output shows each Egress gets one
IP from the IP pool and gets one Node assigned as its Egress Node.

```yaml
# kubectl get egress
NAME                 EGRESSIP       AGE   NODE
egress-prod-web      10.10.0.11     1m    node-4
egress-staging-web   10.10.0.12     1m    node-6
```

Now, the packets from the Pods with label `app=web` in the `prod` Namespace to
the external network will be redirected to the `node-4` Node and SNATed to
`10.10.0.11` while the packets from the Pods with label `app=web` in the
`staging` Namespace to the external network will be redirected to the `node-6`
Node and SNATed to `10.10.0.12`.

Finally, if the `node-4` Node powers off, `10.10.0.11` will be re-assigned to
another available Node quickly, and the packets from the Pods with label
`app=web` in the `prod` Namespace will be redirected to the new Node, minimizing
egress connection disruption without manual intervention.

### Configuring static Egress

In this example, we will make Pods in different namespaces use specific Node IPs
(or any IPs that are configured to the interfaces of the Nodes) to access the
external network.

Since the Egress IPs have been configured to the Nodes, we can create `Egress`
resources with specific IPs directly.

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: Egress
metadata:
  name: egress-prod
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: prod
  egressIP: 10.10.0.104   # node-4's IP
---
apiVersion: crd.antrea.io/v1beta1
kind: Egress
metadata:
  name: egress-staging
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: staging
  egressIP: 10.10.0.105   # node-5's IP
```

List the `Egress` resource with kubectl. The output shows `10.10.0.104` is
discovered on `node-4` Node while `10.10.0.105` is discovered on `node-5`.

```yaml
# kubectl get egress
NAME                 EGRESSIP       AGE   NODE
egress-prod          10.10.0.104    1m    node-4
egress-staging       10.10.0.105    1m    node-5
```

Now, the packets from the Pods with in the `prod` Namespace to the external
network will be redirected to the `node-4` Node and SNATed to `10.10.0.104`
while the packets from the Pods in the `staging` Namespace to the external
network will be redirected to the `node-5` Node and SNATed to `10.10.0.105`.

In this configuration, if the `node-4` Node powers off, re-configuring
`10.10.0.104` to another Node or updating the `egressIP` of `egress-prod` to
another Node's IP can recover the egress connection. Antrea will detect the
configuration change and redirect the packets from the Pods in the `prod`
Namespace to the new Node.

## Configuration options

There are several options that can be configured for Egress according to your
case.

- `egress.exceptCIDRs` - The CIDR ranges to which outbound Pod traffic will not
  be SNAT'd by Egresses. The option was added in Antrea v1.4.0.
- `egress.maxEgressIPsPerNode` - The maximum number of Egress IPs that can be
  assigned to a Node. It's useful when the Node network restricts the number of
  secondary IPs a Node can have, e.g. in AWS EC2. The configured value must not
  be greater than 255. The restriction applies to all Nodes in the cluster. If
  you want to set different capacities for Nodes, the
  `node.antrea.io/max-egress-ips` annotation of Node objects can be used to
  specify different values for different Nodes, taking priority over the value
  configured in the config file. The option and the annotation were added in
  Antrea v1.11.0.

## Egress on Cloud

High-Availability Egress requires the Egress IPs to be able to float across
Nodes. When assigning an Egress IP to a Node, Antrea assumes the responsibility
of advertising the Egress IPs to the Node network via the ARP or NDP protocols.
However, cloud networks usually apply SpoofGuard which prevents the Nodes from
using any IP that is not configured for them in the cloud's control plane, or
even don't support multicast and broadcast. These restrictions lead to
High-Availability Egress not being as readily available on some clouds as it is
on on-premise networks, and some custom (i.e., cloud-specific) work is required
in the cloud's control plane to assign the Egress IP as secondary Node IPs.

### AWS

In Amazon VPC, ARP packets never hit the network, and traffic with Egress IP as
source IP or destination IP isn't transmitted arbitrarily unless they are
explicitly authorized (check [AWS VPC Whitepaper](https://docs.aws.amazon.com/whitepapers/latest/logical-separation/vpc-and-accompanying-features.html)
for more information). To authorize an Egress IP, it must be configured as the
secondary IP of the primary network interface of the Egress Node instance. You
can refer to the [AWS doc](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/MultipleIP.html#assignIP-existing)
to assign a secondary IP to a network interface.

If you are using static Egress and managing the assignment of Egress IPs
yourself: you should ensure the Egress IP is assigned as one of the IP
addresses of the primary network interface of the Egress Node instance via
Amazon EC2 console or AWS CLI.

If you are using High-Availability Egress and let Antrea manage the assignment
of Egress IPs: at the moment Antrea can only assign the Egress IP to an Egress
Node at the operating system level (i.e., add the IP to the interface), and you
still need to ensure the Egress IP is assigned to the Node instance via Amazon
EC2 console or AWS CLI. To automate it, you can build a Kubernetes Operator
which watches the Egress API, gets the Egress IP and the Egress Node from the
status fields, and configures the Egress IP as the secondary IP of the primary
network interface of the Egress Node instance via the
[AssignPrivateIpAddresses](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AssignPrivateIpAddresses.html)
API.

## Limitations

This feature is currently only supported for Nodes running Linux and "encap"
mode. The support for Windows and other traffic modes will be added in the
future.

The previous implementation of Antrea Egress before Antrea v1.7.0 does not work
with the `strictARP` configuration of `kube-proxy` IPVS mode. The `strictARP`
configuration is required by some Service load balancing solutions including:
[Antrea Service external IP management, MetalLB](service-loadbalancer.md#interoperability-with-kube-proxy-ipvs-mode),
and kube-vip. It means Antrea Egress cannot work together with these solutions
in a cluster using `kube-proxy` IPVS. The issue was fixed in Antrea v1.7.0.
