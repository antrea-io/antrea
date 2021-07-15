# Egress

## Table of Contents

- [What is Egress?](#what-is-egress)
- [Prerequisites](#prerequisites)
- [The Egress resource](#the-egress-resource)
  - [AppliedTo](#appliedto)
  - [EgressIP](#egressip)
  - [ExternalIPPool](#externalippool)
- [The ExternalIPPool resource](#the-externalippool-resource)
  - [IPRanges](#ipranges)
  - [NodeSelector](#nodeselector)
- [Usage examples](#usage-examples)
  - [Configuring High-Availability Egress](#configuring-high-availability-egress)
  - [Configuring static Egress](#configuring-static-egress)
- [Limitations](#limitations)

## What is Egress?

`Egress` is a CRD API that manages external access from the Pods in a cluster.
It supports specifying which egress (SNAT) IP the traffic from the selected Pods
to the external network should use. When a selected Pod accesses the external
network, the egress traffic will be tunneled to the Node that hosts the egress
IP if it's different from the Node that the Pod runs on and will be SNATed to
the egress IP when leaving that Node.

You may be interested in using this capability if any of the following apply:

- A consistent IP address is desired when specific Pods connect to services
  outside of the cluster, for source tracing in audit logs, or whitelisting
  by source IP in external firewall, etc.

- You want to force outgoing external connections to leave the cluster via
  certain Nodes, for security controls, or due to network topology restrictions.

This guide demonstrates how to configure `Egress` to achieve the above result.

## Prerequisites

Egress is introduced in v1.0 as an alpha feature. As with other alpha features,
a feature gate `Egress` must be enabled on the antrea-controller and
antrea-agent for the feature to work. The following options in the
`antrea-config` ConfigMap need to be set:

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: antrea-config-dcfb6k2hkm
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
apiVersion: crd.antrea.io/v1alpha2
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

## The ExternalIPPool resource

ExternalIPPool defines one or multiple IP ranges that can be used in the
external network. The IPs in the pool can be allocated to the Egress resources
as the Egress IPs. A typical ExternalIPPool resource example:

```yaml
- apiVersion: crd.antrea.io/v1alpha2
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
- apiVersion: crd.antrea.io/v1alpha2
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
apiVersion: crd.antrea.io/v1alpha2
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
apiVersion: crd.antrea.io/v1alpha2
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
apiVersion: crd.antrea.io/v1alpha2
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
apiVersion: crd.antrea.io/v1alpha2
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
network will be redirected to the `node-5` Node and SNATed to `10.10.0.12`.

In this configuration, if the `node-4` Node powers off, re-configuring
`10.10.0.104` to another Node or updating the `egressIP` of `egress-prod` to
another Node's IP can recover the egress connection. Antrea will detect the
configuration change and redirect the packets from the Pods in the `prod`
Namespace to the new Node.

## Limitations

This feature is currently only supported for Nodes running Linux and "encap"
mode. The support for Windows and other traffic modes will be added in the
future.
