# Traffic Control With Antrea

## Table of Contents

<!-- toc -->
- [What is TrafficControl?](#what-is-trafficcontrol)
- [Prerequisites](#prerequisites)
- [The TrafficControl resource](#the-trafficcontrol-resource)
  - [AppliedTo](#appliedto)
  - [Direction](#direction)
  - [Action](#action)
  - [TargetPort](#targetport)
  - [ReturnPort](#returnport)
- [Examples](#examples)
  - [Mirroring all traffic to remote analyzer](#mirroring-all-traffic-to-remote-analyzer)
  - [Redirecting specific traffic to local receiver](#redirecting-specific-traffic-to-local-receiver)
- [What's next](#whats-next)
<!-- /toc -->

## What is TrafficControl?

`TrafficControl` is a CRD API that manages and manipulates the transmission of
Pod traffic. It allows users to mirror or redirect specific traffic originating
from specific Pods or destined for specific Pods to a local network device or a
remote destination via a tunnel of various types. It provides full visibility
into network traffic, including both north-south and east-west traffic.

You may be interested in using this capability if any of the following apply:

- You want to monitor network traffic passing in or out of a set of Pods for
  purposes such as troubleshooting, intrusion detection, and so on.

- You want to redirect network traffic passing in or out of a set of Pods to
  applications that enforce policies, and reject traffic to prevent intrusion.

This guide demonstrates how to configure `TrafficControl` to achieve the above
goals.

## Prerequisites

TrafficControl was introduced in v1.7 as an alpha feature. A feature gate,
`TrafficControl` must be enabled on the antrea-agent in the `antrea-config`
ConfigMap for the feature to work, like the following:

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      TrafficControl: true
```

## The TrafficControl resource

A TrafficControl in Kubernetes is a REST object. Like all the REST objects, you
can POST a TrafficControl definition to the API server to create a new instance.
For example, supposing you have a set of Pods which contain a label `app=web`,
the following specification creates a new TrafficControl object named
"mirror-web-app", which mirrors all traffic from or to any Pod with the
`app=web` label and send them to a receiver running on "10.0.10.2" encapsulated
within a VXLAN tunnel:

```yaml
apiVersion: crd.antrea.io/v1alpha2
kind: TrafficControl
metadata:
  name: mirror-web-app
spec:
  appliedTo:
    podSelector:
      matchLabels:
        app: web
  direction: Both
  action: Mirror
  targetPort:
    vxlan:
      remoteIP: 10.0.10.2
```

### AppliedTo

The `appliedTo` field specifies the grouping criteria of Pods to which the
TrafficControl applies to. Pods can be selected cluster-wide using
`podSelector`. If set with a `namespaceSelector`, all Pods from Namespaces
selected by the `namespaceSelector` will be selected. Specific Pods from
specific Namespaces can be selected by providing both a `podSelector` and a
`namespaceSelector`. Empty `appliedTo` selects nothing. The field is mandatory.

### Direction

The `direction` field specifies the direction of traffic that should be matched.
It can be `Ingress`, `Egress`, or `Both`.

### Action

The `action` field specifies which action should be taken for the traffic. It
can be `Mirror` or `Redirect`. For the `Mirror` action, `targetPort` must be
set to the port to which the traffic will be mirrored. For the `Redirect`
action, both `targetPort` and `returnPort` need to be specified, the latter of
which represents the port from which the traffic could be sent back to OVS and
be forwarded to its original destination. Once redirected, a packet should be
either dropped or sent back to OVS without modification, otherwise it would lead
to undefined behavior.

### TargetPort

The `targetPort` field specifies the port to which the traffic should be
redirected or mirrored. There are five kinds of ports that can be used to
receive mirrored traffic:

**ovsInternal**: This specifies an OVS internal port on all Nodes. A Pod's
traffic will be redirected or mirrored to the OVS internal port on the same Node
that hosts the Pod. The port doesn't need to exist in advance, Antrea will
create the port if it doesn't exist. To use an OVS internal port, the `name` of
the port must be provided:

```yaml
ovsInternal:
  name: tap0
```

**device**: This specifies a network device on all Nodes. A Pod's traffic will
be redirected or mirrored to the network device on the same Node that hosts the
Pod. The network device must exist on all Nodes and Antrea will attach it to the
OVS bridge if not already attached. To use a network device, the `name` of the
device must be provided:

```yaml
device:
  name: eno2
```

**geneve**: This specifies a remote destination for a GENEVE tunnel. All
selected Pods' traffic will be redirected or mirrored to the destination via
a GENEVE tunnel. The `remoteIP` field must be provided to specify the IP address
of the destination. Optionally, the `destinationPort` field could be used to
specify the UDP destination port of the tunnel, or 6081 will be used by default.
If Virtual Network Identifier (VNI) is desired, the `vni` field can be specified
to an integer in the range 0-16,777,215:

```yaml
geneve:
  remoteIP: 10.0.10.2
  destinationPort: 6081
  vni: 1
```

**vxlan**: This specifies a remote destination for a VXLAN tunnel. All
selected Pods' traffic will be redirected or mirrored to the destination via
a VXLAN tunnel. The `remoteIP` field must be provided to specify the IP address
of the destination. Optionally, the `destinationPort` field could be used to
specify the UDP destination port of the tunnel, or 4789 will be used by default.
If Virtual Network Identifier (VNI) is desired, the `vni` field can be specified
to an integer in the range 0-16,777,215:

```yaml
vxlan:
  remoteIP: 10.0.10.2
  destinationPort: 4789
  vni: 1
```

**gre**: This specifies a remote destination for a GRE tunnel. All selected
Pods' traffic will be redirected or mirrored to the destination via a GRE
tunnel. The `remoteIP` field must be provided to specify the IP address of the
destination. If GRE key is desired, the `key` field can be specified to an
integer in the range 0-4,294,967,295:

```yaml
gre:
  remoteIP: 10.0.10.2
  key: 1
```

**erspan**: This specifies a remote destination for an ERSPAN tunnel. All
selected Pods' traffic will be mirrored to the destination via an ERSPAN tunnel.
The `remoteIP` field must be provided to specify the IP address of the
destination. If ERSPAN session ID is desired, the `sessionID` field can be
specified to an integer in the range 0-1,023. The `version` field must be
provided to specify the ERSPAN version: 1 for version 1 (type II), or 2 for
version 2 (type III).

For version 1, the `index` field can be specified to associate with the ERSPAN
traffic's source port and direction. An example of version 1 might look like
this:

```yaml
erspan:
  remoteIP: 10.0.10.2
  sessionID: 1
  version: 1
  index: 1
```

For version 2, the `dir` field can be specified to indicate the mirrored
traffic's direction: 0 for ingress traffic, 1 for egress traffic. The
`hardwareID` field can be specified as an unique identifier of an ERSPAN v2
engine. An example of version 2 might look like this:

```yaml
erspan:
  remoteIP: 10.0.10.2
  sessionID: 1
  version: 2
  dir: 0
  hardwareID: 4
```

### ReturnPort

The `returnPort` field should only be set when the `action` is `Redirect`. It is
similar to the `targetPort` field, but meant for specifying the port from which
the traffic will be sent back to OVS and be forwarded to its original
destination.

## Examples

### Mirroring all traffic to remote analyzer

In this example, we will mirror all Pods' traffic and send them to a remote
destination via a GENEVE tunnel:

```yaml
apiVersion: crd.antrea.io/v1alpha2
kind: TrafficControl
metadata:
  name: mirror-all-to-remote
spec:
  appliedTo:
    podSelector: {}
  direction: Both
  action: Mirror
  targetPort:
    geneve:
      remoteIP: 10.0.10.2
```

### Redirecting specific traffic to local receiver

In this example, we will redirect traffic of all Pods in the Namespace `prod` to
OVS internal ports named `tap0` configured on Nodes that these Pods run on.
The `returnPort` configuration means, if the traffic is sent back to OVS from
OVS internal ports named `tap1`, it will be forwarded to its original
destination. Therefore, if an intrusion prevention system or a network firewall
is configured to capture and forward traffic between `tap0` and `tap1`, it can
actively scan forwarded network traffic for malicious activities and known
attack patterns, and drop the traffic determined to be malicious.

```yaml
apiVersion: crd.antrea.io/v1alpha2
kind: TrafficControl
metadata:
  name: redirect-prod-to-local
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: prod
  direction: Both
  action: Redirect
  targetPort:
    ovsInternal:
      name: tap0
  returnPort:
    ovsInternal:
      name: tap1
```

## What's next

With the `TrafficControl` capability, Antrea can be used with threat detection
engines to provide network-based IDS/IPS to Pods. We provide a reference
cookbook on how to implement IDS using Suricata. For more information, refer to
the [cookbook](cookbooks/ids).
