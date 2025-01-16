# Antrea OVS Pipeline

## Table of Contents

<!-- toc -->
- [Introduction](#introduction)
- [Terminology](#terminology)
- [Dumping the Flows / Groups](#dumping-the-flows--groups)
- [OVS Registers and Conntrack](#ovs-registers-and-conntrack)
  - [OVS Registers](#ovs-registers)
  - [OVS Ct Mark](#ovs-ct-mark)
  - [OVS Ct Label](#ovs-ct-label)
  - [OVS Ct Zone](#ovs-ct-zone)
- [Antrea Features](#antrea-features)
  - [Kubernetes NetworkPolicy Implementation](#kubernetes-networkpolicy-implementation)
  - [Kubernetes Service Implementation](#kubernetes-service-implementation)
  - [Antrea-native NetworkPolicy Implementation](#antrea-native-networkpolicy-implementation)
  - [Antrea-native L7 NetworkPolicy Implementation](#antrea-native-l7-networkpolicy-implementation)
  - [TrafficControl Implementation](#trafficcontrol-implementation)
  - [Egress Implementation](#egress-implementation)
- [OVS Tables](#ovs-tables)
  - [PipelineRootClassifier](#pipelinerootclassifier)
  - [ARPSpoofGuard](#arpspoofguard)
  - [ARPResponder](#arpresponder)
  - [Classifier](#classifier)
  - [SpoofGuard](#spoofguard)
  - [UnSNAT](#unsnat)
  - [ConntrackZone](#conntrackzone)
  - [ConntrackState](#conntrackstate)
  - [PreRoutingClassifier](#preroutingclassifier)
  - [NodePortMark](#nodeportmark)
  - [SessionAffinity](#sessionaffinity)
  - [ServiceLB](#servicelb)
  - [EndpointDNAT](#endpointdnat)
  - [AntreaPolicyEgressRule](#antreapolicyegressrule)
  - [EgressRule](#egressrule)
  - [EgressDefaultRule](#egressdefaultrule)
  - [EgressMetric](#egressmetric)
  - [L3Forwarding](#l3forwarding)
  - [EgressMark](#egressmark)
  - [L3DecTTL](#l3decttl)
  - [SNATMark](#snatmark)
  - [SNAT](#snat)
  - [L2ForwardingCalc](#l2forwardingcalc)
  - [TrafficControl](#trafficcontrol)
  - [IngressSecurityClassifier](#ingresssecurityclassifier)
  - [AntreaPolicyIngressRule](#antreapolicyingressrule)
  - [IngressRule](#ingressrule)
  - [IngressDefaultRule](#ingressdefaultrule)
  - [IngressMetric](#ingressmetric)
  - [ConntrackCommit](#conntrackcommit)
  - [Output](#output)
<!-- toc -->

## Introduction

This document outlines the Open vSwitch (OVS) pipeline Antrea uses to implement its networking functionalities. The
following assumptions are currently in place:

- Antrea is deployed in encap mode, establishing an overlay network across all Nodes.
- All the Nodes are Linux Nodes.
- IPv6 is disabled.
- Option `antreaProxy.proxyAll` (referred to as `proxyAll` later in this document) is enabled.
- Two Alpha features `TrafficControl` and `L7NetworkPolicy` are enabled.
- Default settings are maintained for other features and options.

The document references version v1.15 of Antrea.

## Terminology

### Antrea / Kubernetes

- *Node Route Controller*: the [Kubernetes controller](https://kubernetes.io/docs/concepts/architecture/controller/)
  which is a part of antrea-agent and watches for updates to Nodes. When a Node is added, it updates the local
  networking configurations (e.g. configure the tunnel to the new Node). When a Node is deleted, it performs the
  necessary clean-ups.
- *peer Node*: this is how we refer to other Nodes in the cluster, to which the local Node is connected through a Geneve,
  VXLAN, GRE, or STT tunnel.
- *Antrea-native NetworkPolicy*: Antrea ClusterNetworkPolicy and Antrea NetworkPolicy CRDs, as documented
  [here](../antrea-network-policy.md).
- *Service session affinity*: a Service attribute that selects the same backend Pods for connections from a particular
  client. For a K8s Service, session affinity can be enabled by setting `service.spec.sessionAffinity` to `ClientIP`
  (default is `None`). See [Kubernetes Service](https://kubernetes.io/docs/concepts/services-networking/service/) for
  more information about session affinity.

### OpenFlow

- *table-miss flow*: a "catch-all" flow in an OpenFlow table, which is used if no other flow is matched. If the table-miss
  flow does not exist, by default packets unmatched by flows are dropped (discarded).
- *action `conjunction`*: an efficient way in OVS to implement conjunctive matches, is a match for which multiple fields
  are required to match conjunctively, each within a set of acceptable values. See [OVS
  fields](http://www.openvswitch.org/support/dist-docs/ovs-fields.7.txt) for more information.
- *action `normal`*: OpenFlow defines this action to submit a packet to "the traditional non-OpenFlow pipeline of
  the switch". In other words, if a flow uses this action, the packets matched by the flow traverse the switch in
  the same manner as they would if OpenFlow were not configured on the switch. Antrea uses this action to process
  ARP packets as a regular learning L2 switch would.
- *action `group`*: an action used to process forwarding decisions on multiple OVS ports. Examples include:
  load-balancing, multicast, and active/standby. See [OVS group
  action](https://docs.openvswitch.org/en/latest/ref/ovs-actions.7/#the-group-action) for more information.
- *action `IN_PORT`*: an action to output packets to the port on which they were received. This is the only standard way
  to output the packets to the input port.
- *action `ct`*: an action to commit connections to the connection tracking module, which OVS can use to match
  the state of a TCP, UDP, ICMP, etc., connection. See the [OVS Conntrack
  tutorial](https://docs.openvswitch.org/en/latest/tutorials/ovs-conntrack/) for more information.
- *reg mark*: a value stored in an OVS register conveying information for a packet across the pipeline. Explore all reg
  marks in the pipeline in the [OVS Registers] section.
- *ct mark*: a value stored in the field `ct_mark` of OVS conntrack, conveying information for a connection throughout
  its entire lifecycle across the pipeline. Explore all values used in the pipeline in the [Ct Marks] section.
- *ct label*: a value stored in the field `ct_label` of OVS conntrack, conveying information for a connection throughout
  its entire lifecycle across the pipeline. Explore all values used in the pipeline in the [Ct Labels] section.
- *ct zone*: a zone is to isolate connection tracking rules stored in the field `ct_zone` of OVS conntrack. It is
  conceptually similar to the more generic Linux network namespace but is specific to conntrack and has less
  overhead. Explore all the zones used in the pipeline in the [Ct Zones] section.

### Misc

- *dmac table*: a traditional L2 switch has a "dmac" table that maps the learned destination MAC address to the appropriate
  egress port. It is often the same physical table as the "smac" table (which matches the source MAC address and
  initiates MAC learning if the address is unknown).
- *Global Virtual MAC*: a virtual MAC address that is used as the destination MAC for all tunneled traffic across all
  Nodes. This simplifies networking by enabling all Nodes to use this MAC address instead of the actual MAC address of
  the appropriate remote gateway. This allows each OVS to act as a "proxy" for the local gateway when receiving
  tunneled traffic and directly take care of the packet forwarding. Currently, we use a hard-coded value of
  `aa:bb:cc:dd:ee:ff`.
- *Virtual Service IP*: a virtual IP address used as the source IP address for hairpin Service connections through the
  Antrea gateway port. Currently, we use a hard-coded value of `169.254.0.253`.
- *Virtual NodePort DNAT IP*: a virtual IP address used as a DNAT IP address for NodePort Service connections through
  Antrea gateway port. Currently, we use a hard-coded value of `169.254.0.252`.

## Dumping the Flows / Groups

This guide includes a representative flow dump for every table in the pipeline, to illustrate the function of each
table. If you have a cluster running Antrea, you can dump the flows or groups on a given Node as follows:

```bash
# Dump all flows.
kubectl exec -n kube-system <ANTREA_AGENT_POD_NAME> -c antrea-ovs -- ovs-ofctl dump-flows <BRIDGE_NAME> -O Openflow15 [--no-stats] [--names]

# Dump all groups.
kubectl exec -n kube-system <ANTREA_AGENT_POD_NAME> -c antrea-ovs -- ovs-ofctl dump-groups <BRIDGE_NAME> -O Openflow15 [--names]
```

where `<ANTREA_AGENT_POD_NAME>` is the name of the antrea-agent Pod running on that Node, and `<BRIDGE_NAME>` is the name
of the bridge created by Antrea (`br-int` by default).

You can also dump the flows for a specific table or group as follows:

```bash
# Dump flows of a table.
kubectl exec -n kube-system <ANTREA_AGENT_POD_NAME> -c antrea-ovs -- ovs-ofctl dump-flows <BRIDGE_NAME> table=<TABLE_NAME> -O Openflow15 [--no-stats] [--names]

# Dump a group.
kubectl exec -n kube-system <ANTREA_AGENT_POD_NAME> -c antrea-ovs -- ovs-ofctl dump-groups <BRIDGE_NAME> <GROUP_ID> -O Openflow15 [--names]
```

where `<TABLE_NAME>` is the name of a table in the pipeline, and `<GROUP_ID>` is the ID of a group.

## OVS Registers and Conntrack

### OVS Registers

We use some OVS registers to carry information throughout the pipeline. To enhance usability, we assign friendly names
to the registers we use.

| Register      | Field Range | Field Name                      | Reg Mark Value | Reg Mark Name                   | Description                                                                                          |
|---------------|-------------|---------------------------------|----------------|---------------------------------|------------------------------------------------------------------------------------------------------|
| NXM_NX_REG0   | bits 0-3    | PktSourceField                  | 0x1            | FromTunnelRegMark               | Packet source is tunnel port.                                                                        |
|               |             |                                 | 0x2            | FromGatewayRegMark              | Packet source is the local Antrea gateway port.                                                      |
|               |             |                                 | 0x3            | FromPodRegMark                  | Packet source is local Pod port.                                                                     |
|               |             |                                 | 0x4            | FromUplinkRegMark               | Packet source is uplink port.                                                                        |
|               |             |                                 | 0x5            | FromBridgeRegMark               | Packet source is local bridge port.                                                                  |
|               |             |                                 | 0x6            | FromTCReturnRegMark             | Packet source is TrafficControl return port.                                                         |
|               | bits 4-7    | PktDestinationField             | 0x1            | ToTunnelRegMark                 | Packet destination is tunnel port.                                                                   |
|               |             |                                 | 0x2            | ToGatewayRegMark                | Packet destination is the local Antrea gateway port.                                                 |
|               |             |                                 | 0x3            | ToLocalRegMark                  | Packet destination is local Pod port.                                                                |
|               |             |                                 | 0x4            | ToUplinkRegMark                 | Packet destination is uplink port.                                                                   |
|               |             |                                 | 0x5            | ToBridgeRegMark                 | Packet destination is local bridge port.                                                             |
|               | bit  9      |                                 | 0b0            | NotRewriteMACRegMark            | Packet's source/destination MAC address does not need to be rewritten.                               |
|               |             |                                 | 0b1            | RewriteMACRegMark               | Packet's source/destination MAC address needs to be rewritten.                                       |
|               | bit  10     |                                 | 0b1            | APDenyRegMark                   | Packet denied (Drop/Reject) by Antrea NetworkPolicy.                                                 |
|               | bits 11-12  | APDispositionField              | 0b00           | DispositionAllowRegMark         | Indicates Antrea NetworkPolicy disposition: allow.                                                   |
|               |             |                                 | 0b01           | DispositionDropRegMark          | Indicates Antrea NetworkPolicy disposition: drop.                                                    |
|               |             |                                 | 0b11           | DispositionPassRegMark          | Indicates Antrea NetworkPolicy disposition: pass.                                                    |
|               | bit  13     |                                 | 0b1            | GeneratedRejectPacketOutRegMark | Indicates packet is a generated reject response packet-out.                                          |
|               | bit  14     |                                 | 0b1            | SvcNoEpRegMark                  | Indicates packet towards a Service without Endpoint.                                                 |
|               | bit  19     |                                 | 0b1            | RemoteSNATRegMark               | Indicates packet needs SNAT on a remote Node.                                                        |
|               | bit  22     |                                 | 0b1            | L7NPRedirectRegMark             | Indicates L7 Antrea NetworkPolicy disposition of redirect.                                           |
|               | bits 21-22  | OutputRegField                  | 0b01           | OutputToOFPortRegMark           | Output packet to an OVS port.                                                                        |
|               |             |                                 | 0b10           | OutputToControllerRegMark       | Send packet to Antrea Agent.                                                                         |
|               | bits 25-32  | PacketInOperationField          |                |                                 | Field to store NetworkPolicy packetIn operation.                                                     |
| NXM_NX_REG1   | bits 0-31   | TargetOFPortField               |                |                                 | Egress OVS port of packet.                                                                           |
| NXM_NX_REG2   | bits 0-31   | SwapField                       |                |                                 | Swap values in flow fields in OpenFlow actions.                                                      |
|               | bits 0-7    | PacketInTableField              |                |                                 | OVS table where it was decided to send packets to the controller (Antrea Agent).                     |
| NXM_NX_REG3   | bits 0-31   | EndpointIPField                 |                |                                 | Field to store IPv4 address of the selected Service Endpoint.                                        |
|               |             | APConjIDField                   |                |                                 | Field to store Conjunction ID for Antrea Policy.                                                     |
| NXM_NX_REG4   | bits 0-15   | EndpointPortField               |                |                                 | Field store TCP/UDP/SCTP port of a Service's selected Endpoint.                                      |
|               | bits 16-18  | ServiceEPStateField             | 0b001          | EpToSelectRegMark               | Packet needs to do Service Endpoint selection.                                                       |
|               | bits 16-18  | ServiceEPStateField             | 0b010          | EpSelectedRegMark               | Packet has done Service Endpoint selection.                                                          |
|               | bits 16-18  | ServiceEPStateField             | 0b011          | EpToLearnRegMark                | Packet has done Service Endpoint selection and the selected Endpoint needs to be cached.             |
|               | bits 0-18   | EpUnionField                    |                |                                 | The union value of EndpointPortField and ServiceEPStateField.                                        |
|               | bit  19     |                                 | 0b1            | ToNodePortAddressRegMark        | Packet is destined for a Service of type NodePort.                                                   |
|               | bit  20     |                                 | 0b1            | AntreaFlexibleIPAMRegMark       | Packet is from local Antrea IPAM Pod.                                                                |
|               | bit  20     |                                 | 0b0            | NotAntreaFlexibleIPAMRegMark    | Packet is not from local Antrea IPAM Pod.                                                            |
|               | bit  21     |                                 | 0b1            | ToExternalAddressRegMark        | Packet is destined for a Service's external IP.                                                      |
|               | bits 22-23  | TrafficControlActionField       | 0b01           | TrafficControlMirrorRegMark     | Indicates packet needs to be mirrored (used by TrafficControl).                                      |
|               |             |                                 | 0b10           | TrafficControlRedirectRegMark   | Indicates packet needs to be redirected (used by TrafficControl).                                    |
|               | bit 24      |                                 | 0b1            | NestedServiceRegMark            | Packet is destined for a Service using other Services as Endpoints.                                  |
|               | bit 25      |                                 | 0b1            | DSRServiceRegMark               | Packet is destined for a Service working in DSR mode.                                                |
|               |             |                                 | 0b0            | NotDSRServiceRegMark            | Packet is destined for a Service working in non-DSR mode.                                            |
|               | bit 26      |                                 | 0b1            | RemoteEndpointRegMark           | Packet is destined for a Service selecting a remote non-hostNetwork Endpoint.                        |
|               | bit 27      |                                 | 0b1            | FromExternalRegMark             | Packet is from Antrea gateway, but its source IP is not the gateway IP.                              |
|               | bit 28      |                                 | 0b1            | FromLocalRegMark                | Packet is from a local Pod or the Node.                                                              |
| NXM_NX_REG5   | bits 0-31   | TFEgressConjIDField             |                |                                 | Egress conjunction ID hit by TraceFlow packet.                                                       |
| NXM_NX_REG6   | bits 0-31   | TFIngressConjIDField            |                |                                 | Ingress conjunction ID hit by TraceFlow packet.                                                      |
| NXM_NX_REG7   | bits 0-31   | ServiceGroupIDField             |                |                                 | GroupID corresponding to the Service.                                                                |
| NXM_NX_REG8   | bits 0-11   | VLANIDField                     |                |                                 | VLAN ID.                                                                                             |
|               | bits 12-15  | CtZoneTypeField                 | 0b0001         | IPCtZoneTypeRegMark             | Ct zone type is IPv4.                                                                                |
|               |             |                                 | 0b0011         | IPv6CtZoneTypeRegMark           | Ct zone type is IPv6.                                                                                |
|               | bits 0-15   | CtZoneField                     |                |                                 | Ct zone ID is a combination of VLANIDField and CtZoneTypeField.                                      |
| NXM_NX_REG9   | bits 0-31   | TrafficControlTargetOFPortField |                |                                 | Field to cache the OVS port to output packets to be mirrored or redirected (used by TrafficControl). |
| NXM_NX_XXREG3 | bits 0-127  | EndpointIP6Field                |                |                                 | Field to store IPv6 address of the selected Service Endpoint.                                        |

Note that reg marks that have overlapped bits will not be used at the same time, such as `SwapField` and `PacketInTableField`.

### OVS Ct Mark

We use some bits of the `ct_mark` field of OVS conntrack to carry information throughout the pipeline. To enhance
usability, we assign friendly names to the bits we use.

| Field Range | Field Name            | Ct Mark Value | Ct Mark Name       | Description                                                     |
|-------------|-----------------------|---------------|--------------------|-----------------------------------------------------------------|
| bits 0-3    | ConnSourceCTMarkField | 0b0010        | FromGatewayCTMark  | Connection source is the Antrea gateway port.                   |
|             |                       | 0b0101        | FromBridgeCTMark   | Connection source is the local bridge port.                     |
| bit 4       |                       | 0b1           | ServiceCTMark      | Connection is for Service.                                      |
|             |                       | 0b0           | NotServiceCTMark   | Connection is not for Service.                                  |
| bit 5       |                       | 0b1           | ConnSNATCTMark     | SNAT'd connection for Service.                                  |
| bit 6       |                       | 0b1           | HairpinCTMark      | Hair-pin connection.                                            |
| bit 7       |                       | 0b1           | L7NPRedirectCTMark | Connection should be redirected to an application-aware engine. |

### OVS Ct Label

We use some bits of the `ct_label` field of OVS conntrack to carry information throughout the pipeline. To enhance
usability, we assign friendly names to the bits we use.

| Field Range | Field Name            | Description                        |
|-------------|-----------------------|------------------------------------|
| bits 0-31   | IngressRuleCTLabel    | Ingress rule ID.                   |
| bits 32-63  | EgressRuleCTLabel     | Egress rule ID.                    |
| bits 64-75  | L7NPRuleVlanIDCTLabel | VLAN ID for L7 NetworkPolicy rule. |

### OVS Ct Zone

We use some OVS conntrack zones to isolate connection tracking rules. To enhance usability, we assign friendly names to
the ct zones.

| Zone ID | Zone Name    | Description                                        |
|---------|--------------|----------------------------------------------------|
| 65520   | CtZone       | Tracking IPv4 connections that don't require SNAT. |
| 65521   | SNATCtZone   | Tracking IPv4 connections that require SNAT.       |

## Antrea Features

### Kubernetes NetworkPolicy Implementation

Several tables of the pipeline are dedicated to [Kubernetes
NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) implementation (tables
[EgressRule], [EgressDefaultRule], [IngressRule], and [IngressDefaultRule]).

Throughout this document, the following K8s NetworkPolicy example is used to demonstrate how simple ingress and egress
policy rules are mapped to OVS flows.

This K8s NetworkPolicy is applied to Pods with the label `app: web` in the `default` Namespace. For these Pods, only TCP
traffic on port 80 from Pods with the label `app: client` and to Pods with the label `app: db` is allowed. Because
Antrea will only install OVS flows for this K8s NetworkPolicy on Nodes that have Pods selected by the policy, we have
scheduled an `app: web` Pod on the current Node from which the sample flows in this document are dumped. The Pod has
been assigned an IP address `10.10.0.19` from the Antrea CNI, so you will see the IP address shown in the associated
flows.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-app-db-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: client
      ports:
        - protocol: TCP
          port: 80
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: db
      ports:
        - protocol: TCP
          port: 3306
```

### Kubernetes Service Implementation

Like K8s NetworkPolicy, several tables of the pipeline are dedicated to [Kubernetes
Service](https://kubernetes.io/docs/concepts/services-networking/service/) implementation (tables [NodePortMark],
[SessionAffinity], [ServiceLB], and [EndpointDNAT]).

By enabling `proxyAll`, ClusterIP, NodePort, LoadBalancer, and ExternalIP are all handled by Antrea Proxy. Otherwise,
only in-cluster ClusterIP is handled. In this document, we use the sample K8s Services below. These Services select Pods
with the label `app: web` as Endpoints.

#### ClusterIP

A sample ClusterIP Service with `clusterIP` set to `10.105.31.235`.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sample-clusterip
spec:
  selector:
    app: web
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  clusterIP: 10.105.31.235
```

#### ClusterIP without Endpoint

A sample Service with `clusterIP` set to `10.101.255.29` does not have any associated Endpoint.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sample-clusterip-no-ep
spec:
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  clusterIP: 10.101.255.29
```

#### NodePort

A sample NodePort Service with `nodePort` set to `30004`.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sample-nodeport
spec:
  selector:
    app: web
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
      nodePort: 30004
  type: NodePort
```

#### LoadBalancer

A sample LoadBalancer Service with ingress IP `192.168.77.150` assigned by an ingress controller.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sample-loadbalancer
spec:
  selector:
    app: web
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  type: LoadBalancer
status:
  loadBalancer:
    ingress:
      - ip: 192.168.77.150
```

#### Service with ExternalIP

A sample Service with external IP `192.168.77.200`.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sample-service-externalip
spec:
  selector:
    app: web
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  externalIPs: 
    - 192.168.77.200
```

#### Service with Session Affinity

A sample Service configured with session affinity.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sample-service-session-affinity
spec:
  selector:
    app: web
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  clusterIP: 10.96.76.15
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 300
```

#### Service with ExternalTrafficPolicy Local

A sample Service configured `externalTrafficPolicy` to `Local`. Only `externalTrafficPolicy` of NodePort/LoadBalancer
Service can be configured with `Local`.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sample-service-etp-local
spec:
  selector:
    app: web
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  type: LoadBalancer
  externalTrafficPolicy: Local
status:
  loadBalancer:
    ingress:
      - ip: 192.168.77.151
```

### Antrea-native NetworkPolicy Implementation

In addition to the tables created for K8s NetworkPolicy, Antrea creates additional dedicated tables to support
[Antrea-native NetworkPolicy](../antrea-network-policy.md) (tables [AntreaPolicyEgressRule] and
[AntreaPolicyIngressRule]).

Consider the following Antrea ClusterNetworkPolicy (ACNP) in the Application Tier as an example for the remainder of
this document.

This ACNP is applied to all Pods with the label `app: web` in all Namespaces. For these Pods, only TCP traffic on port
80 from the Pods with the label `app: client` and to the Pods with the label `app: db` is allowed. Similar to K8s
NetworkPolicy, Antrea will only install OVS flows for this policy on Nodes that have Pods selected by the policy.

This policy has very similar rules as the K8s NetworkPolicy example shown previously. This is intentional to simplify
this document and to allow easier comparison between the flows generated for both types of policies. Additionally, we
should emphasize that this policy applies to Pods across all Namespaces, while a K8s NetworkPolicy is always scoped to
a specific Namespace (in the case of our example, the default Namespace).

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: web-app-db-network-policy
spec:
  priority: 5
  tier: application
  appliedTo:
    - podSelector:
        matchLabels:
          app: web
  ingress:
    - action: Allow
      from:
        - podSelector:
            matchLabels:
              app: client
      ports:
        - protocol: TCP
          port: 80
      name: AllowFromClient
    - action: Drop
  egress:
    - action: Allow
      to:
        - podSelector:
            matchLabels:
              app: db
      ports:
        - protocol: TCP
          port: 3306
      name: AllowToDB
    - action: Drop
```

### Antrea-native L7 NetworkPolicy Implementation

In addition to layer 3 and layer 4 policies mentioned above, [Antrea-native Layer 7
NetworkPolicy](../antrea-l7-network-policy.md) is also supported in Antrea. The main difference is that Antrea-native L7
NetworkPolicy uses layer 7 protocol to filter traffic, not layer 3 or layer 4 protocol.

Consider the following Antrea-native L7 NetworkPolicy in the Application Tier as an example for the remainder of this
document.

This ACNP is applied to all Pods with the label `app: web` in all Namespaces. It allows only HTTP ingress traffic on
port 8080 from Pods with the label `app: client`, limited to the `GET` method and `/api/v2/*` path. Any other HTTP
ingress traffic on port 8080 from Pods with the label `app: client` will be dropped.

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: ingress-allow-http-request-to-api-v2
spec:
  priority: 4
  tier: application
  appliedTo:
    - podSelector:
        matchLabels:
          app: web
  ingress:
    - name: AllowFromClientL7
      action: Allow
      from:
        - podSelector:
            matchLabels:
              app: client
      ports:
        - protocol: TCP
          port: 8080
      l7Protocols:
        - http:
            path: "/api/v2/*"
            method: "GET"
```

### TrafficControl Implementation

[TrafficControl](../traffic-control.md) is a CRD API that manages and manipulates the transmission of Pod traffic.
Antrea creates a dedicated table [TrafficControl] to implement feature `TrafficControl`. We will use the following
TrafficControls as examples for the remainder of this document.

#### TrafficControl for Packet Redirecting

This is a TrafficControl applied to Pods with the label `app: web`. For these Pods, both ingress and egress traffic will
be redirected to port `antrea-tc-tap0`, and returned through port `antrea-tc-tap1`.

```yaml
apiVersion: crd.antrea.io/v1alpha2
kind: TrafficControl
metadata:
  name: redirect-web-to-local
spec:
  appliedTo:
    podSelector:
      matchLabels:
        app: web
  direction: Both
  action: Redirect
  targetPort:
    ovsInternal:
      name: antrea-tc-tap0
  returnPort:
    ovsInternal:
      name: antrea-tc-tap1
```

#### TrafficControl for Packet Mirroring

This is a TrafficControl applied to Pods with the label `app: db`. For these Pods, both ingress and egress will be
mirrored (duplicated) to port `antrea-tc-tap2`.

```yaml
apiVersion: crd.antrea.io/v1alpha2
kind: TrafficControl
metadata:
  name: mirror-db-to-local
spec:
  appliedTo:
    podSelector:
      matchLabels:
        app: db
  direction: Both
  action: Mirror
  targetPort:
    ovsInternal:
      name: antrea-tc-tap2
```

### Egress Implementation

Table [EgressMark] is dedicated to the implementation of feature `Egress`.

Consider the following Egresses as examples for the remainder of this document.

#### Egress Applied to Web Pods

This is an Egress applied to Pods with the label `app: web`. For these Pods, all egress traffic (traffic leaving the
cluster) will be SNAT'd on the Node `k8s-node-control-plane` using Egress IP `192.168.77.112`. In this context,
`k8s-node-control-plane` is known as the "Egress Node" for this Egress resource. Note that the flows presented in the
rest of this document were dumped on Node `k8s-node-control-plane`. Egress flows are different on the "source Node"
(Node running a workload Pod to which the Egress resource is applied) and on the "Egress Node" (Node enforcing the
SNAT policy).

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: Egress
metadata:
  name: egress-web
spec:
  appliedTo:
    podSelector:
      matchLabels:
        app: web
  egressIP: 192.168.77.112
status:
  egressNode: k8s-node-control-plane
```

#### Egress Applied to Client Pods

This is an Egress applied to Pods with the label `app: client`. For these Pods, all egress traffic will be SNAT'd on the
Node `k8s-node-worker-1` using Egress IP `192.168.77.113`.

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: Egress
metadata:
  name: egress-client
spec:
  appliedTo:
    podSelector:
      matchLabels:
        app: client
  egressIP: 192.168.77.113
status:
  egressNode: k8s-node-worker-1
```

## OVS Tables

![OVS pipeline](../assets/ovs-pipeline.svg)

### PipelineRootClassifier

This table serves as the primary entry point in the pipeline, forwarding packets to different tables based on their
respective protocols.

If you dump the flows of this table, you may see the following:

```text
1. table=PipelineRootClassifier, priority=200,arp actions=goto_table:ARPSpoofGuard
2. table=PipelineRootClassifier, priority=200,ip actions=goto_table:Classifier
3. table=PipelineRootClassifier, priority=0 actions=drop
```

Flow 1 forwards ARP packets to table [ARPSpoofGuard].

Flow 2 forwards IP packets to table [Classifier].

Flow 3 is the table-miss flow to drop other unsupported protocols, not normally used.

### ARPSpoofGuard

This table is designed to drop ARP [spoofing](https://en.wikipedia.org/wiki/Spoofing_attack) packets from local Pods or
the local Antrea gateway. We ensure that the advertised IP and MAC addresses are correct, meaning they match the values
configured on the interface when Antrea sets up networking for a local Pod or the local Antrea gateway.

If you dump the flows of this table, you may see the following:

```text
1. table=ARPSpoofGuard, priority=200,arp,in_port="antrea-gw0",arp_spa=10.10.0.1,arp_sha=ba:5e:d1:55:aa:c0 actions=goto_table:ARPResponder
2. table=ARPSpoofGuard, priority=200,arp,in_port="client-6-3353ef",arp_spa=10.10.0.26,arp_sha=5e:b5:e3:a6:90:b7 actions=goto_table:ARPResponder
3. table=ARPSpoofGuard, priority=200,arp,in_port="web-7975-274540",arp_spa=10.10.0.24,arp_sha=fa:b7:53:74:21:a6 actions=goto_table:ARPResponder
4. table=ARPSpoofGuard, priority=200,arp,in_port="db-755c6-5080e3",arp_spa=10.10.0.25,arp_sha=36:48:21:a2:9d:b4 actions=goto_table:ARPResponder
5. table=ARPSpoofGuard, priority=0 actions=drop
```

Flow 1 matches legitimate ARP packets from the local Antrea gateway.

Flows 2-4 match legitimate ARP packets from local Pods.

Flow 5 is the table-miss flow to drop ARP spoofing packets, which are not matched by flows 1-4.

### ARPResponder

The purpose of this table is to handle ARP requests from the local Antrea gateway or local Pods, addressing specific cases:

1. Responding to ARP requests from the local Antrea gateway seeking the MAC address of a remote Antrea gateway located
   on a different Node. This ensures that the local Node can reach any remote Pods.
2. Ensuring the normal layer 2 (L2) learning among local Pods and the local Antrea gateway.

If you dump the flows of this table, you may see the following:

```text
1. table=ARPResponder, priority=200,arp,arp_tpa=10.10.1.1,arp_op=1 actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:aa:bb:cc:dd:ee:ff->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:aa:bb:cc:dd:ee:ff->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:10.10.1.1->arp_spa,IN_PORT
2. table=ARPResponder, priority=190,arp actions=NORMAL
3. table=ARPResponder, priority=0 actions=drop
```

Flow 1 is designed for case 1, matching ARP request packets for the MAC address of a remote Antrea gateway with IP address
`10.10.1.1`. It programs an ARP reply packet and sends it back to the port where the request packet was received. Note
that both the source hardware address and the source MAC address in the ARP reply packet are set to the *Global Virtual
MAC* `aa:bb:cc:dd:ee:ff`, not the actual MAC address of the remote Antrea gateway. This ensures that once the traffic is
received by the remote OVS bridge, it can be directly forwarded to the appropriate Pod without actually going through
the local Antrea gateway. The *Global Virtual MAC* is used as the destination MAC address for all the traffic being
tunneled or routed.

This flow serves as the "ARP responder" for the peer Node whose local Pod subnet is `10.10.1.0/24`. If we were to look
at the routing table for the local Node, we would find the following "onlink" route:

```text
10.10.1.0/24 via 10.10.1.1 dev antrea-gw0 onlink
```

A similar route is installed on the local Antrea gateway (antrea-gw0) interface every time the Antrea *Node Route Controller*
is notified that a new Node has joined the cluster. The route must be marked as "onlink" since the kernel does not have
a route to the peer gateway `10.10.1.1`. We "trick" the kernel into believing that `10.10.1.1` is directly connected to
the local Node, even though it is on the other side of the tunnel.

Flow 2 is designed for case 2, ensuring that OVS handles the remainder of ARP traffic as a regular L2 learning switch
(using the `normal` action). In particular, this takes care of forwarding ARP requests and replies among local Pods.

Flow 3 is the table-miss flow, which should never be used since ARP packets will be matched by either flow 1 or 2.

### Classifier

This table is designed to determine the "category" of IP packets by matching on their ingress port. It addresses
specific cases:

1. Packets originating from the local Node through the local Antrea gateway port, requiring IP spoof legitimacy
   verification.
2. Packets originating from the external network through the Antrea gateway port.
3. Packets received through an overlay tunnel.
4. Packets received through a return port defined in a user-provided TrafficControl CR (for feature `TrafficControl`).
5. Packets returned from an application-aware engine through a specific port (for feature `L7NetworkPolicy`).
6. Packets originating from local Pods, requiring IP spoof legitimacy verification.

If you dump the flows of this table, you may see the following:

```text
1. table=Classifier, priority=210,ip,in_port="antrea-gw0",nw_src=10.10.0.1 actions=set_field:0x2/0xf->reg0,set_field:0x10000000/0x10000000->reg4,goto_table:SpoofGuard
2. table=Classifier, priority=200,in_port="antrea-gw0" actions=set_field:0x2/0xf->reg0,set_field:0x8000000/0x8000000->reg4,goto_table:SpoofGuard
3. table=Classifier, priority=200,in_port="antrea-tun0" actions=set_field:0x1/0xf->reg0,set_field:0x200/0x200->reg0,goto_table:UnSNAT
4. table=Classifier, priority=200,in_port="antrea-tc-tap2" actions=set_field:0x6/0xf->reg0,goto_table:L3Forwarding
5. table=Classifier, priority=200,in_port="antrea-l7-tap1",vlan_tci=0x1000/0x1000 actions=pop_vlan,set_field:0x6/0xf->reg0,goto_table:L3Forwarding
6. table=Classifier, priority=190,in_port="client-6-3353ef" actions=set_field:0x3/0xf->reg0,set_field:0x10000000/0x10000000->reg4,goto_table:SpoofGuard
7. table=Classifier, priority=190,in_port="web-7975-274540" actions=set_field:0x3/0xf->reg0,set_field:0x10000000/0x10000000->reg4,goto_table:SpoofGuard
8. table=Classifier, priority=190,in_port="db-755c6-5080e3" actions=set_field:0x3/0xf->reg0,set_field:0x10000000/0x10000000->reg4,goto_table:SpoofGuard
9. table=Classifier, priority=0 actions=drop
```

Flow 1 is designed for case 1, matching the source IP address `10.10.0.1` to ensure that the packets are originating from
the local Antrea gateway. The following reg marks are loaded:

- `FromGatewayRegMark`, indicating that the packets are received on the local Antrea gateway port, which will be
  consumed in tables [L3Forwarding], [L3DecTTL], [SNATMark] and [SNAT].
- `FromLocalRegMark`, indicating that the packets are from the local Node, which will be consumed in table [ServiceLB].

Flow 2 is designed for case 2, matching packets originating from the external network through the Antrea gateway port
and forwarding them to table [SpoofGuard]. Since packets originating from the local Antrea gateway are matched by flow
1, flow 2 can only match packets originating from the external network. The following reg marks are loaded:

- `FromGatewayRegMark`, the same as flow 1.
- `FromExternalRegMark`, indicating that the packets are from the external network, not the local Node.

Flow 3 is for case 3, matching packets through an overlay tunnel (i.e., from another Node) and forwarding them to table
[UnSNAT]. This approach is based on the understanding that these packets originate from remote Nodes, potentially
bearing varying source IP addresses. These packets undergo legitimacy verification before being tunneled. As a consequence,
packets from the tunnel should be seamlessly forwarded to table [UnSNAT]. The following reg marks are loaded:

- `FromTunnelRegMark`, indicating that the packets are received on a tunnel, consumed in table [L3Forwarding].
- `RewriteMACRegMark`, indicating that the source and destination MAC addresses of the packets should be rewritten,
  and consumed in table [L3Forwarding].

Flow 4 is for case 4, matching packets from a TrafficControl return port and forwarding them to table [L3Forwarding]
to decide the egress port. It's important to note that a forwarding decision for these packets was already made before
redirecting them to the TrafficControl target port in table [Output], and at this point, the source and destination MAC
addresses of these packets have already been set to the correct values. The only purpose of forwarding the packets to
table [L3Forwarding] is to load the tunnel destination IP for packets destined for remote Nodes. This ensures that the
returned packets destined for remote Nodes are forwarded through the tunnel. `FromTCReturnRegMark`, which will be used
in table [TrafficControl], is loaded to mark the packet source.

Flow 5 is for case 5, matching packets returned back from an application-aware engine through a specific port, stripping
the VLAN ID used by the application-aware engine, and forwarding them to table [L3Forwarding] to decide the egress port.
Like flow 4, the purpose of forwarding the packets to table [L3Forwarding] is to load the tunnel destination IP for
packets destined for remote Nodes, and `FromTCReturnRegMark` is also loaded.

Flows 6-8 are for case 6, matching packets from local Pods and forwarding them to table [SpoofGuard] to do legitimacy
verification. The following reg marks are loaded:

- `FromPodRegMark`, indicating that the packets are received on the ports connected to the local Pods, consumed in
  tables [L3Forwarding] and [SNATMark].
- `FromLocalRegMark`, indicating that the packets are from the local Pods, consumed in table [ServiceLB].

Flow 9 is the table-miss flow to drop packets that are not matched by flows 1-8.

### SpoofGuard

This table is crafted to prevent IP [spoofing](https://en.wikipedia.org/wiki/Spoofing_attack) from local Pods. It
addresses specific cases:

1. Allowing all packets from the local Antrea gateway. We do not perform checks for this interface as we need to accept
   external traffic with a source IP address that does not match the gateway IP.
2. Ensuring that the source IP and MAC addresses are correct, i.e., matching the values configured on the interface when
   Antrea sets up networking for a Pod.

If you dump the flows of this table, you may see the following:

```text
1. table=SpoofGuard, priority=200,ip,in_port="antrea-gw0" actions=goto_table:UnSNAT
2. table=SpoofGuard, priority=200,ip,in_port="client-6-3353ef",dl_src=5e:b5:e3:a6:90:b7,nw_src=10.10.0.26 actions=goto_table:UnSNAT
3. table=SpoofGuard, priority=200,ip,in_port="web-7975-274540",dl_src=fa:b7:53:74:21:a6,nw_src=10.10.0.24 actions=goto_table:UnSNAT
4. table=SpoofGuard, priority=200,ip,in_port="db-755c6-5080e3",dl_src=36:48:21:a2:9d:b4,nw_src=10.10.0.25 actions=goto_table:UnSNAT
5. table=SpoofGuard, priority=0 actions=drop
```

Flow 1 is for case 1, matching packets received on the local Antrea gateway port without checking the source IP and MAC
addresses. There are some cases where the source IP of the packets through the local Antrea gateway port is not the local
Antrea gateway IP address:

- When Antrea is deployed with kube-proxy, and the feature `AntreaProxy` is not enabled, packets from local Pods destined
  for Services will first go through the gateway port, get load-balanced by the kube-proxy data path (undergoes DNAT)
  then re-enter the OVS pipeline through the gateway port (through an "onlink" route, installed by Antrea, directing the
  DNAT'd packets to the gateway port), resulting in the source IP being that of a local Pod.
- When Antrea is deployed without kube-proxy, and both the feature `AntreaProxy` and option `proxyAll` are enabled,
  packets from the external network destined for Services will be routed to OVS through the gateway port without
  masquerading source IP.
- When Antrea is deployed with kube-proxy, packets from the external network destined for Services whose
  `externalTrafficPolicy` is set to `Local` will get load-balanced by the kube-proxy data path (undergoes DNAT with a
  local Endpoint selected by the kube-proxy) and then enter the OVS pipeline through the gateway (through a "onlink"
  route, installed by Antrea, directing the DNAT'd packets to the gateway port) without masquerading source IP.

Flows 2-4 are for case 2, matching legitimate IP packets from local Pods.

Flow 5 is the table-miss flow to drop IP spoofing packets.

### UnSNAT

This table is used to undo SNAT on reply packets by invoking action `ct` on them. The packets are from SNAT'd Service
connections that have been committed to `SNATCtZone` in table [SNAT]. After invoking action `ct`, the packets will be
in a "tracked" state, restoring all [connection tracking
fields](https://www.openvswitch.org/support/dist-docs/ovs-fields.7.txt) (such as `ct_state`, `ct_mark`, `ct_label`, etc.)
to their original values. The packets with a "tracked" state are then forwarded to table [ConntrackZone].

If you dump the flows of this table, you may see the following:

```text
1. table=UnSNAT, priority=200,ip,nw_dst=169.254.0.253 actions=ct(table=ConntrackZone,zone=65521,nat)
2. table=UnSNAT, priority=200,ip,nw_dst=10.10.0.1 actions=ct(table=ConntrackZone,zone=65521,nat)
3. table=UnSNAT, priority=0 actions=goto_table:ConntrackZone
```

Flow 1 matches reply packets for Service connections which were SNAT'd with the *Virtual Service IP* `169.254.0.253`
and invokes action `ct` on them.

Flow 2 matches packets for Service connections which were SNAT'd with the local Antrea gateway IP `10.10.0.1` and
invokes action `ct` on them. This flow also matches request packets destined for the local Antrea gateway IP from
local Pods by accident. However, this is harmless since such connections will never be committed to `SNATCtZone`, and
therefore, connection tracking fields for the packets are unset.

Flow 3 is the table-miss flow.

For reply packets from SNAT'd connections, whose destination IP is the translated SNAT IP, after invoking action `ct`,
the destination IP of the packets will be restored to the original IP before SNAT, stored in the connection tracking
field `ct_nw_dst`.

### ConntrackZone

The main purpose of this table is to invoke action `ct` on packets from all connections. After invoking `ct` action,
packets will be in a "tracked" state, restoring all connection tracking fields to their appropriate values. When invoking
action `ct` with `CtZone` to the packets that have a "tracked" state associated with `SNATCtZone`, then the "tracked"
state associated with `SNATCtZone` will be inaccessible. This transition occurs because the "tracked" state shifts to
another state associated with `CtZone`. A ct zone is similar in spirit to the more generic Linux network namespaces,
uniquely containing a "tracked" state within each ct zone.

If you dump the flows of this table, you may see the following:

```text
1. table=ConntrackZone, priority=200,ip actions=ct(table=ConntrackState,zone=65520,nat)
2. table=ConntrackZone, priority=0 actions=goto_table:ConntrackState
```

Flow 1 invokes `ct` action on packets from all connections, and the packets are then forwarded to table [ConntrackState]
with the "tracked" state associated with `CtZone`. Note that for packets in an established Service (DNATed) connection,
not the first packet of a Service connection, DNAT or un-DNAT is performed on them  before they are forwarded.

Flow 2 is the table-miss flow that should remain unused.

### ConntrackState

This table handles packets from the connections that have a "tracked" state associated with `CtZone`. It addresses
specific cases:

1. Dropping invalid packets reported by conntrack.
2. Forwarding tracked packets from all connections to table [AntreaPolicyEgressRule] directly, bypassing the tables
   like [PreRoutingClassifier], [NodePortMark], [SessionAffinity], [ServiceLB], and [EndpointDNAT] for Service Endpoint
   selection.
3. Forwarding packets from new connections to table [PreRoutingClassifier] to start Service Endpoint selection since
   Service connections are not identified at this stage.

If you dump the flows of this table, you may see the following:

```text
1. table=ConntrackState, priority=200,ct_state=+inv+trk,ip actions=drop
2. table=ConntrackState, priority=190,ct_state=-new+trk,ct_mark=0/0x10,ip actions=goto_table:AntreaPolicyEgressRule
3. table=ConntrackState, priority=190,ct_state=-new+trk,ct_mark=0x10/0x10,ip actions=set_field:0x200/0x200->reg0,goto_table:AntreaPolicyEgressRule
4. table=ConntrackState, priority=0 actions=goto_table:PreRoutingClassifier
```

Flow 1 is for case 1, dropping invalid packets.

Flow 2 is for case 2, matching packets from non-Service connections with `NotServiceCTMark` and forwarding them to
table [AntreaPolicyEgressRule] directly, bypassing the tables for Service Endpoint selection.

Flow 3 is also for case 2, matching packets from Service connections with `ServiceCTMark` loaded in table
[EndpointDNAT] and forwarding them to table [AntreaPolicyEgressRule], bypassing the tables for Service Endpoint
selection. `RewriteMACRegMark`, which is used in table [L3Forwarding], is loaded in this flow, indicating that the
source and destination MAC addresses of the packets should be rewritten.

Flow 4 is the table-miss flow for case 3, matching packets from all new connections and forwarding them to table
[PreRoutingClassifier] to start the processing of Service Endpoint selection.

### PreRoutingClassifier

This table handles the first packet from uncommitted Service connections before Service Endpoint selection. It
sequentially resubmits the packets to tables [NodePortMark] and [SessionAffinity] to do some pre-processing, including
the loading of specific reg marks. Subsequently, it forwards the packets to table [ServiceLB] to perform Service Endpoint
selection.

If you dump the flows of this table, you may see the following:

```text
1. table=PreRoutingClassifier, priority=200,ip actions=resubmit(,NodePortMark),resubmit(,SessionAffinity),resubmit(,ServiceLB)
2. table=PreRoutingClassifier, priority=0 actions=goto_table:NodePortMark
```

Flow 1 sequentially resubmits packets to tables [NodePortMark], [SessionAffinity], and [ServiceLB]. Note that packets
are ultimately forwarded to table [ServiceLB]. In tables [NodePortMark] and [SessionAffinity], only reg marks are loaded.

Flow 2 is the table-miss flow that should remain unused.

### NodePortMark

This table is designed to potentially mark packets destined for NodePort Services. It is only created when `proxyAll` is
enabled.

If you dump the flows of this table, you may see the following:

```text
1. table=NodePortMark, priority=200,ip,nw_dst=192.168.77.102 actions=set_field:0x80000/0x80000->reg4
2. table=NodePortMark, priority=200,ip,nw_dst=169.254.0.252 actions=set_field:0x80000/0x80000->reg4
3. table=NodePortMark, priority=0 actions=goto_table:SessionAffinity
```

Flow 1 matches packets destined for the local Node from local Pods. `NodePortRegMark` is loaded, indicating that the
packets are potentially destined for NodePort Services. We assume only one valid IP address, `192.168.77.102` (the
Node's transport IP), can serve as the host IP address for NodePort based on the option `antreaProxy.nodePortAddresses`.
If there are multiple valid IP addresses specified in the option, a flow similar to flow 1 will be installed for each
IP address.

Flow 2 match packets destined for the *Virtual NodePort DNAT IP*. Packets destined for NodePort Services from the local
Node or the external network is DNAT'd to the *Virtual NodePort DNAT IP* by iptables before entering the pipeline.

Flow 3 is the table-miss flow.

Note that packets of NodePort Services have not been identified in this table by matching destination IP address. The
identification of NodePort Services will be done finally in table [ServiceLB] by matching `NodePortRegMark` and the
the specific destination port of a NodePort.

### SessionAffinity

This table is designed to implement Service session affinity. The learned flows that cache the information of the
selected Endpoints are installed here.

If you dump the flows of this table, you may see the following:

```text
1. table=SessionAffinity, hard_timeout=300, priority=200,tcp,nw_src=10.10.0.1,nw_dst=10.96.76.15,tp_dst=80 \
   actions=set_field:0x50/0xffff->reg4,set_field:0/0x4000000->reg4,set_field:0xa0a0001->reg3,set_field:0x20000/0x70000->reg4,set_field:0x200/0x200->reg0
2. table=SessionAffinity, priority=0 actions=set_field:0x10000/0x70000->reg4
```

Flow 1 is a learned flow generated by flow 3 in table [ServiceLB], designed for the sample Service [ClusterIP with
Session Affinity], to implement Service session affinity. Here are some details about the flow:

- The "hard timeout" of the learned flow should be equal to the value of
  `service.spec.sessionAffinityConfig.clientIP.timeoutSeconds` defined in the Service. This means that until the hard
  timeout expires, this flow is present in the pipeline, and the session affinity of the Service takes effect. Unlike an
  "idle timeout", the "hard timeout" does not reset whenever the flow is matched.
- Source IP address, destination IP address, destination port, and transport protocol are used to match packets of
  connections sourced from the same client and destined for the Service during the affinity time window.
- Endpoint IP address and Endpoint port are loaded into `EndpointIPField` and `EndpointPortField` respectively.
- `EpSelectedRegMark` is loaded, indicating that the Service Endpoint selection is done, and ensuring that the packets
  will only match the last flow in table [ServiceLB].
- `RewriteMACRegMark`, which will be consumed in table [L3Forwarding], is loaded here, indicating that the source and
  destination MAC addresses of the packets should be rewritten.

Flow 2 is the table-miss flow to match the first packet of connections destined for Services. The loading of
`EpToSelectRegMark`, to be consumed in table [ServiceLB], indicating that the packet needs to do Service Endpoint
selection.

### ServiceLB

This table is used to implement Service Endpoint selection. It addresses specific cases:

1. ClusterIP, as demonstrated in the examples [ClusterIP without Endpoint] and [ClusterIP].
2. NodePort, as demonstrated in the example [NodePort].
3. LoadBalancer, as demonstrated in the example [LoadBalancer].
4. Service configured with external IPs, as demonstrated in the example [Service with ExternalIP].
5. Service configured with session affinity, as demonstrated in the example [Service with session affinity].
6. Service configured with externalTrafficPolicy to `Local`, as demonstrated in the example [Service with
   ExternalTrafficPolicy Local].

If you dump the flows of this table, you may see the following:

```text
1. table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.101.255.29,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x9->reg7,group:9
2. table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.105.31.235,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0xc->reg7,group:10
3. table=ServiceLB, priority=200,tcp,reg4=0x90000/0xf0000,tp_dst=30004 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x200000/0x200000->reg4,set_field:0xc->reg7,group:12
4. table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=192.168.77.150,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0xe->reg7,group:14
5. table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=192.168.77.200,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x10->reg7,group:16
6. table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=10.96.76.15,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x30000/0x70000->reg4,set_field:0xa->reg7,group:11
7. table=ServiceLB, priority=190,tcp,reg4=0x30000/0x70000,nw_dst=10.96.76.15,tp_dst=80 actions=learn(table=SessionAffinity,hard_timeout=300,priority=200,delete_learned,cookie=0x203000000000a,\
    eth_type=0x800,nw_proto=6,NXM_OF_TCP_DST[],NXM_OF_IP_DST[],NXM_OF_IP_SRC[],load:NXM_NX_REG4[0..15]->NXM_NX_REG4[0..15],load:NXM_NX_REG4[26]->NXM_NX_REG4[26],load:NXM_NX_REG3[]->NXM_NX_REG3[],load:0x2->NXM_NX_REG4[16..18],load:0x1->NXM_NX_REG0[9]),\
    set_field:0x20000/0x70000->reg4,goto_table:EndpointDNAT
8. table=ServiceLB, priority=210,tcp,reg4=0x10010000/0x10070000,nw_dst=192.168.77.151,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x11->reg7,group:17
9. table=ServiceLB, priority=200,tcp,reg4=0x10000/0x70000,nw_dst=192.168.77.151,tp_dst=80 actions=set_field:0x200/0x200->reg0,set_field:0x20000/0x70000->reg4,set_field:0x12->reg7,group:18
10. table=ServiceLB, priority=0 actions=goto_table:EndpointDNAT
```

Flow 1 and flow 2 are designed for case 1, matching the first packet of connections destined for the sample [ClusterIP
without Endpoint] or [ClusterIP]. This is achieved by matching `EpToSelectRegMark` loaded in table [SessionAffinity],
clusterIP, and port. The target of the packet matched by the flow is an OVS group where the Endpoint will be selected.
Before forwarding the packet to the OVS group, `RewriteMACRegMark`, which will be consumed in table [L3Forwarding], is
loaded, indicating that the source and destination MAC addresses of the packets should be rewritten. `EpSelectedRegMark`
, which will be consumed in table [EndpointDNAT], is also loaded, indicating that the Endpoint is selected. Note that the
Service Endpoint selection is not completed yet, as it will be done in the target OVS group.

Flow 3 is for case 2, matching the first packet of connections destined for the sample [NodePort]. This is achieved by
matching `EpToSelectRegMark` loaded in table [SessionAffinity], `NodePortRegMark` loaded in table [NodePortMark], and
NodePort port. Similar to flows 1-2, `RewriteMACRegMark` and `EpSelectedRegMark` are also loaded.

Flow 4 is for case 3, processing the first packet of connections destined for the ingress IP of the sample
[LoadBalancer], similar to flow 1.

Flow 5 is for case 4, processing the first packet of connections destined for the external IP of the sample [Service
with ExternalIP], similar to flow 1.

Flow 6 is the initial process for case 5, matching the first packet of connections destined for the sample [Service with
Session Affinity]. This is achieved by matching the conditions similar to flow 1. Like flow 1, the target of the flow is
also an OVS group, and `RewriteMACRegMark` is loaded. The difference is that `EpToLearnRegMark` is loaded, rather than
`EpSelectedRegMark`, indicating that the selected Endpoint needs to be cached.

Flow 7 is the final process for case 5, matching the packet previously matched by flow 6, resubmitted back from the target OVS
group after selecting an Endpoint. Then a learned flow will be generated in table [SessionAffinity] to match the packets
of the subsequent connections from the same client IP, ensuring that the packets are always forwarded to the same Endpoint
selected the first time. `EpSelectedRegMark`, which will be consumed in table [EndpointDNAT], is loaded, indicating that
Service Endpoint selection has been done.

Flow 8 and flow 9 are for case 6. Flow 8 has higher priority than flow 9, prioritizing matching the first
packet of connections sourced from a local Pod or the local Node with `FromLocalRegMark` loaded in table [Classifier]
and destined for the sample [Service with ExternalTrafficPolicy Local]. The target of flow 8 is an OVS group that has
all the Endpoints across the cluster, ensuring accessibility for Service connections originating from local Pods or
Nodes, even though `externalTrafficPolicy` is set to `Local` for the Service. Due to the existence of flow 8, consequently,
flow 9 exclusively matches packets sourced from the external network, resembling the pattern of flow 1. The target of
flow 9 is an OVS group that has only the local Endpoints since `externalTrafficPolicy` of the Service is `Local`.

Flow 10 is the table-miss flow.

As mentioned above, the Service Endpoint selection is performed within OVS groups. 3 typical OVS groups are listed below:

```text
1. group_id=9,type=select,\
   bucket=bucket_id:0,weight:100,actions=set_field:0x4000/0x4000->reg0,resubmit(,EndpointDNAT)
2. group_id=10,type=select,\
   bucket=bucket_id:0,weight:100,actions=set_field:0xa0a0018->reg3,set_field:0x50/0xffff->reg4,resubmit(,EndpointDNAT),\
   bucket=bucket_id:1,weight:100,actions=set_field:0x4000000/0x4000000->reg4,set_field:0xa0a0106->reg3,set_field:0x50/0xffff->reg4,resubmit(,EndpointDNAT)
3. group_id=11,type=select,\
   bucket=bucket_id:0,weight:100,actions=set_field:0xa0a0018->reg3,set_field:0x50/0xffff->reg4,resubmit(,ServiceLB),\
   bucket=bucket_id:1,weight:100,actions=set_field:0x4000000/0x4000000->reg4,set_field:0xa0a0106->reg3,set_field:0x50/0xffff->reg4,resubmit(,ServiceLB)
```

The first group with `group_id` 9 is the destination of packets matched by flow 1, designed for a Service without
Endpoints. The group only has a single bucket where `SvcNoEpRegMark` which will be used in table [EndpointDNAT] is
loaded, indicating that the Service has no Endpoint, and then packets are forwarded to table [EndpointDNAT].

The second group with `group_id` 10 is the destination of packets matched by flow 2, designed for a Service with
Endpoints. The group has 2 buckets, indicating the availability of 2 selectable Endpoints. Each bucket has an equal
chance of being chosen since they have the same weights. For every bucket, the Endpoint IP and Endpoint port are loaded
into `EndpointIPField` and `EndpointPortField`, respectively. These loaded values will be consumed in table
[EndpointDNAT] to which the packets are forwarded and in which DNAT will be performed. `RemoteEndpointRegMark` is loaded
for remote Endpoints, like the bucket with `bucket_id` 1 in this group.

The third group with `group_id` 11 is the destination of packets matched by flow 6, designed for a Service that has
Endpoints and is configured with session affinity. The group closely resembles the group with `group_id` 10, except that
the destination of the packets is table [ServiceLB], rather than table [EndpointDNAT]. After being resubmitted back to table
[ServiceLB], they will be matched by flow 7.

### EndpointDNAT

The table implements DNAT for Service connections after Endpoint selection is performed in table [ServiceLB].

If you dump the flows of this table, you may see the following::

```text
1. table=EndpointDNAT, priority=200,reg0=0x4000/0x4000 actions=controller(reason=no_match,id=62373,userdata=04)
2. table=EndpointDNAT, priority=200,tcp,reg3=0xa0a0018,reg4=0x20050/0x7ffff actions=ct(commit,table=AntreaPolicyEgressRule,zone=65520,nat(dst=10.10.0.24:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))
3. table=EndpointDNAT, priority=200,tcp,reg3=0xa0a0106,reg4=0x20050/0x7ffff actions=ct(commit,table=AntreaPolicyEgressRule,zone=65520,nat(dst=10.10.1.6:80),exec(set_field:0x10/0x10->ct_mark,move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))
4. table=EndpointDNAT, priority=190,reg4=0x20000/0x70000 actions=set_field:0x10000/0x70000->reg4,resubmit(,ServiceLB)
5. table=EndpointDNAT, priority=0 actions=goto_table:AntreaPolicyEgressRule
```

Flow 1 is designed for Services without Endpoints. It identifies the first packet of connections destined for such Service
by matching `SvcNoEpRegMark`. Subsequently, the packet is forwarded to the OpenFlow controller (Antrea Agent). For TCP
Service traffic, the controller will send a TCP RST, and for all other cases the controller will send an ICMP Destination
Unreachable message.

Flows 2-3 are designed for Services that have selected an Endpoint. These flows identify the first packet of connections
destined for such Services by matching `EndpointPortField`, which stores the Endpoint IP, and `EpUnionField` (a combination
of `EndpointPortField` storing the Endpoint port and `EpSelectedRegMark`). Then `ct` action is invoked on the packet,
performing DNAT'd and forwarding it to table [ConntrackState] with the "tracked" state associated with `CtZone`.
Some bits of ct mark are persisted:

- `ServiceCTMark`, to be consumed in tables [L3Forwarding] and [ConntrackCommit], indicating that the current packet and
  subsequent packets of the connection are for a Service.
- The value of `PktSourceField` is persisted to `ConnSourceCTMarkField`, storing the source of the connection for the
  current packet and subsequent packets of the connection.

Flow 4 is to resubmit the packets which are not matched by flows 1-3 back to table [ServiceLB] to select Endpoint again.

Flow 5 is the table-miss flow to match non-Service packets.

### AntreaPolicyEgressRule

This table is used to implement the egress rules across all Antrea-native NetworkPolicies, except for NetworkPolicies
that are created in the Baseline Tier. Antrea-native NetworkPolicies created in the Baseline Tier will be enforced after
K8s NetworkPolicies and their egress rules are installed in tables [EgressDefaultRule] and [EgressRule] respectively, i.e.

```text
Antrea-native NetworkPolicy other Tiers    ->  AntreaPolicyEgressRule
K8s NetworkPolicy                          ->  EgressRule
Antrea-native NetworkPolicy Baseline Tier  ->  EgressDefaultRule
```

Antrea-native NetworkPolicy relies on the OVS built-in `conjunction` action to implement policies efficiently. This
enables us to do a conjunctive match across multiple dimensions (source IP, destination IP, port, etc.) efficiently
without "exploding" the number of flows. For our use case, we have at most 3 dimensions.

The only requirement of `conj_id` is to be a unique 32-bit integer within the table. At the moment we use a single
custom allocator, which is common to all tables that can have NetworkPolicy flows installed
([AntreaPolicyEgressRule], [EgressRule], [EgressDefaultRule], [AntreaPolicyIngressRule], [IngressRule], and
[IngressDefaultRule]).

For this table, you will need to keep in mind the Antrea-native NetworkPolicy
[specification](#antrea-native-networkpolicy-implementation). Since the sample egress policy resides in the Application
Tie, if you dump the flows of this table, you may see the following:

```text
1. table=AntreaPolicyEgressRule, priority=64990,ct_state=-new+est,ip actions=goto_table:EgressMetric
2. table=AntreaPolicyEgressRule, priority=64990,ct_state=-new+rel,ip actions=goto_table:EgressMetric
3. table=AntreaPolicyEgressRule, priority=14500,ip,nw_src=10.10.0.24 actions=conjunction(7,1/3)
4. table=AntreaPolicyEgressRule, priority=14500,ip,nw_dst=10.10.0.25 actions=conjunction(7,2/3)
5. table=AntreaPolicyEgressRule, priority=14500,tcp,tp_dst=3306 actions=conjunction(7,3/3)
6. table=AntreaPolicyEgressRule, priority=14500,conj_id=7,ip actions=set_field:0x7->reg5,ct(commit,table=EgressMetric,zone=65520,exec(set_field:0x700000000/0xffffffff00000000->ct_label))
7. table=AntreaPolicyEgressRule, priority=14499,ip,nw_src=10.10.0.24 actions=conjunction(5,1/2)
8. table=AntreaPolicyEgressRule, priority=14499,ip actions=conjunction(5,2/2)
9. table=AntreaPolicyEgressRule, priority=14499,conj_id=5 actions=set_field:0x5->reg3,set_field:0x400/0x400->reg0,goto_table:EgressMetric
10. table=AntreaPolicyEgressRule, priority=0 actions=goto_table:EgressRule
```

Flows 1-2, which are installed by default with the highest priority, match non-new and "tracked" packets and
forward them to table [EgressMetric] to bypass the check from egress rules. This means that if a connection is
established, its packets go straight to table [EgressMetric], with no other match required. In particular, this ensures
that reply traffic is never dropped because of an Antrea-native NetworkPolicy or K8s NetworkPolicy rule. However, this
also means that ongoing connections are not affected if the Antrea-native NetworkPolicy or the K8s NetworkPolicy is
updated.

The priorities of flows 3-9 installed for the egress rules are decided by the following:

- The `spec.tier` value in an Antrea-native NetworkPolicy determines the primary level for flow priority.
- The `spec.priority` value in an Antrea-native NetworkPolicy determines the secondary level for flow priority within
  the same `spec.tier`. A lower value in this field corresponds to a higher priority for the flow.
- The rule's position within an Antrea-native NetworkPolicy also influences flow priority. Rules positioned closer to
  the beginning have higher priority for the flow.

Flows 3-6, whose priorities are all 14500, are installed for the egress rule `AllowToDB` in the sample policy. These
flows are described as follows:

- Flow 3 is used to match packets with the source IP address in set {10.10.0.24}, which has all IP addresses of the Pods
  selected by the label `app: web`, constituting the first dimension for `conjunction` with `conj_id` 7.
- Flow 4 is used to match packets with the destination IP address in set {10.10.0.25}, which has all IP addresses of
  the Pods selected by the label `app: db`, constituting the second dimension for `conjunction` with `conj_id` 7.
- Flow 5 is used to match packets with the destination TCP port in set {3306} specified in the rule, constituting the
  third dimension for `conjunction` with `conj_id` 7.
- Flow 6 is used to match packets meeting all the three dimensions of `conjunction` with `conj_id` 7 and forward them
  to table [EgressMetric], persisting `conj_id` to `EgressRuleCTLabel`, which will be consumed in table [EgressMetric].

Flows 7-9, whose priorities are all 14499, are installed for the egress rule with a `Drop` action defined after the rule
`AllowToDB` in the sample policy, and serves as a default rule. Antrea-native NetworkPolicy does not have the same
default isolated behavior as K8s NetworkPolicy (implemented in the [EgressDefaultRule] table). As soon as a rule is
matched, we apply the corresponding action. If no rule is matched, there is no implicit drop for Pods to which an
Antrea-native NetworkPolicy applies. These flows are described as follows:

- Flow 7 is used to match packets with the source IP address in set {10.10.0.24}, which is from the Pods selected
  by the label `app: web`, constituting the first dimension for `conjunction` with `conj_id` 5.
- Flow 8 is used to match any IP packets, constituting the second dimension for `conjunction` with `conj_id` 5. This
  flow, which matches all IP packets, exists because we need at least 2 dimensions for a conjunctive match.
- Flow 9 is used to match packets meeting both dimensions of `conjunction` with `conj_id` 5. `APDenyRegMark` is
  loaded and will be consumed in table [EgressMetric] to which the packets are forwarded.

Flow 10 is the table-miss flow to forward packets not matched by other flows to table [EgressMetric].

### EgressRule

For this table, you will need to keep in mind the K8s NetworkPolicy
[specification](#kubernetes-networkpolicy-implementation) that we are using.

This table is used to implement the egress rules across all K8s NetworkPolicies. If you dump the flows for this table,
you may see the following:

```text
1. table=EgressRule, priority=200,ip,nw_src=10.10.0.24 actions=conjunction(2,1/3)
2. table=EgressRule, priority=200,ip,nw_dst=10.10.0.25 actions=conjunction(2,2/3)
3. table=EgressRule, priority=200,tcp,tp_dst=3306 actions=conjunction(2,3/3)
4. table=EgressRule, priority=190,conj_id=2,ip actions=set_field:0x2->reg5,ct(commit,table=EgressMetric,zone=65520,exec(set_field:0x200000000/0xffffffff00000000->ct_label))
5. table=EgressRule, priority=0 actions=goto_table:EgressDefaultRule
```

Flows 1-4 are installed for the egress rule in the sample K8s NetworkPolicy. These flows are described as follows:

- Flow 1 is to match packets with the source IP address in set {10.10.0.24}, which has all IP addresses of the Pods
  selected by the label `app: web` in the `default` Namespace, constituting the first dimension for `conjunction` with `conj_id` 2.
- Flow 2 is to match packets with the destination IP address in set {10.10.0.25}, which has all IP addresses of the Pods
  selected by the label `app: db` in the `default` Namespace, constituting the second dimension for `conjunction` with `conj_id` 2.
- Flow 3 is to match packets with the destination TCP port in set {3306} specified in the rule, constituting the third
  dimension for `conjunction` with `conj_id` 2.
- Flow 4 is to match packets meeting all the three dimensions of `conjunction` with `conj_id` 2 and forward them to
  table [EgressMetric], persisting `conj_id` to `EgressRuleCTLabel`.

Flow 5 is the table-miss flow to forward packets not matched by other flows to table [EgressDefaultRule].

### EgressDefaultRule

This table complements table [EgressRule] for K8s NetworkPolicy egress rule implementation. When a NetworkPolicy is
applied to a set of Pods, then the default behavior for egress connections for these Pods becomes "deny" (they become [isolated
Pods](https://kubernetes.io/docs/concepts/services-networking/network-policies/#isolated-and-non-isolated-pods)).
This table is in charge of dropping traffic originating from Pods to which a NetworkPolicy (with an egress rule) is
applied, and which did not match any of the "allowed" list rules.

If you dump the flows of this table, you may see the following:

```text
1. table=EgressDefaultRule, priority=200,ip,nw_src=10.10.0.24 actions=drop
2. table=EgressDefaultRule, priority=0 actions=goto_table:EgressMetric
```

Flow 1, based on our sample K8s NetworkPolicy, is to drop traffic originating from 10.10.0.24, an IP address associated
with a Pod selected by the label `app: web`. If there are multiple Pods being selected by the label `app: web`, you will
see multiple similar flows for each IP address.

Flow 2 is the table-miss flow to forward packets to table [EgressMetric].

This table is also used to implement Antrea-native NetworkPolicy egress rules that are created in the Baseline Tier.
Since the Baseline Tier is meant to be enforced after K8s NetworkPolicies, the corresponding flows will be created at a
lower priority than K8s NetworkPolicy default drop flows. These flows are similar to flows 3-9 in table
[AntreaPolicyEgressRule]. For the sake of simplicity, we have not defined any example Baseline policies in this document.

### EgressMetric

This table is used to collect egress metrics for Antrea-native NetworkPolicies and K8s NetworkPolicies.

If you dump the flows of this table, you may see the following:

```text
1. table=EgressMetric, priority=200,ct_state=+new,ct_label=0x200000000/0xffffffff00000000,ip actions=goto_table:L3Forwarding
2. table=EgressMetric, priority=200,ct_state=-new,ct_label=0x200000000/0xffffffff00000000,ip actions=goto_table:L3Forwarding
3. table=EgressMetric, priority=200,ct_state=+new,ct_label=0x700000000/0xffffffff00000000,ip actions=goto_table:L3Forwarding
4. table=EgressMetric, priority=200,ct_state=-new,ct_label=0x700000000/0xffffffff00000000,ip actions=goto_table:L3Forwarding
5. table=EgressMetric, priority=200,reg0=0x400/0x400,reg3=0x5 actions=drop
6. table=EgressMetric, priority=0 actions=goto_table:L3Forwarding
```

Flows 1-2, matching packets with `EgressRuleCTLabel` set to 2, the `conj_id` allocated for the sample K8s NetworkPolicy
egress rule and loaded in table [EgressRule] flow 4, are used to collect metrics for the egress rule.

Flows 3-4, matching packets with `EgressRuleCTLabel` set to 7, the `conj_id` allocated for the sample Antrea-native
NetworkPolicy egress rule and loaded in table [AntreaPolicyEgressRule] flow 6, are used to collect metrics for the
egress rule.

Flow 5 serves as the drop rule for the sample Antrea-native NetworkPolicy egress rule. It drops the packets by matching
`APDenyRegMark` loaded in table [AntreaPolicyEgressRule] flow 9 and `APConjIDField` set to 5 which is the `conj_id`
allocated the egress rule and loaded in table [AntreaPolicyEgressRule] flow 9.

These flows have no explicit action besides the `goto_table` action. This is because we rely on the "implicit" flow
counters to keep track of connection / packet statistics.

Ct label is used in flows 1-4, while reg is used in flow 5. The distinction lies in the fact that the value persisted in
the ct label can be read throughout the entire lifecycle of a connection, but the reg mark is only valid for the current
packet. For a connection permitted by a rule, all its packets should be collected for metrics, thus a ct label is used.
For a connection denied or dropped by a rule, the first packet and the subsequent retry packets will be blocked,
therefore a reg is enough.

Flow 6 is the table-miss flow.

### L3Forwarding

This table, designated as the L3 routing table, serves to assign suitable source and destination MAC addresses to
packets based on their destination IP addresses, as well as their reg marks or ct marks.

If you dump the flows of this table, you may see the following:

```text
1. table=L3Forwarding, priority=210,ip,nw_dst=10.10.0.1 actions=set_field:ba:5e:d1:55:aa:c0->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL
2. table=L3Forwarding, priority=210,ct_state=+rpl+trk,ct_mark=0x2/0xf,ip actions=set_field:ba:5e:d1:55:aa:c0->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL
3. table=L3Forwarding, priority=200,ip,reg0=0/0x200,nw_dst=10.10.0.0/24 actions=goto_table:L2ForwardingCalc
4. table=L3Forwarding, priority=200,ip,nw_dst=10.10.1.0/24 actions=set_field:ba:5e:d1:55:aa:c0->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:192.168.77.103->tun_dst,set_field:0x10/0xf0->reg0,goto_table:L3DecTTL
5. table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.24 actions=set_field:ba:5e:d1:55:aa:c0->eth_src,set_field:fa:b7:53:74:21:a6->eth_dst,goto_table:L3DecTTL
6. table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.25 actions=set_field:ba:5e:d1:55:aa:c0->eth_src,set_field:36:48:21:a2:9d:b4->eth_dst,goto_table:L3DecTTL
7. table=L3Forwarding, priority=200,ip,reg0=0x200/0x200,nw_dst=10.10.0.26 actions=set_field:ba:5e:d1:55:aa:c0->eth_src,set_field:5e:b5:e3:a6:90:b7->eth_dst,goto_table:L3DecTTL
8. table=L3Forwarding, priority=190,ct_state=-rpl+trk,ip,reg0=0x3/0xf,reg4=0/0x100000 actions=goto_table:EgressMark
9. table=L3Forwarding, priority=190,ct_state=-rpl+trk,ip,reg0=0x1/0xf actions=set_field:ba:5e:d1:55:aa:c0->eth_dst,goto_table:EgressMark
10. table=L3Forwarding, priority=190,ct_mark=0x10/0x10,reg0=0x202/0x20f actions=set_field:ba:5e:d1:55:aa:c0->eth_dst,set_field:0x20/0xf0->reg0,goto_table:L3DecTTL
11. table=L3Forwarding, priority=0 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc
```

Flow 1 matches packets destined for the local Antrea gateway IP, rewrites their destination MAC address to that of the
local Antrea gateway, loads `ToGatewayRegMark`, and forwards them to table [L3DecTTL] to decrease TTL value. The action
of rewriting the destination MAC address is not necessary but not harmful for Pod-to-gateway request packets because the
destination MAC address is already the local gateway MAC address. In short, the action is only necessary for
`AntreaIPAM` Pods, not required by the sample NodeIPAM Pods in this document.

Flow 2 matches reply packets with corresponding ct "tracked" states and `FromGatewayCTMark` from connections initiated
through the local Antrea gateway. In other words, these are connections for which the first packet of the connection
(SYN packet for TCP) was received through the local Antrea gateway. It rewrites the destination MAC address to
that of the local Antrea gateway, loads `ToGatewayRegMark`, and forwards them to table [L3DecTTL]. This ensures that
reply packets can be forwarded back to the local Antrea gateway in subsequent tables. This flow is required to handle
the following cases when Antrea Proxy is not enabled:

- Reply traffic for connections from a local Pod to a ClusterIP Service, which are handled by kube-proxy and go through
  DNAT. In this case, the destination IP address of the reply traffic is the Pod which initiated the connection to the
  Service (no SNAT by kube-proxy). These packets should be forwarded back to the local Antrea gateway to the third-party module
  to complete the DNAT processes, e.g., kube-proxy. The destination MAC of the packets is rewritten in the table to
  avoid it is forwarded to the original client Pod by mistake.
- When hairpin is involved, i.e. connections between 2 local Pods, for which NAT is performed. One example is a
  Pod accessing a NodePort Service for which externalTrafficPolicy is set to `Local` using the local Node's IP address,
  as there will be no SNAT for such traffic. Another example could be hostPort support, depending on how the feature
  is implemented.

Flow 3 matches packets from intra-Node connections (excluding Service connections) and marked with
`NotRewriteMACRegMark`, indicating that the destination and source MACs of packets should not be overwritten, and
forwards them to table [L2ForwardingCalc] instead of table [L3DecTTL]. The deviation is due to local Pods connections
not traversing any router device or undergoing NAT process. For packets from Service or inter-Node connections,
`RewriteMACRegMark`, mutually exclusive with `NotRewriteMACRegMark`, is loaded. Therefore, the packets will not be
matched by the flow.

Flow 4 is designed to match packets destined for a remote Pod CIDR. This involves installing a separate flow for each remote
Node, with each flow matching the destination IP address of the packets against the Pod subnet for the respective Node.
For the matched packets, the source MAC address is set to that of the local Antrea gateway MAC, and the destination
MAC address is set to the *Global Virtual MAC*. The Openflow `tun_dst` field is set to the appropriate value (i.e.
the IP address of the remote Node). Additionally, `ToTunnelRegMark` is loaded, signifying that the packets will be
forwarded to remote Nodes through a tunnel. The matched packets are then forwarded to table [L3DecTTL] to decrease the TTL
value.

Flow 5-7 matches packets destined for local Pods and marked by `RewriteMACRegMark`, which signifies that the packets may
originate from Service or inter-Node connections. For the matched packets, the source MAC address is set to that of the
local Antrea gateway MAC, and the destination MAC address is set to the associated local Pod MAC address. The matched
packets are then forwarded to table [L3DecTTL] to decrease the TTL value.

Flow 8 matches request packets originating from local Pods and destined for the external network, and then forwards them
to table [EgressMark] dedicated to feature `Egress`. In table [EgressMark], SNAT IPs for Egress are looked up for the packets.
To match the expected packets, `FromPodRegMark` is used to exclude packets that are not from local Pods.
Additionally, `NotAntreaFlexibleIPAMRegMark`, mutually exclusive with `AntreaFlexibleIPAMRegMark` which is used to mark
packets from Antrea IPAM Pods, is used since Egress can only be applied to Node IPAM Pods.

It's worth noting that packets sourced from local Pods and destined for the Services listed in the option
`antreaProxy.skipServices` are unexpectedly matched by flow 8 due to the fact that there is no flow in [ServiceLB]
to handle these Services. Consequently, the destination IP address of the packets, allocated from the Service CIDR,
is considered part of the "external network". No need to worry about the mismatch, as flow 3 in table [EgressMark]
is designed to match these packets and prevent them from undergoing SNAT by Egress.

Flow 9 matches request packets originating from remote Pods and destined for the external network, and then forwards them
to table [EgressMark] dedicated to feature `Egress`. To match the expected packets, `FromTunnelRegMark` is used to
include packets that are from remote Pods through a tunnel. Considering that the packets from remote Pods traverse a
tunnel, the destination MAC address of the packets, represented by the *Global Virtual MAC*, needs to be rewritten to
MAC address of the local Antrea gateway.

Flow 10 matches packets from Service connections that are originating from the local Antrea gateway and destined for the
external network. This is accomplished by matching `RewriteMACRegMark`, `FromGatewayRegMark`, and `ServiceCTMark`. The
destination MAC address is then set to that of the local Antrea gateway. Additionally, `ToGatewayRegMark`, which will be
used with `FromGatewayRegMark` together to identify hairpin connections in table [SNATMark], is loaded. Finally,
the packets are forwarded to table [L3DecTTL].

Flow 11 is the table-miss flow, and is used for packets originating from local Pods and destined for the external network, and
then forwarding them to table [L2ForwardingCalc]. `ToGatewayRegMark` is loaded as the matched packets traverse the
local Antrea gateway.

### EgressMark

This table is dedicated to feature `Egress`. It includes flows to select the right SNAT IPs for egress traffic
originating from Pods and destined for the external network.

If you dump the flows of this table, you may see the following:

```text
1. table=EgressMark, priority=210,ip,nw_dst=192.168.77.102 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc
2. table=EgressMark, priority=210,ip,nw_dst=192.168.77.103 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc
3. table=EgressMark, priority=210,ip,nw_dst=10.96.0.0/12 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc
4. table=EgressMark, priority=200,ip,in_port="client-6-3353ef" actions=set_field:ba:5e:d1:55:aa:c0->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:192.168.77.113->tun_dst,set_field:0x10/0xf0->reg0,set_field:0x80000/0x80000->reg0,goto_table:L2ForwardingCalc
5. table=EgressMark, priority=200,ct_state=+new+trk,ip,tun_dst=192.168.77.112 actions=set_field:0x1/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc
6. table=EgressMark, priority=200,ct_state=+new+trk,ip,in_port="web-7975-274540" actions=set_field:0x1/0xff->pkt_mark,set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc
7. table=EgressMark, priority=190,ct_state=+new+trk,ip,reg0=0x1/0xf actions=drop
8. table=EgressMark, priority=0 actions=set_field:0x20/0xf0->reg0,goto_table:L2ForwardingCalc
```

Flows 1-2 match packets originating from local Pods and destined for the transport IP of remote Nodes, and then forward
them to table [L2ForwardingCalc] to bypass Egress SNAT. `ToGatewayRegMark` is loaded, indicating that the output port
of the packets is the local Antrea gateway.

Flow 3 matches packets originating from local Pods and destined for the Services listed in the option
`antreaProxy.skipServices`, and then forwards them to table [L2ForwardingCalc] to bypass Egress SNAT. Similar to flows
1-2, `ToGatewayRegMark` is also loaded.

The packets, matched by flows 1-3, are forwarded to this table by flow 8 in table [L3Forwarding], as they are classified
as part of traffic destined for the external network. However, these packets are not intended to undergo Egress SNAT.
Consequently, flows 1-3 are used to bypass Egress SNAT for these packets.

Flow 4 match packets originating from local Pods selected by the sample [Egress egress-client], whose SNAT IP is configured
on a remote Node, which means that the matched packets should be forwarded to the remote Node through a tunnel. Before
sending the packets to the tunnel, the source and destination MAC addresses are set to the local Antrea gateway MAC
and the *Global Virtual MAC* respectively. Additionally, `ToTunnelRegMark`, indicating that the output port is a tunnel,
and `EgressSNATRegMark`, indicating that packets should undergo SNAT on a remote Node, are loaded. Finally, the packets
are forwarded to table [L2ForwardingCalc].

Flow 5 matches the first packet of connections originating from remote Pods selected by the sample [Egress egress-web]
whose SNAT IP is configured on the local Node, and then loads an 8-bit ID allocated for the associated SNAT IP defined
in the sample Egress to the `pkt_mark`, which will be consumed by iptables on the local Node to perform SNAT with the
SNAT IP. Subsequently, `ToGatewayRegMark`, indicating that the output port is the local Antrea gateway, is loaded.
Finally, the packets are forwarded to table [L2ForwardingCalc].

Flow 6 matches the first packet of connections originating from local Pods selected by the sample [Egress egress-web],
whose SNAT IP is configured on the local Node. Similar to flow 4, the 8-bit ID allocated for the SNAT IP is loaded to
`pkt_mark`, `ToGatewayRegMark` is loaded, and the packets are forwarded to table [L2ForwardingCalc] finally.

Flow 7 drops all other packets tunneled from remote Nodes (identified with `FromTunnelRegMark`, indicating that the packets are
from remote Pods through a tunnel). The packets are not matched by any flows 1-6, which means that they are here
unexpected and should be dropped.

Flow 8 is the table-miss flow, which matches "tracked" and non-new packets from Egress connections and forwards
them to table [L2ForwardingCalc]. `ToGatewayRegMark` is also loaded for these packets.

### L3DecTTL

This is the table to decrement TTL for IP packets.

If you dump the flows of this table, you may see the following:

```text
1. table=L3DecTTL, priority=210,ip,reg0=0x2/0xf actions=goto_table:SNATMark
2. table=L3DecTTL, priority=200,ip actions=dec_ttl,goto_table:SNATMark
3. table=L3DecTTL, priority=0 actions=goto_table:SNATMark
```

Flow 1 matches packets with `FromGatewayRegMark`, which means that these packets enter the OVS pipeline from the local
Antrea gateway, as the host IP stack should have decremented the TTL already for such packets, TTL should not be
decremented again.

Flow 2 is to decrement TTL for packets which are not matched by flow 1.

Flow 3 is the table-miss flow that should remain unused.

### SNATMark

This table marks connections requiring SNAT within the OVS pipeline, distinct from Egress SNAT handled by iptables.

If you dump the flows of this table, you may see the following:

```text
1. table=SNATMark, priority=200,ct_state=+new+trk,ip,reg0=0x22/0xff actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))
2. table=SNATMark, priority=200,ct_state=+new+trk,ip,reg0=0x12/0xff,reg4=0x200000/0x2200000 actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark))
3. table=SNATMark, priority=190,ct_state=+new+trk,ip,nw_src=10.10.0.23,nw_dst=10.10.0.23 actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))
4. table=SNATMark, priority=190,ct_state=+new+trk,ip,nw_src=10.10.0.24,nw_dst=10.10.0.24 actions=ct(commit,table=SNAT,zone=65520,exec(set_field:0x20/0x20->ct_mark,set_field:0x40/0x40->ct_mark))
5. table=SNATMark, priority=0 actions=goto_table:SNAT
```

Flow 1 matches the first packet of hairpin Service connections, identified by `FromGatewayRegMark` and `ToGatewayRegMark`,
indicating that both the input and output ports of the connections are the local Antrea gateway port. Such hairpin
connections will undergo SNAT with the *Virtual Service IP* in table [SNAT]. Before forwarding the packets to table
[SNAT], `ConnSNATCTMark`, indicating that the connection requires SNAT, and `HairpinCTMark`, indicating that this is
a hairpin connection, are persisted to mark the connections. These two ct marks will be consumed in table [SNAT].

Flow 2 matches the first packet of Service connections requiring SNAT, identified by `FromGatewayRegMark` and
`ToTunnelRegMark`, indicating that the input port is the local Antrea gateway and the output port is a tunnel. Such
connections will undergo SNAT with the IP address of the local Antrea gateway in table [SNAT]. Before forwarding the
packets to table [SNAT], `ToExternalAddressRegMark` and `NotDSRServiceRegMark` are loaded, indicating that the packets
are destined for a Service's external IP, like NodePort, LoadBalancerIP or ExternalIP, but it is not DSR mode.
Additionally, `ConnSNATCTMark`, indicating that the connection requires SNAT, is persisted to mark the connections.

It's worth noting that flows 1-2 are specific to `proxyAll`, but they are harmless when `proxyAll` is disabled since
these flows should be never matched by in-cluster Service traffic.

Flow 3-4 match the first packet of hairpin Service connections, identified by the same source and destination Pod IP
addresses. Such hairpin connections will undergo SNAT with the IP address of the local Antrea gateway in table [SNAT].
Similar to flow 1, `ConnSNATCTMark` and `HairpinCTMark` are persisted to mark the connections.

Flow 5 is the table-miss flow.

### SNAT

This table performs SNAT for connections requiring SNAT within the pipeline.

If you dump the flows of this table, you may see the following:

```text
1. table=SNAT, priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ip,reg0=0x2/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65521,nat(src=169.254.0.253),exec(set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))
2. table=SNAT, priority=200,ct_state=+new+trk,ct_mark=0x40/0x40,ip,reg0=0x3/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65521,nat(src=10.10.0.1),exec(set_field:0x10/0x10->ct_mark,set_field:0x40/0x40->ct_mark))
3. table=SNAT, priority=200,ct_state=-new-rpl+trk,ct_mark=0x20/0x20,ip actions=ct(table=L2ForwardingCalc,zone=65521,nat)
4. table=SNAT, priority=190,ct_state=+new+trk,ct_mark=0x20/0x20,ip,reg0=0x2/0xf actions=ct(commit,table=L2ForwardingCalc,zone=65521,nat(src=10.10.0.1),exec(set_field:0x10/0x10->ct_mark))
5. table=SNAT, priority=0 actions=goto_table:L2ForwardingCalc
```

Flow 1 matches the first packet of hairpin Service connections through the local Antrea gateway, identified by
`HairpinCTMark` and `FromGatewayRegMark`. It performs SNAT with the *Virtual Service IP* `169.254.0.253` and forwards
the SNAT'd packets to table [L2ForwardingCalc]. Before SNAT, the "tracked" state of packets is associated with `CtZone`.
After SNAT, their "track" state is associated with `SNATCtZone`, and then `ServiceCTMark` and `HairpinCTMark` persisted
in `CtZone` are not accessible anymore. As a result, `ServiceCTMark` and `HairpinCTMark` need to be persisted once
again, but this time they are persisted in `SNATCtZone` for subsequent tables to consume.

Flow 2 matches the first packet of hairpin Service connection originating from local Pods, identified by `HairpinCTMark`
and `FromPodRegMark`. It performs SNAT with the IP address of the local Antrea gateway and forwards the SNAT'd packets
to table [L2ForwardingCalc]. Similar to flow 1, `ServiceCTMark` and `HairpinCTMark` are persisted in `SNATCtZone`.

Flow 3 matches the subsequent request packets of connections for which SNAT was performed for the first packet, and then
invokes `ct` action on the packets again to restore the "tracked" state in `SNATCtZone`. The packets with the appropriate
"tracked" state are forwarded to table [L2ForwardingCalc].

Flow 4 matches the first packet of Service connections requiring SNAT, identified by `ConnSNATCTMark` and
`FromGatewayRegMark`, indicating the connection is destined for an external Service IP initiated through the
Antrea gateway and the Endpoint is a remote Pod. It performs SNAT with the IP address of the local Antrea gateway and
forwards the SNAT'd packets to table [L2ForwardingCalc]. Similar to other flow 1 or 2, `ServiceCTMark` is persisted in
`SNATCtZone`.

Flow 5 is the table-miss flow.

### L2ForwardingCalc

This is essentially the "dmac" table of the switch. We program one flow for each port (tunnel port, the local Antrea
gateway port, and local Pod ports).

If you dump the flows of this table, you may see the following:

```text
1. table=L2ForwardingCalc, priority=200,dl_dst=ba:5e:d1:55:aa:c0 actions=set_field:0x2->reg1,set_field:0x200000/0x600000->reg0,goto_table:TrafficControl
2. table=L2ForwardingCalc, priority=200,dl_dst=aa:bb:cc:dd:ee:ff actions=set_field:0x1->reg1,set_field:0x200000/0x600000->reg0,goto_table:TrafficControl
3. table=L2ForwardingCalc, priority=200,dl_dst=5e:b5:e3:a6:90:b7 actions=set_field:0x24->reg1,set_field:0x200000/0x600000->reg0,goto_table:TrafficControl
4. table=L2ForwardingCalc, priority=200,dl_dst=fa:b7:53:74:21:a6 actions=set_field:0x25->reg1,set_field:0x200000/0x600000->reg0,goto_table:TrafficControl
5. table=L2ForwardingCalc, priority=200,dl_dst=36:48:21:a2:9d:b4 actions=set_field:0x26->reg1,set_field:0x200000/0x600000->reg0,goto_table:TrafficControl
6. table=L2ForwardingCalc, priority=0 actions=goto_table:TrafficControl
```

Flow 1 matches packets destined for the local Antrea gateway, identified by the destination MAC address being that of
the local Antrea gateway. It loads `OutputToOFPortRegMark`, indicating that the packets should output to an OVS port,
and also loads the port number of the local Antrea gateway to `TargetOFPortField`. Both of these two values will be consumed
in table [Output].

Flow 2 matches packets destined for a tunnel, identified by the destination MAC address being that of the *Global Virtual
MAC*. Similar to flow 1, `OutputToOFPortRegMark` is loaded, and the port number of the tunnel is loaded to
`TargetOFPortField`.

Flows 3-5 match packets destined for local Pods, identified by the destination MAC address being that of one of the local
Pods. Similar to flow 1, `OutputToOFPortRegMark` is loaded, and the port number of the local Pods is loaded to
`TargetOFPortField`.

Flow 6 is the table-miss flow.

### TrafficControl

This table is dedicated to `TrafficControl`.

If you dump the flows of this table, you may see the following:

```text
1. table=TrafficControl, priority=210,reg0=0x200006/0x60000f actions=goto_table:Output
2. table=TrafficControl, priority=200,reg1=0x25 actions=set_field:0x22->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier
3. table=TrafficControl, priority=200,in_port="web-7975-274540" actions=set_field:0x22->reg9,set_field:0x800000/0xc00000->reg4,goto_table:IngressSecurityClassifier
4. table=TrafficControl, priority=200,reg1=0x26 actions=set_field:0x27->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier
5. table=TrafficControl, priority=200,in_port="db-755c6-5080e3" actions=set_field:0x27->reg9,set_field:0x400000/0xc00000->reg4,goto_table:IngressSecurityClassifier
6. table=TrafficControl, priority=0 actions=goto_table:IngressSecurityClassifier
```

Flow 1 matches packets returned from TrafficControl return ports and forwards them to table [Output], where the packets
are output to the port to which they are destined. To identify such packets, `OutputToOFPortRegMark`, indicating that
the packets should be output to an OVS port, and `FromTCReturnRegMark` loaded in table [Classifier], indicating that
the packets are from a TrafficControl return port, are used.

Flows 2-3 are installed for the sample [TrafficControl redirect-web-to-local] to mark the packets associated with the
Pods labeled by `app: web` using `TrafficControlRedirectRegMark`. Flow 2 handles the ingress direction, while flow 3
handles the egress direction. In table [Output], these packets will be redirected to a TrafficControl target port
specified in `TrafficControlTargetOFPortField`, of which value is loaded in these 2 flows.

Flows 4-5 are installed for the sample [TrafficControl mirror-db-to-local] to mark the packets associated with the Pods
labeled by `app: db` using `TrafficControlMirrorRegMark`. Similar to flows 2-3, flows 4-5 also handles the two directions.
In table [Output], these packets will be mirrored (duplicated) to a TrafficControl target port specified in
`TrafficControlTargetOFPortField`, of which value is loaded in these 2 flows.

Flow 6 is the table-miss flow.

### IngressSecurityClassifier

This table is to classify packets before they enter the tables for ingress security.

If you dump the flows of this table, you may see the following:

```text
1. table=IngressSecurityClassifier, priority=210,pkt_mark=0x80000000/0x80000000,ct_state=-rpl+trk,ip actions=goto_table:ConntrackCommit
2. table=IngressSecurityClassifier, priority=201,reg4=0x80000/0x80000 actions=goto_table:AntreaPolicyIngressRule
3. table=IngressSecurityClassifier, priority=200,reg0=0x20/0xf0 actions=goto_table:IngressMetric
4. table=IngressSecurityClassifier, priority=200,reg0=0x10/0xf0 actions=goto_table:IngressMetric
5. table=IngressSecurityClassifier, priority=200,reg0=0x40/0xf0 actions=goto_table:IngressMetric
6. table=IngressSecurityClassifier, priority=200,ct_mark=0x40/0x40 actions=goto_table:ConntrackCommit
7. table=IngressSecurityClassifier, priority=0 actions=goto_table:AntreaPolicyIngressRule
```

Flow 1 matches locally generated request packets for liveness/readiness probes from kubelet, identified by `pkt_mark`
which is set by iptables in the host network namespace. It forwards the packets to table [ConntrackCommit] directly to
bypass all tables for ingress security.

Flow 2 matches packets destined for NodePort Services and forwards them to table [AntreaPolicyIngressRule] to enforce
Antrea-native NetworkPolicies applied to NodePort Services. Without this flow, if the selected Endpoint is not a local
Pod, the packets might be matched by one of the flows 3-5, skipping table [AntreaPolicyIngressRule].

Flows 3-5 matches packets destined for the local Antrea gateway, tunnel, uplink port with `ToGatewayRegMark`,
`ToTunnelRegMark` or `ToUplinkRegMark`, respectively, and forwards them to table [IngressMetric] directly to bypass
all tables for ingress security.

Flow 5 matches packets from hairpin connections with `HairpinCTMark` and forwards them to table [ConntrackCommit]
directly to bypass all tables for ingress security. Refer to this PR
[#5687](https://github.com/antrea-io/antrea/pull/5687) for more information.

Flow 6 is the table-miss flow.

### AntreaPolicyIngressRule

This table is very similar to table [AntreaPolicyEgressRule] but implements the ingress rules of Antrea-native
NetworkPolicies. Depending on the tier to which the policy belongs, the rules will be installed in a table corresponding
to that tier. The ingress table to tier mappings is as follows:

```text
Antrea-native NetworkPolicy other Tiers    ->  AntreaPolicyIngressRule
K8s NetworkPolicy                          ->  IngressRule
Antrea-native NetworkPolicy Baseline Tier  ->  IngressDefaultRule
```

Again for this table, you will need to keep in mind the Antrea-native NetworkPolicy
[specification](#antrea-native-networkpolicy-implementation) and Antrea-native L7 NetworkPolicy
[specification](#antrea-native-l7-networkpolicy-implementation) that we are using that we are using. Since these sample
ingress policies reside in the Application Tier, if you dump the flows for this table, you may see the following:

```text
1. table=AntreaPolicyIngressRule, priority=64990,ct_state=-new+est,ip actions=goto_table:IngressMetric
2. table=AntreaPolicyIngressRule, priority=64990,ct_state=-new+rel,ip actions=goto_table:IngressMetric
3. table=AntreaPolicyIngressRule, priority=14500,reg1=0x7 actions=conjunction(14,2/3)
4. table=AntreaPolicyIngressRule, priority=14500,ip,nw_src=10.10.0.26 actions=conjunction(14,1/3)
5. table=AntreaPolicyIngressRule, priority=14500,tcp,tp_dst=8080 actions=conjunction(14,3/3)
6. table=AntreaPolicyIngressRule, priority=14500,conj_id=14,ip actions=set_field:0xd->reg6,ct(commit,table=IngressMetric,zone=65520,exec(set_field:0xd/0xffffffff->ct_label,set_field:0x80/0x80->ct_mark,set_field:0x20000000000000000/0xfff0000000000000000->ct_label))
7. table=AntreaPolicyIngressRule, priority=14600,ip,nw_src=10.10.0.26 actions=conjunction(6,1/3)
8. table=AntreaPolicyIngressRule, priority=14600,reg1=0x25 actions=conjunction(6,2/3)
9. table=AntreaPolicyIngressRule, priority=14600,tcp,tp_dst=80 actions=conjunction(6,3/3)
10. table=AntreaPolicyIngressRule, priority=14600,conj_id=6,ip actions=set_field:0x6->reg6,ct(commit,table=IngressMetric,zone=65520,exec(set_field:0x6/0xffffffff->ct_label))
11. table=AntreaPolicyIngressRule, priority=14600,ip actions=conjunction(4,1/2)
12. table=AntreaPolicyIngressRule, priority=14599,reg1=0x25 actions=conjunction(4,2/2)
13. table=AntreaPolicyIngressRule, priority=14599,conj_id=4 actions=set_field:0x4->reg3,set_field:0x400/0x400->reg0,goto_table:IngressMetric
14. table=AntreaPolicyIngressRule, priority=0 actions=goto_table:IngressRule
```

Flows 1-2, which are installed by default with the highest priority, match non-new and "tracked" packets and
forward them to table [IngressMetric] to bypass the check from egress rules. This means that if a connection is
established, its packets go straight to table [IngressMetric], with no other match required. In particular, this ensures
that reply traffic is never dropped because of an Antrea-native NetworkPolicy or K8s NetworkPolicy rule. However, this
also means that ongoing connections are not affected if the Antrea-native NetworkPolicy or the K8s NetworkPolicy is
updated.

Similar to table [AntreaPolicyEgressRule], the priorities of flows 3-13 installed for the ingress rules are decided by
the following:

- The `spec.tier` value in an Antrea-native NetworkPolicy determines the primary level for flow priority.
- The `spec.priority` value in an Antrea-native NetworkPolicy determines the secondary level for flow priority within
  the same `spec.tier`. A lower value in this field corresponds to a higher priority for the flow.
- The rule's position within an Antrea-native NetworkPolicy also influences flow priority. Rules positioned closer to
  the beginning have higher priority for the flow.

Flows 3-6, whose priories are all 14500, are installed for the egress rule `AllowFromClientL7` in the sample policy.
These flows are described as follows:

- Flow 3 is used to match packets with the source IP address in set {10.10.0.26}, which has all IP addresses of the
  Pods selected by the label `app: client`, constituting the first dimension for `cojunction` with `conj_id` 14.
- Flow 4 is used to match packets with the output OVS port in set {0x25}, which has all the ports of the Pods selected
  by the label `app: web`, constituting the second dimension for `conjunction` with `conj_id` 14.
- Flow 5 is used to match packets with the destination TCP port in set {8080} specified in the rule, constituting the
  third dimension for `conjunction` with `conj_id` 14.
- Flow 6 is used to match packets meeting all the three dimensions of `conjunction` with `conj_id` 14 and forward them
  to table [IngressMetric], persisting `conj_id` to `IngressRuleCTLabel` consumed in table [IngressMetric].
  Additionally, for the L7 protocol:
  - `L7NPRedirectCTMark` is persisted, indicating the packets should be redirected to an application-aware engine to
    be filtered according to L7 rules, such as method `GET` and path `/api/v2/*` in the sample policy.
  - A VLAN ID allocated for the Antrea-native L7 NetworkPolicy is persisted in `L7NPRuleVlanIDCTLabel`, which will be
    consumed in table [Output].

Flows 7-11, whose priorities are 14600, are installed for the egress rule `AllowFromClient` in the sample policy.
These flows are described as follows:

- Flow 7 is used to match packets with the source IP address in set {10.10.0.26}, which has all IP addresses of the Pods
  selected by the label `app: client`, constituting the first dimension for `cojunction` with `conj_id` 6.
- Flow 8 is used to match packets with the output OVS port in set {0x25}, which has all the ports of the Pods selected
  by the label `app: web`, constituting the second dimension for `conjunction` with `conj_id` 6.
- Flow 9 is used to match packets with the destination TCP port in set {80} specified in the rule, constituting the
  third dimension for `conjunction` with `conj_id` 6.
- Flow 10 is used to match packets meeting all the three dimensions of `conjunction` with `conj_id` 6 and forward
  them to table [IngressMetric], persisting `conj_id` to `IngressRuleCTLabel` consumed in table [IngressMetric].

Flows 11-13, whose priorities are all 14599, are installed for the egress rule with a `Drop` action defined after the
rule `AllowFromClient` in the sample policy, serves as a default rule. Unlike the default of K8s NetworkPolicy,
Antrea-native NetworkPolicy has no default rule, and all rules should be explicitly defined. Hence, they are evaluated
as-is, and there is no need for a table [AntreaPolicyIngressDefaultRule]. These flows are described as follows:

- Flow 11 is used to match any IP packets, constituting the second dimension for `conjunction` with `conj_id` 4. This
  flow, which matches all IP packets, exists because we need at least 2 dimensions for a conjunctive match.
- Flow 12 is used to match packets with the output OVS port in set {0x25},  which has all the ports of the Pods
  selected by the label `app: web`, constituting the first dimension for `conjunction` with `conj_id` 4.
- Flow 13 is used to match packets meeting both dimensions of `conjunction` with `conj_id` 4. `APDenyRegMark` that
  will be consumed in table [IngressMetric] to which the packets are forwarded is loaded.

Flow 14 is the table-miss flow to forward packets not matched by other flows to table [IngressMetric].

### IngressRule

This table is very similar to table [EgressRule] but implements ingress rules for K8s NetworkPolicies. Once again, you
will need to keep in mind the K8s NetworkPolicy [specification](#kubernetes-networkpolicy-implementation) that we are
using.

If you dump the flows of this table, you should see something like this:

```text
1. table=IngressRule, priority=200,ip,nw_src=10.10.0.26 actions=conjunction(3,1/3)
2. table=IngressRule, priority=200,reg1=0x25 actions=conjunction(3,2/3)
3. table=IngressRule, priority=200,tcp,tp_dst=80 actions=conjunction(3,3/3)
4. table=IngressRule, priority=190,conj_id=3,ip actions=set_field:0x3->reg6,ct(commit,table=IngressMetric,zone=65520,exec(set_field:0x3/0xffffffff->ct_label))
5. table=IngressRule, priority=0 actions=goto_table:IngressDefaultRule
```

Flows 1-4 are installed for the ingress rule in the sample K8s NetworkPolicy. These flows are described as follows:

- Flow 1 is used to match packets with the source IP address in set {10.10.0.26}, which is from the Pods selected
  by the label `app: client` in the `default` Namespace, constituting the first dimension for `conjunction` with `conj_id` 3.
- Flow 2 is used to match packets with the output port OVS in set {0x25}, which has all ports of the Pods selected
  by the label `app: web` in the `default` Namespace, constituting the second dimension for `conjunction` with `conj_id` 3.
- Flow 3 is used to match packets with the destination TCP port in set {80} specified in the rule, constituting
  the third dimension for `conjunction` with `conj_id` 3.
- Flow 4 is used to match packets meeting all the three dimensions of `conjunction` with `conj_id` 3 and forward
  them to table [IngressMetric], persisting `conj_id` to `IngressRuleCTLabel`.

Flow 5 is the table-miss flow to forward packets not matched by other flows to table [IngressDefaultRule].

### IngressDefaultRule

This table is similar in its purpose to table [EgressDefaultRule], and it complements table [IngressRule] for K8s
NetworkPolicy ingress rule implementation. In Kubernetes, when a NetworkPolicy is applied to a set of Pods, then the default
behavior for ingress connections for these Pods becomes "deny" (they become [isolated
Pods](https://kubernetes.io/docs/concepts/services-networking/network-policies/#isolated-and-non-isolated-pods)). This
table is in charge of dropping traffic destined for Pods to which a NetworkPolicy (with an ingress rule) is applied,
and which did not match any of the "allow" list rules.

If you dump the flows of this table, you may see the following:

```text
1. table=IngressDefaultRule, priority=200,reg1=0x25 actions=drop
2. table=IngressDefaultRule, priority=0 actions=goto_table:IngressMetric
```

Flow 1, based on our sample K8s NetworkPolicy, is to drop traffic destined for OVS port 0x25, the port number associated
with a Pod selected by the label `app: web`.

Flow 2 is the table-miss flow to forward packets to table [IngressMetric].

This table is also used to implement Antrea-native NetworkPolicy ingress rules created in the Baseline Tier.
Since the Baseline Tier is meant to be enforced after K8s NetworkPolicies, the corresponding flows will be created at a
lower priority than K8s NetworkPolicy default drop flows. These flows are similar to flows 3-9 in table
[AntreaPolicyIngressRule].

### IngressMetric

This table is very similar to table [EgressMetric], but used to collect ingress metrics for Antrea-native NetworkPolicies.

If you dump the flows of this table, you may see the following:

```text
1. table=IngressMetric, priority=200,ct_state=+new,ct_label=0x3/0xffffffff,ip actions=goto_table:ConntrackCommit
2. table=IngressMetric, priority=200,ct_state=-new,ct_label=0x3/0xffffffff,ip actions=goto_table:ConntrackCommit
3. table=IngressMetric, priority=200,ct_state=+new,ct_label=0x6/0xffffffff,ip actions=goto_table:ConntrackCommit
4. table=IngressMetric, priority=200,ct_state=-new,ct_label=0x6/0xffffffff,ip actions=goto_table:ConntrackCommit
5. table=IngressMetric, priority=200,reg0=0x400/0x400,reg3=0x4 actions=drop
6. table=IngressMetric, priority=0 actions=goto_table:ConntrackCommit
```

Flows 1-2, matching packets with `IngressRuleCTLabel` set to 3 (the `conj_id` allocated for the sample K8s NetworkPolicy
ingress rule and loaded in table [IngressRule] flow 4), are used to collect metrics for the ingress rule.

Flows 3-4, matching packets with `IngressRuleCTLabel` set to 6 (the `conj_id` allocated for the sample Antrea-native
NetworkPolicy ingress rule and loaded in table [AntreaPolicyIngressRule] flow 10), are used to collect metrics for the
ingress rule.

Flow 5 is the drop rule for the sample Antrea-native NetworkPolicy ingress rule. It drops the packets by matching
`APDenyRegMark` loaded in table [AntreaPolicyIngressRule] flow 13 and `APConjIDField` set to 4 which is the `conj_id`
allocated for the ingress rule and loaded in table [AntreaPolicyIngressRule] flow 13.

Flow 6 is the table-miss flow.

### ConntrackCommit

This table is in charge of committing non-Service connections in `CtZone`.

If you dump the flows of this table, you may see the following:

```text
1. table=ConntrackCommit, priority=200,ct_state=+new+trk-snat,ct_mark=0/0x10,ip actions=ct(commit,table=Output,zone=65520,exec(move:NXM_NX_REG0[0..3]->NXM_NX_CT_MARK[0..3]))
2. table=ConntrackCommit, priority=0 actions=goto_table:Output
```

Flow 1 is designed to match the first packet of non-Service connections with the "tracked" state and `NotServiceCTMark`.
Then it commits the relevant connections in `CtZone`, persisting the value of `PktSourceField` to
`ConnSourceCTMarkField`, and forwards the packets to table [Output].

Flow 2 is the table-miss flow.

### Output

This is the final table in the pipeline, responsible for handling the output of packets from OVS. It addresses the
following cases:

1. Output packets to an application-aware engine for further L7 protocol processing.
2. Output packets to a target port and a mirroring port defined in a TrafficControl CR with `Mirror` action.
3. Output packets to a port defined in a TrafficControl CR with `Redirect` action.
4. Output packets from hairpin connections to the ingress port where they were received.
5. Output packets to a target port.
6. Output packets to the OpenFlow controller (Antrea Agent).
7. Drop packets.

If you dump the flows of this table, you may see the following:

```text
1. table=Output, priority=212,ct_mark=0x80/0x80,reg0=0x200000/0x600000 actions=push_vlan:0x8100,move:NXM_NX_CT_LABEL[64..75]->OXM_OF_VLAN_VID[],output:"antrea-l7-tap0"
2. table=Output, priority=211,reg0=0x200000/0x600000,reg4=0x400000/0xc00000 actions=output:NXM_NX_REG1[],output:NXM_NX_REG9[]
3. table=Output, priority=211,reg0=0x200000/0x600000,reg4=0x800000/0xc00000 actions=output:NXM_NX_REG9[]
4. table=Output, priority=210,ct_mark=0x40/0x40 actions=IN_PORT
5. table=Output, priority=200,reg0=0x200000/0x600000 actions=output:NXM_NX_REG1[]
6. table=Output, priority=200,reg0=0x2400000/0xfe600000 actions=meter:256,controller(reason=no_match,id=62373,userdata=01.01)
7. table=Output, priority=200,reg0=0x4400000/0xfe600000 actions=meter:256,controller(reason=no_match,id=62373,userdata=01.02)
8. table=Output, priority=0 actions=drop
```

Flow 1 is for case 1. It matches packets with `L7NPRedirectCTMark` and `OutputToOFPortRegMark`, and then outputs them to
the port `antrea-l7-tap0` specifically created for connecting to an application-aware engine. Notably, these packets are pushed
with an 802.1Q header and loaded with the VLAN ID value persisted in `L7NPRuleVlanIDCTLabel` before being output, due to
the implementation of Antrea-native L7 NetworkPolicy. The application-aware engine enforcing L7 policies (e.g., Suricata)
can leverage the VLAN ID to determine which set of rules to apply to the packet.

Flow 2 is for case 2. It matches packets with `TrafficControlMirrorRegMark` and `OutputToOFPortRegMark`, and then
outputs them to the port specified in `TargetOFPortField` and the port specified in `TrafficControlTargetOFPortField`.
Unlike the `Redirect` action, the `Mirror` action creates an additional copy of the packet.

Flow 3 is for case 3. It matches packets with `TrafficControlRedirectRegMark` and `OutputToOFPortRegMark`, and then
outputs them to the port specified in `TrafficControlTargetOFPortField`.

Flow 4 is for case 4. It matches packets from hairpin connections by matching `HairpinCTMark` and outputs them back to the
port where they were received.

Flow 5 is for case 5. It matches packets by matching `OutputToOFPortRegMark` and outputs them to the OVS port specified by
the value stored in `TargetOFPortField`.

Flows 6-7 are for case 6. They match packets by matching `OutputToControllerRegMark` and the value stored in
`PacketInOperationField`, then output them to the OpenFlow controller (Antrea Agent) with corresponding user data.

In practice, you will see additional flows similar to these ones to accommodate different scenarios (different
PacketInOperationField values). Note that packets sent to controller are metered to avoid overrunning the antrea-agent
and using too many resources.

Flow 8 is the table-miss flow for case 7. It drops packets that do not match any of the flows in this table.

[ARPSpoofGuard]: #arpspoofguard
[AntreaPolicyEgressRule]: #antreapolicyegressrule
[AntreaPolicyIngressRule]: #antreapolicyingressrule
[Classifier]: #classifier
[ClusterIP without Endpoint]: #clusterip-without-endpoint
[ClusterIP]: #clusterip
[ConntrackCommit]: #conntrackcommit
[ConntrackState]: #conntrackstate
[ConntrackZone]: #conntrackzone
[Ct Labels]: #ovs-ct-label
[Ct Marks]: #ovs-ct-mark
[Ct Zones]: #ovs-ct-zone
[EgressDefaultRule]: #egressdefaultrule
[EgressMark]: #egressmark
[EgressMetric]: #egressmetric
[EgressRule]: #egressrule
[Egress egress-client]: #egress-applied-to-client-pods
[Egress egress-web]: #egress-applied-to-web-pods
[EndpointDNAT]: #endpointdnat
[IngressDefaultRule]: #ingressdefaultrule
[IngressMetric]: #ingressmetric
[IngressRule]: #ingressrule
[L2ForwardingCalc]: #l2forwardingcalc
[L3DecTTL]: #l3decttl
[L3Forwarding]: #l3forwarding
[LoadBalancer]: #loadbalancer
[NodePort]: #nodeport
[NodePortMark]: #nodeportmark
[OVS Registers]: #ovs-registers
[Output]: #output
[PreRoutingClassifier]: #preroutingclassifier
[SNATMark]: #snatmark
[SNAT]: #snat
[Service with ExternalIP]: #service-with-externalip
[Service with ExternalTrafficPolicy Local]: #service-with-externaltrafficpolicy-local
[Service with session affinity]: #service-with-session-affinity
[ServiceLB]: #servicelb
[SessionAffinity]: #sessionaffinity
[SpoofGuard]: #spoofguard
[TrafficControl]: #trafficcontrol
[TrafficControl mirror-db-to-local]: #trafficcontrol-for-packet-mirroring
[TrafficControl redirect-web-to-local]: #trafficcontrol-for-packet-redirecting
[UnSNAT]: #unsnat
