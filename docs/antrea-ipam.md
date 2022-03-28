# Antrea IPAM Capabilities

## Running NodeIPAM within Antrea Controller

NodeIPAM is a Kubernetes component, which manages IP address pool allocation per
each Node, when the Node initializes.

On single stack deployments, NodeIPAM allocates a single IPv4 or IPv6 CIDR per
Node, while in dual stack deployments, NodeIPAM allocates two CIDRs per each
Node: one for each IP family.

NodeIPAM is configured with a CIDR per each family, which it slices into smaller
per-Node CIDRs. When a Node is initialized, the CIDRs are set to the podCIDRs
attribute of the Node spec.

Antrea NodeIPAM controller can be executed in scenarios where the
NodeIPAMController is disabled in kube-controller-manager.

Note that running Antrea NodeIPAM while NodeIPAMController runs within
kube-controller-manager would cause conflicts and result in an unstable
behavior.

### Configuration

Antrea Controller NodeIPAM configuration items are grouped under `nodeIPAM`
dictionary key.

NodeIPAM dictionary contains the following items:

- `enableNodeIPAM`: Enable the integrated NodeIPAM controller within the Antrea
controller. Default is false.

- `clusterCIDRs`: CIDR ranges for Pods in cluster. String array containing single
CIDR range, or multiple ranges. The CIDRs could be either IPv4 or IPv6. At most
one CIDR may be specified for each IP family. Example values:
`[172.100.0.0/16]`, `[172.100.0.0/20, fd00:172:100::/60]`.

- `serviceCIDR`: CIDR range for IPv4 Services in cluster. It is not necessary to
specify it when there is no overlap with clusterCIDRs.

- `serviceCIDRv6`: CIDR range for IPv6 Services in cluster. It is not necessary to
  specify it when there is no overlap with clusterCIDRs.

- `nodeCIDRMaskSizeIPv4`: Mask size for IPv4 Node CIDR in IPv4 or dual-stack
cluster. Valid range is 16 to 30. Default is 24.

- `nodeCIDRMaskSizeIPv6`: Mask size for IPv6 Node CIDR in IPv6 or dual-stack
cluster. Valid range is 64 to 126. Default is 64.

## Antrea Flexible IPAM

Antrea supports flexible control over Pod IP addressing since version 1.4. Pod
IP addresses can be allocated from an `IPPool`. When a Pod's IP is allocated
from an IPPool, the traffic from the Pod to Pods on another Node or to external
network will be sent to the underlay network through the Node's transport
network interface, and will be forwarded/routed by the underlay network. We also
call this forwarding mode `bridging mode`.

`IPPool` CRD defines a desired set of IP ranges and VLANs. An `IPPool` can be annotated
to Namespace, Pod and PodTemplate of StatefulSet/Deployment. Then Antrea will
manage IP address assignment for corresponding Pods according to `IPPool` spec.
Note that the IP pool annotation cannot be updated or deleted without recreating
the resource. An `IPPool` can be extended, but cannot be shrunk if already
assigned to a resource. The IP ranges of IPPools must not overlap, otherwise it
would lead to undefined behavior.

Regular `Subnet per Node` IPAM will continue to be used for resources without the
IPPool annotation, or when the `AntreaIPAM` feature is disabled.

### Usage

#### Enable AntreaIPAM feature gate and bridging mode

To enable flexible IPAM, you need to enable the `AntreaIPAM` feature gate for
for both `antrea-controller` and `antrea-agent`, and set the `enableBridgingMode`
configuration parameter of `antrea-agent` to `true`. The needed changes in the
Antrea deployment YAML are:

```yaml
  antrea-controller.conf: |
    ...
    featureGates:
      AntreaIPAM: true
    ...
  antrea-agent.conf: |
    ...
    featureGates:
      AntreaIPAM: true
    ...
    enableBridgingMode: true
    ...
```

#### Create IPPool CR

The following example YAML manifests create an IPPool CR.

```yaml
apiVersion: "crd.antrea.io/v1alpha2"
kind: IPPool
metadata:
  name: pool1
spec:
  ipVersion: 4
  ipRanges:
  - start: "10.2.0.12"
    end: "10.2.0.20"
    gateway: "10.2.0.1"
    prefixLength: 24
    vlan: 2              # Default is 0 (untagged). Valid value is 0~4095.
```

#### IPPool Annotations on Namespace

The following example YAML manifests create a Namespace to allocate Pod IPs from the IP pool.

```yaml
kind: Namespace
metadata:
  annotations:
    ipam.antrea.io/ippools: 'pool1'
...
```

#### IPPool Annotations on Pod (available since Antrea 1.5)

Since Antrea 1.5, Pod IPPool annotation is supported and has a higher priority than the
Namespace IPPool annotation. This annotation can be added to `PodTemplate` of a
controller resource such as StatefulSet and Deployment.

Pod IP annotation is supported for a single Pod to specify a fixed IP for the Pod.

Examples of annotations on a Pod or PodTemplate:

```yaml
kind: StatefulSet
spec:
  replicas: 1  # Do not increase replicas if there is pod-ips annotation in PodTemplate
  template:
    metadata:
      annotations:
        ipam.antrea.io/ippools: 'sts-ip-pool1'  # This annotation will be set automatically on all Pods managed by this resource
        ipam.antrea.io/pod-ips: '<ip-in-sts-ip-pool1>'
...
```

```yaml
kind: StatefulSet
spec:
  replicas: 4
  template:
    metadata:
      annotations:
        ipam.antrea.io/ippools: 'sts-ip-pool1'  # This annotation will be set automatically on all Pods managed by this resource
        # Do not add pod-ips annotation to PodTemplate if there is more than 1 replica
...
```

```yaml
kind: Pod
metadata:
  annotations:
    ipam.antrea.io/ippools: 'pod-ip-pool1'
...
```

```yaml
kind: Pod
metadata:
  annotations:
    ipam.antrea.io/ippools: 'pod-ip-pool1'
    ipam.antrea.io/pod-ips: '<ip-in-pod-ip-pool1>'
...
```

```yaml
kind: Pod
metadata:
  annotations:
    ipam.antrea.io/pod-ips: '<ip-in-namespace-pool>'
...
```

#### Persistent IP for StatefulSet Pod (available since Antrea 1.5)

A StatefulSet Pod's IP will be kept after Pod restarts, when the IP is allocated from the
annotated IPPool.

### Data path behaviors

When `AntreaIPAM` is enabled, `antrea-agent` will connect the Node's network interface
to the OVS bridge at startup, and it will detach the interface from the OVS bridge and
restore its configurations at exit. Node may lose network connection when `antrea-agent`
or OVS daemons are stopped unexpectedly, which can be recovered by rebooting the Node.
`AntreaIPAM` Pods' traffic will not be routed by local Node's network stack.

Traffic from `AntreaIPAM` Pods without VLAN, regular `Subnet per Node` IPAM Pods, and K8s
Nodes is recognized as VLAN 0 (untagged).

Traffic to a local Pod in the Pod's VLAN will be sent to the Pod's OVS port directly,
after the destination MAC is rewritten to the Pod's MAC address. This includes
`AntreaIPAM` Pods and regular `Subnet per Node` IPAM Pods, even when they are not in the
same subnet. Traffic to a Pod in different VLAN will be sent to the underlay network,
where the underlay router will route the traffic to the destination VLAN.

### Requirements for this Feature

As of now, this feature is supported on Linux Nodes, with IPv4, `system` OVS datapath
type, and `noEncap`, `noSNAT` traffic mode.

The IPs in the `IPPools` without VLAN must be in the same underlay subnet as the Node
IP, because inter-Node traffic of AntreaIPAM Pods is forwarded by the Node network.
`IPPools` with VLAN must not overlap with other network subnets, and the underlay network
router should provide the network connectivity for these VLANs. Only a single IP pool can
be included in the Namespace annotation. In the future, annotation of up to two pools for
IPv4 and IPv6 respectively will be supported.
