# Antrea IPAM Capabilities

<!-- TOC -->
* [Antrea IPAM Capabilities](#antrea-ipam-capabilities)
  * [Running NodeIPAM within Antrea Controller](#running-nodeipam-within-antrea-controller)
    * [Configuration](#configuration)
  * [Antrea Flexible IPAM](#antrea-flexible-ipam)
    * [Usage](#usage)
      * [Enable AntreaIPAM feature gate and bridging mode](#enable-antreaipam-feature-gate-and-bridging-mode)
      * [Create IPPool CR](#create-ippool-cr)
      * [IPPool Annotations on Namespace](#ippool-annotations-on-namespace)
      * [IPPool Annotations on Pod (available since Antrea 1.5)](#ippool-annotations-on-pod-available-since-antrea-15)
      * [Persistent IP for StatefulSet Pod (available since Antrea 1.5)](#persistent-ip-for-statefulset-pod-available-since-antrea-15)
    * [Data path behaviors](#data-path-behaviors)
    * [Requirements for this Feature](#requirements-for-this-feature)
    * [Flexible IPAM design](#flexible-ipam-design)
      * [On IPPool CR create/update event](#on-ippool-cr-createupdate-event)
      * [On StatefulSet create event](#on-statefulset-create-event)
      * [On StatefulSet delete event](#on-statefulset-delete-event)
      * [On Pod create](#on-pod-create)
      * [On Pod delete](#on-pod-delete)
  * [IPAM for Secondary Network](#ipam-for-secondary-network)
    * [Prerequisites](#prerequisites)
    * [CNI IPAM configuration](#cni-ipam-configuration)
    * [Configuration with `NetworkAttachmentDefinition` CRD](#configuration-with-networkattachmentdefinition-crd)
  * [`IPPool` CRD](#ippool-crd)
<!-- TOC -->

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

Below is a sample of needed changes in the Antrea deployment YAML:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-controller.conf: |
    nodeIPAM:
      enableNodeIPAM: true
      clusterCIDRs: [172.100.0.0/16]
```

When running Antrea NodeIPAM in a particular version or scenario, you may need to
be aware of the following:

* Prior to v1.12, a feature gate, `NodeIPAM` must also be enabled for
  `antrea-controller`.
* Prior to v1.13, running Antrea NodeIPAM without kube-proxy is not supported.
  Starting with v1.13, the `kubeAPIServerOverride` option in the `antrea-controller`
  configuration must be set to the address of Kubernetes apiserver when kube-proxy
  is not deployed.

## Antrea Flexible IPAM

Antrea supports flexible control over Pod IP addressing since version 1.4. Pod
IP addresses can be allocated from an `IPPool`. When a Pod's IP is allocated
from an IPPool, the traffic from the Pod to Pods on another Node or from the Pod to
external network will be sent to the underlay network through the Node's transport
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
both `antrea-controller` and `antrea-agent`, and set the `enableBridgingMode`
configuration parameter of `antrea-agent` to `true`.

When Antrea is installed from YAML, the needed changes in the Antrea
ConfigMap `antrea-config` YAML are as below:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-controller.conf: |
    featureGates:
      AntreaIPAM: true
  antrea-agent.conf: |
    featureGates:
      AntreaIPAM: true
    enableBridgingMode: true
    trafficEncapMode: "noEncap"
    noSNAT: true
```

Alternatively, you can use the following helm install/upgrade command to configure
the above options:

 ```bash
 helm upgrade --install antrea antrea/antrea --namespace kube-system --set
enableBridgingMode=true,featureGates.AntreaIPAM=true,trafficEncapMode=noEncap,noSNAT=true
 ```

#### Create IPPool CR

The following example YAML manifest creates an IPPool CR.

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

The following example YAML manifest creates a Namespace to allocate Pod IPs from the IP pool.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: namespace1
  annotations:
    ipam.antrea.io/ippools: 'pool1'
```

#### IPPool Annotations on Pod (available since Antrea 1.5)

Since Antrea v1.5.0, Pod IPPool annotation is supported and has a higher
priority than the Namespace IPPool annotation. This annotation can be added to
`PodTemplate` of a controller resource such as StatefulSet and Deployment.

Pod IP annotation is supported for a single Pod to specify a fixed IP for the Pod.

Examples of annotations on a Pod or PodTemplate:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: statefulset1
spec:
  replicas: 1  # Do not increase replicas if there is pod-ips annotation in PodTemplate
  template:
    metadata:
      annotations:
        ipam.antrea.io/ippools: 'sts-ip-pool1'  # This annotation will be set automatically on all Pods managed by this resource
        ipam.antrea.io/pod-ips: '<ip-in-sts-ip-pool1>'
```

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: statefulset1
spec:
  replicas: 4
  template:
    metadata:
      annotations:
        ipam.antrea.io/ippools: 'sts-ip-pool1'  # This annotation will be set automatically on all Pods managed by this resource
        # Do not add pod-ips annotation to PodTemplate if there is more than 1 replica
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  annotations:
    ipam.antrea.io/ippools: 'pod-ip-pool1'
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  annotations:
    ipam.antrea.io/ippools: 'pod-ip-pool1'
    ipam.antrea.io/pod-ips: '<ip-in-pod-ip-pool1>'
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  annotations:
    ipam.antrea.io/pod-ips: '<ip-in-namespace-pool>'
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
type, `noEncap`, `noSNAT` traffic mode, and `AntreaProxy` feature enabled. Configuration
with `ProxyAll` feature enabled is not verified.

The IPs in the `IPPools` without VLAN must be in the same underlay subnet as the Node
IP, because inter-Node traffic of AntreaIPAM Pods is forwarded by the Node network.
`IPPools` with VLAN must not overlap with other network subnets, and the underlay network
router should provide the network connectivity for these VLANs. Only a single IP pool can
be included in the Namespace annotation. In the future, annotation of up to two pools for
IPv4 and IPv6 respectively will be supported.

### Flexible IPAM design

When the `AntreaIPAM` feature gate is enabled, `antrea-controller` will watch IPPool CRs and
StatefulSets from `kube-apiserver`.

#### On IPPool CR create/update event

`antrea-controller` will update IPPool counters, and periodically clean up stale IP addresses.

#### On StatefulSet create event

`antrea-controller` will check the Antrea IPAM annotations on the StatefullSet, and preallocate
IPs from the specified IPPool for the StatefullSet Pods

#### On StatefulSet delete event

`antrea-controller` will clean up IP allocations for this StatefulSet.

#### On Pod create

`antrea-agent` will receive a CNI add request, and it will then check the Antrea IPAM annotations
and allocate an IP for the Pod, which can be a pre-allocated IP StatefulSet IP, a user-specified
IP, or the next available IP in the specified IPPool.

#### On Pod delete

`antrea-agent` will receive a CNI del request and release the IP allocation from the IPPool.
If the IP is a pre-allocated StatefulSet IP, it will stay in the pre-allocated status thus the Pod
will get same IP after recreated.

## IPAM for Secondary Network

With the AntreaIPAM feature, Antrea can allocate IPs for Pod secondary networks,
including both [secondary networks managed by Antrea](secondary-network.md) and
secondary networks managed by [Multus](cookbooks/multus).

### Prerequisites

The IPAM capability for secondary network was added in Antrea version 1.7. It
requires the `AntreaIPAM` feature gate to be enabled on both `antrea-controller`
and `antrea-agent`, as `AntreaIPAM` is still an alpha feature at this moment and
is not enabled by default.

### CNI IPAM configuration

To configure Antrea IPAM, `antrea` should be specified as the IPAM plugin in the
the CNI IPAM configuration, and at least one Antrea IPPool should be specified
in the `ippools` field. IPs will be allocated from the specified IPPool(s) for
the secondary network.

```json
{
    "cniVersion": "0.3.0",
    "name": "ipv4-net-1",
    "type": "macvlan",
    "master": "eth0",
    "mode": "bridge",
    "ipam": {
        "type": "antrea",
        "ippools": [ "ipv4-pool-1" ]
    }
}
```

Multiple IPPools can be specified to allocate multiple IPs from each IPPool for
the secondary network. For example, you can specify one IPPool to allocate an
IPv4 address and another IPPool to allocate an IPv6 address in the dual-stack
case.

```json
{
    "cniVersion": "0.3.0",
    "name": "dual-stack-net-1",
    "type": "macvlan",
    "master": "eth0",
    "mode": "bridge",
    "ipam": {
        "type": "antrea",
        "ippools": [ "ipv4-pool-1", "ipv6-pool-1" ]
    }
}
```

Additionally, Antrea IPAM also supports the same configuration of static IP
addresses, static routes, and DNS settings, as what is supported by the
[static IPAM plugin](https://www.cni.dev/plugins/current/ipam/static). The
following example requests an IP from an IPPool and also specifies two
additional static IP addresses. It also includes static routes and DNS settings.

```json
{
    "cniVersion": "0.3.0",
    "name": "pool-and-static-net-1",
    "type": "bridge",
    "bridge": "br0",
    "ipam": {
        "type": "antrea",
        "ippools": [ "ipv4-pool-1" ],
        "addresses": [
            {
                "address": "10.10.0.1/24",
                "gateway": "10.10.0.254"
            },
            {
                "address": "3ffe:ffff:0:01ff::1/64",
                "gateway": "3ffe:ffff:0::1"
            }
        ],
        "routes": [
            { "dst": "0.0.0.0/0" },
            { "dst": "192.168.0.0/16", "gw": "10.10.5.1" },
            { "dst": "3ffe:ffff:0:01ff::1/64" }
        ],
        "dns": {
            "nameservers" : ["8.8.8.8"],
            "domain": "example.com",
            "search": [ "example.com" ]
        }
    }
}
```

The CNI IPAM configuration can include only static addresses without IPPools, if
only static IP addresses are needed.

### Configuration with `NetworkAttachmentDefinition` CRD

CNI and IPAM configuration of a secondary network is typically defined with the
`NetworkAttachmentDefinition` CRD. For example:

```yaml
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
  name: ipv4-net-1
spec:
  {
      "cniVersion": "0.3.0",
      "type": "macvlan",
      "master": "eth0",
      "mode": "bridge",
      "ipam": {
          "type": "antrea",
          "ippools": [ "ipv4-pool-1" ]
      }
  }
```

## `IPPool` CRD

Antrea IP pools are defined with the `IPPool` CRD. The following two examples
define an IPv4 and an IPv6 IP pool respectively.

```yaml
apiVersion: "crd.antrea.io/v1alpha2"
kind: IPPool
metadata:
  name: ipv4-pool-1
spec:
  ipVersion: 4
  ipRanges:
  - cidr: "10.10.1.0/26"
    gateway: "10.10.1.1"
    prefixLength: 24
```

```yaml
apiVersion: "crd.antrea.io/v1alpha2"
kind: IPPool
metadata:
  name: ipv6-pool-1
spec:
  ipVersion: 6
  ipRanges:
  - start: "3ffe:ffff:1:01ff::0100"
    end: "3ffe:ffff:1:01ff::0200"
    gateway: "3ffe:ffff:1:01ff::1"
    prefixLength: 64
```

When used for Antrea secondary VLAN network, the VLAN set in an `IPPool` IP
range will be passed to the VLAN interface configuration. For example:

```yaml
apiVersion: "crd.antrea.io/v1alpha2"
kind: IPPool
metadata:
  name: ipv4-pool-1
spec:
  ipVersion: 4
  ipRanges:
  - cidr: "10.10.1.0/26"
    gateway: "10.10.1.1"
    prefixLength: 24
    vlan: 100

---
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
  name: ipv4-net-1
spec:
  {
      "cniVersion": "0.3.0",
      "type": "antrea",
      "networkType": "vlan",
      "ipam": {
          "type": "antrea",
          "ippools": [ "ipv4-pool-1" ]
      }
  }
```

You can refer to the [Antrea secondary network document](secondary-network.md)
for more information about Antrea secondary VLAN network configuration.

For other network types, the VLAN field in the `IPPool` will be ignored.
