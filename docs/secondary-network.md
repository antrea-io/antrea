# Antrea Secondary Network Support

## Table of Contents

<!-- toc -->
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Configurations](#configurations)
  - [VLAN](#vlan)
    - [OVS bridge configuration](#ovs-bridge-configuration)
    - [Secondary VLAN network configuration](#secondary-vlan-network-configuration)
    - [Pod secondary interface configuration](#pod-secondary-interface-configuration)
  - [SR-IOV](#sr-iov)
    - [Creating network functions](#creating-network-functions)
    - [Installing SR-IOV Network Device Plugin](#installing-sr-iov-network-device-plugin)
    - [Secondary SR-IOV network configuration](#secondary-sr-iov-network-configuration)
    - [Pod secondary interface configuration](#pod-secondary-interface-configuration-1)
- [Limitations](#limitations)
<!-- /toc -->

## Introduction

Antrea can work with Multus, in which case Antrea is the primary CNI of the
Kubernetes cluster and provisions the "primary" network interfaces of Pods;
while Multus manages secondary networks and executes other CNIs to create
secondary network interfaces of Pods. The [Antrea + Multus guide](cookbooks/multus)
talks about how to use Antrea with Multus.

Starting with Antrea v1.5, native support for secondary networks was introduced,
initially for SR-IOV based networks. In Antrea v1.15, support was extended to
include VLAN-based networks. The table below summarizes the capabilities of this
feature across different releases.

| Release       | SR-IOV on Bare-Metal Server | VLAN    | SR-IOV on Virtual Machine |
|---------------|-----------------------------|---------|---------------------------|
| v1.5 - v1.14  | `Alpha`                     |         |                           |
| v1.15 - v2.2  | `Alpha`                     | `Alpha` |                           |
| v2.3 - latest | `Alpha`                     | `Alpha` | `Alpha`                   |

This document describes steps to enable and use Antrea's native support for
secondary networks.

## Prerequisites

Native secondary network support is still an alpha feature and is disabled by
default. To use the feature, the `SecondaryNetwork` feature gate must be enabled
in the `antrea-agent` configuration. If you need IPAM for the secondary
interfaces, you should also enable the `AntreaIPAM` feature gate in both
`antrea-agent` and `antrea-controller` configuration. At the moment, Antrea IPAM
is the only available IPAM option for secondary networks managed by Antrea. The
`antrea-config` ConfigMap with the two feature gates enables is like the
following:

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
      SecondaryNetwork: true
```

Antrea leverages the `NetworkAttachmentDefinition` CRD from [Kubernetes Network
Plumbing Working Group](https://github.com/k8snetworkplumbingwg/multi-net-spec)
to define secondary networks. You can import the CRD to your cluster using the
following command:

```bash
kubectl apply -f https://github.com/k8snetworkplumbingwg/network-attachment-definition-client/raw/master/artifacts/networks-crd.yaml
```

## Configurations

You can configure secondary networks for your Pods using one or more of the
following types:

- [VLAN](#vlan)
- [SR-IOV](#sr-iov)

### VLAN

#### OVS bridge configuration

A VLAN secondary interface will be connected to a separate OVS bridge on the
Node. You can specify the secondary OVS bridge configuration in the
`antrea-agent` configuration, and `antrea-agent` will automatically create the
OVS bridge based on the configuration. The OVS bridge configuration supports
the following parameters:

* `bridgeName` - specifies the name of the OVS bridge to be created. This is a
  required parameter and must be unique on the Node.
* `physicalInterfaces` - a list of physical network interface names to be added
  to the bridge. These interfaces will serve as uplinks for the bridge. At
  least one interface must be specified, and up to eight interfaces are
  supported.
* `enableMulticastSnooping` - (supported after v2.4) enable multicast snooping
  on the bridge, allowing the bridge to learn about multicast group memberships
  and forward multicast traffic only to ports that have interested receivers.
  When disabled, multicast traffic is flooded to all ports in the bridge. The
  default value is `false`.

For example, the following configuration will create an OVS bridge named
`br-secondary`, with a physical interface `eth1`.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: antrea-config
  namespace: kube-system
data:
  antrea-agent.conf: |
    secondaryNetwork:
      ovsBridges: [{"bridgeName": "br-secondary", "physicalInterfaces": ["eth1"]}]
```

At the moment, Antrea supports only a single OVS bridge for secondary networks,
and supports up to eight physical interfaces on the bridge.

Note: when you set the Node's primary NIC as a secondary bridge physical interface,
if the Node IP is assigned via DHCP and the DNS server is auto-configured by a DNS
manager (e.g. system-resolved), you may lose the DNS configuration after the interface
is moved to the OVS bridge, because of the interface state change. Please consider providing
a static DNS configuration in `/etc/systemd/resolved.conf` before installing Antrea to
use the primary NIC as a physical interface. Check more details on [issue 6558](https://github.com/antrea-io/antrea/issues/6558).

#### Secondary VLAN network configuration

A secondary VLAN network is defined by a NetworkAttachmentDefinition CR. For
example, the following NetworkAttachmentDefinition defines a VLAN network
`vlan100`.

```yaml
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
  name: vlan100
spec:
  config: '{
      "cniVersion": "0.3.0",
      "type": "antrea",
      "networkType": "vlan",
      "mtu": 1500,
      "vlan": 100,
      "ipam": {
        "type": "antrea",
        "ippools": ["vlan100-ipv4", "vlan100-ipv6"]
      }
    }'
```

`antrea-agent` will connect Pod secondary interfaces belonging to a VLAN network
to the secondary OVS bridge on the Node. If a non-zero VLAN is specified in the
network's `config`, `antrea-agent` will configure the VLAN ID on the OVS port,
so the interface's traffic will be isolated within the VLAN. And before the
traffic is forwarded out of the Node via the secondary bridge's physical
interface, OVS will insert the VLAN tag in the packets.

A few extra notes about the NetworkAttachmentDefinition `config` fields:

* `type` - must be set to `antrea`.
* `networkType` - should be set to `vlan` if VLAN-based network is desired.
* `mtu` - defaults to 1500 if not set.
* `vlan` - can be set to 0 or a valid VLAN ID (1 - 4094). Defaults to 0. The
VLAN ID can also be specified as part of the spec of an IPPool referenced in the
`ipam` section, but `vlan` in NetworkAttachmentDefinition `config` will override
the VLAN in IPPool(s) if both are set.
* `ipam` - it is optional. If not set, the secondary interfaces created for the
network won't have an IP address allocated. For more information about secondary
network IPAM configuration, please refer to the [Antrea IPAM document](antrea-ipam.md#ipam-for-secondary-network).

#### Pod secondary interface configuration

You can create a Pod with secondary network interfaces by adding the
`k8s.v1.cni.cncf.io/networks` annotation to the Pod. The following example Pod
includes two secondary interfaces, one in network `vlan100` which should be
created in the same Namespace as the Pod, the other in network `vlan200` which
is created in Namespace `networks`.

```yaml
apiVersion: v1
kind: Pod
metadata:
 name: sample-pod-secondary-network-vlan
 annotations:
   k8s.v1.cni.cncf.io/networks: '[
     {"name": "vlan100"},
     {"name": "vlan200", "namespace": "networks", "interface": "eth200"}
   ]'
spec:
 containers:
 - name: toolbox
   image: antrea/toolbox:latest
```

If the Pod has only a single secondary network interface, you can also set
the `k8s.v1.cni.cncf.io/networks` annotation to `<network-name>`,
or `<namespace>/<network-name>` if the NetworkAttachmentDefinition CR is created
in a different Namespace from the Pod's Namespace, or
`<network-name>@<interface-name>` if you want to specify the Pod interface name.
For example:

```yaml
apiVersion: v1
kind: Pod
metadata:
 name: sample-pod-secondary-network-vlan
 annotations:
   k8s.v1.cni.cncf.io/networks: networks/vlan200@eth200
spec:
 containers:
 - name: toolbox
   image: antrea/toolbox:latest
```

### SR-IOV

#### Creating network functions

To configure SR-IOV network for Pods, the required network functions must be
available on the Kubernetes Node, whether it is a virtual machine or a
bare-metal server. You can follow the following docs to create SR-IOV Virtual
Functions (VFs) or Subfunctions (SFs).

* [Creating SR-IOV Virtual Functions](https://github.com/k8snetworkplumbingwg/sriov-network-device-plugin/blob/master/docs/vf-setup.md)
* [Creating Subfunctions](https://github.com/k8snetworkplumbingwg/sriov-network-device-plugin/blob/master/docs/subfunctions/README.md)

**While the implementation is designed to work with all SR-IOV capable NICs,
we currently lack the resources to test every model, particularly those with
SFs. Please open an issue if you encounter issues with a specific NIC.**

#### Installing SR-IOV Network Device Plugin

After creating network functions, you need to install the [SR-IOV Network
Device Plugin](https://github.com/k8snetworkplumbingwg/sriov-network-device-plugin),
a Kubernetes device plugin that discovers and advertises networking resources,
including SR-IOV VFs and SFs, on a Kubernetes Node. You can follow [this doc](https://github.com/k8snetworkplumbingwg/sriov-network-device-plugin?tab=readme-ov-file#install-sr-iov-network-device-plugin)
to install the plugin.

On successful installation, the allocatable resource list for the Node should
be updated with network resources discovered by the plugin, as shown below:

```bash
$ kubectl get node node1 -o json | jq '.status.allocatable'
{
  "cpu": "8",
  "ephemeral-storage": "169986638772",
  "hugepages-1Gi": "0",
  "hugepages-2Mi": "8Gi",
  "intel.com/sriov_net_A": "8",
  "intel.com/sriov_net_B": "8",
  "memory": "7880620Ki",
  "pods": "1k"
}
```

#### Secondary SR-IOV network configuration

You can now define a secondary SR-IOV network using a
NetworkAttachmentDefinition of `sriov` network type, which references the
discovered network resource. For example, the following
NetworkAttachmentDefinition defines a SR-IOV network named `sriov-net-a`, linked
to the network resource `intel.com/sriov_net_A`:

```yaml
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
  name: sriov-net-a
  annotations:
    k8s.v1.cni.cncf.io/resourceName: intel.com/sriov_net_A
spec:
  config: '{
      "cniVersion": "0.3.0",
      "type": "antrea",
      "networkType": "sriov",
      "ipam": {
        "type": "antrea",
        "ippools": ["sriov-ipv4"]
      }
    }'
```

A few extra notes about the NetworkAttachmentDefinition `config` fields:

* `type` - must be set to `antrea`.
* `networkType` - should be set to `sriov` if SR-IOV based network is desired.
* `mtu` - defaults to 1500 if not set.
* `ipam` - it is optional. If not set, the secondary interfaces created for the
  network won't have an IP address allocated. For more information about secondary
  network IPAM configuration, please refer to the [Antrea IPAM document](antrea-ipam.md#ipam-for-secondary-network).

#### Pod secondary interface configuration

Finally, to create a Pod with a secondary SR-IOV interface, add the
`k8s.v1.cni.cncf.io/networks` annotation to the Pod, specifying the desired
SR-IOV network.

```yaml
apiVersion: v1
kind: Pod
metadata:
 name: sample-pod-secondary-network-sriov
 annotations:
   k8s.v1.cni.cncf.io/networks: sriov-net-a
spec:
 containers:
 - name: toolbox
   image: antrea/toolbox:latest
   resources:
     requests:
       intel.com/sriov_net_A: '1'
     limits:
       intel.com/sriov_net_A: '1'
```

## Limitations

* At the moment, we do NOT support annotation update / removal: when the
  annotation is added to the Pod for the first time (e.g., when creating the
  Pod), we will configure the secondary network interfaces accordingly, and no
  change is possible after that, until the Pod is deleted.
* We don't support K8s Nodes with multi-path routes.

  > A multi-path route is a route with multiple possible next hops. When listing the
  > rules (e.g., with `ip route list`), a multi-path route may appear as multiple individual
  > routes (one for each next hop), all with the same cost.

  When the K8s Node interfaces are managed by a network manager, please make sure the default
  routes for secondary interfaces are disabled, or configure the routes with different metrics.
  Otherwise, you may encounter K8s Nodes connection issue. Please check issue [#7058](https://github.com/antrea-io/antrea/issues/7058) for details.
