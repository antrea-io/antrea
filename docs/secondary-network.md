# Antrea Secondary Network Support

Antrea can work with Multus, in which case Antrea is the primary CNI of the
Kubernetes cluster and provisions the "primary" network interfaces of Pods;
while Multus manages secondary networks and executes other CNIs to create
secondary network interfaces of Pods. The [Antrea + Multus guide](cookbooks/multus)
talks about how to use Antrea with Multus.

Starting with Antrea v1.15, Antrea can also provision secondary network
interfaces and connect them to VLAN networks. This document describes Antrea's
native support for VLAN secondary networks.

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

## Secondary OVS bridge configuration

A VLAN secondary interface will be connected to a separate OVS bridge on the
Node. You can specify the secondary OVS bridge configuration in the
`antrea-agent` configuration, and `antrea-agent` will automatically create the
OVS bridge based on the configuration. For example, the following configuration
will create an OVS bridge named `br-secondary`, with a physical interface
`eth1`.

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
and supports upto eight physical interfaces on the bridge. The physical
interfaces cannot be the Node's management interface, otherwise the Node's
management network connectivity can be broken after `antrea-agent` creates the
OVS bridge and moves the management interface to the bridge.

## Secondary VLAN network configuration

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
to the secondary OVS bridge on the Node. If a non-zero VLAN is speficied in the
network's `config`, `antrea-agent` will configure the VLAN ID on the OVS port,
so the interface's traffic will be isolated within the VLAN. And before the
traffic is forwarded out of the Node via the secondary bridge's physical
interface, OVS will insert the VLAN tag in the packets.

A few extra notes about the NetworkAttachmentDefinition `config` fields:

* `type` - must be set to `antrea`.
* `networkType` - the only supported network type is `vlan` as of now.
* `mtu` - defaults to 1500 if not set.
* `vlan` - can be set to 0 or a valid VLAN ID (1 - 4094). Defaults to 0. The
VLAN ID can also be specified as part of the spec of an IPPool referenced in the
`ipam` section, but `vlan` in NetworkAttachmentDefinition `config` will override
the VLAN in IPPool(s) if both are set.
* `ipam` - it is optional. If not set, the secondary interfaces created for the
network won't have an IP address allocated. For more information about secondary
network IPAM configuration, please refer to the [Antrea IPAM document](antrea-ipam.md#ipam-for-secondary-network).

## Pod secondary interface configuration

You can create a Pod with secondary network interfaces by adding the
`k8s.v1.cni.cncf.io/networks` annotation to the Pod. The following example Pod
includes two secondary interfaces, one in network `vlan100` which should be
created in the same Namespace as the Pod, the other in network `vlan200` which
is created in Namespace `networks`.

```yaml
apiVersion: v1
kind: Pod
metadata:
 name: sample-pod
 labels:
   app: antrea-secondary-network-demo
 annotations:
   k8s.v1.cni.cncf.io/networks: '[
     {"name": "vlan100"},
     {"name": vlan200, "namespace": "networks", "interface": "eth200"}
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
 name: sample-pod
 labels:
   app: antrea-secondary-network-demo
 annotations:
   k8s.v1.cni.cncf.io/networks: networks/vlan200@eth200
spec:
 containers:
 - name: toolbox
   image: antrea/toolbox:latest
```

**At the moment, we do NOT support annotation update / removal: when the
  annotation is added to the Pod for the first time (e.g., when creating the
  Pod), we will configure the secondary network interfaces accordingly, and no
  change is possible after that, until the Pod is deleted.**
