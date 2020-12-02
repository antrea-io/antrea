# Antrea Roadmap

This document lists the new features being considered for the future. The
intention is for Antrea contributors and users to know what features could come
in the near future, and to share feedback and ideas. Priorities for the project
may change over time and so this roadmap is likely to evolve. A feature that is
not listed now does not mean it will not be considered for Antrea. We definitely
welcome suggestions and ideas from everyone about the roadmap and Antrea
features. Reach us through Issues, Slack and / or Google Group!

## Planned Features

The following features are considered for the near future:

* **Windows support improvements**
Antrea [supports Windows K8s Node](windows.md) since version 0.7.0.
However, a few features like network flow export are not supported for Windows
Node yet. We will continue to add more features for Windows, and improve Antrea
Agent and OVS installation on Windows Nodes.

* **IPv6 Pod network**
Support IPv6 and IPv4/IPv6 dual-stack for Pod network. Right now Antrea supports
only IPv4.

* **Antrea NetworkPolicy**
Antrea has started adding support for [Antrea native NetworkPolicy](antrea-network-policy.md)
in addition to K8s NetworkPolicy since version 0.8.0. We already support
ClusterNetworkPolicy and tiering, and will continue to add more NetworkPolicy
extensions, like traffic logging, policy statistics, policy realization status,
more matching criteria and actions, and external endpoints.

* **Network diagnostics and observability**
Network diagnostics and observability is one area we want to focus on. Antrea
already implements some useful features on this front, including [Octant UI
plugin](octant-plugin-installation.md), [CLI](antctl.md),
[Traceflow](traceflow-guide.md), [network flow export and visualization](network-flow-visibility.md),
[Prometheus metrics](prometheus-integration.md), [OVS flow dumping](antctl.md#dumping-ovs-flows)
and [packet tracing](antctl.md#ovs-packet-tracing). We will continue to
enhance existing features and add new features to help diagnose K8s networking
and NetworkPolicy implementation, and to provide good visibility into the Antrea
network.

* **Flexible IPAM**
So far Antrea leverages K8s NodeIPAM for IPAM which allocates a single subnet
for each K8s Node. In future, Antrea will implement its own IPAM, and support
more IPAM strategies besides subnet per Node, like IP pool per Node or
per Namespace.

* **Egress policy**
Egress policy is to control the egress Nodes and SNAT IPs of traffic from Pods
to external network. For example, a user can request a dedicated SNAT IP per
Namespace, or for a particular set of Pods or Services. This feature is very
useful for services in the Node or external network to identify the source of
Pod traffic based on SNAT IP and enforce specific policies on the traffic. Also
check the [egress policy proposal](https://github.com/vmware-tanzu/antrea/issues/667)
to learn more.

* **NFV and Telco use cases**
We plan to explore and provide support for NFV and Telco use cases. Will support
Multus integration, Pod interfaces on SRIOV devices, and Network Service
Chaining.

* **NetworkPolicy scale and performance tests**
Evaluate and benchmark the NetworkPolicy implementation performance at a large
scale, including the policy computation performance of Antrea Controller and the
OVS datapath performance.

* **OVS with DPDK or AF_XDP**
Leverage OVS with DPDK or AF_XDP for high performance.
