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
However, a few features including: Egress, NodePortLocal, IPsec encryption are
not supported for Windows Node yet. We will continue to add more features for
Windows, and improve Antrea Agent and OVS installation on Windows Nodes.

* **Antrea NetworkPolicy enhancements**
Antrea added support for [Antrea-native policies](antrea-network-policy.md)
in addition to K8s NetworkPolicy since version 0.8.0. We already support
Antrea (Namespace scoped) NetworkPolicy, ClusterNetworkPolicy, ClusterGroup, and
tiering, but will continue to add more advanced NetworkPolicy features.

* **Network diagnostics and observability**
Network diagnostics and observability is one area we want to focus on. Antrea
already implements some useful features on this front, including [Octant UI
plugin](octant-plugin-installation.md), [CLI](antctl.md),
[Traceflow](traceflow-guide.md), [network flow export and visualization](network-flow-visibility.md),
[Prometheus metrics](prometheus-integration.md), [OVS flow dumping](antctl.md#dumping-ovs-flows)
and [packet tracing](antctl.md#ovs-packet-tracing), [NetworkPolicy
diagnostics](antctl.md#networkpolicy-commands). We will continue to
enhance existing features and add new features to help diagnose K8s networking
and NetworkPolicy implementation, and to provide good visibility into the Antrea
network.

* **Flexible IPAM**
So far Antrea leverages K8s NodeIPAM for IPAM which allocates a single subnet
for each K8s Node. In future, Antrea will implement its own IPAM, and support
more IPAM strategies besides subnet per Node, like IP pool per Node or
per Namespace.

* **Egress policy**
Antrea released alpha support for [Egress](feature-gates.md#egress) in
version 1.0.0. Users can choose a specific SNAT IP for a selected set of Pods
with an Egress CRD, and then the egress traffic from the Pods to external
network will be SNAT'd using the SNAT IP. This feature is very useful for
services in the Node or external network to identify the source of Pod traffic
based on SNAT IP and enforce specific policies on the traffic. However, the
Egress feature still has several major limitations which need to be addressed.
For example, today the SNAT IPs used in Egresses must be manually configured on
the Nodes, and there is no auto-failover of Egress Nodes. Also check the
[egress policy proposal](https://github.com/vmware-tanzu/antrea/issues/667) to
learn more.

* **NFV and Telco use cases**
We plan to explore and provide support for NFV and Telco use cases. We will add
native Pod multi-interface support in Antrea, and support Pod interfaces on
SRIOV devices, OVS DPDK bridge, overlay network, and Network Service Chaining.

* **K8s Node security**
So far Antrea focuses on K8s Pod networking and security, but we would like to
extend Antrea-native NetworkPolicies to cover protection of K8s Nodes too.

* **L7 security policy and visibility**
Enhance Antrea to provide application level security and visibility to K8s
workloads. This includes extending Antrea-native NetworkPolicies to support L7 /
application protocols (HTTP, DNS, etc.), and extending Antrea diagnostics and
observability features to get into application level visibility.

* **NetworkPolicy scale and performance tests**
Evaluate and benchmark the NetworkPolicy implementation performance at a large
scale, including the policy computation performance of Antrea Controller and the
OVS datapath performance.

* **OVS with DPDK or AF_XDP**
Leverage OVS with DPDK or AF_XDP for high performance.
