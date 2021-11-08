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
Antrea [supports Windows K8s Node](docs/windows.md) since version 0.7.0.
However, a few features including: Egress, NodePortLocal, IPsec encryption are
not supported for Windows Node yet. We will continue to add more features for
Windows, and improve Antrea Agent and OVS installation on Windows Nodes.

* **Antrea NetworkPolicy enhancements**
Antrea added support for [Antrea-native policies](docs/antrea-network-policy.md)
in addition to K8s NetworkPolicy since version 0.8.0, and already supports
Antrea (Namespace scoped) NetworkPolicy, ClusterNetworkPolicy, ClusterGroup,
Tier, and features including traffic statistics, traffic logging, policy
realization status, `Drop` and `Reject` actions, policy priority, `AppliedTo`
at rule level, Namespace isolation, FQDN and Service as egress rule destination.
We will continue to add more advanced NetworkPolicy features.

* **Network diagnostics and observability**
Network diagnostics and observability is one area we want to focus on. Antrea
already implements some useful features on this front, including [Octant UI
plugin](docs/octant-plugin-installation.md), [CLI](docs/antctl.md),
[Traceflow](docs/traceflow-guide.md), [network flow export and visualization](docs/network-flow-visibility.md),
[Prometheus metrics](docs/prometheus-integration.md), [OVS flow dumping](docs/antctl.md#dumping-ovs-flows)
and [packet tracing](docs/antctl.md#ovs-packet-tracing), [NetworkPolicy
diagnostics](docs/antctl.md#networkpolicy-commands). We will continue to
enhance existing features and add new features to help diagnose K8s networking
and NetworkPolicy implementation, and to provide good visibility into the Antrea
network.

* **Flexible IPAM**
So far Antrea leverages K8s NodeIPAM for IPAM which allocates a single subnet
for each K8s Node. NodeIPAM can either run as part of the Antrea Controller, or
run within kube-controller-manager.
In future, Antrea will implement its own IPAM, and support more IPAM strategies
besides subnet per Node, like multiple IP pools per Node or per Namespace.

* **NFV and Telco use cases**
We plan to explore and provide support for NFV and Telco use cases. We will add
native Pod multi-interface support in Antrea, and support Pod interfaces on
SRIOV devices, OVS DPDK bridge, overlay network, and Network Service Chaining.

* **L7 security policy and visibility**
Enhance Antrea to provide application level security and visibility to K8s
workloads. This includes extending Antrea-native NetworkPolicies to support L7 /
application protocols (HTTP, DNS, etc.), and extending Antrea diagnostics and
observability features to get into application level visibility.

* **Multi-cluster networking**
We would extend Antrea from CNI of a single Kubernetes cluster to multi-cluster
networking, and implement multi-cluster features like multi-cluster Services,
cross-cluster connectivity, multi-cluster NetworkPolicies.

* **Analytics**
With the network flows exported by Antrea, we plan to further build an analytics
solution that consumes the network flows, and provides traffic analysis,
NetworkPolicy recommendation, security and network performance monitoring.

* **K8s Node security**
So far Antrea focuses on K8s Pod networking and security, but we would like to
extend Antrea-native NetworkPolicies to cover protection of K8s Nodes too.

* **NetworkPolicy scale and performance tests**
Evaluate and benchmark the NetworkPolicy implementation performance at a large
scale, including the policy computation performance of Antrea Controller and the
OVS datapath performance.

* **OVS with DPDK or AF_XDP**
Leverage OVS with DPDK or AF_XDP for high performance.
