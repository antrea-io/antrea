# Changelog 1.1

## 1.1.2 - 2021-08-11

### Changed

- Improve the batch installation of NetworkPolicy rules when the Agent starts: only generate flow operations based on final desired state instead of incrementally. ([#2479](https://github.com/antrea-io/antrea/pull/2479), [@tnqn])

### Fixed

- Fix deadlock when initializing the GroupEntityIndex (in the Antrea Controller) with many groups; this was preventing correct distribution and enforcement of NetworkPolicies. ([#2376](https://github.com/antrea-io/antrea/pull/2376), [@tnqn])
- Use "os/exec" package instead of third-party modules to run PowerShell commands and configure host networking on Windows; this change prevents Agent goroutines from getting stuck when configuring routes. ([#2363](https://github.com/antrea-io/antrea/pull/2363), [@lzhecheng]) [Windows]
- Fix panic in Agent when calculating the stats for a rule newly added to an existing NetworkPolicy. ([#2495](https://github.com/antrea-io/antrea/pull/2495), [@tnqn])
- Fix bug in iptables rule installation for dual-stack clusters: if a rule was already present for one protocol but not the other, its installation may have been skipped. ([#2469](https://github.com/antrea-io/antrea/pull/2469), [@lzhecheng])
- Upgrade OVS version to 2.14.2 to pick up security fixes for CVE-2015-8011, CVE-2020-27827 and CVE-2020-35498. ([#2451](https://github.com/antrea-io/antrea/pull/2451), [@antoninbas])

## 1.1.1 - 2021-07-07

### Fixed

- Fix inter-Node ClusterIP Service access when AntreaProxy is deactivated. ([#2318](https://github.com/antrea-io/antrea/pull/2318), [@tnqn])
- Fix duplicate group ID allocation in AntreaProxy when using a combination of IPv4 and IPv6 Services in dual-stack clusters; this was causing Service connectivity issues. ([#2317](https://github.com/antrea-io/antrea/pull/2317), [@hongliangl])
- Fix intra-Node ClusterIP Service access when both the AntreaProxy and Egress features are enabled. ([#2332](https://github.com/antrea-io/antrea/pull/2332), [@tnqn])
- Fix invalid clean-up of the HNS Endpoint during Pod deletion, when Docker is used as the container runtime. ([#2306](https://github.com/antrea-io/antrea/pull/2306), [@wenyingd]) [Windows]
- Fix race condition on Windows when retrieving the local HNS Network created by Antrea for containers. ([#2253](https://github.com/antrea-io/antrea/pull/2253), [@tnqn]) [Windows]
- Fix invalid conversion function between internal and versioned types for controlplane API, which was causing JSON marshalling errors. ([#2312](https://github.com/antrea-io/antrea/pull/2312), [@tnqn])
- Fix implementation of the v1beta1 version of the legacy "controlplane.antrea.tanzu.vmware.com" API: the API was incorrectly using some v1beta2 types and it was missing some field selectors. ([#2305](https://github.com/antrea-io/antrea/pull/2305), [@tnqn])

## 1.1.0 - 2021-05-28

### Added

- Enable "noEncap" and "hybrid" traffic modes for clusters which include Windows Nodes. ([#2160](https://github.com/antrea-io/antrea/pull/2160) [#2161](https://github.com/antrea-io/antrea/pull/2161), [@lzhecheng] [@tnqn]) [Windows]
  * Each Agent is responsible for annotating its Node resource with the MAC address of the uplink interface, using the "node.antrea.io/mac-address" annotation; the annotation is used to forward Pod traffic
- Add a generic mechanism to define policy rules enforced on all the network endpoints belonging to the same Namespace as the target of the AppliedTo; this makes it very easy to define an Antrea CNP to only allow same-Namespace traffic (Namespace isolation) across all Namespaces in the cluster or a subset of them. ([#1961](https://github.com/antrea-io/antrea/pull/1961), [@Dyanngg])
- Add support for the "Reject" action of Antrea-native policies in the Traceflow observations. ([#2032](https://github.com/antrea-io/antrea/pull/2032), [@gran-vmv])
- Add support for the "endPort" field in K8s NetworkPolicies. ([#2190](https://github.com/antrea-io/antrea/pull/2190), [@GraysonWu])
- Add support for [dual-stack Services], which are enabled by default in K8s v1.21, in AntreaProxy. ([#2207](https://github.com/antrea-io/antrea/pull/2207), [@xliuxu])
- Export flow records about connections denied by NetworkPolicies from the FlowExporter and the FlowAggregator; the records include information about the policy responsible for denying the connection when applicable. ([#2112](https://github.com/antrea-io/antrea/pull/2112), [@zyiou])
- Add more NetworkPolicy-related information to IPFIX flow records exported by the FlowAggregator (policy type and rule name). ([#2163](https://github.com/antrea-io/antrea/pull/2163), [@heanlan])
- Add live-traffic Traceflow support to the Antrea [Octant] plugin, which includes support for displaying the captured packet's headers. ([#2124](https://github.com/antrea-io/antrea/pull/2124), [#2182](https://github.com/antrea-io/antrea/pull/2182), [@luolanzone])
- Add crd.antrea.io/v1alpha3/ClusterGroup API resource which removes the deprecated "ipBlock" field; a [conversion webhook] is added to the Controller to convert from the v1alpha2 version to the v1alpha3 version. ([#2008](https://github.com/antrea-io/antrea/pull/2008), [@Dyanngg])
- Add support for providing an IP address as the source for live-traffic Traceflow; the source can also be omitted altogether in which case any source can be a match. ([#2068](https://github.com/antrea-io/antrea/pull/2068), [@jianjuns])
- Add ICMP echo ID and sequence number to the captured packet for live-traffic Traceflow. ([#2162](https://github.com/antrea-io/antrea/pull/2162), [@jianjuns])
- Add support for dumping OVS groups with the "antctl get of" command. ([#1984](https://github.com/antrea-io/antrea/pull/1984), [@jianjuns])
- Add new "antrea_agent_deny_connection_count" Prometheus metric to keep track of the number of connections denied because of NetworkPolicies; if too many connections are denied within a short window of time, the metric may undercount. ([#2112](https://github.com/antrea-io/antrea/pull/2112), [@zyiou])
- Generate and check-in clientset code for ClusterGroupMembers and GroupAssociation, to facilitate consumption of these APIs by third-party software. ([#2130](https://github.com/antrea-io/antrea/pull/2130), [@Dyanngg])
- Document requirements for the Node network (how to configure firewalls, security groups, etc.) when running Antrea. ([#2098](https://github.com/antrea-io/antrea/pull/2098), [@luolanzone])

### Changed

- Rename Antrea Go module from github.com/vmware-tanzu/antrea to antrea.io/antrea, using a vanity import path. ([#2154](https://github.com/antrea-io/antrea/issues/2154), [@antoninbas])
- Enable [Receive Segment Coalescing (RSC)] in the vSwitch on Windows Nodes to reduce host CPU utilization and increase throughput when traffic is not encapsulated. ([#2198](https://github.com/antrea-io/antrea/pull/2198), [@tnqn])
- Change the export mechanism for the FlowAggregator: instead of exporting all flows periodically with a fixed interval, we introduce an "active timeout" and an "inactive timeout", and flow information is exported differently based on flow activity. ([#1949](https://github.com/antrea-io/antrea/pull/1949), [@srikartati])
- Periodically verify the local gateway's configuration and the gateway routes on each Node, and correct any discrepancy. ([#2091](https://github.com/antrea-io/antrea/pull/2091), [@hty690])
- Remove the "enableTLSToFlowAggregator" parameter from the Agent configuration; this information can be provided using the "flowCollectorAddr" parameter. ([#2193](https://github.com/antrea-io/antrea/pull/2193), [@zyiou])
- Specify antrea-agent as the default container for kubectl commands using the "kubectl.kubernetes.io/default-container" annotation introduced in K8s v1.21. ([#2065](https://github.com/antrea-io/antrea/pull/2065), [@tnqn])
- Improve the OpenAPI schema for Antrea-native policy CRDs to enable a more comprehensive validation. ([#2125](https://github.com/antrea-io/antrea/pull/2125), [@wenqiq])
- Bump K8s dependencies (k8s.io/apiserver, k8s.io/client-go, etc.) to v0.21.0 and replace klog with klog/v2. ([#1973](https://github.com/antrea-io/antrea/pull/1973), [@xliuxu])
- Add nodeSelector for FlowAggregator and ELK Pods in YAML manifests: they must run on amd64 Nodes. ([#2087](https://github.com/antrea-io/antrea/pull/2087), [@antoninbas])
- Update reference Kibana configuration to decode the flowType field and display a human-friendly string instead of an integer. ([#2102](https://github.com/antrea-io/antrea/pull/2102), [@zyiou])
- Package [whereabouts] CNI plugin into the Antrea Linux container image and install the binary on each Node. ([#2185](https://github.com/antrea-io/antrea/pull/2185), [@arunvelayutham])
- Start enabling Antrea end-to-end tests for Windows Nodes. ([#2018](https://github.com/antrea-io/antrea/pull/2018), [@lzhecheng])
- Parameterize K8s download path in Windows helper scripts. ([#2174](https://github.com/antrea-io/antrea/pull/2174) [#2192](https://github.com/antrea-io/antrea/pull/2192), [@jayunit100] [@lzhecheng]) [Windows]

### Fixed

- It was discovered that the AntreaProxy implementation has an upper-bound for the number of Endpoints it can support for each Service: we increase this upper-bound from ~500 to 800, log a warning for Services with a number of Endpoints greater than 800, and arbitrarily drop some Endpoints so we can still provide load-balancing for the Service. ([#2101](https://github.com/antrea-io/antrea/pull/2101), [@hongliangl])
- Fix Antrea-native policy with multiple AppliedTo selectors: some rules were never realized by the Agents as they thought they had only received partial information from the Controller. ([#2084](https://github.com/antrea-io/antrea/pull/2084), [@tnqn])
- Fix re-installation of the OpenFlow groups when the OVS daemons are restarted to ensure that AntreaProxy keeps functioning. ([#2134](https://github.com/antrea-io/antrea/pull/2134), [@antoninbas])
- Configure the MTU correctly in Windows containers, or Path MTU Discovery fails and datagrams with the minimum size are transmitted leading to poor performance in overlay mode. ([#2133](https://github.com/antrea-io/antrea/pull/2133), [@lzhecheng]) [Windows]
- Fix IPFIX flow records exported by the Antrea Agent. ([#2089](https://github.com/antrea-io/antrea/pull/2089), [@zyiou])
  * If a connection spanned multiple export cycles, it wasn't handled properly and no record was sent for the connection
  * If a connection spanned a single export cycle, a single record was sent but "delta counters" were set to 0 which caused flow visualization to omit the flow in dashboards
- Fix incorrect stats reporting for ingress rules of some NetworkPolicies: some types of traffic were bypassing the OVS table keeping track of statistics once the connection was established, causing packet and byte stats to be incorrect. ([#2078](https://github.com/antrea-io/antrea/pull/2078), [@ceclinux])
- Fix ability of the FlowExporter to connect to the FlowAggregator on Windows: the "flow-aggregator.flow-aggregator.svc" DNS name cannot be resolved on Windows because the Agent is running as a process. ([#2138](https://github.com/antrea-io/antrea/pull/2138), [@dreamtalen]) [Windows]
- Fix Traceflow for "hairpinned" Service traffic. ([#2167](https://github.com/antrea-io/antrea/pull/2167), [@gran-vmv])
- Fix possible crash in the FlowExporter and FlowAggregator when re-establishing a connection for exporting flow records. ([#2039](https://github.com/antrea-io/antrea/pull/2039), [@srikartati])
- Fix local access (from the K8s Node) to the port of a Pod with NodePortLocal enabled running on the same Node. ([#2200](https://github.com/antrea-io/antrea/pull/2200), [@antoninbas])
- Add conntrack label parsing in the FlowExporter when using the OVS netdev datapath, so that NetworkPolicy information can be populated correctly in flow records. ([#2194](https://github.com/antrea-io/antrea/pull/2194), [@dreamtalen])
- Fix the retry logic when enabling the OVS bridge local interface on Windows Nodes. ([#2081](https://github.com/antrea-io/antrea/pull/2081), [@antoninbas]) [Windows]
- Sleep for a small duration before injecting Traceflow packet even when the destination is local, to ensure that flow installation can complete and avoid transient errors. ([#2114](https://github.com/antrea-io/antrea/pull/2114), [@gran-vmv])
- Build antrea-cni binary and release binaries without cgo, to avoid dependencies on system libraries. ([#2189](https://github.com/antrea-io/antrea/pull/2189), [@antoninbas])
- Do not populate hostNetwork Pods into AppliedTo groups sent by the Controller to the Agents to avoid unnecessary logs (NetworkPolicies are not enforced on hostNetwork Pods). ([2093](https://github.com/antrea-io/antrea/pull/2093), [@Dyanngg])
- Fix formatting of K8s code generation tags for Antrea API type declarations, to ensure that auto-generated godocs are rendered correctly. ([#2164](https://github.com/antrea-io/antrea/pull/2164), [@heshengyuan1311])
- Update brew install commands in the documentation for bringing up a local K8s test cluster. ([#2074](https://github.com/antrea-io/antrea/pull/2074), [@RayBB])

[Octant]: https://github.com/vmware-tanzu/octant
[conversion webhook]: https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#webhook-conversion
[Receive Segment Coalescing (RSC)]: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh997024(v=ws.11)
[whereabouts]: https://github.com/k8snetworkplumbingwg/whereabouts
[dual-stack Services]: https://kubernetes.io/docs/concepts/services-networking/dual-stack/#services

[@antoninbas]: https://github.com/antoninbas
[@arunvelayutham]: https://github.com/arunvelayutham
[@ceclinux]: https://github.com/ceclinux
[@dreamtalen]: https://github.com/dreamtalen
[@Dyanngg]: https://github.com/Dyanngg
[@gran-vmv]: https://github.com/gran-vmv
[@GraysonWu]: https://github.com/GraysonWu
[@heanlan]: https://github.com/heanlan
[@heshengyuan1311]: https://github.com/heshengyuan1311
[@hongliangl]: https://github.com/hongliangl
[@hty690]: https://github.com/hty690
[@jayunit100]: https://github.com/jayunit100
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@lzhecheng]: https://github.com/lzhecheng
[@RayBB]: https://github.com/RayBB
[@shadowlan]: https://github.com/shadowlan
[@srikartati]: https://github.com/srikartati
[@tnqn]: https://github.com/tnqn
[@wenqiq]: https://github.com/wenqiq
[@xliuxu]: https://github.com/xliuxu
[@zyiou]: https://github.com/zyiou
