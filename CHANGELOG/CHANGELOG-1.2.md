# Changelog 1.2

## 1.2.0 - 2021-07-14

The NetworkPolicyStats feature is graduated from Alpha to Beta and is therefore enabled by default.

### Added

- Add new ExternalIPPool API to define ranges of IP addresses which can be used as Egress SNAT IPs; these IPs are allocated to Nodes according to a nodeSelector, with support for failover if a Node goes down. ([#2236](https://github.com/antrea-io/antrea/pull/2236) [#2237](https://github.com/antrea-io/antrea/pull/2237) [#2186](https://github.com/antrea-io/antrea/pull/2186) [#2358](https://github.com/antrea-io/antrea/pull/2358) [#2345](https://github.com/antrea-io/antrea/pull/2345) [#2371](https://github.com/antrea-io/antrea/pull/2371), [@tnqn] [@wenqiq])
  * Refer to the [Egress user documentation](https://github.com/antrea-io/antrea/blob/v1.2.0/docs/egress.md) for more information
- Use OpenFlow meters on Linux to rate-limit PacketIn messages sent by the OVS datapath to the Antrea Agent. ([#2215](https://github.com/antrea-io/antrea/pull/2215), [@GraysonWu] [@antoninbas])
- Add K8s labels for the source and destination Pods (when applicable) as IPFIX Information Elements when exporting flow records from the FlowAggregator. ([#2240](https://github.com/antrea-io/antrea/pull/2240), [@dreamtalen])
- Add ability to print Antrea Agent and / or Antrea Controller FeatureGates using antctl, with the "antctl get featuregates" command. ([#2082](https://github.com/antrea-io/antrea/pull/2082), [@luolanzone])
- Add support for running the same Traceflow request again (with the same parameters) from the Antrea Octant plugin. ([#2202](https://github.com/antrea-io/antrea/pull/2202), [@Dhruv-J])
- Add ability for the Antrea Agent to configure SR-IOV secondary network interfaces for Pods (these interfaces are not attached to the OVS bridge); however, there is currently no available API for users to request secondary Pod network interfaces. ([#2151](https://github.com/antrea-io/antrea/pull/2151), [@ramay1])

### Changed

- When enabling NodePortLocal on a Service, use the Service's target ports instead of the (optional) container ports for the selected Pods to determine how to configure port forwarding for the Pods. ([#2222](https://github.com/antrea-io/antrea/pull/2222), [@monotosh-avi])
- Update version of the [go-ipfix] dependency to improve FlowExporter performance. ([#2129](https://github.com/antrea-io/antrea/pull/2129), [@zyiou])
- Remove deprecated API version networking.antrea.tanzu.vmware.com/v1beta1 as per our API deprecation policy. ([#2265](https://github.com/antrea-io/antrea/pull/2265), [@hangyan])
- Show translated source IP address in Traceflow observations when Antrea performs SNAT in OVS. ([#2227](https://github.com/antrea-io/antrea/pull/2227), [@luolanzone])
- Remove unnecessary IPFIX Information Elements from the flow records exported by the FlowAggregator: "originalExporterIPv4Address", "originalExporterIPv6Address" and "originalObservationDomainId". ([#2361](https://github.com/antrea-io/antrea/pull/2361), [@zyiou])
- Ignore non-TCP Service ports in the NodePortLocal implementation and document the restriction that only TCP is supported. ([#2396](https://github.com/antrea-io/antrea/pull/2396), [@antoninbas])
- Drop packets received by the uplink in PREROUTING (using iptables) when using the OVS userspace datapath (Kind clusters), to prevent these packets from being processed by the Node's TCP/IP stack. ([#2143](https://github.com/antrea-io/antrea/pull/2143), [@antoninbas])
- Improve documentation for Antrea-native policies to include information about the "namespaces" field introduced in Antrea v1.1 for the ClusterNetworkPolicy API. ([#2271](https://github.com/antrea-io/antrea/pull/2271), [@abhiraut])

### Fixed

- Fix inter-Node ClusterIP Service access when AntreaProxy is disabled. ([#2318](https://github.com/antrea-io/antrea/pull/2318), [@tnqn])
- Fix duplicate group ID allocation in AntreaProxy when using a combination of IPv4 and IPv6 Services in dual-stack clusters; this was causing Service connectivity issues. ([#2317](https://github.com/antrea-io/antrea/pull/2317), [@hongliangl])
- Fix intra-Node ClusterIP Service access when both the AntreaProxy and Egress features are enabled. ([#2332](https://github.com/antrea-io/antrea/pull/2332), [@tnqn])
- Fix deadlock when initializing the GroupEntityIndex (in the Antrea Controller) with many groups; this was preventing correct distribution and enforcement of NetworkPolicies. ([#2376](https://github.com/antrea-io/antrea/pull/2376), [@tnqn])
- Fix implementation of ClusterNetworkPolicy rules with an empty "From" field (for ingress rules) or an empty "To" field (for egress rules). ([#2383](https://github.com/antrea-io/antrea/pull/2383), [@Dyanngg])
- Use "os/exec" package instead of third-party modules to run PowerShell commands and configure host networking on Windows; this change prevents Agent goroutines from getting stuck when configuring routes. ([#2363](https://github.com/antrea-io/antrea/pull/2363), [@lzhecheng]) [Windows]
- Fix invalid clean-up of the HNS Endpoint during Pod deletion, when Docker is used as the container runtime. ([#2306](https://github.com/antrea-io/antrea/pull/2306), [@wenyingd]) [Windows]
- Fix race condition on Windows when retrieving the local HNS Network created by Antrea for containers. ([#2253](https://github.com/antrea-io/antrea/pull/2253), [@tnqn]) [Windows]
- Fix checksum computation error when sending PacketOut messages to OVS. ([#2273](https://github.com/antrea-io/antrea/pull/2273), [@Dyanngg])
- Fix invalid conversion function between internal and versioned types for controlplane API, which was causing JSON marshalling errors. ([#2302](https://github.com/antrea-io/antrea/pull/2302), [@tnqn])
- Fix implementation of the v1beta1 version of the legacy "controlplane.antrea.tanzu.vmware.com" API: the API was incorrectly using some v1beta2 types and it was missing some field selectors. ([#2305](https://github.com/antrea-io/antrea/pull/2305), [@tnqn])
- Verify that the discovered uplink is not virtual when creating the HNSNetwork; if it is, log a better error message. ([#2246](https://github.com/antrea-io/antrea/pull/2246), [@tnqn]) [Windows]
- When allocating a host port for NodePortLocal, make sure that the port is available first and reserve it by binding to it. ([#2385](https://github.com/antrea-io/antrea/pull/2385), [@antoninbas])
- Change default port range for NodePortLocal to 61000-62000, in order to avoid conflict with the default ip_local_port_range on Linux. ([#2382](https://github.com/antrea-io/antrea/pull/2382), [@antoninbas])
- Add NamespaceIndex to PodInformer of the NodePortLocal Controller to avoid error logs and slow searches. ([#2377](https://github.com/antrea-io/antrea/pull/2377), [@tnqn])
- When mutating an Antrea-native policy, only set the "PatchType" field in the mutating webhook's response if the "Patch" field is not empty, or the response may not be valid. ([#2295](https://github.com/antrea-io/antrea/pull/2295), [@Dyanngg])
- Populate the "egressNetworkPolicyRuleAction" IPFIX Information Element correctly in the FlowAggregator. ([#2228](https://github.com/antrea-io/antrea/pull/2228), [@zyiou])
- Protect Traceflow state from concurrent access in Antrea Octant plugin (in case of multiple browser sessions). ([#2261](https://github.com/antrea-io/antrea/pull/2261), [@antoninbas])
- Remove assumption that there is a single ovs-vswitchd .ctl file when invoking ovs-appctl from the Antrea Agent. ([#2260](https://github.com/antrea-io/antrea/pull/2260), [@antoninbas])
- Fix file permissions for the [whereabouts] binary included in the antrea/antrea-ubuntu Docker image. ([#2353](https://github.com/antrea-io/antrea/pull/2353), [@antoninbas])

[go-ipfix]: https://github.com/vmware/go-ipfix
[whereabouts]: https://github.com/k8snetworkplumbingwg/whereabouts

[@abhiraut]: https://github.com/abhiraut
[@antoninbas]: https://github.com/antoninbas
[@Dhruv-J]: https://github.com/Dhruv-J
[@dreamtalen]: https://github.com/dreamtalen
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@hangyan]: https://github.com/hangyan
[@hongliangl]: https://github.com/hongliangl
[@luolanzone]: https://github.com/luolanzone
[@lzhecheng]: https://github.com/lzhecheng
[@monotosh-avi]: https://github.com/monotosh-avi
[@ramay1]: https://github.com/ramay1
[@tnqn]: https://github.com/tnqn
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
[@zyiou]: https://github.com/zyiou
