# Changelog 1.2

## 1.2.4 - 2022-04-29

### Changed
- Use iptables-wrapper in Antrea container. Now antrea-agent can work with distros that lack the iptables kernel module of "legacy" mode (ip_tables). ([#3276](https://github.com/antrea-io/antrea/pull/3276), [@antoninbas])
- Reduce permissions of Antrea ServiceAccount for updating annotations. ([#3393](https://github.com/antrea-io/antrea/pull/3393), [@tnqn])
- [Windows] Use uplink MAC as source MAC when transmitting packets to underlay network from Windows Nodes. Therefore, MAC address spoofing configuration like "Forged transmits" in VMware vSphere doesn't need to be enabled. ([#3516](https://github.com/antrea-io/antrea/pull/3516), [@wenyingd])

### Fixed
- Fix DNS resolution error of antrea-agent on AKS by using `ClusterFirst` dnsPolicy. ([#3701](https://github.com/antrea-io/antrea/pull/3701), [@tnqn])
- Fix status report of Antrea-native policies with multiple rules that have different AppliedTo. ([#3074](https://github.com/antrea-io/antrea/pull/3074), [@tnqn])
- Upgrade Go version to 1.17 to pick up security fix for CVE-2021-44716. ([#3189](https://github.com/antrea-io/antrea/pull/3189), [@antoninbas])
- Fix NetworkPolicy resources dump for Agent's supportbundle. ([#3083](https://github.com/antrea-io/antrea/pull/3083), [@antoninbas])
- Fix gateway interface MTU configuration error on Windows. ([#3043](https://github.com/antrea-io/antrea/pull/3043), [@lzhecheng]) [Windows]
- Fix initialization error of antrea-agent on Windows by specifying hostname explicitly in VMSwitch commands. ([#3169](https://github.com/antrea-io/antrea/pull/3169), [@XinShuYang]) [Windows]
- Ensure that the Windows Node name obtained from the environment or from hostname is converted to lower-case. ([#2672](https://github.com/antrea-io/antrea/pull/2672), [@shettyg]) [Windows]
- Fix typos in the example YAML in antrea-network-policy doc. ([#3079](https://github.com/antrea-io/antrea/pull/3079) [#3092](https://github.com/antrea-io/antrea/pull/3092), [@antoninbas] [@Jexf])
- Fix ipBlock referenced in nested ClusterGroup not processed correctly. ([#3383](https://github.com/antrea-io/antrea/pull/3383), [@Dyanngg])
- Fix NetworkPolicy may not be enforced correctly after restarting a Node. ([#3467](https://github.com/antrea-io/antrea/pull/3467), [@tnqn])
- Fix antrea-agent crash caused by interface detection in AKS/EKS with NetworkPolicyOnly mode. ([#3219](https://github.com/antrea-io/antrea/pull/3219), [@wenyingd])
- Fix locally generated packets from Node net namespace might be SNATed mistakenly when Egress is enabled. ([#3430](https://github.com/antrea-io/antrea/pull/3430), [@tnqn])

## 1.2.3 - 2021-09-24

### Changed

- Support returning partial supportbundle results when some Nodes fail to respond. ([#2788](https://github.com/antrea-io/antrea/pull/2788), [@hangyan])
- Remove restriction that only GRE tunnels can be used when enabling IPsec: VXLAN can also be used, and so can Geneve (if the Linux kernel version for the Nodes is recent enough). ([#2764](https://github.com/antrea-io/antrea/pull/2764), [@luolanzone])
- Reduce memory usage of antctl when collecting supportbundle. ([#2821](https://github.com/antrea-io/antrea/pull/2821), [@tnqn])

### Fixed

- Fix nil pointer error when collecting a supportbundle on a Node for which the antrea-agent container image does not include "iproute2"; this does not affect the standard antrea/antrea-ubuntu container image. ([#2789](https://github.com/antrea-io/antrea/pull/2789), [@liu4480])
- When creating an IPsec OVS tunnel port to a remote Node, handle the case where the port already exists but with a stale config graciously: delete the existing port first, then recreate it. ([#2765](https://github.com/antrea-io/antrea/pull/2765), [@luolanzone])
- Fix panic in the Antrea Controller when it processes ClusterGroups that are used by multiple ClusterNetworkPolicies. ([#2768](https://github.com/antrea-io/antrea/pull/2768), [@tnqn])
- Fix nil pointer error when antrea-agent updates OpenFlow priorities of Antrea-native policies without Service ports. ([#2758](https://github.com/antrea-io/antrea/pull/2758), [@wenyingd])
- Fix Pod-to-Service access on Windows when the Endpoints are not non-hostNetwork Pods (e.g. the `kubernetes` Service). ([#2702](https://github.com/antrea-io/antrea/pull/2702), [@wenyingd]) [Windows]
- Fix container network interface MTU configuration error when using containerd as the runtime on Windows. ([#2773](https://github.com/antrea-io/antrea/pull/2773), [@wenyingd]) [Windows]

## 1.2.2 - 2021-08-16

### Changed

- Update [go-ipfix] to version v0.5.7 to improve overall performance of the FlowExporter feature, and in particular of the Flow Aggregator component. ([#2574](https://github.com/antrea-io/antrea/pull/2574), [@srikartati] [@zyiou])

### Fixed

- Handle transient iptables-restore failures (caused by xtables lock contention) in the NodePortLocal initialization logic. ([#2555](https://github.com/antrea-io/antrea/pull/2555), [@antoninbas])
- Fix handling of the "reject" packets generated by the Antrea Agent in the OVS pipeline, to avoid infinite looping when traffic between two endpoints is rejected by network policies in both directions. ([#2579](https://github.com/antrea-io/antrea/pull/2579), [@GraysonWu])
- Fix interface naming for IPsec tunnels: based on Node names, the first char could sometimes be a dash, which is not valid. ([#2486](https://github.com/antrea-io/antrea/pull/2486), [@luolanzone])

## 1.2.1 - 2021-08-06

### Changed

- Install all Endpoint flows belonging to a Service via a single OpenFlow bundle, to reduce flow installation time when the Agent starts. ([#2476](https://github.com/antrea-io/antrea/pull/2476), [@tnqn])
- Improve the batch installation of NetworkPolicy rules when the Agent starts: only generate flow operations based on final desired state instead of incrementally. ([#2479](https://github.com/antrea-io/antrea/pull/2479), [@tnqn])
- Use GroupMemberSet.Merge instead of GroupMemberSet.Union to reduce CPU usage and memory footprint in the Agent's policy controller. ([#2467](https://github.com/antrea-io/antrea/pull/2467), [@tnqn])
- When checking for the existence of an iptables chain, stop listing all the chains and searching through them; this change reduces the Agent's memory footprint. ([#2458](https://github.com/antrea-io/antrea/pull/2458), [@tnqn])
- Tolerate more failures for the Agent's readiness probe, as the Agent may stay disconnected from the Controller for a long time in some scenarios. ([#2535](https://github.com/antrea-io/antrea/pull/2535), [@tnqn])
- When listing NetworkPolicyStats through the Controller API, return an empty list if the `NetworkPolicyStats` Feature Gate is disabled, instead of returning an error. ([#2386](https://github.com/antrea-io/antrea/pull/2386), [@PeterEltgroth])

### Fixed

- Fix panic in Agent when calculating the stats for a rule newly added to an existing NetworkPolicy. ([#2495](https://github.com/antrea-io/antrea/pull/2495), [@tnqn])
- Fix bug in iptables rule installation for dual-stack clusters: if a rule was already present for one protocol but not the other, its installation may have been skipped. ([#2469](https://github.com/antrea-io/antrea/pull/2469), [@lzhecheng])
- Fix deadlock in the Agent's FlowExporter, between the export goroutine and the conntrack polling goroutine. ([#2429](https://github.com/antrea-io/antrea/pull/2429), [@srikartati])
- Upgrade OVS version to 2.14.2 to pick up security fixes for CVE-2015-8011, CVE-2020-27827 and CVE-2020-35498. ([#2451](https://github.com/antrea-io/antrea/pull/2451), [@antoninbas])
- Upgrade OVS version to 2.14.2-antrea.1 for Windows Nodes; this version of OVS is built on top of the upstream 2.14.2 release and also includes a patch to fix TCP checksum computation when the DNAT action is used. ([#2549](https://github.com/antrea-io/antrea/pull/2549), [@lzhecheng]) [Windows]
- Periodically delete stale connections in the Flow Exporter if they cannot be exported (e.g. because the collector is not available), to avoid running out-of-memory. ([#2516](https://github.com/antrea-io/antrea/pull/2516), [@srikartati])
- Clean up log files for the Flow Aggregator periodically: prior to this fix, the "--log_file_max_size" and "--log_file_max_num" command-line flags were ignore for the flow-aggregator Pod. ([#2522](https://github.com/antrea-io/antrea/pull/2522), [@srikartati])
- Fix missing template ID when sending the first IPFIX flow record from the FlowAggregator. ([#2546](https://github.com/antrea-io/antrea/pull/2546), [@zyiou])
- Fix reference Logstash configuration to avoid division by zero in throughput calculation. ([#2432](https://github.com/antrea-io/antrea/pull/2432), [@zyiou])

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

[@Dhruv-J]: https://github.com/Dhruv-J
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@Jexf]: https://github.com/Jexf
[@PeterEltgroth]: https://github.com/PeterEltgroth
[@XinShuYang]: https://github.com/XinShuYang
[@abhiraut]: https://github.com/abhiraut
[@antoninbas]: https://github.com/antoninbas
[@dreamtalen]: https://github.com/dreamtalen
[@hangyan]: https://github.com/hangyan
[@hongliangl]: https://github.com/hongliangl
[@liu4480]: https://github.com/liu4480
[@luolanzone]: https://github.com/luolanzone
[@lzhecheng]: https://github.com/lzhecheng
[@monotosh-avi]: https://github.com/monotosh-avi
[@ramay1]: https://github.com/ramay1
[@shettyg]: https://github.com/shettyg
[@srikartati]: https://github.com/srikartati
[@tnqn]: https://github.com/tnqn
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
[@zyiou]: https://github.com/zyiou
