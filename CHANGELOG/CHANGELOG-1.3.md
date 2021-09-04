# Changelog 1.3

## 1.3.0 - 2021-09-03

### Added

- Add ability to use Fully Qualified Domain Names (FQDNs) in egress policy rules when defining Antrea-native policies: both exact matches and wildcards are supported. ([#2613](https://github.com/antrea-io/antrea/pull/2613) [#2634](https://github.com/antrea-io/antrea/pull/2634) [#2667](https://github.com/antrea-io/antrea/pull/2667) [#2623](https://github.com/antrea-io/antrea/pull/2623) [#2691](https://github.com/antrea-io/antrea/pull/2691), [@Dyanngg] [@antoninbas] [@GraysonWu] [@madhukark] [@lzhecheng])
- Add support for WireGuard to encrypt inter-Node Pod traffic (as an alternative to IPsec); traffic mode must be set to encap and the "tunnelType" option will be ignored. ([#2297](https://github.com/antrea-io/antrea/pull/2297) [#2697](https://github.com/antrea-io/antrea/pull/2697), [@xliuxu] [@tnqn])
- Support for configurable transport interface for Pod traffic. ([#2370](https://github.com/antrea-io/antrea/pull/2370), [@wenyingd])
  * Use the "transportInterface" configuration parameter for the Antrea Agent to choose an interface by name; the default behavior is unchanged (interface to which the K8s Node IP is assigned is used)
  * On Windows, SNAT is now performed by the host and no longer by OVS, to accommodate for this change [Windows]
- Support for dual-stack transport interfaces (the IPv4 and IPv6 addresses have to be assigned to the same interface); this in turn enables support for the noEncap traffic mode in dual-stack clusters. ([#2436](https://github.com/antrea-io/antrea/pull/2436), [@lzhecheng])
- Add Status field to the ExternalIPPool CRD: it is used to report usage information for the pool (total number of IPs in the pool and number of IPs that are currently assigned). ([#2490](https://github.com/antrea-io/antrea/pull/2490), [@wenqiq])
- Add Egress support for IPv6 and dual-stack clusters. ([#2196](https://github.com/antrea-io/antrea/pull/2196) [#2655](https://github.com/antrea-io/antrea/pull/2655), [@wenqiq])
- Add ability to filter logs by timestamp with the "antctl supportbundle" command. ([#2389](https://github.com/antrea-io/antrea/pull/2389), [@hangyan] [@weiqiangt])
- Support for IPv6 / dual-stack Kind clusters. ([#2415](https://github.com/antrea-io/antrea/pull/2415), [@adobley] [@christianang] [@gwang550])
- Add support for sending JSON records from the Flow Aggregator instead of IPFIX records (which is still the default), as it can achieve better performance with Logstash. ([#2559](https://github.com/antrea-io/antrea/pull/2559), [@zyiou])
- Support "--sort-by" flag for "antctl get networkpolicy" in Agent mode. ([#2604](https://github.com/antrea-io/antrea/pull/2604), [@antoninbas])

### Changed

- Remove the restriction that a ClusterGroup must exist before it can be used as a child group to define other ClusterGroups. ([#2443](https://github.com/antrea-io/antrea/pull/2443), [@Dyanngg])
- Remove the restriction that a ClusterGroup must exist before it can be used in an Antrea ClusterNetworkPolicy. ([#2478](https://github.com/antrea-io/antrea/pull/2478), [@Dyanngg] [@abhiraut])
- Remove "controlplane.antrea.tanzu.vmware.com/v1beta1" API as per our API deprecation policy. ([#2528](https://github.com/antrea-io/antrea/pull/2528) [#2631](https://github.com/antrea-io/antrea/pull/2631), [@luolanzone])
- Controller responses to ClusterGroup membership queries ("/clustergroupmembers" API) now include the list of IPBlocks when appropriate. ([#2577](https://github.com/antrea-io/antrea/pull/2577), [@Dyanngg] [@abhiraut])
- Install all Endpoint flows belonging to a Service via a single OpenFlow bundle, to reduce flow installation time when the Agent starts. ([#2476](https://github.com/antrea-io/antrea/pull/2476), [@tnqn])
- Improve the batch installation of NetworkPolicy rules when the Agent starts: only generate flow operations based on final desired state instead of incrementally. ([#2479](https://github.com/antrea-io/antrea/pull/2479), [@tnqn] [@Dyanngg])
- Use GroupMemberSet.Merge instead of GroupMemberSet.Union to reduce CPU usage and memory footprint in the Agent's policy controller. ([#2467](https://github.com/antrea-io/antrea/pull/2467), [@tnqn])
- When checking for the existence of an iptables chain, stop listing all the chains and searching through them; this change reduces the Agent's memory footprint. ([#2458](https://github.com/antrea-io/antrea/pull/2458), [@tnqn])
- Tolerate more failures for the Agent's readiness probe, as the Agent may stay disconnected from the Controller for a long time in some scenarios. ([#2535](https://github.com/antrea-io/antrea/pull/2535), [@tnqn])
- Remove restriction that only GRE tunnels can be used when enabling IPsec: VXLAN can also be used, and so can Geneve (if the Linux kernel version for the Nodes is recent enough). ([#2489](https://github.com/antrea-io/antrea/pull/2489), [@luolanzone])
- Automatically perform deduplication on NetworkPolicy audit logs for denied connections: all duplicate connections received within a 1 second buffer window will be merged and the corresponding log entry will include the connection count. ([#2294](https://github.com/antrea-io/antrea/pull/2294) [#2578](https://github.com/antrea-io/antrea/pull/2578), [@qiyueyao])
- Support returning partial supportbundle results when some Nodes fail to respond. ([#2399](https://github.com/antrea-io/antrea/pull/2399), [@hangyan])
- When listing NetworkPolicyStats through the Controller API, return an empty list if the `NetworkPolicyStats` Feature Gate is disabled, instead of returning an error. ([#2386](https://github.com/antrea-io/antrea/pull/2386), [@PeterEltgroth])
- Update OVS version from 2.14.2 to 2.15.1: the new version fixes Geneve tunnel support in the userspace datapath (used for Kind clusters). ([#2515](https://github.com/antrea-io/antrea/pull/2515), [@antoninbas])
- Update [go-ipfix] to version v0.5.7 to improve overall performance of the FlowExporter feature, and in particular of the Flow Aggregator component. ([#2574](https://github.com/antrea-io/antrea/pull/2574), [@srikartati] [@zyiou])
- Support pretty-printing for AntreaAgentInfo and AntreaControllerInfo CRDs. ([#2572](https://github.com/antrea-io/antrea/pull/2572), [@antoninbas])
- Improve the process of updating the Status of an Egress resource to report the name of the Node to which the Egress IP is assigned. ([#2444](https://github.com/antrea-io/antrea/pull/2444), [@wenqiq])
- Change the singular name of the ClusterGroup CRD from "group" to "clustergroup". ([#2484](https://github.com/antrea-io/antrea/pull/2484), [@abhiraut])
- Officially-supported Go version is no longer 1.15 but 1.17. ([#2609](https://github.com/antrea-io/antrea/pull/2609) [#2640](https://github.com/antrea-io/antrea/pull/2640), [@antoninbas])
  * There was a notable change in the implementation of the "ParseIP" and "ParseCIDR" functions, but Antrea users should not be affected; refer to this [issue](https://github.com/antrea-io/antrea/issues/2606#issuecomment-901502141)
- Standardize the process of reserving OVS register ranges and defining constant values for them; OVS registers are used to store per-packet information when required to implement specific features. ([#2455](https://github.com/antrea-io/antrea/pull/2455), [@wenyingd])
- Update ELK stack reference configuration to support TCP transport. ([#2387](https://github.com/antrea-io/antrea/pull/2387), [@zyiou])
- Update Windows installation instructions. ([#2456](https://github.com/antrea-io/antrea/pull/2456), [@lzheheng])
- Update Antrea-native policies documentation to reflect the addition of the "kubernetes.io/metadata.name" in upstream K8s. ([#2596](https://github.com/antrea-io/antrea/pull/2596), [@abhiraut])
- Default to containerd as the container runtime in the Vagrant-based test K8s cluster. ([#2583](https://github.com/antrea-io/antrea/pull/2583), [@stanleywbwong])
- Update AllowToCoreDNS example in Antrea-native policies documentation. ([#2605](https://github.com/antrea-io/antrea/pull/2605), [@btrieger])
- Update actions/setup-go to v2 in all Github workflows. ([#2517](https://github.com/antrea-io/antrea/pull/2517), [@MysteryBlokHed])

### Fixed

- Fix panic in Agent when calculating the stats for a rule newly added to an existing NetworkPolicy. ([#2495](https://github.com/antrea-io/antrea/pull/2495), [@tnqn])
- Fix bug in iptables rule installation for dual-stack clusters: if a rule was already present for one protocol but not the other, its installation may have been skipped. ([#2469](https://github.com/antrea-io/antrea/pull/2469), [@lzhecheng])
- Fix deadlock in the Agent's FlowExporter, between the export goroutine and the conntrack polling goroutine. ([#2429](https://github.com/antrea-io/antrea/pull/2429), [@srikartati])
- Upgrade OVS version to 2.14.2-antrea.1 for Windows Nodes; this version of OVS is built on top of the upstream 2.14.2 release and also includes a patch to fix TCP checksum computation when the DNAT action is used. ([#2549](https://github.com/antrea-io/antrea/pull/2549), [@lzhecheng]) [Windows]
- Handle transient iptables-restore failures (caused by xtables lock contention) in the NodePortLocal initialization logic. ([#2555](https://github.com/antrea-io/antrea/pull/2555), [@antoninbas])
- Query and check the list of features supported by the OVS datapath during Agent initialization: if any required feature is not supported, the Agent will log an error and crash, instead of continuing to run which makes it hard to troubleshoot such issues. ([#2571](https://github.com/antrea-io/antrea/pull/2571), [@tnqn])
- On Linux, wait for the ovs-vswitchd PID file to be ready before running ovs-apptcl commands. ([#2695](https://github.com/antrea-io/antrea/pull/2695), [@tnqn])
- Periodically delete stale connections in the Flow Exporter if they cannot be exported (e.g. because the collector is not available), to avoid running out-of-memory. ([#2516](https://github.com/antrea-io/antrea/pull/2516), [@srikartati])
- Fix handling of the "reject" packets generated by the Antrea Agent in the OVS pipeline, to avoid infinite looping when traffic between two endpoints is rejected by network policies in both directions. ([#2579](https://github.com/antrea-io/antrea/pull/2579), [@GraysonWu])
- Fix Linux kernel version parsing to accommodate for more Linux distributions, in particular RHEL / CentOS. ([#2450](https://github.com/antrea-io/antrea/pull/2450), [@Jexf])
- Fix interface naming for IPsec tunnels: based on Node names, the first char could sometimes be a dash, which is not valid. ([#2486](https://github.com/antrea-io/antrea/pull/2486), [@luolanzone])
- When creating an IPsec OVS tunnel port to a remote Node, handle the case where the port already exists but with a stale config graciously: delete the existing port first, then recreate it. ([#2582](https://github.com/antrea-io/antrea/pull/2582), [@luolanzone])
- Fix the policy information reported by the Flow Exporter when a Baseline Antrea-native policy is applied to the flow. ([#2542](https://github.com/antrea-io/antrea/pull/2542), [@zyiou])
- Clean up log files for the Flow Aggregator periodically: prior to this fix, the "--log_file_max_size" and "--log_file_max_num" command-line flags were ignore for the flow-aggregator Pod. ([#2522](https://github.com/antrea-io/antrea/pull/2522), [@srikartati])
- Fix missing template ID when sending the first IPFIX flow record from the FlowAggregator. ([#2546](https://github.com/antrea-io/antrea/pull/2546), [@zyiou])
- Ensure that the Windows Node name obtained from the environment or from hostname is converted to lower-case. ([#2672](https://github.com/antrea-io/antrea/pull/2672), [@shettyg]) [Windows]
- Fix Antrea network clean-up script for Windows; in particular remove Hyper-V binding on network adapter used as OVS uplink so that it can recover its IP address correctly. ([#2550](https://github.com/antrea-io/antrea/pull/2550), [@wenyingd]) [Windows]
- Fix reference Logstash configuration to avoid division by zero in throughput calculation. ([#2432](https://github.com/antrea-io/antrea/pull/2432), [@zyiou])
- Fix nil pointer error when collecting a supportbundle on a Node for which the antrea-agent container image does not include "iproute2"; this does not affect the standard antrea/antrea-ubuntu container image. ([#2598](https://github.com/antrea-io/antrea/pull/2598), [@liu4480])

[@abhiraut]: https://github.com/abhiraut
[@adobley]: https://github.com/adobley
[@antoninbas]: https://github.com/antoninbas
[@btrieger]: https://github.com/btrieger
[@christianang]: https://github.com/christianang
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@gwang550]: https://github.com/gwang550
[@hangyan]: https://github.com/hangyan
[@Jexf]: https://github.com/Jexf
[@liu4480]: https://github.com/liu4480
[@luolanzone]: https://github.com/luolanzone
[@lzhecheng]: https://github.com/lzhecheng
[@lzheheng]: https://github.com/lzheheng
[@madhukark]: https://github.com/madhukark
[@MysteryBlokHed]: https://github.com/MysteryBlokHed
[@PeterEltgroth]: https://github.com/PeterEltgroth
[@qiyueyao]: https://github.com/qiyueyao
[@shettyg]: https://github.com/shettyg
[@srikartati]: https://github.com/srikartati
[@stanleywbwong]: https://github.com/stanleywbwong
[@tnqn]: https://github.com/tnqn
[@weiqiangt]: https://github.com/weiqiangt
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu
[@zyiou]: https://github.com/zyiou
