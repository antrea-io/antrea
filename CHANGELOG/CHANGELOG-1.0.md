# Changelog 1.0

## 1.0.1 - 2021-04-29

### Fixed

- It was discovered that the AntreaProxy implementation has an upper-bound for the number of Endpoints it can support for each Service: we increase this upper-bound from ~500 to 800, log a warning for Services with a number of Endpoints greater than 800, and arbitrarily drop some Endpoints so we can still provide load-balancing for the Service. ([#2101](https://github.com/antrea-io/antrea/pull/2101), [@hongliangl])
- Fix Antrea-native policy with multiple AppliedTo selectors: some rules were never realized by the Agents as they thought they had only received partial information from the Controller. ([#2084](https://github.com/antrea-io/antrea/pull/2084), [@tnqn])
- Fix re-installation of the OpenFlow groups when the OVS daemons are restarted to ensure that AntreaProxy keeps functioning. ([#2134](https://github.com/antrea-io/antrea/pull/2134), [@antoninbas])
- Fix IPFIX flow records exported by the Antrea Agent. ([#2089](https://github.com/antrea-io/antrea/pull/2089), [@zyiou])
  * If a connection spanned multiple export cycles, it wasn't handled properly and no record was sent for the connection
  * If a connection spanned a single export cycle, a single record was sent but "delta counters" were set to 0 which caused flow visualization to omit the flow in dashboards
- Fix incorrect stats reporting for ingress rules of some NetworkPolicies: some types of traffic were bypassing the OVS table keeping track of statistics once the connection was established, causing packet and byte stats to be incorrect. ([#2078](https://github.com/antrea-io/antrea/pull/2078), [@ceclinux])
- Fix the retry logic when enabling the OVS bridge local interface on Windows Nodes. ([#2081](https://github.com/antrea-io/antrea/pull/2081), [@antoninbas]) [Windows]

## 1.0.0 - 2021-04-09

The AntreaPolicy feature is graduated from Alpha to Beta and is therefore enabled by default.

### Added

- Add [Egress] feature to configure SNAT policies for Pod-to-external traffic. [Alpha - Feature Gate: `Egress`]
  * A new Egress CRD is introduced to define SNAT policies ([#1433](https://github.com/antrea-io/antrea/pull/1433), [@jianjuns])
  * Update the datapath to implement Egress: on Windows Nodes, everything is implemented in OVS, while on Linux Nodes, OVS marks packets and sends them to the host network namespace, where iptables handles SNAT ([#1892](https://github.com/antrea-io/antrea/pull/1892) [#1969](https://github.com/antrea-io/antrea/pull/1969) [#1998](https://github.com/antrea-io/antrea/pull/1998), [@jianjuns], [@tnqn])
  * A new EgressGroup control plane API is introduced: the Controller computes group membership for each policy and sends this information to the Agents ([#1965](https://github.com/antrea-io/antrea/pull/1965), [@tnqn])
  * Implement the EgressGroup control plane API in the Agent ([#2026](https://github.com/antrea-io/antrea/pull/2026), [@tnqn] [@ceclinux])
  * Document the Egress feature and its datapath implementation ([#2041](https://github.com/antrea-io/antrea/pull/2041) [#2044](https://github.com/antrea-io/antrea/pull/2044), [@jianjuns] [@tnqn])
- Add support for the "Reject" action in Antrea-native policies as an alternative to "Drop" (which silently drops packets). ([#1888](https://github.com/antrea-io/antrea/pull/1888), [@GraysonWu])
  * For rejected TCP connections, the Agent will send a TCP RST packet
  * For UDP and SCTP, the Agent will send an ICMP message with Type 3 (Destination Unreachable) and Code 10 (Host administratively prohibited)
- Add support for nesting in the [ClusterGroup CRD]: a ClusterGroup can now reference a list of ClusterGroups, but only one level of nesting is supported. ([#1920](https://github.com/antrea-io/antrea/pull/1920), [@Dyanngg])
- Add ability to specify multiple IPBlocks when defining a ClusterGroup. ([#1993](https://github.com/antrea-io/antrea/pull/1993), [@Dyanngg])
- Support for IPv6 (IPv6-only and dual-stack clusters) in the FlowAggregator and in the reference ELK stack. ([#1819](https://github.com/antrea-io/antrea/pull/1819) [#1962](https://github.com/antrea-io/antrea/pull/1962), [@dreamtalen])
- Add support for arm/v7 and arm64 to the main Antrea Docker image for Linux (antrea/antrea-ubuntu) instead of using a separate image. ([#1994](https://github.com/antrea-io/antrea/pull/1994), [@antoninbas])
- Add support for live-traffic tracing in Traceflow: rather than injecting a Traceflow packet, we can monitor real traffic and update the Traceflow Status when a matching packet is observed. ([#2005](https://github.com/antrea-io/antrea/pull/2005) [#2029](https://github.com/antrea-io/antrea/pull/2029), [@jianjuns])
  * The captured packet is reported as part of the Traceflow request Status
  * Live-traffic tracing supports a "Dropped-Only" filter which will only capture packets dropped by the datapath
- Introduce a new optional [mutating webhook](https://github.com/antrea-io/antrea/blob/main/docs/antrea-network-policy.md#select-namespace-by-name) to automatically label all Namespaces and Services with their name (`antrea.io/metadata.name: <resourceName>`); this allows NetworkPolicies and ClusterGroup to easily select these resources by name. ([#1690](https://github.com/antrea-io/antrea/pull/1690), [@abhiraut] [@Dyanngg])
- Add support for rule-level statistics for Antrea-native policies, when the NetworkPolicyStats feature is enabled: rules are identified by their name, which can be user-provided or auto-generated. ([#1780](https://github.com/antrea-io/antrea/pull/1780), [@ceclinux])
- Add TCP connection state information to the IPFIX records sent by the FlowExporter, and improve handling of "dying" connections. ([#1904](https://github.com/antrea-io/antrea/pull/1904), [@zyiou])
- Add information about the flow type (intra-Node, inter-Node, Pod-to-external) to the IPFIX records sent by the FlowExporter. ([#2000](https://github.com/antrea-io/antrea/pull/2000), [@dreamtalen])
- Add support for dumping OVS flows related to a Service with the "antctl get of" command. ([#1877](https://github.com/antrea-io/antrea/pull/1877), [@jianjuns])
- Randomly generate a cluster UUID in the Antrea Controller and make it persistent by storing it to a ConfigMap ("antrea-cluster-identity"). ([#1805](https://github.com/antrea-io/antrea/pull/1805), [@antoninbas])
- Add support for IPv6 to "antctl traceflow". ([#1995](https://github.com/antrea-io/antrea/pull/1995), [@luolanzone])

### Changed

- Rename all Antrea API groups from `*.antrea.tanzu.vmware.com` to `*.antrea.io`. ([#1799](https://github.com/antrea-io/antrea/pull/1799), [@hongliangl])
  * All legacy groups will be supported until December 2021
  * See the [API documentation] for more details and information on how to upgrade client applications which use the Antrea API ([#2031](https://github.com/antrea-io/antrea/pull/2031), [@antoninbas])
- Change the export mechanism for the FlowExporter in the Antrea Agent: instead of exporting all flows periodically with a fixed interval, we introduce an "active timeout" and an "idle timeout", and flow information is exported differently based on flow activity. ([#1714](https://github.com/antrea-io/antrea/pull/1714), [@srikartati])
- Add rate-limiting in the Agent for PacketIn messages sent by the OVS datapath: this can help limit the CPU usage when too many messages are sent by OVS. ([#2015](https://github.com/antrea-io/antrea/pull/2015), [@GraysonWu])
- Output partial result when a Traceflow request initiated by antctl fails or times out, as it can still provide useful information. ([#1879](https://github.com/antrea-io/antrea/pull/1879), [@jianjuns])
- Ensure that "antctl version" always outputs the client version, even when antctl cannot connect to the Antrea apiserver. ([#1876](https://github.com/antrea-io/antrea/pull/1876), [@antoninbas])
- Extract the group member calculation for the NetworkPolicy implementation in the Controller to its own module, so it can be reused for different features which need to calculate groups of endpoints based on a given selection criteria; performance (CPU and memory usage) is also improved. ([#1937](https://github.com/antrea-io/antrea/pull/1937), [@tnqn])
- Optimize the computation of unions of sets when processing NetworkPolicies in the Controller. ([#1938](https://github.com/antrea-io/antrea/pull/1938), [@tnqn])
- Optimize the computation of symmetric differences of sets in the Agent (NodePortLocal) and in the Controller (NetworkPolicy processing). ([#1944](https://github.com/antrea-io/antrea/pull/1944), [@tnqn])
- Move mutable ConfigMap resources out of the deployment YAML and create them programmatically instead; this facilitates integration with other projects such as kapp. ([#1983](https://github.com/antrea-io/antrea/pull/1983), [@hty690])
- Improve error logs when the Antrea Agent's connection to the Controller times out, and introduce a dedicated health check in the Agent to report the connection status. ([#1946](https://github.com/antrea-io/antrea/pull/1946), [@hty690])
- Support user-provided signed OVS binaries in Windows installation script. ([#1963](https://github.com/antrea-io/antrea/pull/1963), [@lzhecheng]) [Windows]
- When NodePortLocal is enabled on a Pod, do not allocate new ports on the host for Pod containers with HostPort enabled. ([#2024](https://github.com/antrea-io/antrea/pull/2024), [@annakhm])
- Use "distroless" Docker image for the FlowAggregator to reduce its size. ([#2004](https://github.com/antrea-io/antrea/pull/2004) [#2016](https://github.com/antrea-io/antrea/pull/2016), [@hanlins] [@dreamtalen])
- Improve reference Kibana dashboards for flow visualization and update the documentation for flow visualization with more up-to-date Kibana screenshots. ([#1933](https://github.com/antrea-io/antrea/pull/1933), [@zyiou])
- Reject unsupported positional arguments in antctl commands. ([#2011](https://github.com/antrea-io/antrea/pull/2011), [@hty690])
- Reduce log verbosity for PacketIn messages received by the Agent. ([#2046](https://github.com/antrea-io/antrea/pull/2046), [@jianjuns])
- Improve Windows documentation to cover running Antrea as a Windows service, which is required when using containerd as the container runtime. ([#1874](https://github.com/antrea-io/antrea/pull/1874), [@lzhecheng] [@jayunit100]) [Windows]
- Update the documentation for hardware offload support. ([#1943](https://github.com/antrea-io/antrea/pull/1943), [@Mmduh-483])
- Document IPv6 support for Traceflow. ([#1996](https://github.com/antrea-io/antrea/pull/1996), [@gran-vmv])
- Remove old references to Ubuntu 18.04 from the documentation. ([#1960](https://github.com/antrea-io/antrea/pull/1960), [@shadowlan])

### Fixed

- Fix audit logging on Windows Nodes: the log directory was not configured properly, causing Agent initialization to fail on Windows when the AntreaPolicy feature was enabled. ([#2052](https://github.com/antrea-io/antrea/pull/2052), [@antoninbas]) [Windows]
- When selecting the Pods corresponding to a Service for which NodePortLocal has been enabled, Pods should be filtered by Namespace. ([#1927](https://github.com/antrea-io/antrea/pull/1927), [@chauhanshubham])
- Correctly handle Service Type changes for NodePortLocal, and update Pod annotations accordingly. ([#1936](https://github.com/antrea-io/antrea/pull/1936), [@chauhanshubham])
- Use correct output format for CNI Add in networkPolicyOnly mode: this was not an issue with Docker but was causing failures with containerd. ([#2037](https://github.com/antrea-io/antrea/pull/2037), [@antoninbas] [@dantingl])
- Fix audit logging of IPv6 traffic for Antrea-native policies: IPv6 packets were ignored by the Agent instead of being parsed and logged to file. ([#1990](https://github.com/antrea-io/antrea/pull/1990), [@antoninbas])
- Fix the Traceflow implementation when the destination IP is an external IP or the local gateway's IP. ([#1884](https://github.com/antrea-io/antrea/pull/1884), [@antoninbas])
- Fix a crash in the Agent when the FlowExporter initialization fails; instead of a crash it should try again the next time flow data needs to be exported. ([#1959](https://github.com/antrea-io/antrea/pull/1959), [@srikartati])
- Add missing flows in OVS for IPv6 Traceflow support preventing Traceflow packets from bypassing conntrack. ([#2054](https://github.com/antrea-io/antrea/pull/2054), [@jianjuns])
- Fix Status updates for ClusterNetworkPolicies. ([#2036](https://github.com/antrea-io/antrea/pull/2036), [@Dyanngg])
- Clean up stale IP addresses on Antrea host gateway interface. ([#1900](https://github.com/antrea-io/antrea/pull/1900), [@antoninbas])
  * If a Node leaves and later rejoins a cluster, a new Pod CIDR may be allocated to the Node for each supported IP family and the gateway receives a new IP address (first address in the CIDR)
  * If the previous addresses are not removed from the gateway, we observe connectivity issues across Nodes
- Update libOpenflow to avoid crash in Antrea Agent for certain Traceflow requests. ([#1833](https://github.com/antrea-io/antrea/pull/1883), [@antoninbas])
- Fix the deletion of stale port forwarding iptables rules installed for NodePortLocal, occurring when the Antrea Agent restarts. ([#1887](https://github.com/antrea-io/antrea/pull/1887), [@monotosh-avi])
- Fix output formatting for the "antctl trace-packet" command: the result was displayed as a Go struct variable and newline characters were not rendered, making it hard to read. ([#1897](https://github.com/antrea-io/antrea/pull/1897), [@jianjuns])

[ClusterGroup CRD]: https://github.com/antrea-io/antrea/blob/main/docs/antrea-network-policy.md#clustergroup
[Egress]: https://github.com/antrea-io/antrea/blob/main/docs/feature-gates.md#egress
[API documentation]: https://github.com/antrea-io/antrea/blob/main/docs/api.md

[@abhiraut]: https://github.com/abhiraut
[@annakhm]: https://github.com/annakhm
[@antoninbas]: https://github.com/antoninbas
[@ceclinux]: https://github.com/ceclinux
[@chauhanshubham]: https://github.com/chauhanshubham
[@dantingl]: https://github.com/dantingl
[@dreamtalen]: https://github.com/dreamtalen
[@Dyanngg]: https://github.com/Dyanngg
[@gran-vmv]: https://github.com/gran-vmv
[@GraysonWu]: https://github.com/GraysonWu
[@hanlins]: https://github.com/hanlins
[@hongliangl]: https://github.com/hongliangl
[@hty690]: https://github.com/hty690
[@jayunit100]: https://github.com/jayunit100
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@lzhecheng]: https://github.com/lzhecheng
[@Mmduh-483]: https://github.com/Mmduh-483
[@monotosh-avi]: https://github.com/monotosh-avi
[@shadowlan]: https://github.com/shadowlan
[@srikartati]: https://github.com/srikartati
[@tnqn]: https://github.com/tnqn
[@zyiou]: https://github.com/zyiou
