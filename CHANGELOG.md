# Changelog

All notable changes to this project will be documented in this file.  The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

Features in Alpha or Beta stage are tagged as such. We try to follow the same conventions as
Kubernetes for [feature development
stages](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api_changes.md#alpha-beta-and-stable-versions).

Some experimental features can be enabled / disabled using [Feature Gates](docs/feature-gates.md).

## Unreleased

## 0.13.5 - 2021-07-27

### Fixed

- Upgrade OVS version to 2.14.2 to pick up security fixes for CVE-2015-8011, CVE-2020-27827 and CVE-2020-35498. ([#2451](https://github.com/antrea-io/antrea/pull/2451), [@antoninbas])

## 0.13.4 - 2021-07-16

### Fixed

- Use "os/exec" package instead of third-party modules to run PowerShell commands and configure host networking on Windows; this change prevents Agent goroutines from getting stuck when configuring routes. ([#2363](https://github.com/antrea-io/antrea/pull/2363), [@lzhecheng]) [Windows]

## 0.13.3 - 2021-06-29

### Fixed

- Fix inter-Node ClusterIP Service access when AntreaProxy is disabled. ([#2318](https://github.com/antrea-io/antrea/pull/2318), [@tnqn])
- Fix duplicate group ID allocation in AntreaProxy when using a combination of IPv4 and IPv6 Services in dual-stack clusters; this was causing Service connectivity issues. ([#2317](https://github.com/antrea-io/antrea/pull/2317), [@hongliangl])
- Fix invalid clean-up of the HNS Endpoint during Pod deletion, when Docker is used as the container runtime. ([#2306](https://github.com/antrea-io/antrea/pull/2306), [@wenyingd]) [Windows]
- Fix race condition on Windows when retrieving the local HNS Network created by Antrea for containers. ([#2253](https://github.com/antrea-io/antrea/pull/2253), [@tnqn]) [Windows]
- Fix invalid conversion function between internal and versioned types for controlplane API, which was causing JSON marshalling errors. ([#2312](https://github.com/antrea-io/antrea/pull/2312), [@tnqn])

## 0.13.2 - 2021-04-30

### Fixed

- It was discovered that the AntreaProxy implementation has an upper-bound for the number of Endpoints it can support for each Service: we increase this upper-bound from ~500 to 800, log a warning for Services with a number of Endpoints greater than 800, and arbitrarily drop some Endpoints so we can still provide load-balancing for the Service. ([#2101](https://github.com/vmware-tanzu/antrea/pull/2101), [@hongliangl])
- Fix Antrea-native policy with multiple AppliedTo selectors: some rules were never realized by the Agents as they thought they had only received partial information from the Controller. ([#2084](https://github.com/vmware-tanzu/antrea/pull/2084), [@tnqn])
- Fix re-installation of the OpenFlow groups when the OVS daemons are restarted to ensure that AntreaProxy keeps functioning. ([#2134](https://github.com/vmware-tanzu/antrea/pull/2134), [@antoninbas])
- Fix the retry logic when enabling the OVS bridge local interface on Windows Nodes. ([#2081](https://github.com/vmware-tanzu/antrea/pull/2081), [@antoninbas]) [Windows]
- Fix audit logging on Windows Nodes: the log directory was not configured properly, causing Agent initialization to fail on Windows when the AntreaPolicy feature was enabled. ([#2052](https://github.com/vmware-tanzu/antrea/pull/2052), [@antoninbas]) [Windows]
- When selecting the Pods corresponding to a Service for which NodePortLocal has been enabled, Pods should be filtered by Namespace. ([#1927](https://github.com/vmware-tanzu/antrea/pull/1927), [@chauhanshubham])
- Correctly handle Service Type changes for NodePortLocal, and update Pod annotations accordingly. ([#1936](https://github.com/vmware-tanzu/antrea/pull/1936), [@chauhanshubham])
- Use correct output format for CNI Add in networkPolicyOnly mode: this was not an issue with Docker but was causing failures with containerd. ([#2037](https://github.com/vmware-tanzu/antrea/pull/2037), [@antoninbas] [@dantingl])
- Fix audit logging of IPv6 traffic for Antrea-native policies: IPv6 packets were ignored by the Agent instead of being parsed and logged to file. ([#1990](https://github.com/vmware-tanzu/antrea/pull/1990), [@antoninbas])
- Fix Status updates for ClusterNetworkPolicies. ([#2036](https://github.com/vmware-tanzu/antrea/pull/2036), [@Dyanngg])

## 0.13.1 - 2021-03-12

### Fixed

- Clean up stale IP addresses on Antrea host gateway interface. ([#1900](https://github.com/vmware-tanzu/antrea/pull/1900), [@antoninbas])
  * If a Node leaves and later rejoins a cluster, a new Pod CIDR may be allocated to the Node for each supported IP family and the gateway receives a new IP address (first address in the CIDR)
  * If the previous addresses are not removed from the gateway, we observe connectivity issues across Nodes
- Update libOpenflow to avoid crash in Antrea Agent for certain Traceflow requests. ([#1833](https://github.com/vmware-tanzu/antrea/pull/1883), [@antoninbas])
- Fix the deletion of stale port forwarding iptables rules installed for NodePortLocal, occurring when the Antrea Agent restarts. ([#1887](https://github.com/vmware-tanzu/antrea/pull/1887), [@monotosh-avi])
- Fix output formatting for the "antctl trace-packet" command: the result was displayed as a Go struct variable and newline characters were not rendered, making it hard to read. ([#1897](https://github.com/vmware-tanzu/antrea/pull/1897), [@jianjuns])

## 0.13.0 - 2021-02-11

Includes all the changes from [0.12.1].

### Added

- Add [NodePortLocal] feature to improve integration with external load-balancers. ([#1459](https://github.com/vmware-tanzu/antrea/pull/1459) [#1743](https://github.com/vmware-tanzu/antrea/pull/1743) [#1758](https://github.com/vmware-tanzu/antrea/pull/1758), [@monotosh-avi] [@chauhanshubham] [@hemantavi]) [Alpha - Feature Gate: `NodePortLocal`]
  * Services can be annotated with "nodeportlocal.antrea.io/enabled" to indicate that NodePortLocal should be enabled for this Service's Pod Endpoints
  * For each container port exposed by such a Pod, the Antrea Agent will allocate a local Node port value and traffic sent to this Node port will be forwarded to the container port using DNAT
  * The mapping from allocated Node ports to container ports is stored in a new Pod annotation, "nodeportlocal.antrea.io", e.g. to be consumed by external load-balancers
- Introduce the [ClusterGroup CRD] to logically group different network endpoints and reference them together in Antrea-native policies. ([#1782](https://github.com/vmware-tanzu/antrea/issues/1782), [@abhiraut] [@Dyanngg])
  * The extra level of indirection enables separation between workload selection and policy definition
  * ClusterGroups can be referenced in Antrea ClusterNetworkPolicies, either in the AppliedTo or as peers in policy rules ([#1750](https://github.com/vmware-tanzu/antrea/pull/1750) [#1734](https://github.com/vmware-tanzu/antrea/pull/1734))
  * In addition to the Pod / Namespace selectors and ipBlocks, ClusterGroups can reference a Service by name directly, and all Pod Endpoints for this Service will be included in the ClusterGroup ([#1797](https://github.com/vmware-tanzu/antrea/pull/1797))
  * ClusterGroups can also select ExternalEntitites, which are used to represent labelled non-Pod endpoints ([#1828](https://github.com/vmware-tanzu/antrea/pull/1828))
  * The ClusterGroup CRD includes a Status subresource used to indicate whether the Antrea Controller has already computed the membership list for the group ([#1778](https://github.com/vmware-tanzu/antrea/pull/1778))
  * New APIs are defined in "controlplane.antrea.tanzu.vmware.com/v1beta2": "/clustergroupmembers" retrieves the list of members of a group and "/groupassociations" retrieves the list of groups that a given endpoint (Pod or ExternalEntity) belongs to ([#1688](https://github.com/vmware-tanzu/antrea/pull/1688))
- Add support for containerd runtime on Windows Nodes. ([#1781](https://github.com/vmware-tanzu/antrea/pull/1781) [#1832](https://github.com/vmware-tanzu/antrea/pull/1832), [@ruicao93]) [Windows]
- Add [EndpointSlice] support to AntreaProxy. ([#1703](https://github.com/vmware-tanzu/antrea/pull/1703), [@hongliangl]) [Alpha - Feature Gate: `EndpointSlice`]
  * EndpointSlice needs to be [enabled](https://kubernetes.io/docs/tasks/administer-cluster/enabling-endpointslices/) in the K8s cluster
  * Only the "discovery.k8s.io/v1beta1" EndpointSlice API is supported
- Add support for arm/v7 and arm64 by providing Antrea Docker images for these architectures. ([#1771](https://github.com/vmware-tanzu/antrea/pull/1771), [@antoninbas])
  * Refer to the [documentation](https://github.com/vmware-tanzu/antrea/blob/v0.13.0/docs/arm-support.md) for instructions on how to use the image
- Support IPv6 packets in Traceflow. ([#1579](https://github.com/vmware-tanzu/antrea/pull/1579), [@gran-vmv])
- Add the following Prometheus metrics to the the AntreaProxy implementation: "antrea_proxy_sync_proxy_rules_duration_seconds", "antrea_proxy_total_endpoints_installed", "antrea_proxy_total_endpoints_updates", "antrea_proxy_total_services_installed", "antrea_proxy_total_services_updates". ([#1704](https://github.com/vmware-tanzu/antrea/pull/1704), [@weiqiangt])
- Add the following Prometheus metrics to count Status updates for Antrea-native policies: "antrea_controller_acnp_status_updates", "antrea_controller_anp_status_updates". ([#1801](https://github.com/vmware-tanzu/antrea/pull/1801), [@antoninbas])
- Add support for TLS between the Antrea Agent FlowExporter and the FlowAggregator, using self-signed certificates. ([#1649](https://github.com/vmware-tanzu/antrea/pull/1649), [@zyiou])
- New Antrea Agent configuration option, "kubeAPIServerOverride", which can be used to explicitly provide an address for the K8s apiserver when the Agent is running as Pod; by default, the Agent uses the ClusterIP for the kubernetes Service. ([#1735](https://github.com/vmware-tanzu/antrea/pull/1735), [@anfernee])
- Provide ability to configure TLS cipher suites supported by the Antrea apiservers (Agent and Controller). ([#1784](https://github.com/vmware-tanzu/antrea/pull/1784), [@lzhecheng])
- Add liveness probe to Antrea Controller to ensure it is automatically restarted after a while by kubelet if it stops being responsive. ([#1839](https://github.com/vmware-tanzu/antrea/pull/1839), [@antoninbas])
- Document workaround to install OVS and Antrea on Windows Nodes for which the CPU does not have the required virtualization capabilities, as may be the case for cloud VMs. ([#1744](https://github.com/vmware-tanzu/antrea/pull/1744), [@ruicao93]) [Windows]
- Improve documentation for "noEncap" and "hybrid" traffic modes, and add information about how to use [Kube-router] to advertise Pod CIDRs to the fabric with BGP. ([#1798](https://github.com/vmware-tanzu/antrea/pull/1798), [@jianjuns])
- Add new NetworkPolicy testsuite based on auto-generated test cases. ([#1765](https://github.com/vmware-tanzu/antrea/pull/1765), [@mattfenwick])

### Changed

- Change permissions for the "/var/run/antrea" directory created by the Antrea Agent on each Node to prevent non-root users from accessing it; among other things, it includes the socket file used to send CNI commands to the Agent. ([#1770](https://github.com/vmware-tanzu/antrea/pull/1770), [@jianjuns])
- Add multi-table support to the "antctl get ovsflows" command, to dump flows from multiple tables at once. ([#1708](https://github.com/vmware-tanzu/antrea/pull/1708), [@weiqiangt])
- Change the sanity check performed by the Antrea Agent to validate that the Hyper-V dependency is satisfied. ([#1741](https://github.com/vmware-tanzu/antrea/pull/1741), [@ruicao93])
- Periodically verify that the static iptables rules required by Antrea are present and install missing rules if any. ([#1751](https://github.com/vmware-tanzu/antrea/pull/1751), [@siddhant94])
- Update Mellanox/sriovnet dependency to version v1.0.2 to support OVS hardware offload to Mellanox devices with Kernel versions 5.8 and above. ([#1845](https://github.com/vmware-tanzu/antrea/pull/1845), [@Mmduh-483])
- Remove dependency on [juju](https://github.com/juju) libraries, which are distributed under an LGPL v3 license. ([#1796](https://github.com/vmware-tanzu/antrea/pull/1796), [@antoninbas])

### Fixed

- Ensure that NodePort traffic does not bypass NetworkPolicies. ([#1816](https://github.com/vmware-tanzu/antrea/pull/1816), [@tnqn])
  * NodePort traffic for which ExternalTrafficPolicy is set to Cluster goes through SNAT before NetworkPolicies are enforced; after SNAT the source IP is the IP of the local gateway interface (antrea-gw0)
  * Users will need to define the appropriate NetworkPolicies to allow ingress access to isolated Pods for NodePort traffic
  * This new behavior only applies to Linux Nodes using the OVS system datapath (default)
- When clearing the flow-restore-wait config for the OVS bridge after re-installing flows, ensure that the operation happened successfully and retry if anything unexpected happen; if flow-restore-wait is not cleared, the bridge will not forward packets correctly. ([#1730](https://github.com/vmware-tanzu/antrea/pull/1730), [@tnqn])
- Stop mounting the host's kmod binary to the Antrea initContainer as it may depend on shared libraries not available in the container. ([#1777](https://github.com/vmware-tanzu/antrea/pull/1777), [@antoninbas])
- Fix crashes in the FlowAggregator, along with numerous spurious warnings, by updating the version of the [go-ipfix] library. ([#1817](https://github.com/vmware-tanzu/antrea/pull/1817), [@zyiou] [@srikartati])
- Fix issues with reference logstash configuration and improve reference Kibana dashboards for flow visualization with the FlowExporter feature. ([#1727](https://github.com/vmware-tanzu/antrea/pull/1727), [@zyiou])

## 0.11.2 - 2021-02-11

### Fixed

- Send necessary updates to Antrea Agents when a Pod's IP address is updated, as otherwise NetworkPolicies are not enforced correctly. ([#1808](https://github.com/vmware-tanzu/antrea/pull/1808), [@Dyanngg] [@tnqn])
- On Antrea Agent restart, ensure that OpenFlow priorities are assigned correctly for NetworkPolicy rules, and that rules with the same tier and priority are assigned the same OpenFlow priority. ([#1841](https://github.com/vmware-tanzu/antrea/pull/1841), [@Dyanngg])
- Do not release the OpenFlow priority assigned to a NetworkPolicy rule in case of a transient error when installing the corresponding flows, if other rules are using the same OpenFlow priority. ([#1844](https://github.com/vmware-tanzu/antrea/pull/1844), [@Dyanngg])
- Do not delete Endpoint flows when an Endpoint is no longer used for a specific Service (or if a Service is deleted) if these flows are still required by another Service. ([#1815](https://github.com/vmware-tanzu/antrea/pull/1815), [@weiqiangt])
- Fix bugs in IPv6 AntreaProxy implementation, notably for flow "hairpinning" and ServiceAffinity support. ([#1713](https://github.com/vmware-tanzu/antrea/pull/1713), [@lzhecheng])
- Support non-standardized CIDRs (CIDRs for which some address bits may not have been masked off as per the prefix length) in NetworkPolicies. ([#1767](https://github.com/vmware-tanzu/antrea/pull/1767), [@tnqn])
- Fix minimum required Linux Kernel version (4.6) in documentation. ([#1757](https://github.com/vmware-tanzu/antrea/pull/1757), [@hongliangl])
- Fix Agent crash when creating an Antrea-native policy with a "drop" action, while the NetworkPolicyStats feature is enabled. ([#1606](https://github.com/vmware-tanzu/antrea/pull/1606), [@ceclinux])
- Fix Traceflow when Antrea-native policies are created with a "drop" action. ([#1602](https://github.com/vmware-tanzu/antrea/pull/1602), [@gran-vmv] [@lzhecheng])
- Fix Agent crash when enabling NetworkPolicyStats and Traceflow feature together and creating an Antrea-native policy with a "drop" action. ([#1615](https://github.com/vmware-tanzu/antrea/pull/1615), [@tnqn])
- When the destination is a Service in a Traceflow request, do not overwrite the default TCP SYN flag (needed for the packet to be processed by AntreaProxy correctly) unless the user explicitly provided a non-zero value. ([#1602](https://github.com/vmware-tanzu/antrea/pull/1602), [@gran-vmv] [@lzhecheng])
- Improve handling of transient OVS errors when installing flows for policy rules in the Agent, by ensuring that retries are executed correctly. ([#1667](https://github.com/vmware-tanzu/antrea/pull/1667), [@tnqn])

## 0.12.1 - 2021-02-10

### Changed

- More uniform mechanism in the OVS pipeline to determine whether a MAC address rewrite is needed. ([#1597](https://github.com/vmware-tanzu/antrea/pull/1597) [#1754](https://github.com/vmware-tanzu/antrea/pull/1754), [@wenyingd] [@jianjuns])

### Fixed

- Send necessary updates to Antrea Agents when a Pod's IP address is updated, as otherwise NetworkPolicies are not enforced correctly. ([#1808](https://github.com/vmware-tanzu/antrea/pull/1808), [@Dyanngg] [@tnqn])
- On Antrea Agent restart, ensure that OpenFlow priorities are assigned correctly for NetworkPolicy rules, and that rules with the same tier and priority are assigned the same OpenFlow priority. ([#1841](https://github.com/vmware-tanzu/antrea/pull/1841), [@Dyanngg])
- Do not release the OpenFlow priority assigned to a NetworkPolicy rule in case of a transient error when installing the corresponding flows, if other rules are using the same OpenFlow priority. ([#1844](https://github.com/vmware-tanzu/antrea/pull/1844), [@Dyanngg])
- Do not delete Endpoint flows when an Endpoint is no longer used for a specific Service (or if a Service is deleted) if these flows are still required by another Service. ([#1815](https://github.com/vmware-tanzu/antrea/pull/1815), [@weiqiangt])
- Fix AntreaProxy implementation on Windows for ClusterIP Services with endpoints outside of the cluster's Pod CIDR, by ensuring that SNAT is performed correctly. ([#1824](https://github.com/vmware-tanzu/antrea/pull/1824), [@ruicao93]) [Windows]
- More robust error handling for network adapter operations on Windows; in particular add a retry mechanism if enabling the network adapter fails. ([#1736](https://github.com/vmware-tanzu/antrea/pull/1736), [@ruicao93]) [Windows]
- When the Antrea Agent process is run using the provided PowerShell script, ensure that the Kubeconfigs used by the Agent to connect to the K8s and Antrea Controller apiservers are updated on every restart. ([#1847](https://github.com/vmware-tanzu/antrea/pull/1847), [@ruicao93]) [Windows]
- Fix bugs in IPv6 AntreaProxy implementation, notably for flow "hairpinning" and ServiceAffinity support. ([#1713](https://github.com/vmware-tanzu/antrea/pull/1713), [@lzhecheng])
- Support non-standardized CIDRs (CIDRs for which some address bits may not have been masked off as per the prefix length) in NetworkPolicies. ([#1767](https://github.com/vmware-tanzu/antrea/pull/1767), [@tnqn])
- Fix minimum required Linux Kernel version (4.6) in documentation. ([#1757](https://github.com/vmware-tanzu/antrea/pull/1757), [@hongliangl])

## 0.12.0 - 2020-12-22

Includes all the changes from [0.11.1].

### Added

- Add support for rule-level AppliedTo for Antrea-native policies. ([#1396](https://github.com/vmware-tanzu/antrea/pull/1396), [@Dyanngg])
  * Ability to select different endpoints on which to apply the different rules within the same policy, without having to define multiple policies
  * For a given policy, either the policy-level AppliedTo field must be used, or the rule-level AppliedTo fields
- Add support for port ranges in the rules of Antrea-native policies. ([#1557](https://github.com/vmware-tanzu/antrea/pull/1557), [@GraysonWu])
- Introduce the FlowAggregator, an [IPFIX mediator] implementation to collect, process and export flow records generated by the Antrea Agents. ([#1671](https://github.com/vmware-tanzu/antrea/pull/1671) [#1677](https://github.com/vmware-tanzu/antrea/pull/1677), [@srikartati] [@dreamtalen] [@zyiou])
  * Built using the [go-ipfix] library
  * Flow records exported by the FlowAggregator are not missing any K8s contextual information (e.g. source / destination Pod names)
  * It is recommended to always deploy the FlowAggregator when using the FlowExporter feature, as opposed to sending records directly from the Agent to a third-party collector
  * Refer to the [Flow Exporter] documentation for more information
- Add ability to sort by "effective priority" when listing internal NetworkPolicy resources (computed by the Controller) with antctl: priorities are sorted in the effective order in which they are enforced. ([#1530](https://github.com/vmware-tanzu/antrea/pull/1530), [@Dyanngg])
- Add support for IPv6 to the FlowExporter implementation in the Agent. ([#1677](https://github.com/vmware-tanzu/antrea/pull/1677), [@lzhecheng] [@antoninbas] [@srikartati])
  * Support for IPv6 IPFIX Information Elements in exported flow records
  * Agent can export flows to an IPFIX collector over IPv6
  * However, FlowAggregator is still missing support for IPv6
- Add support for generating an Antrea manifest which is compatible with K8s 1.15 clusters (by default, Antrea requires K8s >= 1.16). ([#1664](https://github.com/vmware-tanzu/antrea/pull/1664), [@guesslin])
  * This can be done by running the hack/generate-manifest.sh script with the "--k8s-1.15" flag

### Changed

- Update the priority of the default Tiers, to space them out more evenly and to provide more room for user-defined Tiers with higher priority than Emergency. ([#1665](https://github.com/vmware-tanzu/antrea/pull/1665), [@abhiraut])
  * This change will impact users who use custom Tiers - in addition to the default Tiers -, as the relative priorities between tiers may change and impact the order in which Antrea-native policies are enforced
  * Impacted users will need to recreate their custom tiers with updated priority values after upgrading Antrea to restore the enforcement order of their policies
- Switch to VMware Harbor registry (projects.registry.vmware.com) for all user-facing Docker images, in response to new Docker Hub rate limits. ([#1617](https://github.com/vmware-tanzu/antrea/pull/1617), [@antoninbas] [@lzhecheng]).
  * When applying one of the official Antrea manifests, the Antrea Docker images will be pulled from projects.registry.vmware.com
- Default to ~/.kube/config as the default location of the Kubeconfig file in the Antrea Octant plugin: this gives a better user experience when running Octant and the plugin as a process (as opposed to running them as a Pod). ([#1662](https://github.com/vmware-tanzu/antrea/pull/1662), [@mengdie-song])
- Set OVS max revalidator delay to 200 ms (instead of 500ms): this reduces the delay before a learned flow is installed in the OVS datapath and improves the quality of the SessionAffinity implementation in AntreaProxy. ([#1584](https://github.com/vmware-tanzu/antrea/pull/1584), [@antoninbas])
- Add more load-balancing information for Service traffic (destination Pod name and IP) in the generated Traceflow graph in Octant when applicable. ([#1607](https://github.com/vmware-tanzu/antrea/pull/1607), [@ZhangYW18])
- Clean up OVS flows in charge of SNAT in Windows Agent implementation. ([#1453](https://github.com/vmware-tanzu/antrea/pull/1453), [@jianjuns]) [Windows]
- Make the OVS flows in charge of L2/L3 forwarding more uniform across different traffic cases. ([#1594](https://github.com/vmware-tanzu/antrea/pull/1594), [@jianjuns])
- Auto-generate listers and informers for AntreaAgentInfo and AntreaControllerInfo CRDs to facilitate consumption by other projects. ([#1612](https://github.com/vmware-tanzu/antrea/pull/1612), [@liu4480])

### Fixed

- Fix Agent crash when creating an Antrea-native policy with a "drop" action, while the NetworkPolicyStats feature is enabled. ([#1606](https://github.com/vmware-tanzu/antrea/pull/1606), [@ceclinux])
- Fix Traceflow when Antrea-native policies are created with a "drop" action. ([#1602](https://github.com/vmware-tanzu/antrea/pull/1602), [@gran-vmv] [@lzhecheng])
- Fix Agent crash when enabling NetworkPolicyStats and Traceflow feature together and creating an Antrea-native policy with a "drop" action. ([#1615](https://github.com/vmware-tanzu/antrea/pull/1615), [@tnqn])
- Do not try to remove existing IP addresses from the Antrea OVS bridge on Windows before assigning the correct one, as there may not be any which would cause an error. ([#1660](https://github.com/vmware-tanzu/antrea/pull/1660), [@ruicao93]) [Windows]
- When the destination is a Service in a Traceflow request, do not overwrite the default TCP SYN flag (needed for the packet to be processed by AntreaProxy correctly) unless the user explicitly provided a non-zero value. ([#1602](https://github.com/vmware-tanzu/antrea/pull/1602), [@gran-vmv] [@lzhecheng])
- Do not decrement the IP TTL field during L3 forwarding if the packet entered the OVS pipeline from the local gateway. ([#1436](https://github.com/vmware-tanzu/antrea/pull/1436), [@wenyingd] [@dumlutimuralp])
- Improve handling of transient OVS errors when installing flows for policy rules in the Agent, by ensuring that retries are executed correctly. ([#1667](https://github.com/vmware-tanzu/antrea/pull/1667), [@tnqn])

## 0.11.1 - 2020-11-20

### Fixed

- Fix SessionAffinity implementation in AntreaProxy: the timeout value was not honored correctly and flows were not updated correctly when the SessionAffinity type changed. ([#1576](https://github.com/vmware-tanzu/antrea/pull/1576), [@antoninbas])
- Ensure that AntreaProxy deletes stale flows when a Service's port number changes. ([#1576](https://github.com/vmware-tanzu/antrea/pull/1576), [@antoninbas])
- Fix networkPolicyOnly traffic mode and support for AKS and EKS by ensuring that the proper criteria are used when determining whether to install IPv4 flows and / or IPv6 flows. ([#1585](https://github.com/vmware-tanzu/antrea/pull/1585) [#1575](https://github.com/vmware-tanzu/antrea/pull/1575), [@antoninbas] [@Dyanngg])
- Ensure backwards-compatibility of "controlplane.antrea.tanzu.vmware.com" for older Agents using the v1beta1 API version to communicate with a new Controller which defaults to v1beta2. ([#1586](https://github.com/vmware-tanzu/antrea/pull/1586), [@tnqn])
  * During upgrade from 0.10.x to 0.11.0, NetworkPolicy enforcement was broken for older Agents (0.10.x) because of an API change
  * Upgrading from 0.10.x to 0.11.1 or from 0.11.0 to 0.11.1 is supported without disruption
- Mutate empty "tier" field in Antrea-native policies to the default "Application" tier to ensure that the correct tier is reported when dumping policies (e.g. with kubectl). ([#1567](https://github.com/vmware-tanzu/antrea/pull/1567), [@abhiraut])

## 0.11.0 - 2020-11-13

Includes all the changes from [0.10.1] and [0.10.2].

The AntreaProxy feature is graduated from Alpha to Beta and is therefore enabled by default.

The Traceflow feature is graduated from Alpha to Beta and is therefore enabled by default.

Support for Prometheus metrics is graduated from Alpha to Beta and Antrea metrics are therefore exposed by default.

### Added

- Support for IPv6 and dual-stack clusters. ([#1518](https://github.com/vmware-tanzu/antrea/pull/1518) [#1102](https://github.com/vmware-tanzu/antrea/pull/1102), [@wenyingd] [@lzhecheng] [@mengdie-song] [@ksamoray]) [Alpha]
  * Note that the FlowExporter feature does not support IPv6 and should not be enabled in clusters where IPv6 addresses are used
- Add "status" field to the Antrea-native policy CRDs to report the realization status of policies (how many Nodes are currently enforcing the policy). ([#1442](https://github.com/vmware-tanzu/antrea/pull/1442), [@tnqn])
  * Each Agent reports its status using an internal API in "controlplane.antrea.tanzu.vmware.com" and everything is aggregated by the Controller which updates the "status" field
- Support for audit logging for Antrea-native policy rules: logging can now be enabled for individual rules with the "enableLogging" field and logs will be written in human-readable format to "/var/log/antrea/networkpolicy/np.log" on the Node's filesystem. ([#1216](https://github.com/vmware-tanzu/antrea/pull/1216), [@qiyueyao])
- Add "name" field for individual rules in Antrea-native policy CRDs and auto-generate rule names when they are not provided by the user. ([#1330](https://github.com/vmware-tanzu/antrea/pull/1330) [#1451](https://github.com/vmware-tanzu/antrea/pull/1451), [@GraysonWu])
- Add "baseline" tier for Antrea-native policies: policies in that tier are enforced after (i.e. with a lower precedence) than K8s network policies. ([#1450](https://github.com/vmware-tanzu/antrea/pull/1450), [@Dyanngg])
- Add support for Antrea-native policies to the "antctl get netpol" command. ([#1301](https://github.com/vmware-tanzu/antrea/pull/1301), [@GraysonWu])
- Add config option to disable SNAT for Pod-to-External traffic in noEncap mode, in case the Pod CIDR is routable in the Node network. ([#1394](https://github.com/vmware-tanzu/antrea/pull/1394), [@jianjuns])
- Add NetworkPolicy information (Namespace and Name of the NetworkPolicy allowing the connection) to the IPFIX flow records exported by the Agent when FlowExporter is enabled. ([#1268](https://github.com/vmware-tanzu/antrea/pull/1268), [@srikartati])
- Support for the FlowExporter feature for Windows Nodes. ([#1321](https://github.com/vmware-tanzu/antrea/pull/1321), [@dreamtalen]) [Windows]
- Add support for Pod [Traffic Shaping] by leveraging the upstream [bandwidth plugin], maintained by the CNI project. ([#1414](https://github.com/vmware-tanzu/antrea/pull/1414), [@tnqn])
- Add "antctl log-level" command to change log verbosity of a specific Antrea Agent or of the Controller at runtime; it invokes the "/loglevel" API. ([#1340](https://github.com/vmware-tanzu/antrea/pull/1340), [@jianjuns])
- Introduce the "antctl proxy" command, which gives antctl the ability to operate as a reverse proxy for the Antrea API, in order to simplify troubleshooting and profiling Antrea. ([#1452](https://github.com/vmware-tanzu/antrea/pull/1452), [@antoninbas])
- Support for providing a list of Node names when generating a support bundle with antctl. ([#1267](https://github.com/vmware-tanzu/antrea/pull/1267), [@weiqiangt])
- Additional documentation:
  * Add list of supported Prometheus metrics ([#726](https://github.com/vmware-tanzu/antrea/pull/726), [@ksamoray])
  * Document Antrea API groups and versioning policy. ([#1352](https://github.com/vmware-tanzu/antrea/pull/1352) [#1469](https://github.com/vmware-tanzu/antrea/pull/1469), [@antoninbas])
  * Start security recommendations document ([#1296](https://github.com/vmware-tanzu/antrea/pull/1296), [@antoninbas])
  * Document available kubectl commands for Antrea-native policies ([#1323](https://github.com/vmware-tanzu/antrea/pull/1323), [@abhiraut])

### Changed

- Upgrade the "controlplane.antrea.tanzu.vmware.com" API to v1beta2; the Antrea Controller still serves version v1beta1 of the API which is now deprecated. ([#1467](https://github.com/vmware-tanzu/antrea/pull/1467), [@Dyanngg] [@tnqn])
  * Internal NetworkPolicy objects in "controlplane.antrea.tanzu.vmware.com/v1beta2" are cluster-scoped instead of Namespace-scoped and collisions between Antrea-native policies and K8s policies are no longer possible
- Upgrade the "core.antrea.tanzu.vmware.com" API to v1alpha2 and remove the v1alpha1 version. ([#1467](https://github.com/vmware-tanzu/antrea/pull/1467), [@Dyanngg])
- Remove deprecated Prometheus metrics "antrea_agent_runtime_info" and "antrea_controller_runtime_info". ([#1503](https://github.com/vmware-tanzu/antrea/pull/1503), [@srikartati])
- Remove unnecessary writes to "send_redirects" Kernel parameters in the Agent; in theory antrea-agent no longer needs to be run as a "privileged" container, although it is recommended to keep doing so for the FlowExporter feature. ([#1364](https://github.com/vmware-tanzu/antrea/pull/1364), [@tnqn])
- Do not track Geneve / VXLAN overlay traffic in the host network; this improves data-plane performance when kube-proxy installs a large number of iptables rules. ([#1425](https://github.com/vmware-tanzu/antrea/pull/1425), [@tnqn])
- Optimize OpenFlow priority assignment in the Agent when converting policies to flows, by assigning all the rule priorities for a given policy in batch. ([#1331](https://github.com/vmware-tanzu/antrea/pull/1331), [@Dyanngg])
- Upgrade Octant to v0.16.1 and leverage support for "alerts" in the UI to display error messages to users when Traceflow request parameters are invalid or when an error occurs. ([#1371](https://github.com/vmware-tanzu/antrea/pull/1371), [@ZhangYW18])
- More robust script for preparing Windows Nodes before running the Antrea Agent. ([#1480](https://github.com/vmware-tanzu/antrea/pull/1480), [@ruicao93])
- Remove dependency on the serviceCIDR configuration parameter in the FlowExporter implementation, when AntreaProxy is enabled. ([#1380](https://github.com/vmware-tanzu/antrea/pull/1380), [@srikartati])
- Cache mapping from OVS flow ID to original NetworkPolicy in the Agent for a small time interval after the flow has been deleted, to ensure the information remains accessible when generating stats reports or flow records. ([#1411](https://github.com/vmware-tanzu/antrea/pull/1411), [@srikartati])
- Officially-supported Go version is no longer 1.13 but 1.15. ([#1420](https://github.com/vmware-tanzu/antrea/pull/1420), [@antoninbas]).

### Fixed

- Support for Antrea-native policies in Traceflow: without this change all the Traceflow requests would time out and fail. ([#1361](https://github.com/vmware-tanzu/antrea/pull/1361), [@gran-vmv])
- Use 32-bit unsigned integers for timestamps in flow records instead of 64-bit signed integers, as per the [IPFIX RFC](https://tools.ietf.org/html/rfc7011#section-6.1.7). ([#1479](https://github.com/vmware-tanzu/antrea/pull/1479), [@zyiou])

## 0.10.2 - 2020-11-11

### Added

- Use logrotate to rotate OVS log files written to the Node and avoid filling up the disk partition; log rotation can be configured by changing the "--log_file_max_num" and "--log_file_max_size" command-line arguments for "start_ovs" in the Antrea manifest. ([#1329](https://github.com/vmware-tanzu/antrea/pull/1329), [@jianjuns])

### Changed

- Update Octant plugin installation guide to simplify the steps when deploying Octant as a Pod. ([#1473](https://github.com/vmware-tanzu/antrea/pull/1473), [@mengdie-song])

### Fixed

- Use IP DSCP field instead of Geneve TLV metadata to encode the Traceflow data-plane tag. ([#1466](https://github.com/vmware-tanzu/antrea/pull/1466), [@gran-vmv])
   * This works around an OVS issue which was causing inter-Node Traceflow requests to frequently hang unless no other traffic was present in the cluster network
   * Traceflow can now be used regardless of the traffic mode: this includes other tunneling protocols (e.g. VXLAN) and noEncap mode
- Update version of libOpenflow to fix a deadlock when an OpenFlow bundle times out, which was causing the Node to run out of Pod IPs; the issue was introduced in v0.10.0. ([#1511](https://github.com/vmware-tanzu/antrea/pull/1511), [@weiqiangt] [@tnqn])
- Do not fail Agent initialization if xtables lock cannot be acquired within a short amount of time, as it only creates more xtables lock contention and prevents Pod from being created. ([#1497](https://github.com/vmware-tanzu/antrea/pull/1497), [@tnqn])
- Bump up portmap CNI plugin version to 0.8.7 to further reduce the xtables lock contention. ([#1534](https://github.com/vmware-tanzu/antrea/pull/1534), [@tnqn])
- When a new Node is allocated the same Pod CIDR as a recently-deleted Node by the K8s control-plane, do not process the Node creation event in the Antrea Agent until after the deletion event for the old Node has been processed. ([#1526](https://github.com/vmware-tanzu/antrea/pull/1526), [@tnqn])
- Fix SessionAffinity implementation in AntreaProxy for non-TCP traffic (UDP & SCTP): the match defined in the learn action was incorrect as the transport protocol was hardcoded to TCP. ([#1398](https://github.com/vmware-tanzu/antrea/pull/1398), [@wenyingd])
- Respect the provided label selector in Antrea aggregated APIs instead of always returning the complete list of objects for each resource type. ([#1481](https://github.com/vmware-tanzu/antrea/pull/1481), [@tnqn])
- When the destination is a Service in a Traceflow request, automatically set the TCP SYN flag so the packet can be processed by AntreaProxy correctly. ([#1386](https://github.com/vmware-tanzu/antrea/pull/1386) [#1378](https://github.com/vmware-tanzu/antrea/pull/1378), [@lzhecheng] [@mengdie-song])
- Ignore Antrea-native policy resources in the Agent if the `AntreaPolicy` feature is not enabled, to avoid crashes. ([#1336](https://github.com/vmware-tanzu/antrea/pull/1336), [@jianjuns])
- When removing Service flows in AntreaProxy, remove Endpoint flows at the very end to avoid "inifinite" packet recirculation in some scenarios. ([#1381](https://github.com/vmware-tanzu/antrea/pull/1381), [@weiqiangt])
- Set OVS version after the ovs-vswitchd service is started in the Windows installation script to ensure it can always be set successfully. ([#1423](https://github.com/vmware-tanzu/antrea/pull/1423), [@ruicao93] [@jayunit100]) [Windows]
- Ensure that the "appliedTo" and "priority" fields are required in the OpenAPI spec for the ClusterNetworkPolicy CRD. ([#1359](https://github.com/vmware-tanzu/antrea/pull/1359), [@abhiraut])
- Always restart OVS services on Windows in case of failure. ([#1495](https://github.com/vmware-tanzu/antrea/pull/1495), [@ruicao93]) [Windows]
- Validate the Agent configuration on startup and log an error message if any enabled feature is not supported by the OS (in particular on Windows Nodes). ([#1468](https://github.com/vmware-tanzu/antrea/pull/1468), [@jianjuns])
- Add sanity checks for IPsec and log helpful error messages if some packages or components are missing. ([#1430](https://github.com/vmware-tanzu/antrea/pull/1430), [@antoninbas])
- Fix reference Kibana dashboard configuration file for FlowExporter feature: some IPFIX IE names did not match the names from the Antrea registry. ([#1370](https://github.com/vmware-tanzu/antrea/pull/1370), [@zyiou])

## 0.10.1 - 2020-09-30

### Fixed

- Fix OpenAPI spec for the ClusterNetworkPolicy CRD: the incorrect spec was causing all CNPs with egress rules to be rejected by kubectl and the K8s apiserver. ([#1314](https://github.com/vmware-tanzu/antrea/pull/1314), [@abhiraut])
   * this only affects users which enable the `AntreaPolicy` Feature Gate in their cluster and create ClusterNetworkPolicies

## 0.10.0 - 2020-09-24

Includes all the bug fixes from [0.9.1], [0.9.2] and [0.9.3].

Starting with Antrea 0.10.0, K8s version >= 1.16 is required.

### Added

- Add Antrea NetworkPolicy CRD API to define namespaced security policies which support additional features compared to K8s NetworkPolicies. ([#1117](https://github.com/vmware-tanzu/antrea/pull/1117) [#1194](https://github.com/vmware-tanzu/antrea/pull/1194), [@Dyanngg] [@abhiraut]) [Alpha - Feature Gate: `AntreaPolicy`]
   * The `ClusterNetworkPolicy` Feature Gate has been removed, `AntreaPolicy` is used for both Antrea NetworkPolicies and ClusterNetworkPolicies
   * Refer to the [Antrea Policy CRDs documentation] for information
- Add "v1alpha1.stats.antrea.tanzu.vmware.com" API to query traffic statistics about NetworkPolicies (number of sessions / packets / bytes which are allowed or denied). ([#1172](https://github.com/vmware-tanzu/antrea/pull/1172) [#1221](https://github.com/vmware-tanzu/antrea/pull/1221) [#1140](https://github.com/vmware-tanzu/antrea/pull/1140), [@tnqn] [@weiqiangt]) [Alpha - Feature Gate: `NetworkPolicyStats`]
   * The stats are aggregated from each Antrea Agent using an internal API in "controlplane.antrea.tanzu.vmware.com"
- Add ability for users to define their own policy tiers using a Tier CRD. ([#926](https://github.com/vmware-tanzu/antrea/pull/926) [#1237](https://github.com/vmware-tanzu/antrea/pull/1237) [#1260](https://github.com/vmware-tanzu/antrea/pull/1260) [#1290](https://github.com/vmware-tanzu/antrea/pull/1290), [@abhiraut] [@Dyanngg])
   * The 5 static tiers introduced in 0.9.x are mapped to read-only CRDs, in order to provide backwards-compatibility for clusters with existing tiered policies
   * [Admission webhooks] ensure consistency across Tiers, NetworkPolicies and ClusterNetworkPolicies
   * Refer to the [Antrea Policy CRDs documentation] for information
- Support for ExternalEntity: rules in Antrea policies can select labelled non-Pod endpoints (e.g. VMs) which are represented by ExternalEntity CRD resources. ([#1084](https://github.com/vmware-tanzu/antrea/pull/1084), [@Dyanngg] [@suwang48404])
- Support for querying the list of NetworkPolicies which are applied to a specific Pod, or which select a specific Pod in an ingress / egress rule. ([#1116](https://github.com/vmware-tanzu/antrea/pull/1116), [@jakesokol1] [@antoninbas]) [Alpha]
   * New "/endpoint" API endpoint in Antrea Controller - API may change in future releases
   * New "antctl query endpoint" command
- Add Prometheus metrics for the connection tracking table (max size, total number of connections, total number of connections installed by Antrea) when `FlowExporter` is enabled. ([#1232](https://github.com/vmware-tanzu/antrea/pull/1232), [@dreamtalen])
- Configure access to Antrea NetworkPolicy and ClusterNetworkPolicy APIs for [default cluster roles] (admin / edit / view) using [aggregated ClusterRoles]. ([#1206](https://github.com/vmware-tanzu/antrea/pull/1206), [@abhiraut])
- Configure access to Traceflows API for [default cluster roles] (admin / edit / view) using [aggregated ClusterRoles]. ([#1231](https://github.com/vmware-tanzu/antrea/pull/1231), [@abhiraut])

### Changed

- Re-introduce legacy "networking.antrea.tanzu.vmware.com" internal API group which was previously removed in [0.9.3], to avoid upgrade issues. ([#1243](https://github.com/vmware-tanzu/antrea/pull/1243), [@tnqn])
   * Users can safely upgrade from any 0.9.x release to 0.10.0 without disruption in NetworkPolicy enforcement, assuming the Antrea Controller is upgraded first.
- Use the v1 version of "apiextensions.k8s.io" instead of "v1beta1"; v1 was introduced in K8s 1.15. ([#1009](https://github.com/vmware-tanzu/antrea/pull/1009), [@abhiraut])
   * As part of this, the OpenAPI spec used for validation was improved for several of the Antrea CRDs
- Use the v1 version of "rbac.authorization.k8s.io" instead of v1beta1; v1 was introduced in K8s 1.8. ([#1274](https://github.com/vmware-tanzu/antrea/pull/1274), [@abhiraut])
- Change type of some Prometheus metrics from "summary" to "histogram", which may impact consumers of these metrics, which where incorrectly tagged as "STABLE" when they were first introduced. ([#1202](https://github.com/vmware-tanzu/antrea/pull/1202), [@dreamtalen])
- Deprecate "antrea_agent_runtime_info" and "antrea_controller_runtime_info" metrics, which will be removed in 0.11; the same information can now be obtained from the instance label of the target. ([#1217](https://github.com/vmware-tanzu/antrea/pull/1217), [@srikartati])
- Upgrade OVS version to 2.14.0 to pick up some recent patches. ([#1121](https://github.com/vmware-tanzu/antrea/pull/1121), [@lzhecheng])
- Collect additional information in support bundle. ([#1145](https://github.com/vmware-tanzu/antrea/pull/1145), [@wenyingd])
   * OVS logs, kubelet logs and host network configuration on Windows Nodes [Windows]
   * Description of the ports associated with the OVS bridge
- Restrict read permissions for the OVSDB file persisted on each Node. ([#1293](https://github.com/vmware-tanzu/antrea/pull/1293), [@antoninbas])
- Add more consistent short names for Antrea NetworkPolicies ("anp") and ClusterNetworkPolicies ("acnp"). ([#1291](https://github.com/vmware-tanzu/antrea/pull/1291), [@abhiraut])
- Add reference to the original user-defined policy object in the internal representation of policies computed by the Antrea Controller and served through the "controlplane.antrea.tanzu.vmware.com" internal API. ([#1258](https://github.com/vmware-tanzu/antrea/pull/1258), [@tnqn])
- Remove dependency on "github.com/goccy/go-graphviz" in the Traceflow UI implementation: usage of cgo was creating issues when cross-compiling assets and some of the module's dependencies were distributed under copyleft licenses. ([#1127](https://github.com/vmware-tanzu/antrea/pull/1127), [@ZhangYW18])
- Remove `serviceCIDR` Agent configuration parameter from Antrea manifests destined to public cloud K8s services (AKS, EKS, GKE) to avoid confusion: AntreaProxy is always enabled for those, which means that the parameter is not needed and will be ignored if provided. ([#1177](https://github.com/vmware-tanzu/antrea/pull/1177), [@jianjuns])
- Add status message in Traceflow UI for running Traceflow requests. ([#1277](https://github.com/vmware-tanzu/antrea/pull/1277), [@ZhangYW18])
- Optimize flow priority assignment for Antrea Policies when the Agent restarts. ([#1105](https://github.com/vmware-tanzu/antrea/pull/1105), [@Dyanngg])

### Fixed

- Periodically check timeout of running Traceflow requests to provide a useful status to users and avoid leaking data-plane tags. ([#1179](https://github.com/vmware-tanzu/antrea/pull/1179), [@jianjuns])

## 0.9.3 - 2020-09-03

### Changed

- Rename *internal* API group from "networking.antrea.tanzu.vmware.com" to "controlplane.antrea.tanzu.vmware.com". ([#1147](https://github.com/vmware-tanzu/antrea/pull/1147), [@jianjuns])
   * This API is served by the Antrea Controller and consumed by Agents (directly) and antctl (through the K8s apiserver using an APIService)
   * Antrea Controller deletes the previous APIService on startup to avoid issues (e.g. with Namespace deletion)
   * During upgrade from a previous version, NetworkPolicy enforcement will be disrupted until the upgrade is complete: NetworkPolicy changes may not take effect and NetworkPolicies may not be applied to new Pods, until all components have been updated

### Fixed

- Fix IPsec support which was broken after updating the base distribution to Ubuntu 20.04 for the Antrea Docker image, as this update introduced a more recent version of [strongSwan]. ([#1184](https://github.com/vmware-tanzu/antrea/pull/1184) [#1191](https://github.com/vmware-tanzu/antrea/pull/1191), [@jianjuns])
- Fix deadlock in the NetworkPolicy implementation in the Antrea Agent: this issue could only be observed when using ClusterNetworkPolicies but was affecting the enforcement of all NetworkPolicies. ([#1186](https://github.com/vmware-tanzu/antrea/pull/1186), [@Dyanngg] [@yktsubo] [@tnqn])
- Fix unbound variable error in "start_ovs" Bash script, which was causing the antrea-ovs container to crash if one OVS daemon stopped for any reason. ([#1190](https://github.com/vmware-tanzu/antrea/pull/1190), [@antoninbas] [@alex-vmw])

## 0.9.2 - 2020-08-27

### Fixed

- Fix incorrect conversion from unsigned integer to string when indexing the flows responsible for the implementation of a NetworkPolicy rule by their conjunction ID / rule ID; this issue could have caused incorrect NetworkPolicy enforcement when a large number of rules are applied to a Node. ([#1161](https://github.com/vmware-tanzu/antrea/pull/1161), [@weiqiangt])
- Fix self-signed certificate rotation in the Antrea Controller: after rotation (at half the expiration time), the new certificate was distributed to clients while the Controller apiserver kept using the old certificate. ([#1154](https://github.com/vmware-tanzu/antrea/pull/1154), [@MatthewHinton56])
- Support setting TCP flags when initiating a Traceflow request from antctl; for Pod-to-Service trace packets, the SYN flag must be set. ([#1128](https://github.com/vmware-tanzu/antrea/pull/1128), [@lzhecheng])
- Generate correct filename for support bundle archive temporary file: on Windows the name included an asterisk which is invalid. ([#1150](https://github.com/vmware-tanzu/antrea/pull/1150), [@weiqiangt]) [Windows]

## 0.9.1 - 2020-08-21

### Changed

- Rotate self-signed certificate generated by the Antrea Controller at half the expiration time, instead of one day before expiration. ([#1115](https://github.com/vmware-tanzu/antrea/pull/1115), [@andrewsykim])
- Collect heap profile data in Antrea support bundle to help troubleshoot issues related to memory usage. ([#1110](https://github.com/vmware-tanzu/antrea/pull/1110), [@weiqiangt])

### Fixed

- Optimize processing of egress policy rules that do not include any named port by avoiding the creation and distribution of a "global" AddressGroup - which includes all the Pods - when unnecessary. ([#1100](https://github.com/vmware-tanzu/antrea/pull/1100), [@tnqn])
- Avoid duplicate processing of Traceflow requests in the Antrea Controller and fix data-plane tag allocation. ([#1094](https://github.com/vmware-tanzu/antrea/pull/1094), [@jianjuns])
- Work around race condition in github.com/containernetworking/plugins when determining the network namespace of the caller which was responsible for errors when configuring Pod networking at scale. ([#1131](https://github.com/vmware-tanzu/antrea/pull/1131), [@tnqn])
- Fail the CNI ADD request if the OF port value returned by OVS is -1, which indicates an error during interface creation. ([#1112](https://github.com/vmware-tanzu/antrea/pull/1112), [@tnqn])
- Resubmit traffic for which Antrea Proxy has performed DNAT to the correct table so that ClusterNetworkPolicies can be enforced correctly. ([#1119](https://github.com/vmware-tanzu/antrea/pull/1119), [@weiqiangt] [@yktsubo])
- Update Windows OVS package so that the dependency on Microsoft Visual C++ can be resolved during installation. ([#1099](https://github.com/vmware-tanzu/antrea/pull/1099), [@ruicao93]) [Windows]
- Temporarily ignore sanity checks when issuing a Traceflow request from the Octant UI since the current version of Octant does not support reporting the errors to the user; instead the Traceflow CRD is created and its "Status" field can be used to troubleshoot. ([#1097](https://github.com/vmware-tanzu/antrea/pull/1097), [@ZhangYW18])
- Revert all priority updates to policy flows if flow installation / modification fails on OVS. ([#1095](https://github.com/vmware-tanzu/antrea/issues/1095), [@Dyanngg])
- Fix the Antrea manifest for EKS (antrea-eks.yml) published for each release. ([#1090](https://github.com/vmware-tanzu/antrea/pull/1090), [@antoninbas])

## 0.9.0 - 2020-08-13

### Added

- Add [flow exporter] feature. [Alpha - Feature Gate: `FlowExporter`]
   * Support sending network flow records using the IPFIX protocol from each Agent ([#825](https://github.com/vmware-tanzu/antrea/pull/825) [#984](https://github.com/vmware-tanzu/antrea/pull/984), [@srikartati])
   * Add reference cookbook to visualize exported flows using Elastic Stack ([#836](https://github.com/vmware-tanzu/antrea/pull/836), [@zyiou])
- Support [OVS hardware offload] for Pod networking: Pods can now be assigned an SR-IOV Virtual Function. ([#786](https://github.com/vmware-tanzu/antrea/pull/786), [@moshe010])
   * Add new CI job to validate the hardware offload functionality ([@AbdYsn])
- Support Node MTU auto-discovery in the Antrea Agent; the user can still override this value in the Agent configuration if desired. ([#909](https://github.com/vmware-tanzu/antrea/pull/909), [@reachjainrahul])
- Enable Antrea support for the [AKS] managed K8s service, using CNI chaining and the "networkPolicyOnly" traffic mode. ([#998](https://github.com/vmware-tanzu/antrea/pull/998), [@reachjainrahul])
- Support for NetworkPolicy tiering (ClusterNetworkPolicy only). ([#956](https://github.com/vmware-tanzu/antrea/pull/956) [#986](https://github.com/vmware-tanzu/antrea/pull/986), [@abhiraut] [@Dyanngg])
   * The `ClusterNetworkPolicy` Feature Gate must now be enabled for the Agent (in addition to the Controller) to activate the feature
- Support executing Traceflow requests with antctl. ([#932](https://github.com/vmware-tanzu/antrea/pull/932), [@lzhecheng])
- Support automatic rotation for the self-signed certificate generated by Antrea when no certificate is provided by the user. ([#1024](https://github.com/vmware-tanzu/antrea/pull/1024), [@MatthewHinton56])
- Add new Agent Prometheus metrics for OVS flow operations. ([#866](https://github.com/vmware-tanzu/antrea/pull/866), [@yktsubo])
- Provide a DaemonSet to automatically restart Pods on new Nodes in EKS when Antrea becomes ready: this ensures that NetworkPolicies are enforced correctly for all Pods. ([#1057](https://github.com/vmware-tanzu/antrea/pull/1057), [@reachjainrahul])
- Add scripts to run the Antrea Agent directly without using a Pod to manage the lifecycle of the process. ([#1013](https://github.com/vmware-tanzu/antrea/pull/1013), [@ruicao93]) [Windows]

### Changed

- Restrict all traffic modes except for "encap" to use "Antrea Proxy" for Pod-to-Service traffic, as this greatly simplifies the datapath implementation. ([#1015](https://github.com/vmware-tanzu/antrea/pull/1015), [@suwang48404])
- Improve Antrea Octant plugin. ([#913](https://github.com/vmware-tanzu/antrea/pull/913), [@ZhangYW18])
   * Merge the two existing plugins (Agent / Controller Info, Traceflow) into a single plugin / binary
   * Enhance Traceflow graph color theme
   * Improve layout of the "Overview" page for the plugin: all CRDs are shown on the same page
   * Update Octant plugin installation guide ([#914](https://github.com/vmware-tanzu/antrea/pull/914), [@mengdie-song])
- Use Ubuntu 20.04 (instead of Ubuntu 18.04) as the base distribution for the Antrea Docker image. ([#1022](https://github.com/vmware-tanzu/antrea/issues/1022), [@antoninbas])
- Enable outer UDP checksum for Geneve and VXLAN tunnels to benefit from Generic Receive Offload (GRO) on the receiver's side. ([#1049](https://github.com/vmware-tanzu/antrea/pull/1049), [@tnqn])
- Support Services as destinations for Traceflow. ([#979](https://github.com/vmware-tanzu/antrea/pull/979), [@gran-vmv])
- Provide additional printer columns in the Traceflow CRD definition, so that more information is included in the "kubectl get" output. ([#958](https://github.com/vmware-tanzu/antrea/pull/958), [@abhiraut])
- More comprehensive OpenAPI schema for Traceflow CRD validation. ([#918](https://github.com/vmware-tanzu/antrea/pull/918), [@abhiraut])
- Optimize OVS flow updates for NetworkPolicies when the Agent restarts, by using batching. ([#844](https://github.com/vmware-tanzu/antrea/pull/844), [@Dyanngg])
- Increase watch timeout for the Antrea apiserver to reduce reconnection frequency; reduce log verbosity when a legitimate reconnection happens. ([#1055](https://github.com/vmware-tanzu/antrea/pull/1055), [@antoninbas])
- Update [OVS pipeline documentation] to account for the new tables used for ClusterNetworkPolicy and tiering support. ([#921](https://github.com/vmware-tanzu/antrea/pull/921) [#1073](https://github.com/vmware-tanzu/antrea/pull/1073), [@abhiraut])

### Fixed

- Fix implementation of NodePort Service on Windows for traffic for which the destination Pod (Service backend) is on the same Node as the source Pod. ([#948](https://github.com/vmware-tanzu/antrea/pull/948), [@wenyingd]) [Windows]
- Fix IPsec support, which was broken because of Python3 error in an upstream OVS script. ([#1046](https://github.com/vmware-tanzu/antrea/pull/1046), [@lzhecheng])
- Support Pod-to-LoadBalancer Service traffic in "Antrea Proxy". ([#943](https://github.com/vmware-tanzu/antrea/pull/943), [@ruicao93])
- Support incoming LoadBalancer Service traffic on Windows, by relying on kube-proxy. ([#943](https://github.com/vmware-tanzu/antrea/pull/943), [@ruicao93]) [Windows]
- Avoid OpenFlow bundle timeout issues when using Traceflow: if PacketIn messages are not consumed fast enough, all inbound messages from OVS are blocked, including bundle reply messages. ([#951](https://github.com/vmware-tanzu/antrea/pull/951), [@gran-vmv])
- Move host routes from the uplink interface to the OVS bridge during Agent initialization on Windows. ([#959](https://github.com/vmware-tanzu/antrea/pull/959), [@ruicao93]) [Windows]
- Optimize handling of very large AddressGroups (introduced by NetworkPolicies which select a large number of Pods in to/from rules) in the Antrea Agent. ([#1031](https://github.com/vmware-tanzu/antrea/pull/1031), [@tnqn])
- Modify "List" apiserver requests in the Agent to use "resourceVersion=0", which forces requests to be served from the cache (instead of etcd persistent storage) and removes performance issues when many agents are restarted simultaneously. ([#1045](https://github.com/vmware-tanzu/antrea/pull/1045), [@wenyingd])
- Fix OVS deadlock caused by glibc bug, by upgrading base distribution to Ubuntu 20.04 in Antrea Docker image. ([#1022](https://github.com/vmware-tanzu/antrea/issues/1022), [@antoninbas] [@alex-vmw])
- Set the "no-flood" configuration option on the uplink bridge port in Windows, so that ARP broadcast traffic is not sent out to the underlay network. ([#922](https://github.com/vmware-tanzu/antrea/pull/922), [@wenyingd]) [Windows]
- Avoid inaccurate warnings in the logs about "POD_NAMESPACE" not set. ([#925](https://github.com/vmware-tanzu/antrea/pull/925), [@antoninbas])
- Fix format of tracing packets for Traceflow:
   * Set protocol version to the correct value in the IP header ([#946](https://github.com/vmware-tanzu/antrea/pull/946), [@lzhecheng])
   * Add correct L3/L4 checksum values ([#967](https://github.com/vmware-tanzu/antrea/pull/967), [@gran-vmv])
   * Set destination MAC address correctly when the provided destination IP address matches a local Pod. ([#981](https://github.com/vmware-tanzu/antrea/pull/981), [@ZhangYW18])
- In "hybrid" traffic mode, reject Traceflow requests if the source and destination Nodes are not connected by a tunnel. ([#944](https://github.com/vmware-tanzu/antrea/pull/944), [@gran-vmv])
- Log human-readable messages when the ofnet library returns an error. ([#1065](https://github.com/vmware-tanzu/antrea/pull/1065), [@wenyingd])
- Wait for the Antrea client in the Agent to be ready before starting watches to avoid error log messages. ([#1042](https://github.com/vmware-tanzu/antrea/pull/1042), [@tnqn])

## 0.8.2 - 2020-07-13

### Fixed

- Fix Agent logic in charge of sending Gratuitous ARP messages when networking is configured for a Pod: the previous code was not thread-safe and causing file descriptor leaks for concurrent CNI ADD requests. ([#933](https://github.com/vmware-tanzu/antrea/pull/933), [@tnqn])
- Clean up some internal state in the Agent's NetworkPolicy implementation when a rule is updated. ([#929](https://github.com/vmware-tanzu/antrea/pull/929), [@jianjuns])

## 0.8.1 - 2020-07-09

## 0.8.0 - 2020-07-02

### Added

- Add "Antrea Proxy" implementation to provide Pod-to-Service load-balancing (for ClusterIP Services) directly in the OVS pipeline. ([#772](https://github.com/vmware-tanzu/antrea/pull/772), [@weiqiangt]) [Alpha - Feature Gate: `AntreaProxy`]
   * This feature is enabled by default for Windows Nodes, as it is required for correct NetworkPolicy implementation for Pod-to-Service traffic
- Add ClusterNetworkPolicy CRD API, which enables cluster admins to define security policies which apply to the entire cluster (not just one Namespace). ([#810](https://github.com/vmware-tanzu/antrea/pull/810) [#872](https://github.com/vmware-tanzu/antrea/pull/872) [#724](https://github.com/vmware-tanzu/antrea/pull/724), [@abhiraut] [@Dyanngg]) [Alpha - Feature Gate: `ClusterNetworkPolicy`]
- Add Traceflow CRD API, which supports generating tracing requests for traffic going through the Antrea-managed Pod network. ([#660](https://github.com/vmware-tanzu/antrea/pull/660) [#731](https://github.com/vmware-tanzu/antrea/pull/731), [@gran-vmv] [@lzhecheng]) [Alpha - FeatureGate: `Traceflow`]
- Add Traceflow Octant plugin: requests can be generated from the Web dashboard (by filling-out a form) and responses are displayed in graph format. ([#841](https://github.com/vmware-tanzu/antrea/pull/841), [@ZhangYW18])
- Wrap klog so that one can specify a maximum number of log files to be kept for each verbosity level (using "--log_file_max_num"), while enforcing the size limit for each file (as specified with "--log_file_max_size"). ([#879](https://github.com/vmware-tanzu/antrea/pull/879), [@jianjuns] [@alex-vmw])
- Support executing Agent API requests which depend on OVS command-line utilities (e.g., ovs-ofctl, ovs-appctl) on Windows Nodes; this enables using the "antctl get ovsflows" and "antctl trace-packet" commands for Windows Nodes. ([#794](https://github.com/vmware-tanzu/antrea/pull/794), [@wenyingd])
- Support "antctl supportbundle" command for Windows Nodes. ([#820](https://github.com/vmware-tanzu/antrea/pull/820), [@weiqiangt])
- Add "--controller-only" flag to "antctl supportbundle" command to only collect information from the Controller, without the Agents. ([#791](https://github.com/vmware-tanzu/antrea/pull/791), [@weiqiangt])
- Add new Agent Prometheus metrics for NetworkPolicies:
   * "antrea_agent_ingress_networkpolicy_rule", "antrea_agent_egress_networkpolicy_rule" ([#770](https://github.com/vmware-tanzu/antrea/pull/770), [@yktsubo])
   * "antrea_agent_networkpolicy_count" ([#834](https://github.com/vmware-tanzu/antrea/pull/834), [@yktsubo])
- Additional documentation:
   * Windows design document ([#751](https://github.com/vmware-tanzu/antrea/pull/751), [@wenyingd] [@ruicao93])
   * information about "supportbundle" command in antctl documentation ([#812](https://github.com/vmware-tanzu/antrea/pull/812), [@antoninbas])
   * Feature gates documentation ([#892](https://github.com/vmware-tanzu/antrea/issues/892), [@antoninbas])

### Changed

- Change default tunnel type from VXLAN to Geneve. ([#858](https://github.com/vmware-tanzu/antrea/pull/858) [#903](https://github.com/vmware-tanzu/antrea/pull/903), [@jianjuns] [@antoninbas] [@abhiraut])
   * **this may cause some disruption during upgrade, as inter-Node Pod communications between Nodes running Antrea pre-v0.8 and Nodes running Antrea post-v0.8 will be broken**; edit the manifest if you want to stick to VXLAN
- Move Octant plugin to a new "plugins/" folder and make it its own Go module. ([#838](https://github.com/vmware-tanzu/antrea/pull/838), [@mengdie-song])
- Update antrea-cni to support CNI version 0.4.0. ([#784](https://github.com/vmware-tanzu/antrea/pull/784), [@moshe010])
- Change gateway and tunnel interface names to antrea-gw0 and antrea-tun0 respectively. ([#854](https://github.com/vmware-tanzu/antrea/pull/854), [@jianjuns])
- Make antrea-agent Pod tolerant of "NoExecute" taints to prevent unwanted evictions. ([#815](https://github.com/vmware-tanzu/antrea/pull/815), [@tnqn])
- Use "Feature Gates" to control enabling / disabling experimental features instead of introducing separate temporary configuration parameters. ([#847](https://github.com/vmware-tanzu/antrea/pull/847), [@tnqn])
- Upgrade K8s API version used by Antrea to 1.18. ([#838](https://github.com/vmware-tanzu/antrea/pull/838), [@mengdie-song])
- Create controller-ca ConfigMap in the same Namespace as the Controller Deployment, instead of hard-coding it to "kube-system". ([#876](https://github.com/vmware-tanzu/antrea/issues/876), [@jianjuns])
- Log error when "iptables-restore" command fails. ([#839](https://github.com/vmware-tanzu/antrea/pull/839), [@tnqn])
- Update OVS version to 2.13.1 on Windows because of some issues, notably with the connection tracking implementation. ([#856](https://github.com/vmware-tanzu/antrea/pull/856), [@ruicao93])
- Update behavior of "antctl supportbundle" command so that the Controller logs are not collected when a Node name or a Node filter is provided. ([#857](https://github.com/vmware-tanzu/antrea/pull/857), [@jianjuns])

### Fixed

- Fix runtime crash in the Agent when processing NetworkPolicy rules for which a Protocol has been provided, but no Port. ([#882](https://github.com/vmware-tanzu/antrea/pull/882), [@wenyingd] [@abhiraut])
- Clean up stale OVS PID files to avoid failure loops in antrea-ovs startup. ([#880](https://github.com/vmware-tanzu/antrea/pull/880), [@jianjuns])
- When using CNI chaining in a cloud-managed service, ensure that the initContainer blocks until the "primary CNI"'s conf file is found. ([#864](https://github.com/vmware-tanzu/antrea/pull/864), [@reachjainrahul])
- Update version of go-iptables library to avoid deadlock when invoking iptables commands. ([#873](https://github.com/vmware-tanzu/antrea/pull/873), [@antoninbas])
- Improve robustness of the liveness probe for the antrea-ovs container. ([#861](https://github.com/vmware-tanzu/antrea/pull/861), [@tnqn])

## 0.7.2 - 2020-06-15

### Fixed

- Fix handling of StatefulSet Pod rescheduling on same Node: a fast rescheduling can cause unexpected ordering of CNI ADD and DELETE commands, which means Antrea cannot use the Pod Namespace+Name as the unique identifier for a Pod's network configuration. [#827](https://github.com/vmware-tanzu/antrea/pull/827)
- Fix IP address leak in IPAM caused by Antrea in-memory cache being out-of-sync with IPAM store. [#828](https://github.com/vmware-tanzu/antrea/pull/828)
- Increase timeout to 5 seconds when waiting for ovs-vswitchd to report the allocated of_port number. [#830](https://github.com/vmware-tanzu/antrea/pull/830)
- Fix CNI CHECK command implementation: the CNI server was always returning success even in case of failure. [#821](https://github.com/vmware-tanzu/antrea/pull/821)
- Update ofnet library version to avoid a goroutine leak. [#813](https://github.com/vmware-tanzu/antrea/pull/813)
- Exclude /healthz from authorization to avoid unnecessary calls to K8s API in readiness probes. [#816](https://github.com/vmware-tanzu/antrea/pull/816)

## 0.7.1 - 2020-06-05

### Fixed

- Fix Agent logic in charge of sending Gratuitous ARP messages when networking is configured for a Pod; stale ARP cache entries may otherwise cause connectivity issues. [#796](https://github.com/vmware-tanzu/antrea/pull/796)
- Fix Agent crash when running in "networkPolicyOnly" mode, and in particular when running Antrea in [EKS]. [#793](https://github.com/vmware-tanzu/antrea/issues/793), [#795](https://github.com/vmware-tanzu/antrea/pull/795)
- Replace usage of 'resubmit' with 'goto_table' action in new Windows-specific OVS flows. [#759](https://github.com/vmware-tanzu/antrea/issues/759)

## 0.7.0 - 2020-05-29

### Added

- Support for worker Nodes running Windows Server 2019 or higher. [Alpha]
   * Refer to [Antrea Windows documentation] for usage
   * A known limitation is that K8s NetworkPolicies are not enforced correctly for Service traffic, due to our reliance on userspace kube-proxy; this will be addressed in a future release
- Support server certificate verification for Controller APIs; users can provide their own certificates (TLS certificate and corresponding CA certificate) or let the Controller generate them.
- Add ability to collect Antrea support bundles (all the relevant information useful for providing support for Antrea) using new "antctl supportbundle" command, along with corresponding Antrea API resources at the Controller and Agent.
- Support local packet tracing in a Node by leveraging 'ovs-appctl ofproto/trace'.
- Add Antrea API port to the AgentInfo and ControllerInfo CRDs.
- Additional documentation:
   * user-facing documentation for antctl commands
   * information about non-default "encapsulation" modes ("hybrid", "noEncap", "networkPolicyOnly") in architecture document
   * design document for "networkPolicyOnly" mode (in particular, this mode is used for Antrea support in EKS)

### Changed

- Bump up K8s libraries to v0.17.6.
- Replace usage of 'resubmit' with 'goto_table' action in OVS pipeline: pipeline functionality is unaffected.
- Only include necessary Antrea binaries in Docker image to reduce its size.
- Support getting kubeconfig path from KUBECONFIG env variable for antctl.

### Fixed

- Fix implementation of K8s NetworkPolicies with overlapping ipBlock CIDRs; in particular, the issue manifested itself when there was overlap between a 'cidr' field in one rule and an 'except' field in another rule.
- Clean-up stale NetworkPolicies in the Agent after a reconnection to the Controller; this ensures that the corresponding stale flows are removed from the OVS bridge.
- Fix usage of iptables-restore in Antrea Agent to support iptables >= 1.6.2.
- Fix return path for NodePort Service traffic in EKS: an additional iptables rule is required in the mangle table, to ensure a correct reverse path through eth0 for traffic load-balanced to a Pod attached to a secondary ENI.
- Register "antrea_agent_local_pod_count" metric, which was defined without being registered properly.

## 0.6.0 - 2020-04-30

### Added

- Expose Prometheus metrics for Agent and Controller using the "/metrics" apiserver endpoint; "enablePrometheusMetrics" must be set to true in configuration.
- Add documentation for deploying Prometheus and scraping Antrea metrics, along with sample YAML manifest.
- Install portmap CNI by default in order to support Pods with "hostPort" set.
- Support configurable ports for Agent and Controller apiservers.
- Set default CPU resource requests for Antrea components in YAML manifest.
- Add "/ovsflows" API endpoint to Agent to query OVS flows and "antctl get ovsflows" command; flows can be filtered by Pod / NetworkPolicy / OVS Table.
- Improvements to "/networkpolicies" API endpoint and "antctl get networkpolicies" command:
   * namespace and name parameters to filter policies
   * ability to get NetworkPolicies applied to a Pod (Agent API only)
- Add object type aliases to antctl (plural form and short alias).
- Document known issues when deploying Antrea on Photon OS or CoreOS.

### Changed

- Add authentication to Agent apiserver to enable external access (from outside of Agent Pod), and generate bearer token for local access instead of delegating authentication to K8s apiserver.
- Send Agent and Controller logs to /var/log/antrea/ on the host as well as stderr.
- Make "table" output format the default for antctl get commands.
- Use custom formatter for logs originating from ofnet / libOpenflow (which use the logrus module) to mimic K8s log format.
- Use Go cross compilation support for "make bin": Antrea Linux binaries can now be built on other OS's.
- Ensure that OVS bridge datapath type is correct when Agent starts.

### Fixed

- Acquire xtables.lock before executing iptables-restore in Agent to avoid initialization error when kube-proxy uses iptables concurrently.
- Start ovs-vswitchd with flow-restore-wait config (only for OVS system datapath type) to avoid conntrack issues after antrea-ovs restarts; this could also reduce downtime during upgrades.
- Fix monitoring CRDs update: recover gracefully from transient errors.
- Handle DeletedFinalStateUnknown in NetworkPolicy Controller to avoid crashes when a watch deletion event is missed, e.g. because of a transient connectivity issue to the K8s apiserver.

## 0.5.1 - 2020-04-01

### Changed

- Remove performance bottleneck during NetworkPolicy computation in the Controller: add namespace-based indexers to quickly determine which internal objects need to be updated when a Pod is added / deleted.

### Fixed

- Fix implementation of deny-all egress policy (no egress traffic should be allowed for any Pod to which the policy is applied).
- Fix antctl segfault when kubeconfig cannot be resolved and print error instead.

## 0.5.0 - 2020-03-25

### Added

- Add "networkPolicyOnly" as a new "encapsulation mode": in this mode Antrea enforces NetworkPolicies with OVS, but is not in charge of forwarding.
- Support for running Antrea in [EKS] and [GKE] clusters; refer to the documentation.
- New antctl "get" commands:
   * in "agent mode": addressgroup, agentinfo, appliedtogroup, networkpolicy, podinterface
   * in "controller mode": addressgroup, appliedtogroup, controllerinfo, networkpolicy
- Support for a user-friendly "table" output format for antctl "get" commands.
- Add health checks to Antrea components by leveraging the apiserver /healthz endpoint (both the Antrea Agent and Controller are running an apiserver).
- Add documentation for connecting to the Antrea Agent or Controller apiserver, in order to check the resources created by Antrea.
- Ship antctl binaries as part of each release for different OS / CPU combinations: antctl-linux-x86_64, antctl-linux-arm, antctl-linux-arm64, antctl-windows-x86_64.exe, antctl-darwin-x86_64.
- Add documentation for antctl installation and usage.

### Changed

- Refactor antctl: most notable change is that the Antrea Agent now runs its own apiserver which the antctl CLI can connect to.
- Improve NetworkPolicy logging; in particular an Agent now logs (by default) a message when it receives a new NetworkPolicy that needs to be implemented locally.
- Upgrade OVS to version 2.13.0, which comes with userspace datapath improvements useful when running Antrea in Kind.
- Use ipset in iptables to match Pod-to-external traffic, which improves performance.
- Replace "beta.kubernetes.io/os" annotation (no longer supported in K8s 1.18) with "kubernetes.io/os".
- Enable running antctl from within the Antrea Controller Pod (by binding the antctl ClusterRrole to the antrea-controller ServiceAccount).

### Fixed

- Cancel ongoing OpenFlow bundle if switch disconnects, to prevent deadlock when replaying flows after a restart of the antrea-ovs container.
- Keep trying to reconnect to OVS switch indefinitely after a disconnection, instead of giving up after 5 seconds.
- Backport post-2.13 patch to OVS to avoid tunnel port deletion when the antrea-ovs container exits gracefully.
- Reduce memory usage of Antrea Controller when an Agent establishes a connection.
- Clean-up the appropriate iptables rules when a Node leaves the cluster.

## 0.4.1 - 2020-02-27

### Fixed

- Fix issues with IPsec support, which was broken in 0.4.0:
   * reduce MTU when IPsec is enabled to accommodate for IPsec overhead
   * add required flows to accept traffic received from IPsec tunnels
- Check and update (if needed) the type of the default tunnel port (tun0) after Agent starts.
- Fix race condition when the same OF port is reused for a new Pod.

## 0.4.0 - 2020-02-20

### Added

- Add support for new encapsulation modes: noEncap (inter-Node Pod traffic is never encapsulated) and hybrid (inter-Node Pod traffic is only encapsulated if Nodes are not on the same subnet).
- Add support for "named ports" to Network Policy implementation.
- Add user documentation for IPsec support.
- Add antctl "agent-info" command: command must be run from within the Agent container and will display information about the Agent (Node subnet, OVS bridge information, ...).
- Add support for new "table" output mode to antctl.

### Changed

- Changes in OpenFlow client:
   * use OpenFlow "bundle" to install related Network Policy flows as part of the same transaction
   * use flow-based tunnelling even when IPsec encryption is enabled
- Use patched OVS version in Antrea Docker image to avoid cleaning-up datapath flows on graceful antrea-ovs container exit.
- Reduce amount of Antrea Controller logs when computing Network Policies.

### Fixed

- Fix bug in the Agent that caused some Network Policies not to be enforced properly: for some flows the agent would overwrite existing conjunctive actions instead of adding new actions to the existing flow. This can notably happen when using a /32 ipBlock CIDR to select sources / destinations.
- Install loopback plugin on Nodes if missing, from the Agent's initContainer.
- Remove unnecessary periodical resync in Antrea K8s controllers to avoid overhead at scale.

## 0.3.0 - 2020-01-23

### Added

- Add support for the IPsec ESP protocol for GRE tunnels only; it can be enabled by applying antrea-ipsec.yml instead of antrea.yml.
- Add framework to develop CLI commands for Antrea; the antctl binary only supports the "version" command at the moment.
- Add octant/octant-antrea-ubuntu Docker image to dockerhub for easier deployment of [Octant] with the Antrea plugin.
- Add OpenFlow and OVSDB connection health information to the Agent's monitoring CRD.
- Add Network Policy information to monitoring CRDs for both the Agent and the Controller.
- Add documentation for OVS pipeline.

### Changed

- Change API group namings (for [CRDs] and Network Policies) from "crd.antrea.io" to "antrea.tanzu.vmware.com" and from "networkpolicy.antrea.io" to "networking.antrea.tanzu.vmware.com".
- Changes in OpenFlow client:
   * use OpenFlow "bundle" to install related flows as part of the same transaction (except for Network Policy flows)
   * all flows now have a cookie indicating their purpose (e.g. Pod flow) and encoding the Agent round number (which is incremented with every antrea-agent restart and persisted in OVSDB)
- Update to "Antrea on Kind" documentation to indicate that macOS hosts are also supported.

### Fixed

- Support NodePort services with externalTrafficPolicy set to Local.
- Mount xtables lock file to antrea-agent container to prevent concurrent iptables access by Antrea and kube-proxy.
- Replay flows to OVS switch after an OpenFlow reconnection (as it may indicate that vswitchd restarted and existing flows were deleted).
- Cleanup stale gateway routes (in host routing table) and tunnel ports (in OVSDB) on Agent startup.
- Cleanup stale flows in OVS switch on Agent startup.
- Improve the robustness of CNI DEL processing: cleanup resources even if provided container netns is no longer valid.
- Fix distribution of Network Polcies at scale: buffer size of the watchers channel is increased and unresponsive watchers (i.e. Agents) are terminated.

## 0.2.0 - 2019-12-19

The Monitoring [CRDs] feature is graduated from Alpha to Beta.

### Added

- Add "Last Hearbeat Time" to [Octant] plugin to visualize the last time the Agent / Controller reported its status.
- Add OVS version to Agent's monitoring CRD.
- Add instructions to run [Octant] and the Antrea plugin either in a Pod or as a process. A Dockerfile and YAML manifest are included for deploying [Octant] as a Pod.
- Support for GRE and STT tunnels for the Pod overlay network.

### Changed

- Use [libOpenflow] Go library to manage OVS flows instead of ovs-ofctl binary.
- Minor changes to the OVS pipeline, in particular to fix issues when using the netdev OVS datapath type.
- Officially-supported Go version is no longer 1.12 but 1.13.

### Fixed

- Allow the Node to reach all local Pods to support liveness probes even in the presence of Network Policies.
- Network Policy fixes:
   * fix implementation of Network Policies with multiple ingress / egress rules
   * support "except" field for "ipBlock" selectors
   * fix support for [default policies]
   * faster Network Policy enforcement by letting the CNI server notify the Agent's Network Policy controller when Pods are created
   * fix race condition that sometimes caused Network Policy span not to be updated properly and the Network Policy not to be disseminated to Nodes properly
   * ignore policy rules using named ports instead of allowing all traffic
- Remove stale Agent [CRDs] from the Controller: the Controller watches the Node list and removes the appropriate Agent CRD when a Node is deleted from the cluster.

## 0.1.1 - 2019-11-27

### Fixed

- Find host-local IPAM plugin even when kubelet is started with custom cni-bin-dir.
- Ensure that the Gratuitous ARP sent after adding container interface is not dropped. This ensures we can pass Kubernetes conformance tests reliably.
- Fix Kind support on Linux hosts.

## 0.1.0 - 2019-11-18

### Added

- Support for configuring and cleaning-up Pod networking as per the [CNI spec]. VXLAN or GENEVE tunnels are used for Pod connectivity across Nodes. [Beta]
- Support for [Kubernetes Network Policies]. [Alpha]
- Monitoring [CRDs] published by both the Antrea Agent and Controller to expose monitoring information. [Alpha]
- [Octant] plugin for visualizing the monitoring CRDs published by the Antrea Agent and Controller. [Alpha]

[CRDs]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
[CNI spec]: https://github.com/containernetworking/cni/blob/spec-v0.4.0/SPEC.md
[default policies]: https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-policies
[Kubernetes Network Policies]: https://kubernetes.io/docs/concepts/services-networking/network-policies/
[libOpenflow]: https://github.com/contiv/libOpenflow
[Octant]: https://github.com/vmware-tanzu/octant
[EKS]: https://aws.amazon.com/eks/
[GKE]: https://cloud.google.com/kubernetes-engine
[Antrea Windows documentation]: https://github.com/vmware-tanzu/antrea/blob/main/docs/windows.md
[OVS pipeline documentation]: https://github.com/vmware-tanzu/antrea/blob/main/docs/design/ovs-pipeline.md
[OVS hardware offload]: https://github.com/vmware-tanzu/antrea/blob/main/docs/ovs-offload.md
[AKS]: https://azure.microsoft.com/en-us/services/kubernetes-service/
[Flow Exporter]: https://github.com/vmware-tanzu/antrea/blob/main/docs/network-flow-visibility.md
[Elastic Stack]: https://www.elastic.co/elastic-stack
[strongSwan]: https://www.strongswan.org/
[Antrea Policy CRDs documentation]: https://github.com/vmware-tanzu/antrea/blob/main/docs/antrea-network-policy.md
[Default cluster roles]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles
[Aggregated ClusterRoles]: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#aggregated-clusterroles
[Admission webhooks]: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
[Traffic Shaping]: https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/#support-traffic-shaping
[bandwidth plugin]: https://github.com/containernetworking/plugins/tree/master/plugins/meta/bandwidth
[IPFIX mediator]: https://tools.ietf.org/html/rfc6183
[go-ipfix]: https://github.com/vmware/go-ipfix
[NodePortLocal]: https://github.com/vmware-tanzu/antrea/blob/main/docs/feature-gates.md#nodeportlocal
[ClusterGroup CRD]: https://github.com/vmware-tanzu/antrea/blob/main/docs/antrea-network-policy.md#clustergroup
[Kube-router]: https://www.kube-router.io/
[EndpointSlice]: https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/

[0.9.1]: #091---2020-08-21
[0.9.2]: #092---2020-08-27
[0.9.3]: #093---2020-09-03
[0.10.1]: #0101---2020-09-30
[0.10.2]: #0102---2020-11-11
[0.11.1]: #0111---2020-11-20
[0.12.1]: #0121---2021-02-10

[@AbdYsn]: https://github.com/AbdYsn
[@abhiraut]: https://github.com/abhiraut
[@alex-vmw]: https://github.com/alex-vmw
[@andrewsykim]: https://github.com/andrewsykim
[@anfernee]: https://github.com/anfernee
[@antoninbas]: https://github.com/antoninbas
[@ceclinux]: https://github.com/ceclinux
[@chauhanshubham]: https://github.com/chauhanshubham
[@dantingl]: https://github.com/dantingl
[@dreamtalen]: https://github.com/dreamtalen
[@dumlutimuralp]: https://github.com/dumlutimuralp
[@Dyanngg]: https://github.com/Dyanngg
[@gran-vmv]: https://github.com/gran-vmv
[@GraysonWu]: https://github.com/GraysonWu
[@guesslin]: https://github.com/guesslin
[@hemantavi]: https://github.com/hemantavi
[@hongliangl]: https://github.com/hongliangl
[@jakesokol1]: https://github.com/jakesokol1
[@jayunit100]: https://github.com/jayunit100
[@jianjuns]: https://github.com/jianjuns
[@ksamoray]: https://github.com/ksamoray
[@liu4480]: https://github.com/liu4480
[@lzhecheng]: https://github.com/lzhecheng
[@mattfenwick]: https://github.com/mattfenwick
[@MatthewHinton56]: https://github.com/MatthewHinton56
[@mengdie-song]: https://github.com/mengdie-song
[@Mmduh-483]: https://github.com/Mmduh-483
[@monotosh-avi]: https://github.com/monotosh-avi
[@moshe010]: https://github.com/moshe010
[@qiyueyao]: https://github.com/qiyueyao
[@reachjainrahul]: https://github.com/reachjainrahul
[@ruicao93]: https://github.com/ruicao93
[@siddhant94]: https://github.com/siddhant94
[@srikartati]: https://github.com/srikartati
[@suwang48404]: https://github.com/suwang48404
[@tnqn]: https://github.com/tnqn
[@weiqiangt]: https://github.com/weiqiangt
[@wenyingd]: https://github.com/wenyingd
[@yktsubo]: https://github.com/yktsubo
[@ZhangYW18]: https://github.com/ZhangYW18
[@zyiou]: https://github.com/zyiou
