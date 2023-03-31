# Changelog 1.8

## 1.8.1 - 2023-03-31

### Changed

- Add OVS connection check to Agent's liveness probes for self-healing on OVS disconnection. ([#4126](https://github.com/antrea-io/antrea/pull/4126), [@tnqn])
- Upgrade Antrea base image to ubuntu:22.04. ([#4459](https://github.com/antrea-io/antrea/pull/4459) [#4499](https://github.com/antrea-io/antrea/pull/4499), [@antoninbas])

### Fixed

- Ensure NO_FLOOD is always set for IPsec tunnel ports and TrafficControl ports. ([#4419](https://github.com/antrea-io/antrea/pull/4419) [#4654](https://github.com/antrea-io/antrea/pull/4654) [#4674](https://github.com/antrea-io/antrea/pull/4674), [@xliuxu] [@tnqn])
- Fix Service routes being deleted on Agent startup on Windows. ([#4470](https://github.com/antrea-io/antrea/pull/4470), [@hongliangl])
- Fix route deletion for Service ClusterIP and LoadBalancerIP when AntreaProxy is enabled. ([#4711](https://github.com/antrea-io/antrea/pull/4711), [@tnqn])
- Add a periodic job to rejoin dead Nodes to fix Egress not working properly after long network downtime. ([#4491](https://github.com/antrea-io/antrea/pull/4491), [@tnqn])
- Fix Agent crash in dual-stack clusters when any Node is not configured with an IP address for each address family. ([#4480](https://github.com/antrea-io/antrea/pull/4480), [@hongliangl])
- Fix potential deadlocks and memory leaks of memberlist maintenance in large-scale clusters. ([#4469](https://github.com/antrea-io/antrea/pull/4469), [@wenyingd])
- Fix connectivity issues caused by MAC address changes with systemd v242 and later. ([#4428](https://github.com/antrea-io/antrea/pull/4428), [@wenyingd])
- Fix OpenFlow rules not being updated when Multi-cluster Gateway updates. ([#4388](https://github.com/antrea-io/antrea/pull/4388), [@luolanzone])
- Set no-flood config with ports for TrafficControl after Agent restarting. ([#4318](https://github.com/antrea-io/antrea/pull/4318), [@hongliangl])
- Fix packet resubmission issue when AntreaProxy is enabled and AntreaPolicy is disable. ([#4261](https://github.com/antrea-io/antrea/pull/4261), [@GraysonWu])
- Fix data race when Multi-cluster controller reconciles ServiceExports concurrently. ([#4305](https://github.com/antrea-io/antrea/pull/4305), [@Dyanngg])
- Fix multicast group not removed from cache when it is uninstalled. ([#4176](https://github.com/antrea-io/antrea/pull/4176), [@wenyingd])
- Fix nil pointer error when there is no ClusterSet found during MemberClusterAnnounce validation. ([#4154](https://github.com/antrea-io/antrea/pull/4154), [@luolanzone])
- Remove redundant Openflow messages when syncing an updated group to OVS. ([#4160](https://github.com/antrea-io/antrea/pull/4160), [@hongliangl])

## 1.8.0 - 2022-08-18

### Added

- Add ExternalNode feature which enables Antrea to manage security policies for non-Kubernetes Nodes (like virtual machines or bare-metal servers). ([#4110](https://github.com/antrea-io/antrea/pull/4110), [@wenyingd] [@mengdie-song] [@Anandkumar26])
  * It introduces the ExternalNode CRD; each resource of this kind represents a virtual machine or bare-metal server and supports specifying which network interfaces on the external Node are expected to be protected with Antrea-native policies.
  * An ExternalEntity resource will be created for each network interface specified in the ExternalNode resource. Antrea-native policies are applied to an external Node by using the ExternalEntity selector.
  * Refer to [this document](https://github.com/antrea-io/antrea/blob/release-1.8/docs/external-node.md) for more information about this feature.
- Add the following capabilities to Antrea-native policies:
  * Add Audit Logging support for K8s Networkpolicy. ([#4047](https://github.com/antrea-io/antrea/pull/4047), [@qiyueyao])
  * Support applying Antrea ClusterNetworkPolicy to NodePort Services for securing ingress traffic. ([#3997](https://github.com/antrea-io/antrea/pull/3997), [@GraysonWu])
  * Introduce the Group CRD to logically group different network endpoints and reference them together in Antrea NetworkPolicy. ([#2438](https://github.com/antrea-io/antrea/pull/2438), [@qiyueyao] [@abhiraut])
- Release new Antrea Helm chart version for each Antrea release. ([#3935](https://github.com/antrea-io/antrea/pull/3935) [#3952](https://github.com/antrea-io/antrea/pull/3952), [@antoninbas] [@yanjunz97])
  * Refer to [this document](https://github.com/antrea-io/antrea/blob/release-1.8/docs/helm.md) for Helm installation method. ([#3989](https://github.com/antrea-io/antrea/pull/3989), [@antoninbas])
- Support TopologyAwareHints in AntreaProxy. ([#3515](https://github.com/antrea-io/antrea/pull/3515), [@hongliangl])
- Add encap mode support for the Multicast feature. ([#3947](https://github.com/antrea-io/antrea/pull/3947), [@wenyingd])
- Support configurable Geneve, VXLAN, or STT port number for encap mode. ([#4065](https://github.com/antrea-io/antrea/pull/4065), [@Jexf])
- Add Status field to the IPPool CRD: it is used to report usage information for the pool (total number of IPs in the pool and number of IPs that are currently assigned). ([#3072](https://github.com/antrea-io/antrea/pull/3072) [#4088](https://github.com/antrea-io/antrea/pull/4088), [@ksamoray] [@tnqn])
- Support updating configuration at runtime for flow-aggregator via antctl or by updating the ConfigMap. ([#3642](https://github.com/antrea-io/antrea/pull/3642), [@yuntanghsu])
- Add antctl commands to set up and delete Multi-cluster ClusterSet. ([#3992](https://github.com/antrea-io/antrea/pull/3992), [@hjiajing])
- Add [documentation](https://github.com/antrea-io/antrea/blob/release-1.8/docs/multicluster/antctl.md) to set up Multi-cluster ClusterSet with antctl. ([#4096](https://github.com/antrea-io/antrea/pull/4096), [@jianjuns])

### Changed

- Antrea now uses OpenFlow 1.5 to program OVS. ([#3770](https://github.com/antrea-io/antrea/pull/3770), [@wenyingd] [@ashish-varma])
- Rename Windows script Start.ps1 to Start-AntreaAgent.ps1, and rename Stop.ps1 to Stop-AntreaAgent.ps1. ([#3904](https://github.com/antrea-io/antrea/pull/3904), [@wenyingd])
- Unify NodePortLocal behavior across Linux and Windows. Linux agents now support allocating different Node ports for different protocols even when the Pod port number is the same. ([#3936](https://github.com/antrea-io/antrea/pull/3936), [@XinShuYang])
- Antrea IPAM now uses the name of the uplink interface to name the host internal port, and the uplink interface will be renamed with a `~` suffix, e.g. `eth0~`. ([#3938](https://github.com/antrea-io/antrea/pull/3938), [@gran-vmv])
- Send Neighbor Advertisement messages after creating Pods in an IPv6 cluster. ([#3998](https://github.com/antrea-io/antrea/pull/3998), [@gran-vmv])
- Add an output formatter "raw" to better display multi-line string responses for antctl. ([#3589](https://github.com/antrea-io/antrea/pull/3589), [@Atish-iaf])
- Add new ports to network requirement doc. ([#4063](https://github.com/antrea-io/antrea/pull/4063), [@luolanzone])
- Windows OVS installation script now installs required SSL library if missing. ([#4029](https://github.com/antrea-io/antrea/pull/4029), [@XinShuYang])
- Upgrade whereabouts CNI to v0.5.4 and provide required pluginArgs when invoking the CNI binary. ([#3987](https://github.com/antrea-io/antrea/pull/3987), [@arunvelayutham])
- Remove Grafana flow collector files in the Antrea repo (as they were moved to the Theia repo). ([#4048](https://github.com/antrea-io/antrea/pull/4048), [@dreamtalen])
- Make the following changes to the Multi-cluster feature:
  * Add columns of kubectl outputs for Multi-cluster custom resources. ([#3923](https://github.com/antrea-io/antrea/pull/3923), [@jianjuns])
  * Use hostNetwork for Multi-cluster controller. ([#3965](https://github.com/antrea-io/antrea/pull/3965), [@luolanzone])
  * Update ClusterClaim CRD to v1alpha2. ([#3755](https://github.com/antrea-io/antrea/pull/3755), [@bangqipropel])
  * Update GatewayIPPrecedence to support the "external/internal" options. ([#3930](https://github.com/antrea-io/antrea/pull/3930), [@luolanzone])
  * Disable metrics API and change the health binding address port to 8080. ([#4101](https://github.com/antrea-io/antrea/pull/4101), [@luolanzone])
  * Improve CRD validation. ([#4062](https://github.com/antrea-io/antrea/pull/4062) [#4090](https://github.com/antrea-io/antrea/pull/4090) [#4043](https://github.com/antrea-io/antrea/pull/4043), [@luolanzone])
  * Auto create MemberClusterAnnounce and update ClusterSet in leader cluster for each member cluster. ([#3956](https://github.com/antrea-io/antrea/pull/3956) [#4054](https://github.com/antrea-io/antrea/pull/4054) [#4026](https://github.com/antrea-io/antrea/pull/4026), [@hjiajing] [@luolanzone])
  * Add Multi-cluster Gateway descriptions in the Multi-cluster architecture document. ([#3638](https://github.com/antrea-io/antrea/pull/3638) [#3899](https://github.com/antrea-io/antrea/pull/3899), [@luolanzone] [@jianjuns])

### Fixed

- Fix reconnection issue between Agent and OVS. ([#4091](https://github.com/antrea-io/antrea/pull/4091), [@wenyingd])
- Fix the wrong DNAT IP used by AntreaProxy for serving NodePort traffic on Windows Nodes. ([#4103](https://github.com/antrea-io/antrea/pull/4103), [@XinShuYang])
- Fix Antrea Octant plugin build. ([#4107](https://github.com/antrea-io/antrea/pull/4107), [@antoninbas])
- Fix Pod-to-external traffic on EKS in policyOnly mode. ([#3975](https://github.com/antrea-io/antrea/pull/3975), [@antoninbas])
- Fix problems caused by Node restart on EKS in policyOnly mode. ([#4012](https://github.com/antrea-io/antrea/pull/4012) [#4042](https://github.com/antrea-io/antrea/pull/4042), [@antoninbas])
- Fix race conditions in NetworkPolicyController. ([#4028](https://github.com/antrea-io/antrea/pull/4028), [@tnqn])
- Fix FlowExporter memory bloat when export process is dead. ([#3994](https://github.com/antrea-io/antrea/pull/3994), [@wsquan171])
- Fix socket leak in an IPv6 cluster. ([#4104](https://github.com/antrea-io/antrea/pull/4104), [@wenyingd])
- Fix ClickHouse client race during batch commit. ([#4071](https://github.com/antrea-io/antrea/pull/4071), [@wsquan171])
- Retry when retrieval of PodCIDRs fails to avoid Agent crash due to the delay in allocating PodCIDRs for the Node. ([#3950](https://github.com/antrea-io/antrea/pull/3950), [@ksamoray])
- Fix nil pointer issue when ClusterSet is deleted in leader cluster. ([#3915](https://github.com/antrea-io/antrea/pull/3915), [@luolanzone])
- Clean up ResourceExport if the exported Service has no available Endpoints. ([#4056](https://github.com/antrea-io/antrea/pull/4056), [@luolanzone])


[@Anandkumar26]: https://github.com/Anandkumar26
[@Atish-iaf]: https://github.com/Atish-iaf
[@GraysonWu]: https://github.com/GraysonWu
[@Jexf]: https://github.com/Jexf
[@KMAnju-2021]: https://github.com/KMAnju-2021
[@XinShuYang]: https://github.com/XinShuYang
[@abhiraut]: https://github.com/abhiraut
[@antoninbas]: https://github.com/antoninbas
[@antrea-bot]: https://github.com/antrea-bot
[@arunvelayutham]: https://github.com/arunvelayutham
[@ashish-varma]: https://github.com/ashish-varma
[@bangqipropel]: https://github.com/bangqipropel
[@ceclinux]: https://github.com/ceclinux
[@dependabot]: https://github.com/dependabot
[@dreamtalen]: https://github.com/dreamtalen
[@Dyanngg]: https://github.com/Dyanngg
[@gran-vmv]: https://github.com/gran-vmv
[@heshengyuan1311]: https://github.com/heshengyuan1311
[@hjiajing]: https://github.com/hjiajing
[@hongliangl]: https://github.com/hongliangl
[@jainpulkit22]: https://github.com/jainpulkit22
[@jianjuns]: https://github.com/jianjuns
[@ksamoray]: https://github.com/ksamoray
[@liu4480]: https://github.com/liu4480
[@luolanzone]: https://github.com/luolanzone
[@mengdie-song]: https://github.com/mengdie-song
[@qiyueyao]: https://github.com/qiyueyao
[@tnqn]: https://github.com/tnqn
[@wenyingd]: https://github.com/wenyingd
[@wsquan171]: https://github.com/wsquan171
[@xliuxu]: https://github.com/xliuxu
[@yanjunz97]: https://github.com/yanjunz97
[@yuntanghsu]: https://github.com/yuntanghsu
