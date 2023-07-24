# Changelog 1.13

## 1.13.0 - 2023-07-28

### Added

- Add AdminNetworkPolicy support in Antrea to align with K8s NetworkPolicy API, and document the introduction and usage. ([#5170](https://github.com/antrea-io/antrea/pull/5170) [#5270](https://github.com/antrea-io/antrea/pull/5270), [@Dyanngg])
- Support DSR mode for Service's external addresses in AntreaProxy, including LoadBalancerIPs and ExternalIPs. ([#5202](https://github.com/antrea-io/antrea/pull/5202) [#5251](https://github.com/antrea-io/antrea/pull/5251), [@tnqn])
- Containerize Windows userspace OVS processes and run them in a container of the Antrea Agent Pod to align with the Linux design. ([#4936](https://github.com/antrea-io/antrea/pull/4936) [#5052](https://github.com/antrea-io/antrea/pull/5052) [#5303](https://github.com/antrea-io/antrea/pull/5303), [@rajnkamr] [@Atish-iaf])
- Add a new option `ContainerRuntime` to allow users to configure the container runtime while using the script `Prepare-Node.ps1` on K8s Windows Node. ([#5071](https://github.com/antrea-io/antrea/pull/5071), [@NamanAg30])
- Add support for TLS, HTTP, and HTTPS protocols for FlowAggregator to connect to the ClickHouse DB, and allow users to specify the CA certificate for TLS and HTTPS. ([#5171](https://github.com/antrea-io/antrea/pull/5171), [@yuntanghsu])
- Enhance Antrea L7 NetworkPolicy to support the TLS protocol. ([#4932](https://github.com/antrea-io/antrea/pull/4932), [@hongliangl])
- Add command `antctl upgrade api-storage` in antctl to support resource storage version migration for Antrea CRDs. ([#5198](https://github.com/antrea-io/antrea/pull/5198), [@hongliangl])
- Add support for removing the associated stale conntrack entries when UDP Endpoints are removed, with which UDP requests can be redirected to other Endpoints immediately rather than waiting for the conntrack entries to expire. ([#5112](https://github.com/antrea-io/antrea/pull/5112), [@hongliangl])
- Add Egress information to flow records for Pod-to-external flows in FlowExporter. ([#5088](https://github.com/antrea-io/antrea/pull/5088), [@dreamtalen])
- Increase accuracy of Pod information in the flow records by adding a Pod store in FlowExporter and FlowAggregator for them to fetch the Pod information. ([#5185](https://github.com/antrea-io/antrea/pull/5185), [@yuntanghsu])
- Add support for Service annotation `service.kubernetes.io/topology-mode` in AntreaProxy since the old `service.kubernetes.io/topology-aware-hints` annotation has been deprecated in Kubernetes 1.27. ([#5241](https://github.com/antrea-io/antrea/pull/5241), [@mengdie-song])
- Support the well-known label `service.kubernetes.io/service-proxy-name` in AntreaProxy to align with KEP 2447. ([#4973](https://github.com/antrea-io/antrea/pull/4973), [@hongliangl])
- Add a new Prometheus metric to represent the number of packets dropped by OVS meter. ([#5165](https://github.com/antrea-io/antrea/pull/5165), [@mengdie-song])
- Add support for the `sort-by` flag in more `antctl get` commands for more fields. ([#4346](https://github.com/antrea-io/antrea/pull/4346), [@jainpulkit22])
- Add the `kubeAPIServerOverride` option to allow users to override the kube-apiserver address for antrea-controller. ([#5056](https://github.com/antrea-io/antrea/pull/5056), [@tnqn])
- Add documentation for deploying Antrea with a Rancher cluster. ([#4733](https://github.com/antrea-io/antrea/pull/4733), [@jainpulkit22])

### Changed

- Multiple APIs are promoted from alpha to beta. The alpha versions are deprecated and will be removed in a future release.
  - Promote ClusterGroup and Group to v1beta1. ([#5181](https://github.com/antrea-io/antrea/pull/5181), [@GraysonWu])
  - Promote ExternalIPPool API to v1beta1. ([#5176](https://github.com/antrea-io/antrea/pull/5176), [@hongliangl])
  - Promote Tier API to v1beta1. ([#5172](https://github.com/antrea-io/antrea/pull/5172), [@GraysonWu])
  - Promote Egress API to v1beta1. ([#5180](https://github.com/antrea-io/antrea/pull/5180), [@wenqiq])
  - Promote AntreaClusterNetworkPolicy and AntreaNativeNetworkPolicy API to v1beta1. ([#5186](https://github.com/antrea-io/antrea/pull/5186), [@GraysonWu])
  - Promote Traceflow API to v1beta1. ([#5108](https://github.com/antrea-io/antrea/pull/5108), [@luolanzone])
  - Add a validation schema for the matchLabels field of the ExternalIPPool CRD. ([#5284](https://github.com/antrea-io/antrea/pull/5284), [@tnqn])
- Enable `proxyAll` by default for AntreaProxy on Windows because the kube-proxy userspace datapath has been removed since Kubernetes 1.26. ([#4980](https://github.com/antrea-io/antrea/pull/4980), [@XinShuYang])
- Change default port range of NodePortLocal on Windows to `40000-41000` to avoid conflicts with the Windows default dynamic port range. ([#5107](https://github.com/antrea-io/antrea/pull/5107), [@XinShuYang])
- Remove the ClusterClaim CRD and upgrade the ClusterSet CRD version to v1alpha2, and enhance the ClusterSet controller to support ClusterSet version upgrade. ([#5001](https://github.com/antrea-io/antrea/pull/5001) [#5250](https://github.com/antrea-io/antrea/pull/5250), [@luolanzone])
- Increase the controller QPS setting in Multi-cluster Controller to improve multi-cluster resource export performance, and increase the LabelIdentity controller worker count to improve its performance. ([#5099](https://github.com/antrea-io/antrea/pull/5099), [@GraysonWu])
- Improve direct connections to the Antrea apiserver in antctl with accessibility to Node ExternalIP and add a new `--insecure` option to support both secure and insecure connections. ([#5135](https://github.com/antrea-io/antrea/pull/5135), [@antoninbas])
- Add two new fields to audit logs, including the "direction" of the NP rule (Ingress or Egress) and the reference of the Pod (`<Namespace>/<Name>`) to which the NP rule is applied. ([#5101](https://github.com/antrea-io/antrea/pull/5101), [@antoninbas])
- Add a FlowExporter configuration toggle to antrea-agent for users to explicitly enable/disable flow exports. ([#5021](https://github.com/antrea-io/antrea/pull/5021), [@yuntanghsu])
- Add OpenAPI schema for the AntreaAgentInfo and AntreaControllerInfo CRDs. ([#5206](https://github.com/antrea-io/antrea/pull/5206), [@ceclinux])
- Update short-name for AntreaNetworkPolicy to ANNP. ([#5081](https://github.com/antrea-io/antrea/pull/5081), [@qiyueyao])
- Use syscall to query or operate network adapters on Windows to reduce operation delay. ([#4898](https://github.com/antrea-io/antrea/pull/4898), [@wenyingd] [@qiyueyao])
- Update out-of-date audit logs docs for new log fields. ([#5199](https://github.com/antrea-io/antrea/pull/5199), [@cr7258])
- Switched to structured logging and change verbosity of potentially misleading Info log in the Antrea NetworkPolicy reconciler. ([#5048](https://github.com/antrea-io/antrea/pull/5048), [@antoninbas])
- Revert a change to serve the v1alpha2 version of the ClusterGroup CRD again for the consistent API promotion plan. ([#5277](https://github.com/antrea-io/antrea/pull/5277), [@GraysonWu])
- Upgrade Open vSwitch to version 2.17.7. ([#5225](https://github.com/antrea-io/antrea/pull/5225), [@antoninbas])
- Upgrade Windows Open vSwitch to version 3.0.5. ([#5120](https://github.com/antrea-io/antrea/pull/5120), [@wenyingd])
- Upgrade ClickHouse go client to v2. ([#5020](https://github.com/antrea-io/antrea/pull/5020), [@heanlan])
- Remove Antrea Octant plugin. ([#5049](https://github.com/antrea-io/antrea/pull/5049), [@antoninbas])

### Fixed

- Bump up `libOpenflow` and `ofnet` library versions to fix a PacketIn2 response parse error. ([#5154](https://github.com/antrea-io/antrea/pull/5154), [@wenyingd])
- Bump up `libOpenflow` library to v0.12.1 to fix an antrea-agent crash issue when marshaling the IGMPv3 query packet. ([#5320](https://github.com/antrea-io/antrea/pull/5320), [@ceclinux])
- Use OpenFlow group for Network Policy logging to avoid packet drops when massive connections hit the policy. ([#5061](https://github.com/antrea-io/antrea/pull/5061), [@wenyingd])
- Fix an issue in Antrea-native policies with FQDN rules where TCP src port is unset on the TCP DNS response flow. ([#5078](https://github.com/antrea-io/antrea/pull/5078), [@wenyingd])
- Fix status report when no-op changes are applied to Antrea-native policies. ([#5096](https://github.com/antrea-io/antrea/pull/5096), [@tnqn])
- Ensure the Egress IP is always correctly advertised to the network, including when the userspace ARP responder is not running or when the Egress IP is temporarily claimed by multiple Nodes. ([#5127](https://github.com/antrea-io/antrea/pull/5127), [@tnqn])
- Fix incorrect FlowMod message passing in the modifyFlows function of the OpenFlow client to avoid unexpected flow error. ([#5125](https://github.com/antrea-io/antrea/pull/5125), [@Dyanngg])
- Fix a bug that antrea-agent fails to delete the ExternalNode CR when it runs on a RHEL 8.4 VM on Azure cloud. ([#5191](https://github.com/antrea-io/antrea/pull/5191), [@wenyingd])
- Fix IPv4 groups containing IPv6 endpoints mistakenly in dual-stack clusters in AntreaProxy implementation. ([#5194](https://github.com/antrea-io/antrea/pull/5194), [@tnqn])
- Fix RBAC permissions for the Antctl ClusterRole to ensure the ClusterRole definition is up-to-date. ([#5166](https://github.com/antrea-io/antrea/pull/5166), [@antoninbas])
- Fix some code examples in a few documentations. ([#5182](https://github.com/antrea-io/antrea/pull/5182), [@tnqn])
- Add apiVersion and kind for unstructured objects in `antctl mc` codes to fix a rollback failure. ([#5138](https://github.com/antrea-io/antrea/pull/5138), [@luolanzone])
- Fix a ClusterClaim webhook bug that can lead to ClusterClaim deletion failures. ([#5075](https://github.com/antrea-io/antrea/pull/5075), [@luolanzone])
- Revise "antctl mc deploy" command to fix a Multi-cluster deployment failure on EKS clusters. ([#5080](https://github.com/antrea-io/antrea/pull/5080), [@luolanzone])

[@Atish-iaf]: https://github.com/Atish-iaf
[@cr7258]: https://github.com/cr7258
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@NamanAg30]: https://github.com/NamanAg30
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@ceclinux]: https://github.com/ceclinux
[@dreamtalen]: https://github.com/dreamtalen
[@heanlan]: https://github.com/heanlan
[@hongliangl]: https://github.com/hongliangl
[@jainpulkit22]: https://github.com/jainpulkit22
[@luolanzone]: https://github.com/luolanzone
[@mengdie-song]: https://github.com/mengdie-song
[@qiyueyao]: https://github.com/qiyueyao
[@rajnkamr]: https://github.com/rajnkamr
[@tnqn]: https://github.com/tnqn
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
[@yuntanghsu]: https://github.com/yuntanghsu