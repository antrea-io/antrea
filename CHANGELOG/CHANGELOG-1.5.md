# Changelog 1.5

## 1.5.1 - 2022-03-07

### Changed

- Use iptables-wrapper in Antrea container. Now antrea-agent can work with distros that lack the iptables kernel module of "legacy" mode (ip_tables). ([#3308](https://github.com/antrea-io/antrea/pull/3308), [@antoninbas])
- Reduce permissions of Antrea ServiceAccount for updating annotations. ([#3408](https://github.com/antrea-io/antrea/pull/3408), [@tnqn])

### Fixed

- Fix NodePort/LoadBalancer Service cannot be accessed when externalTrafficPolicy changed from Cluster to Local with proxyAll enabled. ([#3380](https://github.com/antrea-io/antrea/pull/3380), [@hongliangl])
- Fix initial egress connections from Pods may go out with node IP rather than Egress IP. ([#3378](https://github.com/antrea-io/antrea/pull/3378), [@tnqn])
- Fix NodePort Service access when an Egress selects the same Pod as the NodePort Service. ([#3397](https://github.com/antrea-io/antrea/pull/3397), [@hongliangl])
- Fix ipBlock referenced in nested ClusterGroup not processed correctly. ([#3405](https://github.com/antrea-io/antrea/pull/3405), [@Dyanngg])

## 1.5.0 - 2022-01-21

### Added

- Add Antrea Multi-cluster feature which allows users to export and import Services and Endpoints across multiple clusters within a ClusterSet, and enables inter-cluster Service communication in the ClusterSet. ([#3199](https://github.com/antrea-io/antrea/pull/3199), [@luolanzone] [@aravindakidambi] [@bangqipropel] [@hjiajing] [@Dyanngg] [@suwang48404] [@abhiraut]) [Alpha]
  * Refer to [Antrea Multi-cluster Installation] to get started
  * Refer to [Antrea Multi-cluster Architecture] for more information regarding the implementation
- Add support for multicast that allows forwarding multicast traffic within the cluster network (i.e., between Pods) and between the external network and the cluster network. ([#2652](https://github.com/antrea-io/antrea/pull/2652) [#3142](https://github.com/antrea-io/antrea/pull/3142) [#2835](https://github.com/antrea-io/antrea/pull/2835) [#3171](https://github.com/antrea-io/antrea/pull/3171) [#2986](https://github.com/antrea-io/antrea/pull/2986), [@wenyingd] [@ceclinux] [@XinShuYang]) [Alpha - Feature Gate: `Multicast`]
  * In this release the feature is only supported on Linux Nodes for IPv4 traffic in `noEncap` mode
- Add support for IPPool and IP annotations on Pod and PodTemplate of Deployment and StatefulSet in AntreaIPAM mode. ([#3093](https://github.com/antrea-io/antrea/pull/3093) [#3042](https://github.com/antrea-io/antrea/pull/3042) [#3141](https://github.com/antrea-io/antrea/pull/3141) [#3164](https://github.com/antrea-io/antrea/pull/3164) [#3146](https://github.com/antrea-io/antrea/pull/3146), [@gran-vmv] [@annakhm])
  * IPPool annotation on Pod has a higher priority than the IPPool annotation on Namespace
  * A StatefulSet Pod's IP will be kept after Pod restarts when the IP is allocated from IPPool
  * Refer to [Antrea IPAM Capabilities] for more information
- Add support for SR-IOV secondary network. Antrea can now create secondary network interfaces for Pods using SR-IOV VFs on bare metal Nodes. ([#2651](https://github.com/antrea-io/antrea/pull/2651), [@arunvelayutham]) [Alpha - Feature Gate: `SecondaryNetwork`]
- Add support for allocating external IPs for Services of type LoadBalancer from an ExternalIPPool. ([#3147](https://github.com/antrea-io/antrea/pull/3147) [@Shengkai2000]) [Alpha - Feature Gate: `ServiceExternalIP`]
- Add support for antctl in the flow aggregator Pod. ([#2878](https://github.com/antrea-io/antrea/pull/2878), [@yanjunz97])
  * Support `antctl log-level` for changing log verbosity level
  * Support `antctl get flowrecords [-o json]` for dumping flow records
  * Support `antctl get recordmetrics` for dumping flow records metrics
- Add support for the "Pass" action in Antrea-native policies to skip evaluation of further Antrea-native policy rules and delegate evaluation to Kubernetes NetworkPolicy. ([#2964](https://github.com/antrea-io/antrea/pull/2964), [@Dyanngg])
- Add user documentation for using Project Antrea with [Fluentd] in order to collect audit logs from each Node. ([#2853](https://github.com/antrea-io/antrea/pull/2853), [@qiyueyao])
- Add user documentation for [deploying Antrea on AKS Engine]. ([#2963](https://github.com/antrea-io/antrea/pull/2963), [@jianjuns])
- Improve [NodePortLocal documentation] to list supported Service types and add information about existing integrations with external Load Balancers. ([#3113](https://github.com/antrea-io/antrea/pull/3113), [@antoninbas])
- Document how to run Antrea e2e tests on an existing K8s cluster ([#3045](https://github.com/antrea-io/antrea/pull/3045), [@xiaoxiaobaba])

### Changed

- Make LoadBalancer IP proxying configurable for AntreaProxy to support scenarios in which it is desirable to send Pod-to-ExternalIP traffic to the external LoadBalancer. ([#3130](https://github.com/antrea-io/antrea/pull/3130), [@antoninbas])
- Add `startTime` to the Traceflow Status to avoid issues caused by clock skew. ([#2952](https://github.com/antrea-io/antrea/pull/2952), [@antoninbas])
- Add `reason` field in antctl traceflow command output. ([#3175](https://github.com/antrea-io/antrea/pull/3175), [@Jexf])
- Validate serviceCIDR configuration only if AntreaProxy is disabled. ([#2936](https://github.com/antrea-io/antrea/pull/2936), [@wenyingd])
- Improve configuration parameter validation for NodeIPAM. ([#3009](https://github.com/antrea-io/antrea/pull/3009), [@tnqn])
- More comprehensive validation for Antrea-native policies. ([#3104](https://github.com/antrea-io/antrea/pull/3104) [#3109](https://github.com/antrea-io/antrea/pull/3109), [@GraysonWu] [@tnqn])
- Update Antrea Octant plugin to support Octant 0.24 and to use the Dashboard client to perform CRUD operations on Antrea CRDs. ([#2951](https://github.com/antrea-io/antrea/pull/2951), [@antoninbas])
- Omit hostNetwork Pods when computing members of ClusterGroup and AddressGroup. ([#3080](https://github.com/antrea-io/antrea/pull/3080), [@Dyanngg])
- Support for using an env parameter `ALLOW_NO_ENCAP_WITHOUT_ANTREA_PROXY` to allow running Antrea in noEncap mode without AntreaProxy. ([#3116](https://github.com/antrea-io/antrea/pull/3116), [@Jexf] [@WenzelZ])
- Move throughput calculation for network flow visibility from logstash to flow-aggregator. ([#2692](https://github.com/antrea-io/antrea/pull/2692), [@heanlan])
- Add Go version information to full version string for Antrea binaries. ([#3182](https://github.com/antrea-io/antrea/pull/3182), [@antoninbas])
- Improve kind-setup.sh script and Kind documentation. ([#2937](https://github.com/antrea-io/antrea/pull/2937), [@antoninbas])
- Enable Go benchmark tests in CI. ([#3004](https://github.com/antrea-io/antrea/pull/3004), [@wenqiq])
- Upgrade Windows OVS version to 2.15.2 to pick up some recent patches. ([#2996](https://github.com/antrea-io/antrea/pull/2996), [@lzhecheng]) [Windows]
- Remove HNSEndpoint only if infra container fails to create. ([#2976](https://github.com/antrea-io/antrea/pull/2976), [@lzhecheng]) [Windows]
- Use OVS Port externalIDs instead of HNSEndpoint to cache the externalIDS when using containerd as the runtime on Windows. ([#2931](https://github.com/antrea-io/antrea/pull/2931), [@wenyingd]) [Windows]
- Reduce network downtime when starting antrea-agent on Windows Node by using Windows management virtual network adapter as OVS internal port. ([#3067](https://github.com/antrea-io/antrea/pull/3067), [@wenyingd]) [Windows]

### Fixed

- Fix error handling of the "Reject" action of Antrea-native policies when determining if the packet belongs to Service traffic. ([#3010](https://github.com/antrea-io/antrea/pull/3010), [@GraysonWu])
- Make the "Reject" action of Antrea-native policies work in AntreaIPAM mode. ([#3003](https://github.com/antrea-io/antrea/pull/3003), [@GraysonWu])
- Set ClusterGroup with child groups to `groupMembersComputed` after all its child groups are created and processed. ([#3030](https://github.com/antrea-io/antrea/pull/3030), [@Dyanngg])
- Fix status report of Antrea-native policies with multiple rules that have different AppliedTo. ([#3074](https://github.com/antrea-io/antrea/pull/3074), [@tnqn])
- Fix typos and improve the example YAML in antrea-network-policy doc. ([#3079](https://github.com/antrea-io/antrea/pull/3079), [#3092](https://github.com/antrea-io/antrea/pull/3092), [#3108](https://github.com/antrea-io/antrea/pull/3108) [@antoninbas] [@Jexf] [@tnqn])
- Fix duplicated attempts to delete unreferenced AddressGroups when deleting Antrea-native policies. ([#3136](https://github.com/antrea-io/antrea/pull/3136), [@Jexf])
- Add retry to update NetworkPolicy status to avoid error logs. ([#3134](https://github.com/antrea-io/antrea/pull/3134), [@Jexf])
- Fix NetworkPolicy resources dump for Agent's supportbundle. ([#3083](https://github.com/antrea-io/antrea/pull/3083), [@antoninbas])
- Use go 1.17 to build release assets. ([#3007](https://github.com/antrea-io/antrea/pull/3007), [@antoninbas])
- Restore the gateway route automatically configured by kernel when configuring IP address if it is missing. ([#2835](https://github.com/antrea-io/antrea/pull/2835), [@antoninbas])
- Fix incorrect parameter used to check if a container is the infra container, which caused errors when reattaching HNS Endpoint. ([#3089](https://github.com/antrea-io/antrea/pull/3089), [@XinShuYang]) [Windows]
- Fix gateway interface MTU configuration error on Windows. ([#3043](https://github.com/antrea-io/antrea/pull/3043), @[lzhecheng]) [Windows]
- Fix initialization error of antrea-agent on Windows by specifying hostname explicitly in VMSwitch commands. ([#3169](https://github.com/antrea-io/antrea/pull/3169), [@XinShuYang]) [Windows]


[Antrea Multi-cluster Installation]: https://github.com/antrea-io/antrea/blob/v1.5.0/docs/multicluster/getting-started.md
[Antrea Multi-cluster Architecture]: https://github.com/antrea-io/antrea/blob/v1.5.0/docs/multicluster/architecture.md
[Antrea IPAM Capabilities]: https://github.com/antrea-io/antrea/blob/v1.5.0/docs/antrea-ipam.md
[Fluentd]: https://github.com/fluent/fluentd-kubernetes-daemonset
[deploying Antrea on AKS Engine]: https://github.com/antrea-io/antrea/blob/v1.5.0/docs/aks-installation.md#deploy-antrea-to-an-aks-engine-cluster
[NodePortLocal documentation]: https://github.com/antrea-io/antrea/blob/v1.5.0/docs/node-port-local.md

[@abhiraut]: https://github.com/abhiraut
[@annakhm]: https://github.com/annakhm
[@antoninbas]: https://github.com/antoninbas
[@aravindakidambi]: https://github.com/aravindakidambi
[@arunvelayutham]: https://github.com/arunvelayutham
[@bangqipropel]: https://github.com/bangqipropel
[@ceclinux]: https://github.com/ceclinux
[@Dyanngg]: https://github.com/Dyanngg
[@gran-vmv]: https://github.com/gran-vmv
[@GraysonWu]: https://github.com/GraysonWu
[@heanlan]: https://github.com/heanlan
[@hjiajing]: https://github.com/hjiajing
[@hongliangl]: https://github.com/hongliangl
[@Jexf]: https://github.com/Jexf
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@lzhecheng]: https://github.com/lzhecheng
[@qiyueyao]: https://github.com/qiyueyao
[@Shengkai2000]: https://github.com/Shengkai2000
[@suwang48404]: https://github.com/suwang48404
[@tnqn]: https://github.com/tnqn
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
[@WenzelZ]: https://github.com/WenzelZ
[@xiaoxiaobaba]: https://github.com/xiaoxiaobaba
[@XinShuYang]: https://github.com/XinShuYang
[@yanjunz97]: https://github.com/yanjunz97
