# Changelog 2.5

## 2.5.1 - 2026-01-06

### Fixed

- Add init container to apply Antrea-specific sysctl configuration. ([#7651](https://github.com/antrea-io/antrea/pull/7651), [@hongliangl])
- Fix antrea-agent crashing due to a nil pointer when AntreaProxy is not enabled. ([#7636](https://github.com/antrea-io/antrea/pull/7636), [@hongliangl])
- Generate self-signed certificates only when required to prevent conflicts in multi-replica flow-aggregator deployments. ([#7559](https://github.com/antrea-io/antrea/pull/7559), [@andrew-su])
- Update module github.com/containernetworking/plugins to v1.9.0 to address CVEs. ([#7624](https://github.com/antrea-io/antrea/pull/7624), [@renovatebot])
- Lock feature gates `TopologyAwareHints` and `ServiceTrafficDistribution` to true. ([#7620](https://github.com/antrea-io/antrea/pull/7620), [@hongliangl])
- Fix handling of self-connections on Egress Nodes in hybrid mode. ([#7611](https://github.com/antrea-io/antrea/pull/7611), [@hongliangl])

## 2.5.0 - 2025-12-03

### Added

- Introduce a new feature gate `NFTablesHostNetworkMode` and an option `hostNetworkMode` to support `nftables` for proxyAll rules installed in the Node's host network by AntreaProxy. ([#7545](https://github.com/antrea-io/antrea/pull/7545), [@hongliangl])
- Add support for Antrea Egress in hybrid mode. ([#7239](https://github.com/antrea-io/antrea/pull/7239), [@hongliangl])
- Add `direction` flag to `antctl packetcapture` command. ([#7195](https://github.com/antrea-io/antrea/pull/7195), [@sratslla])
- Add IPv6 support for PacketCapture feature, including ICMPv6 handling and new CLI filter options. ([#7385](https://github.com/antrea-io/antrea/pull/7385), [@harshgdev])
- Enhance PacketCapture to support matching arbitrary source or destination. ([#7215](https://github.com/antrea-io/antrea/pull/7215), [@harshgdev])
- Enhance PacketCapture to also capture packets at the destination Pod, in addition to the source. ([#7289](https://github.com/antrea-io/antrea/pull/7289), [@harshgdev])
- Add confederation identifier to the `antctl get bgppolicy` command response. ([#7275](https://github.com/antrea-io/antrea/pull/7275), [@Atish-iaf])
- Add member ASNs to the `antctl get bgppolicy` command response. ([#7425](https://github.com/antrea-io/antrea/pull/7425), [@Atish-iaf])
- Add `conntrack_poll_cycle_duration_seconds` metric to track the time taken to poll conntrack and update the connection store. ([#7460](https://github.com/antrea-io/antrea/pull/7460), [@antoninbas])
- Add a `network-policy-delay` flag to `antctl check installation` to configure the maximum policy realization delay. ([#7427](https://github.com/antrea-io/antrea/pull/7427), [@antoninbas])
- Add resource requests for Windows container in Antrea deployment. ([#7254](https://github.com/antrea-io/antrea/pull/7254), [@XinShuYang])
- Accelerate Pod-to-Pod networking in `noEncap` and `hybrid` modes by leveraging nftables `flowtable` to reduce host network stack overhead. If some nftables dependencies are not met, it will fallback to the old behavior. The new behavior can also be disabled by explicitly setting `hostNetworkAcceleration.enable` to false. ([#7324](https://github.com/antrea-io/antrea/pull/7324), [@hongliangl])

### Changed

- Upgrade Go to 1.25. ([#7561](https://github.com/antrea-io/antrea/pull/7561), [@antoninbas])
- Deprecate `L7FlowExporter` feature. ([#7567](https://github.com/antrea-io/antrea/pull/7567), [@luolanzone])
- Increase the minimum supported Kubernetes version to 1.23. ([#7564](https://github.com/antrea-io/antrea/pull/7564), [@antoninbas])
- Add `uniqueMACForSubInterfaces` option to Egress, enabling unique MAC addresses for Egress VLAN interfaces by default. ([#7599](https://github.com/antrea-io/antrea/pull/7599), [@luolanzone])
- Evolve the AntreaProxy framework, introducing a healthz server as an alternative to kube-proxy's, and adding feature `PreferSameTrafficDistribution` support. ([#7371](https://github.com/antrea-io/antrea/pull/7371), [@hongliangl])
- Promote feature gates `TopologyAwareHints` and `ServiceTrafficDistribution` to GA. ([#7503](https://github.com/antrea-io/antrea/pull/7503), [@hongliangl])
- Improve FlowExporter performance by using netlink zone filtering when dumping conntrack flows, reducing CPU and memory usage. ([#7504](https://github.com/antrea-io/antrea/pull/7504), [@antoninbas])
- Prevent WireGuard enablement when the traffic mode is not Encap. ([#7464](https://github.com/antrea-io/antrea/pull/7464), [@luolanzone])
- Add disclaimers to Azure-related documentation and code, as Antrea is no longer tested on Azure. ([#7381](https://github.com/antrea-io/antrea/pull/7381), [@edwardbadboy])
- Migrate dependency update configuration from Dependabot to Renovate. ([#7354](https://github.com/antrea-io/antrea/pull/7354), [@ghadeer-elsalhawy])
- Remove `AntreaProxy` and `NodePortLocal` feature gates from Helm charts and standard manifests. ([#7505](https://github.com/antrea-io/antrea/pull/7505), [@hongliangl])
- Add validation to ensure that `AntreaIPAM` is enabled with `SecondaryNetwork`. ([#7556](https://github.com/antrea-io/antrea/pull/7556), [@luolanzone])
- Periodically sync ip rules managed by Antrea to ensure consistency. ([#7295](https://github.com/antrea-io/antrea/pull/7295), [@hongliangl])
- Use a more robust way to extract the source Node IP from encapsulated IGMP messages for multicast when the traffic mode is Encap. ([#7282](https://github.com/antrea-io/antrea/pull/7282), [@hongliangl])
- Add validation to prevent Antrea Multicast from being enabled in `networkPolicyOnly` mode. ([#7362](https://github.com/antrea-io/antrea/pull/7362), [@wenyingd])
- Unify validation logic for IPPool and ExternalIPPool for more consistent checks and failures. ([#7319](https://github.com/antrea-io/antrea/pull/7319), [@wenqiq])

### Fixed

- Fix overflow issue in network policy priority assigner. ([#7496](https://github.com/antrea-io/antrea/pull/7496), [@Dyanngg])
- Add missing policy UIDs for denied connections in FlowExporter. ([#7388](https://github.com/antrea-io/antrea/pull/7388), [@antoninbas])
- Upgrade `libOpenflow` to handle OpenFlow message overflow. ([#7470](https://github.com/antrea-io/antrea/pull/7470), [@wenyingd])
- Fix ServiceCIDR discovery in the Multi-cluster member controller for Kubernetes versions 1.33 and newer. ([#7291](https://github.com/antrea-io/antrea/pull/7291), [@luolanzone])
- Fix Agent crash issue which is caused by unexpected interface store initialization for FlexibleIPAM uplink internal port. ([#7389](https://github.com/antrea-io/antrea/pull/7389), [@gran-vmv])
- Avoid missing or invalid NetworkPolicy data in FlowExporter records by increasing flow ID reuse delay and filtering old connections. ([#7468](https://github.com/antrea-io/antrea/pull/7468), [@antoninbas])
- Refine Traceflow to correctly handle inter-Node Pod-to-Pod traffic across all traffic modes. ([#7481](https://github.com/antrea-io/antrea/pull/7481), [@hongliangl])
- Fix ACNP applied to NodePort failing to reject traffic when the traffic mode is `noEncap` or `hybrid`. ([#7265](https://github.com/antrea-io/antrea/pull/7265), [@hongliangl])
- Fix a type assertion panic in `GetFlowTableID` function, which affected the `/ovsflows` HTTP handler. ([#7515](https://github.com/antrea-io/antrea/pull/7515), [@antoninbas])
- Handle missing Pod IP and Pod IP changes in NodePortLocal to prevent incorrect datapath rules. ([#7512](https://github.com/antrea-io/antrea/pull/7512), [@antoninbas])
- Exclude Egress VLAN sub-interfaces (`antrea-ext.VLAN`) from NodePort addresses for consistency. ([#7519](https://github.com/antrea-io/antrea/pull/7519), [@antoninbas])
- Improve `initK8sNodeLocalConfig` in Agent initialization by separating Node and PodCIDR polling for better logging, and increase the timeout to 60s. ([#7473](https://github.com/antrea-io/antrea/pull/7473), [@antoninbas])
- Fix panic in Antrea monitor controller caused by unexpected delete event type. ([#7568](https://github.com/antrea-io/antrea/pull/7568), [@luolanzone])
- Clean up stale secondary IPs in IPPool when Node restarts with invalid OVSDB. ([#7511](https://github.com/antrea-io/antrea/pull/7511), [@luolanzone])
- Improve stale IP recycling in AntreaIPAM controller. ([#7538](https://github.com/antrea-io/antrea/pull/7538) [#7571](https://github.com/antrea-io/antrea/pull/7571), [@luolanzone])
- Handle Traceflow external destination IP correctly in `noEncap` mode to fix timeout issue. ([#7266](https://github.com/antrea-io/antrea/pull/7266), [@gran-vmv])
- Add validation to ensure that IP range start is not greater than end in IPPool. ([#7308](https://github.com/antrea-io/antrea/pull/7308), [@wenqiq])
- Improve SR-IOV device assignment to ensure it's idempotent. ([#7322](https://github.com/antrea-io/antrea/pull/7322), [@luolanzone])
- Improve secondary interface reconciliation and fix a nil pointer exception when both SR-IOV and VLAN interfaces are enabled in Antrea SecondaryNetwork. ([#7286](https://github.com/antrea-io/antrea/pull/7286), [@jianjuns])
- Add missing Run calls for nodeStore / serviceStore to start the garbage collection routines and fix a memory leak for FlowAggregator. ([#7343](https://github.com/antrea-io/antrea/pull/7343), [@antoninbas])
- Remove trailing whitespace from default manifests to fix antrea-config ConfigMap formatting issues. ([#7311](https://github.com/antrea-io/antrea/pull/7311), [@antoninbas])

[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@XinShuYang]: https://github.com/XinShuYang
[@andrew-su]: https://github.com/andrew-su
[@antoninbas]: https://github.com/antoninbas
[@edwardbadboy]: https://github.com/edwardbadboy
[@ghadeer-elsalhawy]: https://github.com/ghadeer-elsalhawy
[@gran-vmv]: https://github.com/gran-vmv
[@harshgdev]: https://github.com/harshgdev
[@hongliangl]: https://github.com/hongliangl
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@renovatebot](https://github.com/renovatebot)
[@sratslla]: https://github.com/sratslla
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
