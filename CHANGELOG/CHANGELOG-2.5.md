# Changelog 2.5

## 2.5.0 - 2025-11-28

### Added

- Support `nftables` in Node host network for AntreaProxy. ([#7545](https://github.com/antrea-io/antrea/pull/7545), [@hongliangl])
- Add support for Antrea Egress in hybrid mode. ([#7239](https://github.com/antrea-io/antrea/pull/7239), [@hongliangl])
- Add direction flag to antctl packetcapture command. ([#7195](https://github.com/antrea-io/antrea/pull/7195), [@sratslla])
- Add IPv6 support for PacketCapture feature, including ICMPv6 handling and new CLI filter options. ([#7385](https://github.com/antrea-io/antrea/pull/7385), [@harshgdev])
- Enhance PacketCapture to support matching arbitrary source or destination. ([#7215](https://github.com/antrea-io/antrea/pull/7215), [@harshgdev])
- Enhance PacketCapture to also capture packets at the destination Pod, in addition to the source. ([#7289](https://github.com/antrea-io/antrea/pull/7289), [@harshgdev])
- Add a new `FlowExporterTarget` CRD to enable defining multiple flow exporter targets with different rules and protocols. ([#7494](https://github.com/antrea-io/antrea/pull/7494), [@andrew-su])
- Add autoscaling and multi-replica for FlowAggregator with proxy mode. ([#7256](https://github.com/antrea-io/antrea/pull/7256), [@andrew-su])
- Add confederation identifier to the `antctl get bgppolicy` command response. ([#7275](https://github.com/antrea-io/antrea/pull/7275), [@Atish-iaf])
- Add member ASNs to the `antctl get bgppolicy` command response. ([#7425](https://github.com/antrea-io/antrea/pull/7425), [@Atish-iaf])
- Add `conntrack_poll_cycle_duration_seconds` metric to track the time taken to poll conntrack and update the connection store. ([#7460](https://github.com/antrea-io/antrea/pull/7460), [@antoninbas])
- Add a `network-policy-delay` flag to `antctl check installation` to configure the policy realization delay. ([#7427](https://github.com/antrea-io/antrea/pull/7427), [@antoninbas])
- Add resource requests for Windows container in Antrea deployment. ([#7254](https://github.com/antrea-io/antrea/pull/7254), [@XinShuYang])
- Accelerate Pod-to-Pod networking in `noEncap` and `hybrid` modes by leveraging nftables `flowtable` to reduce host network stack overhead. ([#7324](https://github.com/antrea-io/antrea/pull/7324), [@hongliangl])

### Changed

- Upgrade Go to 1.25. ([#7561](https://github.com/antrea-io/antrea/pull/7561), [@antoninbas])
- Deprecate `L7FlowExporter` feature. ([#7567](https://github.com/antrea-io/antrea/pull/7567), [@luolanzone])
- Increase the minimum supported Kubernetes version to 1.23. ([#7564](https://github.com/antrea-io/antrea/pull/7564), [@antoninbas])
- Evolve AntreaProxy with a new healthz server on port 10256, and with `PreferSameTrafficDistribution` support. ([#7371](https://github.com/antrea-io/antrea/pull/7371), [@hongliangl])
- Update `FlowExporterDestination` to allow specifying the namespace and name for TLS certificate resources, supporting cross-namespace configurations. ([#7549](https://github.com/antrea-io/antrea/pull/7549), [@andrew-su])
- Promote feature gates `TopologyAwareHints` and `ServiceTrafficDistribution` to General Availability (GA). ([#7503](https://github.com/antrea-io/antrea/pull/7503), [@hongliangl])
- Improve FlowExporter performance by using netlink zone filtering when dumping conntrack flows, reducing CPU and memory usage. ([#7504](https://github.com/antrea-io/antrea/pull/7504), [@antoninbas])
- Prevent WireGuard enablement when the traffic mode is not Encap. ([#7464](https://github.com/antrea-io/antrea/pull/7464), [@luolanzone])
- Add disclaimers to Azure-related documentation and code, as Antrea is no longer tested on Azure. ([#7381](https://github.com/antrea-io/antrea/pull/7381), [@edwardbadboy])
- Migrate dependency update configuration from Dependabot to Renovate to unify dependency management. ([#7354](https://github.com/antrea-io/antrea/pull/7354), [@ghadeer-elsalhawy])
- Remove `AntreaProxy` and `NodePortLocal` feature gates from Helm charts and standard manifests. ([#7505](https://github.com/antrea-io/antrea/pull/7505), [@hongliangl])
- Add validation to ensure `AntreaIPAM` is enabled with `SecondaryNetwork`. ([#7556](https://github.com/antrea-io/antrea/pull/7556), [@luolanzone])
- Periodically sync ip rules to ensure consistency. ([#7295](https://github.com/antrea-io/antrea/pull/7295), [@hongliangl])
- Use a more robust way to extract the source Node IP from encapsulated IGMP messages for multicast when the traffic mode is Encap. ([#7282](https://github.com/antrea-io/antrea/pull/7282), [@hongliangl])
- Add validation to clarify `networkPolicyOnly` mode is not supported with Antrea Multicast. ([#7362](https://github.com/antrea-io/antrea/pull/7362), [@wenyingd])

### Fixed

- Upgrade CNI plugins to v1.8.0 to fix CVEs. ([#7397](https://github.com/antrea-io/antrea/pull/7397), [@luolanzone])
- Add missing policy UIDs for denied connections. ([#7388](https://github.com/antrea-io/antrea/pull/7388), [@antoninbas])
- Upgrade `libOpenflow` to support OpenFlow message overflow. ([#7470](https://github.com/antrea-io/antrea/pull/7470), [@wenyingd])
- Fix ServiceCIDR discovery in the Multi-cluster member controller for Kubernetes versions 1.33 and newer. ([#7291](https://github.com/antrea-io/antrea/pull/7291), [@luolanzone])
- Fix agent crash issue which is caused by unexpected interface store initialization for FlexibleIPAM uplink internal port. ([#7389](https://github.com/antrea-io/antrea/pull/7389), [@gran-vmv])
- Avoid missing or invalid NetworkPolicy data in FlowExporter records by increasing flow ID reuse delay and filtering old connections. ([#7468](https://github.com/antrea-io/antrea/pull/7468), [@antoninbas])
- Refine Traceflow to correctly handle inter-Node Pod-to-Pod traffic across all traffic modes. ([#7481](https://github.com/antrea-io/antrea/pull/7481), [@hongliangl])
- Fix ACNP applied to NodePort failing to reject traffic in `noEncap`/`hybrid` mode. ([#7265](https://github.com/antrea-io/antrea/pull/7265), [@hongliangl])
- Fix a type assertion panic in `GetFlowTableID` function, which affected the `/ovsflows` HTTP handler. ([#7515](https://github.com/antrea-io/antrea/pull/7515), [@antoninbas])
- Handle missing Pod IP and Pod IP changes in NodePortLocal to prevent incorrect datapath rules and clear NPL annotations. ([#7512](https://github.com/antrea-io/antrea/pull/7512), [@antoninbas])
- Exclude Egress VLAN sub-interfaces (`antrea-ext.VLAN`) from NodePort addresses for consistency. ([#7519](https://github.com/antrea-io/antrea/pull/7519), [@antoninbas])
- Improve `initK8sNodeLocalConfig` in Agent initialization by separating Node and PodCIDR polling for better logging, and increase the timeout to 60s. ([#7473](https://github.com/antrea-io/antrea/pull/7473), [@antoninbas])
- Fix panic in monitor controller caused by unexpected delete event type. ([#7568](https://github.com/antrea-io/antrea/pull/7568), [@luolanzone])
- Clean up stale secondary IPs in IPPool when Node restarts with invalid OVSDB. ([#7511](https://github.com/antrea-io/antrea/pull/7511), [@luolanzone])
- Improve stale IP recycling in AntreaIPAM controller. ([#7538](https://github.com/antrea-io/antrea/pull/7538) [#7571](https://github.com/antrea-io/antrea/pull/7571), [@luolanzone])
- Handle Traceflow external destination IP correctly in NoEncap mode to fix timeout issue. ([#7266](https://github.com/antrea-io/antrea/pull/7266), [@gran-vmv])
- Unify validation logic for IPPool and ExternalIPPool for more consistent checks and failures. ([#7319](https://github.com/antrea-io/antrea/pull/7319), [@wenqiq])
- Add validation to ensure IP range start is not greater than end in IPPool. ([#7308](https://github.com/antrea-io/antrea/pull/7308), [@wenqiq])
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
[@sratslla]: https://github.com/sratslla
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
