# Changelog 2.6

## 2.6.0 - 2026-03-20

### Added

- Add support for multiple flow export destinations via `FlowExporterDestination` CRDs, enabling dynamic configuration of flow export targets without requiring Agent restarts. ([#7641](https://github.com/antrea-io/antrea/pull/7641), [@andrew-su] [@Dyanngg])
- Add NetworkInfo field to AntreaAgentInfo CRD. ([#7763](https://github.com/antrea-io/antrea/pull/7763), [@antoninbas])
- Add IPv6 and Dual-Stack support for Antrea NodePortLocal. ([#7594](https://github.com/antrea-io/antrea/pull/7594), [@antoninbas])
- Support Traceflow with WireGuard encryption enabled. ([#7634](https://github.com/antrea-io/antrea/pull/7634), [@xliuxu])
- Support Egress with WireGuard encryption enabled. ([#7628](https://github.com/antrea-io/antrea/pull/7628), [@xliuxu])
- Support IPv6 traffic over IPv4 IPsec tunnel. ([#7759](https://github.com/antrea-io/antrea/pull/7759), [@xliuxu])
- Add nftables information in Agent supportbundle. ([#7547](https://github.com/antrea-io/antrea/pull/7547), [@molegit9])
- Add ipset information to Agent supportbundle. ([#7552](https://github.com/antrea-io/antrea/pull/7552), [@aniskhalfallah])
- Add WireGuard validation test to `antctl check installation`. ([#7809](https://github.com/antrea-io/antrea/pull/7809), [@antoninbas])
- Add IPsec validation test to `antctl check installation`. ([#7757](https://github.com/antrea-io/antrea/pull/7757), [@antoninbas])
- Add init container to apply Antrea-specific sysctl configuration. ([#7651](https://github.com/antrea-io/antrea/pull/7651), [@hongliangl])
- Support NodeSelector in ClusterGroups for both AppliedTo and Rules of NodeNetworkPolicy. ([#7344](https://github.com/antrea-io/antrea/pull/7344), [@petertran-avgo])

### Changed

- Lock feature gates `TopologyAwareHints` and `ServiceTrafficDistribution` to true. ([#7620](https://github.com/antrea-io/antrea/pull/7620), [@hongliangl])
- Install host network rules to allow AntreaProxy health check traffic. ([#7605](https://github.com/antrea-io/antrea/pull/7605), [@hongliangl])
- Remove deprecated L7FlowExporter. ([#7593](https://github.com/antrea-io/antrea/pull/7593), [@antoninbas])
- Remove FlowExporter feature gate from Windows yaml. ([#7606](https://github.com/antrea-io/antrea/pull/7606), [@luolanzone])
- Migrate ServiceExternalIP controller to use EndpointSlice API, replacing the deprecated Endpoints API. ([#7686](https://github.com/antrea-io/antrea/pull/7686), [@xliuxu])
- Migrate from core.Event to events.Event API when creating Events from Antrea. ([#7613](https://github.com/antrea-io/antrea/pull/7613), [@kartikangiras])
- Update to latest iptables-wrapper, which fixes Antrea with recent versions of Talos. ([#7729](https://github.com/antrea-io/antrea/pull/7729) [#7756](https://github.com/antrea-io/antrea/pull/7756), [@antoninbas])
- Improve logging in Agent's NetworkPolicy controller. ([#7456](https://github.com/antrea-io/antrea/pull/7456), [@antoninbas])
- Improve logging and minor refactor in cert provider for FlowAggregator. ([#7648](https://github.com/antrea-io/antrea/pull/7648), [@antoninbas])
- Use reserved OVS controller ports for Antrea SecondaryNetwork. ([#7645](https://github.com/antrea-io/antrea/pull/7645), [@luolanzone])
- Clarify `rp_filter` behavior with some Linux distributions in Egress documentation. ([#7661](https://github.com/antrea-io/antrea/pull/7661), [@hongliangl])
- Upgrade Go to 1.26. ([#7795](https://github.com/antrea-io/antrea/pull/7795), [@antoninbas])
- Update K8s libraries to v1.35.0. ([#7668](https://github.com/antrea-io/antrea/pull/7668), [@antoninbas])
- Update module github.com/containernetworking/plugins to v1.9.0 to address CVEs. ([#7624](https://github.com/antrea-io/antrea/pull/7624), [@renovatebot])

### Fixed

- Fix host tunnel traffic rules ignoring the configured TunnelPort and always using a fixed port value. ([#7824](https://github.com/antrea-io/antrea/pull/7824), [@hongliangl])
- Fix handling of self-connections on Egress Nodes in hybrid mode. ([#7611](https://github.com/antrea-io/antrea/pull/7611), [@hongliangl])
- Fix a bug in hybrid mode where a failed nftables delete for a non-existent Pod CIDR element left stale cached state, preventing OVS flows and routes from being installed when a new Node reused the same Pod CIDR. ([#7760](https://github.com/antrea-io/antrea/pull/7760), [@hongliangl])
- Fix concurrent map access in GetFQDNCache to avoid Antrea agent crash issue. ([#7794](https://github.com/antrea-io/antrea/pull/7794), [@Ady0333])
- Fix premature loop exit in RunPeriodicDeletion method to ensure the function exits cleanly for Antrea FlowExporter. ([#7842](https://github.com/antrea-io/antrea/pull/7842), [@Denyme24])
- Fix default options for audit logging configuration. ([#7825](https://github.com/antrea-io/antrea/pull/7825), [@Denyme24])
- Fix race in ReassignFlowPriorities by adding missing locks. ([#7717](https://github.com/antrea-io/antrea/pull/7717), [@Ady0333])
- Fix incorrect ConfigMap name for FlowAggregator deployment. ([#7687](https://github.com/antrea-io/antrea/pull/7687), [@andrew-su])
- Add missing Service info in AntreaProxy for Pod to Service flows. ([#7614](https://github.com/antrea-io/antrea/pull/7614), [@petertran-avgo])
- Fix FlowAggregator skipping Service UID population for flows from Services without a port name, causing exported flows to be missing Service UID information. ([#7681](https://github.com/antrea-io/antrea/pull/7681), [@luolanzone])
- Fix `antctl mc join` cleanup on error. ([#7649](https://github.com/antrea-io/antrea/pull/7649), [@SharanRP])
- Fix antrea-agent crash due to a nil pointer when AntreaProxy is not enabled. ([#7636](https://github.com/antrea-io/antrea/pull/7636), [@hongliangl])
- Generate self-signed certificates only when required to prevent conflicts in multi-replica flow-aggregator deployments. ([#7559](https://github.com/antrea-io/antrea/pull/7559), [@andrew-su])
- Fix Helm chart to support installing to multiple namespaces without name conflicts for FlowAggregator. ([#7670](https://github.com/antrea-io/antrea/pull/7670), [@andrew-su])


[@Ady0333]: https://github.com/Ady0333
[@Denyme24]: https://github.com/Denyme24
[@Dyanngg]: https://github.com/Dyanngg
[@SharanRP]: https://github.com/SharanRP
[@andrew-su]: https://github.com/andrew-su
[@aniskhalfallah]: https://github.com/aniskhalfallah
[@antoninbas]: https://github.com/antoninbas
[@hongliangl]: https://github.com/hongliangl
[@kartikangiras]: https://github.com/kartikangiras
[@luolanzone]: https://github.com/luolanzone
[@molegit9]: https://github.com/molegit9
[@petertran-avgo]: https://github.com/petertran-avgo
[@renovatebot]: https://github.com/renovatebot
[@xliuxu]: https://github.com/xliuxu
