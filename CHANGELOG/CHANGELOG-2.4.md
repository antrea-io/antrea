# Changelog 2.4

## 2.4.3 - 2025-10-14

### Fixed

- Fix overflow issue in network policy priority assigner. ([#7496](https://github.com/antrea-io/antrea/pull/7496), [@Dyanngg])
- Unify validation logic for IPPool and ExternalIPPool for more consistent checks and failures. ([#7319](https://github.com/antrea-io/antrea/pull/7319), [@wenqiq])
- Handle Traceflow external destination IP correctly in NoEncap mode to fix timeout issue. ([#7266](https://github.com/antrea-io/antrea/pull/7266), [@gran-vmv])

## 2.4.2 - 2025-09-15

### Fixed

- Fix agent crash issue which is caused by unexpected interface store initialization for FlexibleIPAM uplink internal port. ([#7389](https://github.com/antrea-io/antrea/pull/7389), [@gran-vmv])
- Ignore conntrack connections denied by policy for FlowExporter. ([#7361](https://github.com/antrea-io/antrea/pull/7361), [@antoninbas])
- Add missing policy UIDs for denied connections for FlowExporter. ([#7388](https://github.com/antrea-io/antrea/pull/7388), [@antoninbas])
- Fix ACNP applied to NodePort failing to reject traffic in noEncap/hybrid mode. ([#7265](https://github.com/antrea-io/antrea/pull/7265), [@hongliangl])
- Use a more robust way to extract the source Node IP from encapsulated IGMP messages for Multicast. ([#7282](https://github.com/antrea-io/antrea/pull/7282), [@hongliangl])
- Upgrade CNI plugins to v1.8.0 to fix CVEs. ([#7397](https://github.com/antrea-io/antrea/pull/7397), [@luolanzone])

## 2.4.1 - 2025-08-13

### Added

- Add resource requests for Windows container in Antrea deployment. ([#7254](https://github.com/antrea-io/antrea/pull/7254), [@XinShuYang])

### Fixed

- Add missing Run calls for nodeStore / serviceStore to start the garbage collection routines and fix a memory leak for FlowAggregator. ([#7343](https://github.com/antrea-io/antrea/pull/7343), [@antoninbas])
- Improve SR-IOV device assignment to ensure it's idempotent. ([#7322](https://github.com/antrea-io/antrea/pull/7322), [@luolanzone])
- Add validation to ensure IP range start is not greater than end in IPPool. ([#7308](https://github.com/antrea-io/antrea/pull/7308), [@wenqiq])
- Improve secondary interface reconciliation and fix a nil pointer exception when both SR-IOV and VLAN interfaces are enabled in Antrea SecondaryNetwork. ([#7286](https://github.com/antrea-io/antrea/pull/7286), [@jianjuns])
- Remove trailing whitespace from default manifests to fix `antrea-config` ConfigMap formatting issues. ([#7311](https://github.com/antrea-io/antrea/pull/7311), [@antoninbas])

## 2.4.0 - 2025-07-09

### Added

- Add BGP confederation support in BGPPolicy. ([#6927](https://github.com/antrea-io/antrea/pull/6927) [#6905](https://github.com/antrea-io/antrea/pull/6905), [@hongliangl])
- Support mTLS when exporting flows to an external flow collector for FlowAggregator. ([#7212](https://github.com/antrea-io/antrea/pull/7212), [@antoninbas])
- Add `k8s.v1.cni.cncf.io/network-status` annotation to make SecondaryNetwork Pod IP visible. ([#7069](https://github.com/antrea-io/antrea/pull/7069), [@wenqiq])
- Add `protocolFilter` config to FlowExporter to filter and export flows only with the specified protocols. ([#7145](https://github.com/antrea-io/antrea/pull/7145), [@petertran-avgo])
- Add `antctl get fqdncache` sub-command to fetch the DNS mapping entries for FQDN policies. ([#6868](https://github.com/antrea-io/antrea/pull/6868), [@Dhruv-J])
- Add TCP flags filter support for PacketCapture. ([#7070](https://github.com/antrea-io/antrea/pull/7070), [@AryanBakliwal])
- Add bidirectional packet capture support for PacketCapture. ([#6882](https://github.com/antrea-io/antrea/pull/6882), [@AryanBakliwal])
- Add ICMP messages filter support for PacketCapture. ([#7164](https://github.com/antrea-io/antrea/pull/7164), [@AryanBakliwal])
- Support `antctl packetcapture` sub-commands for PacketCapture. ([#6884](https://github.com/antrea-io/antrea/pull/6884), [@hangyan])
- Support enabling multicast snooping for SecondaryNetwork. ([#7200](https://github.com/antrea-io/antrea/pull/7200), [@tnqn])
- Allow defining static MAC addresses for SecondaryInterfaces for VLAN network. ([#7137](https://github.com/antrea-io/antrea/pull/7137), [@KMAnju-2021] [@rajnkamr])

### Changed

- Multiple enhancements for FlowAggregator are introduced:
  - Move aggregation logic from go-ipfix to Antrea for FlowAggregator. ([#7227](https://github.com/antrea-io/antrea/pull/7227), [@antoninbas])
  - Remove several instances of log spam in the Flow Aggregator, and improve handling of connection failures. ([#7223](https://github.com/antrea-io/antrea/pull/7223), [@antoninbas])
  - Set `priorityClassName` to `system-node-critical` by default for FlowAggregator. ([#7124](https://github.com/antrea-io/antrea/pull/7124), [@luolanzone])
  - Support custom ClusterIDs attached to exported flow records for FlowAggregator. ([#7197](https://github.com/antrea-io/antrea/pull/7197), [@petertran-avgo])
  - Clean up RBAC for FlowAggregator. ([#7125](https://github.com/antrea-io/antrea/pull/7125), [@antoninbas])
  - Use Protobuf message in FlowAggregator to represent flows. ([#7253](https://github.com/antrea-io/antrea/pull/7253), [@antoninbas])
  - Use Protobuf / gRPC between FlowExporter and FlowAggregator by default, and allow disabling IPFIX collector via `aggregatorTransportProtocol`. ([#7264](https://github.com/antrea-io/antrea/pull/7264), [@antoninbas])
  - Add ability to export K8s UIDs in the IPFIX exporter. ([#7279](https://github.com/antrea-io/antrea/pull/7279), [@antoninbas])
  - Add more configuration values to the flow-aggregator chart. ([#7138](https://github.com/antrea-io/antrea/pull/7138), [@antoninbas])
  - Push flow-aggregator image to `ghcr.io` registry. ([#7036](https://github.com/antrea-io/antrea/pull/7036), [@antoninbas])
- Log error when OVS meter drops packets, which helps to evaluate whether increasing the packetInRate configuration is needed. ([#7242](https://github.com/antrea-io/antrea/pull/7242), [@tnqn])
- Log PacketIn drops when dispatching to per-category queues to improve troubleshooting. ([#7174](https://github.com/antrea-io/antrea/pull/7174), [@tnqn])
- Increase the default packet-in rate limit to 5000. ([#7243](https://github.com/antrea-io/antrea/pull/7243), [@tnqn])
- Sync affected groups in the Antrea Controller when a Pod goes into `Terminated` state, to ensure that the Pod is excluded from NetworkPolicy source and destination immediately. ([#7217](https://github.com/antrea-io/antrea/pull/7217), [@Dyanngg])
- Decouple sending of ICMP probes & latency reporting for NodeLatencyMonitor, which can improve accuracy of measurements and reduce system load. ([#7189](https://github.com/antrea-io/antrea/pull/7189), [@g4rud4kun])
- Add ICMP Rule for NodeLatencyMonitor to make it work when the Node is configured with iptables default DROP policy. ([#7011](https://github.com/antrea-io/antrea/pull/7011), [@Dhruv-J])
- Handle Pod UID updates in PodStore to account for the corner case where old and new Pods from update handler are actually different objects. ([#6964](https://github.com/antrea-io/antrea/pull/6964), [@antoninbas])
- Support configuring file permissions for the Antrea CNI configuration file. ([#7098](https://github.com/antrea-io/antrea/pull/7098), [@luolanzone])
- Install iptables rules to allow WireGuard packets to ensure Antrea with WireGuard can work properly when the Node is configured with iptables default DROP policy. ([#7030](https://github.com/antrea-io/antrea/pull/7030), [@wenyingd])
- Make IPPool `prefixLength` and `gateway` immutable. ([#7186](https://github.com/antrea-io/antrea/pull/7186), [@wenqiq])
- Periodically sync permanent neighbors to ensure route correctness for Antrea host gateway interface. ([#7238](https://github.com/antrea-io/antrea/pull/7238), [@hongliangl])
- Rename a SR-IOV VF device, which is configured as a secondary Pod interface, back to the original name when the Pod is deleted. ([#7144](https://github.com/antrea-io/antrea/pull/7144), [@luolanzone])
- Support removing the whole `k8s.v1.cni.cncf.io/networks` annotation or resetting it to an empty value, which deletes the Pod's SecondaryNetwork interfaces. ([#7119](https://github.com/antrea-io/antrea/pull/7119), [@wenqiq])
- Document Antrea native secondary network support for SR-IOV interfaces. ([#7076](https://github.com/antrea-io/antrea/pull/7076), [@tnqn])

### Fixed

- Enhance OVS commands for Antrea Windows to accelerate container recovery and improve robustness. ([#7228](https://github.com/antrea-io/antrea/pull/7228), [@XinShuYang])
- Configure routes via `ip route add` to avoid incorrect replacement of routes when the interface is managed by a network daemon. ([#7134](https://github.com/antrea-io/antrea/pull/7134), [@luolanzone])
- Restore secondary VLAN interface information and reconcile OVS ports after Agent restarts. ([#6853](https://github.com/antrea-io/antrea/pull/6853), [@KMAnju-2021])
- Persist container netns with OVS port external IDs. ([#7199](https://github.com/antrea-io/antrea/pull/7199), [@[@jianjuns])
- Restore the existing SR-IOV secondary interface information when Agent restarts, using the information stored in the Pod NetworkStatus annotation, which ensures correct IP release and VF device name restoration after Pod deletion. ([#7240](https://github.com/antrea-io/antrea/pull/7240), [@luolanzone])
- Fix invalid template ID in FlowAggregator for IPFIX exporter. ([#7208](https://github.com/antrea-io/antrea/pull/7208), [@antoninbas])
- Fix race condition when getting metrics via `antctl` for FlowAggregator. ([#7230](https://github.com/antrea-io/antrea/pull/7230), [@antoninbas])
- Fix invalid IPFIX UDP traffic fragmentation in the Flow Aggregator. ([#7080](https://github.com/antrea-io/antrea/pull/7080), [@antoninbas])
- Fix invalid Antrea IE registry ID in docs. ([#7087](https://github.com/antrea-io/antrea/pull/7087), [@ColonelBundy])
- Remove stale local members in the group cache for Multicast, which resolves an issue that the same receiver may fail to receive multicast packets after it rejoins the group. ([#7154](https://github.com/antrea-io/antrea/pull/7154), [@wenyingd])
- Fix Agent crash when deleting the Secret storing BGP passwords. ([#7042](https://github.com/antrea-io/antrea/pull/7042), [@hongliangl])
- Fix rollback when `configureContainerLinkVeth` fails, to ensure subsequent retries can succeed. ([#7210](https://github.com/antrea-io/antrea/pull/7210) [#7213](https://github.com/antrea-io/antrea/pull/7213), [@tnqn])
- Upgrade `otelhttp` to v0.55.0 to fix `WriteHeader` logging flood. ([#7196](https://github.com/antrea-io/antrea/pull/7196), [@DeeBi9])

[@AryanBakliwal]: https://github.com/AryanBakliwal
[@ColonelBundy]: https://github.com/ColonelBundy
[@DeeBi9]: https://github.com/DeeBi9
[@Dhruv-J]: https://github.com/Dhruv-J
[@Dyanngg]: https://github.com/Dyanngg
[@KMAnju-2021]: https://github.com/KMAnju-2021
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@g4rud4kun]: https://github.com/g4rud4kun
[@gran-vmv]: https://github.com/gran-vmv
[@hangyan]: https://github.com/hangyan
[@hongliangl]: https://github.com/hongliangl
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@petertran-avgo]: https://github.com/petertran-avgo
[@rajnkamr]: https://github.com/rajnkamr
[@tnqn]: https://github.com/tnqn
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
