# Changelog 2.4

## 2.4.0 - 2025-06-30

### Added

- Add BGP confederation support in BGPPolicy. ([#6927](https://github.com/antrea-io/antrea/pull/6927) [#6905](https://github.com/antrea-io/antrea/pull/6905), [@hongliangl])
- Support mTLS when exporting to an external flow collector for FlowAggregator. ([#7212](https://github.com/antrea-io/antrea/pull/7212), [@antoninbas])
- Add `k8s.v1.cni.cncf.io/network-status` annotation to make SecondaryNetwork Pod IP visible. ([#7069](https://github.com/antrea-io/antrea/pull/7069), [@wenqiq])
- Adds protocol filter to FlowExporter. ([#7145](https://github.com/antrea-io/antrea/pull/7145), [@petertran-avgo])
- Add `antctl get fqdncache` sub-command to fetch the DNS mapping entries for FQDN policies. ([#6868](https://github.com/antrea-io/antrea/pull/6868), [@Dhruv-J])
- add TCP flags filter support to PacketCapture. ([#7070](https://github.com/antrea-io/antrea/pull/7070), [@AryanBakliwal])
- Add bidirectional packet capture support for PacketCapture. ([#6882](https://github.com/antrea-io/antrea/pull/6882), [@AryanBakliwal])
- Add ICMP messages filter support to PacketCapture. ([#7164](https://github.com/antrea-io/antrea/pull/7164), [@AryanBakliwal])
- Support `antctl packetcapture` sub-commands for PacketCapture. ([#6884](https://github.com/antrea-io/antrea/pull/6884), [@hangyan])

### Changed

- Promote feature `AntreaIPAM` from Alpha to Beta. ([#7184](https://github.com/antrea-io/antrea/pull/7184), [@wenqiq])
- Promote feature `SecondaryNetwork` from Alpha to Beta. ([#7169](https://github.com/antrea-io/antrea/pull/7169), [@wenqiq])
- Multiple enhancements for FlowAggregator are introduced:
  - Move aggregation logic from go-ipfix to Antrea for FlowAggregator. ([#7227](https://github.com/antrea-io/antrea/pull/7227), [@antoninbas])
  - Multiple improvements for IPFIX collector on FlowAggregator. ([#7223](https://github.com/antrea-io/antrea/pull/7223), [@antoninbas])
  - Add `priorityClassName` as `system-node-critical` by default for FlowAggregator. ([#7124](https://github.com/antrea-io/antrea/pull/7124), [@luolanzone])
  - Support custom ClusterIDs attached to exported flow records for FlowAggregator. ([#7197](https://github.com/antrea-io/antrea/pull/7197), [@petertran-avgo])
  - Clean up RBAC for FlowAggregator. ([#7125](https://github.com/antrea-io/antrea/pull/7125), [@antoninbas])
  - Push flow-aggregator image to `ghcr.io` registry. ([#7036](https://github.com/antrea-io/antrea/pull/7036), [@antoninbas])
- Log error when OVS meter drops packets, which helps to evaluate whether increasing the packetInRate configuration is needed. ([#7242](https://github.com/antrea-io/antrea/pull/7242), [@tnqn])
- Log PacketIn drops when dispatching to per-category queues to improve troubleshooting. ([#7174](https://github.com/antrea-io/antrea/pull/7174), [@tnqn])
- Increase the default packet-in rate limit to 5000. ([#7243](https://github.com/antrea-io/antrea/pull/7243), [@tnqn])
- Sync groups members for Pods that turns into terminated status to ensure released IPs are excluded in time for Antrea NetworkPolicy. ([#7217](https://github.com/antrea-io/antrea/pull/7217), [@Dyanngg])
- Add more configuration values to the flow-aggregator chart. ([#7138](https://github.com/antrea-io/antrea/pull/7138), [@antoninbas])
- Decouple sending of ICMP probes & latency reporting for NodeLatencyMonitor, which can improve accuracy of measurements and reduce system load. ([#7189](https://github.com/antrea-io/antrea/pull/7189), [@g4rud4kun])
- Support enabling multicast snooping for SecondaryNetwork. ([#7200](https://github.com/antrea-io/antrea/pull/7200), [@tnqn])
- Add ICMP Rule for NodeLatencyMonitor to make it work when the Node is configured with iptables default DROP policy. ([#7011](https://github.com/antrea-io/antrea/pull/7011), [@Dhruv-J])
- Handle Pod UID updates in PodStore to handle a corner case that old and new Pods from update handler are actually different objects. ([#6964](https://github.com/antrea-io/antrea/pull/6964), [@antoninbas])
- Support configuring file permission for the Antrea CNI configuration file. ([#7098](https://github.com/antrea-io/antrea/pull/7098), [@luolanzone])
- Install iptables rules to allow WireGuard packets to ensure Antrea with WireGuard can work properly when the Node is configured with iptables default DROP policy. ([#7030](https://github.com/antrea-io/antrea/pull/7030), [@wenyingd])
- Make IPPool `prefixLength` and `gateway` immutable. ([#7186](https://github.com/antrea-io/antrea/pull/7186), [@wenqiq])
- Periodically sync permanent neighbors to ensure route correctness. ([#7238](https://github.com/antrea-io/antrea/pull/7238), [@hongliangl])
- Update go-ipfix to v0.14.0. ([#7080](https://github.com/antrea-io/antrea/pull/7080), [@antoninbas])
- Document SecondaryNetwork support for SR-IOV. ([#7076](https://github.com/antrea-io/antrea/pull/7076), [@tnqn])

### Fixed

- Enhance OVS commands for Antrea Windows to accelerate container recovery and improve robustness. ([#7228](https://github.com/antrea-io/antrea/pull/7228), [@XinShuYang])
- Configure routes via `ip route add` to avoid incorrect routes replacement when the interface is managed by a network daemon. ([#7134](https://github.com/antrea-io/antrea/pull/7134), [@luolanzone])
- Reconcile secondary network OVS ports after Agent restart to ensure stale ports can be removed correctly. ([#6853](https://github.com/antrea-io/antrea/pull/6853), [@KMAnju-2021])
- Rename SR-IOV VF device name back to the original one when a Pod is deleted. ([#7144](https://github.com/antrea-io/antrea/pull/7144), [@luolanzone])
- Fix invalid template ID in FlowAggregator for IPFIX exporter. ([#7208](https://github.com/antrea-io/antrea/pull/7208), [@antoninbas])
- Fix race condition when getting metrics via `antctl` for FlowAggregator. ([#7230](https://github.com/antrea-io/antrea/pull/7230), [@antoninbas])
- Fix invalid Antrea IE registry ID in docs. ([#7087](https://github.com/antrea-io/antrea/pull/7087), [@ColonelBundy])
- Remove stale local members in the group cache for Multicast, which resolve an issue that the same receiver may fail to receive multicast packets after it rejoins the group . ([#7154](https://github.com/antrea-io/antrea/pull/7154), [@wenyingd])
- Fix agent crash when deleting the Secret storing BGP passwords. ([#7042](https://github.com/antrea-io/antrea/pull/7042), [@hongliangl])
- Fix rollback when `configureContainerLinkVeth` fails to ensure retry can succeed. ([#7210](https://github.com/antrea-io/antrea/pull/7210) [#7213](https://github.com/antrea-io/antrea/pull/7213), [@tnqn])
- Upgrade `otelhttp` to v0.55.0 to fix WriteHeader logging flood. ([#7196](https://github.com/antrea-io/antrea/pull/7196), [@DeeBi9])

[@AryanBakliwal]: https://github.com/AryanBakliwal
[@ColonelBundy]: https://github.com/ColonelBundy
[@DeeBi9]: https://github.com/DeeBi9
[@Dhruv-J]: https://github.com/Dhruv-J
[@Dyanngg]: https://github.com/Dyanngg
[@KMAnju-2021]: https://github.com/KMAnju-2021
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@g4rud4kun]: https://github.com/g4rud4kun
[@hangyan]: https://github.com/hangyan
[@hongliangl]: https://github.com/hongliangl
[@luolanzone]: https://github.com/luolanzone
[@petertran-avgo]: https://github.com/petertran-avgo
[@tnqn]: https://github.com/tnqn
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd