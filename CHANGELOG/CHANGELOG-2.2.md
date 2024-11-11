# Changelog 2.2

## 2.2.0 - 2024-11-10

### Added

- Add a new feature `PacketCapture` to allow users to capture live traffic and upload captured packets to a specified location:
  - Add PacketCapture API. ([#6257](https://github.com/antrea-io/antrea/pull/6257), [@hangyan])
  - Add PacketCapture data path support. ([#6756](https://github.com/antrea-io/antrea/pull/6756), [@hangyan])
  - Refer to [this document](https://github.com/antrea-io/antrea/blob/release-2.2/docs/packetcapture-guide.md) for more information about this feature.
- Add a few new antctl sub-commands for the `BGPPolicy` feature to improve usability:
  -  `antctl get bgppolicy` to get the effective BGP policy applied on the local Node. ([#6646](https://github.com/antrea-io/antrea/pull/6646), [@Atish-iaf])
  -  `antctl get bgppeers` to print the current status of all BGP peers of the effective BGPPolicy applied on the local Node. ([#6689](https://github.com/antrea-io/antrea/pull/6689) [#6755](https://github.com/antrea-io/antrea/pull/6755), [@Atish-iaf])
  -  `antctl get bgproutes` to print the BGP routes advertised from the local Node. ([#6734](https://github.com/antrea-io/antrea/pull/6734), [@Atish-iaf])
- Add an `except` field to the Antrea-native policy field `ipBlock` to allow users to exclude certain CIDRs from `ipBlock.cidr`. ([#6658](https://github.com/antrea-io/antrea/pull/6658) [#6677](https://github.com/antrea-io/antrea/pull/6677), [@Dyanngg])
- Add a new `templateRefreshTimeout` configuration for `FlowAggregator` to define the template retransmission interval when using the UDP protocol to export records. ([#6699](https://github.com/antrea-io/antrea/pull/6699), [@antoninbas])
- Add `EnableLogging` and `LogLabel` support for Antrea Node NetworkPolicy. ([#6626](https://github.com/antrea-io/antrea/pull/6626), [@hongliangl])
- Add `ServiceTrafficDistribution` feature in Antrea Proxy that enables traffic distribution for Services. ([#6604](https://github.com/antrea-io/antrea/pull/6604), [@hongliangl])
- Support `--random-fully` for iptables SNAT / MASQUERADE rules. ([#6602](https://github.com/antrea-io/antrea/pull/6602), [@antoninbas])
- Add `antctl-darwin-arm64` to Antrea release assets. ([#6640](https://github.com/antrea-io/antrea/pull/6640), [@antoninbas])
- Add documentation for the `NodeLatencyMonitor` feature. ([#6561](https://github.com/antrea-io/antrea/pull/6561), [@antoninbas])

### Changed

- Uniform BGP router ID selection for IPv4 and IPv6 for the `BGPPolicy` feature. ([#6605](https://github.com/antrea-io/antrea/pull/6605), [@Atish-iaf])
- Use the default protocol / port when the destination is a Service in Traceflow. ([#6601](https://github.com/antrea-io/antrea/pull/6601), [@Atish-iaf])
- Add validations for Antrea Node NetworkPolicy to fail invalid configurations. ([#6613](https://github.com/antrea-io/antrea/pull/6613), [@Atish-iaf])
- More robust system Tier creation / update for Antrea-native policies. ([#6696](https://github.com/antrea-io/antrea/pull/6696), [@antoninbas])
- Handle `ExternalIPPool` range changes in Egress controller. ([#6685](https://github.com/antrea-io/antrea/pull/6685), [@antoninbas])
- Close connection to IPFIX collector explicitly on Stop for `FlowAggregator`. ([#6635](https://github.com/antrea-io/antrea/pull/6635), [@antoninbas])
- Unify the checker image and make it configurable when running `antctl check cluster`. ([#6579](https://github.com/antrea-io/antrea/pull/6579), [@tnqn])
- Update the `Finalizer` of `ResourceExport` to be a domain-qualified string. ([#6742](https://github.com/antrea-io/antrea/pull/6742), [@Dyanngg])
- Upgrade Ubuntu to 24.04 (Noble). ([#6575](https://github.com/antrea-io/antrea/pull/6575), [@antoninbas])
- Upgrade Go to 1.23. ([#6647](https://github.com/antrea-io/antrea/pull/6647), [@antoninbas])
- Upgrade Suricata to 7.0. ([#6589](https://github.com/antrea-io/antrea/pull/6589), [@antoninbas])

### Fixed

- Install OpenFlow entries by PortStatus to fix an Antrea Agent failure on Windows when the OF port allocation takes longer than 5s. ([#6763](https://github.com/antrea-io/antrea/pull/6763), [@wenyingd])
- Match `dstIP` in `ClassifierTable` to fix a potential source MAC and IP mismatched issue on Windows when `promiscuous` mode is enabled. ([#6528](https://github.com/antrea-io/antrea/pull/6528), [@XinShuYang])
- Fix the checker image tag when running `antctl check cluster` with a released `antctl` binary. ([#6565](https://github.com/antrea-io/antrea/pull/6565), [@tnqn])
- Use the same MTU as uplink for bridge ports to fix a potential MTU mismatch issue when the traffic mode is changed. ([#6577](https://github.com/antrea-io/antrea/pull/6577), [@antoninbas])
- Cache TTLs for individual IP addresses in DNS responses to avoid evicting valid IPs before they are expired. ([#6732](https://github.com/antrea-io/antrea/pull/6732), [@hkiiita])
- Fix an issue with ipset or iptables chain removal during Antrea Node NetworkPolicy updates or deletions. ([#6707](https://github.com/antrea-io/antrea/pull/6707), [@hongliangl])
- Fix an issue with logging support for L7 NetworkPolicy causing the wrong packet to be logged by Suricata for the default reject rule. From now on, `enableLogging` only controls L4 audit logging and we unconditionally log the packet data for all Suricata alert events. ([#6651](https://github.com/antrea-io/antrea/pull/6651), [@qiyueyao])
- Fix `NetworkPolicy` related antctl commands including `antctl get networkpolicy` and `antctl get ovsflows`. ([#6487](https://github.com/antrea-io/antrea/pull/6487), [@Dyanngg])
- Fix the template ID not existing error in IPFIX exporter for `FlowAggregator`. ([#6630](https://github.com/antrea-io/antrea/pull/6630), [@antoninbas])
- Fix an antrea-agent crash issue when the host interface is already attached to the OVS bridge for `SecondaryNetwork`. ([#6666](https://github.com/antrea-io/antrea/pull/6666), [@xliuxu])
- Delay the initialization of ARP / NDP responders to fix the `ServiceExternalIP` feature when `SecondaryNetwork` is enabled. ([#6700](https://github.com/antrea-io/antrea/pull/6700), [@xliuxu])
- Run the `IPPool` webhook handler when `SecondaryNetwork` is enabled. ([#6691](https://github.com/antrea-io/antrea/pull/6691), [@luolanzone])
- Fix a slice init length issue for `NetworkPolicy` controller. ([#6715](https://github.com/antrea-io/antrea/pull/6715), [@cuishuang])
- Improve memory copying logic to avoid a potential memory fault on Windows. ([#6664](https://github.com/antrea-io/antrea/pull/6664) [#6673](https://github.com/antrea-io/antrea/pull/6673), [@XinShuYang] [@tnqn])
- Document a workaround for using `EgressSeparateSubnet` feature on OpenShift. ([#6622](https://github.com/antrea-io/antrea/pull/6622) [#6775](https://github.com/antrea-io/antrea/pull/6775), [@luolanzone] [@jianjuns])
- Clean up stale resources when `antctl check cluster` fails. ([#6597](https://github.com/antrea-io/antrea/pull/6597), [@luolanzone])
- Fix hint annotation implementation in `AntreaProxy`. ([#6607](https://github.com/antrea-io/antrea/pull/6607), [@hongliangl])
- Initialize `creationTimestamp` when creating instances of `NodeLatencyStats` to prevent a null `creationTimestamp` issue. ([#6574](https://github.com/antrea-io/antrea/pull/6574), [@hkiiita])
- Avoid error log when unmarshalling config for Antrea Multi-cluster Controller. ([#6744](https://github.com/antrea-io/antrea/pull/6744), [@antoninbas])

[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@cuishuang]: https://github.com/cuishuang
[@hangyan]: https://github.com/hangyan
[@hkiiita]: https://github.com/hkiiita
[@luolanzone]: https://github.com/luolanzone
[@hongliangl]: https://github.com/hongliangl
[@jianjuns]: https://github.com/jianjuns
[@qiyueyao]: https://github.com/qiyueyao
[@tnqn]: https://github.com/tnqn
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu
