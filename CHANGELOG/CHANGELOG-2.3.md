# Changelog 2.3

## 2.3.0 - 2025-02-21

### Added

- Add `Proxy` mode for Flow Aggregator to send flows directly without buffering or aggregation. ([#6920](https://github.com/antrea-io/antrea/pull/6920) [#6961](https://github.com/antrea-io/antrea/pull/6961), [@antoninbas])
- Support version skew between Antrea Agent and Flow Aggregator to improve upgrade robustness. ([#6912](https://github.com/antrea-io/antrea/pull/6912), [@antoninbas])
- Add `clusterId` to aggregated records for Flow Aggregator. ([#6769](https://github.com/antrea-io/antrea/pull/6769), [@antoninbas])
- Add `checksum/config` annotation to the Deployment of Flow Aggregator. ([#6967](https://github.com/antrea-io/antrea/pull/6967), [@antoninbas])
- Support SecondaryNetwork of `SR-IOV` type for VM Nodes. ([#6881](https://github.com/antrea-io/antrea/pull/6881), [@tnqn])
- Add more printer columns for `PacketCapture` CRD. ([#6977](https://github.com/antrea-io/antrea/pull/6977), [@antoninbas])
- Add fallback log collection to the `antctl supportbundle` command for Antrea components for which regular Support Bundle collection has failed. ([#3659](https://github.com/antrea-io/antrea/pull/3659), [@hangyan])
- Add `antreaProxy.disableServiceHealthCheckServer` config to disable the health check server run by Antrea Proxy to avoid `kube-proxy` error logs. ([#6939](https://github.com/antrea-io/antrea/pull/6939), [@antoninbas])
- Add route info to the output of `antctl get bgproutes`. ([#6803](https://github.com/antrea-io/antrea/pull/6803) [#6823](https://github.com/antrea-io/antrea/pull/6823) [#6835](https://github.com/antrea-io/antrea/pull/6835), [@Atish-iaf])

### Changed

- Promote feature `EgressSeparateSubnet` from Alpha to Beta. ([#6982](https://github.com/antrea-io/antrea/pull/6982), [@luolanzone])
- Promote feature `ServiceExternalIP` from Alpha to Beta. ([#6903](https://github.com/antrea-io/antrea/pull/6903), [@xliuxu])
- Allow running Flow Aggregator with no collector / sink. ([#7006](https://github.com/antrea-io/antrea/pull/7006), [@antoninbas])
- More efficient IP checks in the Flow Exporter when determining the type of flow being exported. ([#6960](https://github.com/antrea-io/antrea/pull/6960), [@antoninbas])
- Require `k8s.v1.cni.cncf.io/resourceName` annotations for `SR-IOV` type of  `NetworkAttachmentDefinitions` for SecondaryNetwork. ([#6999](https://github.com/antrea-io/antrea/pull/6999), [@antoninbas])
- Remove stale OVS interfaces in the CNIServer reconciler if the original Pod interface is disconnected. ([#6919](https://github.com/antrea-io/antrea/pull/6919), [@wenyingd])
- Remove local ASN range limitation in `BGPPolicy` API. ([#6914](https://github.com/antrea-io/antrea/pull/6914), [@hongliangl])
- Support providing a fixed public host key for SFTP uploads with a new field `hostPublicKey` to `PacketCapture` and `SupportBundleCollection` CRDs. ([#6848](https://github.com/antrea-io/antrea/pull/6848), [@antoninbas])
- Upgrade CNI plugins from v1.5.1 to v1.6.2. ([#6796](https://github.com/antrea-io/antrea/pull/6796), [@luolanzone])
- Push Antrea Ubuntu-based images to `ghcr.io`. ([#6834](https://github.com/antrea-io/antrea/pull/6834), [@antoninbas])
- Upgrade go-ipfix to 0.13.0, which includes performance improvements and supports sending multiple data records in the same IPFIX message. ([#6998](https://github.com/antrea-io/antrea/pull/6998), [@antoninbas])

### Fixed

- Add `-ComputerName localhost` explicitly for VMSwitch commands to avoid potential validation issues on Windows with Active Directory. ([#6985](https://github.com/antrea-io/antrea/pull/6985), [@XinShuYang])
- Fix that Antrea L7NetworkPolicies do not handle Service traffic correctly. ([#6941](https://github.com/antrea-io/antrea/pull/6941), [@hongliangl])
- Disable TX checksum offload for Antrea host gateway interface when `disableTXChecksumOffload` is set to `true`. ([#6843](https://github.com/antrea-io/antrea/pull/6843), [@hongliangl])
- Add `fqdnCacheMinTTL` configuration for Antrea-native policies which will ensure that resolved IPs are included in data path rules for at least the configured amount of time, in case some applications are caching the results of DNS queries. ([#6808](https://github.com/antrea-io/antrea/pull/6808), [@hkiiita])
- Ensure that OpenFlow rules for a Windows Pod are installed as long as the OpenFlow port is allocated, even if its state is incorrectly reported as "LINK_DOWN". ([#6889](https://github.com/antrea-io/antrea/pull/6889), [@wenyingd])
- Fix audit logging for default deny-all K8s NetworkPolicy rules. ([#6855](https://github.com/antrea-io/antrea/pull/6855), [@qiyueyao])
- Ensure that `promote_secondaries` is set on `IPAssigner` interfaces to avoid the automatic removal of all other IP addresses in the same subnet when the primary IP address is deleted. ([#6898](https://github.com/antrea-io/antrea/pull/6898) [#6900](https://github.com/antrea-io/antrea/pull/6900), [@antoninbas])
- Set the maximum packet size explicitly to fix an issue with reading `PacketCapture` pcapng files with `tcpdump` on macOS. ([#6804](https://github.com/antrea-io/antrea/pull/6804), [@hangyan])
- Reconcile Pods with `hostNetwork` after Antrea Agent is restarted on Windows. ([#6944](https://github.com/antrea-io/antrea/pull/6944), [@wenyingd])
- Create a new kubeconfig for `SupportBundleClient` to fix `antctl supportbundle` failures on Windows. ([#6840](https://github.com/antrea-io/antrea/pull/6840), [@XinShuYang])
- Fix PacketCapture bpf filter issue to avoid receiving packets when the socket is created but the bpf filter is not applied yet. ([#6821](https://github.com/antrea-io/antrea/pull/6821), [@hangyan])

[@Atish-iaf]: https://github.com/Atish-iaf
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@hangyan]: https://github.com/hangyan
[@hkiiita]: https://github.com/hkiiita
[@hongliangl]: https://github.com/hongliangl
[@luolanzone]: https://github.com/luolanzone
[@qiyueyao]: https://github.com/qiyueyao
[@tnqn]: https://github.com/tnqn
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu
