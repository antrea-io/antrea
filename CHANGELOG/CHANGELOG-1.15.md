# Changelog 1.15

## 1.15.1 - 2024-03-25

### Changed

- Stop using `projects.registry.vmware.com` for user-facing images. ([#6073](https://github.com/antrea-io/antrea/pull/6073), [@antoninbas])
- Persist TLS certificate and key of antrea-controller and periodically sync the CA cert to improve robustness. ([#5955](https://github.com/antrea-io/antrea/pull/5955), [@tnqn])
- Disable cgo for all Antrea binaries. ([#5988](https://github.com/antrea-io/antrea/pull/5988), [@antoninbas])

### Fixed

- Disable `libcapng` to make logrotate run as root in UBI images to fix an OVS crash issue. ([#6052](https://github.com/antrea-io/antrea/pull/6052), [@xliuxu])
- Fix nil pointer dereference when ClusterGroup/Group is used in NetworkPolicy controller. ([#6077](https://github.com/antrea-io/antrea/pull/6077), [@tnqn])
- Fix race condition in agent Traceflow controller when a tag is associated again with a new Traceflow before the old Traceflow deletion event is processed. ([#5954](https://github.com/antrea-io/antrea/pull/5954), [@tnqn])
- Change the maximum flags from 7 to 255 to fix the wrong TCP flags validation issue in Traceflow CRD. ([#6050](https://github.com/antrea-io/antrea/pull/6050), [@gran-vmv])
- Update maximum number of buckets to 700 in OVS group add/insert_bucket message. ([#5942](https://github.com/antrea-io/antrea/pull/5942), [@hongliangl])
- Use 65000 MTU upper bound for interfaces in encap mode in case of large packets being dropped unexpectedly. ([#5997](https://github.com/antrea-io/antrea/pull/5997), [@antoninbas])
- Skip loading openvswitch kernel module if it's already built-in. ([#5979](https://github.com/antrea-io/antrea/pull/5979), [@antoninbas])

## 1.15.0 - 2024-01-26

### Added

- Support Egress using IPs from a subnet that is different from the default Node subnet
. ([#5799](https://github.com/antrea-io/antrea/pull/5799), [@tnqn])
    * Refer to [this document](https://github.com/antrea-io/antrea/blob/release-1.15/docs/egress.md) for more information about this feature.
- Add a migration tool to support migrating from other CNIs to Antrea. ([#5677](https://github.com/antrea-io/antrea/pull/5677), [@hjiajing])
    * Refer to [this document](https://github.com/antrea-io/antrea/blob/release-1.15/docs/migrate-to-antrea.md) for more information about this tool.
- Add L7 network flow export support in Antrea that enables exporting network flows with L7 protocol information. ([#5218](https://github.com/antrea-io/antrea/pull/5218), [@tushartathgur])
    * Refer to [this document](https://github.com/antrea-io/antrea/blob/release-1.15/docs/network-flow-visibility.md) for more information about this feature.
- Add a new feature `NodeNetworkPolicy` that allows users to apply `ClusterNetworkPolicy` to Kubernetes Nodes. ([#5658](https://github.com/antrea-io/antrea/pull/5658) [#5716](https://github.com/antrea-io/antrea/pull/5716), [@hongliangl] [@Atish-iaf])
    * Refer to [this document](https://github.com/antrea-io/antrea/blob/release-1.15/docs/antrea-node-network-policy.md) for more information about this feature.
- Add Antrea flexible IPAM support for the Multicast feature. ([#4922](https://github.com/antrea-io/antrea/pull/4922), [@ceclinux])
- Support Talos clusters to run Antrea as the CNI, and add Talos to the K8s installers document. ([#5718](https://github.com/antrea-io/antrea/pull/5718) [#5766](https://github.com/antrea-io/antrea/pull/5766), [@antoninbas])
- Support secondary network when the network configuration in `NetworkAttachmentDefinition` does not include IPAM configuration. ([#5762](https://github.com/antrea-io/antrea/pull/5762), [@jianjuns])
- Add instructions to install Antrea in `encap` mode in AKS. ([#5901](https://github.com/antrea-io/antrea/pull/5901), [@antoninbas])

### Changed

- Change secondary network Pod controller to subscribe to CNIServer events to support bridging and VLAN network. ([#5767](https://github.com/antrea-io/antrea/pull/5767), [@jianjuns])
- Use Antrea IPAM for secondary network support. ([#5427](https://github.com/antrea-io/antrea/pull/5427), [@jianjuns])
- Create different images for antrea-agent and antrea-controller to minimize the overall image size, speeding up the startup of both antrea-agent and antrea-controller. ([#5856](https://github.com/antrea-io/antrea/pull/5856) [#5902](https://github.com/antrea-io/antrea/pull/5902) [#5903](https://github.com/antrea-io/antrea/pull/5903), [@jainpulkit22])
- Don't create tunnel interface (antrea-tun0) when using Wireguard encryption mode. ([#5885](https://github.com/antrea-io/antrea/pull/5885) [#5909](https://github.com/antrea-io/antrea/pull/5909), [@antoninbas])
- Record an event when Egress IP assignment changes for better troubleshooting. ([#5765](https://github.com/antrea-io/antrea/pull/5765), [@jainpulkit22])
- Update Windows documentation with clearer installation guide and instructions. ([#5789](https://github.com/antrea-io/antrea/pull/5789), [@antoninbas])
- Enable IPv4/IPv6 forwarding on demand automatically to eliminate the need for user intervention or dependencies on other components. ([#5833](https://github.com/antrea-io/antrea/pull/5833), [@tnqn])
- Add ability to skip loading kernel modules in antrea-agent to support some specialized distributions (e.g.: Talos). ([#5754](https://github.com/antrea-io/antrea/pull/5754), [@antoninbas])
- Add NetworkPolicy rule name in Traceflow observation. ([#5667](https://github.com/antrea-io/antrea/pull/5667), [@Atish-iaf])
- Use Traceflow API v1beta1 instead of the deprecated API version in `antctl traceflow`. ([#5689](https://github.com/antrea-io/antrea/pull/5689), [@Atish-iaf])
- Replace `net.IP` with `netip.Addr` in FlowExporter which optimizes the memory usage and improves the performance of the FlowExporter. ([#5532](https://github.com/antrea-io/antrea/pull/5532), [@antoninbas])
- Update kubemark from v1.18.4 to v1.29.0 for antrea-agent-simulator. ([#5820](https://github.com/antrea-io/antrea/pull/5820), [@luolanzone])
- Upgrade CNI plugins to v1.4.0. ([#5747](https://github.com/antrea-io/antrea/pull/5747) [#5813](https://github.com/antrea-io/antrea/pull/5813), [@antoninbas] [@luolanzone])
- Update the document for Egress feature's options and usage on AWS cloud. ([#5436](https://github.com/antrea-io/antrea/pull/5436), [@tnqn])
- Add Flexible IPAM design details in `antrea-ipam.md`. ([#5339](https://github.com/antrea-io/antrea/pull/5339), [@gran-vmv])

### Fixed

- Fix incorrect MTU configurations for the WireGuard encryption mode and GRE tunnel mode. ([#5880](https://github.com/antrea-io/antrea/pull/5880) [#5926](https://github.com/antrea-io/antrea/pull/5926), [@hjiajing] [@tnqn])
- Prioritize L7 NetworkPolicy flows over `TrafficControl` to avoid a potential issue that a `TrafficControl` CR with a redirect action to the same Pod could bypass the L7 engine. ([#5768](https://github.com/antrea-io/antrea/pull/5768), [@hongliangl])
- Delete OVS port and flows before releasing Pod IP. ([#5788](https://github.com/antrea-io/antrea/pull/5788), [@tnqn])
- Store NetworkPolicy in filesystem as fallback data source to let antre-agent fallback to use the files if it can't connect to antrea-controller on startup. ([#5739](https://github.com/antrea-io/antrea/pull/5739), [@tnqn])
- Enable Pod network after realizing initial NetworkPolicies to avoid traffic from/to Pods bypassing NetworkPolicy when antrea-agent restarts. ([#5777](https://github.com/antrea-io/antrea/pull/5777), [@tnqn])
- Fix Clean-AntreaNetwork.ps1 invocation in Prepare-AntreaAgent.ps1 for containerized OVS on Windows. ([#5859](https://github.com/antrea-io/antrea/pull/5859), [@antoninbas])
- Add missing space to kubelet args in Prepare-Node.ps1 so that kubelet can start successfully on Windows. ([#5858](https://github.com/antrea-io/antrea/pull/5858), [@antoninbas])
- Fix `antctl trace-packet` command failure which is caused by missing arguments. ([#5838](https://github.com/antrea-io/antrea/pull/5838), [@luolanzone])
- Support Local ExternalTrafficPolicy for Services with ExternalIPs when Antrea proxyAll mode is enabled. ([#5795](https://github.com/antrea-io/antrea/pull/5795), [@tnqn])
- Set `net.ipv4.conf.antrea-gw0.arp_announce` to 1 to fix an ARP request leak when a Node or hostNetwork Pod accesses a local Pod and AntreaIPAM is enabled. ([#5657](https://github.com/antrea-io/antrea/pull/5657), [@gran-vmv])
- Skip enforcement of ingress NetworkPolicies rules for hairpinned Service traffic (Pod accessing itself via a Service). ([#5687](https://github.com/antrea-io/antrea/pull/5687) [#5705](https://github.com/antrea-io/antrea/pull/5705), [@GraysonWu])
- Add host-local IPAM GC on startup to avoid potential IP leak issue after antrea-agent restart. ([#5660](https://github.com/antrea-io/antrea/pull/5660), [@antoninbas])
- Fix the CrashLookBackOff issue when using the UBI-based image. ([#5723](https://github.com/antrea-io/antrea/pull/5723), [@antoninbas])
- Remove redundant log in `fillPodInfo`/`fillServiceInfo` to fix log flood issue, and update `DestinationServiceAddress` for deny connections. ([#5592](https://github.com/antrea-io/antrea/pull/5592) [#5704](https://github.com/antrea-io/antrea/pull/5704), [@yuntanghsu])
- Enhance HNS network initialization on Windows to avoid some corner cases. ([#5841](https://github.com/antrea-io/antrea/pull/5841), [@XinShuYang])
- Fix endpoint querier rule index in response to improve troubleshooting. ([#5783](https://github.com/antrea-io/antrea/pull/5783), [@qiyueyao])
- Avoid unnecessary rule reconciliations in FQDN controller. ([#5893](https://github.com/antrea-io/antrea/pull/5893), [@Dyanngg])
- Update Windows OVS download link to remove the invalid certificate preventing unsigned OVS driver installation. ([#5839](https://github.com/antrea-io/antrea/pull/5839), [@XinShuYang])
- Fix IP annotation not working on StatefulSets for Antrea FlexibleIPAM. ([#5715](https://github.com/antrea-io/antrea/pull/5715), [@gran-vmv])
- Add DHCP IP retries in `PrepareHNSNetwork` to fix potential IP retrieving failure. ([#5819](https://github.com/antrea-io/antrea/pull/5819), [@XinShuYang])
- Revise `antctl mc deploy` to support Antrea Multi-cluster deployment update when the manifests are changed. ([#5257](https://github.com/antrea-io/antrea/pull/5257), [@luolanzone])


[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@ceclinux]: https://github.com/ceclinux
[@gran-vmv]: https://github.com/gran-vmv
[@hjiajing]: https://github.com/hjiajing
[@hongliangl]: https://github.com/hongliangl
[@jainpulkit22]: https://github.com/jainpulkit22
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@qiyueyao]: https://github.com/qiyueyao
[@tnqn]: https://github.com/tnqn
[@tushartathgur]: https://github.com/tushartathgur
[@xliuxu]: https://github.com/xliuxu
[@yuntanghsu]: https://github.com/yuntanghsu
