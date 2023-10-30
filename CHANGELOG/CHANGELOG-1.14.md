# Changelog 1.14

## 1.14.0 - 2023-10-27

### Added

- Add rate-limit config to Egress to specify the rate limit of north-south egress traffic of this Egress. ([#5425](https://github.com/antrea-io/antrea/pull/5425), [@GraysonWu])
- Add `IPAllocated` and `IPAssigned` conditions to Egress status to improve Egress visibility. ([#5282](https://github.com/antrea-io/antrea/pull/5282), [@AJPL88] [@tnqn])
- Add goroutine stack dump in `SupportBundle` for both Antrea Agent and Antrea Controller. ([#5538](https://github.com/antrea-io/antrea/pull/5538), [@aniketraj1947])
- Add "X-Load-Balancing-Endpoint-Weight" header to AntreaProxy Service healthcheck. ([#5299](https://github.com/antrea-io/antrea/pull/5299), [@hongliangl])
- Add log rotation configuration in Antrea Agent config for audit logs. ([#5337](https://github.com/antrea-io/antrea/pull/5337) [#5366](https://github.com/antrea-io/antrea/pull/5366), [@antoninbas] [@mengdie-song])
- Add GroupMembers API Pagination support to Antrea Go clientset. ([#5533](https://github.com/antrea-io/antrea/pull/5533), [@qiyueyao])
- Add Namespaced Group Membership API for Antrea Controller. ([#5380](https://github.com/antrea-io/antrea/pull/5380), [@qiyueyao])
- Support Pod secondary interfaces on VLAN network. ([#5341](https://github.com/antrea-io/antrea/pull/5341) [#5365](https://github.com/antrea-io/antrea/pull/5365) [#5279](https://github.com/antrea-io/antrea/pull/5279), [@jianjuns])
- Enable Windows OVS container to run on pristine host environment, without requiring some dependencies to be installed manually ahead of time. ([#5440](https://github.com/antrea-io/antrea/pull/5440), [@NamanAg30])
- Update `Install-WindowsCNI-Containerd.ps1` script to make it compatible with containerd 1.7. ([#5528](https://github.com/antrea-io/antrea/pull/5528), [@NamanAg30])
- Add a new all-in-one manifest for the Multi-cluster leader cluster, and update the Multi-cluster user guide. ([#5389](https://github.com/antrea-io/antrea/pull/5389) [#5531](https://github.com/antrea-io/antrea/pull/5531), [@luolanzone])
- Clean up auto-generated resources in leader and member clusters when a ClusterSet is deleted, and recreate resources when a member cluster rejoins the ClusterSet. ([#5351](https://github.com/antrea-io/antrea/pull/5351) [#5410](https://github.com/antrea-io/antrea/pull/5410), [@luolanzone])

### Changed

- Multiple APIs are promoted from beta to GA. The corresponding feature gates are removed from Antrea config files.
  - Promote feature gate EndpointSlice to GA. ([#5393](https://github.com/antrea-io/antrea/pull/5393), [@hongliangl])
  - Promote feature gate NodePortLocal to GA. ([#5491](https://github.com/antrea-io/antrea/pull/5491), [@hjiajing])
  - Promote feature gate AntreaProxy to GA, and add an option `antreaProxy.enable` to allow users to disable this feature. ([#5401](https://github.com/antrea-io/antrea/pull/5401), [@hongliangl])
- Make antrea-controller not tolerate Node unreachable to speed up the failover process. ([#5521](https://github.com/antrea-io/antrea/pull/5521), [@tnqn])
- Improve `antctl get featuregates` output. ([#5314](https://github.com/antrea-io/antrea/pull/5314), [@cr7258])
- Increase the rate limit setting of `PacketInMeter` and the size of `PacketInQueue`. ([#5460](https://github.com/antrea-io/antrea/pull/5460), [@GraysonWu])
- Add `hostAliases` to Helm values for Flow Aggregator. ([#5386](https://github.com/antrea-io/antrea/pull/5386), [@yuntanghsu])
- Decouple Audit logging from AntreaPolicy feature gate to enable logging for NetworkPolicy when AntreaPolicy is disabled. ([#5352](https://github.com/antrea-io/antrea/pull/5352), [@qiyueyao])
- Change Traceflow CRD validation to webhook validation. ([#5230](https://github.com/antrea-io/antrea/pull/5230), [@shi0rik0])
- Stop using `/bin/sh` and invoke the binary directly for OVS commands in Antrea Agent. ([#5364](https://github.com/antrea-io/antrea/pull/5364), [@antoninbas])
- Install flows for nested Services in `EndpointDNAT` only when Antrea Multi-cluster is enabled. ([#5411](https://github.com/antrea-io/antrea/pull/5411), [@hongliangl])
- Make rate-limiting of PacketIn messages configurable; the same rate-limit value applies to each feature that is dependent on PacketIn messages (e.g, Traceflow) but the limit is enforced independently for each feature. ([#5450](https://github.com/antrea-io/antrea/pull/5450), [@GraysonWu])
- Change the default flow's action to `drop` in `ARPSpoofGuardTable` to effectively prevent ARP spoofing. ([#5378](https://github.com/antrea-io/antrea/pull/5378), [@hongliangl])
- Remove auto-generated suffix from ConfigMap names, and add config checksums as Deployment annotations in Windows manifests, to avoid stale ConfigMaps when updating Antrea while preserving automatic rolling of Pods. ([#5545](https://github.com/antrea-io/antrea/pull/5545), [@Atish-iaf])
- Add a ClusterSet deletion webhook for the leader cluster to reject ClusterSet deletion if there is any MemberClusterAnnounce. ([#5475](https://github.com/antrea-io/antrea/pull/5475), [@luolanzone])
- Update Go version to v1.21. ([#5377](https://github.com/antrea-io/antrea/pull/5377), [@antoninbas])

### Fixed

- Remove the dependency of the MulticastGroup API on the NetworkPolicyStats feature gate, to fix the empty list issue when users run `kubectl get multicastgroups` even when the Multicast is enabled. ([#5367](https://github.com/antrea-io/antrea/pull/5367), [@ceclinux])
- Fix `antctl tf` CLI failure when the Traceflow is using an IPv6 address. ([#5588](https://github.com/antrea-io/antrea/pull/5588), [@Atish-iaf])
- Fix a deadlock issue in NetworkPolicy Controller which causes a FQDN resolution failure. ([#5566](https://github.com/antrea-io/antrea/pull/5566) [#5583](https://github.com/antrea-io/antrea/pull/5583), [@Dyanngg] [@tnqn])
- Fix NetworkPolicy span calculation to avoid out-dated data when multiple NetworkPolicies have the same selector. ([#5554](https://github.com/antrea-io/antrea/pull/5554), [@tnqn])
- Use the first matching address when getting Node address to find the correct transport interface. ([#5529](https://github.com/antrea-io/antrea/pull/5529), [@xliuxu])
- Fix rollback invocation after CmdAdd failure in CNI server and improve logging. ([#5548](https://github.com/antrea-io/antrea/pull/5548), [@antoninbas])
- Add error log when Antrea network's MTU exceeds Suricata's maximum supported value. ([#5408](https://github.com/antrea-io/antrea/pull/5408), [@hongliangl])
- Do not delete IPv6 link-local route in route reconciler to fix cross-Node Pod traffic or Pod-to-external traffic. ([#5483](https://github.com/antrea-io/antrea/pull/5483), [@wenyingd])
- Do not apply Egress to traffic destined for ServiceCIDRs to avoid performance issue and unexpected behaviors. ([#5495](https://github.com/antrea-io/antrea/pull/5495), [@tnqn])
- Unify TCP and UDP DNS interception flows to fix invalid flow matching for DNS responses. ([#5392](https://github.com/antrea-io/antrea/pull/5392), [@GraysonWu])
- Fix the burst setting of the `PacketInQueue` to reduce the DNS response delay when a Pod has any FQDN policy applied. ([#5456](https://github.com/antrea-io/antrea/pull/5456), [@tnqn])
- Fix SSL library downloading failure in Install-OVS.ps1 on Windows. ([#5510](https://github.com/antrea-io/antrea/pull/5510), [@XinShuYang])
- Do not attempt to join Windows antrea-agents to the memberlist cluster to avoid misleading error logs. ([#5434](https://github.com/antrea-io/antrea/pull/5434), [@tnqn])
- Fix an issue that antctl proxy is not using the user specified port. ([#5435](https://github.com/antrea-io/antrea/pull/5435), [@tnqn])
- Enable IPv6 on OVS internal port if needed in bridging mode to fix agent crash issue when IPAM is enabled. ([#5409](https://github.com/antrea-io/antrea/pull/5409), [@antoninbas])
- Fix missing protocol in Service when processing ANP named ports to ensure rule can be enforced correctly in OVS. ([#5370](https://github.com/antrea-io/antrea/pull/5370), [@Dyanngg])
- Fix error log when agent fails to connect to K8s API. ([#5353](https://github.com/antrea-io/antrea/pull/5353), [@tnqn])
- Fix a bug that ClusterSet status is not updated in Antrea Multi-cluster. ([#5338](https://github.com/antrea-io/antrea/pull/5338), [@luolanzone])
- Fix an Antrea Controller crash issue in handling empty Pod labels for LabelIdentity when the config enableStretchedNetworkPolicy is enabled for Antrea Multi-cluster. ([#5404](https://github.com/antrea-io/antrea/pull/5404) [#5449](https://github.com/antrea-io/antrea/pull/5449), [@Dyanngg])
- Always initialize `ovs_meter_packet_dropped_count` metrics to fix a bug that the metrics are not showing up if OVS Meter is not supported on the system. ([#5413](https://github.com/antrea-io/antrea/pull/5413), [@tnqn])
- Skip starting modules which are not required by VM Agent to fix logs flood due to RBAC warning. ([#5391](https://github.com/antrea-io/antrea/pull/5391), [@mengdie-song])

[@AJPL88]: https://github.com/AJPL88
[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@NamanAg30]: https://github.com/NamanAg30
[@XinShuYang]: https://github.com/XinShuYang
[@aniketraj1947]: https://github.com/aniketraj1947
[@antoninbas]: https://github.com/antoninbas
[@ceclinux]: https://github.com/ceclinux
[@cr7258]: https://github.com/cr7258
[@hongliangl]: https://github.com/hongliangl
[@hjiajing]: https://github.com/hjiajing
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@mengdie-song]: https://github.com/mengdie-song
[@qiyueyao]: https://github.com/qiyueyao
[@shi0rik0]: https://github.com/shi0rik0
[@tnqn]: https://github.com/tnqn
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu
[@yuntanghsu]: https://github.com/yuntanghsu