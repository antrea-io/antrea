# Changelog 1.12

## 1.12.3 - 2024-01-12

### Fixed

- Update `Install-WindowsCNI-Containerd.ps1` script to make it compatible with containerd 1.7. ([#5528](https://github.com/antrea-io/antrea/pull/5528), [@NamanAg30])
- Store NetworkPolicy in filesystem as fallback data source to let antre-agent fallback to use the files if it can't connect to antrea-controller on startup. ([#5739](https://github.com/antrea-io/antrea/pull/5739), [@tnqn])
- Support Local ExternalTrafficPolicy for Services with ExternalIPs when Antrea proxyAll mode is enabled. ([#5795](https://github.com/antrea-io/antrea/pull/5795), [@tnqn])
- Enable Pod network after realizing initial NetworkPolicies to avoid traffic from/to Pods bypassing NetworkPolicy when antrea-agent restarts. ([#5777](https://github.com/antrea-io/antrea/pull/5777), [@tnqn])
- Fix a deadlock issue in NetworkPolicy Controller which causes a FQDN resolution failure. ([#5566](https://github.com/antrea-io/antrea/pull/5566) [#5583](https://github.com/antrea-io/antrea/pull/5583), [@Dyanngg] [@tnqn])
- Skip enforcement of ingress NetworkPolicies rules for hairpinned Service traffic (Pod accessing itself via a Service). ([#5687](https://github.com/antrea-io/antrea/pull/5687) [#5705](https://github.com/antrea-io/antrea/pull/5705), [@GraysonWu])
- Set net.ipv4.conf.antrea-gw0.arp_announce to 1 to fix an ARP request leak when a Node or hostNetwork Pod accesses a local Pod and AntreaIPAM is enabled. ([#5657](https://github.com/antrea-io/antrea/pull/5657), [@gran-vmv])
- Fix `antctl tf` CLI failure when the Traceflow is using an IPv6 address. ([#5588](https://github.com/antrea-io/antrea/pull/5588), [@Atish-iaf])
- Fix NetworkPolicy span calculation to avoid out-dated data when multiple NetworkPolicies have the same selector. ([#5554](https://github.com/antrea-io/antrea/pull/5554), [@tnqn])
- Fix SSL library downloading failure in Install-OVS.ps1 on Windows. ([#5510](https://github.com/antrea-io/antrea/pull/5510), [@XinShuYang])
- Fix rollback invocation after CmdAdd failure in CNI server. ([#5548](https://github.com/antrea-io/antrea/pull/5548), [@antoninbas])
- Do not apply Egress to traffic destined for ServiceCIDRs to avoid performance issue and unexpected behaviors. ([#5495](https://github.com/antrea-io/antrea/pull/5495), [@tnqn])
- Do not delete IPv6 link-local route in route reconciler to fix cross-Node Pod traffic or Pod-to-external traffic. ([#5483](https://github.com/antrea-io/antrea/pull/5483), [@wenyingd])

## 1.12.2 - 2023-09-15

### Changed

- Change the default flow's action to `drop` in ARPSpoofGuardTable to effectively prevent ARP spoofing. ([#5378](https://github.com/antrea-io/antrea/pull/5378), [@hongliangl])
- Stop using `/bin/sh` and invoke the binary directly for OVS commands in Antrea Agent. ([#5364](https://github.com/antrea-io/antrea/pull/5364), [@antoninbas])
- Increase the rate limit setting of `PacketInMeter` and the size of `PacketInQueue`. ([#5460](https://github.com/antrea-io/antrea/pull/5460), [@GraysonWu])
- Revert a change to serve the v1alpha2 version of the ClusterGroup CRD again for the consistent API promotion plan. ([#5277](https://github.com/antrea-io/antrea/pull/5277), [@GraysonWu])
- Upgrade Open vSwitch to 2.17.7. ([#5225](https://github.com/antrea-io/antrea/pull/5225), [@antoninbas])

### Fixed

- Fix an Antrea Controller crash issue in handling empty Pod labels for LabelIdentity when the config `enableStretchedNetworkPolicy` is enabled for Antrea Multi-cluster. ([#5404](https://github.com/antrea-io/antrea/pull/5404) [#5449](https://github.com/antrea-io/antrea/pull/5449), [@Dyanngg])
- Remove NetworkPolicyStats dependency of MulticastGroup API to fix the empty list issue when users run `kubectl get multicastgroups` even when the Multicast is enabled. ([#5367](https://github.com/antrea-io/antrea/pull/5367), [@ceclinux])
- Do not attempt to join Windows agents to the memberlist cluster to avoid misleading error logs. ([#5434](https://github.com/antrea-io/antrea/pull/5434), [@tnqn])
- Fix the burst setting of the `PacketInQueue` to reduce the DNS response delay when a Pod has any FQDN policy applied. ([#5456](https://github.com/antrea-io/antrea/pull/5456), [@tnqn])
- Use OpenFlow group for Network Policy logging to avoid packet drops when massive connections hit the policy. ([#5061](https://github.com/antrea-io/antrea/pull/5061), [@wenyingd])

## 1.12.1 - 2023-07-04

### Fixed

- Bump up libOpenflow and ofnet versions to fix a PacketIn2 response parse error. ([#5154](https://github.com/antrea-io/antrea/pull/5154), [@wenyingd])
- Fix incorrect FlowMod message passing in the `modifyFlows` function of the OpenFlow client to avoid unexpected flow error. ([#5125](https://github.com/antrea-io/antrea/pull/5125), [@Dyanngg])
- Ensure the Egress IP is always correctly advertised to the network, including when the userspace ARP responder is not running or when the Egress IP is temporarily claimed by multiple Nodes. ([#5127](https://github.com/antrea-io/antrea/pull/5127), [@tnqn])
- Fix ClusterClaim webhook bug to avoid ClusterClaim deletion failure. ([#5075](https://github.com/antrea-io/antrea/pull/5075), [@luolanzone])
- Fix an issue in ANP with FQDN rules where TCP src port is unset on the TCP DNS response flow. ([#5078](https://github.com/antrea-io/antrea/pull/5078), [@wenyingd])
- Fix status report when no-op changes are applied to Antrea-native policies. ([#5096](https://github.com/antrea-io/antrea/pull/5096), [@tnqn])
- Fix IPv4 groups containing IPv6 endpoints mistakenly in dual-stack clusters in AntreaProxy implementation. ([#5194](https://github.com/antrea-io/antrea/pull/5194), [@tnqn])

## 1.12.0 - 2023-05-24

- The Multicast, TopologyAwareHints, NodeIPAM features are graduated from Alpha to Beta. The TopologyAwareHints, NodeIPAM features are enabled by default. Multicast can be enabled with a new Antrea Agent configuration parameter: `multicast.enable`.

### Added

- Add two new fields `sourcePort` and `sourceEndPort` in Antrea-native policy API to match traffic initiated from specific ports. ([#4687](https://github.com/antrea-io/antrea/pull/4687), [@Dyanngg])
- Add a new field `logLabel` to Antrea-native policy CRDs; the user-provided label is added to audit logs. ([#4748](https://github.com/antrea-io/antrea/pull/4748), [@qiyueyao])
- Add Antrea Controller API for querying Antrea Groups and ClusterGroups by IP addresses. ([#4807](https://github.com/antrea-io/antrea/pull/4807), [@Dyanngg])
- Add a new Antrea Controller configuration `clientCAFile` to allow user to specify client CA. ([#4664](https://github.com/antrea-io/antrea/pull/4664), [@wenyingd])
- Add support for ExternalIP in AntreaProxy to allow a Service to be accessed from outside the cluster using an external IP address. ([#4866](https://github.com/antrea-io/antrea/pull/4866), [@hongliangl])
- Add WireGuard tunnel mode for Antrea Multi-cluster to support encryption of the traffic between member clusters. ([#4737](https://github.com/antrea-io/antrea/pull/4737) [#4606](https://github.com/antrea-io/antrea/pull/4606) [#4848](https://github.com/antrea-io/antrea/pull/4848), [@hjiajing])
  * Refer to [Antrea Multi-cluster user guide](../docs/multicluster/user-guide.md) for more informantion about this feature.
- Add support for EndpointSlice API for Multi-cluster Services. When the EndpointSlice API is available for the cluster, EndpointSlice resources of the exported Service, rather than the Endpoints resource, will be processed. ([#4895](https://github.com/antrea-io/antrea/pull/4895), [@luolanzone])
- Add a new exporter to FlowAggregator to write flows to a local file. ([#4855](https://github.com/antrea-io/antrea/pull/4855), [@antoninbas])
- Add openEuler 22.03 as a new supported OS of Antrea, and update the [Kubernetes installer document](../docs/kubernetes-installers.md) with the information. ([#4957](https://github.com/antrea-io/antrea/pull/4957), [@ceclinux])

### Changed

- Deprecate Antrea Octant Plugin; it is replaced by a dedicated Antrea UI. ([#4825](https://github.com/antrea-io/antrea/pull/4825), [@antoninbas])
- Update Open vSwitch version to 2.17.6. ([#4959](https://github.com/antrea-io/antrea/pull/4959), [@tnqn])
- Update Windows OVS version to 2.16.7. ([#4705](https://github.com/antrea-io/antrea/pull/4705), [@XinShuYang])
- Add `status.egressIP` field for Egress to represent the effective Egress IP. ([#4603](https://github.com/antrea-io/antrea/pull/4603), [@tnqn])
- Add a new `Failed` phase in ANP status for the case when all Agents have reported the status and at least one failure is received. ([#4608](https://github.com/antrea-io/antrea/pull/4608), [@wenyingd])
- Check the existence of AntreaAgentInfo CRD before operating on it for worker Node or ExternalNode. ([#4762](https://github.com/antrea-io/antrea/pull/4762), [@wenyingd])
- Stop serving v1alpha2 version of the ClusterGroup CRD. ([#4812](https://github.com/antrea-io/antrea/pull/4812), [@antoninbas])
- Optimize the cached flows in Antrea Agent to reduce Agent memory usage. ([#4495](https://github.com/antrea-io/antrea/pull/4495), [@wenyingd])
- Replace PacketIn/Controller with PacketIn2/Controller2 to improve packetin handler. ([#4768](https://github.com/antrea-io/antrea/pull/4768), [@GraysonWu])
- Change to look up Pods by name instead of IP address to fetch labels in Flow Aggregator, to avoid obtaining incorrect Pods when Pod turnover is high. ([#4942](https://github.com/antrea-io/antrea/pull/4942), [@dreamtalen])
- Do not export Services of type ExternalName in Antrea Multi-cluster; this is consistent with the upstream Multi-cluster Service KEP. ([#4814](https://github.com/antrea-io/antrea/pull/4814), [@luolanzone])
- Update Multi-cluster user guide to provide more details for Gateway enablement. ([#4889](https://github.com/antrea-io/antrea/pull/4889), [@luolanzone])
- Update documentation for recent MetalLB versions. ([#4803](https://github.com/antrea-io/antrea/pull/4803), [@antoninbas])
- Add support for short-circuiting in AntreaProxy to ensure that the traffic from Pod/Node clients to
external addresses behaves the same way as the traffic from external clients to external addresses. ([#4815](https://github.com/antrea-io/antrea/pull/4815), [@hongliangl])
- Add OVS table name as label for `ovs_flow_count` Prometheus metrics. ([#4893](https://github.com/antrea-io/antrea/pull/4893), [@cr7258])
- Make IGMP query versions configurable for Antrea Multicast. ([#4876](https://github.com/antrea-io/antrea/pull/4876), [@ceclinux])
- Document the limit of maximum receiver group number on a Linux Node for Antrea Multicast. ([#4850](https://github.com/antrea-io/antrea/pull/4850), [@ceclinux])
- Upgrade K8s libraries to v0.26.4. ([#4935](https://github.com/antrea-io/antrea/pull/4935), [@heanlan])
- Bump up whereabouts to v0.6.1. ([#4988](https://github.com/antrea-io/antrea/pull/4988), [@hjiajing])

### Fixed

- Unify AntreaProxy behavior across Linux and Windows. Windows agents now configure only a single route for
all Service ClusterIPs and can restore routes after they are deleted by accident. ([#3889](https://github.com/antrea-io/antrea/pull/3889), [@hongliangl])
- Use LOCAL instead of CONTROLLER as the in_port of packet-out messages to fix a Windows agent crash issue. ([#4992](https://github.com/antrea-io/antrea/pull/4992), [@tnqn])
- Run agent modules that rely on Services access after AntreaProxy is ready to fix a Windows agent crash issue. ([#4946](https://github.com/antrea-io/antrea/pull/4946), [@tnqn])
- Improve Windows cleanup scripts to avoid unexpected failures. ([#4722](https://github.com/antrea-io/antrea/pull/4722) [#5013](https://github.com/antrea-io/antrea/pull/5013), [@wenyingd])
- Fix a bug that a deleted NetworkPolicy is still enforced when a new NetworkPolicy with the same name exists. ([#4986](https://github.com/antrea-io/antrea/pull/4986), [@tnqn])
- Make FQDN NetworkPolicy work for upper case FQDNs. ([#4934](https://github.com/antrea-io/antrea/pull/4934), [@GraysonWu])
- Fix a bug that K8s Networkpolicy audit logging doesn't work for Service access. ([#4780](https://github.com/antrea-io/antrea/pull/4780), [@qiyueyao])
- Fix Service not being updated correctly when stickyMaxAgeSeconds or InternalTrafficPolicy is updated. ([#4845](https://github.com/antrea-io/antrea/pull/4845), [@tnqn])
- Fix EndpointSlice API availablility check to resolve the issue that AntreaProxy always falls back to the Endpoints API when EndpointSlice is enabled. ([#4852](https://github.com/antrea-io/antrea/pull/4852), [@tnqn])
- In Antrea Agent Service CIDR discovery, prevent headless Services from updating the discovered Service CIDR to avoid overwriting the default route of host network unexpectedly. ([#5008](https://github.com/antrea-io/antrea/pull/5008), [@hongliangl])
- Fix the Antrea Agent crash issue when a large amount of multicast receivers with different multicast IPs on one Node start together. ([#4870](https://github.com/antrea-io/antrea/pull/4870), [@ceclinux])
- Fix the Antrea Agent crash issue which is caused by a concurrency bug in Multicast feature with encap mode. ([#4903](https://github.com/antrea-io/antrea/pull/4903), [@ceclinux])
- Use a random port when the UDP source port in a Traceflow is 0. ([#4963](https://github.com/antrea-io/antrea/pull/4963), [@gran-vmv])
- Set default flag to 2 for TCP Traceflow to fix a Traceflow timeout issue when the flag is not provided. ([#4948](https://github.com/antrea-io/antrea/pull/4948), [@luolanzone])
- Fix concurrent map write bug for LabelIdentity controller in Antrea Multi-cluster. ([#4994](https://github.com/antrea-io/antrea/pull/4994), [@Dyanngg])
- Fix a race condition between stale controller and ResourceImport reconcilers in Antrea Multi-cluster controller. ([#4853](https://github.com/antrea-io/antrea/pull/4853), [@Dyanngg])
- Bump up Suricata to 6.0.12 to fix a L7 NetworkPolicy issue. ([#4968](https://github.com/antrea-io/antrea/pull/4968), [@xliuxu])
- Fix discovered Service CIDR flapping on Agent start. ([#5017](https://github.com/antrea-io/antrea/pull/5017), [@tnqn])

[@Atish-iaf]: https://github.com/Atish-iaf
[@antoninbas]: https://github.com/antoninbas
[@ceclinux]: https://github.com/ceclinux
[@cr7258]: https://github.com/cr7258
[@dreamtalen]: https://github.com/dreamtalen
[@Dyanngg]: https://github.com/Dyanngg
[@gran-vmv]: https://github.com/gran-vmv
[@GraysonWu]: https://github.com/GraysonWu
[@NamanAg30]: https://github.com/NamanAg30
[@heanlan]: https://github.com/heanlan
[@hongliangl]: https://github.com/hongliangl
[@hjiajing]: https://github.com/hjiajing
[@luolanzone]: https://github.com/luolanzone
[@qiyueyao]: https://github.com/qiyueyao
[@tnqn]: https://github.com/tnqn
[@XinShuYang]: https://github.com/XinShuYang
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu
