# Changelog 2.1

## 2.1.0 - 2024-07-26

### Added

- Add a new feature `BGPPolicy` that allows users to run a BGP process on selected Kubernetes Nodes and advertise Service IPs, Pod IPs, and Egress IPs to remote BGP peers.
  - Add `BGPPolicy` API and Controller. ([#6009](https://github.com/antrea-io/antrea/pull/6009) [#6203](https://github.com/antrea-io/antrea/pull/6203), [@hongliangl])
  - Add BGP datapath interface and implement goBGP integration. ([#6447](https://github.com/antrea-io/antrea/pull/6447), [@hongliangl])
  - Add documentation for the `BGPPolicy` feature. ([#6524](https://github.com/antrea-io/antrea/pull/6524), [@hongliangl])
  - Refer to [this document](https://github.com/antrea-io/antrea/blob/release-2.1/docs/bgp-policy.md) for more information about this feature.
- Add a new feature `NodeLatencyMonitor` that allows users to do east/west connectivity monitoring and provides an API to query inter-Node latency. ([#6120](https://github.com/antrea-io/antrea/pull/6120) [#6392](https://github.com/antrea-io/antrea/pull/6392) [#6479](https://github.com/antrea-io/antrea/pull/6479), [@IRONICBo])
- Add two new antctl commands to validate a K8s Cluster before Antrea installation, and allow users to validate basic network and security functionalities after Antrea is installed.
  - Add `antctl check cluster` command to to ensure that a K8s cluster is configured properly before Antrea installation. ([#6278](https://github.com/antrea-io/antrea/pull/6278), [@kanha-gupta])
  - Add `antctl check installation` command to conduct Pod/Service connectivity checks and verify basic NetworkPolicy rules. ([#6133](https://github.com/antrea-io/antrea/pull/6133) [#6313](https://github.com/antrea-io/antrea/pull/6313) [#6367](https://github.com/antrea-io/antrea/pull/6367), [@kanha-gupta])
  - Add documentation for the new `antctl check` commands. ([#6373](https://github.com/antrea-io/antrea/pull/6373), [@kanha-gupta])
  - Refer to [this document](https://github.com/antrea-io/antrea/blob/release-2.1/docs/antctl.md#performing-checks-to-facilitate-installation-process) for more information about these new commands.

### Changed

- Ensure Antrea Proxy handles all Service traffic with proxyAll enabled, even when kube-proxy is present. ([#6308](https://github.com/antrea-io/antrea/pull/6308), [@hongliangl])
- Optimize the containerized OVS installation on Windows, manual installation of the OVS kernel driver is usually not required anymore. ([#6383](https://github.com/antrea-io/antrea/pull/6383), [@wenyingd])
- Add OVS driver installation in initContainer for Antrea Agent on Windows. ([#6312](https://github.com/antrea-io/antrea/pull/6312), [@XinShuYang])
- Use HostProcess container base image and buildx to build the Antrea Agent Windows image, Window Server 2019 and later are now supported with the same image, including Windows Server 2022. ([#6325](https://github.com/antrea-io/antrea/pull/6325), [@wenyingd])
- Support shared LoadBalancerIP for multiple Services by introducing a new annotation `service.antrea.io/allow-shared-load-balancer-ip: true`. ([#6480](https://github.com/antrea-io/antrea/pull/6480), [@tnqn])
- Promote feature `CleanupStaleUDPSvcConntrack` from Alpha to Beta. ([#6372](https://github.com/antrea-io/antrea/pull/6372), [@hongliangl])
- Always include Pod labels in FlowAggregator IPFIX template. ([#6418](https://github.com/antrea-io/antrea/pull/6418), [@antoninbas])
- Fix live config updates on IPFIXExporter for FlowAggregator. ([#6385](https://github.com/antrea-io/antrea/pull/6385), [@antoninbas])
- Improve handling of config changes in FlowAggregator to support updating `recordContents.podLabels` at runtime. ([#6378](https://github.com/antrea-io/antrea/pull/6378), [@antoninbas])
- Add an `EndpointResolver` to remove Antrea Agent's dependency on proxy to access Antrea Service. ([#6361](https://github.com/antrea-io/antrea/pull/6361), [@antoninbas])
- Replace `bincover` with built-in Go coverage profiling tool. ([#6090](https://github.com/antrea-io/antrea/pull/6090), [@shikharish])
- Trim unneeded fields stored in informers and Node objects to reduce memory footprint. ([#6317](https://github.com/antrea-io/antrea/pull/6317) [#6351](https://github.com/antrea-io/antrea/pull/6351), [@tnqn])
- Remove stale multicast routes to improve the readability of multicast routes. ([#3242](https://github.com/antrea-io/antrea/pull/3242), [@ceclinux])
- Add `srcPodIP` field in Traceflow observations. ([#6247](https://github.com/antrea-io/antrea/pull/6247), [@Atish-iaf])
- Use Helm to generate Antrea Windows manifests. ([#6360](https://github.com/antrea-io/antrea/pull/6360), [@shikharish])
- Upgrade CNI plugins from v1.4.1 to v1.5.1. ([#6475](https://github.com/antrea-io/antrea/pull/6475), [@antoninbas])
- Add documentation for the `sameLabels` feature in Antrea ClusterNetworkPolicy. ([#6280](https://github.com/antrea-io/antrea/pull/6280), [@Dyanngg])
- Add recommended usage of FQDN policies. ([#6389](https://github.com/antrea-io/antrea/pull/6389), [@Dyanngg])

### Fixed

- Fix NodePortLocal rules being deleted incorrectly due to PodIP recycle. ([#6531](https://github.com/antrea-io/antrea/pull/6531), [@tnqn])
- Fix "Access is denied" error when importing certificates into the trusted publishers store on Windows server 2022. ([#6529](https://github.com/antrea-io/antrea/pull/6529), [@wenyingd])
- Fix the Node network connection breaking when attaching a host interface to the secondary OVS bridge. ([#6504](https://github.com/antrea-io/antrea/pull/6504), [@wenyingd])
- Exclude terminated Pods from group members when calculating `AppliedToGroups` and `EgressGroups` to prevent NetworkPolicies or Egresses applying to wrong Pods. ([#6508](https://github.com/antrea-io/antrea/pull/6508), [@tnqn])
- Fix `install_cni_chaining` script not configuring CNI conf correctly with AKS or CNI chaining, when the CNI conf file is not ready. ([#6506](https://github.com/antrea-io/antrea/pull/6506), [@tnqn])
- Wait for OVS bridge datapath ID to be available after creating br-int to avoid failures when the Antrea Agent tries to query supported OVS datapath features. ([#6472](https://github.com/antrea-io/antrea/pull/6472), [@antoninbas])
- Fix a bug causing Antrea Proxy not to delete stale UDP conntrack entries for the virtual NodePort DNAT IP. ([#6379](https://github.com/antrea-io/antrea/pull/6379), [@hongliangl])
- Fix Antrea Agent crash when enabling `proxyAll` in `networkPolicyOnly` mode. ([#6259](https://github.com/antrea-io/antrea/pull/6259), [@hongliangl])
- Improve stale UDP conntrack entries deletion accuracy in Antrea Proxy. ([#6193](https://github.com/antrea-io/antrea/pull/6193), [@hongliangl])
- Remove unexpected `altname` after renaming interface to avoid failure when moving host interface to OVS bridge. ([#6321](https://github.com/antrea-io/antrea/pull/6321), [@gran-vmv])
- Avoid generating a zombie process when starting Suricata, the L7 ANP engine. ([#6366](https://github.com/antrea-io/antrea/pull/6366), [@hongliangl])
- Fix a single rule deletion bug for NodePortLocal on Linux and improve robustness of NPL rule cleanup. ([#6284](https://github.com/antrea-io/antrea/pull/6284), [@antoninbas])
- Delay removal of `flow-restore-wait` to fix traffic interruption issue when Antrea Agent restarts. ([#6342](https://github.com/antrea-io/antrea/pull/6342), [@antoninbas])
- Fix `antctl mc deploy` command usage to make the version parameter optional. ([#6287](https://github.com/antrea-io/antrea/pull/6287), [@roopeshsn])
- Fix inaccuracy in Traceflow user guide. ([#6319](https://github.com/antrea-io/antrea/pull/6319), [@antoninbas])


[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@IRONICBo]: https://github.com/IRONICBo
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@ceclinux]: https://github.com/ceclinux
[@gran-vmv]: https://github.com/gran-vmv
[@hongliangl]: https://github.com/hongliangl
[@kanha-gupta]: https://github.com/kanha-gupta
[@roopeshsn]: https://github.com/roopeshsn
[@shikharish]: https://github.com/shikharish
[@tnqn]: https://github.com/tnqn
[@wenyingd]: https://github.com/wenyingd