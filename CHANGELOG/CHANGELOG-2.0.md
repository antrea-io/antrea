# Changelog 2.0

*Some deprecated APIs have been removed in Antrea v2.0. Before upgrading, please read these [guidelines](https://github.com/antrea-io/antrea/blob/release-2.0/docs/versioning.md#upgrading-from-antrea-v1-to-antrea-v2) carefully.*

## 2.0.1 - 2024-06-20

### Changed

- Update CNI binaries version to v1.4.1. ([#6334](https://github.com/antrea-io/antrea/pull/6334), [@antoninbas])
- Add documentation for the sameLabels feature in ACNP. ([#6280](https://github.com/antrea-io/antrea/pull/6280), [@Dyanngg])

### Fixed

- Remove unexpected `altname` after renaming interface to avoid failure when moving host interface to OVS bridge. ([#6321](https://github.com/antrea-io/antrea/pull/6321), [@gran-vmv])
- Fix a single rule deletion bug for NodePortLocal on Linux and improve robustness of NPL rule cleanup. ([#6284](https://github.com/antrea-io/antrea/pull/6284), [@antoninbas])
- Fix a bug causing AntreaProxy not to delete stale UDP conntrack entries for the virtual NodePort DNAT IP. ([#6379](https://github.com/antrea-io/antrea/pull/6379), [@hongliangl])
- Improve stale UDP conntrack entries deletion accuracy in AntreaProxy. ([#6193](https://github.com/antrea-io/antrea/pull/6193), [@hongliangl])
- Fix antrea-agent crash when enabling proxyAll in networkPolicyOnly mode. ([#6259](https://github.com/antrea-io/antrea/pull/6259), [@hongliangl])
- Avoid generating defunct process when starting Suricata, the L7 ANP engine. ([#6366](https://github.com/antrea-io/antrea/pull/6366), [@hongliangl])
- Fix inaccuracy in Traceflow user guide. ([#6319](https://github.com/antrea-io/antrea/pull/6319), [@antoninbas])

## 2.0.0 - 2024-04-26

### Added

- Support `LoadBalancerIPMode` in AntreaProxy to implement K8s [KEP-1860](https://github.com/kubernetes/enhancements/tree/master/keps/sig-network/1860-kube-proxy-IP-node-binding). ([#6102](https://github.com/antrea-io/antrea/pull/6102), [@hongliangl])
- Add `sameLabels` field support for Antrea ClusterNetworkPolicy peer Namespace selection to allow users to create ACNPs that isolate Namespaces based on their label values. ([#4537](https://github.com/antrea-io/antrea/pull/4537), [@Dyanngg])
- Add multiple physical interfaces support for the secondary network bridge. ([#5959](https://github.com/antrea-io/antrea/pull/5959), [@aroradaman])
- Use a Node's primary NIC as the secondary OVS bridge physical interface. ([#6108](https://github.com/antrea-io/antrea/pull/6108), [@aroradaman])
- Add user documentation for Antrea native secondary network support. ([#6015](https://github.com/antrea-io/antrea/pull/6015) [#6042](https://github.com/antrea-io/antrea/pull/6042), [@jianjuns] [@antoninbas])
- Add a new versioned API `NetworkPolicyEvaluation` and a new antctl sub-command for querying the effective policy rule applied to particular traffic. ([#5740](https://github.com/antrea-io/antrea/pull/5740) [#6112](https://github.com/antrea-io/antrea/pull/6112), [@qiyueyao])

### Changed

- Multiple deprecated APIs, fields and options have been removed from Antrea.
  - Remove deprecated v1alpha1 CRDs `Tier`, `ClusterNetworkPolicy`, `NetworkPolicy`, `Traceflow` and `ExternalEntity`. ([#6162](https://github.com/antrea-io/antrea/pull/6162) [#6177](https://github.com/antrea-io/antrea/pull/6177) [#6238](https://github.com/antrea-io/antrea/pull/6238), [@luolanzone] [@hjiajing] [@antoninbas])
  - Remove deprecated v1alpha2 and v1alpha3 CRDs `ClusterGroups`, `ExternalIPPool`, `ClusterGroup` and `Group`. ([#6049](https://github.com/antrea-io/antrea/pull/6049) [#6239](https://github.com/antrea-io/antrea/pull/6239), [@luolanzone] [@antoninbas])
  - Remove deprecated `ServiceAccount` field in `ClusterSet` type for Antrea Multi-cluster. ([#6134](https://github.com/antrea-io/antrea/pull/6134), [@luolanzone])
  - Remove deprecated options `enableIPSecTunnel`,`multicastInterfaces`, `multicluster.enable` and `legacyCRDMirroring`. ([#5158](https://github.com/antrea-io/antrea/pull/5158), [@luolanzone])
  - Clean up unused code for NodePortLocal and remove the deprecated `nplPortRange` config. ([#5943](https://github.com/antrea-io/antrea/pull/5943), [@luolanzone])
  - Clean up deprecated APIServices. ([#6002](https://github.com/antrea-io/antrea/pull/6002), [@tnqn])
- Documentation has been updated to reflect recent changes and provide better guidance to users.
  - Add upgrade instructions for Antrea v2.0. ([#6261](https://github.com/antrea-io/antrea/pull/6261), [@antoninbas])
  - Update the OVS pipeline document and workflow diagram to keep them up to date. ([#5412](https://github.com/antrea-io/antrea/pull/5412), [@hongliangl])
  - Clarify documentation for `IPPool` and `ExternalIPPool` CRDs. ([#6183](https://github.com/antrea-io/antrea/pull/6183), [@antoninbas])
  - Document Pods using FQDN based policies must respect DNS TTL. ([#6230](https://github.com/antrea-io/antrea/pull/6230), [@tnqn])
  - Document the limitations of Audit Logging for policy rules. ([#6225](https://github.com/antrea-io/antrea/pull/6225), [@antoninbas])
- Optimizing Antrea binaries size.
  - Optimize package organization to reduce antctl binary size. ([#6037](https://github.com/antrea-io/antrea/pull/6037), [@tnqn])
  - Reduce antrea-cni binary size by removing unnecessary import packages. ([#6038](https://github.com/antrea-io/antrea/pull/6038), [@tnqn])
  - Strip all debug symbols from Go binaries by default. ([#6035](https://github.com/antrea-io/antrea/pull/6035), [@antoninbas])
  - Disable cgo for all Antrea binaries. ([#5988](https://github.com/antrea-io/antrea/pull/5988), [@antoninbas])
- Increase the minimum supported Kubernetes version to v1.19. ([#6089](https://github.com/antrea-io/antrea/pull/6089), [@hjiajing])
- Add OVS groups dump information to support bundle to help troubleshooting. ([#6195](https://github.com/antrea-io/antrea/pull/6195), [@shikharish])
- Add `egressNodeName` in flow records for Antrea Flow Aggregator. ([#6012](https://github.com/antrea-io/antrea/pull/6012), [@Atish-iaf])
- Add `EgressNode` field in the Traceflow Egress observation to include the name of the Egress Node. ([#5949](https://github.com/antrea-io/antrea/pull/5949), [@Atish-iaf])
- Upgrade `IPPool` CRD to v1beta1 and make the subnet definition consistent with the one in `ExternalIPPool` CRD. ([#6036](https://github.com/antrea-io/antrea/pull/6036), [@mengdie-song])
- Request basic memory for antrea-controller to improve its scheduling and reduce its OOM adjustment score, enhancing overall robustness. ([#6233](https://github.com/antrea-io/antrea/pull/6233), [@tnqn])
- Increase default rate limit of antrea-controller to improve performance for batch requests. ([#6231](https://github.com/antrea-io/antrea/pull/6231), [@tnqn])
- Remove Docker support for antrea-agent on Windows, update Windows documentation to remove all Docker-specific instructions, and all mentions of (userspace) kube-proxy. ([#6019](https://github.com/antrea-io/antrea/pull/6019) [#6255](https://github.com/antrea-io/antrea/pull/6255), [@XinShuYang] [@antoninbas])
- Stop publishing the legacy unified image. ([#6182](https://github.com/antrea-io/antrea/pull/6182), [@antoninbas])
- Avoid unnecessary DNS queries for FQDN rule of NetworkPolicy in antrea-agent. ([#6200](https://github.com/antrea-io/antrea/pull/6200), [@tnqn])
- Stop using `projects.registry.vmware.com` for user-facing images. ([#6073](https://github.com/antrea-io/antrea/pull/6073), [@antoninbas])
- Fall back to lenient decoding when strict decoding config fails to tolerate unknown fields and duplicate fields, ensuring forward compatibility of configurations. ([#6156](https://github.com/antrea-io/antrea/pull/6156), [@tnqn])
- Skip loading `openvswitch` kernel module if it's already built-in. ([#5979](https://github.com/antrea-io/antrea/pull/5979), [@antoninbas])
- Persist TLS certificate and key of antrea-controller and sync the CA cert periodically to improve robustness. ([#5955](https://github.com/antrea-io/antrea/pull/5955) [#6205](https://github.com/antrea-io/antrea/pull/6205), [@tnqn])
- Add more validations for `ExternalIPPool` CRD to improve robustness. ([#5898](https://github.com/antrea-io/antrea/pull/5898), [@aroradaman])
- Add Antrea L7 NetworkPolicy logs for `allowed` HTTP traffic. ([#6014](https://github.com/antrea-io/antrea/pull/6014), [@qiyueyao])
- Update maximum number of buckets to 700 in OVS group add/insert_bucket message. ([#5942](https://github.com/antrea-io/antrea/pull/5942), [@hongliangl])
- Add a flag for antctl to print OVS table names when users run `antctl get ovsflows --table-names-only`. ([#5895](https://github.com/antrea-io/antrea/pull/5895) [#6100](https://github.com/antrea-io/antrea/pull/6100), [@luolanzone])
- Improve log message when antrea-agent fails to join a new Node. ([#6048](https://github.com/antrea-io/antrea/pull/6048), [@roopeshsn])
- Remove the prefix `rancher-wins` when collecting antrea-agent logs on Windows. ([#6223](https://github.com/antrea-io/antrea/pull/6223), [@wenyingd])
- Upgrade K8s libraries to v0.29.2. ([#5843](https://github.com/antrea-io/antrea/pull/5843), [@hjiajing])
- Upgrade base image from UBI8 to UBI9 for Antrea UBI images. ([#5737](https://github.com/antrea-io/antrea/pull/5737), [@xliuxu])

### Fixed

- Fix nil pointer dereference when `ClusterGroup`/`Group` is used in NetworkPolicy controller. ([#6077](https://github.com/antrea-io/antrea/pull/6077), [@tnqn])
- Disable `libcapng` to make logrotate run as root in UBI images to fix an OVS crash issue. ([#6052](https://github.com/antrea-io/antrea/pull/6052), [@xliuxu])
- Fix a race condition in antrea-agent Traceflow controller when a tag is associated again with a new Traceflow before the old Traceflow deletion event is processed. ([#5954](https://github.com/antrea-io/antrea/pull/5954), [@tnqn])
- Change the maximum flags from 7 to 255 to fix the wrong TCP flags validation issue in `Traceflow` CRD. ([#6050](https://github.com/antrea-io/antrea/pull/6050), [@gran-vmv])
- Use 65000 MTU upper bound for interfaces in `encap` mode to account for the MTU automatically configured by OVS on tunnel ports, and avoid packet drops on some clusters. ([#5997](https://github.com/antrea-io/antrea/pull/5997), [@antoninbas])
- Install multicast related iptables rules only on IPv4 chains to fix the antrea-agent initialization failure occurred when the Multicast feature is enabled in dual-stack clusters. ([#6123](https://github.com/antrea-io/antrea/pull/6123), [@wenyingd])
- Remove incorrect AntreaProxy warning on Windows when `proxyAll` is disabled. ([#6242](https://github.com/antrea-io/antrea/pull/6242), [@antoninbas])
- Explicitly set kubelet's log files in Prepare-Node.ps1 on Windows, to ensure that they are included in support bundle collections. ([#6221](https://github.com/antrea-io/antrea/pull/6221), [@wenyingd])
- Add validation on antrea-agent options to fail immediately when encryption is requested and the Multicast feature enabled. ([#5920](https://github.com/antrea-io/antrea/pull/5920), [@wenyingd])
- Don't print the incorrect warning message when users run `antrea-controller --version` outside of K8s. ([#5993](https://github.com/antrea-io/antrea/pull/5993), [@prakrit55])
- Record event when EgressIP is uninstalled from a Node and remains unassigned. ([#6011](https://github.com/antrea-io/antrea/pull/6011), [@jainpulkit22])
- Fix a bug that the local traffic cannot be identified on `networkPolicyOnly` mode. ([#6251](https://github.com/antrea-io/antrea/pull/6251), [@hongliangl])
- Use reserved OVS controller ports for the default Antrea ports to fix a potential `ofport` mismatch issue. ([#6202](https://github.com/antrea-io/antrea/pull/6202), [@antoninbas])

[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@aroradaman]: https://github.com/aroradaman
[@gran-vmv]: https://github.com/gran-vmv
[@hangyan]: https://github.com/hangyan
[@hjiajing]: https://github.com/hjiajing
[@hongliangl]: https://github.com/hongliangl
[@jainpulkit22]: https://github.com/jainpulkit22
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@mengdie-song]: https://github.com/mengdie-song
[@prakrit55]: https://github.com/prakrit55
[@roopeshsn]: https://github.com/roopeshsn
[@qiyueyao]: https://github.com/qiyueyao
[@shikharish]: https://github.com/shikharish
[@tnqn]: https://github.com/tnqn
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu
