# Changelog 2.7

## 2.7.0 - 2026-08-15

> **Important:** this release authenticates and encrypts Antrea Agent gossip
> traffic by default, preventing unauthorized hosts from influencing the cluster
> membership state and impacting the features that depend on it (IP ownership for
> Egress and ServiceExternalIP specifically). Refer to
> [#8259](https://github.com/antrea-io/antrea/pull/8259). A rolling update of the
> antrea-agent DaemonSet on a large cluster could disrupt Egress /
> ServiceExternalIP for users, for the duration of the update. Refer to the
> [upgrade guide](https://github.com/antrea-io/antrea/blob/main/docs/egress.md#enabling-encryption-when-upgrading-an-existing-cluster)
> for the recommended upgrade procedure.

### Added

- Adds end-to-end support for exporting and aggregating External-to-Pod flows and preserving the original external source IP. ([#7884](https://github.com/antrea-io/antrea/pull/7884), [@Dyanngg])
- Add IPv6 support for Antrea SecondaryNetwork. ([#7762](https://github.com/antrea-io/antrea/pull/7762), [@wenqiq])
- Add AntreaNodeConfig CRD that allows users to define secondary OVS bridge and physical interface configuration per node pool. ([#7812](https://github.com/antrea-io/antrea/pull/7812) [#7835](https://github.com/antrea-io/antrea/pull/7835) [#8039](https://github.com/antrea-io/antrea/pull/8039) [#8068](https://github.com/antrea-io/antrea/pull/8068) [#8149](https://github.com/antrea-io/antrea/pull/8149), [@luolanzone])
- Add FlowStreamService for Flow Aggregator. ([#7937](https://github.com/antrea-io/antrea/pull/7937), [@Dyanngg])
- Support external flows from NodePortLocal in flow exporter, preserving the original external client IP and destination node port. ([#8001](https://github.com/antrea-io/antrea/pull/8001), [@Dyanngg])
- Add ClusterNetworkPolicy network policy type in flow record for flows hitting ClusterNetworkPolicies. ([#8210](https://github.com/antrea-io/antrea/pull/8210), [@Dyanngg])
- Support ClusterNetworkPolicy in network-policy-api v0.2.0. ([#8018](https://github.com/antrea-io/antrea/pull/8018) [#8044](https://github.com/antrea-io/antrea/pull/8044), [@Dyanngg])
- Support IPv6 SFTP URL in PacketCapture CRD. ([#8250](https://github.com/antrea-io/antrea/pull/8250), [@hangyan])

### Changed

- Use ring buffer for Flow Aggregator exporters. ([#7931](https://github.com/antrea-io/antrea/pull/7931), [@antoninbas])
- Enforce strict Pod IP and IPPool address family validation to reject requests that assign multiple IPs of the same family to a single Pod. ([#7994](https://github.com/antrea-io/antrea/pull/7994), [@wenqiq])
- Exports aggregated flow records as soon as they become ReadyToSend. ([#7997](https://github.com/antrea-io/antrea/pull/7997), [@antoninbas])
- Sync NodeIPAM range allocator with upstream Kubernetes. ([#7917](https://github.com/antrea-io/antrea/pull/7917), [@antoninbas])
- Change OFBridge get/set OFSwitch to use an atomic pointer. ([#8167](https://github.com/antrea-io/antrea/pull/8167), [@jianjuns])
- Annotate end-of-initial-events bookmark with the resourceVersion and initial-events-end annotation required by watch-list semantics, fixing a cache sync stalled issue for watch-list clients. ([#8124](https://github.com/antrea-io/antrea/pull/8124), [@stroebs])
- Log invalid Namespace enable-logging annotation values. ([#8135](https://github.com/antrea-io/antrea/pull/8135), [@Anand-240])
- Include ip rule and ip route show table all in Agent SupportBundle. ([#8015](https://github.com/antrea-io/antrea/pull/8015), [@mail2sudheerobbu-oss])
- Strengthen IPPool status retry on concurrent updates. ([#7996](https://github.com/antrea-io/antrea/pull/7996), [@wenqiq])
- Improve tombstone objects handling in multiple controller handlers. ([#7949](https://github.com/antrea-io/antrea/pull/7949) [#7958](https://github.com/antrea-io/antrea/pull/7958) [#7964](https://github.com/antrea-io/antrea/pull/7964), [@OmAmbole009])
- Build flow-aggregator image for multiple architectures. ([#8002](https://github.com/antrea-io/antrea/pull/8002), [@antoninbas])
- Update the Antrea module path to `antrea.io/antrea/v2` to comply with Go's semantic versioning requirements for v2 and later releases. ([#7747](https://github.com/antrea-io/antrea/pull/7747), [@alronova])
- Ignore user-managed VLAN sub-interfaces in the IP assigner to exclude them from stale Egress cleanup, preventing Node connectivity disruption. ([#7898](https://github.com/antrea-io/antrea/pull/7898), [@antoninbas])
- Authenticate and encrypt memberlist gossip traffic by default to prevent unauthorized hosts from influencing Egress and ServiceExternalIP ownership. ([#8259](https://github.com/antrea-io/antrea/pull/8259), [@antoninbas])
- Upgrade Linux OVS to version 3.7.1. ([#8082](https://github.com/antrea-io/antrea/pull/8082), [@luolanzone])
- Update CNI plugins to 1.9.1 with CVE fix. ([#7894](https://github.com/antrea-io/antrea/pull/7894), [@luolanzone])
- Migrate github.com/osrg/gobgp/v3 to github.com/osrg/gobgp/v4. ([#8066](https://github.com/antrea-io/antrea/pull/8066), [@hongliangl])
- Update sigs.k8s.io/mcs-api to v0.5.0. ([#8054](https://github.com/antrea-io/antrea/pull/8054), [@luolanzone])
- Migrate UUID library from google/uuid to gofrs/uuid/v5. ([#8055](https://github.com/antrea-io/antrea/pull/8055), [@hangyan])
- Update lumberjack dependency to use antrea-io fork. ([#8053](https://github.com/antrea-io/antrea/pull/8053), [@hangyan])
- Update mdlayher dependencies to use antrea-io forks. ([#8046](https://github.com/antrea-io/antrea/pull/8046), [@hangyan])
- Upgrade K8s dependencies to 1.36.1 and regenerate code. ([#8057](https://github.com/antrea-io/antrea/pull/8057), [@antoninbas])
- Replace blang/semver with golang.org/x/mod/semver in Antrea code. ([#8031](https://github.com/antrea-io/antrea/pull/8031), [@luolanzone])
- Replace OVSDB-golang-lib with antrea-io/libovsdb. ([#8092](https://github.com/antrea-io/antrea/pull/8092) [#8169](https://github.com/antrea-io/antrea/pull/8169), [@hongliangl] [@luolanzone])
- Migrate YAML dependencies from gopkg.in to go.yaml.in and update YAML handling to v3. ([#7956](https://github.com/antrea-io/antrea/pull/7956), [#7984](https://github.com/antrea-io/antrea/pull/7984), [@SharanRP])
- Remove a few unmaintained dependencies, including lithammer/dedent, davecgh/go-spew, and github.com/munnerz/goautoneg. ([#8032](https://github.com/antrea-io/antrea/pull/8032), [@luolanzone])
- Deprecate the 'destinationClusterIP' IE for 'destinationServiceIP' in flow visibility. ([#8157](https://github.com/antrea-io/antrea/pull/8157), [@Dyanngg])
- Add documentation for restricting multicluster ServiceExports to mitigate the risk of arbitrary Namespace imports. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@luolanzone] [@antoninbas])
- Require Multi-cluster member tokens to be bound to a ClusterID and remove the shared default member token. ([#8265](https://github.com/antrea-io/antrea/pull/8265), [@luolanzone] [@antoninbas])

### Fixed

- Fix NetworkPolicyEvaluation to exclude host-network and terminated Pods from applicable policy results. ([#8042](https://github.com/antrea-io/antrea/pull/8042), [@Dyanngg])
- Start member StaleResCleanupController after cache is synced for Antrea Multi-cluster. ([#8180](https://github.com/antrea-io/antrea/pull/8180), [@Archong-Liu])
- Add missing continue statement in syncWireGuard. ([#7951](https://github.com/antrea-io/antrea/pull/7951), [@Denyme24])
- Exclude terminated Pods in podstore indexer to ensure Flow Aggregator always correlates flows to the correct currently running ones. ([#8043](https://github.com/antrea-io/antrea/pull/8043), [@Dyanngg])
- Fix socket leak in NPL AddRule when iptables rule installation fails. ([#8110](https://github.com/antrea-io/antrea/pull/8110), [@aneek22112007-tech])
- Fix NetNat log format and newlines on Windows. ([#8121](https://github.com/antrea-io/antrea/pull/8121), [@hongliangl])
- Fix WireGuard tunnel destination metadata in Traceflow observations for remote Pod forwarding. ([#8090](https://github.com/antrea-io/antrea/pull/8090), [@xliuxu])
- Fixes inconsistent state in the conntrack flow exporter bulk deletion path by ensuring DeleteAllConnections() resets all related state. ([#7935](https://github.com/antrea-io/antrea/pull/7935), [@Denyme24])
- Add nil-safe handling of StartTs / EndTs when converting aggregated flows to the legacy map format in Antrea FlowAggregator. ([#7929](https://github.com/antrea-io/antrea/pull/7929), [@OmAmbole009])
- Fix incorrect bitmap index in AllocateRange causing double allocation. ([#7945](https://github.com/antrea-io/antrea/pull/7945), [@OmAmbole009])
- Fix NetworkPolicy stats panic caused by stale OpenFlow flows after pipeline table changes. ([#7952](https://github.com/antrea-io/antrea/pull/7952), [@luolanzone])
- Fix nil IPs from empty AntreaIPAM Pod IP tokens. ([#7930](https://github.com/antrea-io/antrea/pull/7930), [@wenqiq])
- Fix wrong error variable in updateSupportBundleCollectionStatus. ([#7923](https://github.com/antrea-io/antrea/pull/7923), [@Anujkumar9081])
- Fix panic in NodeIPsIndexFunc for Nodes without IPs. ([#7916](https://github.com/antrea-io/antrea/pull/7916), [@antoninbas])
- Clamp negative IPFIX delta counts to 0 instead of wrapping on Antrea FlowExporter. ([#7883](https://github.com/antrea-io/antrea/pull/7883), [@Denyme24])
- Fix OpenAPI schema generation for Antrea API. ([#7901](https://github.com/antrea-io/antrea/pull/7901), [@antoninbas])
- Update the leader Multicluster controller’s stale resource cleanup loop to run as a controller-runtime Manager runnable to fix unexpected log message about cache not started. ([#8133](https://github.com/antrea-io/antrea/pull/8133), [@aclfe])
- Fix FlowAggregator IPFIX export missing proxySnat fields. ([#8227](https://github.com/antrea-io/antrea/pull/8227), [@Dyanngg])
- Fix scrambled Aggregate-mode stats/throughput IEs in FlowAggregator IPFIX export. ([#8228](https://github.com/antrea-io/antrea/pull/8228), [@Dyanngg])
- Recover Service group install after a timed-out bundle commit. ([#8190](https://github.com/antrea-io/antrea/pull/8190), [@hongliangl])
- Return the error when adding messages to a bundle fails, so failed OVS flow installations are retried. ([#8211](https://github.com/antrea-io/antrea/pull/8211), [@hongliangl])
- Fix nil transaction panic in ClickHouse batchCommitAll when BeginTx fails. ([#8214](https://github.com/antrea-io/antrea/pull/8214), [@SAY-5])
- Close files explicitly in the extraction loop to prevent file descriptor exhaustion in compress utility. ([#8197](https://github.com/antrea-io/antrea/pull/8197), [@magic-peach])
- Fix host-local IPAM GC releasing in-use Pod IPs. ([#8240](https://github.com/antrea-io/antrea/pull/8240), [@antoninbas])
- Retry AntreaProxy Service synchronization after transient failures to ensure datapath state converges. ([#8206](https://github.com/antrea-io/antrea/pull/8206), [@hongliangl])
- Bind Multi-cluster MemberClusterAnnounce and ResourceExport operations to the requesting member's identity to prevent ClusterID spoofing and unauthorized ResourceExports. ([#8265](https://github.com/antrea-io/antrea/pull/8265), [@luolanzone] [@antoninbas])
- Stop forwarding antctl caller credentials to Agents, authenticating with a short-lived token minted for the dedicated antctl ServiceAccount instead. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])
- Check requester authorization for SupportBundleCollection authSecret, rejecting requests where the requester cannot read the referenced Secret. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])
- Do not realize Groups whose childGroups are nested too deeply, preventing an antrea-controller crash caused by a ChildGroups cycle. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])
- Check requester authorization for PacketCapture fileServer, rejecting requests where the requester cannot read the file server credentials. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])
- Prevent antrea-agent panic on short reject packets. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])
- Prevent antrea-agent panic on non-echo ICMPv6 packet-in. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])
- Sanitize comment and log-prefix args in iptables rule builder to prevent injection of arbitrary rules. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])
- Bind Windows ovsdb-server to loopback instead of all interfaces. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])
- Prevent antrea-agent panic on short IGMP packets. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])
- Fix antrea-agent panic on Traceflow to a portless Service. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])
- Bound FQDN tracking growth in fqdnController with a single capped cache. ([#8251](https://github.com/antrea-io/antrea/pull/8251), [@antoninbas])

[@aclfe]: https://github.com/aclfe
[@alronova]: https://github.com/alronova
[@Anand-240]: https://github.com/Anand-240
[@aneek22112007-tech]: https://github.com/aneek22112007-tech
[@antoninbas]: https://github.com/antoninbas
[@Anujkumar9081]: https://github.com/Anujkumar9081
[@Archong-Liu]: https://github.com/Archong-Liu
[@Denyme24]: https://github.com/Denyme24
[@Dyanngg]: https://github.com/Dyanngg
[@hangyan]: https://github.com/hangyan
[@hongliangl]: https://github.com/hongliangl
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@magic-peach]: https://github.com/magic-peach
[@mail2sudheerobbu-oss]: https://github.com/mail2sudheerobbu-oss
[@OmAmbole009]: https://github.com/OmAmbole009
[@SAY-5]: https://github.com/SAY-5
[@SharanRP]: https://github.com/SharanRP
[@stroebs]: https://github.com/stroebs
[@wenqiq]: https://github.com/wenqiq
[@XinShuYang]: https://github.com/XinShuYang
[@xliuxu]: https://github.com/xliuxu
