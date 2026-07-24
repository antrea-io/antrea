# Changelog 2.7

## 2.7.0 - 2026-07-24

### Added

- Support ClusterNetworkPolicy in network-policy-api v0.2.0. ([#8018](https://github.com/antrea-io/antrea/pull/8018) [#8044](https://github.com/antrea-io/antrea/pull/8044), [@Dyanngg])
- Adds end-to-end support for exporting and aggregating External-to-Pod flows and preserving the original external source IP. ([#7884](https://github.com/antrea-io/antrea/pull/7884), [@Dyanngg])
- Add IPv6 support for Antrea SecondaryNetwork. ([#7762](https://github.com/antrea-io/antrea/pull/7762), [@wenqiq])
- Add dual-stack support for Antrea Egress. ([#7761](https://github.com/antrea-io/antrea/pull/7761), [@XinShuYang])
- Add AntreaNodeConfig CRD and validation webhook. ([#7812](https://github.com/antrea-io/antrea/pull/7812) [#8149](https://github.com/antrea-io/antrea/pull/8149) [#8039](https://github.com/antrea-io/antrea/pull/8039), [@luolanzone])
- Add AntreaNodeConfig-aware secondary network bridge management to allow users to define multiple uplinks and manage secondary bridge per node pool. ([#7835](https://github.com/antrea-io/antrea/pull/7835) [#8068](https://github.com/antrea-io/antrea/pull/8068), [@luolanzone])
- Use ring buffer for Flow Aggregator exporters. ([#7931](https://github.com/antrea-io/antrea/pull/7931), [@antoninbas])
- Add FlowStreamService for Flow Aggregator. ([#7937](https://github.com/antrea-io/antrea/pull/7937), [@Dyanngg])

### Changed

- Enforce strict Pod IP and IPPool address family validation to reject requests that assign multiple IPs of the same family to a single Pod. ([#7994](https://github.com/antrea-io/antrea/pull/7994), [@wenqiq])
- Exports aggregated flow records as soon as they become ReadyToSend. ([#7997](https://github.com/antrea-io/antrea/pull/7997), [@antoninbas])
- Sync NodeIPAM range allocator with upstream Kubernetes. ([#7917](https://github.com/antrea-io/antrea/pull/7917), [@antoninbas])
- Change OFBridge get/set OFSwitch to use an atomic pointer. ([#8167](https://github.com/antrea-io/antrea/pull/8167), [@jianjuns])
- Annotate end-of-initial-events bookmark for watch-list clients to fix cache sync stalled issue on a Rancher cluster. ([#8124](https://github.com/antrea-io/antrea/pull/8124), [@stroebs])
- Log invalid Namespace enable-logging annotation values. ([#8135](https://github.com/antrea-io/antrea/pull/8135), [@Anand-240])
- Include ip rule and ip route show table all in Agent SupportBundle. ([#8015](https://github.com/antrea-io/antrea/pull/8015), [@mail2sudheerobbu-oss])
- Strengthen IPPool status retry on concurrent updates. ([#7996](https://github.com/antrea-io/antrea/pull/7996), [@wenqiq])
- Improve tombstone objects handling in multiple handlers. ([#7949](https://github.com/antrea-io/antrea/pull/7949) [#7958](https://github.com/antrea-io/antrea/pull/7958) [#7964](https://github.com/antrea-io/antrea/pull/7964), [@OmAmbole009]
- Build flow-aggregator image for multiple architectures. ([#8002](https://github.com/antrea-io/antrea/pull/8002), [@antoninbas])
- Update module path to `antrea.io/antrea/v2`. ([#7747](https://github.com/antrea-io/antrea/pull/7747), [@alronova])
- Ignore user-managed VLAN sub-interfaces in IP assigner. ([#7898](https://github.com/antrea-io/antrea/pull/7898), [@antoninbas])
- Upgrade Linux OVS to version 3.7.1. ([#8082](https://github.com/antrea-io/antrea/pull/8082), [@luolanzone])
- Update CNI plugins to 1.9.1 with CVE fix. ([#7894](https://github.com/antrea-io/antrea/pull/7894), [@luolanzone])
- Bump gobgp to v4. ([#8066](https://github.com/antrea-io/antrea/pull/8066), [@hongliangl])
- Update sigs.k8s.io/mcs-api to v0.5.0. ([#8054](https://github.com/antrea-io/antrea/pull/8054), [@luolanzone])
- Migrate UUID library from google/uuid to gofrs/uuid/v5. ([#8055](https://github.com/antrea-io/antrea/pull/8055), [@hangyan])
- Update lumberjack dependency to use antrea-io fork. ([#8053](https://github.com/antrea-io/antrea/pull/8053), [@hangyan])
- Update mdlayher dependencies to use antrea-io forks. ([#8046](https://github.com/antrea-io/antrea/pull/8046), [@hangyan])
- Upgrade K8s dependencies to 1.36.1 and regenerate code. ([#8057](https://github.com/antrea-io/antrea/pull/8057), [@antoninbas])
- Replace blang/semver with golang.org/x/mod/semver in Antrea code. ([#8031](https://github.com/antrea-io/antrea/pull/8031), [@luolanzone])
- Replace OVSDB-golang-lib with antrea-io/libovsdb. ([#8092](https://github.com/antrea-io/antrea/pull/8092), [@hongliangl])
- Migrate YAML dependencies from gopkg.in to go.yaml.in and update YAML handling to v3. ([#7956](https://github.com/antrea-io/antrea/pull/7956), [#7984](https://github.com/antrea-io/antrea/pull/7984), [@SharanRP])
- Update multiple dependencies, including ClickHouse, fsnotify, mdlayher, miekg/dns, Ginkgo, Gomega, Prometheus, logrus, golang.org/x, gRPC, klog, and knftables. ([#8035](https://github.com/antrea-io/antrea/pull/8035), [@luolanzone])
- Remove a few unmaintained dependencies, including lithammer/dedent, davecgh/go-spew, and github.com/munnerz/goautoneg. ([#8032](https://github.com/antrea-io/antrea/pull/8032), [@luolanzone])

### Fixed

- Fix NetworkPolicyEvaluation to exclude host-network and terminated Pods from applicable policy results. ([#8042](https://github.com/antrea-io/antrea/pull/8042), [@Dyanngg])
- Start member StaleResCleanupController after cache is synced for Antrea Multi-cluster. ([#8180](https://github.com/antrea-io/antrea/pull/8180), [@Archong-Liu])
- Add missing continue statement in syncWireGuard. ([#7951](https://github.com/antrea-io/antrea/pull/7951), [@Denyme24])
- Exclude terminated Pods in podstore indexer to ensure Flow Aggregator always correlates flows to the correct currently running ones. ([#8043](https://github.com/antrea-io/antrea/pull/8043), [@Dyanngg])
- Fix bridge-scoped OVS ofport lookup after the libovsdb migration. ([#8169](https://github.com/antrea-io/antrea/pull/8169), [@luolanzone])
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
- Fix LB service status patch in e2e framework. ([#7904](https://github.com/antrea-io/antrea/pull/7904), [@luolanzone])
- Fix OpenAPI schema generation for Antrea API. ([#7901](https://github.com/antrea-io/antrea/pull/7901), [@antoninbas])
- Update the leader Multicluster controller’s stale resource cleanup loop to run as a controller-runtime Manager runnable to fix unexpected log message about cache not started. ([#8133](https://github.com/antrea-io/antrea/pull/8133), [@aclfe])

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
[@mail2sudheerobbu-oss]: https://github.com/mail2sudheerobbu-oss
[@OmAmbole009]: https://github.com/OmAmbole009
[@SharanRP]: https://github.com/SharanRP
[@stroebs]: https://github.com/stroebs
[@wenqiq]: https://github.com/wenqiq
[@XinShuYang]: https://github.com/XinShuYang
[@xliuxu]: https://github.com/xliuxu
