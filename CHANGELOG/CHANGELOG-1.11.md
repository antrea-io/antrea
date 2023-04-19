# Changelog 1.11

## 1.11.1 - 2023-04-20

### Changed

- Document the limit of maximum receiver group number on a Linux Node for multicast. ([#4850](https://github.com/antrea-io/antrea/pull/4850), [@ceclinux])

### Fixed

- Fix Service not being updated correctly when stickyMaxAgeSeconds or InternalTrafficPolicy is updated. ([#4845](https://github.com/antrea-io/antrea/pull/4845), [@tnqn])
- Fix EndpointSlice API availablility check to resolve the issue that AntreaProxy always falls back to the Endpoints API when EndpointSlice is enabled ([#4852](https://github.com/antrea-io/antrea/pull/4852), [@tnqn])
- Fix the Antrea Agent crash issue when large amount of multicast receivers with different multicast IPs on one Node start together.([#4870](https://github.com/antrea-io/antrea/pull/4870), [@ceclinux])

## 1.11.0 - 2023-03-22

- The EndpointSlice feature is graduated from Alpha to Beta and is therefore enabled by default.

### Added

- Add the following capabilities to Antrea-native policies:
  * ClusterSet scoped policy rules now support with the `namespaces` field. ([#4571](https://github.com/antrea-io/antrea/pull/4571), [@Dyanngg])
  * Layer 7 policy rules now support traffic logging. ([#4625](https://github.com/antrea-io/antrea/pull/4625), [@qiyueyao])
  * The implementation of FQDN policy rules has been extended to process DNS packets over TCP. ([#4612](https://github.com/antrea-io/antrea/pull/4612) [#4732](https://github.com/antrea-io/antrea/pull/4732), [@GraysonWu] [@tnqn])
- Add the following capabilities to the AntreaProxy feature:
  * Graduate EndpointSlice from Alpha to Beta; antrea-agent now listens to EndpointSlice events by default. ([#4634](https://github.com/antrea-io/antrea/pull/4607), [@hongliangl])
  * Support ProxyTerminatingEndpoints in AntreaProxy. ([#4607](https://github.com/antrea-io/antrea/pull/4607), [@hongliangl])
  * Support rejecting requests to Services without available Endpoints. ([#4656](https://github.com/antrea-io/antrea/pull/4656), [@hongliangl])
- Add the following capabilities to Egress policies:
  * Support limiting the number of Egress IPs that can be assigned to a Node via new configuration option `egress.maxEgressIPsPerNode` or Node annotation "node.antrea.io/max-egress-ips". ([#4593](https://github.com/antrea-io/antrea/pull/4593) [#4627](https://github.com/antrea-io/antrea/pull/4627), [@tnqn])
  * Add `antctl get memberlist` CLI command to get memberlist state. ([#4611](https://github.com/antrea-io/antrea/pull/4611), [@Atish-iaf])
- Support "noEncap", "hybrid", and "networkPolicyOnly" in-cluster traffic encapsulation modes with Multi-cluster Gateway. ([#4407](https://github.com/antrea-io/antrea/pull/4407), [@luolanzone])
- Enhance CI to validate Antrea with Rancher clusters. ([#4496](https://github.com/antrea-io/antrea/pull/4496), [@jainpulkit22])

### Changed

- Ensure cni folders are created when starting antrea-agent with containerd on Windows. ([#4685](https://github.com/antrea-io/antrea/pull/4685), [@XinShuYang])
- Decrease log verbosity value for antrea-agent specified in the Windows manifest for containerd from 4 to 0. ([#4676](https://github.com/antrea-io/antrea/pull/4676), [@XinShuYang])
- Bump up cni and plugins libraries to v1.1.1. ([#4425](https://github.com/antrea-io/antrea/pull/4425), [@wenyingd])
- Upgrade OVS version to 2.17.5. ([#4742](https://github.com/antrea-io/antrea/pull/4742), [@antoninbas])
- Extend the message length limitation in the Conditions of Antrea-native policies to 256 characters. ([#4574](https://github.com/antrea-io/antrea/pull/4574), [@wenyingd])
- Stop using ClusterFirstWithHostNet DNSPolicy for antrea-agent; revert it to the default value. ([#4548](https://github.com/antrea-io/antrea/pull/4548), [@antoninbas])
- Perform Service load balancing within OVS for Multi-cluster Service traffic, when the local member Service of the Multi-cluster Service is selected as the destination. ([#4693](https://github.com/antrea-io/antrea/pull/4693), [@luolanzone])
- Rename the `multicluster.enable` configuration parameter to `multicluster.enableGateway`. ([#4533](https://github.com/antrea-io/antrea/pull/4533), [@jianjuns])
- Add the `multicluster.enablePodToPodConnectivity` configuration parameter for antrea-agent to enable Multi-cluster Pod-to-Pod connectivity. ([#4605](https://github.com/antrea-io/antrea/pull/4605), [@hjiajing])
- No longer install Whereabouts CNI to host. ([#4617](https://github.com/antrea-io/antrea/pull/4617), [@jianjuns])
- Add an explicit Secret for the `vm-agent` ServiceAccount to the manifest for non-Kubernetes Nodes. ([#4560](https://github.com/antrea-io/antrea/pull/4560), [@wenyingd])
- Change the `toService.scope` field of Antrea ClusterNetworkPolicy to an enum. ([#4562](https://github.com/antrea-io/antrea/pull/4562), [@GraysonWu])

### Fixed

- Fix route deletion for Service ClusterIP and LoadBalancerIP when AntreaProxy is enabled. ([#4711](https://github.com/antrea-io/antrea/pull/4711), [@tnqn])
- Fix Service routes being deleted on Agent startup on Windows. ([#4470](https://github.com/antrea-io/antrea/pull/4470), [@hongliangl])
- Avoid duplicate Node Results in Live Traceflow Status. ([#4715](https://github.com/antrea-io/antrea/pull/4715), [@antoninbas])
- Fix OpenFlow Group being reused with wrong type because groupDb cache was not cleaned up. ([#4592](https://github.com/antrea-io/antrea/pull/4592), [@ceclinux])
- Ensure NO_FLOOD is always set for IPsec tunnel ports and TrafficControl ports. ([#4654](https://github.com/antrea-io/antrea/pull/4654) [#4419](https://github.com/antrea-io/antrea/pull/4419), [@xliuxu])
- Fix Agent crash in dual-stack clusters when any Node is not configured with an IP address for each address family. ([#4480](https://github.com/antrea-io/antrea/pull/4480), [@hongliangl])
- Fix antctl not being able to talk with GCP kube-apiserver due to missing platforms specific imports. ([#4494](https://github.com/antrea-io/antrea/pull/4494), [@luolanzone])


[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@KMAnju-2021]: https://github.com/KMAnju-2021
[@NamanAg30]: https://github.com/NamanAg30
[@Nithish555]: https://github.com/Nithish555
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@antrea-bot]: https://github.com/antrea-bot
[@bangqipropel]: https://github.com/bangqipropel
[@ceclinux]: https://github.com/ceclinux
[@dependabot]: https://github.com/dependabot
[@gran-vmv]: https://github.com/gran-vmv
[@hjiajing]: https://github.com/hjiajing
[@hongliangl]: https://github.com/hongliangl
[@jainpulkit22]: https://github.com/jainpulkit22
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@panpan0000]: https://github.com/panpan0000
[@qiyueyao]: https://github.com/qiyueyao
[@tnqn]: https://github.com/tnqn
[@urharshitha]: https://github.com/urharshitha
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu