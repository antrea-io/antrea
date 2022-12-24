# Changelog 1.10

## 1.10.0 - 2022-12-23

### Added

- Add L7NetworkPolicy feature which enables users to protect their applications by specifying how they are allowed to communicate with others, taking into account application context. ([#4380](https://github.com/antrea-io/antrea/pull/4380) [#4406](https://github.com/antrea-io/antrea/pull/4406) [#4410](https://github.com/antrea-io/antrea/pull/4410), [@hongliangl] [@qiyueyao] [@tnqn])
    * Layer 7 NetworkPolicy can be configured through the `l7Protocols` field of Antrea-native policies.
    * Refer to [this document](https://github.com/antrea-io/antrea/blob/release-1.10/docs/antrea-l7-network-policy.md) for more information about this feature.
- Add SupportBundleCollection feature which enables a CRD API for Antrea to collect support bundle files on any K8s Node or ExternalNode, and upload to a user-defined file server. ([#4184](https://github.com/antrea-io/antrea/pull/4184) [#4338](https://github.com/antrea-io/antrea/pull/4338) [#4249](https://github.com/antrea-io/antrea/pull/4249), [@wenyingd] [@mengdie-song] [@ceclinux])
    * Refer to [this document](https://github.com/antrea-io/antrea/blob/release-1.10/docs/support-bundle-guide.md) for more information about this feature.
- Add support for NetworkPolicy for cross-cluster traffic. ([#4432](https://github.com/antrea-io/antrea/pull/4432) [#3914](https://github.com/antrea-io/antrea/pull/3914), [@Dyanngg] [@GraysonWu])
    * Setting `scope` of an ingress peer to `clusterSet` expands the scope of the `podSelector` or `namespaceSelector` to the entire ClusterSet.
    * Setting `scope` of `toServices` to `clusterSet` selects a Multi-cluster Service. ([#4397](https://github.com/antrea-io/antrea/pull/4397), [@Dyanngg])
    * Refer to [this document](https://github.com/antrea-io/antrea/blob/release-1.10/docs/multicluster/user-guide.md#networkpolicy-for-cross-cluster-traffic) for more information about this feature.
- Add the following capabilities to the ExternalNode feature:
    * Containerized option for antrea-agent installation on Linux VMs. ([#4413](https://github.com/antrea-io/antrea/pull/4413), [@Nithish555])
    * Support for RHEL 8.4. ([#4323](https://github.com/antrea-io/antrea/pull/4323), [@Nithish555])
- Add support for running antrea-agent as DaemonSet when using containerd as the runtime on Windows. ([#4279](https://github.com/antrea-io/antrea/pull/4279), [@XinShuYang])
- Add [documentation](https://github.com/antrea-io/antrea/blob/release-1.10/docs/multicast-guide.md) for Antrea Multicast. ([#4339](https://github.com/antrea-io/antrea/pull/4339), [@ceclinux])

### Changed

- Extend `antctl mc get joinconfig` to print member token Secret. ([#4363](https://github.com/antrea-io/antrea/pull/4363), [@jianjuns])
- Improve support for Egress in Traceflow. ([#3926](https://github.com/antrea-io/antrea/pull/3926), [@Atish-iaf])
- Add NodePortLocalPortRange field for AntreaAgentInfo. ([#4379](https://github.com/antrea-io/antrea/pull/4379), [@wenqiq])
- Use format "namespace/name" as the key for ExternalNode span calculation. ([#4401](https://github.com/antrea-io/antrea/pull/4401), [@wenyingd])
- Enclose Pod labels with single quotes when uploading CSV record to S3 in the FlowAggregator. ([#4334](https://github.com/antrea-io/antrea/pull/4334), [@dreamtalen])
- Upgrade Antrea base image to ubuntu 22.04. ([#4459](https://github.com/antrea-io/antrea/pull/4459) [#4499](https://github.com/antrea-io/antrea/pull/4499), [@antoninbas])
- Update OVS to 2.17.3. ([#4402](https://github.com/antrea-io/antrea/pull/4402), [@mnaser])
- Reduce confusion caused by transient error encountered when creating static Tiers. ([#4414](https://github.com/antrea-io/antrea/pull/4414), [@tnqn])

### Fixed

- Add a periodic job to rejoin dead Nodes, to fix Egress not working properly after long network downtime. ([#4491](https://github.com/antrea-io/antrea/pull/4491), [@tnqn])
- Fix potential deadlocks and memory leaks of memberlist maintenance in large-scale clusters. ([#4469](https://github.com/antrea-io/antrea/pull/4469), [@wenyingd])
- Fix connectivity issues caused by MAC address changes with systemd v242 and later. ([#4428](https://github.com/antrea-io/antrea/pull/4428), [@wenyingd])
- Fix error handling when S3Uploader partially succeeds. ([#4433](https://github.com/antrea-io/antrea/pull/4433), [@heanlan])
- Fix a ClusterInfo export bug when Multi-cluster Gateway changes. ([#4412](https://github.com/antrea-io/antrea/pull/4412), [@luolanzone])
- Fix OpenFlow rules not being updated when Multi-cluster Gateway updates. ([#4388](https://github.com/antrea-io/antrea/pull/4388), [@luolanzone])
- Delete Pod specific VF resource cache when a Pod gets deleted. ([#4285](https://github.com/antrea-io/antrea/pull/4285), [@arunvelayutham])
- Fix OpenAPI descriptions for AntreaAgentInfo and AntreaControllerInfo. ([#4390](https://github.com/antrea-io/antrea/pull/4390), [@tnqn])


[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@NamanAg30]: https://github.com/NamanAg30
[@Nithish555]: https://github.com/Nithish555
[@XinShuYang]: https://github.com/XinShuYang
[@adwaitni]: https://github.com/adwaitni
[@antoninbas]: https://github.com/antoninbas
[@antrea-bot]: https://github.com/antrea-bot
[@arunvelayutham]: https://github.com/arunvelayutham
[@bangqipropel]: https://github.com/bangqipropel
[@ceclinux]: https://github.com/ceclinux
[@dependabot]: https://github.com/dependabot
[@dreamtalen]: https://github.com/dreamtalen
[@heanlan]: https://github.com/heanlan
[@hjiajing]: https://github.com/hjiajing
[@hongliangl]: https://github.com/hongliangl
[@jainpulkit22]: https://github.com/jainpulkit22
[@jianjuns]: https://github.com/jianjuns
[@liu4480]: https://github.com/liu4480
[@luolanzone]: https://github.com/luolanzone
[@mengdie-song]: https://github.com/mengdie-song
[@mnaser]: https://github.com/mnaser
[@qiyueyao]: https://github.com/qiyueyao
[@tnqn]: https://github.com/tnqn
[@urharshitha]: https://github.com/urharshitha
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu