# Changelog 1.9

## 1.9.0 - 2022-10-21

### Added

- Add the following capabilities to the Multi-cluster feature:
  * Add support for Pod-to-Pod connectivity across clusters. ([#4219](https://github.com/antrea-io/antrea/pull/4219), [@hjiajing])
  * Add active-passive mode high availability support for Gateway Nodes. ([#4069](https://github.com/antrea-io/antrea/pull/4069), [@luolanzone])
  * Allow Pod IPs as Endpoints of Multi-cluster Service; option `endpointIPType` is added to the Multi-cluster Controller ConfigMap to specify the Service Endpoints type. ([#4198](https://github.com/antrea-io/antrea/pull/4198), [@luolanzone])
  * Add `antctl mc get joinconfig` command to print ClusterSet join parameters. ([#4299](https://github.com/antrea-io/antrea/pull/4299), [@jianjuns])
  * Add `antctl mc get|delete membertoken` commands to get/delete member token. ([#4254](https://github.com/antrea-io/antrea/pull/4254), [@bangqipropel])
- Add rule name to Audit Logging for Antrea-native policies. ([#4178](https://github.com/antrea-io/antrea/pull/4178), [@qiyueyao])
- Add Service health check similar to kube-proxy in antrea-agent; it provides HTTP endpoints "<nodeIP>:<healthCheckNodePort>/healthz" for querying number of local Endpoints of a Service. ([#4120](https://github.com/antrea-io/antrea/pull/4120), [@shettyg])
- Add S3Uploader as a new exporter of Flow Aggregator, which periodically exports expired flow records to AWS S3 storage bucket. ([#4143](https://github.com/antrea-io/antrea/pull/4143), [@heanlan])
- Add scripts and binaries needed for running Antrea on non-Kubernetes Nodes (ExternalNode) in release assets. ([#4266](https://github.com/antrea-io/antrea/pull/4266) [#4113](https://github.com/antrea-io/antrea/pull/4113), [@antoninbas] [@Anandkumar26])

### Changed

- AntreaProxy now supports more than 800 Endpoints for a Service. ([#4167](https://github.com/antrea-io/antrea/pull/4167), [@hongliangl])
- Add OVS connection check to Agent's liveness probes for self-healing on OVS disconnection. ([#4126](https://github.com/antrea-io/antrea/pull/4126), [@tnqn])
- antrea-agent startup scripts now perform cleanup automatically on non-Kubernetes Nodes (ExternalNode) upon Node restart. ([#4277](https://github.com/antrea-io/antrea/pull/4277), [@Anandkumar26])
- Make tunnel csum option configurable and default to false which avoids double encapsulation checksum issues on some platforms. ([#4250](https://github.com/antrea-io/antrea/pull/4250), [@tnqn])
- Use standard value type for k8s.v1.cni.cncf.io/networks annotation for the SecondaryNetwork feature. ([#4146](https://github.com/antrea-io/antrea/pull/4146), [@antoninbas])
- Update Go to v1.19. ([#4106](https://github.com/antrea-io/antrea/pull/4106), [@antoninbas])
- Add API support for reporting Antrea NetworkPolicy realization failure. ([#4248](https://github.com/antrea-io/antrea/pull/4248), [@wenyingd])
- Update ResourceExport's json tag to lowerCamelCase. ([#4211](https://github.com/antrea-io/antrea/pull/4211), [@luolanzone])
- Add clusterUUID column to S3 uploader and ClickHouseExporter to support multiple clusters in the same data warehouse. ([#4214](https://github.com/antrea-io/antrea/pull/4214), [@heanlan])

### Fixed

- Fix nil pointer error when collecting support bundle from Agent fails. ([#4306](https://github.com/antrea-io/antrea/pull/4306), [@tnqn])
- Set no-flood config for TrafficControl ports after restarting Agent to prevent ARP packet loops. ([#4318](https://github.com/antrea-io/antrea/pull/4318), [@hongliangl])
- Fix packet resubmission issue when AntreaProxy is enabled and AntreaPolicy is disable. ([#4261](https://github.com/antrea-io/antrea/pull/4261), [@GraysonWu])
- Fix ownerReferences in APIExternalEntities generated from ExternalNodes. ([#4259](https://github.com/antrea-io/antrea/pull/4259), [@wenyingd])
- Fix the issue that "MulticastGroup" API returned wrong Pods that have joined multicast groups. ([#4240](https://github.com/antrea-io/antrea/pull/4240), [@ceclinux])
- Fix inappropriate route for IPv6 ClusterIPs in the host network when proxyAll is enabled. ([#4297](https://github.com/antrea-io/antrea/pull/4297), [@tnqn])
- Fix log spam when there is any DNS based LoadBalancer Service. ([#4234](https://github.com/antrea-io/antrea/pull/4234), [@tnqn])
- Remove multicast group from cache when group is uninstalled. ([#4176](https://github.com/antrea-io/antrea/pull/4176), [@wenyingd])
- Remove redundant Openflow messages when syncing an updated group to OVS. ([#4160](https://github.com/antrea-io/antrea/pull/4160), [@hongliangl])
- Fix nil pointer error when there is no ClusterSet found during MemberClusterAnnounce validation. ([#4154](https://github.com/antrea-io/antrea/pull/4154), [@luolanzone])
- Fix data race when Multi-cluster controller reconciles ServiceExports concurrently. ([#4305](https://github.com/antrea-io/antrea/pull/4305), [@Dyanngg])
- Fix memory leak in Multi-cluster resource import controllers. ([#4251](https://github.com/antrea-io/antrea/pull/4251), [@Dyanngg])
- Fix Antrea-native policies for multicast traffic matching IGMP traffic unexpectedly. ([#4206](https://github.com/antrea-io/antrea/pull/4206), [@liu4480])
- Fix IPsec not working in UBI-based image. ([#4244](https://github.com/antrea-io/antrea/pull/4244), [@xliuxu])
- Fix `antctl mc get clusterset` command output when a ClusterSet's status is empty. ([#4174](https://github.com/antrea-io/antrea/pull/4174), [@luolanzone])


[@Anandkumar26]: https://github.com/Anandkumar26
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@XinShuYang]: https://github.com/XinShuYang
[@antoninbas]: https://github.com/antoninbas
[@antrea-bot]: https://github.com/antrea-bot
[@arunvelayutham]: https://github.com/arunvelayutham
[@bangqipropel]: https://github.com/bangqipropel
[@ceclinux]: https://github.com/ceclinux
[@dependabot]: https://github.com/dependabot
[@heanlan]: https://github.com/heanlan
[@hjiajing]: https://github.com/hjiajing
[@hongliangl]: https://github.com/hongliangl
[@jainpulkit22]: https://github.com/jainpulkit22
[@jianjuns]: https://github.com/jianjuns
[@liu4480]: https://github.com/liu4480
[@luolanzone]: https://github.com/luolanzone
[@qiyueyao]: https://github.com/qiyueyao
[@shettyg]: https://github.com/shettyg
[@tnqn]: https://github.com/tnqn
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu
[@yanjunz97]: https://github.com/yanjunz97
[@yuntanghsu]: https://github.com/yuntanghsu
