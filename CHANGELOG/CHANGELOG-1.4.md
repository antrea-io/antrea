# Changelog 1.4

## 1.4.0 - 2021-11-03

The NodePortLocal feature is graduated from Alpha to Beta.

### Added

- Support for proxying all Service traffic by Antrea Proxy, including NodePort, LoadBalancer, and ClusterIP traffic. Therefore, running kube-proxy is no longer required. ([#2599](https://github.com/antrea-io/antrea/pull/2599) [#2235](https://github.com/antrea-io/antrea/pull/2235) [#2897](https://github.com/antrea-io/antrea/pull/2897) [#2863](https://github.com/antrea-io/antrea/pull/2863), [@hongliangl] [@lzhecheng])
  * The feature works for both Linux and Windows
  * The feature is experimental and therefore disabled by default. Use the `antreaProxy.proxyAll` configuration parameter for the Antrea Agent to enable it
  * If kube-proxy is removed, the `kubeAPIServerOverride` configuration parameter for the Antrea Agent must be set to access kube-apiserver directly
- Add [AntreaIPAM] feature that allows flexible control over Pod IP Addressing by assigning pools of IP addresses to specific Namespaces. ([#2956](https://github.com/antrea-io/antrea/pull/2956), [@gran-vmv] [@annakhm])
  * Add new IPPool API to define ranges of IP addresses which can be used as Pod IPs; the IPs in the IPPools must be in the same "underlay" subnet as the Node IP
  * A Pod's IP will be allocated from the IPPool specified by the `ipam.antrea.io/ippools` annotation of the Pod's Namespace if there is one
  * When the feature is enabled, the Node's network interface will be connected to the OVS bridge, in order to forward cross-Node traffic of AntreaIPAM Pods through the underlay network
  * Refer to the [feature documentation](https://github.com/antrea-io/antrea/blob/v1.4.0/docs/feature-gates.md#nodeipam) for more information
- Add [NodeIPAM] feature to handle the per-Node PodCIDR allocation for clusters where kube-controller-manager does not run NodeIPAMController. ([#1561](https://github.com/antrea-io/antrea/pull/1561), [@ksamoray])
  * Refer to the [feature documentation](https://github.com/antrea-io/antrea/blob/v1.4.0/docs/antrea-ipam.md#running-nodeipam-within-antrea-controller) for instructions on how to configure it
- Support for configurable transport interface CIDRs for Pod traffic. ([#2704](https://github.com/antrea-io/antrea/pull/2704), [@Jexf])
  * Use the `transportInterfaceCIDRs` configuration parameter for the Antrea Agent to choose an interface by network CIDRs
- Add UDP support for NodePortLocal. ([#2448](https://github.com/antrea-io/antrea/pull/2448), [@chauhanshubham])
- Add the `nodePortLocal.enable` configuration parameter for the Antrea Agent to enable NodePortLocal. ([#2924](https://github.com/antrea-io/antrea/pull/2924), [@antoninbas])
- Add more visibility metrics to report the connection status of the Antrea Agent to the Flow Aggregator. ([#2668](https://github.com/antrea-io/antrea/pull/2668), [@zyiou])
- Add the `antreaProxy.skipServices` configuration parameter for the Antrea Agent to specify Services which should be ignored by AntreaProxy. ([#2882](https://github.com/antrea-io/antrea/pull/2882), [@luolanzone])
  * A typical use case is setting `antreaProxy.skipServices` to `["kube-system/kube-dns"]` to make [NodeLocal DNSCache] work when AntreaProxy is enabled
- Add support for `ToServices` in the rules of Antrea-native policies to allow matching traffic intended for Services. ([#2755](https://github.com/antrea-io/antrea/pull/2755), [@GraysonWu])
- Add the `egress.exceptCIDRs` configuration parameter for the Antrea Agent, to specify IP destinations for which SNAT should not be performed on outgoing traffic. ([#2749](https://github.com/antrea-io/antrea/pull/2749), [@leonstack])
- Add user documentation for [WireGuard encryption]. ([#2902](https://github.com/antrea-io/antrea/pull/2902), [@jianjuns])
- Add user documentation for [encap mode installation for EKS]. ([#2929](https://github.com/antrea-io/antrea/pull/2929), [@jianjuns])


### Changed

- Remove chmod for OVSDB file from start_ovs, as the permissions are set correctly by OVS 2.15.1. ([#2803](https://github.com/antrea-io/antrea/pull/2803), [@antoninbas])
- Reduce memory usage of antctl when collecting supportbundle. ([#2813](https://github.com/antrea-io/antrea/pull/2813), [@tnqn])
- Do not perform SNAT for egress traffic to Kubernetes Node IPs. ([#2762](https://github.com/antrea-io/antrea/pull/2762), [@leonstack])
- Send gratuitous ARP for EgressIP via the transport interface, as opposed to the interface with Node IP (if they are different). ([#2845](https://github.com/antrea-io/antrea/pull/2845), [@Jexf])
- Ignore hostNetwork Pods selected by Egress, as they are not supported. ([#2851](https://github.com/antrea-io/antrea/pull/2851), [@Jexf])
- Avoid duplicate processing of Egress. ([#2884](https://github.com/antrea-io/antrea/pull/2884), [@Jexf])
- Ignore the IPs of kube-ipvs0 for Egress as they cannot be used for SNAT. ([#2930](https://github.com/antrea-io/antrea/pull/2930), [@Jexf])
- Change flow exporter export expiry mechanism to priority queue based, to reduce CPU usage and memory footprint. ([#2360](https://github.com/antrea-io/antrea/pull/2360), [@heanlan])
- Make Pod labels optional in the flow records. By default, they will not be included in the flow records. Use the `recordContents.podLabels` configuration parameter for the Flow Aggregator to include them. ([#2739](https://github.com/antrea-io/antrea/pull/2739), [@yanjunz97])
- Wait for AntreaProxy to be ready before accessing any K8s Service if `antreaProxy.proxyAll` is enabled, to avoid connection issues on Agent startup. ([#2858](https://github.com/antrea-io/antrea/pull/2858), [@tnqn])
- Update [OVS pipeline documentation] to include information about AntreaProxy. ([#2725](https://github.com/antrea-io/antrea/pull/2725), [@hongliangl])
- Remove offensive words from scripts and documentation. ([#2799](https://github.com/antrea-io/antrea/pull/2799), [@xiaoxiaobaba])
- Use readable names for OpenFlow tables. ([#2585](https://github.com/antrea-io/antrea/pull/2585), [@wenyingd])
- Improve the OpenAPI schema for CRDs to validate the `matchExpressions` field. ([#2887](https://github.com/antrea-io/antrea/pull/2887), [@wenqiq])
- Fail fast if the source Pod for non-live-traffic Traceflow is invalid. ([#2736](https://github.com/antrea-io/antrea/pull/2736), [@gran-vmv])
- Use the `RenewIPConfig` parameter to indicate whether to renew ipconfig on the host for `Clean-AntreaNetwork.ps1`. It defaults to false. ([#2955](https://github.com/antrea-io/antrea/pull/2955, [@wenyingd]) [Windows]
- Add Windows task delay up to 30s to improve job resiliency of `Prepare-AntreaAgent.ps1`, to avoid a failure in initialization after Windows startup. ([#2864](https://github.com/antrea-io/antrea/pull/2864), [@perithompson]) [Windows]

### Fixed

- Fix nil pointer error when antrea-agent updates OpenFlow priorities of Antrea-native policies without Service ports. ([#2730](https://github.com/antrea-io/antrea/pull/2730), [@wenyingd])
- Fix panic in the Antrea Controller when it processes ClusterGroups that are used by multiple ClusterNetworkPolicies. ([#2768](https://github.com/antrea-io/antrea/pull/2768), [@tnqn])
- Fix an issue with NodePortLocal when a given Pod port needs to be exposed for both TCP and UDP. ([#2903](https://github.com/antrea-io/antrea/pull/2903), [@antoninbas])
- Fix handling of the "Reject" action of Antrea-native policies when the traffic is intended for Services. ([#2772](https://github.com/antrea-io/antrea/pull/2772), [@GraysonWu])
- Fix Agent crash when removing the existing NetNat on Windows Nodes. ([#2751](https://github.com/antrea-io/antrea/pull/2751), [@wenyingd]) [Windows]
- Fix container network interface MTU configuration error when using containerd as the runtime on Windows. ([#2778](https://github.com/antrea-io/antrea/pull/2778), [@wenyingd]) [Windows]
- Fix path to Prepare-AntreaAgent.ps1 in Windows docs. ([#2840](https://github.com/antrea-io/antrea/pull/2840), [@perithompson]) [Windows]
- Fix NetNeighbor Powershell error handling. ([#2905](https://github.com/antrea-io/antrea/pull/2905), [@lzhecheng]) [Windows]

[AntreaIPAM]: https://github.com/antrea-io/antrea/blob/v1.4.0/docs/feature-gates.md##antreaipam
[encap mode installation for EKS]: https://github.com/antrea-io/antrea/blob/v1.4.0/docs/eks-installation.md#deploying-antrea-in-encap-mode
[NodeIPAM]: https://github.com/antrea-io/antrea/blob/v1.4.0/docs/feature-gates.md#nodeipam
[NodeLocal DNSCache]: https://kubernetes.io/docs/tasks/administer-cluster/nodelocaldns/
[OVS pipeline documentation]: https://github.com/antrea-io/antrea/blob/v1.4.0/docs/design/ovs-pipeline.md
[WireGuard encryption]: https://github.com/antrea-io/antrea/blob/v1.4.0/docs/traffic-encryption.md#wireguard

[@annakhm]: https://github.com/annakhm
[@antoninbas]: https://github.com/antoninbas
[@chauhanshubham]: https://github.com/chauhanshubham
[@gran-vmv]: https://github.com/gran-vmv
[@GraysonWu]: https://github.com/GraysonWu
[@heanlan]: https://github.com/heanlan
[@hongliangl]: https://github.com/hongliangl
[@Jexf]: https://github.com/Jexf
[@jianjuns]: https://github.com/jianjuns
[@ksamoray]: https://github.com/ksamoray
[@leonstack]: https://github.com/leonstack
[@luolanzone]: https://github.com/luolanzone
[@lzhecheng]: https://github.com/lzhecheng
[@perithompson]: https://github.com/perithompson
[@tnqn]: https://github.com/tnqn
[@wenqiq]: https://github.com/wenqiq
[@wenyingd]: https://github.com/wenyingd
[@xiaoxiaobaba]: https://github.com/xiaoxiaobaba
[@yanjunz97]: https://github.com/yanjunz97
[@zyiou]: https://github.com/zyiou