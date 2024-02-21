# antrea

![Version: 2.0.0-dev](https://img.shields.io/badge/Version-2.0.0--dev-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: latest](https://img.shields.io/badge/AppVersion-latest-informational?style=flat-square)

Kubernetes networking based on Open vSwitch

**Homepage:** <https://antrea.io/>

## Source Code

* <https://github.com/antrea-io/antrea>

## Requirements

Kubernetes: `>= 1.16.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| agent.affinity | object | `{}` | Affinity for the antrea-agent Pods. |
| agent.antreaAgent.extraArgs | list | `[]` | Extra command-line arguments for antrea-agent. |
| agent.antreaAgent.extraEnv | object | `{}` | Extra environment variables to be injected into antrea-agent. |
| agent.antreaAgent.extraVolumeMounts | list | `[]` | Additional volumeMounts for the antrea-agent container. |
| agent.antreaAgent.logFileMaxNum | int | `4` | Max number of log files. |
| agent.antreaAgent.logFileMaxSize | int | `100` | Max size in MBs of any single log file. |
| agent.antreaAgent.resources | object | `{"requests":{"cpu":"200m"}}` | Resource requests and limits for the antrea-agent container. |
| agent.antreaAgent.securityContext.capabilities | list | `[]` | Capabilities for the antrea-agent container. |
| agent.antreaAgent.securityContext.privileged | bool | `true` | Run the antrea-agent container as privileged. Currently we require this to be true (for sysctl configurations), but we may support running as non-privileged in the future. |
| agent.antreaIPsec.resources | object | `{"requests":{"cpu":"50m"}}` | Resource requests and limits for the antrea-ipsec container (when IPsec is enabled). |
| agent.antreaIPsec.securityContext.capabilities | list | `["NET_ADMIN"]` | Capabilities for the antrea-ipsec container. |
| agent.antreaIPsec.securityContext.privileged | bool | `false` | Run the antrea-ipsec container as privileged. |
| agent.antreaOVS.extraArgs | list | `[]` | Extra command-line arguments for antrea-ovs. |
| agent.antreaOVS.extraEnv | object | `{}` | Extra environment variables to be injected into antrea-ovs. |
| agent.antreaOVS.logFileMaxNum | int | `4` | Max number of log files. |
| agent.antreaOVS.logFileMaxSize | int | `100` | Max size in MBs of any single log file. |
| agent.antreaOVS.resources | object | `{"requests":{"cpu":"200m"}}` | Resource requests and limits for the antrea-ovs container. |
| agent.antreaOVS.securityContext.capabilities | list | `["SYS_NICE","NET_ADMIN","SYS_ADMIN","IPC_LOCK"]` | Capabilities for the antrea-ovs container. |
| agent.antreaOVS.securityContext.privileged | bool | `false` | Run the antrea-ovs container as privileged. |
| agent.apiPort | int | `10350` | Port for the antrea-agent APIServer to serve on. |
| agent.dnsPolicy | string | `""` | DNS Policy for the antrea-agent Pods. If empty, the Kubernetes default will be used. |
| agent.dontLoadKernelModules | bool | `false` | Do not try to load any of the required Kernel modules (e.g., openvswitch) during initialization of the antrea-agent. Most users should never need to set this to true, but it may be required with some specific distributions. Note that we will never try to load a module if we can detect that it is "built-in", regardless of this value. |
| agent.enablePrometheusMetrics | bool | `true` | Enable metrics exposure via Prometheus. |
| agent.extraVolumes | list | `[]` | Additional volumes for antrea-agent Pods. |
| agent.installCNI.extraEnv | object | `{}` | Extra environment variables to be injected into install-cni. |
| agent.installCNI.resources | object | `{"requests":{"cpu":"100m"}}` | Resource requests and limits for the install-cni initContainer. |
| agent.installCNI.securityContext.capabilities | list | `["SYS_MODULE"]` | Capabilities for the install-cni initContainer. |
| agent.installCNI.securityContext.privileged | bool | `false` | Run the install-cni container as privileged. |
| agent.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node selector for the antrea-agent Pods. |
| agent.podAnnotations | object | `{}` | Annotations to be added to antrea-agent Pods. |
| agent.podLabels | object | `{}` | Labels to be added to antrea-agent Pods. |
| agent.priorityClassName | string | `"system-node-critical"` | Prority class to use for the antrea-agent Pods. |
| agent.tolerations | list | `[{"key":"CriticalAddonsOnly","operator":"Exists"},{"effect":"NoSchedule","operator":"Exists"},{"effect":"NoExecute","operator":"Exists"}]` | Tolerations for the antrea-agent Pods. |
| agent.updateStrategy | object | `{"type":"RollingUpdate"}` | Update strategy for the antrea-agent DaemonSet. |
| agentImage | object | `{"pullPolicy":"IfNotPresent","repository":"antrea/antrea-agent-ubuntu","tag":""}` | Container image to use for the antrea-agent component. |
| antreaProxy.defaultLoadBalancerMode | string | `"nat"` | Determines how external traffic is processed when it's load balanced across Nodes by default. It must be one of "nat" or "dsr". |
| antreaProxy.enable | bool | `true` | To disable AntreaProxy, set this to false. |
| antreaProxy.nodePortAddresses | list | `[]` | String array of values which specifies the host IPv4/IPv6 addresses for NodePort. By default, all host addresses are used. |
| antreaProxy.proxyAll | bool | `false` | Proxy all Service traffic, for all Service types, regardless of where it comes from. |
| antreaProxy.proxyLoadBalancerIPs | bool | `true` | When set to false, AntreaProxy no longer load-balances traffic destined to the External IPs of LoadBalancer Services. |
| antreaProxy.serviceProxyName | string | `""` | The value of the "service.kubernetes.io/service-proxy-name" label for AntreaProxy to match. If it is set, then AntreaProxy will only handle Services with the label that equals the provided value. If it is not set, then AntreaProxy will only handle Services without the "service.kubernetes.io/service-proxy-name" label, but ignore Services with the label no matter what is the value. |
| antreaProxy.skipServices | list | `[]` | List of Services which should be ignored by AntreaProxy. |
| auditLogging.compress | bool | `true` | Compress enables gzip compression on rotated files. |
| auditLogging.maxAge | int | `28` | MaxAge is the maximum number of days to retain old log files based on the timestamp encoded in their filename. If set to 0, old log files are not removed based on age. |
| auditLogging.maxBackups | int | `3` | MaxBackups is the maximum number of old log files to retain. If set to 0, all log files will be retained (unless MaxAge causes them to be deleted). |
| auditLogging.maxSize | int | `500` | MaxSize is the maximum size in MB of a log file before it gets rotated. |
| clientCAFile | string | `""` | File path of the certificate bundle for all the signers that is recognized for incoming client certificates. |
| cni.hostBinPath | string | `"/opt/cni/bin"` | Installation path of CNI binaries on the host. |
| cni.plugins | object | `{"bandwidth":true,"portmap":true}` | Chained plugins to use alongside antrea-cni. |
| cni.skipBinaries | list | `[]` | CNI binaries shipped with Antrea for which installation should be skipped. |
| controller.affinity | object | `{}` | Affinity for the antrea-controller Pod. |
| controller.antreaController.extraArgs | list | `[]` | Extra command-line arguments for antrea-controller. |
| controller.antreaController.extraEnv | object | `{}` | Extra environment variables to be injected into antrea-controller. |
| controller.antreaController.logFileMaxNum | int | `4` | Max number of log files. |
| controller.antreaController.logFileMaxSize | int | `100` | Max size in MBs of any single log file. |
| controller.antreaController.resources | object | `{"requests":{"cpu":"200m"}}` | Resource requests and limits for the antrea-controller container. |
| controller.apiNodePort | int | `0` | NodePort for the antrea-controller APIServer to server on. |
| controller.apiPort | int | `10349` | Port for the antrea-controller APIServer to serve on. |
| controller.enablePrometheusMetrics | bool | `true` | Enable metrics exposure via Prometheus. |
| controller.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node selector for the antrea-controller Pod. |
| controller.podAnnotations | object | `{}` | Annotations to be added to antrea-controller Pod. |
| controller.podLabels | object | `{}` | Labels to be added to antrea-controller Pod. |
| controller.priorityClassName | string | `"system-cluster-critical"` | Prority class to use for the antrea-controller Pod. |
| controller.selfSignedCert | bool | `true` | Indicates whether to use auto-generated self-signed TLS certificates. If false, a Secret named "antrea-controller-tls" must be provided with the following keys: ca.crt, tls.crt, tls.key. |
| controller.tolerations | list | `[{"key":"CriticalAddonsOnly","operator":"Exists"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/master"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/control-plane"},{"effect":"NoExecute","key":"node.kubernetes.io/unreachable","operator":"Exists","tolerationSeconds":0}]` | Tolerations for the antrea-controller Pod. |
| controllerImage | object | `{"pullPolicy":"IfNotPresent","repository":"antrea/antrea-controller-ubuntu","tag":""}` | Container image to use for the antrea-controller component. |
| defaultMTU | int | `0` | Default MTU to use for the host gateway interface and the network interface of each Pod. By default, antrea-agent will discover the MTU of the Node's primary interface and adjust it to accommodate for tunnel encapsulation overhead if applicable. |
| disableTXChecksumOffload | bool | `false` | Disable TX checksum offloading for container network interfaces. It's supposed to be set to true when the datapath doesn't support TX checksum offloading, which causes packets to be dropped due to bad checksum. It affects Pods running on Linux Nodes only. |
| dnsServerOverride | string | `""` | Address of DNS server, to override the kube-dns Service. It's used to resolve hostnames in a FQDN policy. |
| egress.exceptCIDRs | list | `[]` | CIDR ranges to which outbound Pod traffic will not be SNAT'd by Egresses. |
| egress.maxEgressIPsPerNode | int | `255` | The maximum number of Egress IPs that can be assigned to a Node. It is useful when the Node network restricts the number of secondary IPs a Node can have, e.g. EKS. It must not be greater than 255. |
| enableBridgingMode | bool | `false` | Enable bridging mode of Pod network on Nodes, in which the Node's transport interface is connected to the OVS bridge. |
| featureGates | object | `{}` | To explicitly enable or disable a FeatureGate and bypass the Antrea defaults, add an entry to the dictionary with the FeatureGate's name as the key and a boolean as the value. |
| flowExporter.activeFlowExportTimeout | string | `"5s"` | timeout after which a flow record is sent to the collector for active flows. |
| flowExporter.enable | bool | `false` | Enable the flow exporter feature. |
| flowExporter.flowCollectorAddr | string | `"flow-aggregator/flow-aggregator:4739:tls"` | IPFIX collector address as a string with format <HOST>:[<PORT>][:<PROTO>]. If the collector is running in-cluster as a Service, set <HOST> to <Service namespace>/<Service name>. |
| flowExporter.flowPollInterval | string | `"5s"` | Determines how often the flow exporter polls for new connections. |
| flowExporter.idleFlowExportTimeout | string | `"15s"` | timeout after which a flow record is sent to the collector for idle flows. |
| hostGateway | string | `"antrea-gw0"` | Name of the interface antrea-agent will create and use for host <-> Pod communication. |
| image | object | `{}` | Container image to use for Antrea components. DEPRECATED: use agentImage and controllerImage instead. |
| ipsec.authenticationMode | string | `"psk"` | The authentication mode to use for IPsec. Must be one of "psk" or "cert". |
| ipsec.csrSigner.autoApprove | bool | `true` | Enable auto approval of Antrea signer for IPsec certificates. |
| ipsec.csrSigner.selfSignedCA | bool | `true` | Whether or not to use auto-generated self-signed CA. |
| ipsec.psk | string | `"changeme"` | Preshared Key (PSK) for IKE authentication. It will be stored in a secret and passed to antrea-agent as an environment variable. |
| kubeAPIServerOverride | string | `""` | Address of Kubernetes apiserver, to override any value provided in kubeconfig or InClusterConfig. |
| logVerbosity | int | `0` | Global log verbosity switch for all Antrea components. |
| multicast.enable | bool | `false` | To enable Multicast, you need to set "enable" to true, and ensure that the Multicast feature gate is also enabled (which is the default). |
| multicast.igmpQueryInterval | string | `"125s"` | The interval at which the antrea-agent sends IGMP queries to Pods. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h". |
| multicast.igmpQueryVersions | list | `[1,2,3]` | The versions of IGMP queries antrea-agent sends to Pods. Valid versions are 1, 2 and 3. |
| multicast.multicastInterfaces | list | `[]` | Names of the interfaces on Nodes that are used to forward multicast traffic. |
| multicluster.enableGateway | bool | `false` | Enable Antrea Multi-cluster Gateway to support cross-cluster traffic. |
| multicluster.enablePodToPodConnectivity | bool | `false` | Enable Multi-cluster Pod to Pod connectivity. |
| multicluster.enableStretchedNetworkPolicy | bool | `false` | Enable Multi-cluster NetworkPolicy. Multi-cluster Gateway must be enabled to enable StretchedNetworkPolicy. |
| multicluster.namespace | string | `""` | The Namespace where Antrea Multi-cluster Controller is running. The default is antrea-agent's Namespace. |
| multicluster.trafficEncryptionMode | string | `"none"` | Determines how cross-cluster traffic is encrypted. It can be one of "none" (default) or "wireGuard". When set to "none", cross-cluster traffic will not be encrypted. When set to "wireGuard", cross-cluster traffic will be sent over encrypted WireGuard tunnels. "wireGuard" requires Multi-cluster Gateway to be enabled. Note that when using WireGuard for cross-cluster traffic, encryption is no longer supported for in-cluster traffic. |
| multicluster.wireGuard.port | int | `51821` | WireGuard tunnel port for cross-cluster traffic. |
| noSNAT | bool | `false` | Whether or not to SNAT (using the Node IP) the egress traffic from a Pod to the external network. |
| nodeIPAM.clusterCIDRs | list | `[]` | CIDR ranges to use when allocating Pod IP addresses. |
| nodeIPAM.enable | bool | `false` | Enable Node IPAM in Antrea |
| nodeIPAM.nodeCIDRMaskSizeIPv4 | int | `24` | Mask size for IPv4 Node CIDR in IPv4 or dual-stack cluster. |
| nodeIPAM.nodeCIDRMaskSizeIPv6 | int | `64` | Mask size for IPv6 Node CIDR in IPv6 or dual-stack cluster. |
| nodeIPAM.serviceCIDR | string | `""` | IPv4 CIDR ranges reserved for Services. |
| nodeIPAM.serviceCIDRv6 | string | `""` | IPv6 CIDR ranges reserved for Services. |
| nodePortLocal.enable | bool | `false` | Enable the NodePortLocal feature. |
| nodePortLocal.portRange | string | `"61000-62000"` | Port range used by NodePortLocal when creating Pod port mappings. |
| ovs.bridgeName | string | `"br-int"` | Name of the OVS bridge antrea-agent will create and use. |
| ovs.hwOffload | bool | `false` | Enable hardware offload for the OVS bridge (required additional configuration). |
| packetInRate | int | `500` | packetInRate defines the OVS controller packet rate limits for different features. All features will apply this rate-limit individually on packet-in messages sent to antrea-agent. The number stands for the rate as packets per second(pps) and the burst size will be automatically set to twice the rate. When the rate and burst size are exceeded, new packets will be dropped. |
| secondaryNetwork.ovsBridges | list | `[]` | Configuration of OVS bridges for secondary network. At the moment, at most one OVS bridge can be specified. If the specified bridge does not exist on the Node, antrea-agent will create it based on the configuration. The following configuration specifies an OVS bridge with name "br1" and a physical interface "eth1": [{bridgeName: "br1", physicalInterfaces: ["eth1"]}] |
| serviceCIDR | string | `""` | IPv4 CIDR range used for Services. Required when AntreaProxy is disabled. |
| serviceCIDRv6 | string | `""` | IPv6 CIDR range used for Services. Required when AntreaProxy is disabled. |
| testing.coverage | bool | `false` | Enable code coverage measurement (used when testing Antrea only). |
| testing.simulator.enable | bool | `false` |  |
| tlsCipherSuites | string | `""` | Comma-separated list of cipher suites that will be used by the Antrea APIservers. If empty, the default Go Cipher Suites will be used. See https://golang.org/pkg/crypto/tls/#pkg-constants. |
| tlsMinVersion | string | `""` | TLS min version from: VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13. |
| trafficEncapMode | string | `"encap"` | Determines how traffic is encapsulated. It must be one of "encap", "noEncap", "hybrid", or "networkPolicyOnly". |
| trafficEncryptionMode | string | `"none"` | Determines how tunnel traffic is encrypted. Currently encryption only works with encap mode. It must be one of "none", "ipsec", "wireGuard". |
| transportInterface | string | `""` | Name of the interface on Node which is used for tunneling or routing the traffic across Nodes. |
| transportInterfaceCIDRs | list | `[]` | Network CIDRs of the interface on Node which is used for tunneling or routing the traffic across Nodes. |
| tunnelCsum | bool | `false` | TunnelCsum determines whether to compute UDP encapsulation header (Geneve or VXLAN) checksums on outgoing packets. For Linux kernel before Mar 2021, UDP checksum must be present to trigger GRO on the receiver for better performance of Geneve and VXLAN tunnels. The issue has been fixed by https://github.com/torvalds/linux/commit/89e5c58fc1e2857ccdaae506fb8bc5fed57ee063, thus computing UDP checksum is no longer necessary. It should only be set to true when you are using an unpatched Linux kernel and observing poor transfer performance. |
| tunnelPort | int | `0` | TunnelPort is the destination port for UDP and TCP based tunnel protocols (Geneve, VXLAN, and STT). If zero, it will use the assigned IANA port for the protocol, i.e. 6081 for Geneve, 4789 for VXLAN, and 7471 for STT. |
| tunnelType | string | `"geneve"` | Tunnel protocol used for encapsulating traffic across Nodes. It must be one of "geneve", "vxlan", "gre", "stt". |
| webhooks.labelsMutator.enable | bool | `false` | Mutate all namespaces to add the "antrea.io/metadata.name" label. |
| wireGuard.port | int | `51820` | Port for WireGuard to send and receive traffic. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.7.0](https://github.com/norwoodj/helm-docs/releases/v1.7.0)
