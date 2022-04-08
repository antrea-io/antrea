# antrea

![Version: 1.17.0-dev](https://img.shields.io/badge/Version-1.17.0--dev-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.17.0-dev](https://img.shields.io/badge/AppVersion-1.17.0--dev-informational?style=flat-square)

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
| agent.antreaIPsec.resources | object | `{"requests":{"cpu":"50m"}}` | Resource requests and limits for the antrea-ipsec container (when IPsec is enabled). |
| agent.antreaOVS.extraArgs | list | `[]` | Extra command-line arguments for antrea-ovs. |
| agent.antreaOVS.logFileMaxNum | int | `4` | Max number of log files. |
| agent.antreaOVS.logFileMaxSize | int | `100` | Max size in MBs of any single log file. |
| agent.antreaOVS.resources | object | `{"requests":{"cpu":"200m"}}` | Resource requests and limits for the antrea-ovs container. |
| agent.apiPort | int | `10350` | Port for the antrea-agent APIServer to serve on. |
| agent.dnsPolicy | string | `"ClusterFirstWithHostNet"` | DNS Policy for the antrea-agent Pods. |
| agent.enablePrometheusMetrics | bool | `true` | Enable metrics exposure via Prometheus. |
| agent.extraVolumes | list | `[]` | Additional volumes for antrea-agent Pods. |
| agent.installCNI.resources | object | `{"requests":{"cpu":"100m"}}` | Resource requests and limits for the install-cni initContainer. |
| agent.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node selector for the antrea-agent Pods. |
| agent.podAnnotations | object | `{}` | Annotations to be added to antrea-agent Pods. |
| agent.podLabels | object | `{}` | Labels to be added to antrea-agent Pods. |
| agent.priorityClassName | string | `"system-node-critical"` | Prority class to use for the antrea-agent Pods. |
| agent.tolerations | list | `[{"key":"CriticalAddonsOnly","operator":"Exists"},{"effect":"NoSchedule","operator":"Exists"},{"effect":"NoExecute","operator":"Exists"}]` | Tolerations for the antrea-agent Pods. |
| agent.updateStrategy | object | `{"type":"RollingUpdate"}` | Update strategy for the antrea-agent DaemonSet. |
| antreaProxy.nodePortAddresses | list | `[]` | String array of values which specifies the host IPv4/IPv6 addresses for NodePort. By default, all host addresses are used. |
| antreaProxy.proxyAll | bool | `false` | Proxy all Service traffic, for all Service types, regardless of where it comes from. |
| antreaProxy.proxyLoadBalancerIPs | bool | `true` | When set to false, AntreaProxy no longer load-balances traffic destined to the External IPs of LoadBalancer Services. |
| antreaProxy.skipServices | list | `[]` |  |
| cni.hostBinPath | string | `"/opt/cni/bin"` | Installation path of CNI binaries on the host. |
| cni.plugins | object | `{"bandwidth":true,"portmap":true}` | Chained plugins to use alongside antrea-cni. |
| cni.skipBinaries | list | `[]` | CNI binaries shipped with Antrea for which installation should be skipped. |
| controller.affinity | object | `{}` | Affinity for the antrea-controller Pod. |
| controller.antreaController.extraArgs | list | `[]` | Extra command-line arguments for antrea-controller. |
| controller.antreaController.extraEnv | object | `{}` | Extra environment variables to be injected into antrea-controller. |
| controller.antreaController.logFileMaxNum | int | `4` | Max number of log files. |
| controller.antreaController.logFileMaxSize | int | `100` | Max size in MBs of any single log file. |
| controller.antreaController.resources | object | `{"requests":{"cpu":"200m"}}` | Resource requests and limits for the antrea-controller container. |
| controller.apiPort | int | `10349` | Port for the antrea-controller APIServer to serve on. |
| controller.enablePrometheusMetrics | bool | `true` | Enable metrics exposure via Prometheus. |
| controller.nodeSelector | object | `{"kubernetes.io/os":"linux"}` | Node selector for the antrea-controller Pod. |
| controller.podAnnotations | object | `{}` | Annotations to be added to antrea-controller Pod. |
| controller.podLabels | object | `{}` | Labels to be added to antrea-controller Pod. |
| controller.priorityClassName | string | `"system-cluster-critical"` | Prority class to use for the antrea-controller Pod. |
| controller.selfSignedCert | bool | `true` | Indicates whether to use auto-generated self-signed TLS certificates. If false, a Secret named "antrea-controller-tls" must be provided with the following keys: ca.crt, tls.crt, tls.key. |
| controller.tolerations | list | `[{"key":"CriticalAddonsOnly","operator":"Exists"},{"effect":"NoSchedule","key":"node-role.kubernetes.io/master"}]` | Tolerations for the antrea-controller Pod. |
| defaultMTU | int | `0` | Default MTU to use for the host gateway interface and the network interface of each Pod. By default, antrea-agent will discover the MTU of the Node's primary interface and adjust it to accommodate for tunnel encapsulation overhead if applicable. |
| egress.exceptCIDRs | list | `[]` | CIDR ranges to which outbound Pod traffic will not be SNAT'd by Egresses. |
| enableBridgingMode | bool | `false` | Enable bridging mode of Pod network on Nodes, in which the Node's transport interface is connected to the OVS bridge. |
| featureGates | object | `{}` | To explicitly enable or disable a FeatureGate and bypass the Antrea defaults, add an entry to the dictionary with the FeatureGate's name as the key and a boolean as the value. |
| flowCollector.activeFlowExportTimeout | string | `"5s"` | timeout after which a flow record is sent to the collector for active flows. |
| flowCollector.collectorAddr | string | `"flow-aggregator.flow-aggregator.svc:4739:tls"` | IPFIX collector address as a string with format <HOST>:[<PORT>][:<PROTO>]. |
| flowCollector.flowPollInterval | string | `"5s"` | Determines how often the flow exporter polls for new connections. |
| flowCollector.idleFlowExportTimeout | string | `"15s"` | timeout after which a flow record is sent to the collector for idle flows. |
| hostGateway | string | `"antrea-gw0"` | Name of the interface antrea-agent will create and use for host <-> Pod communication. |
| image | object | `{"pullPolicy":"IfNotPresent","repository":"projects.registry.vmware.com/antrea/antrea-ubuntu","tag":"latest"}` | Container image to use for Antrea components. |
| ipsec.psk | string | `"changeme"` | Preshared Key (PSK) for IKE authentication. It will be stored in a secret and passed to antrea-agent as an environment variable. |
| kubeAPIServerOverride | string | `""` | Address of Kubernetes apiserver, to override any value provided in kubeconfig or InClusterConfig. |
| logVerbosity | int | `0` |  |
| multicastInterfaces | list | `[]` | Names of the interfaces on Nodes that are used to forward multicast traffic. |
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
| serviceCIDR | string | `""` | IPv4 CIDR range used for Services. Required when AntreaProxy is disabled. |
| serviceCIDRv6 | string | `""` | IPv6 CIDR range used for Services. Required when AntreaProxy is disabled. |
| testing.coverage | bool | `false` |  |
| testing.simulator.enable | bool | `false` |  |
| tlsCipherSuites | string | `""` | Comma-separated list of cipher suites that will be used by the Antrea APIservers. If empty, the default Go Cipher Suites will be used. See https://golang.org/pkg/crypto/tls/#pkg-constants. |
| tlsMinVersion | string | `""` | TLS min version from: VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13. |
| trafficEncapMode | string | `"encap"` | Determines how traffic is encapsulated. It must be one of "encap", "noEncap", "hybrid", or "networkPolicyOnly". |
| trafficEncryptionMode | string | `"none"` | Determines how tunnel traffic is encrypted. Currently encryption only works with encap mode.It must be one of "none", "ipsec", "wireGuard". |
| transportInterface | string | `""` | Name of the interface on Node which is used for tunneling or routing the traffic across Nodes. |
| transportInterfaceCIDRs | list | `[]` | Network CIDRs of the interface on Node which is used for tunneling or routing the traffic across Nodes. |
| tunnelType | string | `"geneve"` | Tunnel protocol used for encapsulating traffic across Nodes. It must be one of "geneve", "vxlan", "gre", "stt". |
| webhooks.labelsMutator.enable | bool | `false` |  |
| whereabouts.enable | bool | `false` |  |
| wireGuard.port | int | `51820` | Port for WireGuard to send and receive traffic. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.7.0](https://github.com/norwoodj/helm-docs/releases/v1.7.0)
