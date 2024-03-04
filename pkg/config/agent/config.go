// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	componentbaseconfig "k8s.io/component-base/config"
)

type AgentConfig struct {
	// featureGates is a map of feature names to bools that enable or disable experimental features.
	FeatureGates map[string]bool `yaml:"featureGates,omitempty"`

	CNISocket string `yaml:"cniSocket,omitempty"`
	// clientConnection specifies the kubeconfig file and client connection settings for the agent
	// to communicate with the apiserver.
	ClientConnection componentbaseconfig.ClientConnectionConfiguration `yaml:"clientConnection"`
	// AntreaClientConnection specifies the kubeconfig file and client connection settings for the
	// agent to communicate with the Antrea Controller apiserver.
	AntreaClientConnection componentbaseconfig.ClientConnectionConfiguration `yaml:"antreaClientConnection"`
	// Name of the OpenVSwitch bridge antrea-agent will create and use.
	// Make sure it doesn't conflict with your existing OpenVSwitch bridges.
	// Defaults to br-int.
	OVSBridge string `yaml:"ovsBridge,omitempty"`
	// Datapath type to use for the OpenVSwitch bridge created by Antrea. At the moment, the only supported
	// value is 'system', which corresponds to the kernel datapath.
	OVSDatapathType string `yaml:"ovsDatapathType,omitempty"`
	// Runtime data directory used by Open vSwitch.
	// Default value:
	// - On Linux platform: /var/run/openvswitch
	// - On Windows platform: C:\openvswitch\var\run\openvswitch
	OVSRunDir string `yaml:"ovsRunDir,omitempty"`
	// Name of the interface antrea-agent will create and use for host <--> pod communication.
	// Make sure it doesn't conflict with your existing interfaces.
	// Defaults to antrea-gw0.
	HostGateway string `yaml:"hostGateway,omitempty"`
	// Determines how traffic is encapsulated. It has the following options:
	// encap(default):    Inter-node Pod traffic is always encapsulated and Pod to external network
	//                    traffic is SNAT'd.
	// noEncap:           Inter-node Pod traffic is not encapsulated; Pod to external network traffic is
	//                    SNAT'd if noSNAT is not set to true. Underlying network must be capable of
	//                    supporting Pod traffic across IP subnets.
	// hybrid:            noEncap if source and destination Nodes are on the same subnet, otherwise encap.
	// networkPolicyOnly: Antrea enforces NetworkPolicy only, and utilizes CNI chaining and delegates Pod
	//                    IPAM and connectivity to the primary CNI.
	TrafficEncapMode string `yaml:"trafficEncapMode,omitempty"`
	// Whether or not to SNAT (using the Node IP) the egress traffic from a Pod to the external network.
	// This option is for the noEncap traffic mode only, and the default value is false. In the noEncap
	// mode, if the cluster's Pod CIDR is reachable from the external network, then the Pod traffic to
	// the external network needs not be SNAT'd. In the networkPolicyOnly mode, antrea-agent never
	// performs SNAT and this option will be ignored; for other modes it must be set to false.
	NoSNAT bool `yaml:"noSNAT,omitempty"`
	// Tunnel protocols used for encapsulating traffic across Nodes. Supported values:
	// - geneve (default)
	// - vxlan
	// - gre
	// - stt
	TunnelType string `yaml:"tunnelType,omitempty"`
	// TunnelPort is the destination port for UDP and TCP based tunnel protocols (Geneve, VXLAN, and STT).
	// If zero, it will use the assigned IANA port for the protocol, i.e. 6081 for Geneve, 4789 for VXLAN,
	// and 7471 for STT.
	TunnelPort int32 `yaml:"tunnelPort,omitempty"`
	// TunnelCsum determines whether to compute UDP encapsulation header (Geneve or VXLAN) checksums on outgoing
	// packets. For Linux kernel before Mar 2021, UDP checksum must be present to trigger GRO on the receiver for better
	// performance of Geneve and VXLAN tunnels. The issue has been fixed by
	// https://github.com/torvalds/linux/commit/89e5c58fc1e2857ccdaae506fb8bc5fed57ee063, thus computing UDP checksum is
	// no longer necessary.
	// Default is false. It should only be set to true when you are using an unpatched Linux kernel and observing poor
	// transfer performance.
	TunnelCsum bool `yaml:"tunnelCsum,omitempty"`
	// Default MTU to use for the host gateway interface and the network interface of each Pod.
	// If omitted, antrea-agent will discover the MTU of the Node's primary interface and
	// also adjust MTU to accommodate for tunnel encapsulation overhead (if applicable).
	DefaultMTU int `yaml:"defaultMTU,omitempty"`
	// Mount location of the /proc directory. The default is "/host", which is appropriate when
	// antrea-agent is run as part of the Antrea DaemonSet (and the host's /proc directory is mounted
	// as /host/proc in the antrea-agent container). When running antrea-agent as a process,
	// hostProcPathPrefix should be set to "/" in the YAML config.
	HostProcPathPrefix string `yaml:"hostProcPathPrefix,omitempty"`
	// ClusterIP CIDR range for Services. It's required when AntreaProxy is not enabled, and should be
	// set to the same value as the one specified by --service-cluster-ip-range for kube-apiserver. When
	// AntreaProxy is enabled, this parameter is not needed and will be ignored if provided.
	// Default is 10.96.0.0/12
	ServiceCIDR string `yaml:"serviceCIDR,omitempty"`
	// ClusterIP CIDR range for IPv6 Services. It's required when using kube-proxy to provide IPv6 Service in a Dual-Stack
	// cluster or an IPv6 only cluster. The value should be the same as the configuration for kube-apiserver specified by
	// --service-cluster-ip-range. When AntreaProxy is enabled, this parameter is not needed.
	// No default value for this field.
	ServiceCIDRv6 string `yaml:"serviceCIDRv6,omitempty"`
	// Deprecated. Use TrafficEncryptionMode instead.
	EnableIPSecTunnel bool `yaml:"enableIPSecTunnel,omitempty"`
	// Determines how tunnel traffic is encrypted.
	// It has the following options:
	// - none (default): Inter-node Pod traffic will not be encrypted.
	// - ipsec:          Enable IPsec (ESP) encryption for Pod traffic across Nodes. Antrea uses
	//                   Preshared Key (PSK) for IKE authentication. When IPsec tunnel is enabled,
	//                   the PSK value must be passed to Antrea Agent through an environment
	//                   variable: ANTREA_IPSEC_PSK.
	// - wireguard:      Enable WireGuard for tunnel traffic encryption.
	TrafficEncryptionMode string `yaml:"trafficEncryptionMode,omitempty"`
	// WireGuard related configurations.
	WireGuard WireGuardConfig `yaml:"wireGuard"`
	// Enable bridging mode of Pod network on Nodes, in which the Node's transport interface is connected
	// to the OVS bridge, and cross-Node/VLAN traffic of AntreaIPAM Pods (Pods whose IP addresses are
	// allocated by AntreaIPAM from IPPools) is sent to the underlay network, and forwarded/routed by the
	// underlay network.
	// This option requires the `AntreaIPAM` feature gate to be enabled. At this moment, it supports only
	// IPv4 and Linux Nodes, and can be enabled only when `ovsDatapathType` is `system`,
	// `trafficEncapMode` is `noEncap`, and `noSNAT` is true.
	EnableBridgingMode bool `yaml:"enableBridgingMode,omitempty"`
	// Disable TX checksum offloading for container network interfaces. It's supposed to be set to true when the
	// datapath doesn't support TX checksum offloading, which causes packets to be dropped due to bad checksum.
	// It affects Pods running on Linux Nodes only.
	DisableTXChecksumOffload bool `yaml:"disableTXChecksumOffload,omitempty"`
	// APIPort is the port for the antrea-agent APIServer to serve on.
	// Defaults to 10350.
	APIPort int `yaml:"apiPort,omitempty"`
	// ClusterMembershipPort is the server port used by the antrea-agent to run a gossip-based cluster
	// membership protocol. Currently it's used only when the Egress feature is enabled.
	// Defaults to 10351.
	ClusterMembershipPort int `yaml:"clusterPort,omitempty"`
	// Enable metrics exposure via Prometheus. Initializes Prometheus metrics listener
	// Defaults to true.
	EnablePrometheusMetrics *bool `yaml:"enablePrometheusMetrics,omitempty"`
	// Deprecated. Use the FlowExporter config options instead.
	FlowCollectorAddr string `yaml:"flowCollectorAddr,omitempty"`
	// Deprecated. Use the FlowExporter config options instead.
	FlowPollInterval string `yaml:"flowPollInterval,omitempty"`
	// Deprecated. Use the FlowExporter config options instead.
	ActiveFlowExportTimeout string `yaml:"activeFlowExportTimeout,omitempty"`
	// Deprecated. Use the FlowExporter config options instead.
	IdleFlowExportTimeout string `yaml:"idleFlowExportTimeout,omitempty"`
	// NodePortLocal (NPL) configuration options.
	NodePortLocal NodePortLocalConfig `yaml:"nodePortLocal,omitempty"`
	// FlowExporter configuration options.
	FlowExporter FlowExporterConfig `yaml:"flowExporter,omitempty"`
	// Provide the address of Kubernetes apiserver, to override any value provided in kubeconfig or
	// InClusterConfig. It is typically used when kube-proxy is not deployed (replaced by AntreaProxy).
	// Defaults to "". It must be a host string, a host:port pair, or a URL to the base of the apiserver.
	KubeAPIServerOverride string `yaml:"kubeAPIServerOverride,omitempty"`
	// Provide the address of DNS server, to override the kube-dns Service. It's used to resolve
	// hostnames in a FQDN policy.
	// Defaults to "". It must be a host string or a host:port pair of the DNS server (e.g. 10.96.0.10,
	// 10.96.0.10:53, [fd00:10:96::a]:53).
	DNSServerOverride string `yaml:"dnsServerOverride,omitempty"`
	// Cipher suites to use.
	TLSCipherSuites string `yaml:"tlsCipherSuites,omitempty"`
	// TLS min version.
	TLSMinVersion string `yaml:"tlsMinVersion,omitempty"`
	// The name of the interface on Node which is used for tunneling or routing the traffic across Nodes.
	// If there are multiple IP addresses configured on the interface, the first one is used. The IP
	// address used for tunneling or routing traffic to remote Nodes is decided in the following order of
	// preference (from highest to lowest):
	// 1. TransportInterface
	// 2. TransportInterfaceCIDRs
	// 3. The Node IP
	TransportInterface string `yaml:"transportInterface,omitempty"`
	// The network CIDRs of the interface on Node which is used for tunneling or routing the traffic across
	// Nodes. If there are multiple interfaces configured the same network CIDR, the first one is used. The
	// IP address used for tunneling or routing traffic to remote Nodes is decided in the following order of
	// preference (from highest to lowest):
	// 1. TransportInterface
	// 2. TransportInterfaceCIDRs
	// 3. The Node IP
	TransportInterfaceCIDRs []string `yaml:"transportInterfaceCIDRs,omitempty"`
	// The names of the interfaces on Nodes that are used to forward multicast traffic.
	// Defaults to transport interface if not set.
	// Deprecated: use Multicast.MulticastInterfaces instead.
	MulticastInterfaces []string `yaml:"multicastInterfaces,omitempty"`
	// Multicast configuration options.
	Multicast MulticastConfig `yaml:"multicast,omitempty"`
	// AntreaProxy contains AntreaProxy related configuration options.
	AntreaProxy AntreaProxyConfig `yaml:"antreaProxy,omitempty"`
	// Egress related configurations.
	Egress EgressConfig `yaml:"egress"`
	// IPsec related configurations.
	IPsec IPsecConfig `yaml:"ipsec"`
	// Multicluster configuration options.
	Multicluster MulticlusterConfig `yaml:"multicluster,omitempty"`
	// NodeType is type of the Node where Antrea Agent is running.
	// Defaults to "k8sNode". Valid values include "k8sNode", and "externalNode".
	NodeType string `yaml:"nodeType,omitempty"`
	// ExternalNode related configurations.
	ExternalNode ExternalNodeConfig `yaml:"externalNode,omitempty"`
	// AuditLogging supports configuring log rotation for audit logs.
	AuditLogging AuditLoggingConfig `yaml:"auditLogging,omitempty"`
	// Antrea's native secondary network configuration.
	SecondaryNetwork SecondaryNetworkConfig `yaml:"secondaryNetwork,omitempty"`
	// PacketInRate defines the OVS controller packet rate limits for different
	// features. All features will apply this rate-limit individually on packet-in
	// messages sent to antrea-agent. The number stands for the rate as packets per
	// second(pps) and the burst size will be automatically set to twice the rate.
	// When the rate and burst size are exceeded, new packets will be dropped.
	PacketInRate int `yaml:"packetInRate,omitempty"`
}

type AntreaProxyConfig struct {
	// To disable AntreaProxy, set this to false.
	Enable *bool `yaml:"enable,omitempty"`
	// ProxyAll tells antrea-agent to proxy all Service traffic, including NodePort, LoadBalancer, and ClusterIP traffic,
	// regardless of where they come from. Therefore, running kube-proxy is no longer required.
	ProxyAll bool `yaml:"proxyAll,omitempty"`
	// A string array of values which specifies the host IPv4/IPv6 addresses for NodePorts. Values may be valid IP blocks.
	// (e.g. 1.2.3.0/24, 1.2.3.4/32). An empty string slice is meant to select all host IPv4/IPv6 addresses.
	NodePortAddresses []string `yaml:"nodePortAddresses,omitempty"`
	// An array of string values to specify a list of Services which should be ignored by AntreaProxy (traffic to these
	// Services will not be load-balanced). Values can be a valid ClusterIP (e.g. 10.11.1.2) or a Service name
	// with Namespace (e.g. kube-system/kube-dns)
	SkipServices []string `yaml:"skipServices,omitempty"`
	// When ProxyLoadBalancerIPs is set to false, AntreaProxy no longer load-balances traffic destined to the
	// External IPs of LoadBalancer Services. This is useful when the external LoadBalancer provides additional
	// capabilities (e.g. TLS termination) and it is desirable for Pod-to-ExternalIP traffic to be sent to the
	// external LoadBalancer instead of being load-balanced to an Endpoint directly by AntreaProxy.
	// Note that setting ProxyLoadBalancerIPs to false usually only makes sense when ProxyAll is set to true and
	// kube-proxy is removed from the cluser, otherwise kube-proxy will still load-balance this traffic.
	// Defaults to true.
	ProxyLoadBalancerIPs *bool `yaml:"proxyLoadBalancerIPs,omitempty"`
	// The value of service.kubernetes.io/service-proxy-name label for AntreaProxy to match. If it is set, then
	// AntreaProxy only handles the Service objects matching this label. The default value is empty string, which
	// means that AntreaProxy will manage all Service objects without the mentioned label.
	ServiceProxyName string `yaml:"serviceProxyName,omitempty"`
	// Determines how external traffic is processed when it's load balanced across Nodes by default.
	// It has the following options:
	// - nat (default): External traffic is SNAT'd when it's load balanced across Nodes to ensure symmetric path.
	// - dsr:           External traffic is never SNAT'd. Backend Pods running on Nodes that are not the ingress Node
	//                  can reply to clients directly, bypassing the ingress Node.
	// A Service's load balancer mode can be overridden by annotating it with `service.antrea.io/load-balancer-mode`.
	DefaultLoadBalancerMode string `yaml:"defaultLoadBalancerMode,omitempty"`
}

type WireGuardConfig struct {
	// The port for the WireGuard to receive traffic. Defaults to 51820.
	Port int `yaml:"port,omitempty"`
}

type NodePortLocalConfig struct {
	// Enable NodePortLocal, a feature used to make Pods reachable using port forwarding on the
	// host. To enable this feature, you need to set "enable" to true, and ensure that the
	// NodePortLocal feature gate is also enabled (which is the default).
	Enable bool `yaml:"enable,omitempty"`
	// Provide the port range used by NodePortLocal. When the NodePortLocal feature is enabled,
	// a port from that range will be assigned whenever a Pod's container defines a specific
	// port to be exposed (each container can define a list of ports as
	// pod.spec.containers[].ports), and all Node traffic directed to that port will be
	// forwarded to the Pod.
	PortRange string `yaml:"portRange,omitempty"`
}

type FlowExporterConfig struct {
	// Enable FlowExporter, a feature used to export polled conntrack connections as
	// IPFIX flow records from each agent to a configured collector. To enable this
	// feature, you need to set "enable" to true, and ensure that the FlowExporter
	// feature gate is also enabled.
	Enable bool `yaml:"enable,omitempty"`
	// Provide the IPFIX collector address as a string with format <HOST>:[<PORT>][:<PROTO>].
	// HOST can either be the DNS name, IP, or Service name of the Flow Collector. If
	// using an IP, it can be either IPv4 or IPv6. However, IPv6 address should be
	// wrapped with []. When the collector is running in-cluster as a Service, set
	// <HOST> to <Service namespace>/<Service name>. For example,
	// "flow-aggregator/flow-aggregator" can be provided to connect to the Antrea
	// Flow Aggregator Service.
	// If PORT is empty, we default to 4739, the standard IPFIX port.
	// If no PROTO is given, we consider "tcp" as default. We support "tcp" and
	// "udp" L4 transport protocols.
	// Defaults to "flow-aggregator/flow-aggregator:4739:tcp".
	FlowCollectorAddr string `yaml:"flowCollectorAddr,omitempty"`
	// Provide flow poll interval in format "0s". This determines how often flow
	// exporter dumps connections in conntrack module. Flow poll interval should
	// be greater than or equal to 1s(one second).
	// Defaults to "5s". Valid time units are "ns", "us" (or "µs"), "ms", "s",
	// "m", "h".
	FlowPollInterval string `yaml:"flowPollInterval,omitempty"`
	// Provide the active flow export timeout, which is the timeout after which
	// a flow record is sent to the collector for active flows. Thus, for flows
	// with a continuous stream of packets, a flow record will be exported to the
	// collector once the elapsed time since the last export event is equal to the
	// value of this timeout.
	// Defaults to "30s". Valid time units are "ns", "us" (or "µs"), "ms", "s",
	// "m", "h".
	ActiveFlowExportTimeout string `yaml:"activeFlowExportTimeout,omitempty"`
	// Provide the idle flow export timeout, which is the timeout after which a
	// flow record is sent to the collector for idle flows. A flow is considered
	// idle if no packet matching this flow has been observed since the last export
	// event.
	// Defaults to "15s". Valid time units are "ns", "us" (or "µs"), "ms", "s",
	// "m", "h".
	IdleFlowExportTimeout string `yaml:"idleFlowExportTimeout,omitempty"`
}

type MulticastConfig struct {
	// To enable Multicast, you need to set "enable" to true, and ensure that the
	// Multicast feature gate is also enabled (which is the default).
	Enable bool `yaml:"enable,omitempty"`
	// The names of the interfaces on Nodes that are used to forward multicast traffic.
	// Defaults to transport interface if not set.
	MulticastInterfaces []string `yaml:"multicastInterfaces,omitempty"`
	// The interval for antrea-agent to send IGMP queries to Pods.
	// Defaults to 125 seconds.
	IGMPQueryInterval string `yaml:"igmpQueryInterval"`
	// The versions of IGMP queries antrea-agent sends to Pods.
	// Defaults to [1, 2, 3].
	IGMPQueryVersions []int `yaml:"igmpQueryVersions"`
}

type EgressConfig struct {
	ExceptCIDRs []string `yaml:"exceptCIDRs,omitempty"`
	// The maximum number of Egress IPs that can be assigned to a Node. It's useful when the Node network restricts
	// the number of secondary IPs a Node can have, e.g. EKS. It must not be greater than 255.
	// Defaults to 255.
	MaxEgressIPsPerNode int `yaml:"maxEgressIPsPerNode,omitempty"`
}

type IPsecConfig struct {
	// The authentication mode of IPsec tunnel. It has the following options:
	// - psk (default): Use pre-shared key (PSK) for IKE authentication.
	// - cert:          Use CA-signed certificates for IKE authentication.
	AuthenticationMode string `yaml:"authenticationMode,omitempty"`
}

type MulticlusterConfig struct {
	// Deprecated and replaced by "enableGateway". Keep the field in MulticlusterConfig to be
	// compatible with earlier version (<= v1.10) Antrea deployment manifests.
	Enable bool `yaml:"enable,omitempty"`
	// Enable Multi-cluster Gateway.
	EnableGateway bool `yaml:"enableGateway,omitempty"`
	// The Namespace where Antrea Multi-cluster Controller is running.
	// The default is antrea-agent's Namespace.
	Namespace string `yaml:"namespace,omitempty"`
	// Enable Multi-cluster NetworkPolicy which allows Antrea-native policy ingress rules to select peers
	// from all clusters in a ClusterSet.
	EnableStretchedNetworkPolicy bool `yaml:"enableStretchedNetworkPolicy,omitempty"`
	// Enable Multi-cluster Pod to Pod connectivity which allows one Pod access to another Pod in other member
	// clusters directly. This feature also requires Pod CIDRs to be provided in the Multi-cluster Controller
	// configuration.
	EnablePodToPodConnectivity bool `yaml:"enablePodToPodConnectivity,omitempty"`
	// Antrea Multi-cluster WireGuard tunnel configuration.
	WireGuard WireGuardConfig `yaml:"wireGuard,omitempty"`
	// Determines how cross-cluster traffic is encrypted.
	// It has the following options:
	// - none (default): Cross-cluster traffic will not be encrypted.
	// - wireGuard:      Enable WireGuard for tunnel traffic encryption.
	TrafficEncryptionMode string `yaml:"trafficEncryptionMode,omitempty"`
}

type ExternalNodeConfig struct {
	// The expected Namespace in which the ExternalNode should be created for a VM or baremetal server Node.
	// The default value is "default".
	// It is used only when NodeType is externalNode.
	ExternalNodeNamespace string `yaml:"externalNodeNamespace,omitempty"`
	// The policy bypass rules define traffic that should bypass NetworkPolicy rules.
	// Each rule contains the following four attributes:
	// direction (ingress|egress), protocol(tcp/udp/icmp/ip), remote CIDR, dst port (ICMP doesn't require),
	// It is used only when NodeType is externalNode.
	PolicyBypassRules []PolicyBypassRule `yaml:"policyBypassRules,omitempty"`
}

type PolicyBypassRule struct {
	// The direction value can be ingress or egress.
	Direction string `yaml:"direction,omitempty"`
	// The protocol which traffic must match. Supported values are TCP, UDP, ICMP and IP.
	Protocol string `yaml:"protocol,omitempty"`
	// CIDR marks the destination CIDR for Egress and source CIDR for Ingress.
	CIDR string `json:"cidr,omitempty"`
	// The destination port of the given protocol.
	Port int `yaml:"port,omitempty"`
}

type AuditLoggingConfig struct {
	// MaxSize is the maximum size in MB of a log file before it gets rotated. Defaults to 500MB.
	MaxSize int32 `yaml:"maxSize,omitempty"`
	// MaxBackups is the maximum number of old log files to retain. If set to 0, all log files
	// will be retained (unless MaxAge causes them to be deleted). Defaults to 3.
	MaxBackups *int32 `yaml:"maxBackups,omitempty"`
	// MaxAge is the maximum number of days to retain old log files based on the timestamp
	// encoded in their filename. If set to 0, old log files are not removed based on age.
	// Defaults to 28.
	MaxAge *int32 `yaml:"maxAge,omitempty"`
	// Compress enables gzip compression on rotated files. Defaults to true.
	Compress *bool `yaml:"compress,omitempty"`
}

type SecondaryNetworkConfig struct {
	// Configuration of OVS bridges for secondary networks. At the moment, only a
	// single OVS bridge is supported.
	OVSBridges []OVSBridgeConfig `yaml:"ovsBridges,omitempty"`
}

type OVSBridgeConfig struct {
	BridgeName string `yaml:"bridgeName"`
	// Names of physical interfaces to be connected to the bridge.
	PhysicalInterfaces []string `yaml:"physicalInterfaces,omitempty"`
}
