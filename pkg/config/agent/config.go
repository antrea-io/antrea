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

package config

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
	// Datapath type to use for the OpenVSwitch bridge created by Antrea. Supported values are:
	// - system
	// - netdev
	// 'system' is the default value and corresponds to the kernel datapath. Use 'netdev' to run
	// OVS in userspace mode. Userspace mode requires the tun device driver to be available.
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
	// - ipsec:          Enable IPSec (ESP) encryption for Pod traffic across Nodes. Antrea uses
	//                   Preshared Key (PSK) for IKE authentication. When IPSec tunnel is enabled,
	//                   the PSK value must be passed to Antrea Agent through an environment
	//                   variable: ANTREA_IPSEC_PSK.
	// - wireguard:      Enable WireGuard for tunnel traffic encryption.
	TrafficEncryptionMode string `yaml:"trafficEncryptionMode,omitempty"`
	// WireGuard related configurations.
	WireGuard WireGuardConfig `yaml:"wireGuard"`
	// APIPort is the port for the antrea-agent APIServer to serve on.
	// Defaults to 10350.
	APIPort int `yaml:"apiPort,omitempty"`

	// ClusterMembershipPort is the server port used by the antrea-agent to run a gossip-based cluster membership protocol. Currently it's used only when the Egress feature is enabled.
	// Defaults to 10351.
	ClusterMembershipPort int `yaml:"clusterPort,omitempty"`

	// Enable metrics exposure via Prometheus. Initializes Prometheus metrics listener
	// Defaults to true.
	EnablePrometheusMetrics bool `yaml:"enablePrometheusMetrics,omitempty"`
	// Provide the IPFIX collector address as a string with format <HOST>:[<PORT>][:<PROTO>].
	// HOST can either be the DNS name or the IP of the Flow Collector. For example,
	// "flow-aggregator.flow-aggregator.svc" can be provided as DNS name to connect
	// to the Antrea Flow Aggregator service. If IP, it can be either IPv4 or IPv6.
	// However, IPv6 address should be wrapped with [].
	// If PORT is empty, we default to 4739, the standard IPFIX port.
	// If no PROTO is given, we consider "tcp" as default. We support "tcp" and
	// "udp" L4 transport protocols.
	// Defaults to "flow-aggregator.flow-aggregator.svc:4739:tcp".
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
	// Deprecated. Use the NodePortLocal config options instead.
	NPLPortRange string `yaml:"nplPortRange,omitempty"`
	// NodePortLocal (NPL) configuration options.
	NodePortLocal NodePortLocalConfig `yaml:"nodePortLocal,omitempty"`
	// Provide the address of Kubernetes apiserver, to override any value provided in kubeconfig or InClusterConfig.
	// Defaults to "". It must be a host string, a host:port pair, or a URL to the base of the apiserver.
	KubeAPIServerOverride string `yaml:"kubeAPIServerOverride,omitempty"`
	// Provide the address of DNS server, to override the kube-dns service. It's used to resolve hostname in FQDN policy.
	// Defaults to "". It must be a host string or a host:port pair of the dns server.
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
	// AntreaProxy contains AntreaProxy related configuration options.
	AntreaProxy AntreaProxyConfig `yaml:"antreaProxy,omitempty"`
	// Egress related configurations.
	Egress EgressConfig `yaml:"egress"`
}

type AntreaProxyConfig struct {
	// ProxyAll tells antrea-agent to proxy all Service traffic, including NodePort, LoadBalancer, and ClusterIP traffic,
	// regardless of where they come from. Therefore, running kube-proxy is no longer required. This requires the AntreaProxy
	// feature to be enabled.
	ProxyAll bool `yaml:"proxyAll,omitempty"`
	// A string array of values which specifies the host IPv4/IPv6 addresses for NodePorts. Values may be valid IP blocks.
	// (e.g. 1.2.3.0/24, 1.2.3.4/32). An empty string slice is meant to select all host IPv4/IPv6 addresses.
	NodePortAddresses []string `yaml:"nodePortAddresses,omitempty"`
	// An array of string values to specify a list of Services which should be ignored by AntreaProxy (traffic to these
	// Services will not be load-balanced). Values can be a valid ClusterIP (e.g. 10.11.1.2) or a Service name
	// with Namespace (e.g. kube-system/kube-dns)
	SkipServices []string `yaml:"skipServices,omitempty"`
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

type EgressConfig struct {
	ExceptCIDRs []string `yaml:"exceptCIDRs,omitempty"`
}
