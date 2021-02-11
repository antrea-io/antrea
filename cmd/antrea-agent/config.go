// Copyright 2019 Antrea Authors
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

package main

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
	// Default MTU to use for the host gateway interface and the network interface of each
	// Pod. If omitted, antrea-agent will default this value to 1450 to accommodate for tunnel
	// encapsulate overhead.
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
	// Whether or not to enable IPSec (ESP) encryption for Pod traffic across Nodes. IPSec encryption
	// is supported only for the GRE tunnel type. Antrea uses Preshared Key (PSK) for IKE
	// authentication. When IPSec tunnel is enabled, the PSK value must be passed to Antrea Agent
	// through an environment variable: ANTREA_IPSEC_PSK.
	// Defaults to false.
	EnableIPSecTunnel bool `yaml:"enableIPSecTunnel,omitempty"`
	// APIPort is the port for the antrea-agent APIServer to serve on.
	// Defaults to 10350.
	APIPort int `yaml:"apiPort,omitempty"`
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
	// Provide flow poll interval in format "0s". This determines how often flow exporter dumps connections in conntrack module.
	// Flow poll interval should be greater than or equal to 1s(one second).
	// Defaults to "5s". Follow the time units of duration.
	FlowPollInterval string `yaml:"flowPollInterval,omitempty"`
	// Provide flow export frequency, which is the number of poll cycles elapsed before flow exporter exports flow records to
	// the flow collector.
	// Flow export frequency should be greater than or equal to 1.
	// Defaults to "12".
	FlowExportFrequency uint `yaml:"flowExportFrequency,omitempty"`
	// Enable TLS communication from flow exporter to flow aggregator.
	// Defaults to true.
	EnableTLSToFlowAggregator bool `yaml:"enableTLSToFlowAggregator,omitempty"`
	// Provide the port range used by NodePortLocal. When the NodePortLocal feature is enabled, a port from that range will be assigned
	// whenever a Pod's container defines a specific port to be exposed (each container can define a list of ports as pod.spec.containers[].ports),
	// and all Node traffic directed to that port will be forwarded to the Pod.
	NPLPortRange string `yaml:"nplPortRange,omitempty"`
	// Provide the address of Kubernetes apiserver, to override any value provided in kubeconfig or InClusterConfig.
	// Defaults to "". It must be a host string, a host:port pair, or a URL to the base of the apiserver.
	KubeAPIServerOverride string `yaml:"kubeAPIServerOverride,omitempty"`
	// Cipher suites to use.
	TLSCipherSuites string `yaml:"tlsCipherSuites,omitempty"`
	// TLS min version.
	TLSMinVersion string `yaml:"tlsMinVersion,omitempty"`
}
