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
	// Runtime data directory used by OpenVSwitch.
	// Default value:
	// - On Linux platform: /var/run/openvswitch
	// - On Windows platform: C:\openvswitch\var\run\openvswitch
	OVSRunDir string `yaml:"ovsRunDir,omitempty"`
	// Name of the interface antrea-agent will create and use for host <--> pod communication.
	// Make sure it doesn't conflict with your existing interfaces.
	// Defaults to gw0.
	HostGateway string `yaml:"hostGateway,omitempty"`
	// Encapsulation mode for communication between Pods across Nodes, supported values:
	// - vxlan (default)
	// - geneve
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
	// CIDR Range for services in cluster. It's required to support egress network policy, should
	// be set to the same value as the one specified by --service-cluster-ip-range for kube-apiserver.
	// Default is 10.96.0.0/12
	ServiceCIDR string `yaml:"serviceCIDR,omitempty"`
	// Whether or not to enable IPSec (ESP) encryption for Pod traffic across Nodes. IPSec encryption
	// is supported only for the GRE tunnel type. Antrea uses Preshared Key (PSK) for IKE
	// authentication. When IPSec tunnel is enabled, the PSK value must be passed to Antrea Agent
	// through an environment variable: ANTREA_IPSEC_PSK.
	// Defaults to false.
	EnableIPSecTunnel bool `yaml:"enableIPSecTunnel,omitempty"`
	// Determines how traffic is encapsulated. It has the following options
	// Encap(default): Inter-node Pod traffic is always encapsulated and Pod to outbound traffic is masqueraded.
	// NoEncap: Inter-node Pod traffic is not encapsulated, but Pod to outbound traffic is masqueraded.
	//          Underlying network must be capable of supporting Pod traffic across IP subnet.
	// Hybrid: noEncap if worker Nodes on same subnet, otherwise encap.
	// NetworkPolicyOnly: Antrea enforces NetworkPolicy only, and utilizes CNI chaining and delegates Pod IPAM and connectivity to primary CNI.
	TrafficEncapMode string `yaml:"trafficEncapMode,omitempty"`
}
