// Copyright 2019 OKN Authors
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
	// Name of the OpenVSwitch bridge okn-agent will create and use.
	// Make sure it doesn't conflict with your existing OpenVSwitch bridges.
	// Defaults to br-int.
	OVSBridge string `yaml:"ovsBridge,omitempty"`
	// Name of the interface okn-agent will create and use for host <--> pod communication.
	// Make sure it doesn't conflict with your existing interfaces.
	// Defaults to gw0.
	HostGateway string `yaml:"hostGateway,omitempty"`
	// Encapsulation mode for communication between Pods across Nodes, supported values:
	// - vxlan (default)
	// - geneve
	TunnelType string `yaml:"tunnelType,omitempty"`
	// Default MTU to use for the host gateway interface and the network interface of each
	// Pod. If omitted, okn-agent will default this value to 1450 to accomodate for tunnel
	// encapsulate overhead.
	DefaultMTU int `yaml:"defaultMTU,omitempty"`
	// Mount location of the /proc directory. The default is "/host", which is appropriate when
	// okn-agent is run as part of the OKN DaemonSet (and the host's /proc directory is mounted
	// as /host/proc in the okn-agent container). When running okn-agent as a process,
	// hostProcPathPrefix should be set to "/" in the YAML config.
	HostProcPathPrefix string `yaml:"hostProcPathPrefix,omitempty"`
	// CIDR Range for services in cluster. It's required to support egress network policy, should
	// be set to the same value as the one specified by --service-cluster-ip-range for kube-apiserver.
	// Default is 10.96.0.0/12
	ServiceCIDR string `yaml:"serviceCIDR,omitempty"`
}
