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
	// Mount location of the /proc directory. The default is "/host", which is appropriate when
	// okn-agent is run as part of the OKN DaemonSet (and the host's /proc directory is mounted
	// as /host/proc in the okn-agent container). When running okn-agent as a process,
	// hostProcPathPrefix should be set to '' in the YAML config.
	HostProcPathPrefix string `yaml:"hostProcPathPrefix,omitempty"`
}
