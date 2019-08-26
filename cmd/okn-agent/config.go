package main

import (
	componentbaseconfig "k8s.io/component-base/config"
)

type AgentConfig struct {
	CNISocket string `yaml:"cniSocket,omitempty"`
	// clientConnection specifies the kubeconfig file and client connection settings for the agent
	// to use when communicating with the apiserver.
	ClientConnection componentbaseconfig.ClientConnectionConfiguration `yaml:"clientConnection"`
	OVSBridge        string                                            `yaml:"ovsBridge,omitempty"`
	HostGateway      string                                            `yaml:"hostGateway,omitempty"`
	TunnelType       string                                            `yaml:"tunnelType,omitempty"`
	// Mount location of the /proc directory. The default is "/host", which is appropriate when
	// okn-agent is run as part of the OKN DaemonSet (and the host's /proc directory is mounted
	// as /host/proc in the okn-agent container). When running okn-agent as a process,
	// hostProcPathPrefix should be set to '' in the YAML config.
	HostProcPathPrefix string `yaml:"hostProcPathPrefix,omitempty"`
}
