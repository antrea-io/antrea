package main

import (
	componentbaseconfig "k8s.io/component-base/config"
)

type ControllerConfig struct {
	// clientConnection specifies the kubeconfig file and client connection settings for the agent
	// to communicate with the apiserver.
	ClientConnection componentbaseconfig.ClientConnectionConfiguration `yaml:"clientConnection"`
}
