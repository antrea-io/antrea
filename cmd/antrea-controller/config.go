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

type ControllerConfig struct {
	// FeatureGates is a map of feature names to bools that enable or disable experimental features.
	FeatureGates map[string]bool `yaml:"featureGates,omitempty"`
	// clientConnection specifies the kubeconfig file and client connection settings for the
	// antrea-controller to communicate with the Kubernetes apiserver.
	ClientConnection componentbaseconfig.ClientConnectionConfiguration `yaml:"clientConnection"`
	// APIPort is the port for the antrea-controller APIServer to serve on.
	// Defaults to 10349.
	APIPort int `yaml:"apiPort,omitempty"`
	// Enable metrics exposure via Prometheus. Initializes Prometheus metrics listener
	// Defaults to true.
	EnablePrometheusMetrics bool `yaml:"enablePrometheusMetrics,omitempty"`
	// Indicates whether to use auto-generated self-signed TLS certificate.
	// If false, A Secret named "antrea-controller-tls" must be provided with the following keys:
	//   ca.crt: <CA certificate>
	//   tls.crt: <TLS certificate>
	//   tls.key: <TLS private key>
	// And the Secret must be mounted to directory "/var/run/antrea/antrea-controller-tls" of the
	// antrea-controller container.
	// Defaults to true.
	SelfSignedCert bool `yaml:"selfSignedCert,omitempty"`
	// Cipher suites to use.
	TLSCipherSuites string `yaml:"tlsCipherSuites,omitempty"`
	// TLS min version.
	TLSMinVersion string `yaml:"tlsMinVersion,omitempty"`
	// EnableCustomAdmissionControllers enables admission controller webhooks to mutate/validate resources.
	// For example, it enables the labels mutator which labels all Namespaces with the reserved
	// "antrea.io/metadata.name = <namespaceName>" label.
	// Defaults to false.
	EnableCustomAdmissionControllers bool `yaml:"enableCustomAdmissionControllers,omitempty"`
}
