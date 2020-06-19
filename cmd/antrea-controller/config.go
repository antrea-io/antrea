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
	// Defaults to false.
	EnablePrometheusMetrics bool `yaml:"enablePrometheusMetrics,omitempty"`
	// Indicates whether to use auto-generated self-signed TLS certificate.
	// If false, A secret named "kube-system/antrea-controller-tls" must be provided with the following keys:
	//   ca.crt: <CA certificate>
	//   tls.crt: <TLS certificate>
	//   tls.key: <TLS private key>
	// Defaults to true.
	SelfSignedCert bool `yaml:"selfSignedCert,omitempty"`
}
