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

type NodeIPAMConfig struct {
	// Enable the integrated node IPAM controller within the Antrea controller.
	// Defaults to false.
	EnableNodeIPAM bool `yaml:"enableNodeIPAM,omitempty"`
	// CIDR ranges for Pods in cluster. String array containing single CIDR range, or multiple ranges. The CIDRs could
	// be either IPv4 or IPv6. At most one CIDR may be specified for each IP family. Value ignored when EnableNodeIPAM
	// is false.
	ClusterCIDRs []string `yaml:"clusterCIDRs,omitempty"`
	// CIDR ranges for Services in cluster. It is not necessary to specify it when there is no overlap with clusterCIDRs.
	// Value ignored when EnableNodeIPAM is false.
	ServiceCIDR   string `yaml:"serviceCIDR,omitempty"`
	ServiceCIDRv6 string `yaml:"serviceCIDRv6,omitempty"`
	// Mask size for IPv4 Node CIDR in IPv4 or dual-stack cluster. Value ignored when EnableNodeIPAM is false
	// or when IPv4 Pod CIDR is not configured.
	NodeCIDRMaskSizeIPv4 int `yaml:"nodeCIDRMaskSizeIPv4,omitempty"`
	// Mask size for IPv6 Node CIDR in IPv6 or dual-stack cluster. Value ignored when EnableNodeIPAM is false
	// or when IPv6 Pod CIDR is not configured.
	NodeCIDRMaskSizeIPv6 int `yaml:"nodeCIDRMaskSizeIPv6,omitempty"`
}

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
	EnablePrometheusMetrics *bool `yaml:"enablePrometheusMetrics,omitempty"`
	// Indicates whether to use auto-generated self-signed TLS certificate.
	// If false, A Secret named "antrea-controller-tls" must be provided with the following keys:
	//   ca.crt: <CA certificate>
	//   tls.crt: <TLS certificate>
	//   tls.key: <TLS private key>
	// And the Secret must be mounted to directory "/var/run/antrea/antrea-controller-tls" of the
	// antrea-controller container.
	// Defaults to true.
	SelfSignedCert *bool `yaml:"selfSignedCert,omitempty"`
	// Cipher suites to use.
	TLSCipherSuites string `yaml:"tlsCipherSuites,omitempty"`
	// TLS min version.
	TLSMinVersion string `yaml:"tlsMinVersion,omitempty"`
	// Legacy CRD mirroring.
	LegacyCRDMirroring *bool `yaml:"legacyCRDMirroring,omitempty"`
	// NodeIPAM Configuration
	NodeIPAM NodeIPAMConfig `yaml:"nodeIPAM"`
}
