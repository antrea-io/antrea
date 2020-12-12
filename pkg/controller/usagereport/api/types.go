// Copyright 2020 Antrea Authors
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

// Package api defines version 1 of the Antrea usage reporting (telemetry)
// API. New fields can be added as needed, but modifying a field or removing one
// will require defining a version 2.
// It is important to keep in mind that the reported data is meant to be
// ingested by data warehouses like Google BigQuery with minimal
// transformation. This motivated some of the design choices. For example,
// "BigQuery does not support maps or dictionaries in JSON, due to potential
// lack of schema information in a pure JSON dictionary" - which explains the
// FeatureGates type.

package api

import (
	"time"
)

type FeatureGate struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type AgentConfig struct {
	FeatureGates            []FeatureGate `json:"featureGates"`
	OVSDatapathType         string        `json:"ovsDatapathType"`
	TrafficEncapMode        string        `json:"trafficEncapMode"`
	NoSNAT                  bool          `json:"noSNAT"`
	TunnelType              string        `json:"tunnelType"`
	EnableIPSecTunnel       bool          `json:"enableIPSecTunnel"`
	EnablePrometheusMetrics bool          `json:"enablePrometheusMetrics"`
}

type ControllerConfig struct {
	FeatureGates            []FeatureGate `json:"featureGates"`
	EnablePrometheusMetrics bool          `json:"enablePrometheusMetrics"`
}

// NodeInfo includes a subset of https://godoc.org/k8s.io/api/core/v1#NodeSystemInfo, plus IP
// address family information
type NodeInfo struct {
	KernelVersion           string `json:"kernelVersion"`
	OSImage                 string `json:"osImage"`
	ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
	KubeletVersion          string `json:"kubeletVersion"`
	KubeProxyVersion        string `json:"kubeProxyVersion"`
	OperatingSystem         string `json:"operatingSystem"`
	Architecture            string `json:"architecture"`
	HasIPv4Address          bool   `json:"hasIPv4Address"`
	HasIPv6Address          bool   `json:"hasIPv6Address"`
}

type IPFamily string

const (
	IPFamilyIPv4 = "IPv4"
	IPFamilyIPv6 = "IPv6"
)

// We use *int32 for "count" fields: 0 can be a valid value and we need a way to indicate that the
// value cannot be determined (using -1 would also have been an option).

type NetworkPolicyInfo struct {
	// NumTiers is the number of Tiers defined in the cluster; nil if cannot be determined.
	NumTiers *int32 `json:"numTiers"`
	// NumNetworkPolicies is the number of NetworkPolicies defined in the cluster; nil if cannot
	// be determined.
	NumNetworkPolicies *int32 `json:"numNetworkPolicies"`
	// NumAntreaNetworkPolicies is the number of Antrea NetworkPolicies defined in the cluster;
	// nil if cannot be determined.
	NumAntreaNetworkPolicies *int32 `json:"numAntreaNetworkPolicies"`
	// NumAntreaClusterNetworkPolicies is the number of Antrea ClusterNetworkPolicies defined in
	// the cluster; nil if cannot be determined.
	NumAntreaClusterNetworkPolicies *int32 `json:"numAntreaClusterNetworkPolicies"`
}

type K8sDistributionName string

// New distributions can be added to the list when support is added to detect them.
const (
	K8sDistributionUnknown K8sDistributionName = "Unknown"
	K8sDistributionAKS     K8sDistributionName = "AKS"
	K8sDistributionEKS     K8sDistributionName = "EKS"
	K8sDistributionGKE     K8sDistributionName = "GKE"
)

type ClusterInfo struct {
	// K8sVersion is the version of the API server retrieved using the discovery client; empty
	// string if cannot be determined.
	K8sVersion string `json:"k8sVersion"`
	// K8sDistribution is the version of the API server retrieved using the discovery client;
	// "Unknown" string if cannot be determined. Since there is no unified mechanism to detect
	// the distribution, having a separate constant for each distribution seems appropriate.
	K8sDistribution K8sDistributionName `json:"k8sDistribution"`
	// NumNodes is the number of K8s Nodes which constitute the cluster; nil if cannot be
	// determined.
	NumNodes *int32     `json:"numNodes"`
	Nodes    []NodeInfo `json:"nodes"`
	// NumNamespaces is the number of Namespaces in the cluster; nil if cannot be determined.
	NumNamespaces *int32 `json:"numNamespaces"`
	// NumPods is the number of Pods in the cluster; nil if cannot be determined.
	NumPods         *int32            `json:"numPods"`
	NetworkPolicies NetworkPolicyInfo `json:"networkPolicies"`
	// Does the cluster support IPv4 / IPv6? For dual-stack, the "primary" IP family should come
	// first.
	IPFamilies []IPFamily `json:"ipFamilies"`
}

type UsageReport struct {
	ClusterUUID string `json:"clusterUUID"`
	// Version is the version of the Antrea controller
	Version              string            `json:"version"`
	FullVersion          string            `json:"fullVersion"`
	IsReleased           bool              `json:"isReleased"`
	AgentConfig          *AgentConfig      `json:"agentConfig"`
	ControllerConfig     *ControllerConfig `json:"controllerConfig"`
	ClusterInfo          ClusterInfo       `json:"clusterInfo"`
	AntreaDeploymentTime time.Time         `json:"antreaDeploymentTime"`
}
