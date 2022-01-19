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

package features

import (
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/featuregate"
)

// When editing this file, make sure you edit the documentation as well to keep
// it consistent: /docs/feature-gates.md

const (
	// Every feature gate should add constant here following this template:
	//
	// alpha: vX.Y
	// beta: vX.Y
	// MyFeature featuregate.Feature = "MyFeature"

	// alpha: v0.8
	// beta: v1.0
	// Enables support for ClusterNetworkPolicy and AntreaNetworkPolicy CRDs.
	AntreaPolicy featuregate.Feature = "AntreaPolicy"

	// alpha: v0.13
	// Enable EndpointSlice support in AntreaProxy. If AntreaProxy is not enabled, this
	// flag will not take effect.
	EndpointSlice featuregate.Feature = "EndpointSlice"

	// alpha: v0.8
	// beta: v0.11
	// Enable antrea proxy which provides ServiceLB for in-cluster services in antrea agent.
	// It should be enabled on Windows, otherwise NetworkPolicy will not take effect on
	// Service traffic.
	AntreaProxy featuregate.Feature = "AntreaProxy"

	// alpha: v0.8
	// beta: v0.11
	// Allows to trace path from a generated packet.
	Traceflow featuregate.Feature = "Traceflow"

	// alpha: v0.9
	// Flow exporter exports IPFIX flow records of Antrea flows seen in conntrack module.
	FlowExporter featuregate.Feature = "FlowExporter"

	// alpha: v0.10
	// beta: v1.2
	// Enable collecting and exposing NetworkPolicy statistics.
	NetworkPolicyStats featuregate.Feature = "NetworkPolicyStats"

	// alpha: v0.13
	// beta: v1.4
	// Expose Pod ports through NodePort
	NodePortLocal featuregate.Feature = "NodePortLocal"

	// alpha: v1.0
	// Enable controlling SNAT IPs of Pod egress traffic.
	Egress featuregate.Feature = "Egress"

	// alpha: v1.4
	// Run Kubernetes NodeIPAM with Antrea.
	NodeIPAM featuregate.Feature = "NodeIPAM"

	// alpha: v1.4
	// Enable flexible IPAM for Pods.
	AntreaIPAM featuregate.Feature = "AntreaIPAM"

	// alpha: v1.5
	// Enable Multicast.
	Multicast featuregate.Feature = "Multicast"

	// alpha: v1.5
	// Enable Secondary interface feature for Antrea.
	SecondaryNetwork featuregate.Feature = "SecondaryNetwork"
)

var (
	// DefaultMutableFeatureGate is a mutable version of DefaultFeatureGate.
	DefaultMutableFeatureGate featuregate.MutableFeatureGate = featuregate.NewFeatureGate()

	// DefaultFeatureGate is a shared global FeatureGate.
	// The feature gate should be modified via DefaultMutableFeatureGate.
	DefaultFeatureGate featuregate.FeatureGate = DefaultMutableFeatureGate

	// DefaultAntreaFeatureGates consists of all known Antrea-specific feature keys.
	// To add a new feature, define a key for it above and add it here. The features will be
	// available throughout Antrea binaries.
	DefaultAntreaFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
		AntreaPolicy:       {Default: true, PreRelease: featuregate.Beta},
		AntreaProxy:        {Default: true, PreRelease: featuregate.Beta},
		Egress:             {Default: false, PreRelease: featuregate.Alpha},
		EndpointSlice:      {Default: false, PreRelease: featuregate.Alpha},
		Traceflow:          {Default: true, PreRelease: featuregate.Beta},
		AntreaIPAM:         {Default: false, PreRelease: featuregate.Alpha},
		FlowExporter:       {Default: false, PreRelease: featuregate.Alpha},
		NetworkPolicyStats: {Default: true, PreRelease: featuregate.Beta},
		NodePortLocal:      {Default: true, PreRelease: featuregate.Beta},
		NodeIPAM:           {Default: false, PreRelease: featuregate.Alpha},
		Multicast:          {Default: false, PreRelease: featuregate.Alpha},
		SecondaryNetwork:   {Default: false, PreRelease: featuregate.Alpha},
	}

	// UnsupportedFeaturesOnWindows records the features not supported on
	// a Windows Node. Antrea Agent on a Windows Node checks the enabled
	// features, and fails the startup if an unsupported feature is enabled.
	// We do not define a separate defaultAntreaFeatureGates map for
	// Windows, because Agent code assumes all features are registered (
	// FeatureGate.Enabled(feature) will panic if the feature is not added
	// to the FeatureGate).
	// In future, if a feature is supported on both Linux and Windows, but
	// can have different FeatureSpecs between Linux and Windows, we should
	// still define a separate defaultAntreaFeatureGates map for Windows.
	unsupportedFeaturesOnWindows = map[featuregate.Feature]struct{}{
		NodePortLocal:    {},
		Egress:           {},
		AntreaIPAM:       {},
		Multicast:        {},
		SecondaryNetwork: {},
	}
)

func init() {
	runtime.Must(DefaultMutableFeatureGate.Add(DefaultAntreaFeatureGates))
}

// SupportedOnWindows checks whether a feature is supported on a Windows Node.
func SupportedOnWindows(feature featuregate.Feature) bool {
	_, exists := DefaultAntreaFeatureGates[feature]
	if !exists {
		return false
	}
	_, exists = unsupportedFeaturesOnWindows[feature]
	return !exists
}
