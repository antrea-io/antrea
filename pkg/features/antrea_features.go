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
	// Allows to apply ClusterNetworkPolicy and AntreaNetworkPolicy CRDs.
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

	// alpha: v0.14
	// Enable NodePort Service support in AntreaProxy in antrea-agent.
	AntreaProxyNodePort featuregate.Feature = "AntreaProxyNodePort"

	// alpha: v0.8
	// beta: v0.11
	// Allows to trace path from a generated packet.
	Traceflow featuregate.Feature = "Traceflow"

	// alpha: v0.9
	// Flow exporter exports IPFIX flow records of Antrea flows seen in conntrack module.
	FlowExporter featuregate.Feature = "FlowExporter"

	// alpha: v0.10
	// Enable collecting and exposing NetworkPolicy statistics.
	NetworkPolicyStats featuregate.Feature = "NetworkPolicyStats"

	// alpha: v0.13
	// Expose Pod ports through NodePort
	NodePortLocal featuregate.Feature = "NodePortLocal"
)

var (
	// DefaultMutableFeatureGate is a mutable version of DefaultFeatureGate.
	DefaultMutableFeatureGate featuregate.MutableFeatureGate = featuregate.NewFeatureGate()

	// DefaultFeatureGate is a shared global FeatureGate.
	// The feature gate should be modified via DefaultMutableFeatureGate.
	DefaultFeatureGate featuregate.FeatureGate = DefaultMutableFeatureGate

	// defaultAntreaFeatureGates consists of all known Antrea-specific feature keys.
	// To add a new feature, define a key for it above and add it here. The features will be
	// available throughout Antrea binaries.
	defaultAntreaFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
		AntreaPolicy:        {Default: false, PreRelease: featuregate.Alpha},
		AntreaProxy:         {Default: true, PreRelease: featuregate.Beta},
		EndpointSlice:       {Default: false, PreRelease: featuregate.Alpha},
		AntreaProxyNodePort: {Default: false, PreRelease: featuregate.Alpha},
		Traceflow:           {Default: true, PreRelease: featuregate.Beta},
		FlowExporter:        {Default: false, PreRelease: featuregate.Alpha},
		NetworkPolicyStats:  {Default: false, PreRelease: featuregate.Alpha},
		NodePortLocal:       {Default: false, PreRelease: featuregate.Alpha},
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
		AntreaProxyNodePort: {},
		NodePortLocal:       {},
	}
)

func init() {
	runtime.Must(DefaultMutableFeatureGate.Add(defaultAntreaFeatureGates))
}

// SupportedOnWindows checks whether a feature is supported on a Windows Node.
func SupportedOnWindows(feature featuregate.Feature) bool {
	_, exists := defaultAntreaFeatureGates[feature]
	if !exists {
		return false
	}
	_, exists = unsupportedFeaturesOnWindows[feature]
	return !exists
}
