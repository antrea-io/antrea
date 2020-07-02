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
	// Allows to apply cluster-wide NetworkPolicies.
	ClusterNetworkPolicy featuregate.Feature = "ClusterNetworkPolicy"

	// alpha: v0.8
	// Enable antrea proxy which provides ServiceLB for in-cluster services in antrea agent.
	// It should be enabled on Windows, otherwise NetworkPolicy will not take effect on
	// Service traffic.
	AntreaProxy featuregate.Feature = "AntreaProxy"

	// alpha: v0.8
	// Allows to trace path from a generated packet.
	Traceflow featuregate.Feature = "Traceflow"
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
		ClusterNetworkPolicy: {Default: false, PreRelease: featuregate.Alpha},
		AntreaProxy:          {Default: false, PreRelease: featuregate.Alpha},
		Traceflow:            {Default: false, PreRelease: featuregate.Alpha},
	}
)

func init() {
	runtime.Must(DefaultMutableFeatureGate.Add(defaultAntreaFeatureGates))
}
