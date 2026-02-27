// Copyright 2025 Antrea Authors
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
	"k8s.io/component-base/featuregate"
	"k8s.io/klog/v2"
)

// FeaturePrerequisites maps feature gates to their prerequisite flags
var FeaturePrerequisites = map[featuregate.Feature][]string{
	// AntreaIPAM prerequisites
	AntreaIPAM: {
		"enableBridgingMode=true",
		"trafficEncapMode=true",
		"noSNAT=true",
	},
	// AntreaProxy prerequisites
	AntreaProxy: {
		"proxyAll=true",
	},
	// SecondaryNetwork prerequisites
	SecondaryNetwork: {
		"multipleNetworkInterfaces=true",
	},
	// Add more feature gates and their prerequisites as needed
}

// GetFeaturePrerequisites returns the prerequisites for a given feature gate
func GetFeaturePrerequisites(featureName featuregate.Feature) []string {
	if prerequisites, exists := FeaturePrerequisites[featureName]; exists {
		// Log when prerequisites are found
		klog.V(2).InfoS("Found prerequisites for feature gate", "featureName", string(featureName), "prerequisites", prerequisites)
		return prerequisites
	}
	// Log when no prerequisites are found
	klog.V(2).InfoS("No prerequisites found for feature gate", "featureName", string(featureName))
	return nil
}
