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

package featuregates

import (
	"encoding/json"
	"net/http"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/features"
)

type Response struct {
	Component string `json:"component,omitempty"`
	Name      string `json:"name,omitempty"`
	Status    string `json:"status,omitempty"`
	Version   string `json:"version,omitempty"`
}

// HandleFunc returns the function which can handle queries issued by 'antctl get featuregates' command.
// The handler function populates Antrea Agent feature gates information to the response.
// For now, it will return all feature gates included in features.DefaultAntreaFeatureGates for agent
// We need to exclude any new feature gates which is not consumed by agent in the future.
func HandleFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var featureGates []Response
		status, version := "", ""
		for df := range features.DefaultAntreaFeatureGates {
			if features.DefaultMutableFeatureGate.Enabled(df) {
				status = "Enabled"
			} else {
				status = "Disabled"
			}
			version = string(features.DefaultAntreaFeatureGates[df].PreRelease)
			featureGates = append(featureGates, Response{
				Component: "agent",
				Name:      string(df),
				Status:    status,
				Version:   version,
			})
		}

		err := json.NewEncoder(w).Encode(featureGates)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.Errorf("Error when encoding FeatureGates to json: %v", err)
		}
	}
}
