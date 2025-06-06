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
	"sort"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/features"
)

// Config is a struct that contains feature gates configuration
type Config struct {
	FeatureGates map[string]bool `yaml:"featureGates,omitempty"`
}

// Constants for component types
const (
	AgentMode        = "agent"
	AgentWindowsMode = "agent-windows"
)

// HandleFunc returns the function which can handle queries issued by 'antctl get featuregates' command.
// The handler function populates Antrea Agent feature gates information to the response.
func HandleFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		featureGates := getFeatureGatesResponse(nil, AgentMode)
		err := json.NewEncoder(w).Encode(featureGates)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when encoding FeatureGates to json")
		}
	}
}

func getFeatureGatesResponse(cfg *Config, component string) []apis.FeatureGateResponse {
	gatesResp := []apis.FeatureGateResponse{}
	for df := range features.DefaultAntreaFeatureGates {
		if component == AgentMode && features.AgentGates.Has(df) ||
			component == AgentWindowsMode && features.AgentGates.Has(df) && features.SupportedOnWindows(df) {

			var status bool
			if cfg != nil {
				var ok bool
				status, ok = cfg.FeatureGates[string(df)]
				if !ok {
					status = features.DefaultFeatureGate.Enabled(df)
				}
			} else {
				status = features.DefaultFeatureGate.Enabled(df)
			}
			featureStatus := features.GetStatus(status)

			// Get prerequisites for this feature gate
			prerequisites := features.GetFeaturePrerequisites(df)
			klog.V(2).InfoS("Agent: Feature gate prerequisites", "featureGate", string(df), "prerequisites", prerequisites)

			gatesResp = append(gatesResp, apis.FeatureGateResponse{
				Component:     component,
				Name:          string(df),
				Status:        featureStatus,
				Version:       features.GetVersion(string(features.DefaultAntreaFeatureGates[df].PreRelease)),
				Prerequisites: prerequisites,
			})
		}
	}
	sort.Slice(gatesResp, func(i, j int) bool {
		return gatesResp[i].Name < gatesResp[j].Name
	})
	return gatesResp
}
