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

package healthcheck

import (
	"encoding/json"
	"net/http"

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/monitor"
)

type AntreaAgentHealthCheckResponse struct {
	HealthStatus bool `json:"healthStatus,omitempty"`
}

// Handler returns the function which can handle queries issued by agent-info commands,
// the handler function populate component's health-check-info to the response.
func HandleFunc(aq monitor.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		healthCheckResponse := &AntreaAgentHealthCheckResponse{HealthStatus: aq.GetHealthCheckStatus(r)}
		err := json.NewEncoder(w).Encode(healthCheckResponse)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.Errorf("Error when encoding AntreaAgentHealthCheckInfo to json: %v", err)
		}
	}
}
