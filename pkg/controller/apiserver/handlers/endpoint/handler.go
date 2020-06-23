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

package endpoint

import (
	"encoding/json"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
	"net/http"
)

// HandleFunc creates a http.HandlerFunc which uses an AgentNetworkPolicyInfoQuerier
// to query network policy rules in current agent.
func HandleFunc(eq networkpolicy.EndpointQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		podName := r.URL.Query().Get("pod")
		namespace := r.URL.Query().Get("namespace")
		// check for incomplete arguments
		if podName == "" || namespace == "" {
			http.Error(w, "namespace and pod must be provided", http.StatusBadRequest)
			return
		}
		// query endpoint and handle response errors
		endpointQueryResponse, err := eq.QueryNetworkPolicies(namespace, podName)
		if err == nil && endpointQueryResponse == nil {
			http.Error(w, "could not find any endpoints matching your selection", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(*endpointQueryResponse); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
