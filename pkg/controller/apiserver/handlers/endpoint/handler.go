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
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
	"net/http"

	"github.com/vmware-tanzu/antrea/pkg/querier"
)

// Policies describes the policies relevant to a certain endpoint
type Policies struct {
	Applied []types.NetworkPolicy `json:"applied"`
	Egress  []types.NetworkPolicy `json:"egress"`
	Ingress []types.NetworkPolicy `json:"ingress"`
}

// HandleFunc creates a http.HandlerFunc which uses an AgentNetworkPolicyInfoQuerier
// to query network policy rules in current agent.
func HandleFunc(cnpq querier.ControllerNetworkPolicyInfoQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		podName := r.URL.Query().Get("pod")
		namespace := r.URL.Query().Get("namespace")
		println("query")
		println(podName)
		println("query")
		println(namespace)
		//TODO: error handling for name and namespace and GetNetworkPolicies
		applied, egress, ingress := cnpq.GetNetworkPolicies(namespace, podName)

		policies := Policies{
			Applied: applied,
			Egress:  egress,
			Ingress: ingress,
		}

		if err := json.NewEncoder(w).Encode(policies); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

func printPoliciesForDebugging(policies Policies) {
	println("Applied policies:")
	for _, policy := range policies.Applied {
		println(policy.Name)
	}
	println("Egress policies:")
	for _, policy := range policies.Egress {
		println(policy.Name)
	}
	println("Ingress policies:")
	for _, policy := range policies.Ingress {
		println(policy.Name)
	}
}
