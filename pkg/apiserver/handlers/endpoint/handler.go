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
	"net/http"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apiserver/apis"
	"antrea.io/antrea/pkg/controller/networkpolicy"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

// HandleFunc creates a http.HandlerFunc which uses an AgentNetworkPolicyInfoQuerier
// to query network policy rules in current agent.
func HandleFunc(eq networkpolicy.EndpointQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		podName := r.URL.Query().Get("pod")
		namespace := r.URL.Query().Get("namespace")
		// check for incomplete arguments
		if podName == "" {
			http.Error(w, "pod must be provided", http.StatusBadRequest)
			return
		}
		// query endpoint and handle response errors
		endpointNetworkPolicyRules, err := eq.QueryNetworkPolicyRules(namespace, podName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if endpointNetworkPolicyRules == nil {
			http.Error(w, "could not find any endpoints matching your selection", http.StatusNotFound)
			return
		}

		// make response policies
		var responsePolicies []v1beta2.NetworkPolicyReference
		var responsePolicy v1beta2.NetworkPolicyReference
		for _, internalPolicy := range endpointNetworkPolicyRules.AppliedPolicies {
			v1beta2.Convert_controlplane_NetworkPolicyReference_To_v1beta2_NetworkPolicyReference(internalPolicy.SourceRef, &responsePolicy, nil)
			responsePolicies = append(responsePolicies, responsePolicy)
		}
		// create rules based on effective rules on this endpoint
		extractRules := func(effectiveRules []*antreatypes.RuleInfo) []apis.Rule {
			var responseRules []apis.Rule
			for _, rule := range effectiveRules {
				v1beta2.Convert_controlplane_NetworkPolicyReference_To_v1beta2_NetworkPolicyReference(rule.Policy.SourceRef, &responsePolicy, nil)
				newRule := apis.Rule{
					PolicyRef: responsePolicy,
					Direction: v1beta2.Direction(rule.Rule.Direction),
					RuleIndex: rule.Index,
				}
				responseRules = append(responseRules, newRule)
			}
			return responseRules
		}
		// for now, selector only selects a single endpoint (pod, namespace)
		endpoint := apis.Endpoint{
			Namespace:       namespace,
			Name:            podName,
			AppliedPolicies: responsePolicies,
			IngressSrcRules: extractRules(endpointNetworkPolicyRules.EndpointAsIngressSrcRules),
			EgressDstRules:  extractRules(endpointNetworkPolicyRules.EndpointAsEgressDstRules),
		}
		endpointQueryResponse := &apis.EndpointQueryResponse{Endpoints: []apis.Endpoint{endpoint}}

		if err := json.NewEncoder(w).Encode(*endpointQueryResponse); err != nil {
			http.Error(w, "failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
