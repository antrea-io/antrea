// Copyright 2024 Antrea Authors
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

package policyconjunctions

import (
	"encoding/json"
	"net/http"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	agentquerier "antrea.io/antrea/pkg/agent/querier"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/querier"
)

// From user shorthand input to cpv1beta1.NetworkPolicyType
var mapToNetworkPolicyType = map[string]cpv1beta.NetworkPolicyType{
	"K8SNP": cpv1beta.K8sNetworkPolicy,
	"ACNP":  cpv1beta.AntreaClusterNetworkPolicy,
	"ANNP":  cpv1beta.AntreaNetworkPolicy,
	"ANP":   cpv1beta.AdminNetworkPolicy,
}

var clusterScopedResources = sets.New[string]("ACNP", "ANP")

// HandleFunc creates a http.HandlerFunc which uses an AgentNetworkPolicyInfoQuerier
// to query network policy rules in current agent.
func HandleFunc(aq agentquerier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		uid := query.Get("uid")
		npFilter := &querier.NetworkPolicyQueryFilter{Name: uid}
		if uid == "" {
			if query.Get("source") == "" {
				http.Error(w, "policy uid or name must be provided", http.StatusBadRequest)
				return
			}
			policyType := strings.ToUpper(query.Get("type"))
			cpType, ok := mapToNetworkPolicyType[policyType]
			if !ok {
				http.Error(w, "valid policy type must be provided with policy name", http.StatusBadRequest)
				return
			}
			if !clusterScopedResources.Has(policyType) && query.Get("namespace") == "" {
				http.Error(w, "policy Namespace must be provided for policy type "+policyType, http.StatusBadRequest)
				return
			}
			npFilter = &querier.NetworkPolicyQueryFilter{
				SourceName: query.Get("source"),
				Namespace:  query.Get("namespace"),
				SourceType: cpType,
			}
		}
		npq := aq.GetNetworkPolicyInfoQuerier()
		policies := npq.GetNetworkPolicies(npFilter)
		if len(policies) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		uid = string(policies[0].SourceRef.UID)
		realizedRules := npq.GetRealizedRulesByPolicy(uid)
		if err := json.NewEncoder(w).Encode(realizedRules); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
