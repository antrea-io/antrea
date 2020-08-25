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

package networkpolicy

import (
	"encoding/json"
	"net/http"

	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
	cpv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1"
)

// HandleFunc creates a http.HandlerFunc which uses an AgentNetworkPolicyInfoQuerier
// to query network policy rules in current agent.
func HandleFunc(aq querier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		ns := r.URL.Query().Get("namespace")
		pod := r.URL.Query().Get("pod")

		if (name != "" || pod != "") && ns == "" {
			http.Error(w, "namespace must be provided", http.StatusBadRequest)
			return
		}

		var obj interface{}
		npq := aq.GetNetworkPolicyInfoQuerier()

		if name != "" {
			// Query the specified NetworkPolicy.
			np := npq.GetNetworkPolicy(name, ns)
			if np != nil {
				obj = *np
			}
		} else if pod != "" {
			// Query NetworkPolicies applied to the Pod
			interfaces := aq.GetInterfaceStore().GetContainerInterfacesByPod(pod, ns)
			if len(interfaces) > 0 {
				nps := npq.GetAppliedNetworkPolicies(pod, ns)
				obj = cpv1beta1.NetworkPolicyList{Items: nps}
			}
		} else {
			nps := npq.GetNetworkPolicies(ns)
			obj = cpv1beta1.NetworkPolicyList{Items: nps}
		}

		if obj == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(w).Encode(obj); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
