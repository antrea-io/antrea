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

	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/querier"
)

// HandleFunc creates a http.HandlerFunc which uses an AgentNetworkPolicyInfoQuerier
// to query network policy rules in current agent.
func HandleFunc(npq querier.AgentNetworkPolicyInfoQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		ns := r.URL.Query().Get("namespace")
		if len(name) > 0 && len(ns) == 0 {
			http.Error(w, "an empty namespace may not be set when a resource name is provided", http.StatusBadRequest)
			return
		}

		policies := npq.GetNetworkPolicies()
		var resp []networkingv1beta1.NetworkPolicy
		for _, p := range policies {
			if (len(name) == 0 || name == p.Name) && (len(ns) == 0 || ns == p.Namespace) {
				resp = append(resp, p)
			}
		}

		if len(name) > 0 && len(resp) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var obj interface{}
		if len(name) > 0 {
			obj = resp[0]
		} else {
			obj = networkingv1beta1.NetworkPolicyList{Items: resp}
		}
		if err := json.NewEncoder(w).Encode(obj); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
