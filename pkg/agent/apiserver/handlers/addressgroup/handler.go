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

package addressgroup

import (
	"encoding/json"
	"net/http"

	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/querier"
)

// HandleFunc creates a http.HandlerFunc which uses an AgentNetworkPolicyInfoQuerier
// to query address groups in current agent. The HandlerFunc accepts `name` parameter
// in URL and returns the specific address group.
func HandleFunc(npq querier.AgentNetworkPolicyInfoQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		groups := npq.GetAddressGroups()
		var obj interface{}
		if len(name) > 0 {
			for _, group := range groups {
				if group.Name == name {
					obj = group
					break
				}
			}
			if obj == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		} else {
			obj = networkingv1beta1.AddressGroupList{Items: groups}
		}
		if err := json.NewEncoder(w).Encode(obj); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
