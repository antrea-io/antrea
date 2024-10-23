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

package bgproute

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/controller/bgp"
	"antrea.io/antrea/pkg/querier"
)

// HandleFunc returns the function which can handle queries issued by the bgproutes command.
func HandleFunc(bq querier.AgentBGPPolicyInfoQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bq == nil || reflect.ValueOf(bq).IsNil() {
			// The error message must match the "FOO is not enabled" pattern to pass antctl e2e tests.
			http.Error(w, "bgp is not enabled", http.StatusServiceUnavailable)
			return
		}

		values := r.URL.Query()
		var ipv4Only, ipv6Only bool
		if values.Has("ipv4-only") {
			if values.Get("ipv4-only") != "" {
				http.Error(w, "invalid query", http.StatusBadRequest)
				return
			}
			ipv4Only = true
		}
		if values.Has("ipv6-only") {
			if values.Get("ipv6-only") != "" {
				http.Error(w, "invalid query", http.StatusBadRequest)
				return
			}
			ipv6Only = true
		}
		if ipv4Only && ipv6Only {
			http.Error(w, "invalid query", http.StatusBadRequest)
			return
		}

		bgpRoutes, err := bq.GetBGPRoutes(r.Context(), !ipv6Only, !ipv4Only)
		if err != nil {
			if errors.Is(err, bgp.ErrBGPPolicyNotFound) {
				http.Error(w, "there is no effective bgp policy applied to the Node", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var bgpRoutesResp []apis.BGPRouteResponse
		for _, bgpRoute := range bgpRoutes {
			bgpRoutesResp = append(bgpRoutesResp, apis.BGPRouteResponse{
				Route: bgpRoute,
			})
		}

		if err := json.NewEncoder(w).Encode(bgpRoutesResp); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when encoding BGPRoutesResp to json")
		}
	}
}
