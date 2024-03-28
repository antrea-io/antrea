// Copyright 2022 Antrea Authors
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

package serviceexternalip

import (
	"encoding/json"
	"net/http"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/querier"
)

// HandleFunc creates a http.HandlerFunc which uses an ServiceExternalIPStatusQuerier
// to query Service external IP status.
func HandleFunc(sq querier.ServiceExternalIPStatusQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		ns := r.URL.Query().Get("namespace")
		if !features.DefaultFeatureGate.Enabled(features.ServiceExternalIP) {
			http.Error(w, "ServiceExternalIP is not enabled", http.StatusServiceUnavailable)
			return
		}
		result := sq.GetServiceExternalIPStatus()
		var response []apis.ServiceExternalIPInfo
		for _, r := range result {
			if (len(name) == 0 || name == r.ServiceName) && (len(ns) == 0 || ns == r.Namespace) {
				response = append(response, r)
			}
		}
		if len(name) > 0 && len(response) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}
