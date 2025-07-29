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

package bgppolicy

import (
	"encoding/json"
	"net/http"
	"reflect"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/querier"
)

// HandleFunc returns the function which can handle queries issued by the bgppolicy command.
func HandleFunc(bq querier.AgentBGPPolicyInfoQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bq == nil || reflect.ValueOf(bq).IsNil() {
			// The error message must match the "FOO is not enabled" pattern to pass antctl e2e tests.
			http.Error(w, "bgp is not enabled", http.StatusServiceUnavailable)
			return
		}

		bgpPolicyName, routerID, localASN, listenPort, confederationIdentifier := bq.GetBGPPolicyInfo()
		bgpPolicyResp := apis.BGPPolicyResponse{
			BGPPolicyName:           bgpPolicyName,
			RouterID:                routerID,
			LocalASN:                localASN,
			ListenPort:              listenPort,
			ConfederationIdentifier: confederationIdentifier,
		}
		if bgpPolicyName == "" {
			http.Error(w, "there is no effective bgp policy applied to the Node", http.StatusNotFound)
			return
		}

		if err := json.NewEncoder(w).Encode(bgpPolicyResp); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when encoding BGPPolicyResp to json")
		}
	}
}
