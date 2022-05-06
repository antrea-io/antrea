// Copyright 2022 Antrea Authors.
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

// The simulator binary is responsible to run simulated nodes for antrea agent.
// It watches NetworkPolicies, AddressGroups and AppliedToGroups from antrea
// controller and prints the events of these resources to log.

package policyrecoresult

import (
	"encoding/json"
	"fmt"

	"net/http"

	"github.com/google/uuid"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/flowaggregator/querier"
)

// Response is the response struct of policyReco result command.
type Response struct {
	Result string `json:"result,omitempty"`
}

func HandleFunc(faq querier.FlowAggregatorQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		recoID := r.URL.Query().Get("id")
		_, err := uuid.Parse(recoID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to decode input id %s into a UUID, err: %v", recoID, err), http.StatusBadRequest)
			return
		}
		recoResult, err := faq.GetPolicyRecommendationResult(recoID)
		if err != nil {
			recoResult = fmt.Sprintf("Get policy recommendation result failed, err: %v", err)
		}
		err = json.NewEncoder(w).Encode(Response{recoResult})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when encoding recommendation result to json", "recommendation result", recoResult)
		}
	}
}
