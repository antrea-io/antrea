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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	aqtest "antrea.io/antrea/pkg/agent/querier/testing"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	qtest "antrea.io/antrea/pkg/querier/testing"
)

func TestBadRequests(t *testing.T) {
	badRequests := map[string]string{
		"Policy name only":        "?source=allow-http",
		"No policy type":          "?source=allow-http&namespace=ns1",
		"No namespace for ANNP":   "?source=allow-http&type=ANNP",
		"No namespace for K8s NP": "?source=allow-http&type=K8sNP",
	}
	handler := HandleFunc(nil)
	for k, r := range badRequests {
		req, err := http.NewRequest(http.MethodGet, r, nil)
		assert.Nil(t, err)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusBadRequest, recorder.Code, k)
	}
}

func TestPolicyConjunctionsQuery(t *testing.T) {
	c := gomock.NewController(t)
	tests := []struct {
		name             string
		query            string
		policiesReturned []cpv1beta.NetworkPolicy
		expectedStatus   int
	}{
		{
			name:  "policy found",
			query: "?uid=uid1",
			policiesReturned: []cpv1beta.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "uid1",
					},
					SourceRef: &cpv1beta.NetworkPolicyReference{
						Type: cpv1beta.AntreaClusterNetworkPolicy,
						Name: "test-acnp",
						UID:  "uid1",
					},
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:             "policy not found",
			query:            "?uid=uid2",
			policiesReturned: []cpv1beta.NetworkPolicy{},
			expectedStatus:   http.StatusNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npQuerier := qtest.NewMockAgentNetworkPolicyInfoQuerier(c)
			npQuerier.EXPECT().GetNetworkPolicies(gomock.Any()).Return(tt.policiesReturned).Times(1)
			if len(tt.policiesReturned) == 1 {
				npQuerier.EXPECT().GetRealizedRulesByPolicy(string(tt.policiesReturned[0].SourceRef.UID)).Times(1)
			}
			aq := aqtest.NewMockAgentQuerier(c)
			aq.EXPECT().GetNetworkPolicyInfoQuerier().Return(npQuerier).Times(1)

			handler := HandleFunc(aq)
			req, err := http.NewRequest(http.MethodGet, tt.query, nil)
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			assert.Equal(t, tt.expectedStatus, recorder.Code)
		})
	}
}
